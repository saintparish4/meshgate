// shared/models/policy.go
package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/saintparish4/meshgate/shared/utils"
)

// PolicyType represents the type of policy
type PolicyType string

const (
	PolicyTypeAccess     PolicyType = "access"
	PolicyTypeRouting    PolicyType = "routing"
	PolicyTypeFirewall   PolicyType = "firewall"
	PolicyTypeQoS        PolicyType = "qos"
	PolicyTypeCompliance PolicyType = "compliance"
)

// PolicyAction represents the action to take when policy matches
type PolicyAction string

const (
	PolicyActionAllow PolicyAction = "allow"
	PolicyActionDeny  PolicyAction = "deny"
	PolicyActionDrop  PolicyAction = "drop"
	PolicyActionRoute PolicyAction = "route"
	PolicyActionLimit PolicyAction = "limit"
	PolicyActionLog   PolicyAction = "log"
)

// PolicyStatus represents the current status of a policy
type PolicyStatus string

const (
	PolicyStatusActive   PolicyStatus = "active"
	PolicyStatusInactive PolicyStatus = "inactive"
	PolicyStatusDraft    PolicyStatus = "draft"
	PolicyStatusArchived PolicyStatus = "archived"
)

// Policy represents a network policy
type Policy struct {
	ID          string       `json:"id" db:"id"`
	TenantID    string       `json:"tenant_id" db:"tenant_id"`
	Name        string       `json:"name" db:"name"`
	Description string       `json:"description" db:"description"`
	Type        PolicyType   `json:"type" db:"type"`
	Status      PolicyStatus `json:"status" db:"status"`
	Priority    int          `json:"priority" db:"priority"`
	Rules       PolicyRules  `json:"rules" db:"rules"`
	Tags        StringArray  `json:"tags" db:"tags"`
	CreatedBy   string       `json:"created_by" db:"created_by"`
	CreatedAt   time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at" db:"updated_at"`
	ExpiresAt   *time.Time   `json:"expires_at" db:"expires_at"`

	// Relationships
	Assignments []PolicyAssignment `json:"assignments,omitempty" db:"-"`
	AuditLogs   []PolicyAuditLog   `json:"audit_logs,omitempty" db:"-"`
}

// PolicyRules contains the actual policy logic
type PolicyRules struct {
	Source      PolicyTarget      `json:"source"`
	Destination PolicyTarget      `json:"destination"`
	Action      PolicyAction      `json:"action"`
	Protocol    string            `json:"protocol,omitempty"`
	Ports       []int             `json:"ports,omitempty"`
	Schedule    PolicySchedule    `json:"schedule,omitempty"`
	Conditions  []PolicyCondition `json:"conditions,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// PolicyTarget represents a source or destination in a policy
type PolicyTarget struct {
	Type        string   `json:"type"` // node, group, cidr, any
	Identifiers []string `json:"identifiers"`
	Tags        []string `json:"tags,omitempty"`
	Exclude     []string `json:"exclude,omitempty"`
}

// PolicySchedule defines when a policy is active
type PolicySchedule struct {
	Enabled   bool     `json:"enabled"`
	StartTime string   `json:"start_time,omitempty"` // HH:MM format
	EndTime   string   `json:"end_time,omitempty"`   // HH:MM format
	Days      []string `json:"days,omitempty"`       // monday, tuesday, etc.
	Timezone  string   `json:"timezone,omitempty"`
}

// PolicyCondition represents additional conditions for policy evaluation
type PolicyCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // eq, ne, gt, lt, contains, matches
	Value    interface{} `json:"value"`
}

// PolicyAssignment represents which nodes/groups a policy applies to
type PolicyAssignment struct {
	ID         string    `json:"id" db:"id"`
	PolicyID   string    `json:"policy_id" db:"policy_id"`
	TargetType string    `json:"target_type" db:"target_type"` // node, group, tag
	TargetID   string    `json:"target_id" db:"target_id"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`

	// Computed fields
	Policy *Policy `json:"policy,omitempty" db:"-"`
}

// PolicyAuditLog tracks policy changes and evaluations
type PolicyAuditLog struct {
	ID        string                 `json:"id" db:"id"`
	PolicyID  string                 `json:"policy_id" db:"policy_id"`
	Action    string                 `json:"action" db:"action"` // created, updated, deleted, evaluated
	NodeID    string                 `json:"node_id" db:"node_id"`
	UserID    string                 `json:"user_id" db:"user_id"`
	Details   map[string]interface{} `json:"details" db:"details"`
	Result    string                 `json:"result" db:"result"` // allow, deny, error
	CreatedAt time.Time              `json:"created_at" db:"created_at"`
}

// PolicyGroup represents a collection of policies
type PolicyGroup struct {
	ID          string      `json:"id" db:"id"`
	TenantID    string      `json:"tenant_id" db:"tenant_id"`
	Name        string      `json:"name" db:"name"`
	Description string      `json:"description" db:"description"`
	PolicyIDs   StringArray `json:"policy_ids" db:"policy_ids"`
	Tags        StringArray `json:"tags" db:"tags"`
	CreatedAt   time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at" db:"updated_at"`

	// Relationships
	Policies []Policy `json:"policies,omitempty" db:"-"`
}

// Scan implements the sql.Scanner interface for PolicyRules
func (pr *PolicyRules) Scan(value interface{}) error {
	if value == nil {
		*pr = PolicyRules{}
		return nil
	}

	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, pr)
	case string:
		return json.Unmarshal([]byte(v), pr)
	default:
		return fmt.Errorf("cannot scan %T into PolicyRules", value)
	}
}

// Value implements the driver.Valuer interface for PolicyRules
func (pr PolicyRules) Value() (driver.Value, error) {
	return json.Marshal(pr)
}

// TableName returns the database table name for Policy
func (Policy) TableName() string {
	return "policies"
}

// TableName returns the database table name for PolicyAssignment
func (PolicyAssignment) TableName() string {
	return "policy_assignments"
}

// TableName returns the database table name for PolicyAuditLog
func (PolicyAuditLog) TableName() string {
	return "policy_audit_logs"
}

// TableName returns the database table name for PolicyGroup
func (PolicyGroup) TableName() string {
	return "policy_groups"
}

// IsActive returns true if the policy is currently active
func (p *Policy) IsActive() bool {
	if p.Status != PolicyStatusActive {
		return false
	}

	if p.ExpiresAt != nil && time.Now().After(*p.ExpiresAt) {
		return false
	}

	return p.isScheduleActive()
}

// isScheduleActive checks if the policy schedule allows current execution
func (p *Policy) isScheduleActive() bool {
	if !p.Rules.Schedule.Enabled {
		return true
	}

	now := time.Now()
	if p.Rules.Schedule.Timezone != "" {
		if loc, err := time.LoadLocation(p.Rules.Schedule.Timezone); err == nil {
			now = now.In(loc)
		}
	}

	// Check day of week
	if len(p.Rules.Schedule.Days) > 0 {
		currentDay := strings.ToLower(now.Weekday().String())
		dayFound := false
		for _, day := range p.Rules.Schedule.Days {
			if strings.ToLower(day) == currentDay {
				dayFound = true
				break
			}
		}
		if !dayFound {
			return false
		}
	}

	// Check time range
	if p.Rules.Schedule.StartTime != "" && p.Rules.Schedule.EndTime != "" {
		currentTime := now.Format("15:04")
		if currentTime < p.Rules.Schedule.StartTime || currentTime > p.Rules.Schedule.EndTime {
			return false
		}
	}

	return true
}

// MatchesTarget checks if a node matches the policy target
func (pt *PolicyTarget) MatchesTarget(nodeID string, node *Node) bool {
	switch pt.Type {
	case "any":
		return true
	case "node":
		for _, id := range pt.Identifiers {
			if id == nodeID {
				return !pt.isExcluded(nodeID)
			}
		}
	case "cidr":
		if node != nil && node.IPAddress != "" {
			nodeIP := net.ParseIP(node.IPAddress)
			if nodeIP != nil {
				for _, cidr := range pt.Identifiers {
					if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
						if ipNet.Contains(nodeIP) {
							return !pt.isExcluded(nodeID)
						}
					}
				}
			}
		}
	case "tag":
		if node != nil {
			for _, tag := range pt.Tags {
				for _, nodeTag := range node.Tags {
					if tag == nodeTag {
						return !pt.isExcluded(nodeID)
					}
				}
			}
		}
	}
	return false
}

// isExcluded checks if a node is in the exclude list
func (pt *PolicyTarget) isExcluded(nodeID string) bool {
	for _, excludeID := range pt.Exclude {
		if excludeID == nodeID {
			return true
		}
	}
	return false
}

// EvaluateConditions checks if all conditions are met
func (p *Policy) EvaluateConditions(context map[string]interface{}) bool {
	for _, condition := range p.Rules.Conditions {
		if !p.evaluateCondition(condition, context) {
			return false
		}
	}
	return true
}

// evaluateCondition evaluates a single condition
func (p *Policy) evaluateCondition(condition PolicyCondition, context map[string]interface{}) bool {
	value, exists := context[condition.Field]
	if !exists {
		return false
	}

	switch condition.Operator {
	case "eq":
		return value == condition.Value
	case "ne":
		return value != condition.Value
	case "contains":
		if str, ok := value.(string); ok {
			if substr, ok := condition.Value.(string); ok {
				return strings.Contains(str, substr)
			}
		}
	case "matches":
		// Could implement regex matching here
		return false
	}

	return false
}

// Validate validates the policy data
func (p *Policy) Validate() error {
	if p.ID == "" {
		return fmt.Errorf("policy ID is required")
	}
	if p.TenantID == "" {
		return fmt.Errorf("tenant ID is required")
	}
	if p.Name == "" {
		return fmt.Errorf("policy name is required")
	}
	if p.Type == "" {
		return fmt.Errorf("policy type is required")
	}
	if p.Rules.Action == "" {
		return fmt.Errorf("policy action is required")
	}
	if p.Priority < 0 || p.Priority > 1000 {
		return fmt.Errorf("policy priority must be between 0 and 1000")
	}
	return nil
}

// AddAssignment adds a new policy assignment
func (p *Policy) AddAssignment(targetType, targetID string) {
	assignment := PolicyAssignment{
		ID:         utils.GenerateID(),
		PolicyID:   p.ID,
		TargetType: targetType,
		TargetID:   targetID,
		CreatedAt:  time.Now(),
	}
	p.Assignments = append(p.Assignments, assignment)
}

// RemoveAssignment removes a policy assignment
func (p *Policy) RemoveAssignment(targetType, targetID string) {
	for i, assignment := range p.Assignments {
		if assignment.TargetType == targetType && assignment.TargetID == targetID {
			p.Assignments = append(p.Assignments[:i], p.Assignments[i+1:]...)
			return
		}
	}
}

// LogAudit logs an audit entry for the policy
func (p *Policy) LogAudit(action, nodeID, userID, result string, details map[string]interface{}) {
	auditLog := PolicyAuditLog{
		ID:        utils.GenerateID(),
		PolicyID:  p.ID,
		Action:    action,
		NodeID:    nodeID,
		UserID:    userID,
		Details:   details,
		Result:    result,
		CreatedAt: time.Now(),
	}
	p.AuditLogs = append(p.AuditLogs, auditLog)
}
