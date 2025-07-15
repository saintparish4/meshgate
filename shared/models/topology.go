// shared/models/topology.go
package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"math"
	"time"
)

// TopologyType represents different mesh topology configurations
type TopologyType string

const (
	TopologyTypeFull   TopologyType = "full"   // Full mesh - all nodes connected
	TopologyTypeHub    TopologyType = "hub"    // Hub and spoke
	TopologyTypeRing   TopologyType = "ring"   // Ring topology
	TopologyTypeTree   TopologyType = "tree"   // Hierarchical tree
	TopologyTypeCustom TopologyType = "custom" // Custom configuration
	TopologyTypeAuto   TopologyType = "auto"   // Auto-optimized
)

// NetworkTopology represents the overall mesh network topology
type NetworkTopology struct {
	ID            string          `json:"id" db:"id"`
	TenantID      string          `json:"tenant_id" db:"tenant_id"`
	Name          string          `json:"name" db:"name"`
	Description   string          `json:"description" db:"description"`
	Type          TopologyType    `json:"type" db:"type"`
	Configuration TopologyConfig  `json:"configuration" db:"configuration"`
	Metrics       TopologyMetrics `json:"metrics" db:"metrics"`
	Status        string          `json:"status" db:"status"`
	CreatedAt     time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at" db:"updated_at"`

	// Relationships
	Nodes   []Node          `json:"nodes,omitempty" db:"-"`
	Links   []TopologyLink  `json:"links,omitempty" db:"-"`
	Subnets []NetworkSubnet `json:"subnets,omitempty" db:"-"`
}

// TopologyConfig contains topology-specific configuration
type TopologyConfig struct {
	MaxPeersPerNode    int                    `json:"max_peers_per_node"`
	PreferredPeers     []string               `json:"preferred_peers,omitempty"`
	HubNodes           []string               `json:"hub_nodes,omitempty"`
	RedundancyLevel    int                    `json:"redundancy_level"`
	AutoOptimize       bool                   `json:"auto_optimize"`
	OptimizationMetric string                 `json:"optimization_metric"` // latency, bandwidth, cost
	Constraints        TopologyConstraints    `json:"constraints"`
	CustomParameters   map[string]interface{} `json:"custom_parameters,omitempty"`
}

// TopologyConstraints defines limits and rules for topology
type TopologyConstraints struct {
	MaxLatency           int                 `json:"max_latency_ms"`
	MinBandwidth         int                 `json:"min_bandwidth_mbps"`
	GeographicLimits     []GeographicZone    `json:"geographic_limits,omitempty"`
	CostLimits           CostConstraints     `json:"cost_limits"`
	SecurityRequirements SecurityConstraints `json:"security_requirements"`
}

// GeographicZone represents geographic constraints
type GeographicZone struct {
	Name      string  `json:"name"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Radius    float64 `json:"radius_km"`
	Priority  int     `json:"priority"`
}

// CostConstraints defines cost-related limits
type CostConstraints struct {
	MaxMonthlyCost    float64       `json:"max_monthly_cost"`
	CostPerGB         float64       `json:"cost_per_gb"`
	CostPerConnection float64       `json:"cost_per_connection"`
	BudgetAlerts      []BudgetAlert `json:"budget_alerts,omitempty"`
}

// BudgetAlert defines cost alerting thresholds
type BudgetAlert struct {
	Threshold  float64  `json:"threshold_percent"`
	Action     string   `json:"action"` // notify, throttle, disconnect
	Recipients []string `json:"recipients,omitempty"`
}

// SecurityConstraints defines security requirements for topology
type SecurityConstraints struct {
	RequireEncryption    bool     `json:"require_encryption"`
	AllowedCiphers       []string `json:"allowed_ciphers,omitempty"`
	RequirePresharedKeys bool     `json:"require_preshared_keys"`
	MaxTrustDistance     int      `json:"max_trust_distance"`
	IsolatedZones        []string `json:"isolated_zones,omitempty"`
}

// TopologyMetrics stores performance and health metrics
type TopologyMetrics struct {
	NodeCount           int                 `json:"node_count"`
	LinkCount           int                 `json:"link_count"`
	AverageLatency      float64             `json:"average_latency_ms"`
	AverageBandwidth    float64             `json:"average_bandwidth_mbps"`
	NetworkEfficiency   float64             `json:"network_efficiency"`
	RedundancyScore     float64             `json:"redundancy_score"`
	HealthScore         float64             `json:"health_score"`
	LastOptimized       *time.Time          `json:"last_optimized"`
	OptimizationHistory []OptimizationEvent `json:"optimization_history,omitempty"`
}

// OptimizationEvent tracks topology optimization changes
type OptimizationEvent struct {
	Timestamp      time.Time              `json:"timestamp"`
	Trigger        string                 `json:"trigger"`
	Changes        []TopologyChange       `json:"changes"`
	ImprovementPct float64                `json:"improvement_percent"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// TopologyChange represents a specific change in topology
type TopologyChange struct {
	Type     string      `json:"type"` // add_link, remove_link, change_hub
	NodeA    string      `json:"node_a,omitempty"`
	NodeB    string      `json:"node_b,omitempty"`
	OldValue interface{} `json:"old_value,omitempty"`
	NewValue interface{} `json:"new_value,omitempty"`
	Reason   string      `json:"reason"`
}

// TopologyLink represents a connection between two nodes
type TopologyLink struct {
	ID         string    `json:"id" db:"id"`
	TopologyID string    `json:"topology_id" db:"topology_id"`
	NodeAID    string    `json:"node_a_id" db:"node_a_id"`
	NodeBID    string    `json:"node_b_id" db:"node_b_id"`
	Status     string    `json:"status" db:"status"`
	Latency    int       `json:"latency_ms" db:"latency_ms"`
	Bandwidth  int       `json:"bandwidth_mbps" db:"bandwidth_mbps"`
	Quality    float64   `json:"quality" db:"quality"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time `json:"updated_at" db:"updated_at"`

	// Computed fields
	NodeA *Node `json:"node_a,omitempty" db:"-"`
	NodeB *Node `json:"node_b,omitempty" db:"-"`
}

// NetworkSubnet represents a subnet in the topology
type NetworkSubnet struct {
	ID          string    `json:"id" db:"id"`
	TopologyID  string    `json:"topology_id" db:"topology_id"`
	CIDR        string    `json:"cidr" db:"cidr"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Scan implements the sql.Scanner interface for TopologyConfig
func (tc *TopologyConfig) Scan(value interface{}) error {
	if value == nil {
		*tc = TopologyConfig{}
		return nil
	}

	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, tc)
	case string:
		return json.Unmarshal([]byte(v), tc)
	default:
		return fmt.Errorf("cannot scan %T into TopologyConfig", value)
	}
}

// Value implements the driver.Valuer interface for TopologyConfig
func (tc TopologyConfig) Value() (driver.Value, error) {
	return json.Marshal(tc)
}

// Scan implements the sql.Scanner interface for TopologyMetrics
func (tm *TopologyMetrics) Scan(value interface{}) error {
	if value == nil {
		*tm = TopologyMetrics{}
		return nil
	}

	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, tm)
	case string:
		return json.Unmarshal([]byte(v), tm)
	default:
		return fmt.Errorf("cannot scan %T into TopologyMetrics", value)
	}
}

// Value implements the driver.Valuer interface for TopologyMetrics
func (tm TopologyMetrics) Value() (driver.Value, error) {
	return json.Marshal(tm)
}

// TableName returns the database table name for NetworkTopology
func (NetworkTopology) TableName() string {
	return "network_topologies"
}

// TableName returns the database table name for TopologyLink
func (TopologyLink) TableName() string {
	return "topology_links"
}

// TableName returns the database table name for NetworkSubnet
func (NetworkSubnet) TableName() string {
	return "network_subnets"
}

// CalculateEfficiency calculates the network efficiency score
func (tm *TopologyMetrics) CalculateEfficiency() float64 {
	if tm.NodeCount == 0 {
		return 0.0
	}

	// Simple efficiency calculation based on connectivity
	maxPossibleLinks := tm.NodeCount * (tm.NodeCount - 1) / 2
	if maxPossibleLinks == 0 {
		return 0.0
	}

	efficiency := float64(tm.LinkCount) / float64(maxPossibleLinks)
	return math.Min(efficiency, 1.0)
}

// UpdateMetrics updates the topology metrics
func (nt *NetworkTopology) UpdateMetrics() {
	nt.Metrics.NodeCount = len(nt.Nodes)
	nt.Metrics.LinkCount = len(nt.Links)
	nt.Metrics.NetworkEfficiency = nt.Metrics.CalculateEfficiency()
	nt.UpdatedAt = time.Now()
}
