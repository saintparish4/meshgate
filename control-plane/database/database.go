package database

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"time"

	"go.etcd.io/bbolt"
)

// Database schema version
const CurrentSchemaVersion = 2

// Migration represents a database migration
type Migration struct {
	Version     int       `json:"version"`
	Description string    `json:"description"`
	AppliedAt   time.Time `json:"applied_at"`
}

// Database manager with migration support
type DatabaseManager struct {
	db *bbolt.DB
}

// DB is an alias for DatabaseManager for backward compatibility
type DB = DatabaseManager

// NewDB creates a new database manager
func NewDB(dbPath string) (*DatabaseManager, error) {
	return NewDatabaseManager(dbPath)
}

// Tx is an alias for bbolt.Tx
type Tx = bbolt.Tx

func NewDatabaseManager(dbPath string) (*DatabaseManager, error) {
	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}

	dm := &DatabaseManager{db: db}

	// Initialize database and run migrations
	if err := dm.initializeDatabase(); err != nil {
		return nil, err
	}

	return dm, nil
}

func (dm *DatabaseManager) initializeDatabase() error {
	return dm.db.Update(func(tx *bbolt.Tx) error {
		// Create initial buckets
		buckets := []string{
			"users", "tenants", "nodes", "sessions",
			"policies", "audit_logs", "api_keys",
			"node_groups", "network_policies", "migrations",
		}

		for _, bucket := range buckets {
			if _, err := tx.CreateBucketIfNotExists([]byte(bucket)); err != nil {
				return err
			}
		}

		// Check current schema version and run migrations
		return dm.runMigrations(tx)
	})
}

func (dm *DatabaseManager) runMigrations(tx *bbolt.Tx) error {
	migrationsBucket := tx.Bucket([]byte("migrations"))

	// Get current version
	currentVersion := 0
	if data := migrationsBucket.Get([]byte("schema_version")); data != nil {
		var version int
		if err := json.Unmarshal(data, &version); err == nil {
			currentVersion = version
		}
	}

	log.Printf("Current schema version: %d, target version: %d", currentVersion, CurrentSchemaVersion)

	// Run migrations
	for version := currentVersion + 1; version <= CurrentSchemaVersion; version++ {
		if err := dm.runMigration(tx, version); err != nil {
			return fmt.Errorf("migration %d failed: %w", version, err)
		}
		log.Printf("Applied migration %d", version)
	}

	// Update schema version
	versionData, _ := json.Marshal(CurrentSchemaVersion)
	return migrationsBucket.Put([]byte("schema_version"), versionData)
}

func (dm *DatabaseManager) runMigration(tx *bbolt.Tx, version int) error {
	migration := Migration{
		Version:   version,
		AppliedAt: time.Now(),
	}

	switch version {
	case 1:
		migration.Description = "Initial schema with multi-tenancy support"
		return dm.migration001_InitialSchema(tx)
	case 2:
		migration.Description = "Add enhanced monitoring and audit features"
		return dm.migration002_EnhancedMonitoring(tx)
	default:
		return fmt.Errorf("unknown migration version: %d", version)
	}

	// Record migration
	migrationsBucket := tx.Bucket([]byte("migrations"))
	migrationData, _ := json.Marshal(migration)
	key := fmt.Sprintf("migration_%03d", version)
	return migrationsBucket.Put([]byte(key), migrationData)
}

func (dm *DatabaseManager) migration001_InitialSchema(tx *bbolt.Tx) error {
	// Create index buckets for efficient lookups
	indexBuckets := []string{
		"idx_users_by_email",
		"idx_users_by_tenant",
		"idx_nodes_by_tenant",
		"idx_nodes_by_status",
		"idx_sessions_by_user",
	}

	for _, bucket := range indexBuckets {
		if _, err := tx.CreateBucketIfNotExists([]byte(bucket)); err != nil {
			return err
		}
	}

	// Create default admin tenant if none exists
	tenantsBucket := tx.Bucket([]byte("tenants"))
	cursor := tenantsBucket.Cursor()
	first, _ := cursor.First()

	if first == nil {
		// Create default system tenant
		defaultTenant := &Tenant{
			ID:     "system",
			Name:   "System Tenant",
			Domain: "system.local",
			Settings: TenantSettings{
				SubnetCIDR:        "10.10.10.0/24",
				MaxNodes:          1000,
				PolicyMode:        "strict",
				HeartbeatInterval: 30,
			},
			CreatedAt: time.Now(),
			IsActive:  true,
			NodeLimit: 1000,
		}

		tenantData, _ := json.Marshal(defaultTenant)
		if err := tenantsBucket.Put([]byte("system"), tenantData); err != nil {
			return err
		}
		log.Printf("Created default system tenant")
	}

	return nil
}

func (dm *DatabaseManager) migration002_EnhancedMonitoring(tx *bbolt.Tx) error {
	// Add new buckets for enhanced features
	newBuckets := []string{
		"metrics_snapshots",
		"alert_rules",
		"notification_channels",
		"node_metrics",
		"tenant_quotas",
		"billing_records",
	}

	for _, bucket := range newBuckets {
		if _, err := tx.CreateBucketIfNotExists([]byte(bucket)); err != nil {
			return err
		}
	}

	// Add default alert rules
	alertRulesBucket := tx.Bucket([]byte("alert_rules"))

	defaultRules := []AlertRule{
		{
			ID:          "node-down",
			Name:        "Node Down",
			Description: "Alert when a node goes offline",
			Expression:  "meshgate_active_nodes < 1",
			Severity:    "warning",
			Duration:    "5m",
			Enabled:     true,
			CreatedAt:   time.Now(),
		},
		{
			ID:          "high-auth-failures",
			Name:        "High Authentication Failures",
			Description: "Alert on high authentication failure rate",
			Expression:  "rate(meshgate_auth_attempts_total{status=\"failed\"}[5m]) > 0.1",
			Severity:    "warning",
			Duration:    "2m",
			Enabled:     true,
			CreatedAt:   time.Now(),
		},
		{
			ID:          "api-errors",
			Name:        "API Errors",
			Description: "Alert on high API error rate",
			Expression:  "rate(meshgate_api_requests_total{status=~\"5..\"}[5m]) > 0.05",
			Severity:    "critical",
			Duration:    "2m",
			Enabled:     true,
			CreatedAt:   time.Now(),
		},
	}

	for _, rule := range defaultRules {
		ruleData, _ := json.Marshal(rule)
		if err := alertRulesBucket.Put([]byte(rule.ID), ruleData); err != nil {
			return err
		}
	}

	// Update existing tenants with quota information
	tenantsBucket := tx.Bucket([]byte("tenants"))
	quotasBucket := tx.Bucket([]byte("tenant_quotas"))

	cursor := tenantsBucket.Cursor()
	for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
		var tenant Tenant
		if err := json.Unmarshal(v, &tenant); err != nil {
			continue
		}

		// Create default quota for existing tenants
		quota := TenantQuota{
			TenantID:      tenant.ID,
			MaxNodes:      tenant.NodeLimit,
			MaxUsers:      50,
			MaxAPIKeys:    10,
			MaxBandwidth:  1000000000, // 1GB
			UsedNodes:     tenant.UsedNodes,
			UsedUsers:     0,
			UsedAPIKeys:   0,
			UsedBandwidth: 0,
			UpdatedAt:     time.Now(),
		}

		quotaData, _ := json.Marshal(quota)
		if err := quotasBucket.Put([]byte(tenant.ID), quotaData); err != nil {
			return err
		}
	}

	return nil
}

// Enhanced data models
type AlertRule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Expression  string    `json:"expression"`
	Severity    string    `json:"severity"` // info, warning, critical
	Duration    string    `json:"duration"`
	Enabled     bool      `json:"enabled"`
	TenantID    string    `json:"tenant_id,omitempty"` // Empty for global rules
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type NotificationChannel struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Type     string                 `json:"type"` // email, slack, webhook
	Config   map[string]interface{} `json:"config"`
	TenantID string                 `json:"tenant_id"`
	Enabled  bool                   `json:"enabled"`
}

type TenantQuota struct {
	TenantID      string    `json:"tenant_id"`
	MaxNodes      int       `json:"max_nodes"`
	MaxUsers      int       `json:"max_users"`
	MaxAPIKeys    int       `json:"max_api_keys"`
	MaxBandwidth  int64     `json:"max_bandwidth"` // bytes per month
	UsedNodes     int       `json:"used_nodes"`
	UsedUsers     int       `json:"used_users"`
	UsedAPIKeys   int       `json:"used_api_keys"`
	UsedBandwidth int64     `json:"used_bandwidth"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type MetricsSnapshot struct {
	ID          string             `json:"id"`
	TenantID    string             `json:"tenant_id"`
	Timestamp   time.Time          `json:"timestamp"`
	Metrics     map[string]float64 `json:"metrics"`
	Labels      map[string]string  `json:"labels"`
	Granularity string             `json:"granularity"` // minute, hour, day
}

type AuditLog struct {
	ID        string                 `json:"id"`
	TenantID  string                 `json:"tenant_id"`
	UserID    string                 `json:"user_id"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	Details   map[string]interface{} `json:"details"`
	IPAddress string                 `json:"ip_address"`
	UserAgent string                 `json:"user_agent"`
	Timestamp time.Time              `json:"timestamp"`
	Success   bool                   `json:"success"`
}

type APIKey struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Key         string    `json:"key"` // Hashed
	TenantID    string    `json:"tenant_id"`
	UserID      string    `json:"user_id"`
	Permissions []string  `json:"permissions"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsed    time.Time `json:"last_used"`
	IsActive    bool      `json:"is_active"`
}

type NodeGroup struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	TenantID    string            `json:"tenant_id"`
	NodeIDs     []string          `json:"node_ids"`
	Labels      map[string]string `json:"labels"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type NetworkPolicy struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	TenantID    string              `json:"tenant_id"`
	Rules       []NetworkPolicyRule `json:"rules"`
	AppliedTo   NetworkPolicyTarget `json:"applied_to"`
	Priority    int                 `json:"priority"`
	Enabled     bool                `json:"enabled"`
	CreatedAt   time.Time           `json:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
}

type NetworkPolicyRule struct {
	Action      string              `json:"action"`   // allow, deny, log
	Protocol    string              `json:"protocol"` // tcp, udp, icmp, any
	Ports       []string            `json:"ports"`
	Source      NetworkPolicyTarget `json:"source"`
	Destination NetworkPolicyTarget `json:"destination"`
}

type NetworkPolicyTarget struct {
	Type   string            `json:"type"` // node, group, cidr, any
	Values []string          `json:"values"`
	Labels map[string]string `json:"labels"`
}

// Database operations with multi-tenancy support
func (dm *DatabaseManager) SaveUser(user *User) error {
	return dm.db.Update(func(tx *bbolt.Tx) error {
		// Save user
		usersBucket := tx.Bucket([]byte("users"))
		userData, err := json.Marshal(user)
		if err != nil {
			return err
		}

		if err := usersBucket.Put([]byte(user.ID), userData); err != nil {
			return err
		}

		// Update indexes
		emailIndexBucket := tx.Bucket([]byte("idx_users_by_email"))
		if err := emailIndexBucket.Put([]byte(user.Email), []byte(user.ID)); err != nil {
			return err
		}

		tenantIndexBucket := tx.Bucket([]byte("idx_users_by_tenant"))
		tenantKey := fmt.Sprintf("%s:%s", user.TenantID, user.ID)
		return tenantIndexBucket.Put([]byte(tenantKey), []byte(user.ID))
	})
}

func (dm *DatabaseManager) GetUsersByTenant(tenantID string) ([]*User, error) {
	var users []*User

	err := dm.db.View(func(tx *bbolt.Tx) error {
		usersBucket := tx.Bucket([]byte("users"))
		indexBucket := tx.Bucket([]byte("idx_users_by_tenant"))

		cursor := indexBucket.Cursor()
		prefix := []byte(tenantID + ":")

		for k, v := cursor.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = cursor.Next() {
			userData := usersBucket.Get(v)
			if userData == nil {
				continue
			}

			var user User
			if err := json.Unmarshal(userData, &user); err != nil {
				continue
			}

			users = append(users, &user)
		}

		return nil
	})

	return users, err
}

func (dm *DatabaseManager) SaveAuditLog(log *AuditLog) error {
	return dm.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("audit_logs"))
		logData, err := json.Marshal(log)
		if err != nil {
			return err
		}

		// Use timestamp + random suffix for unique key
		key := fmt.Sprintf("%d:%s", log.Timestamp.Unix(), log.ID)
		return bucket.Put([]byte(key), logData)
	})
}

func (dm *DatabaseManager) GetTenantQuota(tenantID string) (*TenantQuota, error) {
	var quota *TenantQuota

	err := dm.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("tenant_quotas"))
		data := bucket.Get([]byte(tenantID))
		if data == nil {
			return fmt.Errorf("quota not found for tenant %s", tenantID)
		}

		quota = &TenantQuota{}
		return json.Unmarshal(data, quota)
	})

	return quota, err
}

func (dm *DatabaseManager) UpdateTenantQuota(quota *TenantQuota) error {
	return dm.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("tenant_quotas"))
		quota.UpdatedAt = time.Now()

		quotaData, err := json.Marshal(quota)
		if err != nil {
			return err
		}

		return bucket.Put([]byte(quota.TenantID), quotaData)
	})
}

func (dm *DatabaseManager) SaveMetricsSnapshot(snapshot *MetricsSnapshot) error {
	return dm.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("metrics_snapshots"))
		snapshotData, err := json.Marshal(snapshot)
		if err != nil {
			return err
		}

		// Key format: tenant:granularity:timestamp:id
		key := fmt.Sprintf("%s:%s:%d:%s",
			snapshot.TenantID,
			snapshot.Granularity,
			snapshot.Timestamp.Unix(),
			snapshot.ID)

		return bucket.Put([]byte(key), snapshotData)
	})
}

func (dm *DatabaseManager) GetMetricsSnapshots(tenantID, granularity string, from, to time.Time) ([]*MetricsSnapshot, error) {
	var snapshots []*MetricsSnapshot

	err := dm.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("metrics_snapshots"))
		cursor := bucket.Cursor()

		// Seek to start of range
		startKey := fmt.Sprintf("%s:%s:%d:", tenantID, granularity, from.Unix())
		endKey := fmt.Sprintf("%s:%s:%d:", tenantID, granularity, to.Unix())

		for k, v := cursor.Seek([]byte(startKey)); k != nil && bytes.Compare(k, []byte(endKey)) <= 0; k, v = cursor.Next() {
			var snapshot MetricsSnapshot
			if err := json.Unmarshal(v, &snapshot); err != nil {
				continue
			}

			snapshots = append(snapshots, &snapshot)
		}

		return nil
	})

	return snapshots, err
}

func (dm *DatabaseManager) CleanupOldData(retentionDays int) error {
	cutoff := time.Now().AddDate(0, 0, -retentionDays)

	return dm.db.Update(func(tx *bbolt.Tx) error {
		// Cleanup old audit logs
		auditBucket := tx.Bucket([]byte("audit_logs"))
		cursor := auditBucket.Cursor()

		var keysToDelete [][]byte
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var log AuditLog
			if err := json.Unmarshal(v, &log); err != nil {
				continue
			}

			if log.Timestamp.Before(cutoff) {
				keysToDelete = append(keysToDelete, k)
			}
		}

		for _, key := range keysToDelete {
			auditBucket.Delete(key)
		}

		// Cleanup old metrics snapshots
		metricsBucket := tx.Bucket([]byte("metrics_snapshots"))
		cursor = metricsBucket.Cursor()

		keysToDelete = nil
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var snapshot MetricsSnapshot
			if err := json.Unmarshal(v, &snapshot); err != nil {
				continue
			}

			if snapshot.Timestamp.Before(cutoff) {
				keysToDelete = append(keysToDelete, k)
			}
		}

		for _, key := range keysToDelete {
			metricsBucket.Delete(key)
		}

		return nil
	})
}

func (dm *DatabaseManager) Close() error {
	return dm.db.Close()
}

// Update executes a function in a read-write transaction
func (dm *DatabaseManager) Update(fn func(*bbolt.Tx) error) error {
	return dm.db.Update(fn)
}

// View executes a function in a read-only transaction
func (dm *DatabaseManager) View(fn func(*bbolt.Tx) error) error {
	return dm.db.View(fn)
}

// Utility functions
func generateID() string {
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), randomString(8))
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
