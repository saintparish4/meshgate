// control-plane/database/database.go - Enhanced for Phase 2
package database

import (
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/saintparish4/meshgate/shared/models"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Database represents the database connection and operations
type Database struct {
	db   *sql.DB
	path string
}

// MigrationInfo represents information about a database migration
type MigrationInfo struct {
	Version   int
	Name      string
	AppliedAt *time.Time
	Checksum  string
}

// NewDatabase creates a new database connection
func NewDatabase(path string) (*Database, error) {
	db, err := sql.Open("sqlite3", path+"?_foreign_keys=on&_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	database := &Database{
		db:   db,
		path: path,
	}

	// Create migrations table
	if err := database.createMigrationsTable(); err != nil {
		return nil, fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Run migrations
	if err := database.RunMigrations(); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return database, nil
}

// Close closes the database connection
func (d *Database) Close() error {
	return d.db.Close()
}

// createMigrationsTable creates the migrations tracking table
func (d *Database) createMigrationsTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		checksum TEXT NOT NULL,
		applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	_, err := d.db.Exec(query)
	return err
}

// RunMigrations runs all pending database migrations
func (d *Database) RunMigrations() error {
	log.Println("Running database migrations...")

	// Get list of migration files
	files, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("failed to read migration files: %w", err)
	}

	// Sort migration files by version
	var migrations []string
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".sql") {
			migrations = append(migrations, file.Name())
		}
	}
	sort.Strings(migrations)

	// Get applied migrations
	appliedMigrations, err := d.getAppliedMigrations()
	if err != nil {
		return fmt.Errorf("failed to get applied migrations: %w", err)
	}

	// Apply pending migrations
	for _, migration := range migrations {
		version, name := parseMigrationFilename(migration)
		if version == 0 {
			log.Printf("Skipping invalid migration file: %s", migration)
			continue
		}

		// Check if migration is already applied
		if _, exists := appliedMigrations[version]; exists {
			continue
		}

		log.Printf("Applying migration %03d: %s", version, name)

		// Read migration content
		content, err := migrationFiles.ReadFile(filepath.Join("migrations", migration))
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", migration, err)
		}

		// Apply migration in transaction
		if err := d.applyMigration(version, name, string(content)); err != nil {
			return fmt.Errorf("failed to apply migration %s: %w", migration, err)
		}

		log.Printf("Successfully applied migration %03d: %s", version, name)
	}

	log.Println("Database migrations completed successfully")
	return nil
}

// getAppliedMigrations returns a map of applied migration versions
func (d *Database) getAppliedMigrations() (map[int]MigrationInfo, error) {
	query := "SELECT version, name, applied_at, checksum FROM schema_migrations"
	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	migrations := make(map[int]MigrationInfo)
	for rows.Next() {
		var info MigrationInfo
		err := rows.Scan(&info.Version, &info.Name, &info.AppliedAt, &info.Checksum)
		if err != nil {
			return nil, err
		}
		migrations[info.Version] = info
	}

	return migrations, rows.Err()
}

// applyMigration applies a single migration in a transaction
func (d *Database) applyMigration(version int, name, content string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Execute migration content
	_, err = tx.Exec(content)
	if err != nil {
		return err
	}

	// Record migration as applied
	checksum := calculateChecksum(content)
	_, err = tx.Exec(
		"INSERT INTO schema_migrations (version, name, checksum) VALUES (?, ?, ?)",
		version, name, checksum,
	)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// parseMigrationFilename extracts version and name from migration filename
func parseMigrationFilename(filename string) (int, string) {
	// Expected format: 001_initial.sql
	parts := strings.SplitN(filename, "_", 2)
	if len(parts) != 2 {
		return 0, ""
	}

	version, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, ""
	}

	name := strings.TrimSuffix(parts[1], ".sql")
	return version, name
}

// calculateChecksum calculates a simple checksum for migration content
func calculateChecksum(content string) string {
	// Simple checksum implementation
	hash := 0
	for _, char := range content {
		hash = hash*31 + int(char)
	}
	return fmt.Sprintf("%x", hash)
}

// Node operations

// CreateNode creates a new node in the database
func (d *Database) CreateNode(node *models.Node) error {
	query := `
	INSERT INTO nodes (
		id, tenant_id, name, public_key, ip_address, endpoint, 
		listen_port, status, metadata, tags
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := d.db.Exec(query,
		node.ID, node.TenantID, node.Name, node.PublicKey,
		node.IPAddress, node.Endpoint, node.ListenPort,
		node.Status, node.Metadata, node.Tags,
	)

	if err != nil {
		return fmt.Errorf("failed to create node: %w", err)
	}

	return nil
}

// GetNode retrieves a node by ID
func (d *Database) GetNode(id string) (*models.Node, error) {
	query := `
	SELECT id, tenant_id, name, public_key, ip_address, endpoint,
		   listen_port, status, last_seen, metadata, tags, created_at, updated_at
	FROM nodes WHERE id = ?`

	var node models.Node
	var lastSeen sql.NullTime

	err := d.db.QueryRow(query, id).Scan(
		&node.ID, &node.TenantID, &node.Name, &node.PublicKey,
		&node.IPAddress, &node.Endpoint, &node.ListenPort,
		&node.Status, &lastSeen, &node.Metadata, &node.Tags,
		&node.CreatedAt, &node.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("node not found")
		}
		return nil, fmt.Errorf("failed to get node: %w", err)
	}

	if lastSeen.Valid {
		node.LastSeen = &lastSeen.Time
	}

	// Load relationships
	if err := d.loadNodeRelationships(&node); err != nil {
		return nil, fmt.Errorf("failed to load node relationships: %w", err)
	}

	return &node, nil
}

// UpdateNode updates an existing node
func (d *Database) UpdateNode(node *models.Node) error {
	query := `
	UPDATE nodes SET 
		name = ?, endpoint = ?, listen_port = ?, status = ?,
		last_seen = ?, metadata = ?, tags = ?, updated_at = CURRENT_TIMESTAMP
	WHERE id = ?`

	_, err := d.db.Exec(query,
		node.Name, node.Endpoint, node.ListenPort, node.Status,
		node.LastSeen, node.Metadata, node.Tags, node.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update node: %w", err)
	}

	return nil
}

// DeleteNode deletes a node from the database
func (d *Database) DeleteNode(id string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete related records first due to foreign key constraints
	queries := []string{
		"DELETE FROM node_peers WHERE node_id = ? OR peer_node_id = ?",
		"DELETE FROM node_connections WHERE node_id = ? OR peer_node_id = ?",
		"DELETE FROM subnet_assignments WHERE node_id = ?",
		"DELETE FROM routing_tables WHERE node_id = ?",
		"DELETE FROM nodes WHERE id = ?",
	}

	for i, query := range queries {
		if i == len(queries)-1 {
			// Last query (delete node) only needs one parameter
			_, err = tx.Exec(query, id)
		} else if i >= len(queries)-3 {
			// subnet_assignments and routing_tables queries need one parameter
			_, err = tx.Exec(query, id)
		} else {
			// node_peers and node_connections queries need two parameters
			_, err = tx.Exec(query, id, id)
		}

		if err != nil {
			return fmt.Errorf("failed to delete node data: %w", err)
		}
	}

	return tx.Commit()
}

// ListNodes retrieves all nodes for a tenant
func (d *Database) ListNodes(tenantID string) ([]models.Node, error) {
	query := `
	SELECT id, tenant_id, name, public_key, ip_address, endpoint,
		   listen_port, status, last_seen, metadata, tags, created_at, updated_at
	FROM nodes WHERE tenant_id = ? ORDER BY created_at DESC`

	rows, err := d.db.Query(query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}
	defer rows.Close()

	var nodes []models.Node
	for rows.Next() {
		var node models.Node
		var lastSeen sql.NullTime

		err := rows.Scan(
			&node.ID, &node.TenantID, &node.Name, &node.PublicKey,
			&node.IPAddress, &node.Endpoint, &node.ListenPort,
			&node.Status, &lastSeen, &node.Metadata, &node.Tags,
			&node.CreatedAt, &node.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan node: %w", err)
		}

		if lastSeen.Valid {
			node.LastSeen = &lastSeen.Time
		}

		nodes = append(nodes, node)
	}

	return nodes, rows.Err()
}

// loadNodeRelationships loads peer and connection data for a node
func (d *Database) loadNodeRelationships(node *models.Node) error {
	// Load peers
	peerQuery := `
	SELECT id, node_id, peer_node_id, allowed_ips, persistent_keepalive,
		   created_at, updated_at
	FROM node_peers WHERE node_id = ?`

	rows, err := d.db.Query(peerQuery, node.ID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var peer models.NodePeer
		err := rows.Scan(
			&peer.ID, &peer.NodeID, &peer.PeerNodeID, &peer.AllowedIPs,
			&peer.PersistentKeepalive, &peer.CreatedAt, &peer.UpdatedAt,
		)
		if err != nil {
			return err
		}
		node.Peers = append(node.Peers, peer)
	}

	// Load connections
	connQuery := `
	SELECT id, node_id, peer_node_id, bytes_received, bytes_transmitted,
		   packets_received, packets_transmitted, last_handshake,
		   latency_ms, quality, created_at, updated_at
	FROM node_connections WHERE node_id = ?`

	rows, err = d.db.Query(connQuery, node.ID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var conn models.NodeConnection
		var lastHandshake sql.NullTime

		err := rows.Scan(
			&conn.ID, &conn.NodeID, &conn.PeerNodeID,
			&conn.BytesReceived, &conn.BytesTransmitted,
			&conn.PacketsReceived, &conn.PacketsTransmitted,
			&lastHandshake, &conn.Latency, &conn.Quality,
			&conn.CreatedAt, &conn.UpdatedAt,
		)
		if err != nil {
			return err
		}

		if lastHandshake.Valid {
			conn.LastHandshake = &lastHandshake.Time
		}

		node.Connections = append(node.Connections, conn)
	}

	return nil
}

// GetNodesByTenant retrieves all nodes for a tenant with their relationships
func (d *Database) GetNodesByTenant(tenantID string) ([]models.Node, error) {
	nodes, err := d.ListNodes(tenantID)
	if err != nil {
		return nil, err
	}

	// Load relationships for each node
	for i := range nodes {
		if err := d.loadNodeRelationships(&nodes[i]); err != nil {
			return nil, fmt.Errorf("failed to load relationships for node %s: %w", nodes[i].ID, err)
		}
	}

	return nodes, nil
}

// UpdateNodeConnectionStats updates connection statistics for a node
func (d *Database) UpdateNodeConnectionStats(stats *models.NodeConnection) error {
	query := `
	INSERT OR REPLACE INTO node_connections (
		id, node_id, peer_node_id, bytes_received, bytes_transmitted,
		packets_received, packets_transmitted, last_handshake,
		latency_ms, quality, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
		COALESCE((SELECT created_at FROM node_connections WHERE node_id = ? AND peer_node_id = ?), CURRENT_TIMESTAMP),
		CURRENT_TIMESTAMP)`

	_, err := d.db.Exec(query,
		stats.ID, stats.NodeID, stats.PeerNodeID, stats.BytesReceived,
		stats.BytesTransmitted, stats.PacketsReceived, stats.PacketsTransmitted,
		stats.LastHandshake, stats.Latency, stats.Quality,
		stats.NodeID, stats.PeerNodeID,
	)

	if err != nil {
		return fmt.Errorf("failed to update node connection stats: %w", err)
	}

	return nil
}

// Policy operations

// CreatePolicy creates a new policy in the database
func (d *Database) CreatePolicy(policy *models.Policy) error {
	query := `
	INSERT INTO policies (
		id, tenant_id, name, description, type, status, priority,
		rules, tags, created_by, expires_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := d.db.Exec(query,
		policy.ID, policy.TenantID, policy.Name, policy.Description,
		policy.Type, policy.Status, policy.Priority, policy.Rules,
		policy.Tags, policy.CreatedBy, policy.ExpiresAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	return nil
}

// GetPolicy retrieves a policy by ID
func (d *Database) GetPolicy(id string) (*models.Policy, error) {
	query := `
	SELECT id, tenant_id, name, description, type, status, priority,
		   rules, tags, created_by, created_at, updated_at, expires_at
	FROM policies WHERE id = ?`

	var policy models.Policy
	var expiresAt sql.NullTime

	err := d.db.QueryRow(query, id).Scan(
		&policy.ID, &policy.TenantID, &policy.Name, &policy.Description,
		&policy.Type, &policy.Status, &policy.Priority, &policy.Rules,
		&policy.Tags, &policy.CreatedBy, &policy.CreatedAt,
		&policy.UpdatedAt, &expiresAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("policy not found")
		}
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}

	if expiresAt.Valid {
		policy.ExpiresAt = &expiresAt.Time
	}

	// Load relationships
	if err := d.loadPolicyRelationships(&policy); err != nil {
		return nil, fmt.Errorf("failed to load policy relationships: %w", err)
	}

	return &policy, nil
}

// UpdatePolicy updates an existing policy
func (d *Database) UpdatePolicy(policy *models.Policy) error {
	query := `
	UPDATE policies SET 
		name = ?, description = ?, type = ?, status = ?, priority = ?,
		rules = ?, tags = ?, expires_at = ?, updated_at = CURRENT_TIMESTAMP
	WHERE id = ?`

	_, err := d.db.Exec(query,
		policy.Name, policy.Description, policy.Type, policy.Status,
		policy.Priority, policy.Rules, policy.Tags, policy.ExpiresAt,
		policy.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update policy: %w", err)
	}

	return nil
}

// DeletePolicy deletes a policy from the database
func (d *Database) DeletePolicy(id string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete related records first
	_, err = tx.Exec("DELETE FROM policy_assignments WHERE policy_id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete policy assignments: %w", err)
	}

	_, err = tx.Exec("DELETE FROM policy_audit_logs WHERE policy_id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete policy audit logs: %w", err)
	}

	_, err = tx.Exec("DELETE FROM policies WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	return tx.Commit()
}

// ListPolicies retrieves all policies for a tenant
func (d *Database) ListPolicies(tenantID string) ([]models.Policy, error) {
	query := `
	SELECT id, tenant_id, name, description, type, status, priority,
		   rules, tags, created_by, created_at, updated_at, expires_at
	FROM policies WHERE tenant_id = ? ORDER BY priority ASC, created_at DESC`

	rows, err := d.db.Query(query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}
	defer rows.Close()

	var policies []models.Policy
	for rows.Next() {
		var policy models.Policy
		var expiresAt sql.NullTime

		err := rows.Scan(
			&policy.ID, &policy.TenantID, &policy.Name, &policy.Description,
			&policy.Type, &policy.Status, &policy.Priority, &policy.Rules,
			&policy.Tags, &policy.CreatedBy, &policy.CreatedAt,
			&policy.UpdatedAt, &expiresAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan policy: %w", err)
		}

		if expiresAt.Valid {
			policy.ExpiresAt = &expiresAt.Time
		}

		policies = append(policies, policy)
	}

	return policies, rows.Err()
}

// loadPolicyRelationships loads assignments and audit logs for a policy
func (d *Database) loadPolicyRelationships(policy *models.Policy) error {
	// Load assignments
	assignQuery := `
	SELECT id, policy_id, target_type, target_id, created_at
	FROM policy_assignments WHERE policy_id = ?`

	rows, err := d.db.Query(assignQuery, policy.ID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var assignment models.PolicyAssignment
		err := rows.Scan(
			&assignment.ID, &assignment.PolicyID, &assignment.TargetType,
			&assignment.TargetID, &assignment.CreatedAt,
		)
		if err != nil {
			return err
		}
		policy.Assignments = append(policy.Assignments, assignment)
	}

	return nil
}

// GetActivePoliciesForNode retrieves all active policies that apply to a node
func (d *Database) GetActivePoliciesForNode(nodeID string) ([]models.Policy, error) {
	query := `
	SELECT DISTINCT p.id, p.tenant_id, p.name, p.description, p.type, 
		   p.status, p.priority, p.rules, p.tags, p.created_by, 
		   p.created_at, p.updated_at, p.expires_at
	FROM policies p
	JOIN policy_assignments pa ON p.id = pa.policy_id
	JOIN nodes n ON (
		(pa.target_type = 'node' AND pa.target_id = n.id) OR
		(pa.target_type = 'tag' AND JSON_EXTRACT(n.tags, '$') LIKE '%' || pa.target_id || '%')
	)
	WHERE n.id = ? 
	  AND p.status = 'active'
	  AND (p.expires_at IS NULL OR p.expires_at > CURRENT_TIMESTAMP)
	ORDER BY p.priority ASC`

	rows, err := d.db.Query(query, nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get active policies for node: %w", err)
	}
	defer rows.Close()

	var policies []models.Policy
	for rows.Next() {
		var policy models.Policy
		var expiresAt sql.NullTime

		err := rows.Scan(
			&policy.ID, &policy.TenantID, &policy.Name, &policy.Description,
			&policy.Type, &policy.Status, &policy.Priority, &policy.Rules,
			&policy.Tags, &policy.CreatedBy, &policy.CreatedAt,
			&policy.UpdatedAt, &expiresAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan policy: %w", err)
		}

		if expiresAt.Valid {
			policy.ExpiresAt = &expiresAt.Time
		}

		policies = append(policies, policy)
	}

	return policies, rows.Err()
}

// RecordPolicyEvaluation records a policy evaluation result
func (d *Database) RecordPolicyEvaluation(evaluation *models.PolicyAuditLog) error {
	query := `
	INSERT INTO policy_audit_logs (
		id, policy_id, action, node_id, user_id, details, result
	) VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err := d.db.Exec(query,
		evaluation.ID, evaluation.PolicyID, evaluation.Action,
		evaluation.NodeID, evaluation.UserID, evaluation.Details,
		evaluation.Result,
	)

	if err != nil {
		return fmt.Errorf("failed to record policy evaluation: %w", err)
	}

	return nil
}

// Topology operations

// CreateTopology creates a new network topology
func (d *Database) CreateTopology(topology *models.NetworkTopology) error {
	query := `
	INSERT INTO network_topologies (
		id, tenant_id, name, description, type, configuration, 
		metrics, status
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := d.db.Exec(query,
		topology.ID, topology.TenantID, topology.Name, topology.Description,
		topology.Type, topology.Configuration, topology.Metrics,
		topology.Status,
	)

	if err != nil {
		return fmt.Errorf("failed to create topology: %w", err)
	}

	return nil
}

// GetTopology retrieves a topology by ID
func (d *Database) GetTopology(id string) (*models.NetworkTopology, error) {
	query := `
	SELECT id, tenant_id, name, description, type, configuration,
		   metrics, status, created_at, updated_at
	FROM network_topologies WHERE id = ?`

	var topology models.NetworkTopology

	err := d.db.QueryRow(query, id).Scan(
		&topology.ID, &topology.TenantID, &topology.Name, &topology.Description,
		&topology.Type, &topology.Configuration, &topology.Metrics,
		&topology.Status, &topology.CreatedAt, &topology.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("topology not found")
		}
		return nil, fmt.Errorf("failed to get topology: %w", err)
	}

	// Load relationships
	if err := d.loadTopologyRelationships(&topology); err != nil {
		return nil, fmt.Errorf("failed to load topology relationships: %w", err)
	}

	return &topology, nil
}

// UpdateTopology updates an existing topology
func (d *Database) UpdateTopology(topology *models.NetworkTopology) error {
	query := `
	UPDATE network_topologies SET 
		name = ?, description = ?, type = ?, configuration = ?,
		metrics = ?, status = ?, updated_at = CURRENT_TIMESTAMP
	WHERE id = ?`

	_, err := d.db.Exec(query,
		topology.Name, topology.Description, topology.Type,
		topology.Configuration, topology.Metrics, topology.Status,
		topology.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update topology: %w", err)
	}

	return nil
}

// loadTopologyRelationships loads links and subnets for a topology
func (d *Database) loadTopologyRelationships(topology *models.NetworkTopology) error {
	// Load links
	linkQuery := `
	SELECT id, topology_id, node_a_id, node_b_id, status, quality,
		   latency_ms, bandwidth_mbps, created_at, updated_at
	FROM topology_links WHERE topology_id = ?`

	rows, err := d.db.Query(linkQuery, topology.ID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var link models.TopologyLink
		err := rows.Scan(
			&link.ID, &link.TopologyID, &link.NodeAID, &link.NodeBID,
			&link.Status, &link.Quality, &link.Latency, &link.Bandwidth,
			&link.CreatedAt, &link.UpdatedAt,
		)
		if err != nil {
			return err
		}
		topology.Links = append(topology.Links, link)
	}

	// Load subnets
	subnetQuery := `
	SELECT id, topology_id, name, cidr, description, created_at, updated_at
	FROM network_subnets WHERE topology_id = ?`

	rows, err = d.db.Query(subnetQuery, topology.ID)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var subnet models.NetworkSubnet
		err := rows.Scan(
			&subnet.ID, &subnet.TopologyID, &subnet.Name,
			&subnet.CIDR, &subnet.Description, &subnet.CreatedAt, &subnet.UpdatedAt,
		)
		if err != nil {
			return err
		}
		topology.Subnets = append(topology.Subnets, subnet)
	}

	return nil
}

// CreateTopologyLink creates a new topology link
func (d *Database) CreateTopologyLink(link *models.TopologyLink) error {
	query := `
	INSERT INTO topology_links (
		id, topology_id, node_a_id, node_b_id, status, quality,
		latency_ms, bandwidth_mbps
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := d.db.Exec(query,
		link.ID, link.TopologyID, link.NodeAID, link.NodeBID,
		link.Status, link.Quality, link.Latency, link.Bandwidth,
	)

	if err != nil {
		return fmt.Errorf("failed to create topology link: %w", err)
	}

	return nil
}

// GetTopologyOverview retrieves topology overview statistics
func (d *Database) GetTopologyOverview(tenantID string) ([]map[string]interface{}, error) {
	query := `
	SELECT t.id, t.name, t.type, t.status,
		   COALESCE(node_count, 0) as node_count,
		   COALESCE(link_count, 0) as link_count,
		   COALESCE(avg_quality, 0) as avg_quality,
		   COALESCE(avg_latency, 0) as avg_latency,
		   COALESCE(total_cost, 0) as total_cost,
		   t.created_at, t.updated_at
	FROM network_topologies t
	LEFT JOIN topology_overview to ON t.id = to.id
	WHERE t.tenant_id = ?
	ORDER BY t.created_at DESC`

	rows, err := d.db.Query(query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get topology overview: %w", err)
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var id, name, topologyType, status string
		var nodeCount, linkCount int
		var avgQuality, avgLatency, totalCost float64
		var createdAt, updatedAt time.Time

		err := rows.Scan(
			&id, &name, &topologyType, &status, &nodeCount, &linkCount,
			&avgQuality, &avgLatency, &totalCost, &createdAt, &updatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan topology overview: %w", err)
		}

		result := map[string]interface{}{
			"id":          id,
			"name":        name,
			"type":        topologyType,
			"status":      status,
			"node_count":  nodeCount,
			"link_count":  linkCount,
			"avg_quality": avgQuality,
			"avg_latency": avgLatency,
			"total_cost":  totalCost,
			"created_at":  createdAt,
			"updated_at":  updatedAt,
		}

		results = append(results, result)
	}

	return results, rows.Err()
}

// CleanupExpiredData removes old audit logs and expired policies
func (d *Database) CleanupExpiredData() error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Clean up old audit logs (older than 90 days)
	_, err = tx.Exec(`
		DELETE FROM policy_audit_logs 
		WHERE created_at < datetime('now', '-90 days')
	`)
	if err != nil {
		return fmt.Errorf("failed to cleanup audit logs: %w", err)
	}

	// Clean up old mesh metrics (older than 30 days)
	_, err = tx.Exec(`
		DELETE FROM mesh_metrics 
		WHERE timestamp < datetime('now', '-30 days')
	`)
	if err != nil {
		return fmt.Errorf("failed to cleanup mesh metrics: %w", err)
	}

	// Archive expired policies
	_, err = tx.Exec(`
		UPDATE policies 
		SET status = 'archived', updated_at = CURRENT_TIMESTAMP
		WHERE expires_at IS NOT NULL 
		  AND expires_at < CURRENT_TIMESTAMP 
		  AND status = 'active'
	`)
	if err != nil {
		return fmt.Errorf("failed to archive expired policies: %w", err)
	}

	return tx.Commit()
}

// Health check
func (d *Database) HealthCheck() error {
	var result int
	err := d.db.QueryRow("SELECT 1").Scan(&result)
	if err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}
	return nil
}

// User operations
func (d *Database) CreateUser(user *User) error {
	query := `
	INSERT INTO users (
		id, email, password_hash, role, tenant_id, created_at, last_login
	) VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err := d.db.Exec(query,
		user.ID, user.Email, user.PasswordHash, user.Role,
		user.TenantID, user.CreatedAt, user.LastLogin,
	)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

func (d *Database) GetUserByEmail(email string) (*User, error) {
	query := `SELECT id, email, password_hash, role, tenant_id, created_at, last_login FROM users WHERE email = ?`

	var user User
	err := d.db.QueryRow(query, email).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.Role,
		&user.TenantID, &user.CreatedAt, &user.LastLogin,
	)

	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	return &user, nil
}

func (d *Database) UpdateUser(user *User) error {
	query := `
	UPDATE users SET 
		email = ?, password_hash = ?, role = ?, tenant_id = ?, 
		created_at = ?, last_login = ?
	WHERE id = ?`

	_, err := d.db.Exec(query,
		user.Email, user.PasswordHash, user.Role, user.TenantID,
		user.CreatedAt, user.LastLogin, user.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// Tenant operations
func (d *Database) CreateTenant(tenant *Tenant) error {
	query := `
	INSERT INTO tenants (
		id, name, domain, subnet_cidr, max_nodes, policy_mode, 
		heartbeat_interval, created_at, is_active, node_limit, used_nodes
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := d.db.Exec(query,
		tenant.ID, tenant.Name, tenant.Domain, tenant.Settings.SubnetCIDR,
		tenant.Settings.MaxNodes, tenant.Settings.PolicyMode,
		tenant.Settings.HeartbeatInterval, tenant.CreatedAt,
		tenant.IsActive, tenant.NodeLimit, tenant.UsedNodes,
	)

	if err != nil {
		return fmt.Errorf("failed to create tenant: %w", err)
	}

	return nil
}

func (d *Database) GetTenant(id string) (*Tenant, error) {
	query := `
	SELECT id, name, domain, subnet_cidr, max_nodes, policy_mode, 
		   heartbeat_interval, created_at, is_active, node_limit, used_nodes
	FROM tenants WHERE id = ?`

	var tenant Tenant
	err := d.db.QueryRow(query, id).Scan(
		&tenant.ID, &tenant.Name, &tenant.Domain, &tenant.Settings.SubnetCIDR,
		&tenant.Settings.MaxNodes, &tenant.Settings.PolicyMode,
		&tenant.Settings.HeartbeatInterval, &tenant.CreatedAt,
		&tenant.IsActive, &tenant.NodeLimit, &tenant.UsedNodes,
	)

	if err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	return &tenant, nil
}

func (d *Database) UpdateTenant(tenant *Tenant) error {
	query := `
	UPDATE tenants SET 
		name = ?, domain = ?, subnet_cidr = ?, max_nodes = ?, 
		policy_mode = ?, heartbeat_interval = ?, created_at = ?, 
		is_active = ?, node_limit = ?, used_nodes = ?
	WHERE id = ?`

	_, err := d.db.Exec(query,
		tenant.Name, tenant.Domain, tenant.Settings.SubnetCIDR,
		tenant.Settings.MaxNodes, tenant.Settings.PolicyMode,
		tenant.Settings.HeartbeatInterval, tenant.CreatedAt,
		tenant.IsActive, tenant.NodeLimit, tenant.UsedNodes, tenant.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update tenant: %w", err)
	}

	return nil
}

// Node operations using local Node type
func (d *Database) CreateLocalNode(node *Node) error {
	query := `
	INSERT INTO nodes (
		id, tenant_id, name, public_key, ip_address, status, 
		last_seen, created_at, metadata
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	metadataJSON, err := json.Marshal(node.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	_, err = d.db.Exec(query,
		node.ID, node.TenantID, node.Name, node.PublicKey,
		node.IPAddress, node.Status, node.LastSeen, node.CreatedAt, metadataJSON,
	)

	if err != nil {
		return fmt.Errorf("failed to create node: %w", err)
	}

	return nil
}

func (d *Database) GetLocalNode(id string) (*Node, error) {
	query := `
	SELECT id, tenant_id, name, public_key, ip_address, status, 
		   last_seen, created_at, metadata
	FROM nodes WHERE id = ?`

	var node Node
	var metadataJSON []byte
	err := d.db.QueryRow(query, id).Scan(
		&node.ID, &node.TenantID, &node.Name, &node.PublicKey,
		&node.IPAddress, &node.Status, &node.LastSeen, &node.CreatedAt, &metadataJSON,
	)

	if err != nil {
		return nil, fmt.Errorf("node not found: %w", err)
	}

	if metadataJSON != nil {
		if err := json.Unmarshal(metadataJSON, &node.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return &node, nil
}

func (d *Database) UpdateLocalNode(node *Node) error {
	query := `
	UPDATE nodes SET 
		tenant_id = ?, name = ?, public_key = ?, ip_address = ?, 
		status = ?, last_seen = ?, created_at = ?, metadata = ?
	WHERE id = ?`

	metadataJSON, err := json.Marshal(node.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	_, err = d.db.Exec(query,
		node.TenantID, node.Name, node.PublicKey, node.IPAddress,
		node.Status, node.LastSeen, node.CreatedAt, metadataJSON, node.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update node: %w", err)
	}

	return nil
}

func (d *Database) GetLocalNodesByTenant(tenantID string) ([]*Node, error) {
	query := `
	SELECT id, tenant_id, name, public_key, ip_address, status, 
		   last_seen, created_at, metadata
	FROM nodes WHERE tenant_id = ?`

	rows, err := d.db.Query(query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query nodes: %w", err)
	}
	defer rows.Close()

	var nodes []*Node
	for rows.Next() {
		var node Node
		var metadataJSON []byte
		err := rows.Scan(
			&node.ID, &node.TenantID, &node.Name, &node.PublicKey,
			&node.IPAddress, &node.Status, &node.LastSeen, &node.CreatedAt, &metadataJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan node: %w", err)
		}

		if metadataJSON != nil {
			if err := json.Unmarshal(metadataJSON, &node.Metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}

		nodes = append(nodes, &node)
	}

	return nodes, rows.Err()
}
