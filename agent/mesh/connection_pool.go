package mesh

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ConnectionPoolConfig holds configuration for the connection pool
type ConnectionPoolConfig struct {
	MaxConnections      int           `json:"max_connections"`
	MinConnections      int           `json:"min_connections"`
	MaxIdleTime         time.Duration `json:"max_idle_time"`
	ConnectionTimeout   time.Duration `json:"connection_timeout"`
	EnableReuse         bool          `json:"enable_reuse"`
	MaxReuseCount       int           `json:"max_reuse_count"`
	HealthCheckInterval time.Duration `json:"health_check_interval"`
}

// PooledConnection represents a connection in the pool
type PooledConnection struct {
	ID           string
	SourceNodeID string
	TargetNodeID string
	Connection   *MeshConnection
	Status       ConnectionStatus
	CreatedAt    time.Time
	LastUsed     time.Time
	UseCount     int
	IsActive     bool
	HealthScore  float64
	Metadata     map[string]string
}

// ConnectionPool manages a pool of mesh connections
type ConnectionPool struct {
	config      *ConnectionPoolConfig
	logger      *slog.Logger
	connections map[string]*PooledConnection
	available   chan *PooledConnection
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(config *ConnectionPoolConfig, logger *slog.Logger) *ConnectionPool {
	if config == nil {
		config = &ConnectionPoolConfig{
			MaxConnections:      200, // Support 100+ concurrent connections
			MinConnections:      10,
			MaxIdleTime:         300 * time.Second,
			ConnectionTimeout:   30 * time.Second,
			EnableReuse:         true,
			MaxReuseCount:       100,
			HealthCheckInterval: 60 * time.Second,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	pool := &ConnectionPool{
		config:      config,
		logger:      logger,
		connections: make(map[string]*PooledConnection),
		available:   make(chan *PooledConnection, config.MaxConnections),
		ctx:         ctx,
		cancel:      cancel,
	}

	return pool
}

// Start begins the connection pool
func (cp *ConnectionPool) Start() error {
	cp.logger.Info("Starting connection pool", "max_connections", cp.config.MaxConnections)

	// Start background services
	go cp.healthCheckLoop()
	go cp.cleanupLoop()

	cp.logger.Info("Connection pool started")
	return nil
}

// Stop stops the connection pool
func (cp *ConnectionPool) Stop() error {
	cp.logger.Info("Stopping connection pool")
	cp.cancel()

	// Close all connections
	cp.mu.Lock()
	for _, conn := range cp.connections {
		cp.closeConnection(conn)
	}
	cp.mu.Unlock()

	cp.logger.Info("Connection pool stopped")
	return nil
}

// GetConnection gets a connection from the pool
func (cp *ConnectionPool) GetConnection(sourceNodeID, targetNodeID string) (*PooledConnection, error) {
	// First, try to find an existing connection
	cp.mu.RLock()
	for _, conn := range cp.connections {
		if conn.SourceNodeID == sourceNodeID &&
			conn.TargetNodeID == targetNodeID &&
			conn.IsActive &&
			conn.Status == ConnectionActive {
			cp.mu.RUnlock()
			return cp.reuseConnection(conn), nil
		}
	}
	cp.mu.RUnlock()

	// Create a new connection if pool is not full
	if cp.getActiveConnectionCount() < cp.config.MaxConnections {
		return cp.createNewConnection(sourceNodeID, targetNodeID)
	}

	// Wait for an available connection
	select {
	case conn := <-cp.available:
		return cp.reuseConnection(conn), nil
	case <-time.After(cp.config.ConnectionTimeout):
		return nil, fmt.Errorf("timeout waiting for available connection")
	case <-cp.ctx.Done():
		return nil, fmt.Errorf("connection pool stopped")
	}
}

// ReturnConnection returns a connection to the pool
func (cp *ConnectionPool) ReturnConnection(conn *PooledConnection) {
	if conn == nil {
		return
	}

	cp.mu.Lock()
	defer cp.mu.Unlock()

	// Update connection stats
	conn.LastUsed = time.Now()
	conn.UseCount++

	// Check if connection should be reused
	if cp.config.EnableReuse &&
		conn.UseCount < cp.config.MaxReuseCount &&
		conn.IsActive &&
		conn.Status == ConnectionActive {

		// Return to available pool
		select {
		case cp.available <- conn:
			cp.logger.Debug("Connection returned to pool", "connection_id", conn.ID)
		default:
			// Pool is full, close the connection
			cp.closeConnection(conn)
		}
	} else {
		// Close connection that can't be reused
		cp.closeConnection(conn)
	}
}

// createNewConnection creates a new connection
func (cp *ConnectionPool) createNewConnection(sourceNodeID, targetNodeID string) (*PooledConnection, error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	// Create mesh connection
	meshConn := &MeshConnection{
		ID:           generateConnectionID(),
		SourceNodeID: sourceNodeID,
		TargetNodeID: targetNodeID,
		Status:       ConnectionActive,
		Quality:      ConnectionQuality{Reliability: 1.0},
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		Metadata:     make(map[string]string),
	}

	// Create pooled connection
	pooledConn := &PooledConnection{
		ID:           meshConn.ID,
		SourceNodeID: sourceNodeID,
		TargetNodeID: targetNodeID,
		Connection:   meshConn,
		Status:       ConnectionActive,
		CreatedAt:    time.Now(),
		LastUsed:     time.Now(),
		UseCount:     1,
		IsActive:     true,
		HealthScore:  1.0,
		Metadata:     make(map[string]string),
	}

	// Add to pool
	cp.connections[pooledConn.ID] = pooledConn

	cp.logger.Info("New connection created",
		"connection_id", pooledConn.ID,
		"source", sourceNodeID,
		"target", targetNodeID)

	return pooledConn, nil
}

// reuseConnection reuses an existing connection
func (cp *ConnectionPool) reuseConnection(conn *PooledConnection) *PooledConnection {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	conn.LastUsed = time.Now()
	conn.UseCount++
	conn.Connection.UpdatedAt = time.Now()

	cp.logger.Debug("Connection reused",
		"connection_id", conn.ID,
		"use_count", conn.UseCount)

	return conn
}

// closeConnection closes a connection
func (cp *ConnectionPool) closeConnection(conn *PooledConnection) {
	if conn == nil {
		return
	}

	conn.IsActive = false
	conn.Status = ConnectionShuttingDown
	conn.Connection.Status = ConnectionShuttingDown

	delete(cp.connections, conn.ID)

	cp.logger.Info("Connection closed",
		"connection_id", conn.ID,
		"total_uses", conn.UseCount)
}

// healthCheckLoop runs the health check loop
func (cp *ConnectionPool) healthCheckLoop() {
	ticker := time.NewTicker(cp.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-cp.ctx.Done():
			return
		case <-ticker.C:
			cp.performHealthChecks()
		}
	}
}

// cleanupLoop runs the cleanup loop
func (cp *ConnectionPool) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-cp.ctx.Done():
			return
		case <-ticker.C:
			cp.cleanupIdleConnections()
		}
	}
}

// performHealthChecks performs health checks on all connections
func (cp *ConnectionPool) performHealthChecks() {
	cp.mu.RLock()
	connections := make([]*PooledConnection, 0, len(cp.connections))
	for _, conn := range cp.connections {
		connections = append(connections, conn)
	}
	cp.mu.RUnlock()

	for _, conn := range connections {
		cp.checkConnectionHealth(conn)
	}
}

// checkConnectionHealth checks the health of a specific connection
func (cp *ConnectionPool) checkConnectionHealth(conn *PooledConnection) {
	// In a real implementation, you would perform actual health checks
	// For now, simulate health check based on age and use count

	age := time.Since(conn.CreatedAt)
	lastUsed := time.Since(conn.LastUsed)

	// Calculate health score based on various factors
	healthScore := 1.0

	// Reduce score based on age
	if age > 24*time.Hour {
		healthScore *= 0.8
	}

	// Reduce score based on use count
	if conn.UseCount > 50 {
		healthScore *= 0.9
	}

	// Reduce score based on idle time
	if lastUsed > cp.config.MaxIdleTime {
		healthScore *= 0.7
	}

	conn.HealthScore = healthScore

	// Mark as inactive if health is too low
	if healthScore < 0.3 {
		cp.mu.Lock()
		conn.IsActive = false
		conn.Status = ConnectionFailed
		cp.mu.Unlock()

		cp.logger.Warn("Connection health check failed",
			"connection_id", conn.ID,
			"health_score", healthScore)
	}
}

// cleanupIdleConnections removes idle connections
func (cp *ConnectionPool) cleanupIdleConnections() {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	now := time.Now()
	var toRemove []string

	for id, conn := range cp.connections {
		// Remove connections that have been idle too long
		if now.Sub(conn.LastUsed) > cp.config.MaxIdleTime {
			toRemove = append(toRemove, id)
		}

		// Remove connections that have been used too many times
		if conn.UseCount > cp.config.MaxReuseCount {
			toRemove = append(toRemove, id)
		}
	}

	for _, id := range toRemove {
		cp.closeConnection(cp.connections[id])
	}

	if len(toRemove) > 0 {
		cp.logger.Info("Cleaned up idle connections", "count", len(toRemove))
	}
}

// getActiveConnectionCount returns the number of active connections
func (cp *ConnectionPool) getActiveConnectionCount() int {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	count := 0
	for _, conn := range cp.connections {
		if conn.IsActive {
			count++
		}
	}
	return count
}

// GetStats returns connection pool statistics
func (cp *ConnectionPool) GetStats() map[string]interface{} {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	var activeCount, idleCount, failedCount int
	var totalUses int64

	for _, conn := range cp.connections {
		totalUses += int64(conn.UseCount)
		switch conn.Status {
		case ConnectionActive:
			if conn.IsActive {
				activeCount++
			} else {
				idleCount++
			}
		case ConnectionFailed:
			failedCount++
		}
	}

	return map[string]interface{}{
		"total_connections":  len(cp.connections),
		"active_connections": activeCount,
		"idle_connections":   idleCount,
		"failed_connections": failedCount,
		"max_connections":    cp.config.MaxConnections,
		"total_uses":         totalUses,
		"enable_reuse":       cp.config.EnableReuse,
		"max_reuse_count":    cp.config.MaxReuseCount,
	}
}

// generateConnectionID generates a unique connection ID
func generateConnectionID() string {
	return fmt.Sprintf("conn_%d", time.Now().UnixNano())
}
