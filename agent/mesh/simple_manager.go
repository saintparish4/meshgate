package mesh

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// SimpleMeshManager provides a simplified interface for mesh management
// This version reduces complexity and makes it easier for LLMs to understand
type SimpleMeshManager struct {
	logger      *slog.Logger
	nodes       map[string]*MeshNode
	connections map[string]*MeshConnection
	segments    map[string]*NetworkSegment
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	config      *SimpleMeshConfig // Added config field
}

// SimpleMeshConfig holds basic configuration for the simple mesh manager
type SimpleMeshConfig struct {
	HeartbeatTimeout time.Duration `json:"heartbeat_timeout"`
	MaxNodes         int           `json:"max_nodes"`
	MaxConnections   int           `json:"max_connections"`
}

// NewSimpleMeshManager creates a new simplified mesh manager
func NewSimpleMeshManager(config *SimpleMeshConfig, logger *slog.Logger) *SimpleMeshManager {
	if config == nil {
		config = &SimpleMeshConfig{
			HeartbeatTimeout: 5 * time.Minute,
			MaxNodes:         1000,
			MaxConnections:   100,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &SimpleMeshManager{
		logger:      logger,
		nodes:       make(map[string]*MeshNode),
		connections: make(map[string]*MeshConnection),
		segments:    make(map[string]*NetworkSegment),
		ctx:         ctx,
		cancel:      cancel,
		config:      config,
	}
}

// Start begins the mesh management process
func (sm *SimpleMeshManager) Start() error {
	sm.logger.Info("Starting simple mesh manager")

	// Start background heartbeat monitoring
	go sm.monitorHeartbeats()

	return nil
}

// Stop stops the mesh management process
func (sm *SimpleMeshManager) Stop() error {
	sm.logger.Info("Stopping simple mesh manager")
	sm.cancel()
	return nil
}

// RegisterNode registers a new node in the mesh
func (sm *SimpleMeshManager) RegisterNode(node *MeshNode) error {
	if node == nil || node.ID == "" {
		return fmt.Errorf("invalid node")
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	existing, exists := sm.nodes[node.ID]

	if exists {
		// Update existing node
		existing.Name = node.Name
		existing.Endpoint = node.Endpoint
		existing.LastHeartbeat = now
		existing.Status = NodeOnline
		existing.Capabilities = node.Capabilities
		existing.Region = node.Region
		existing.Zone = node.Zone
		existing.UpdatedAt = now
		sm.logger.Debug("Updated existing node", "node_id", node.ID)
	} else {
		// Register new node
		node.Status = NodeOnline
		node.LastHeartbeat = now
		node.CreatedAt = now
		node.UpdatedAt = now
		sm.nodes[node.ID] = node
		sm.logger.Info("Registered new node", "node_id", node.ID)
	}

	return nil
}

// UnregisterNode removes a node from the mesh
func (sm *SimpleMeshManager) UnregisterNode(nodeID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.nodes[nodeID]; !exists {
		return fmt.Errorf("node not found: %s", nodeID)
	}

	// Remove all connections for this node
	connectionsToRemove := make([]string, 0)
	for connID, conn := range sm.connections {
		if conn.SourceNodeID == nodeID || conn.TargetNodeID == nodeID {
			connectionsToRemove = append(connectionsToRemove, connID)
		}
	}

	for _, connID := range connectionsToRemove {
		delete(sm.connections, connID)
	}

	delete(sm.nodes, nodeID)
	sm.logger.Info("Unregistered node", "node_id", nodeID)

	return nil
}

// UpdateNodeHeartbeat updates a node's heartbeat and statistics
func (sm *SimpleMeshManager) UpdateNodeHeartbeat(nodeID string, stats NodeStats) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	node, exists := sm.nodes[nodeID]
	if !exists {
		return fmt.Errorf("node not found: %s", nodeID)
	}

	node.LastHeartbeat = time.Now()
	node.Stats = stats
	node.Status = NodeOnline
	node.UpdatedAt = time.Now()

	return nil
}

// GetNode retrieves a node by ID
func (sm *SimpleMeshManager) GetNode(nodeID string) (*MeshNode, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	node, exists := sm.nodes[nodeID]
	return node, exists
}

// GetNodesBySegment gets all nodes in a specific segment
func (sm *SimpleMeshManager) GetNodesBySegment(segmentID string) []*MeshNode {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var nodes []*MeshNode
	for _, node := range sm.nodes {
		if node.SegmentID == segmentID {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// GetNodesByTenant gets all nodes for a specific tenant
func (sm *SimpleMeshManager) GetNodesByTenant(tenantID string) []*MeshNode {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var nodes []*MeshNode
	for _, node := range sm.nodes {
		if node.TenantID == tenantID {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

// GetOptimalTopologyForNode gets the optimal connections for a node
func (sm *SimpleMeshManager) GetOptimalTopologyForNode(nodeID string) ([]*MeshConnection, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Check if node exists
	if _, exists := sm.nodes[nodeID]; !exists {
		return nil, fmt.Errorf("node not found: %s", nodeID)
	}

	// Get all connections for this node
	var connections []*MeshConnection
	for _, conn := range sm.connections {
		if conn.SourceNodeID == nodeID || conn.TargetNodeID == nodeID {
			connections = append(connections, conn)
		}
	}

	return connections, nil
}

// CreateConnection creates a connection between two nodes
func (sm *SimpleMeshManager) CreateConnection(sourceNodeID, targetNodeID string, allowedIPs []string) (*MeshConnection, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Validate nodes exist
	if _, exists := sm.nodes[sourceNodeID]; !exists {
		return nil, fmt.Errorf("source node not found: %s", sourceNodeID)
	}
	if _, exists := sm.nodes[targetNodeID]; !exists {
		return nil, fmt.Errorf("target node not found: %s", targetNodeID)
	}

	// Check if connection already exists
	connectionID := fmt.Sprintf("%s-%s", sourceNodeID, targetNodeID)
	if _, exists := sm.connections[connectionID]; exists {
		return nil, fmt.Errorf("connection already exists")
	}

	// Create new connection
	connection := &MeshConnection{
		ID:           connectionID,
		SourceNodeID: sourceNodeID,
		TargetNodeID: targetNodeID,
		Status:       ConnectionActive,
		AllowedIPs:   allowedIPs,
		Metadata:     make(map[string]string),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	sm.connections[connectionID] = connection
	sm.logger.Info("Created connection", "connection_id", connectionID)

	return connection, nil
}

// RemoveConnection removes a connection
func (sm *SimpleMeshManager) RemoveConnection(connectionID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if _, exists := sm.connections[connectionID]; !exists {
		return fmt.Errorf("connection not found: %s", connectionID)
	}

	delete(sm.connections, connectionID)
	sm.logger.Info("Removed connection", "connection_id", connectionID)

	return nil
}

// CreateSegment creates a new network segment
func (sm *SimpleMeshManager) CreateSegment(segment *NetworkSegment) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if segment == nil || segment.ID == "" {
		return fmt.Errorf("invalid segment")
	}

	if _, exists := sm.segments[segment.ID]; exists {
		return fmt.Errorf("segment already exists: %s", segment.ID)
	}

	segment.CreatedAt = time.Now()
	segment.UpdatedAt = time.Now()
	sm.segments[segment.ID] = segment

	sm.logger.Info("Created segment", "segment_id", segment.ID)
	return nil
}

// GetSegment retrieves a segment by ID
func (sm *SimpleMeshManager) GetSegment(segmentID string) (*NetworkSegment, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	segment, exists := sm.segments[segmentID]
	return segment, exists
}

// GetStats returns basic statistics about the mesh
func (sm *SimpleMeshManager) GetStats() map[string]interface{} {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	onlineNodes := 0
	for _, node := range sm.nodes {
		if node.Status == NodeOnline {
			onlineNodes++
		}
	}

	activeConnections := 0
	for _, conn := range sm.connections {
		if conn.Status == ConnectionActive {
			activeConnections++
		}
	}

	return map[string]interface{}{
		"total_nodes":        len(sm.nodes),
		"online_nodes":       onlineNodes,
		"total_connections":  len(sm.connections),
		"active_connections": activeConnections,
		"total_segments":     len(sm.segments),
		"timestamp":          time.Now(),
	}
}

// monitorHeartbeats monitors node heartbeats and marks offline nodes
func (sm *SimpleMeshManager) monitorHeartbeats() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			sm.checkHeartbeats()
		}
	}
}

// checkHeartbeats checks all node heartbeats and marks offline nodes
func (sm *SimpleMeshManager) checkHeartbeats() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	timeout := sm.config.HeartbeatTimeout // Use configured timeout

	for nodeID, node := range sm.nodes {
		if now.Sub(node.LastHeartbeat) > timeout {
			if node.Status != NodeOffline {
				node.Status = NodeOffline
				node.UpdatedAt = now
				sm.logger.Warn("Node marked offline", "node_id", nodeID)
			}
		}
	}
}
