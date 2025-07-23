package mesh

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// NetworkSegment represents a logical network segment in the mesh
type NetworkSegment struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	CIDR      string            `json:"cidr"`
	TenantID  string            `json:"tenant_id"`
	Policies  []string          `json:"policies"`
	Metadata  map[string]string `json:"metadata"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// MeshNode represents a node in the mesh network
type MeshNode struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	TenantID        string            `json:"tenant_id"`
	PublicKey       string            `json:"public_key"`
	IPAddress       string            `json:"ip_address"`
	Endpoint        string            `json:"endpoint"`
	Status          NodeStatus        `json:"status"`
	LastHeartbeat   time.Time         `json:"last_heartbeat"`
	Capabilities    []string          `json:"capabilities"`
	Region          string            `json:"region"`
	Zone            string            `json:"zone"`
	SegmentID       string            `json:"segment_id"`
	ConnectionCount int               `json:"connection_count"`
	Stats           NodeStats         `json:"stats"`
	Metadata        map[string]string `json:"metadata"`
	CreatedAt       time.Time         `json:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at"`
}

// NodeStatus represents the status of a mesh node
type NodeStatus int

const (
	NodeOnline NodeStatus = iota
	NodeOffline
	NodeConnecting
	NodeDegraded
	NodeMaintenance
)

// NodeStats holds statistics for a mesh node
type NodeStats struct {
	BytesReceived      int64     `json:"bytes_received"`
	BytesTransmitted   int64     `json:"bytes_transmitted"`
	PacketsReceived    int64     `json:"packets_received"`
	PacketsTransmitted int64     `json:"packets_transmitted"`
	ActivePeers        int       `json:"active_peers"`
	Uptime             int64     `json:"uptime"`
	LastUpdate         time.Time `json:"last_update"`
}

// MeshConnection represents a connection between two nodes
type MeshConnection struct {
	ID           string            `json:"id"`
	SourceNodeID string            `json:"source_node_id"`
	TargetNodeID string            `json:"target_node_id"`
	Status       ConnectionStatus  `json:"status"`
	Quality      ConnectionQuality `json:"quality"`
	AllowedIPs   []string          `json:"allowed_ips"`
	PresharedKey string            `json:"preshared_key,omitempty"`
	Metadata     map[string]string `json:"metadata"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// MeshManagerConfig holds configuration for the mesh manager
type MeshManagerConfig struct {
	HeartbeatTimeout         time.Duration `json:"heartbeat_timeout"`
	TopologyUpdateInterval   time.Duration `json:"topology_update_interval"`
	MaxNodesPerSegment       int           `json:"max_nodes_per_segment"`
	MaxConnectionsPerNode    int           `json:"max_connections_per_node"`
	MaxConcurrentConnections int           `json:"max_concurrent_connections"`
	EnableAutoSegmentation   bool          `json:"enable_auto_segmentation"`
	EnableLoadBalancing      bool          `json:"enable_load_balancing"`
	EnableFailover           bool          `json:"enable_failover"`
	EnableNATTraversal       bool          `json:"enable_nat_traversal"`
	DefaultTopologyType      TopologyType  `json:"default_topology_type"`
	ConnectionPoolSize       int           `json:"connection_pool_size"`
	EnableConnectionReuse    bool          `json:"enable_connection_reuse"`
	MaxRetryAttempts         int           `json:"max_retry_attempts"`
	RetryBackoffMultiplier   float64       `json:"retry_backoff_multiplier"`
}

// MeshManager manages the global mesh network state
type MeshManager struct {
	config      *MeshManagerConfig
	logger      *slog.Logger
	nodes       map[string]*MeshNode
	connections map[string]*MeshConnection
	segments    map[string]*NetworkSegment
	callbacks   []MeshCallback
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc

	// Enhanced components for 100+ concurrent connections
	natTraversal   *NATTraversal
	failoverMgr    *FailoverManager
	connectionPool *ConnectionPool
	loadBalancer   *LoadBalancer
}

// MeshCallback is called when mesh events occur
type MeshCallback func(event MeshEvent, data interface{})

// MeshEvent represents different mesh lifecycle events
type MeshEvent int

const (
	NodeJoined MeshEvent = iota
	NodeLeft
	NodeUpdated
	ConnectionCreated
	ConnectionRemoved
	TopologyChanged
	SegmentCreated
	SegmentUpdated
)

// NewMeshManager creates a new mesh manager
func NewMeshManager(config *MeshManagerConfig, logger *slog.Logger) *MeshManager {
	if config == nil {
		config = &MeshManagerConfig{
			HeartbeatTimeout:         30 * time.Second,
			TopologyUpdateInterval:   60 * time.Second,
			MaxNodesPerSegment:       100,
			MaxConnectionsPerNode:    50,
			MaxConcurrentConnections: 200, // Support 100+ concurrent connections
			EnableAutoSegmentation:   true,
			EnableLoadBalancing:      true,
			EnableFailover:           true,
			EnableNATTraversal:       true,
			DefaultTopologyType:      TopologyHybrid,
			ConnectionPoolSize:       200,
			EnableConnectionReuse:    true,
			MaxRetryAttempts:         3,
			RetryBackoffMultiplier:   2.0,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create enhanced components
	natConfig := &NATTraversalConfig{
		STUNServers: []string{
			"stun:stun.l.google.com:19302",
			"stun:stun1.l.google.com:19302",
		},
		DiscoveryInterval:  30 * time.Second,
		KeepAliveInterval:  60 * time.Second,
		MaxRetries:         3,
		Timeout:            10 * time.Second,
		EnableRelay:        true,
		EnableHolePunching: true,
	}

	failoverConfig := &FailoverConfig{
		HealthCheckInterval:    30 * time.Second,
		FailoverTimeout:        10 * time.Second,
		RecoveryTimeout:        60 * time.Second,
		MaxFailoverAttempts:    3,
		EnableAutoRecovery:     true,
		LoadBalancingEnabled:   true,
		MaxConcurrentFailovers: 10,
		PriorityBasedRouting:   true,
	}

	poolConfig := &ConnectionPoolConfig{
		MaxConnections:      config.MaxConcurrentConnections,
		MinConnections:      10,
		MaxIdleTime:         300 * time.Second,
		ConnectionTimeout:   30 * time.Second,
		EnableReuse:         config.EnableConnectionReuse,
		MaxReuseCount:       100,
		HealthCheckInterval: 60 * time.Second,
	}

	lbConfig := &LoadBalancerConfig{
		Strategy:                StrategyRoundRobin,
		HealthCheckInterval:     30 * time.Second,
		MaxRetries:              3,
		RetryTimeout:            5 * time.Second,
		EnableStickySessions:    false,
		StickySessionTimeout:    300 * time.Second,
		MaxConnectionsPerNode:   config.MaxConnectionsPerNode,
		EnableCircuitBreaker:    true,
		CircuitBreakerThreshold: 5,
	}

	return &MeshManager{
		config:         config,
		logger:         logger,
		nodes:          make(map[string]*MeshNode),
		connections:    make(map[string]*MeshConnection),
		segments:       make(map[string]*NetworkSegment),
		callbacks:      make([]MeshCallback, 0),
		ctx:            ctx,
		cancel:         cancel,
		natTraversal:   NewNATTraversal(natConfig, logger),
		failoverMgr:    NewFailoverManager(failoverConfig, logger),
		connectionPool: NewConnectionPool(poolConfig, logger),
		loadBalancer:   NewLoadBalancer(lbConfig, logger),
	}
}

// Start begins the mesh management process
func (mm *MeshManager) Start() error {
	mm.logger.Info("Starting mesh manager",
		"heartbeat_timeout", mm.config.HeartbeatTimeout,
		"max_nodes_per_segment", mm.config.MaxNodesPerSegment,
		"max_concurrent_connections", mm.config.MaxConcurrentConnections)

	// Start enhanced components
	if mm.config.EnableNATTraversal {
		if err := mm.natTraversal.Start(); err != nil {
			return fmt.Errorf("failed to start NAT traversal: %w", err)
		}
	}

	if mm.config.EnableFailover {
		if err := mm.failoverMgr.Start(); err != nil {
			return fmt.Errorf("failed to start failover manager: %w", err)
		}
	}

	if err := mm.connectionPool.Start(); err != nil {
		return fmt.Errorf("failed to start connection pool: %w", err)
	}

	if mm.config.EnableLoadBalancing {
		if err := mm.loadBalancer.Start(); err != nil {
			return fmt.Errorf("failed to start load balancer: %w", err)
		}
	}

	// Start background processes
	go mm.heartbeatMonitor()
	go mm.topologyOptimizer()
	go mm.statisticsCollector()

	mm.logger.Info("Mesh manager started with enhanced capabilities")
	return nil
}

// Stop stops the mesh management process
func (mm *MeshManager) Stop() error {
	mm.logger.Info("Stopping mesh manager")

	// Stop enhanced components
	if mm.config.EnableNATTraversal {
		if err := mm.natTraversal.Stop(); err != nil {
			mm.logger.Warn("Failed to stop NAT traversal", "error", err)
		}
	}

	if mm.config.EnableFailover {
		if err := mm.failoverMgr.Stop(); err != nil {
			mm.logger.Warn("Failed to stop failover manager", "error", err)
		}
	}

	if err := mm.connectionPool.Stop(); err != nil {
		mm.logger.Warn("Failed to stop connection pool", "error", err)
	}

	if mm.config.EnableLoadBalancing {
		if err := mm.loadBalancer.Stop(); err != nil {
			mm.logger.Warn("Failed to stop load balancer", "error", err)
		}
	}

	mm.cancel()
	mm.logger.Info("Mesh manager stopped")
	return nil
}

// RegisterNode registers a new node in the mesh
func (mm *MeshManager) RegisterNode(node *MeshNode) error {
	if node == nil || node.ID == "" {
		return fmt.Errorf("invalid node")
	}

	mm.mu.Lock()
	defer mm.mu.Unlock()

	now := time.Now()
	existing, exists := mm.nodes[node.ID]

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
		mm.notifyCallbacks(NodeUpdated, existing)
		mm.logger.Debug("Updated existing node", "node_id", node.ID)
	} else {
		// Register new node
		node.Status = NodeOnline
		node.LastHeartbeat = now
		node.CreatedAt = now
		node.UpdatedAt = now

		// Auto-assign to segment if enabled
		if mm.config.EnableAutoSegmentation {
			if err := mm.autoAssignSegment(node); err != nil {
				mm.logger.Warn("Failed to auto-assign segment",
					"node_id", node.ID, "error", err)
			}
		}

		mm.nodes[node.ID] = node
		mm.notifyCallbacks(NodeJoined, node)
		mm.logger.Info("Registered new node",
			"node_id", node.ID,
			"segment_id", node.SegmentID)
	}

	return nil
}

// UnregisterNode removes a node from the mesh
func (mm *MeshManager) UnregisterNode(nodeID string) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	node, exists := mm.nodes[nodeID]
	if !exists {
		return fmt.Errorf("node not found: %s", nodeID)
	}

	// Remove all connections for this node
	connectionsToRemove := make([]string, 0)
	for connID, conn := range mm.connections {
		if conn.SourceNodeID == nodeID || conn.TargetNodeID == nodeID {
			connectionsToRemove = append(connectionsToRemove, connID)
		}
	}

	for _, connID := range connectionsToRemove {
		delete(mm.connections, connID)
	}

	delete(mm.nodes, nodeID)
	mm.notifyCallbacks(NodeLeft, node)
	mm.logger.Info("Unregistered node",
		"node_id", nodeID,
		"removed_connections", len(connectionsToRemove))

	return nil
}

// UpdateNodeHeartbeat updates the heartbeat timestamp for a node
func (mm *MeshManager) UpdateNodeHeartbeat(nodeID string, stats NodeStats) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	node, exists := mm.nodes[nodeID]
	if !exists {
		return fmt.Errorf("node not found: %s", nodeID)
	}

	node.LastHeartbeat = time.Now()
	node.Stats = stats
	node.Status = NodeOnline
	node.UpdatedAt = time.Now()

	return nil
}

// GetNode returns a specific node
func (mm *MeshManager) GetNode(nodeID string) (*MeshNode, bool) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	node, exists := mm.nodes[nodeID]
	if exists {
		nodeCopy := *node
		return &nodeCopy, true
	}
	return nil, false
}

// GetNodesBySegment returns all nodes in a specific segment
func (mm *MeshManager) GetNodesBySegment(segmentID string) []*MeshNode {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	nodes := make([]*MeshNode, 0)
	for _, node := range mm.nodes {
		if node.SegmentID == segmentID {
			nodeCopy := *node
			nodes = append(nodes, &nodeCopy)
		}
	}

	return nodes
}

// GetNodesByTenant returns all nodes for a specific tenant
func (mm *MeshManager) GetNodesByTenant(tenantID string) []*MeshNode {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	nodes := make([]*MeshNode, 0)
	for _, node := range mm.nodes {
		if node.TenantID == tenantID {
			nodeCopy := *node
			nodes = append(nodes, &nodeCopy)
		}
	}

	return nodes
}

// GetOptimalTopologyForNode calculates optimal topology for a specific node
func (mm *MeshManager) GetOptimalTopologyForNode(nodeID string) ([]*MeshConnection, error) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	node, exists := mm.nodes[nodeID]
	if !exists {
		return nil, fmt.Errorf("node not found: %s", nodeID)
	}

	// Get all nodes in the same segment
	candidateNodes := make([]*MeshNode, 0)
	for _, candidate := range mm.nodes {
		if candidate.ID != nodeID &&
			candidate.SegmentID == node.SegmentID &&
			candidate.Status == NodeOnline {
			candidateNodes = append(candidateNodes, candidate)
		}
	}

	// Calculate optimal connections based on topology type
	connections := mm.calculateOptimalConnections(node, candidateNodes)

	return connections, nil
}

// CreateConnection creates a new connection between two nodes
func (mm *MeshManager) CreateConnection(sourceNodeID, targetNodeID string, allowedIPs []string) (*MeshConnection, error) {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	// Validate nodes exist
	sourceNode, exists := mm.nodes[sourceNodeID]
	if !exists {
		return nil, fmt.Errorf("source node not found: %s", sourceNodeID)
	}

	targetNode, exists := mm.nodes[targetNodeID]
	if !exists {
		return nil, fmt.Errorf("target node not found: %s", targetNodeID)
	}

	// Check if connection already exists
	connID := fmt.Sprintf("%s-%s", sourceNodeID, targetNodeID)
	if _, exists := mm.connections[connID]; exists {
		return nil, fmt.Errorf("connection already exists")
	}

	// Create connection
	connection := &MeshConnection{
		ID:           connID,
		SourceNodeID: sourceNodeID,
		TargetNodeID: targetNodeID,
		Status:       ConnectionConnecting,
		AllowedIPs:   allowedIPs,
		Metadata:     make(map[string]string),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	mm.connections[connID] = connection

	// Update connection counts
	sourceNode.ConnectionCount++
	targetNode.ConnectionCount++

	mm.notifyCallbacks(ConnectionCreated, connection)
	mm.logger.Info("Created connection",
		"connection_id", connID,
		"source", sourceNodeID,
		"target", targetNodeID)

	return connection, nil
}

// RemoveConnection removes a connection between two nodes
func (mm *MeshManager) RemoveConnection(connectionID string) error {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	connection, exists := mm.connections[connectionID]
	if !exists {
		return fmt.Errorf("connection not found: %s", connectionID)
	}

	// Update connection counts
	if sourceNode, exists := mm.nodes[connection.SourceNodeID]; exists {
		sourceNode.ConnectionCount--
	}
	if targetNode, exists := mm.nodes[connection.TargetNodeID]; exists {
		targetNode.ConnectionCount--
	}

	delete(mm.connections, connectionID)
	mm.notifyCallbacks(ConnectionRemoved, connection)
	mm.logger.Info("Removed connection", "connection_id", connectionID)

	return nil
}

// CreateSegment creates a new network segment
func (mm *MeshManager) CreateSegment(segment *NetworkSegment) error {
	if segment == nil || segment.ID == "" {
		return fmt.Errorf("invalid segment")
	}

	mm.mu.Lock()
	defer mm.mu.Unlock()

	if _, exists := mm.segments[segment.ID]; exists {
		return fmt.Errorf("segment already exists: %s", segment.ID)
	}

	segment.CreatedAt = time.Now()
	segment.UpdatedAt = time.Now()
	mm.segments[segment.ID] = segment

	mm.notifyCallbacks(SegmentCreated, segment)
	mm.logger.Info("Created network segment",
		"segment_id", segment.ID,
		"cidr", segment.CIDR)

	return nil
}

// GetSegment returns a specific segment
func (mm *MeshManager) GetSegment(segmentID string) (*NetworkSegment, bool) {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	segment, exists := mm.segments[segmentID]
	if exists {
		segmentCopy := *segment
		return &segmentCopy, true
	}
	return nil, false
}

// AddCallback adds a callback for mesh events
func (mm *MeshManager) AddCallback(callback MeshCallback) {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	mm.callbacks = append(mm.callbacks, callback)
}

// heartbeatMonitor monitors node heartbeats and marks offline nodes
func (mm *MeshManager) heartbeatMonitor() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-mm.ctx.Done():
			return
		case <-ticker.C:
			mm.checkNodeHeartbeats()
		}
	}
}

// topologyOptimizer runs periodic topology optimization
func (mm *MeshManager) topologyOptimizer() {
	ticker := time.NewTicker(mm.config.TopologyUpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-mm.ctx.Done():
			return
		case <-ticker.C:
			mm.optimizeTopology()
		}
	}
}

// statisticsCollector collects and aggregates mesh statistics
func (mm *MeshManager) statisticsCollector() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-mm.ctx.Done():
			return
		case <-ticker.C:
			mm.collectStatistics()
		}
	}
}

// checkNodeHeartbeats checks for stale heartbeats and marks nodes offline
func (mm *MeshManager) checkNodeHeartbeats() {
	mm.mu.Lock()
	defer mm.mu.Unlock()

	now := time.Now()
	staleNodes := make([]*MeshNode, 0)

	for _, node := range mm.nodes {
		if node.Status == NodeOnline &&
			now.Sub(node.LastHeartbeat) > mm.config.HeartbeatTimeout {
			node.Status = NodeOffline
			node.UpdatedAt = now
			staleNodes = append(staleNodes, node)
		}
	}

	for _, node := range staleNodes {
		mm.notifyCallbacks(NodeUpdated, node)
		mm.logger.Warn("Node marked offline due to stale heartbeat",
			"node_id", node.ID,
			"last_heartbeat", node.LastHeartbeat)
	}
}

// optimizeTopology optimizes the mesh topology for all segments
func (mm *MeshManager) optimizeTopology() {
	mm.mu.RLock()
	segments := make([]*NetworkSegment, 0, len(mm.segments))
	for _, segment := range mm.segments {
		segmentCopy := *segment
		segments = append(segments, &segmentCopy)
	}
	mm.mu.RUnlock()

	for _, segment := range segments {
		if err := mm.optimizeSegmentTopology(segment.ID); err != nil {
			mm.logger.Error("Failed to optimize segment topology",
				"segment_id", segment.ID, "error", err)
		}
	}
}

// optimizeSegmentTopology optimizes topology for a specific segment
func (mm *MeshManager) optimizeSegmentTopology(segmentID string) error {
	nodes := mm.GetNodesBySegment(segmentID)
	if len(nodes) < 2 {
		return nil // No optimization needed for single node or empty segment
	}

	mm.logger.Debug("Optimizing segment topology",
		"segment_id", segmentID,
		"node_count", len(nodes))

	// For each node, calculate optimal connections
	for _, node := range nodes {
		if node.Status != NodeOnline {
			continue
		}

		optimalConnections, err := mm.GetOptimalTopologyForNode(node.ID)
		if err != nil {
			mm.logger.Error("Failed to calculate optimal topology",
				"node_id", node.ID, "error", err)
			continue
		}

		// Compare with current connections and make adjustments
		mm.reconcileNodeConnections(node.ID, optimalConnections)
	}

	return nil
}

// reconcileNodeConnections reconciles current connections with optimal topology
func (mm *MeshManager) reconcileNodeConnections(nodeID string, optimal []*MeshConnection) {
	mm.mu.RLock()
	currentConnections := make([]*MeshConnection, 0)
	for _, conn := range mm.connections {
		if conn.SourceNodeID == nodeID {
			currentConnections = append(currentConnections, conn)
		}
	}
	mm.mu.RUnlock()

	// Create maps for comparison
	currentMap := make(map[string]*MeshConnection)
	for _, conn := range currentConnections {
		currentMap[conn.TargetNodeID] = conn
	}

	optimalMap := make(map[string]*MeshConnection)
	for _, conn := range optimal {
		optimalMap[conn.TargetNodeID] = conn
	}

	// Remove connections that are no longer optimal
	for targetID, conn := range currentMap {
		if _, exists := optimalMap[targetID]; !exists {
			if err := mm.RemoveConnection(conn.ID); err != nil {
				mm.logger.Error("Failed to remove connection",
					"connection_id", conn.ID, "error", err)
			}
		}
	}

	// Add new optimal connections
	for targetID, conn := range optimalMap {
		if _, exists := currentMap[targetID]; !exists {
			if _, err := mm.CreateConnection(nodeID, targetID, conn.AllowedIPs); err != nil {
				mm.logger.Error("Failed to create optimal connection",
					"source", nodeID, "target", targetID, "error", err)
			}
		}
	}
}

// calculateOptimalConnections calculates optimal connections for a node
func (mm *MeshManager) calculateOptimalConnections(node *MeshNode, candidates []*MeshNode) []*MeshConnection {
	connections := make([]*MeshConnection, 0)

	if len(candidates) == 0 {
		return connections
	}

	// Use the default topology type from config
	switch mm.config.DefaultTopologyType {
	case TopologyFullMesh:
		connections = mm.calculateFullMeshConnections(node, candidates)
	case TopologyHub:
		connections = mm.calculateHubConnections(node, candidates)
	case TopologyHybrid:
		connections = mm.calculateHybridConnections(node, candidates)
	default:
		connections = mm.calculateHybridConnections(node, candidates)
	}

	// Limit by max connections per node
	maxConnections := mm.config.MaxConnectionsPerNode
	if len(connections) > maxConnections {
		connections = connections[:maxConnections]
	}

	return connections
}

// calculateFullMeshConnections creates full mesh connections
func (mm *MeshManager) calculateFullMeshConnections(node *MeshNode, candidates []*MeshNode) []*MeshConnection {
	connections := make([]*MeshConnection, 0)

	for _, candidate := range candidates {
		if candidate.Status == NodeOnline {
			conn := &MeshConnection{
				ID:           fmt.Sprintf("%s-%s", node.ID, candidate.ID),
				SourceNodeID: node.ID,
				TargetNodeID: candidate.ID,
				Status:       ConnectionConnecting,
				AllowedIPs:   []string{candidate.IPAddress + "/32"},
			}
			connections = append(connections, conn)
		}
	}

	return connections
}

// calculateHubConnections creates hub-based connections
func (mm *MeshManager) calculateHubConnections(node *MeshNode, candidates []*MeshNode) []*MeshConnection {
	connections := make([]*MeshConnection, 0)

	// Simple hub selection based on node capabilities or first available
	var hub *MeshNode
	for _, candidate := range candidates {
		if candidate.Status == NodeOnline {
			// Prefer nodes with "hub" capability
			for _, capability := range candidate.Capabilities {
				if capability == "hub" {
					hub = candidate
					break
				}
			}
			if hub == nil {
				hub = candidate // Use first available as fallback
			}
		}
	}

	if hub != nil {
		conn := &MeshConnection{
			ID:           fmt.Sprintf("%s-%s", node.ID, hub.ID),
			SourceNodeID: node.ID,
			TargetNodeID: hub.ID,
			Status:       ConnectionConnecting,
			AllowedIPs:   []string{hub.IPAddress + "/32"},
		}
		connections = append(connections, conn)
	}

	return connections
}

// calculateHybridConnections creates hybrid topology connections
func (mm *MeshManager) calculateHybridConnections(node *MeshNode, candidates []*MeshNode) []*MeshConnection {
	connections := make([]*MeshConnection, 0)

	// Score and sort candidates
	type scoredCandidate struct {
		node  *MeshNode
		score float64
	}

	scored := make([]scoredCandidate, 0)
	for _, candidate := range candidates {
		if candidate.Status == NodeOnline {
			score := mm.calculateNodeScore(node, candidate)
			scored = append(scored, scoredCandidate{
				node:  candidate,
				score: score,
			})
		}
	}

	// Sort by score (higher is better)
	for i := 0; i < len(scored)-1; i++ {
		for j := i + 1; j < len(scored); j++ {
			if scored[i].score < scored[j].score {
				scored[i], scored[j] = scored[j], scored[i]
			}
		}
	}

	// Select top candidates (up to optimal connection count)
	optimalCount := mm.config.MaxConnectionsPerNode / 2
	if optimalCount < 3 {
		optimalCount = 3
	}
	if len(scored) < optimalCount {
		optimalCount = len(scored)
	}

	for i := 0; i < optimalCount; i++ {
		candidate := scored[i].node
		conn := &MeshConnection{
			ID:           fmt.Sprintf("%s-%s", node.ID, candidate.ID),
			SourceNodeID: node.ID,
			TargetNodeID: candidate.ID,
			Status:       ConnectionConnecting,
			AllowedIPs:   []string{candidate.IPAddress + "/32"},
		}
		connections = append(connections, conn)
	}

	return connections
}

// calculateNodeScore calculates a score for node selection in hybrid topology
func (mm *MeshManager) calculateNodeScore(source, candidate *MeshNode) float64 {
	score := 100.0 // Base score

	// Regional affinity
	if source.Region == candidate.Region {
		score += 50.0
	}
	if source.Zone == candidate.Zone {
		score += 20.0
	}

	// Connection count penalty (prefer less connected nodes for load balancing)
	if mm.config.EnableLoadBalancing {
		connectionPenalty := float64(candidate.ConnectionCount) * 5.0
		score -= connectionPenalty
	}

	// Capability bonus
	for _, capability := range candidate.Capabilities {
		switch capability {
		case "hub":
			score += 30.0
		case "gateway":
			score += 20.0
		case "relay":
			score += 10.0
		}
	}

	return score
}

// autoAssignSegment automatically assigns a node to a segment
func (mm *MeshManager) autoAssignSegment(node *MeshNode) error {
	// Find existing segment for the tenant
	var targetSegment *NetworkSegment
	for _, segment := range mm.segments {
		if segment.TenantID == node.TenantID {
			// Check if segment has capacity
			nodeCount := len(mm.GetNodesBySegment(segment.ID))
			if nodeCount < mm.config.MaxNodesPerSegment {
				targetSegment = segment
				break
			}
		}
	}

	// Create new segment if none found or all are full
	if targetSegment == nil {
		segmentID := fmt.Sprintf("segment-%s-%d", node.TenantID, time.Now().Unix())
		targetSegment = &NetworkSegment{
			ID:       segmentID,
			Name:     fmt.Sprintf("Auto Segment for %s", node.TenantID),
			TenantID: node.TenantID,
			CIDR:     "10.100.0.0/16", // Default CIDR - should be configurable
			Metadata: map[string]string{
				"auto_created": "true",
			},
		}

		if err := mm.CreateSegment(targetSegment); err != nil {
			return fmt.Errorf("failed to create auto segment: %w", err)
		}
	}

	node.SegmentID = targetSegment.ID
	return nil
}

// collectStatistics collects and logs mesh statistics
func (mm *MeshManager) collectStatistics() {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	totalNodes := len(mm.nodes)
	onlineNodes := 0
	totalConnections := len(mm.connections)
	activeConnections := 0

	for _, node := range mm.nodes {
		if node.Status == NodeOnline {
			onlineNodes++
		}
	}

	for _, conn := range mm.connections {
		if conn.Status == ConnectionActive {
			activeConnections++
		}
	}

	mm.logger.Info("Mesh statistics",
		"total_nodes", totalNodes,
		"online_nodes", onlineNodes,
		"total_connections", totalConnections,
		"active_connections", activeConnections,
		"segments", len(mm.segments))
}

// notifyCallbacks notifies all registered callbacks about a mesh event
func (mm *MeshManager) notifyCallbacks(event MeshEvent, data interface{}) {
	for _, callback := range mm.callbacks {
		go func(cb MeshCallback) {
			defer func() {
				if r := recover(); r != nil {
					mm.logger.Error("Mesh callback panicked", "error", r)
				}
			}()
			cb(event, data)
		}(callback)
	}
}

// GetConfig returns the mesh manager configuration
func (mm *MeshManager) GetConfig() *MeshManagerConfig {
	return mm.config
}

// GetNATTraversal returns the NAT traversal component
func (mm *MeshManager) GetNATTraversal() *NATTraversal {
	return mm.natTraversal
}

// GetFailoverManager returns the failover manager component
func (mm *MeshManager) GetFailoverManager() *FailoverManager {
	return mm.failoverMgr
}

// GetConnectionPool returns the connection pool component
func (mm *MeshManager) GetConnectionPool() *ConnectionPool {
	return mm.connectionPool
}

// GetLoadBalancer returns the load balancer component
func (mm *MeshManager) GetLoadBalancer() *LoadBalancer {
	return mm.loadBalancer
}

// GetStats returns comprehensive mesh statistics
func (mm *MeshManager) GetStats() map[string]interface{} {
	mm.mu.RLock()
	defer mm.mu.RUnlock()

	totalNodes := len(mm.nodes)
	onlineNodes := 0
	totalConnections := len(mm.connections)
	activeConnections := 0
	totalSegments := len(mm.segments)

	// Calculate status distribution
	statusCounts := make(map[string]int)
	for _, node := range mm.nodes {
		status := node.Status.String()
		statusCounts[status]++
		if node.Status == NodeOnline {
			onlineNodes++
		}
	}

	// Calculate connection status distribution
	connStatusCounts := make(map[string]int)
	for _, conn := range mm.connections {
		status := conn.Status.String()
		connStatusCounts[status]++
		if conn.Status == ConnectionActive {
			activeConnections++
		}
	}

	// Calculate average connection count per node
	avgConnections := 0.0
	if totalNodes > 0 {
		totalNodeConnections := 0
		for _, node := range mm.nodes {
			totalNodeConnections += node.ConnectionCount
		}
		avgConnections = float64(totalNodeConnections) / float64(totalNodes)
	}

	return map[string]interface{}{
		"total_nodes":        totalNodes,
		"online_nodes":       onlineNodes,
		"total_connections":  totalConnections,
		"active_connections": activeConnections,
		"total_segments":     totalSegments,
		"avg_connections":    avgConnections,
		"node_status_counts": statusCounts,
		"conn_status_counts": connStatusCounts,
		"auto_segmentation":  mm.config.EnableAutoSegmentation,
		"load_balancing":     mm.config.EnableLoadBalancing,
		"default_topology":   mm.config.DefaultTopologyType.String(),
	}
}

// String returns a string representation of NodeStatus
func (ns NodeStatus) String() string {
	switch ns {
	case NodeOnline:
		return "online"
	case NodeOffline:
		return "offline"
	case NodeConnecting:
		return "connecting"
	case NodeDegraded:
		return "degraded"
	case NodeMaintenance:
		return "maintenance"
	default:
		return "unknown"
	}
}

// MarshalJSON implements json.Marshaler for NodeStats
func (ns *NodeStats) MarshalJSON() ([]byte, error) {
	type Alias NodeStats
	return json.Marshal(&struct {
		*Alias
		UptimeHours float64 `json:"uptime_hours"`
	}{
		Alias:       (*Alias)(ns),
		UptimeHours: float64(ns.Uptime) / 3600,
	})
}
