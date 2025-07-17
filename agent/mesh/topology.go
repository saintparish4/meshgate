package mesh

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"sync"
	"time"
)

// TopologyType represents different mesh topology strategies
type TopologyType int

const (
	TopologyFullMesh TopologyType = iota
	TopologyHub
	TopologyTree
	TopologyRing
	TopologyHybrid
)

// TopologyConfig holds configuration for topology management
type TopologyConfig struct {
	Type                TopologyType  `json:"type"`
	MaxConnections      int           `json:"max_connections"`
	MinConnections      int           `json:"min_connections"`
	OptimalConnections  int           `json:"optimal_connections"`
	RebalanceInterval   time.Duration `json:"rebalance_interval"`
	FailoverTimeout     time.Duration `json:"failover_timeout"`
	EnableAutoHealing   bool          `json:"enable_auto_healing"`
	EnableLoadBalancing bool          `json:"enable_load_balancing"`
	MaxHops             int           `json:"max_hops"`
	RegionAffinity      float64       `json:"region_affinity"` // 0-1, preference for same region
}

// Connection represents a mesh connection between nodes
type Connection struct {
	PeerID      string            `json:"peer_id"`
	PublicKey   string            `json:"public_key"`
	Endpoint    string            `json:"endpoint"`
	AllowedIPs  []string          `json:"allowed_ips"`
	Status      ConnectionStatus  `json:"status"`
	Quality     ConnectionQuality `json:"quality"`
	CreatedAt   time.Time         `json:"created_at"`
	LastActive  time.Time         `json:"last_active"`
	Metadata    map[string]string `json:"metadata"`
}

// ConnectionStatus represents the status of a mesh connection
type ConnectionStatus int

const (
	ConnectionActive ConnectionStatus = iota
	ConnectionConnecting
	ConnectionFailed
	ConnectionIdle
	ConnectionShuttingDown
)

// ConnectionQuality holds quality metrics for a connection
type ConnectionQuality struct {
	RTT         time.Duration `json:"rtt"`
	PacketLoss  float64       `json:"packet_loss"`
	Bandwidth   int64         `json:"bandwidth"`
	Reliability float64       `json:"reliability"`
	LastUpdate  time.Time     `json:"last_update"`
}

// TopologyManager manages the mesh topology
type TopologyManager struct {
	config      *TopologyConfig
	logger      *slog.Logger
	discovery   *Discovery
	connections map[string]*Connection
	callbacks   []TopologyCallback
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// TopologyCallback is called when topology events occur
type TopologyCallback func(event TopologyEvent, connection *Connection)

// TopologyEvent represents different topology lifecycle events
type TopologyEvent int

const (
	ConnectionEstablished TopologyEvent = iota
	ConnectionUpdated
	ConnectionLost
	TopologyRebalanced
	FailoverTriggered
)

// NewTopologyManager creates a new topology manager
func NewTopologyManager(config *TopologyConfig, discovery *Discovery, logger *slog.Logger) *TopologyManager {
	if config == nil {
		config = &TopologyConfig{
			Type:                TopologyHybrid,
			MaxConnections:      10,
			MinConnections:      3,
			OptimalConnections:  5,
			RebalanceInterval:   5 * time.Minute,
			FailoverTimeout:     30 * time.Second,
			EnableAutoHealing:   true,
			EnableLoadBalancing: true,
			MaxHops:             4,
			RegionAffinity:      0.7,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &TopologyManager{
		config:      config,
		logger:      logger,
		discovery:   discovery,
		connections: make(map[string]*Connection),
		callbacks:   make([]TopologyCallback, 0),
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Start begins the topology management process
func (tm *TopologyManager) Start() error {
	tm.logger.Info("Starting topology manager", 
		"type", tm.config.Type,
		"max_connections", tm.config.MaxConnections)

	// Register for peer discovery events
	tm.discovery.AddCallback(tm.handlePeerEvent)

	// Start background processes
	go tm.rebalanceLoop()
	if tm.config.EnableAutoHealing {
		go tm.healingLoop()
	}

	// Perform initial topology formation
	go tm.formInitialTopology()

	return nil
}

// Stop stops the topology management process
func (tm *TopologyManager) Stop() error {
	tm.logger.Info("Stopping topology manager")
	tm.cancel()
	
	// Close all connections gracefully
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	for _, conn := range tm.connections {
		conn.Status = ConnectionShuttingDown
	}
	
	return nil
}

// AddConnection adds a new connection to the topology
func (tm *TopologyManager) AddConnection(conn *Connection) error {
	if conn == nil || conn.PeerID == "" {
		return fmt.Errorf("invalid connection")
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	existing, exists := tm.connections[conn.PeerID]
	if exists {
		// Update existing connection
		existing.Endpoint = conn.Endpoint
		existing.AllowedIPs = conn.AllowedIPs
		existing.Status = conn.Status
		existing.LastActive = time.Now()
		tm.notifyCallbacks(ConnectionUpdated, existing)
		tm.logger.Debug("Updated connection", "peer_id", conn.PeerID)
	} else {
		// Add new connection
		conn.CreatedAt = time.Now()
		conn.LastActive = time.Now()
		if conn.Status == 0 {
			conn.Status = ConnectionConnecting
		}
		tm.connections[conn.PeerID] = conn
		tm.notifyCallbacks(ConnectionEstablished, conn)
		tm.logger.Info("Added new connection", "peer_id", conn.PeerID)
	}

	return nil
}

// RemoveConnection removes a connection from the topology
func (tm *TopologyManager) RemoveConnection(peerID string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if conn, exists := tm.connections[peerID]; exists {
		conn.Status = ConnectionShuttingDown
		delete(tm.connections, peerID)
		tm.notifyCallbacks(ConnectionLost, conn)
		tm.logger.Info("Removed connection", "peer_id", peerID)
	}
}

// GetConnection returns a specific connection
func (tm *TopologyManager) GetConnection(peerID string) (*Connection, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	conn, exists := tm.connections[peerID]
	if exists {
		connCopy := *conn
		return &connCopy, true
	}
	return nil, false
}

// GetActiveConnections returns all active connections
func (tm *TopologyManager) GetActiveConnections() []*Connection {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	connections := make([]*Connection, 0)
	for _, conn := range tm.connections {
		if conn.Status == ConnectionActive {
			connCopy := *conn
			connections = append(connections, &connCopy)
		}
	}

	return connections
}

// GetOptimalTopology calculates the optimal topology based on current peers
func (tm *TopologyManager) GetOptimalTopology() ([]*Connection, error) {
	peers := tm.discovery.GetOptimalPeers(tm.config.MaxConnections * 2)
	
	switch tm.config.Type {
	case TopologyFullMesh:
		return tm.calculateFullMesh(peers), nil
	case TopologyHub:
		return tm.calculateHubTopology(peers), nil
	case TopologyTree:
		return tm.calculateTreeTopology(peers), nil
	case TopologyRing:
		return tm.calculateRingTopology(peers), nil
	case TopologyHybrid:
		return tm.calculateHybridTopology(peers), nil
	default:
		return nil, fmt.Errorf("unsupported topology type: %v", tm.config.Type)
	}
}

// UpdateConnectionQuality updates the quality metrics for a connection
func (tm *TopologyManager) UpdateConnectionQuality(peerID string, quality ConnectionQuality) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if conn, exists := tm.connections[peerID]; exists {
		quality.LastUpdate = time.Now()
		conn.Quality = quality
		conn.LastActive = time.Now()
		
		// Update connection status based on quality
		if quality.Reliability < 0.5 || quality.RTT > 2*time.Second {
			conn.Status = ConnectionFailed
		} else {
			conn.Status = ConnectionActive
		}
	}
}

// AddCallback adds a callback for topology events
func (tm *TopologyManager) AddCallback(callback TopologyCallback) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.callbacks = append(tm.callbacks, callback)
}

// rebalanceLoop runs periodic topology rebalancing
func (tm *TopologyManager) rebalanceLoop() {
	ticker := time.NewTicker(tm.config.RebalanceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-tm.ctx.Done():
			return
		case <-ticker.C:
			if err := tm.rebalanceTopology(); err != nil {
				tm.logger.Error("Topology rebalancing failed", "error", err)
			}
		}
	}
}

// healingLoop runs periodic topology healing
func (tm *TopologyManager) healingLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-tm.ctx.Done():
			return
		case <-ticker.C:
			tm.healTopology()
		}
	}
}

// formInitialTopology creates the initial mesh topology
func (tm *TopologyManager) formInitialTopology() {
	// Wait a bit for peer discovery to populate
	time.Sleep(10 * time.Second)

	optimal, err := tm.GetOptimalTopology()
	if err != nil {
		tm.logger.Error("Failed to calculate initial topology", "error", err)
		return
	}

	for _, conn := range optimal {
		if err := tm.AddConnection(conn); err != nil {
			tm.logger.Error("Failed to add initial connection", 
				"peer_id", conn.PeerID, "error", err)
		}
	}

	tm.logger.Info("Formed initial topology", "connections", len(optimal))
}

// rebalanceTopology rebalances the mesh topology
func (tm *TopologyManager) rebalanceTopology() error {
	tm.logger.Debug("Rebalancing topology")

	currentConnections := tm.GetActiveConnections()
	optimalTopology, err := tm.GetOptimalTopology()
	if err != nil {
		return fmt.Errorf("failed to calculate optimal topology: %w", err)
	}

	// Create maps for comparison
	currentMap := make(map[string]*Connection)
	for _, conn := range currentConnections {
		currentMap[conn.PeerID] = conn
	}

	optimalMap := make(map[string]*Connection)
	for _, conn := range optimalTopology {
		optimalMap[conn.PeerID] = conn
	}

	// Remove connections that are no longer optimal
	for peerID := range currentMap {
		if _, exists := optimalMap[peerID]; !exists {
			tm.RemoveConnection(peerID)
		}
	}

	// Add new optimal connections
	for peerID, conn := range optimalMap {
		if _, exists := currentMap[peerID]; !exists {
			if err := tm.AddConnection(conn); err != nil {
				tm.logger.Error("Failed to add connection during rebalance", 
					"peer_id", peerID, "error", err)
			}
		}
	}

	tm.notifyCallbacks(TopologyRebalanced, nil)
	tm.logger.Debug("Topology rebalanced", 
		"removed", len(currentConnections)-len(optimalTopology),
		"added", len(optimalTopology)-len(currentConnections))

	return nil
}

// healTopology heals failed connections and ensures minimum connectivity
func (tm *TopologyManager) healTopology() {
	tm.mu.RLock()
	failedConnections := make([]*Connection, 0)
	activeCount := 0

	for _, conn := range tm.connections {
		switch conn.Status {
		case ConnectionFailed:
			failedConnections = append(failedConnections, conn)
		case ConnectionActive:
			activeCount++
		}
	}
	tm.mu.RUnlock()

	// Trigger failover for failed connections
	for _, conn := range failedConnections {
		tm.triggerFailover(conn)
	}

	// Ensure minimum connectivity
	if activeCount < tm.config.MinConnections {
		tm.ensureMinimumConnectivity(tm.config.MinConnections - activeCount)
	}
}

// triggerFailover handles failover for a failed connection
func (tm *TopologyManager) triggerFailover(failedConn *Connection) {
	tm.logger.Info("Triggering failover", "failed_peer", failedConn.PeerID)

	// Find alternative peers
	allPeers := tm.discovery.GetOptimalPeers(10)
	alternativePeers := make([]*PeerInfo, 0)

	tm.mu.RLock()
	for _, peer := range allPeers {
		if _, exists := tm.connections[peer.NodeID]; !exists {
			alternativePeers = append(alternativePeers, peer)
		}
	}
	tm.mu.RUnlock()

	if len(alternativePeers) > 0 {
		// Select best alternative
		bestPeer := alternativePeers[0]
		newConn := &Connection{
			PeerID:     bestPeer.NodeID,
			PublicKey:  bestPeer.PublicKey,
			Endpoint:   bestPeer.Endpoint,
			AllowedIPs: []string{}, // Will be populated by policy engine
			Status:     ConnectionConnecting,
		}

		if err := tm.AddConnection(newConn); err != nil {
			tm.logger.Error("Failover connection failed", 
				"peer_id", bestPeer.NodeID, "error", err)
		} else {
			tm.notifyCallbacks(FailoverTriggered, newConn)
		}
	}

	// Remove the failed connection
	tm.RemoveConnection(failedConn.PeerID)
}

// ensureMinimumConnectivity ensures we have minimum required connections
func (tm *TopologyManager) ensureMinimumConnectivity(needed int) {
	allPeers := tm.discovery.GetOptimalPeers(needed * 2)
	
	tm.mu.RLock()
	connected := make(map[string]bool)
	for peerID := range tm.connections {
		connected[peerID] = true
	}
	tm.mu.RUnlock()

	added := 0
	for _, peer := range allPeers {
		if added >= needed {
			break
		}
		
		if !connected[peer.NodeID] {
			conn := &Connection{
				PeerID:     peer.NodeID,
				PublicKey:  peer.PublicKey,
				Endpoint:   peer.Endpoint,
				AllowedIPs: []string{},
				Status:     ConnectionConnecting,
			}
			
			if err := tm.AddConnection(conn); err != nil {
				tm.logger.Error("Failed to add connection for minimum connectivity", 
					"peer_id", peer.NodeID, "error", err)
			} else {
				added++
			}
		}
	}

	tm.logger.Info("Ensured minimum connectivity", "added", added, "needed", needed)
}

// handlePeerEvent handles events from the peer discovery system
func (tm *TopologyManager) handlePeerEvent(event PeerEvent, peer *PeerInfo) {
	switch event {
	case PeerDiscovered:
		tm.handlePeerDiscovered(peer)
	case PeerLost:
		tm.handlePeerLost(peer)
	case PeerUnhealthy:
		tm.handlePeerUnhealthy(peer)
	}
}

// handlePeerDiscovered handles when a new peer is discovered
func (tm *TopologyManager) handlePeerDiscovered(peer *PeerInfo) {
	tm.mu.RLock()
	activeCount := len(tm.connections)
	tm.mu.RUnlock()

	// Only auto-connect if we're below optimal connections
	if activeCount < tm.config.OptimalConnections {
		conn := &Connection{
			PeerID:     peer.NodeID,
			PublicKey:  peer.PublicKey,
			Endpoint:   peer.Endpoint,
			AllowedIPs: []string{},
			Status:     ConnectionConnecting,
		}

		if err := tm.AddConnection(conn); err != nil {
			tm.logger.Error("Failed to auto-connect to discovered peer", 
				"peer_id", peer.NodeID, "error", err)
		}
	}
}

// handlePeerLost handles when a peer is lost
func (tm *TopologyManager) handlePeerLost(peer *PeerInfo) {
	tm.RemoveConnection(peer.NodeID)
}

// handlePeerUnhealthy handles when a peer becomes unhealthy
func (tm *TopologyManager) handlePeerUnhealthy(peer *PeerInfo) {
	if conn, exists := tm.GetConnection(peer.NodeID); exists {
		conn.Status = ConnectionFailed
		tm.mu.Lock()
		tm.connections[peer.NodeID] = conn
		tm.mu.Unlock()
	}
}

// calculateFullMesh calculates a full mesh topology
func (tm *TopologyManager) calculateFullMesh(peers []*PeerInfo) []*Connection {
	connections := make([]*Connection, 0)
	maxPeers := tm.config.MaxConnections
	
	if len(peers) > maxPeers {
		peers = peers[:maxPeers]
	}

	for _, peer := range peers {
		conn := &Connection{
			PeerID:     peer.NodeID,
			PublicKey:  peer.PublicKey,
			Endpoint:   peer.Endpoint,
			AllowedIPs: []string{},
			Status:     ConnectionConnecting,
		}
		connections = append(connections, conn)
	}

	return connections
}

// calculateHubTopology calculates a hub-and-spoke topology
func (tm *TopologyManager) calculateHubTopology(peers []*PeerInfo) []*Connection {
	connections := make([]*Connection, 0)
	
	if len(peers) == 0 {
		return connections
	}

	// Select the best peer as hub (highest reliability, lowest RTT)
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].Reliability != peers[j].Reliability {
			return peers[i].Reliability > peers[j].Reliability
		}
		return peers[i].RTT < peers[j].RTT
	})

	// Connect to hub and a few backup connections
	maxConnections := tm.config.MaxConnections
	if len(peers) > maxConnections {
		peers = peers[:maxConnections]
	}

	for _, peer := range peers {
		conn := &Connection{
			PeerID:     peer.NodeID,
			PublicKey:  peer.PublicKey,
			Endpoint:   peer.Endpoint,
			AllowedIPs: []string{},
			Status:     ConnectionConnecting,
		}
		connections = append(connections, conn)
	}

	return connections
}

// calculateTreeTopology calculates a tree topology
func (tm *TopologyManager) calculateTreeTopology(peers []*PeerInfo) []*Connection {
	// For simplicity, this creates a balanced tree approach
	// In practice, you'd want to consider network topology and latency
	return tm.calculateHubTopology(peers) // Simplified to hub for now
}

// calculateRingTopology calculates a ring topology
func (tm *TopologyManager) calculateRingTopology(peers []*PeerInfo) []*Connection {
	connections := make([]*Connection, 0)
	
	if len(peers) < 2 {
		return tm.calculateFullMesh(peers)
	}

	// Sort peers by some consistent criteria (node ID for determinism)
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].NodeID < peers[j].NodeID
	})

	// Connect to next 2-3 peers in the ring for redundancy
	connectionsPerNode := 3
	if len(peers) < connectionsPerNode {
		connectionsPerNode = len(peers) - 1
	}

	for i := 0; i < connectionsPerNode && i < len(peers); i++ {
		peer := peers[i]
		conn := &Connection{
			PeerID:     peer.NodeID,
			PublicKey:  peer.PublicKey,
			Endpoint:   peer.Endpoint,
			AllowedIPs: []string{},
			Status:     ConnectionConnecting,
		}
		connections = append(connections, conn)
	}

	return connections
}

// calculateHybridTopology calculates a hybrid topology (recommended)
func (tm *TopologyManager) calculateHybridTopology(peers []*PeerInfo) []*Connection {
	connections := make([]*Connection, 0)
	
	if len(peers) == 0 {
		return connections
	}

	// Hybrid approach: connect to best peers with regional preference
	maxConnections := tm.config.MaxConnections
	optimalConnections := tm.config.OptimalConnections

	// Sort peers by a hybrid score
	sort.Slice(peers, func(i, j int) bool {
		scoreI := tm.calculateHybridScore(peers[i])
		scoreJ := tm.calculateHybridScore(peers[j])
		return scoreI > scoreJ
	})

	// Select optimal number of connections, but limit by max
	targetCount := optimalConnections
	if len(peers) < targetCount {
		targetCount = len(peers)
	}
	if targetCount > maxConnections {
		targetCount = maxConnections
	}

	for i := 0; i < targetCount; i++ {
		peer := peers[i]
		conn := &Connection{
			PeerID:     peer.NodeID,
			PublicKey:  peer.PublicKey,
			Endpoint:   peer.Endpoint,
			AllowedIPs: []string{},
			Status:     ConnectionConnecting,
		}
		connections = append(connections, conn)
	}

	return connections
}

// calculateHybridScore calculates a score for hybrid topology selection
func (tm *TopologyManager) calculateHybridScore(peer *PeerInfo) float64 {
	score := peer.Reliability * 100 // Base reliability score (0-100)

	// RTT penalty (lower RTT is better)
	rttMs := float64(peer.RTT.Milliseconds())
	rttScore := math.Max(0, 100-rttMs/10) // Penalty increases with RTT
	score += rttScore * 0.3

	// Region affinity bonus
	// This would need to be implemented based on current node's region
	// For now, we'll assume same region gets a bonus
	regionBonus := 20.0 * tm.config.RegionAffinity
	score += regionBonus

	return score
}

// notifyCallbacks notifies all registered callbacks about a topology event
func (tm *TopologyManager) notifyCallbacks(event TopologyEvent, connection *Connection) {
	for _, callback := range tm.callbacks {
		go func(cb TopologyCallback) {
			defer func() {
				if r := recover(); r != nil {
					tm.logger.Error("Topology callback panicked", "error", r)
				}
			}()
			cb(event, connection)
		}(callback)
	}
}

// GetStats returns topology statistics
func (tm *TopologyManager) GetStats() map[string]interface{} {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	totalConnections := len(tm.connections)
	activeConnections := 0
	failedConnections := 0
	avgRTT := time.Duration(0)
	avgReliability := 0.0

	if totalConnections > 0 {
		totalRTT := time.Duration(0)
		for _, conn := range tm.connections {
			switch conn.Status {
			case ConnectionActive:
				activeConnections++
			case ConnectionFailed:
				failedConnections++
			}
			totalRTT += conn.Quality.RTT
			avgReliability += conn.Quality.Reliability
		}
		avgRTT = totalRTT / time.Duration(totalConnections)
		avgReliability = avgReliability / float64(totalConnections)
	}

	return map[string]interface{}{
		"topology_type":       tm.config.Type,
		"total_connections":   totalConnections,
		"active_connections":  activeConnections,
		"failed_connections":  failedConnections,
		"avg_rtt_ms":         avgRTT.Milliseconds(),
		"avg_reliability":    avgReliability,
		"optimal_connections": tm.config.OptimalConnections,
		"max_connections":    tm.config.MaxConnections,
		"auto_healing":       tm.config.EnableAutoHealing,
	}
}

// String returns a string representation of TopologyType
func (t TopologyType) String() string {
	switch t {
	case TopologyFullMesh:
		return "full-mesh"
	case TopologyHub:
		return "hub"
	case TopologyTree:
		return "tree"
	case TopologyRing:
		return "ring"
	case TopologyHybrid:
		return "hybrid"
	default:
		return "unknown"
	}
}

// String returns a string representation of ConnectionStatus
func (cs ConnectionStatus) String() string {
	switch cs {
	case ConnectionActive:
		return "active"
	case ConnectionConnecting:
		return "connecting"
	case ConnectionFailed:
		return "failed"
	case ConnectionIdle:
		return "idle"
	case ConnectionShuttingDown:
		return "shutting-down"
	default:
		return "unknown"
	}
}