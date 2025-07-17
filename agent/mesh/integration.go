package mesh

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// MeshAgent integrates the agent with the mesh discovery and topology systems
type MeshAgent struct {
	logger    *slog.Logger
	wgClient  *wgctrl.Client
	discovery *Discovery
	topology  *TopologyManager

	// Agent configuration
	nodeID        string
	publicKey     string
	privateKey    wgtypes.Key
	interfaceName string
	listenPort    int

	// Current mesh state
	currentPeers map[string]*PeerInfo
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
}

// MeshAgentConfig holds configuration for the mesh agent
type MeshAgentConfig struct {
	NodeID        string   `json:"node_id"`
	InterfaceName string   `json:"interface_name"`
	ListenPort    int      `json:"listen_port"`
	Region        string   `json:"region"`
	Zone          string   `json:"zone"`
	Capabilities  []string `json:"capabilities"`
}

// WireGuardPeer represents a WireGuard peer configuration
type WireGuardPeer struct {
	PublicKey    wgtypes.Key  `json:"public_key"`
	Endpoint     *net.UDPAddr `json:"endpoint"`
	AllowedIPs   []net.IPNet  `json:"allowed_ips"`
	PresharedKey *wgtypes.Key `json:"preshared_key,omitempty"`
}

// NewMeshAgent creates a new mesh agent
func NewMeshAgent(config *MeshAgentConfig, privateKey wgtypes.Key, logger *slog.Logger) (*MeshAgent, error) {
	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create WireGuard client: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create discovery config
	discoveryConfig := &DiscoveryConfig{
		DiscoveryInterval:    30 * time.Second,
		PeerTimeout:          5 * time.Minute,
		MaxPeers:             50,
		EnabledHealthCheck:   true,
		HealthCheckInterval:  60 * time.Second,
		RTTThreshold:         500 * time.Millisecond,
		ReliabilityThreshold: 0.8,
		PreferredRegions:     []string{config.Region},
	}

	discovery := NewDiscovery(discoveryConfig, logger)

	// Create topology config
	topologyConfig := &TopologyConfig{
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

	topology := NewTopologyManager(topologyConfig, discovery, logger)

	agent := &MeshAgent{
		logger:        logger,
		wgClient:      wgClient,
		discovery:     discovery,
		topology:      topology,
		nodeID:        config.NodeID,
		publicKey:     privateKey.PublicKey().String(),
		privateKey:    privateKey,
		interfaceName: config.InterfaceName,
		listenPort:    config.ListenPort,
		currentPeers:  make(map[string]*PeerInfo),
		ctx:           ctx,
		cancel:        cancel,
	}

	return agent, nil
}

// Start starts the mesh agent
func (ma *MeshAgent) Start() error {
	ma.logger.Info("Starting mesh agent",
		"node_id", ma.nodeID,
		"interface", ma.interfaceName,
		"public_key", ma.publicKey)

	// Start discovery
	if err := ma.discovery.Start(); err != nil {
		return fmt.Errorf("failed to start discovery: %w", err)
	}

	// Start topology manager
	if err := ma.topology.Start(); err != nil {
		return fmt.Errorf("failed to start topology manager: %w", err)
	}

	// Register callbacks
	ma.discovery.AddCallback(ma.handlePeerEvent)
	ma.topology.AddCallback(ma.handleTopologyEvent)

	// Start background tasks
	go ma.syncLoop()
	go ma.metricsLoop()

	return nil
}

// Stop stops the mesh agent
func (ma *MeshAgent) Stop() error {
	ma.logger.Info("Stopping mesh agent")

	ma.cancel()

	if err := ma.topology.Stop(); err != nil {
		ma.logger.Error("Failed to stop topology manager", "error", err)
	}

	if err := ma.discovery.Stop(); err != nil {
		ma.logger.Error("Failed to stop discovery", "error", err)
	}

	return nil
}

// AddPeer adds a peer to the mesh
func (ma *MeshAgent) AddPeer(peer *PeerInfo) error {
	return ma.discovery.AddPeer(peer)
}

// RemovePeer removes a peer from the mesh
func (ma *MeshAgent) RemovePeer(nodeID string) {
	ma.discovery.RemovePeer(nodeID)
}

// GetMeshTopology returns the current mesh topology
func (ma *MeshAgent) GetMeshTopology() []*Connection {
	return ma.topology.GetActiveConnections()
}

// GetPeerStats returns statistics about discovered peers
func (ma *MeshAgent) GetPeerStats() map[string]interface{} {
	return ma.discovery.GetStats()
}

// GetTopologyStats returns statistics about the mesh topology
func (ma *MeshAgent) GetTopologyStats() map[string]interface{} {
	return ma.topology.GetStats()
}

// ApplyWireGuardConfig applies a WireGuard configuration to the interface
func (ma *MeshAgent) ApplyWireGuardConfig(peers []WireGuardPeer) error {
	ma.logger.Debug("Applying WireGuard configuration", "peer_count", len(peers))

	// Convert peers to wgtypes.PeerConfig
	wgPeers := make([]wgtypes.PeerConfig, 0, len(peers))
	for _, peer := range peers {
		peerConfig := wgtypes.PeerConfig{
			PublicKey:  peer.PublicKey,
			AllowedIPs: peer.AllowedIPs,
		}

		if peer.Endpoint != nil {
			peerConfig.Endpoint = peer.Endpoint
		}

		if peer.PresharedKey != nil {
			peerConfig.PresharedKey = peer.PresharedKey
		}

		wgPeers = append(wgPeers, peerConfig)
	}

	// Configure WireGuard interface
	config := wgtypes.Config{
		PrivateKey:   &ma.privateKey,
		ListenPort:   &ma.listenPort,
		Peers:        wgPeers,
		ReplacePeers: true,
	}

	if err := ma.wgClient.ConfigureDevice(ma.interfaceName, config); err != nil {
		return fmt.Errorf("failed to configure WireGuard device: %w", err)
	}

	ma.logger.Info("WireGuard configuration applied successfully",
		"interface", ma.interfaceName,
		"peer_count", len(wgPeers))

	return nil
}

// GetWireGuardStats returns current WireGuard interface statistics
func (ma *MeshAgent) GetWireGuardStats() (map[string]interface{}, error) {
	device, err := ma.wgClient.Device(ma.interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get device info: %w", err)
	}

	stats := map[string]interface{}{
		"interface_name": device.Name,
		"public_key":     device.PublicKey.String(),
		"listen_port":    device.ListenPort,
		"peer_count":     len(device.Peers),
		"peers":          make([]map[string]interface{}, 0, len(device.Peers)),
	}

	totalRx := int64(0)
	totalTx := int64(0)
	activePeers := 0

	for _, peer := range device.Peers {
		totalRx += peer.ReceiveBytes
		totalTx += peer.TransmitBytes

		// Consider peer active if it has recent handshake
		isActive := time.Since(peer.LastHandshakeTime) < 3*time.Minute

		if isActive {
			activePeers++
		}

		peerStats := map[string]interface{}{
			"public_key":           peer.PublicKey.String(),
			"endpoint":             peer.Endpoint,
			"allowed_ips":          peer.AllowedIPs,
			"last_handshake":       peer.LastHandshakeTime,
			"receive_bytes":        peer.ReceiveBytes,
			"transmit_bytes":       peer.TransmitBytes,
			"persistent_keepalive": peer.PersistentKeepaliveInterval,
			"active":               isActive,
		}

		stats["peers"] = append(stats["peers"].([]map[string]interface{}), peerStats)
	}

	stats["total_receive_bytes"] = totalRx
	stats["total_transmit_bytes"] = totalTx
	stats["active_peers"] = activePeers

	return stats, nil
}

// syncLoop periodically syncs the mesh topology with WireGuard configuration
func (ma *MeshAgent) syncLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ma.ctx.Done():
			return
		case <-ticker.C:
			if err := ma.syncMeshToWireGuard(); err != nil {
				ma.logger.Error("Failed to sync mesh to WireGuard", "error", err)
			}
		}
	}
}

// metricsLoop periodically updates peer metrics from WireGuard interface
func (ma *MeshAgent) metricsLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ma.ctx.Done():
			return
		case <-ticker.C:
			ma.updatePeerMetrics()
		}
	}
}

// syncMeshToWireGuard synchronizes the mesh topology to WireGuard configuration
func (ma *MeshAgent) syncMeshToWireGuard() error {
	connections := ma.topology.GetActiveConnections()
	peers := make([]WireGuardPeer, 0, len(connections))

	for _, conn := range connections {
		// Get peer info from discovery
		peerInfo, exists := ma.discovery.GetPeer(conn.PeerID)
		if !exists {
			ma.logger.Warn("Peer not found in discovery", "peer_id", conn.PeerID)
			continue
		}

		// Parse public key
		publicKey, err := wgtypes.ParseKey(peerInfo.PublicKey)
		if err != nil {
			ma.logger.Error("Invalid peer public key",
				"peer_id", conn.PeerID, "error", err)
			continue
		}

		// Parse endpoint
		var endpoint *net.UDPAddr
		if peerInfo.Endpoint != "" {
			endpoint, err = net.ResolveUDPAddr("udp", peerInfo.Endpoint)
			if err != nil {
				ma.logger.Error("Invalid peer endpoint",
					"peer_id", conn.PeerID, "endpoint", peerInfo.Endpoint, "error", err)
				continue
			}
		}

		// Parse allowed IPs
		allowedIPs := make([]net.IPNet, 0, len(conn.AllowedIPs))
		for _, ip := range conn.AllowedIPs {
			_, ipNet, err := net.ParseCIDR(ip)
			if err != nil {
				ma.logger.Error("Invalid allowed IP",
					"peer_id", conn.PeerID, "ip", ip, "error", err)
				continue
			}
			allowedIPs = append(allowedIPs, *ipNet)
		}

		peer := WireGuardPeer{
			PublicKey:  publicKey,
			Endpoint:   endpoint,
			AllowedIPs: allowedIPs,
		}

		peers = append(peers, peer)
	}

	return ma.ApplyWireGuardConfig(peers)
}

// updatePeerMetrics updates peer metrics from WireGuard interface statistics
func (ma *MeshAgent) updatePeerMetrics() {
	stats, err := ma.GetWireGuardStats()
	if err != nil {
		ma.logger.Error("Failed to get WireGuard stats", "error", err)
		return
	}

	peerStats, ok := stats["peers"].([]map[string]interface{})
	if !ok {
		return
	}

	for _, peerStat := range peerStats {
		publicKey, ok := peerStat["public_key"].(string)
		if !ok {
			continue
		}

		// Find corresponding peer in discovery
		allPeers := ma.discovery.GetAllPeers()
		for _, peer := range allPeers {
			if peer.PublicKey == publicKey {
				// Update RTT based on handshake freshness
				lastHandshake, ok := peerStat["last_handshake"].(time.Time)
				if ok && !lastHandshake.IsZero() {
					timeSinceHandshake := time.Since(lastHandshake)
					if timeSinceHandshake < time.Minute {
						// Estimate RTT based on handshake frequency
						estimatedRTT := timeSinceHandshake / 10
						ma.discovery.UpdatePeerRTT(peer.NodeID, estimatedRTT)
					}
				}

				// Update reliability based on activity
				isActive, ok := peerStat["active"].(bool)
				if ok {
					if isActive {
						ma.discovery.UpdatePeerReliability(peer.NodeID,
							math.Min(1.0, peer.Reliability+0.05))
					} else {
						ma.discovery.UpdatePeerReliability(peer.NodeID,
							math.Max(0.0, peer.Reliability-0.1))
					}
				}

				// Update topology connection quality
				rxBytes, _ := peerStat["receive_bytes"].(int64)
				txBytes, _ := peerStat["transmit_bytes"].(int64)

				quality := ConnectionQuality{
					RTT:         peer.RTT,
					Reliability: peer.Reliability,
					Bandwidth:   rxBytes + txBytes, // Simple bandwidth estimate
					LastUpdate:  time.Now(),
				}

				ma.topology.UpdateConnectionQuality(peer.NodeID, quality)
				break
			}
		}
	}
}

// handlePeerEvent handles events from the peer discovery system
func (ma *MeshAgent) handlePeerEvent(event PeerEvent, peer *PeerInfo) {
	switch event {
	case PeerDiscovered:
		ma.logger.Info("Peer discovered",
			"peer_id", peer.NodeID,
			"endpoint", peer.Endpoint,
			"reliability", peer.Reliability)

	case PeerLost:
		ma.logger.Info("Peer lost",
			"peer_id", peer.NodeID)

	case PeerHealthy:
		ma.logger.Debug("Peer healthy",
			"peer_id", peer.NodeID,
			"reliability", peer.Reliability)

	case PeerUnhealthy:
		ma.logger.Warn("Peer unhealthy",
			"peer_id", peer.NodeID,
			"reliability", peer.Reliability)
	}
}

// handleTopologyEvent handles events from the topology management system
func (ma *MeshAgent) handleTopologyEvent(event TopologyEvent, connection *Connection) {
	switch event {
	case ConnectionEstablished:
		ma.logger.Info("Connection established",
			"peer_id", connection.PeerID,
			"endpoint", connection.Endpoint)

	case ConnectionLost:
		ma.logger.Info("Connection lost",
			"peer_id", connection.PeerID)

	case TopologyRebalanced:
		ma.logger.Info("Topology rebalanced")

	case FailoverTriggered:
		ma.logger.Info("Failover triggered",
			"peer_id", connection.PeerID)
	}
}

// GetMeshState returns the current state of the mesh
func (ma *MeshAgent) GetMeshState() map[string]interface{} {
	ma.mu.RLock()
	defer ma.mu.RUnlock()

	allPeers := ma.discovery.GetAllPeers()
	connections := ma.topology.GetActiveConnections()

	state := map[string]interface{}{
		"node_id":          ma.nodeID,
		"public_key":       ma.publicKey,
		"interface_name":   ma.interfaceName,
		"listen_port":      ma.listenPort,
		"peer_count":       len(allPeers),
		"connection_count": len(connections),
		"peers":            make([]map[string]interface{}, 0, len(allPeers)),
		"connections":      make([]map[string]interface{}, 0, len(connections)),
		"discovery_stats":  ma.discovery.GetStats(),
		"topology_stats":   ma.topology.GetStats(),
	}

	// Add peer information
	for _, peer := range allPeers {
		peerMap := map[string]interface{}{
			"node_id":      peer.NodeID,
			"public_key":   peer.PublicKey,
			"endpoint":     peer.Endpoint,
			"last_seen":    peer.LastSeen,
			"reliability":  peer.Reliability,
			"rtt_ms":       peer.RTT.Milliseconds(),
			"region":       peer.Region,
			"zone":         peer.Zone,
			"capabilities": peer.Capabilities,
		}
		state["peers"] = append(state["peers"].([]map[string]interface{}), peerMap)
	}

	// Add connection information
	for _, conn := range connections {
		connMap := map[string]interface{}{
			"peer_id":     conn.PeerID,
			"status":      conn.Status.String(),
			"endpoint":    conn.Endpoint,
			"allowed_ips": conn.AllowedIPs,
			"created_at":  conn.CreatedAt,
			"last_active": conn.LastActive,
			"quality": map[string]interface{}{
				"rtt_ms":      conn.Quality.RTT.Milliseconds(),
				"reliability": conn.Quality.Reliability,
				"bandwidth":   conn.Quality.Bandwidth,
			},
		}
		state["connections"] = append(state["connections"].([]map[string]interface{}), connMap)
	}

	return state
}

// UpdateLocalPeerInfo updates the local peer information in discovery
func (ma *MeshAgent) UpdateLocalPeerInfo(metadata map[string]string, capabilities []string, region, zone string) {
	localPeer := &PeerInfo{
		NodeID:       ma.nodeID,
		PublicKey:    ma.publicKey,
		Endpoint:     fmt.Sprintf(":%d", ma.listenPort), // Will be updated with actual endpoint
		LastSeen:     time.Now(),
		Metadata:     metadata,
		Capabilities: capabilities,
		Region:       region,
		Zone:         zone,
		RTT:          0,   // Local peer has no RTT
		Reliability:  1.0, // Local peer is always reliable
	}

	// Update discovery with local peer info
	// This is mainly for consistency and debugging
	ma.discovery.AddPeer(localPeer)
}

// TriggerTopologyRebalance manually triggers a topology rebalance
func (ma *MeshAgent) TriggerTopologyRebalance() error {
	ma.logger.Info("Manually triggering topology rebalance")

	optimal, err := ma.topology.GetOptimalTopology()
	if err != nil {
		return fmt.Errorf("failed to calculate optimal topology: %w", err)
	}

	// Apply optimal topology
	current := ma.topology.GetActiveConnections()

	// Create maps for comparison
	currentMap := make(map[string]*Connection)
	for _, conn := range current {
		currentMap[conn.PeerID] = conn
	}

	optimalMap := make(map[string]*Connection)
	for _, conn := range optimal {
		optimalMap[conn.PeerID] = conn
	}

	// Remove non-optimal connections
	for peerID := range currentMap {
		if _, exists := optimalMap[peerID]; !exists {
			ma.topology.RemoveConnection(peerID)
		}
	}

	// Add new optimal connections
	for peerID, conn := range optimalMap {
		if _, exists := currentMap[peerID]; !exists {
			if err := ma.topology.AddConnection(conn); err != nil {
				ma.logger.Error("Failed to add optimal connection",
					"peer_id", peerID, "error", err)
			}
		}
	}

	ma.logger.Info("Topology rebalance completed",
		"removed", len(current)-len(optimal),
		"added", len(optimal)-len(current))

	return nil
}

// SetTopologyType changes the topology type
func (ma *MeshAgent) SetTopologyType(topologyType TopologyType) error {
	ma.logger.Info("Changing topology type",
		"old_type", ma.topology.config.Type,
		"new_type", topologyType)

	ma.topology.config.Type = topologyType

	// Trigger immediate rebalance with new topology
	return ma.TriggerTopologyRebalance()
}

// GetOptimalPeers returns the optimal peers for connection
func (ma *MeshAgent) GetOptimalPeers(maxCount int) []*PeerInfo {
	return ma.discovery.GetOptimalPeers(maxCount)
}

// ConnectToPeer manually connects to a specific peer
func (ma *MeshAgent) ConnectToPeer(peerInfo *PeerInfo, allowedIPs []string) error {
	if peerInfo == nil {
		return fmt.Errorf("peer info is nil")
	}

	// Add peer to discovery if not already present
	if err := ma.discovery.AddPeer(peerInfo); err != nil {
		return fmt.Errorf("failed to add peer to discovery: %w", err)
	}

	// Create connection in topology
	connection := &Connection{
		PeerID:     peerInfo.NodeID,
		PublicKey:  peerInfo.PublicKey,
		Endpoint:   peerInfo.Endpoint,
		AllowedIPs: allowedIPs,
		Status:     ConnectionConnecting,
		Metadata:   make(map[string]string),
	}

	if err := ma.topology.AddConnection(connection); err != nil {
		return fmt.Errorf("failed to add connection: %w", err)
	}

	ma.logger.Info("Manually connected to peer",
		"peer_id", peerInfo.NodeID,
		"endpoint", peerInfo.Endpoint)

	return nil
}

// DisconnectFromPeer manually disconnects from a specific peer
func (ma *MeshAgent) DisconnectFromPeer(peerID string) error {
	ma.topology.RemoveConnection(peerID)
	ma.discovery.RemovePeer(peerID)

	ma.logger.Info("Manually disconnected from peer", "peer_id", peerID)
	return nil
}

// ValidateConfiguration validates the mesh configuration
func (ma *MeshAgent) ValidateConfiguration() error {
	// Check if WireGuard interface exists and is configured correctly
	device, err := ma.wgClient.Device(ma.interfaceName)
	if err != nil {
		return fmt.Errorf("WireGuard interface not found: %w", err)
	}

	if device.PrivateKey.String() != ma.privateKey.String() {
		return fmt.Errorf("WireGuard private key mismatch")
	}

	if device.ListenPort != ma.listenPort {
		ma.logger.Warn("WireGuard listen port mismatch",
			"expected", ma.listenPort,
			"actual", device.ListenPort)
	}

	ma.logger.Info("Mesh configuration validation passed")
	return nil
}

// GetHealthStatus returns the health status of the mesh agent
func (ma *MeshAgent) GetHealthStatus() map[string]interface{} {
	discoveryStats := ma.discovery.GetStats()
	topologyStats := ma.topology.GetStats()

	isHealthy := true
	issues := make([]string, 0)

	// Check discovery health
	if discoveryActive, ok := discoveryStats["discovery_active"].(bool); !ok || !discoveryActive {
		isHealthy = false
		issues = append(issues, "discovery not active")
	}

	// Check if we have minimum connections
	if activeConns, ok := topologyStats["active_connections"].(int); ok {
		minConns := ma.topology.config.MinConnections
		if activeConns < minConns {
			isHealthy = false
			issues = append(issues, fmt.Sprintf("insufficient connections: %d/%d", activeConns, minConns))
		}
	}

	// Check WireGuard interface
	if err := ma.ValidateConfiguration(); err != nil {
		isHealthy = false
		issues = append(issues, fmt.Sprintf("wireguard validation failed: %v", err))
	}

	status := map[string]interface{}{
		"healthy":         isHealthy,
		"issues":          issues,
		"node_id":         ma.nodeID,
		"discovery_stats": discoveryStats,
		"topology_stats":  topologyStats,
		"uptime_seconds":  time.Since(ma.ctx.Value("start_time").(time.Time)).Seconds(),
	}

	return status
}
