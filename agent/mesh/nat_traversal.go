package mesh

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// NATType represents the type of NAT detected
type NATType int

const (
	NATTypeUnknown NATType = iota
	NATTypeOpen
	NATTypeFullCone
	NATTypeRestrictedCone
	NATTypePortRestrictedCone
	NATTypeSymmetric
	NATTypeBlocked
)

// NATTraversalConfig holds configuration for NAT traversal
type NATTraversalConfig struct {
	STUNServers        []string      `json:"stun_servers"`
	TURNServers        []TURNServer  `json:"turn_servers"`
	DiscoveryInterval  time.Duration `json:"discovery_interval"`
	KeepAliveInterval  time.Duration `json:"keep_alive_interval"`
	MaxRetries         int           `json:"max_retries"`
	Timeout            time.Duration `json:"timeout"`
	EnableRelay        bool          `json:"enable_relay"`
	EnableHolePunching bool          `json:"enable_hole_punching"`
}

// TURNServer represents a TURN server configuration
type TURNServer struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
	Realm    string `json:"realm"`
}

// NATMapping represents a NAT mapping discovered
type NATMapping struct {
	InternalAddr *net.UDPAddr
	ExternalAddr *net.UDPAddr
	NATType      NATType
	Lifetime     time.Duration
	LastSeen     time.Time
}

// PeerNATInfo holds NAT information for a peer
type PeerNATInfo struct {
	NodeID       string
	NATType      NATType
	ExternalAddr *net.UDPAddr
	Mappings     []*NATMapping
	LastUpdate   time.Time
}

// NATTraversal handles NAT traversal for mesh networking
type NATTraversal struct {
	config    *NATTraversalConfig
	logger    *slog.Logger
	peers     map[string]*PeerNATInfo
	callbacks []NATCallback
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
}

// NATCallback is called when NAT events occur
type NATCallback func(event NATEvent, data interface{})

// NATEvent represents different NAT traversal events
type NATEvent int

const (
	NATMappingDiscovered NATEvent = iota
	NATMappingExpired
	NATTypeChanged
	HolePunchSuccess
	HolePunchFailed
	RelayEstablished
)

// NewNATTraversal creates a new NAT traversal instance
func NewNATTraversal(config *NATTraversalConfig, logger *slog.Logger) *NATTraversal {
	if config == nil {
		config = &NATTraversalConfig{
			STUNServers: []string{
				"stun:stun.l.google.com:19302",
				"stun:stun1.l.google.com:19302",
				"stun:stun2.l.google.com:19302",
			},
			DiscoveryInterval:  30 * time.Second,
			KeepAliveInterval:  60 * time.Second,
			MaxRetries:         3,
			Timeout:            10 * time.Second,
			EnableRelay:        true,
			EnableHolePunching: true,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &NATTraversal{
		config:    config,
		logger:    logger,
		peers:     make(map[string]*PeerNATInfo),
		callbacks: make([]NATCallback, 0),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Start begins NAT traversal services
func (nt *NATTraversal) Start() error {
	nt.logger.Info("Starting NAT traversal services")

	// Start background services
	go nt.discoveryLoop()
	go nt.keepAliveLoop()
	go nt.mappingCleanupLoop()

	nt.logger.Info("NAT traversal services started")
	return nil
}

// Stop ends NAT traversal services
func (nt *NATTraversal) Stop() error {
	nt.logger.Info("Stopping NAT traversal services")
	nt.cancel()
	nt.logger.Info("NAT traversal services stopped")
	return nil
}

// DiscoverNATMapping discovers NAT mapping using external service
func (nt *NATTraversal) DiscoverNATMapping() (*NATMapping, error) {
	// Create UDP connection to discover local address
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP connection: %w", err)
	}
	defer conn.Close()

	internalAddr := conn.LocalAddr().(*net.UDPAddr)

	// For now, assume external address is the same (simplified)
	// In a real implementation, you would use STUN to discover the external address
	externalAddr := &net.UDPAddr{
		IP:   internalAddr.IP,
		Port: internalAddr.Port,
	}

	// Determine NAT type (simplified)
	natType := nt.determineNATType(internalAddr, externalAddr)

	return &NATMapping{
		InternalAddr: internalAddr,
		ExternalAddr: externalAddr,
		NATType:      natType,
		Lifetime:     300 * time.Second, // Default 5 minutes
		LastSeen:     time.Now(),
	}, nil
}

// determineNATType determines the type of NAT (simplified implementation)
func (nt *NATTraversal) determineNATType(internal, external *net.UDPAddr) NATType {
	// This is a simplified NAT type detection
	// In a real implementation, you would perform multiple STUN tests
	// to determine the exact NAT type

	if internal.IP.Equal(external.IP) && internal.Port == external.Port {
		return NATTypeOpen
	}

	// For now, assume it's a cone NAT
	return NATTypeFullCone
}

// AttemptHolePunch attempts to establish a direct connection with a peer
func (nt *NATTraversal) AttemptHolePunch(peerID string, peerAddr *net.UDPAddr) error {
	nt.logger.Info("Attempting hole punch", "peer", peerID, "address", peerAddr)

	// Create UDP connection
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return fmt.Errorf("failed to create UDP connection: %w", err)
	}
	defer conn.Close()

	// Send hole punch packet
	punchPacket := []byte("HOLE_PUNCH")
	if _, err := conn.WriteToUDP(punchPacket, peerAddr); err != nil {
		return fmt.Errorf("failed to send hole punch packet: %w", err)
	}

	// Wait for response
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("failed to set read deadline: %w", err)
	}

	buffer := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		return fmt.Errorf("hole punch failed: %w", err)
	}

	nt.logger.Info("Hole punch successful", "peer", peerID, "response", string(buffer[:n]))
	nt.notifyCallbacks(HolePunchSuccess, peerID)
	return nil
}

// EstablishRelay establishes a relay connection through TURN server (simplified)
func (nt *NATTraversal) EstablishRelay(peerID string) (*net.UDPConn, error) {
	if len(nt.config.TURNServers) == 0 {
		return nil, fmt.Errorf("no TURN servers configured")
	}

	// Simplified relay implementation
	// In a real implementation, you would use TURN protocol
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create relay connection: %w", err)
	}

	nt.logger.Info("Relay established", "peer", peerID, "relay", conn.LocalAddr())
	nt.notifyCallbacks(RelayEstablished, peerID)
	return conn, nil
}

// AddPeer adds a peer for NAT traversal
func (nt *NATTraversal) AddPeer(peerID string, natInfo *PeerNATInfo) {
	nt.mu.Lock()
	defer nt.mu.Unlock()
	nt.peers[peerID] = natInfo
}

// GetPeerNATInfo gets NAT information for a peer
func (nt *NATTraversal) GetPeerNATInfo(peerID string) (*PeerNATInfo, bool) {
	nt.mu.RLock()
	defer nt.mu.RUnlock()
	info, exists := nt.peers[peerID]
	return info, exists
}

// AddCallback adds a callback for NAT events
func (nt *NATTraversal) AddCallback(callback NATCallback) {
	nt.mu.Lock()
	defer nt.mu.Unlock()
	nt.callbacks = append(nt.callbacks, callback)
}

// discoveryLoop runs the NAT discovery loop
func (nt *NATTraversal) discoveryLoop() {
	ticker := time.NewTicker(nt.config.DiscoveryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-nt.ctx.Done():
			return
		case <-ticker.C:
			nt.performDiscovery()
		}
	}
}

// keepAliveLoop runs the keep-alive loop
func (nt *NATTraversal) keepAliveLoop() {
	ticker := time.NewTicker(nt.config.KeepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-nt.ctx.Done():
			return
		case <-ticker.C:
			nt.sendKeepAlives()
		}
	}
}

// mappingCleanupLoop cleans up expired mappings
func (nt *NATTraversal) mappingCleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-nt.ctx.Done():
			return
		case <-ticker.C:
			nt.cleanupExpiredMappings()
		}
	}
}

// performDiscovery performs NAT discovery
func (nt *NATTraversal) performDiscovery() {
	mapping, err := nt.DiscoverNATMapping()
	if err != nil {
		nt.logger.Warn("NAT discovery failed", "error", err)
		return
	}

	nt.logger.Info("NAT mapping discovered",
		"internal", mapping.InternalAddr,
		"external", mapping.ExternalAddr,
		"type", mapping.NATType)

	nt.notifyCallbacks(NATMappingDiscovered, mapping)
}

// sendKeepAlives sends keep-alive packets
func (nt *NATTraversal) sendKeepAlives() {
	// Send keep-alive to STUN servers to maintain NAT mappings
	for _, stunServer := range nt.config.STUNServers {
		go nt.sendKeepAliveToServer(stunServer)
	}
}

// sendKeepAliveToServer sends keep-alive to a specific STUN server
func (nt *NATTraversal) sendKeepAliveToServer(serverURL string) {
	// Implementation would send a STUN binding request
	// to keep the NAT mapping alive
	_ = serverURL // TODO: Implement actual keep-alive logic
	nt.logger.Debug("Sending keep-alive", "server", serverURL)
}

// cleanupExpiredMappings removes expired NAT mappings
func (nt *NATTraversal) cleanupExpiredMappings() {
	nt.mu.Lock()
	defer nt.mu.Unlock()

	now := time.Now()
	for peerID, peerInfo := range nt.peers {
		var validMappings []*NATMapping
		for _, mapping := range peerInfo.Mappings {
			if now.Sub(mapping.LastSeen) < mapping.Lifetime {
				validMappings = append(validMappings, mapping)
			} else {
				nt.notifyCallbacks(NATMappingExpired, mapping)
			}
		}
		peerInfo.Mappings = validMappings
		_ = peerID // Avoid unused variable warning
	}
}

// notifyCallbacks notifies registered callbacks
func (nt *NATTraversal) notifyCallbacks(event NATEvent, data interface{}) {
	nt.mu.RLock()
	callbacks := make([]NATCallback, len(nt.callbacks))
	copy(callbacks, nt.callbacks)
	nt.mu.RUnlock()

	for _, callback := range callbacks {
		go callback(event, data)
	}
}

// GetStats returns NAT traversal statistics
func (nt *NATTraversal) GetStats() map[string]interface{} {
	nt.mu.RLock()
	defer nt.mu.RUnlock()

	return map[string]interface{}{
		"peers_count":          len(nt.peers),
		"stun_servers":         len(nt.config.STUNServers),
		"turn_servers":         len(nt.config.TURNServers),
		"enable_relay":         nt.config.EnableRelay,
		"enable_hole_punching": nt.config.EnableHolePunching,
	}
}

// String returns string representation of NAT type
func (nt NATType) String() string {
	switch nt {
	case NATTypeUnknown:
		return "Unknown"
	case NATTypeOpen:
		return "Open"
	case NATTypeFullCone:
		return "Full Cone"
	case NATTypeRestrictedCone:
		return "Restricted Cone"
	case NATTypePortRestrictedCone:
		return "Port Restricted Cone"
	case NATTypeSymmetric:
		return "Symmetric"
	case NATTypeBlocked:
		return "Blocked"
	default:
		return "Unknown"
	}
}
