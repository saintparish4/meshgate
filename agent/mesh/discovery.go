package mesh

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// PeerInfo represents information about a discovered peer
type PeerInfo struct {
	NodeID       string            `json:"node_id"`
	PublicKey    string            `json:"public_key"`
	Endpoint     string            `json:"endpoint"`
	LastSeen     time.Time         `json:"last_seen"`
	Metadata     map[string]string `json:"metadata"`
	Capabilities []string          `json:"capabilities"`
	Region       string            `json:"region"`
	Zone         string            `json:"zone"`
	RTT          time.Duration     `json:"rtt"`
	Reliability  float64           `json:"reliability"` // 0-1 score
}

// DiscoveryConfig holds configuration for peer discovery
type DiscoveryConfig struct {
	DiscoveryInterval    time.Duration `json:"discovery_interval"`
	PeerTimeout          time.Duration `json:"peer_timeout"`
	MaxPeers             int           `json:"max_peers"`
	PreferredRegions     []string      `json:"preferred_regions"`
	EnabledHealthCheck   bool          `json:"enabled_health_check"`
	HealthCheckInterval  time.Duration `json:"health_check_interval"`
	RTTThreshold         time.Duration `json:"rtt_threshold"`
	ReliabilityThreshold float64       `json:"reliability_threshold"`
}

// Discovery handles peer discovery and management
type Discovery struct {
	config    *DiscoveryConfig
	logger    *slog.Logger
	peers     map[string]*PeerInfo
	callbacks []PeerCallback
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
}

// PeerCallback is called when peer events occur
type PeerCallback func(event PeerEvent, peer *PeerInfo)

// PeerEvent represents different peer lifecycle events
type PeerEvent int

const (
	PeerDiscovered PeerEvent = iota
	PeerUpdated
	PeerLost
	PeerHealthy
	PeerUnhealthy
)

// NewDiscovery creates a new peer discovery instance
func NewDiscovery(config *DiscoveryConfig, logger *slog.Logger) *Discovery {
	if config == nil {
		config = &DiscoveryConfig{
			DiscoveryInterval:    30 * time.Second,
			PeerTimeout:          10 * time.Second,
			MaxPeers:             100,
			EnabledHealthCheck:   true,
			HealthCheckInterval:  60 * time.Second,
			RTTThreshold:         500 * time.Millisecond,
			ReliabilityThreshold: 0.9,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Discovery{
		config:    config,
		logger:    logger,
		peers:     make(map[string]*PeerInfo),
		callbacks: make([]PeerCallback, 0),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Start begins peer discovery (stub)
func (d *Discovery) Start() error {
	// Start background discovery loop (not implemented)
	d.logger.Info("Discovery started")
	return nil
}

// Stop ends peer discovery (stub)
func (d *Discovery) Stop() error {
	d.logger.Info("Discovery stopped")
	d.cancel()
	return nil
}

// AddCallback registers a callback for peer events
func (d *Discovery) AddCallback(cb PeerCallback) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.callbacks = append(d.callbacks, cb)
}

// AddPeer adds or updates a peer in discovery
func (d *Discovery) AddPeer(peer *PeerInfo) error {
	if peer == nil || peer.NodeID == "" {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.peers[peer.NodeID] = peer
	return nil
}

// RemovePeer removes a peer from discovery
func (d *Discovery) RemovePeer(nodeID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.peers, nodeID)
}

// GetStats returns simple stats about discovery
func (d *Discovery) GetStats() map[string]interface{} {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return map[string]interface{}{
		"peer_count":       len(d.peers),
		"discovery_active": d.ctx.Err() == nil,
	}
}

// GetPeer returns a peer by node ID
func (d *Discovery) GetPeer(nodeID string) (*PeerInfo, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	peer, ok := d.peers[nodeID]
	return peer, ok
}

// GetAllPeers returns all known peers
func (d *Discovery) GetAllPeers() []*PeerInfo {
	d.mu.RLock()
	defer d.mu.RUnlock()
	peers := make([]*PeerInfo, 0, len(d.peers))
	for _, p := range d.peers {
		peers = append(peers, p)
	}
	return peers
}

// GetOptimalPeers returns up to maxCount peers (simple: all peers)
func (d *Discovery) GetOptimalPeers(maxCount int) []*PeerInfo {
	peers := d.GetAllPeers()
	if len(peers) > maxCount {
		return peers[:maxCount]
	}
	return peers
}

// UpdatePeerRTT updates the RTT for a peer (stub)
func (d *Discovery) UpdatePeerRTT(nodeID string, rtt time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if peer, ok := d.peers[nodeID]; ok {
		peer.RTT = rtt
	}
}

// UpdatePeerReliability updates the reliability for a peer (stub)
func (d *Discovery) UpdatePeerReliability(nodeID string, reliability float64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if peer, ok := d.peers[nodeID]; ok {
		peer.Reliability = reliability
	}
}
