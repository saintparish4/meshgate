package models

import (
	"time"
)

// MeshNode represents a node in the mesh network for API operations
// This is a simplified version of the Node model for mesh-specific operations
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

// String methods for better debugging and logging
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
		return "shutting_down"
	default:
		return "unknown"
	}
}
