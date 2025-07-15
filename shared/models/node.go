package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/saintparish4/meshgate/shared/utils"
)

// NodeStatus represents the current status of a node
type NodeStatus string

const (
	NodeStatusOnline     NodeStatus = "online"
	NodeStatusOffline    NodeStatus = "offline"
	NodeStatusConnecting NodeStatus = "connecting"
	NodeStatusError      NodeStatus = "error"
)

// Node represents a mesh network node
type Node struct {
	ID         string       `json:"id" db:"id"`
	TenantID   string       `json:"tenant_id" db:"tenant_id"`
	Name       string       `json:"name" db:"name"`
	PublicKey  string       `json:"public_key" db:"public_key"`
	IPAddress  string       `json:"ip_address" db:"ip_address"`
	Endpoint   string       `json:"endpoint" db:"endpoint"`
	ListenPort int          `json:"listen_port" db:"listen_port"`
	Status     NodeStatus   `json:"status" db:"status"`
	LastSeen   *time.Time   `json:"last_seen" db:"last_seen"`
	Metadata   NodeMetadata `json:"metadata" db:"metadata"`
	Tags       StringArray  `json:"tags" db:"tags"`
	CreatedAt  time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time    `json:"updated_at" db:"updated_at"`

	// Relationships
	Peers       []NodePeer       `json:"peers,omitempty" db:"-"`
	Connections []NodeConnection `json:"connections,omitempty" db:"-"`
}

// NodeMetadata stores flexible node information
type NodeMetadata struct {
	Platform     string            `json:"platform"`
	Version      string            `json:"version"`
	AgentType    string            `json:"agent_type"`
	MTU          int               `json:"mtu"`
	Location     string            `json:"location,omitempty"`
	Environment  string            `json:"environment,omitempty"`
	CustomFields map[string]string `json:"custom_fields,omitempty"`
}

// NodePeer represents a peer relationship between nodes
type NodePeer struct {
	ID                  string      `json:"id" db:"id"`
	NodeID              string      `json:"node_id" db:"node_id"`
	PeerNodeID          string      `json:"peer_node_id" db:"peer_node_id"`
	AllowedIPs          StringArray `json:"allowed_ips" db:"allowed_ips"`
	PersistentKeepalive int         `json:"persistent_keepalive" db:"persistent_keepalive"`
	CreatedAt           time.Time   `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time   `json:"updated_at" db:"updated_at"`

	// Computed fields
	PeerNode *Node `json:"peer_node,omitempty" db:"-"`
}

// NodeConnection represents active connection statistics
type NodeConnection struct {
	ID                 string     `json:"id" db:"id"`
	NodeID             string     `json:"node_id" db:"node_id"`
	PeerNodeID         string     `json:"peer_node_id" db:"peer_node_id"`
	BytesReceived      int64      `json:"bytes_received" db:"bytes_received"`
	BytesTransmitted   int64      `json:"bytes_transmitted" db:"bytes_transmitted"`
	PacketsReceived    int64      `json:"packets_received" db:"packets_received"`
	PacketsTransmitted int64      `json:"packets_transmitted" db:"packets_transmitted"`
	LastHandshake      *time.Time `json:"last_handshake" db:"last_handshake"`
	Latency            int        `json:"latency_ms" db:"latency_ms"`
	Quality            float64    `json:"quality" db:"quality"`
	CreatedAt          time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at" db:"updated_at"`
}

// StringArray is a custom type for handling string arrays in SQL
type StringArray []string

// Scan implements the sql.Scanner interface
func (s *StringArray) Scan(value interface{}) error {
	if value == nil {
		*s = StringArray{}
		return nil
	}
	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, s)
	case string:
		return json.Unmarshal([]byte(v), s)
	default:
		return fmt.Errorf("cannot scan %T into StringArray", value)
	}
}

// Value implements the driver.Valuer interface
func (s StringArray) Value() (driver.Value, error) {
	if len(s) == 0 {
		return "[]", nil
	}
	return json.Marshal(s)
}

// Scan implements the sql.Scanner interface for NodeMetadata
func (nm *NodeMetadata) Scan(value interface{}) error {
	if value == nil {
		*nm = NodeMetadata{}
		return nil
	}
	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, nm)
	case string:
		return json.Unmarshal([]byte(v), nm)
	default:
		return fmt.Errorf("cannot scan %T into NodeMetadata", value)
	}
}

// Value implements the driver.Valuer interface for NodeMetadata
func (nm NodeMetadata) Value() (driver.Value, error) {
	return json.Marshal(nm)
}

// TableName returns the database table name for Node
func (Node) TableName() string {
	return "nodes"
}

// TableName returns the database table name for NodePeer
func (NodePeer) TableName() string {
	return "node_peers"
}

// TableName returns the database table name for NodeConnection
func (NodeConnection) TableName() string {
	return "node_connections"
}

// IsOnline returns true if the node is currently online
func (n *Node) IsOnline() bool {
	return n.Status == NodeStatusOnline && n.LastSeen != nil && time.Since(*n.LastSeen) < 5*time.Minute
}

// GetAllowedIPsForPeer returns the allowed IPs for a specific peer
func (n *Node) GetAllowedIPsForPeer(peerID string) []string {
	for _, peer := range n.Peers {
		if peer.PeerNodeID == peerID {
			return peer.AllowedIPs
		}
	}
	return []string{}
}

// AddPeer adds a new peer to the node
func (n *Node) AddPeer(peerID string, allowedIPs []string) {
	// Check if peer already exists
	for i, peer := range n.Peers {
		if peer.PeerNodeID == peerID {
			// Update existing peer
			n.Peers[i].AllowedIPs = allowedIPs
			n.Peers[i].UpdatedAt = time.Now()
			return
		}
	}

	// Add new peer
	newPeer := NodePeer{
		ID:         utils.GenerateID(),
		NodeID:     n.ID,
		PeerNodeID: peerID,
		AllowedIPs: allowedIPs,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	n.Peers = append(n.Peers, newPeer)
}

// RemovePeer removes a peer from the node
func (n *Node) RemovePeer(peerID string) {
	for i, peer := range n.Peers {
		if peer.PeerNodeID == peerID {
			n.Peers = append(n.Peers[:i], n.Peers[i+1:]...)
			return
		}
	}
}

// UpdateConnectionStats updates connection statistics for a peer
func (n *Node) UpdateConnectionStats(peerID string, stats NodeConnection) {
	for i, conn := range n.Connections {
		if conn.PeerNodeID == peerID {
			n.Connections[i] = stats
			n.Connections[i].UpdatedAt = time.Now()
			return
		}
	}

	// Add new connection stats
	stats.ID = utils.GenerateID()
	stats.NodeID = n.ID
	stats.CreatedAt = time.Now()
	stats.UpdatedAt = time.Now()
	n.Connections = append(n.Connections, stats)
}

// GetConnectionQuality returns the average connection quality
func (n *Node) GetConnectionQuality() float64 {
	if len(n.Connections) == 0 {
		return 0.0
	}
	var total float64
	for _, conn := range n.Connections {
		total += conn.Quality
	}
	return total / float64(len(n.Connections))
}

// Validate validates the node data
func (n *Node) Validate() error {
	if n.ID == "" {
		return fmt.Errorf("node ID is required")
	}
	if n.TenantID == "" {
		return fmt.Errorf("tenant ID is required")
	}
	if n.Name == "" {
		return fmt.Errorf("node name is required")
	}
	if n.PublicKey == "" {
		return fmt.Errorf("public key is required")
	}
	if n.IPAddress == "" {
		return fmt.Errorf("IP address is required")
	}
	if n.ListenPort < 1 || n.ListenPort > 65535 {
		return fmt.Errorf("invalid listen port: %d", n.ListenPort)
	}
	return nil
}
