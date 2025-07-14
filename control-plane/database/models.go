package database

import (
	"time"
)

// User represents a user in the system
type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"password_hash"`
	Role         string    `json:"role"` // admin, user, viewer
	TenantID     string    `json:"tenant_id"`
	CreatedAt    time.Time `json:"created_at"`
	LastLogin    time.Time `json:"last_login"`
}

// TenantSettings represents tenant configuration
type TenantSettings struct {
	SubnetCIDR        string `json:"subnet_cidr"`
	MaxNodes          int    `json:"max_nodes"`
	PolicyMode        string `json:"policy_mode"`
	HeartbeatInterval int    `json:"heartbeat_interval"`
}

// Tenant represents a tenant in the system
type Tenant struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Domain    string         `json:"domain"`
	Settings  TenantSettings `json:"settings"`
	CreatedAt time.Time      `json:"created_at"`
	IsActive  bool           `json:"is_active"`
	NodeLimit int            `json:"node_limit"`
	UsedNodes int            `json:"used_nodes"`
}

// Node represents a mesh node
type Node struct {
	ID        string            `json:"id"`
	TenantID  string            `json:"tenant_id"`
	Name      string            `json:"name"`
	PublicKey string            `json:"public_key"`
	IPAddress string            `json:"ip_address"`
	Status    string            `json:"status"` // online, offline, maintenance, unknown
	LastSeen  time.Time         `json:"last_seen"`
	CreatedAt time.Time         `json:"created_at"`
	Metadata  map[string]string `json:"metadata"`
}
