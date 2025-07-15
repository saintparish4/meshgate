-- Enable foreign key constraints
PRAGMA foreign_keys = ON;

-- Create tenants table for multi-tenancy
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    settings TEXT DEFAULT '{}', -- JSON
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create nodes table
CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL UNIQUE,
    ip_address TEXT NOT NULL,
    endpoint TEXT,
    listen_port INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'offline',
    last_seen DATETIME,
    metadata TEXT DEFAULT '{}', -- JSON
    tags TEXT DEFAULT '[]', -- JSON array
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Create node_peers table for peer relationships
CREATE TABLE IF NOT EXISTS node_peers (
    id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    peer_node_id TEXT NOT NULL,
    allowed_ips TEXT DEFAULT '[]', -- JSON array
    preshared_key TEXT,
    persistent_keepalive INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (peer_node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    UNIQUE(node_id, peer_node_id)
);

-- Create node_connections table for connection statistics
CREATE TABLE IF NOT EXISTS node_connections (
    id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    peer_node_id TEXT NOT NULL,
    bytes_received INTEGER DEFAULT 0,
    bytes_transmitted INTEGER DEFAULT 0,
    packets_received INTEGER DEFAULT 0,
    packets_transmitted INTEGER DEFAULT 0,
    last_handshake DATETIME,
    latency_ms INTEGER DEFAULT 0,
    quality REAL DEFAULT 0.0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (peer_node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    UNIQUE(node_id, peer_node_id)
);

-- Create indexes for nodes table
CREATE INDEX IF NOT EXISTS idx_nodes_tenant_id ON nodes(tenant_id);
CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status);
CREATE INDEX IF NOT EXISTS idx_nodes_last_seen ON nodes(last_seen);
CREATE INDEX IF NOT EXISTS idx_nodes_public_key ON nodes(public_key);

-- Create indexes for node_peers table
CREATE INDEX IF NOT EXISTS idx_node_peers_node_id ON node_peers(node_id);
CREATE INDEX IF NOT EXISTS idx_node_peers_peer_node_id ON node_peers(peer_node_id);

-- Create indexes for node_connections table
CREATE INDEX IF NOT EXISTS idx_node_connections_node_id ON node_connections(node_id);
CREATE INDEX IF NOT EXISTS idx_node_connections_peer_node_id ON node_connections(peer_node_id);
CREATE INDEX IF NOT EXISTS idx_node_connections_updated_at ON node_connections(updated_at);

-- Create triggers for updated_at timestamps
CREATE TRIGGER IF NOT EXISTS update_tenants_updated_at
    AFTER UPDATE ON tenants
BEGIN
    UPDATE tenants SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS update_nodes_updated_at
    AFTER UPDATE ON nodes
BEGIN
    UPDATE nodes SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS update_node_peers_updated_at
    AFTER UPDATE ON node_peers
BEGIN
    UPDATE node_peers SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS update_node_connections_updated_at
    AFTER UPDATE ON node_connections
BEGIN
    UPDATE node_connections SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;