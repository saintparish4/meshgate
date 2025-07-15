-- Database schema for network topology and mesh management

-- Create network_topologies table
CREATE TABLE IF NOT EXISTS network_topologies (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    type TEXT NOT NULL, -- full, hub, ring, tree, custom, auto
    configuration TEXT DEFAULT '{}', -- JSON TopologyConfig
    metrics TEXT DEFAULT '{}', -- JSON TopologyMetrics
    status TEXT NOT NULL DEFAULT 'inactive',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Create topology_links table for mesh connections
CREATE TABLE IF NOT EXISTS topology_links (
    id TEXT PRIMARY KEY,
    topology_id TEXT NOT NULL,
    node_a_id TEXT NOT NULL,
    node_b_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active', -- active, inactive, degraded
    quality REAL DEFAULT 1.0,
    latency_ms INTEGER DEFAULT 0,
    bandwidth_mbps INTEGER DEFAULT 0,
    cost REAL DEFAULT 0.0,
    weight REAL DEFAULT 1.0,
    properties TEXT DEFAULT '{}', -- JSON LinkProperties
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (topology_id) REFERENCES network_topologies(id) ON DELETE CASCADE,
    FOREIGN KEY (node_a_id) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (node_b_id) REFERENCES nodes(id) ON DELETE CASCADE,
    UNIQUE(topology_id, node_a_id, node_b_id)
);

-- Create network_subnets table
CREATE TABLE IF NOT EXISTS network_subnets (
    id TEXT PRIMARY KEY,
    topology_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    cidr TEXT NOT NULL,
    gateway TEXT,
    dns_servers TEXT DEFAULT '[]', -- JSON array
    purpose TEXT DEFAULT 'mesh', -- mesh, services, management
    isolated BOOLEAN DEFAULT FALSE,
    tags TEXT DEFAULT '[]', -- JSON array
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (topology_id) REFERENCES network_topologies(id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Create routing_tables table
CREATE TABLE IF NOT EXISTS routing_tables (
    id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    topology_id TEXT NOT NULL,
    routes TEXT DEFAULT '[]', -- JSON array of RouteEntry
    version INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (topology_id) REFERENCES network_topologies(id) ON DELETE CASCADE,
    UNIQUE(node_id, topology_id)
);

-- Create topology_changes table for tracking modifications
CREATE TABLE IF NOT EXISTS topology_changes (
    id TEXT PRIMARY KEY,
    topology_id TEXT NOT NULL,
    change_type TEXT NOT NULL, -- add_node, remove_node, add_link, remove_link, optimize
    node_id TEXT,
    peer_node_id TEXT,
    old_value TEXT,
    new_value TEXT,
    reason TEXT,
    user_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (topology_id) REFERENCES network_topologies(id) ON DELETE CASCADE,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE SET NULL,
    FOREIGN KEY (peer_node_id) REFERENCES nodes(id) ON DELETE SET NULL
);

-- Create mesh_metrics table for performance tracking
CREATE TABLE IF NOT EXISTS mesh_metrics (
    id TEXT PRIMARY KEY,
    topology_id TEXT NOT NULL,
    node_id TEXT,
    metric_type TEXT NOT NULL, -- latency, bandwidth, packet_loss, jitter
    value REAL NOT NULL,
    unit TEXT NOT NULL,
    source_node_id TEXT,
    destination_node_id TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (topology_id) REFERENCES network_topologies(id) ON DELETE CASCADE,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (source_node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    FOREIGN KEY (destination_node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

-- Create subnet_assignments table for node-subnet relationships
CREATE TABLE IF NOT EXISTS subnet_assignments (
    id TEXT PRIMARY KEY,
    subnet_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (subnet_id) REFERENCES network_subnets(id) ON DELETE CASCADE,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE,
    UNIQUE(subnet_id, node_id),
    UNIQUE(subnet_id, ip_address)
);

-- Create indexes for network_topologies table
CREATE INDEX IF NOT EXISTS idx_network_topologies_tenant_id ON network_topologies(tenant_id);
CREATE INDEX IF NOT EXISTS idx_network_topologies_type ON network_topologies(type);
CREATE INDEX IF NOT EXISTS idx_network_topologies_status ON network_topologies(status);

-- Create indexes for topology_links table
CREATE INDEX IF NOT EXISTS idx_topology_links_topology_id ON topology_links(topology_id);
CREATE INDEX IF NOT EXISTS idx_topology_links_node_a_id ON topology_links(node_a_id);
CREATE INDEX IF NOT EXISTS idx_topology_links_node_b_id ON topology_links(node_b_id);
CREATE INDEX IF NOT EXISTS idx_topology_links_status ON topology_links(status);
CREATE INDEX IF NOT EXISTS idx_topology_links_quality ON topology_links(quality);

-- Create indexes for network_subnets table
CREATE INDEX IF NOT EXISTS idx_network_subnets_topology_id ON network_subnets(topology_id);
CREATE INDEX IF NOT EXISTS idx_network_subnets_tenant_id ON network_subnets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_network_subnets_purpose ON network_subnets(purpose);

-- Create indexes for routing_tables table
CREATE INDEX IF NOT EXISTS idx_routing_tables_node_id ON routing_tables(node_id);
CREATE INDEX IF NOT EXISTS idx_routing_tables_topology_id ON routing_tables(topology_id);
CREATE INDEX IF NOT EXISTS idx_routing_tables_version ON routing_tables(version);

-- Create indexes for topology_changes table
CREATE INDEX IF NOT EXISTS idx_topology_changes_topology_id ON topology_changes(topology_id);
CREATE INDEX IF NOT EXISTS idx_topology_changes_change_type ON topology_changes(change_type);
CREATE INDEX IF NOT EXISTS idx_topology_changes_created_at ON topology_changes(created_at);

-- Create indexes for mesh_metrics table
CREATE INDEX IF NOT EXISTS idx_mesh_metrics_topology_id ON mesh_metrics(topology_id);
CREATE INDEX IF NOT EXISTS idx_mesh_metrics_node_id ON mesh_metrics(node_id);
CREATE INDEX IF NOT EXISTS idx_mesh_metrics_metric_type ON mesh_metrics(metric_type);
CREATE INDEX IF NOT EXISTS idx_mesh_metrics_timestamp ON mesh_metrics(timestamp);

-- Create indexes for subnet_assignments table
CREATE INDEX IF NOT EXISTS idx_subnet_assignments_subnet_id ON subnet_assignments(subnet_id);
CREATE INDEX IF NOT EXISTS idx_subnet_assignments_node_id ON subnet_assignments(node_id);

-- Create triggers for updated_at timestamps
CREATE TRIGGER IF NOT EXISTS update_network_topologies_updated_at
    AFTER UPDATE ON network_topologies
BEGIN
    UPDATE network_topologies SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS update_topology_links_updated_at
    AFTER UPDATE ON topology_links
BEGIN
    UPDATE topology_links SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS update_network_subnets_updated_at
    AFTER UPDATE ON network_subnets
BEGIN
    UPDATE network_subnets SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS update_routing_tables_updated_at
    AFTER UPDATE ON routing_tables
BEGIN
    UPDATE routing_tables SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Create views for topology analysis
CREATE VIEW IF NOT EXISTS topology_overview AS
SELECT 
    t.id,
    t.tenant_id,
    t.name,
    t.type,
    t.status,
    COUNT(DISTINCT tl.node_a_id) + COUNT(DISTINCT tl.node_b_id) as node_count,
    COUNT(tl.id) as link_count,
    AVG(tl.quality) as avg_quality,
    AVG(tl.latency_ms) as avg_latency,
    SUM(tl.cost) as total_cost,
    t.created_at,
    t.updated_at
FROM network_topologies t
LEFT JOIN topology_links tl ON t.id = tl.topology_id AND tl.status = 'active'
GROUP BY t.id;

-- Create view for node connectivity
CREATE VIEW IF NOT EXISTS node_connectivity AS
SELECT 
    n.id as node_id,
    n.tenant_id,
    n.name as node_name,
    COUNT(DISTINCT CASE WHEN tl.node_a_id = n.id THEN tl.node_b_id 
                       WHEN tl.node_b_id = n.id THEN tl.node_a_id END) as peer_count,
    AVG(CASE WHEN tl.node_a_id = n.id OR tl.node_b_id = n.id THEN tl.quality END) as avg_quality,
    AVG(CASE WHEN tl.node_a_id = n.id OR tl.node_b_id = n.id THEN tl.latency_ms END) as avg_latency
FROM nodes n
LEFT JOIN topology_links tl ON (tl.node_a_id = n.id OR tl.node_b_id = n.id) AND tl.status = 'active'
GROUP BY n.id;

-- Create view for subnet utilization
CREATE VIEW IF NOT EXISTS subnet_utilization AS
SELECT 
    s.id as subnet_id,
    s.name as subnet_name,
    s.cidr,
    s.purpose,
    COUNT(sa.node_id) as assigned_nodes,
    s.created_at
FROM network_subnets s
LEFT JOIN subnet_assignments sa ON s.id = sa.subnet_id
GROUP BY s.id;

-- Insert default topology if not exists
INSERT OR IGNORE INTO network_topologies (
    id, tenant_id, name, description, type, configuration, status
) VALUES (
    'default-auto-topology',
    'default',
    'Default Auto Topology',
    'Automatically optimized mesh topology for default tenant',
    'auto',
    '{
        "max_peers_per_node": 5,
        "redundancy_level": 2,
        "auto_optimize": true,
        "optimization_metric": "latency",
        "constraints": {
            "max_latency": 200,
            "min_bandwidth": 10,
            "cost_limits": {
                "max_monthly_cost": 1000.0
            },
            "security_requirements": {
                "require_encryption": true,
                "require_preshared_keys": false
            }
        }
    }',
    'active'
);

-- Insert default mesh subnet
INSERT OR IGNORE INTO network_subnets (
    id, topology_id, tenant_id, name, cidr, gateway, purpose
) VALUES (
    'default-mesh-subnet',
    'default-auto-topology', 
    'default',
    'Default Mesh Network',
    '10.0.0.0/16',
    '10.0.0.1',
    'mesh'
);

-- Insert management subnet
INSERT OR IGNORE INTO network_subnets (
    id, topology_id, tenant_id, name, cidr, gateway, purpose
) VALUES (
    'default-mgmt-subnet',
    'default-auto-topology',
    'default', 
    'Management Network',
    '10.1.0.0/24',
    '10.1.0.1',
    'management'
);

-- Create function to auto-assign IP addresses (trigger-based)
CREATE TRIGGER IF NOT EXISTS auto_assign_mesh_ip
    AFTER INSERT ON nodes
    WHEN NEW.ip_address IS NULL OR NEW.ip_address = ''
BEGIN
    UPDATE nodes 
    SET ip_address = (
        SELECT '10.0.' || 
               CAST((ROW_NUMBER() OVER (ORDER BY created_at) / 254) AS TEXT) || '.' ||
               CAST((ROW_NUMBER() OVER (ORDER BY created_at) % 254) + 1 AS TEXT)
        FROM nodes 
        WHERE tenant_id = NEW.tenant_id 
        AND id = NEW.id
    )
    WHERE id = NEW.id;
    
    -- Also create subnet assignment
    INSERT OR IGNORE INTO subnet_assignments (
        id, subnet_id, node_id, ip_address
    ) VALUES (
        'sa_' || NEW.id,
        'default-mesh-subnet',
        NEW.id,
        NEW.ip_address
    );
END;