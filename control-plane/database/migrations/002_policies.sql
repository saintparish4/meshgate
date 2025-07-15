-- Database schema for network policies

-- Create policies table
CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    type TEXT NOT NULL, -- access, routing, firewall, qos, compliance
    status TEXT NOT NULL DEFAULT 'draft', -- active, inactive, draft, archived
    priority INTEGER NOT NULL DEFAULT 100,
    rules TEXT NOT NULL, -- JSON PolicyRules
    tags TEXT DEFAULT '[]', -- JSON array
    created_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Create policy_assignments table
CREATE TABLE IF NOT EXISTS policy_assignments (
    id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL,
    target_type TEXT NOT NULL, -- node, group, tag
    target_id TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE,
    UNIQUE(policy_id, target_type, target_id)
);

-- Create policy_audit_logs table
CREATE TABLE IF NOT EXISTS policy_audit_logs (
    id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL,
    action TEXT NOT NULL, -- created, updated, deleted, evaluated
    node_id TEXT,
    user_id TEXT,
    details TEXT DEFAULT '{}', -- JSON
    result TEXT, -- allow, deny, error
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE SET NULL
);

-- Create policy_groups table
CREATE TABLE IF NOT EXISTS policy_groups (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    policy_ids TEXT DEFAULT '[]', -- JSON array
    tags TEXT DEFAULT '[]', -- JSON array
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Create node_groups table for grouping nodes
CREATE TABLE IF NOT EXISTS node_groups (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    node_ids TEXT DEFAULT '[]', -- JSON array
    tags TEXT DEFAULT '[]', -- JSON array
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

-- Create policy_evaluations table for tracking policy decisions
CREATE TABLE IF NOT EXISTS policy_evaluations (
    id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    protocol TEXT,
    port INTEGER,
    action TEXT NOT NULL, -- allow, deny, drop
    reason TEXT,
    evaluation_time_ms INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

-- Create indexes for policies table
CREATE INDEX IF NOT EXISTS idx_policies_tenant_id ON policies(tenant_id);
CREATE INDEX IF NOT EXISTS idx_policies_type ON policies(type);
CREATE INDEX IF NOT EXISTS idx_policies_status ON policies(status);
CREATE INDEX IF NOT EXISTS idx_policies_priority ON policies(priority);
CREATE INDEX IF NOT EXISTS idx_policies_expires_at ON policies(expires_at);

-- Create indexes for policy_assignments table
CREATE INDEX IF NOT EXISTS idx_policy_assignments_policy_id ON policy_assignments(policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_assignments_target ON policy_assignments(target_type, target_id);

-- Create indexes for policy_audit_logs table
CREATE INDEX IF NOT EXISTS idx_policy_audit_logs_policy_id ON policy_audit_logs(policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_audit_logs_node_id ON policy_audit_logs(node_id);
CREATE INDEX IF NOT EXISTS idx_policy_audit_logs_action ON policy_audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_policy_audit_logs_created_at ON policy_audit_logs(created_at);

-- Create indexes for policy_groups table
CREATE INDEX IF NOT EXISTS idx_policy_groups_tenant_id ON policy_groups(tenant_id);

-- Create indexes for node_groups table
CREATE INDEX IF NOT EXISTS idx_node_groups_tenant_id ON node_groups(tenant_id);

-- Create indexes for policy_evaluations table
CREATE INDEX IF NOT EXISTS idx_policy_evaluations_policy_id ON policy_evaluations(policy_id);
CREATE INDEX IF NOT EXISTS idx_policy_evaluations_node_id ON policy_evaluations(node_id);
CREATE INDEX IF NOT EXISTS idx_policy_evaluations_created_at ON policy_evaluations(created_at);

-- Create triggers for updated_at timestamps
CREATE TRIGGER IF NOT EXISTS update_policies_updated_at
    AFTER UPDATE ON policies
BEGIN
    UPDATE policies SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS update_policy_groups_updated_at
    AFTER UPDATE ON policy_groups
BEGIN
    UPDATE policy_groups SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

CREATE TRIGGER IF NOT EXISTS update_node_groups_updated_at
    AFTER UPDATE ON node_groups
BEGIN
    UPDATE node_groups SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Create view for active policies
CREATE VIEW IF NOT EXISTS active_policies AS
SELECT 
    p.*,
    COUNT(pa.id) as assignment_count
FROM policies p
LEFT JOIN policy_assignments pa ON p.id = pa.policy_id
WHERE p.status = 'active'
  AND (p.expires_at IS NULL OR p.expires_at > CURRENT_TIMESTAMP)
GROUP BY p.id;

-- Create view for node policy assignments
CREATE VIEW IF NOT EXISTS node_policy_assignments AS
SELECT 
    n.id as node_id,
    n.tenant_id,
    p.id as policy_id,
    p.name as policy_name,
    p.type as policy_type,
    p.priority,
    pa.target_type,
    pa.target_id
FROM nodes n
JOIN policy_assignments pa ON (
    (pa.target_type = 'node' AND pa.target_id = n.id) OR
    (pa.target_type = 'tag' AND JSON_EXTRACT(n.tags, '$') LIKE '%' || pa.target_id || '%')
)
JOIN policies p ON pa.policy_id = p.id
WHERE p.status = 'active'
  AND (p.expires_at IS NULL OR p.expires_at > CURRENT_TIMESTAMP);

-- Insert default tenant if not exists
INSERT OR IGNORE INTO tenants (id, name, description) 
VALUES ('default', 'Default Tenant', 'Default tenant for single-tenant deployments');

-- Insert sample policies for demonstration
INSERT OR IGNORE INTO policies (
    id, tenant_id, name, description, type, status, priority, rules, created_by
) VALUES (
    'default-allow-mesh',
    'default',
    'Allow Mesh Traffic',
    'Default policy to allow mesh network traffic between nodes',
    'access',
    'active',
    100,
    '{
        "source": {"type": "any", "identifiers": []},
        "destination": {"type": "any", "identifiers": []},
        "action": "allow",
        "protocol": "udp",
        "ports": [51820],
        "conditions": []
    }',
    'system'
);

INSERT OR IGNORE INTO policies (
    id, tenant_id, name, description, type, status, priority, rules, created_by
) VALUES (
    'default-deny-external',
    'default',
    'Deny External Traffic',
    'Default policy to deny traffic from external sources',
    'firewall',
    'active',
    200,
    '{
        "source": {"type": "cidr", "identifiers": ["0.0.0.0/0"], "exclude": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]},
        "destination": {"type": "any", "identifiers": []},
        "action": "deny",
        "conditions": []
    }',
    'system'
);