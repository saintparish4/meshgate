# Database Package

This package provides a comprehensive database management system for the MeshGate control plane with support for:

## Features

- **Database Migrations**: Automatic schema versioning and migration system
- **Multi-tenancy**: Full support for tenant isolation and management
- **Enhanced Monitoring**: Metrics snapshots, alert rules, and audit logging
- **Network Policies**: Advanced network policy management
- **API Key Management**: Secure API key handling with permissions
- **Data Cleanup**: Automatic cleanup of old audit logs and metrics

## Schema Version

Current schema version: **2**

### Migration History

1. **Version 1**: Initial schema with multi-tenancy support
   - Creates index buckets for efficient lookups
   - Sets up default system tenant
   - Establishes basic user, tenant, and node structures

2. **Version 2**: Enhanced monitoring and audit features
   - Adds metrics snapshots, alert rules, notification channels
   - Implements tenant quotas and billing records
   - Creates default alert rules for monitoring

## Data Models

### Core Models
- `User`: User accounts with role-based access
- `Tenant`: Multi-tenant isolation
- `Node`: Mesh network nodes
- `TenantSettings`: Tenant configuration

### Enhanced Models
- `AlertRule`: Monitoring alert rules
- `NotificationChannel`: Alert notification channels
- `TenantQuota`: Resource usage limits
- `MetricsSnapshot`: Time-series metrics data
- `AuditLog`: Security audit trail
- `APIKey`: API authentication keys
- `NodeGroup`: Logical node groupings
- `NetworkPolicy`: Advanced network policies

## Usage

```go
import "github.com/saintparish4/meshgate/control-plane/database"

// Create database manager
dm, err := database.NewDatabaseManager("meshgate.db")
if err != nil {
    log.Fatal(err)
}
defer dm.Close()

// Save user
user := &database.User{
    ID:       "user-123",
    Email:    "user@example.com",
    TenantID: "tenant-456",
    Role:     "user",
}
err = dm.SaveUser(user)

// Get users by tenant
users, err := dm.GetUsersByTenant("tenant-456")

// Save audit log
log := &database.AuditLog{
    ID:        "log-789",
    TenantID:  "tenant-456",
    UserID:    "user-123",
    Action:    "login",
    Resource:  "auth",
    Timestamp: time.Now(),
    Success:   true,
}
err = dm.SaveAuditLog(log)
```

## Database Operations

The package provides comprehensive database operations including:

- User management with tenant isolation
- Audit logging for security compliance
- Metrics snapshot storage and retrieval
- Tenant quota management
- Data cleanup for maintenance

## Migration System

The migration system automatically:
- Detects current schema version
- Applies pending migrations
- Records migration history
- Maintains backward compatibility

## Performance Features

- Indexed lookups for efficient queries
- Batch operations for bulk data
- Automatic cleanup of old data
- Optimized key structures for range queries 