# MeshGate - Zero-Trust VPN Mesh Network

A Go-powered overlay network for connecting private infrastructure across clouds, using WireGuard and a custom zero-trust control plane. **MeshGate is a learning project inspired by Tailscale** that demonstrates deep understanding of mesh networking, distributed systems, and zero-trust security principles.

## 🎯 One-liner
A zero-trust VPN mesh network built with Go, WireGuard, and multi-tenant architecture for secure cross-cloud connectivity.

## 🎓 About This Project

This project was built as a **learning exercise and portfolio piece** to demonstrate understanding of modern mesh networking concepts, distributed systems architecture, and zero-trust security principles. It's inspired by Tailscale's excellent work in this space and serves as a practical exploration of the challenges they solve.

**Key Learning Objectives:**
- Deep dive into WireGuard protocol and mesh networking
- Understanding zero-trust security architectures
- Building distributed systems with Go
- Multi-cloud infrastructure management
- Service discovery and health monitoring

This project showcases the ability to architect, build, and deploy complex distributed systems while demonstrating practical knowledge of the technologies and patterns used in production environments.

## 🔧 Tech Stack

### Core Components
- **Go**: Control plane API server + WireGuard agent
- **WireGuard**: Fast, modern VPN protocol for mesh networking
- **SQLite**: Embedded database with migrations
- **JWT**: Authentication and authorization
- **Prometheus**: Metrics and monitoring

### Infrastructure & Operations
- **Terraform**: Multi-cloud setup across AWS + GCP
- **Ubuntu 22.04**: Base OS for all instances
- **WireGuard Tools**: Native WireGuard utilities for interface management

## 🚀 Quick Start

### Prerequisites
- Go 1.21+
- Terraform 1.5+
- WireGuard tools (`wg`, `wg-quick`)
- AWS/GCP credentials configured

### 1. Deploy Infrastructure

#### AWS Deployment
```bash
# Clone the repository
git clone https://github.com/your-org/meshgate.git
cd meshgate

# Initialize and deploy AWS infrastructure
cd terraform/aws
terraform init
terraform plan
terraform apply
```

#### GCP Deployment
```bash
# Clone the repository
git clone https://github.com/your-org/meshgate.git
cd meshgate

# Configure GCP project
cd terraform/gcp
# Edit terraform.tfvars with your GCP project ID
# gcp_project = "your-gcp-project-id"

# Initialize and deploy GCP infrastructure
terraform init
terraform plan
terraform apply
```

### 2. Start Control Plane

```bash
# Start the control plane
cd control-plane
go run main.go -config config/local.json
```

### 3. Deploy Agents

```bash
# Build and deploy agents
cd agent
go build -o meshgate-agent main.go

# Deploy to your infrastructure
./meshgate-agent -config /path/to/agent-config.json
```

## 📋 Features

### 🔐 Zero-Trust Security
- Multi-tenant architecture with role-based access
- JWT-based authentication and authorization
- Policy-based network access control
- Audit logging for security compliance

### 🌐 Multi-Cloud Support
- AWS VPC integration with security groups
- Google Cloud VPC integration
- On-premises deployment support
- Cross-cloud mesh connectivity

### 🔄 Service Discovery & Management
- Automatic node registration and discovery
- Real-time health monitoring with heartbeats
- Dynamic WireGuard configuration distribution
- Self-healing agent with auto-reconnection

### 🚀 Infrastructure as Code
- Terraform for AWS and GCP provisioning
- Automated security group configuration
- Multi-cloud deployment patterns
- Ubuntu 22.04 base images

## 📁 Project Structure

```
meshgate/
├── agent/                 # WireGuard mesh agent
│   ├── main.go           # Agent with WireGuard interface management
│   ├── mesh/             # Mesh networking logic
│   └── wireguard/        # Platform-specific WireGuard utilities
├── control-plane/         # Zero-trust control plane
│   ├── main.go           # HTTP API server with JWT auth
│   ├── api/              # API handlers and middleware
│   ├── database/         # SQLite database with migrations
│   └── config/           # Configuration files
├── shared/               # Shared models and utilities
│   ├── models/           # Data models for mesh, policy, topology
│   ├── crypto/           # Cryptographic utilities
│   └── utils/            # Common utilities
├── terraform/            # Infrastructure as Code
│   ├── aws/              # AWS VPC, security groups, EC2
│   └── gcp/              # GCP VPC, firewall rules, Compute
├── go.mod                # Go module dependencies
└── README.md             # This file
```

## 🔧 Configuration

### Agent Configuration

The agent automatically:
- Generates and manages WireGuard key pairs
- Registers with the control plane
- Fetches peer configurations
- Applies WireGuard interface settings
- Sends heartbeat signals with metrics

Key settings:
- `control_plane_url`: Control plane API endpoint
- `tenant_id`: Multi-tenant organization ID
- `auth_token`: JWT authentication token
- `interface_name`: WireGuard interface name
- `heartbeat_interval`: Health check frequency

### Control Plane Configuration

The control plane provides:
- Multi-tenant user management with JWT auth
- Node registration and lifecycle management
- Policy-based network access control
- Real-time configuration distribution
- Prometheus metrics and health monitoring

### Policy System

Advanced policy engine supporting:
- Access control policies (allow/deny)
- Routing policies
- Firewall rules
- QoS policies
- Time-based scheduling
- Audit logging

## 🔍 API Endpoints

### Control Plane API

**Authentication:**
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/tenants` - Create tenant

**Node Management:**
- `GET /api/v1/nodes` - List nodes
- `POST /api/v1/nodes` - Create node
- `GET /api/v1/nodes/{id}/config` - Get WireGuard config
- `POST /api/v1/nodes/{id}/heartbeat` - Update heartbeat

**Policy Management:**
- `GET /api/v1/policies` - List policies
- `PUT /api/v1/policies` - Update policies

**Monitoring:**
- `GET /metrics` - Prometheus metrics
- `GET /health` - Health check

### Example Usage

```bash
# Login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@example.com", "password": "password"}'

# Get node configuration
curl http://localhost:8080/api/v1/nodes/node-id/config \
  -H "Authorization: Bearer <jwt-token>"
```

## 🛠️ Development

### Building from Source

```bash
# Build agent
cd agent
go build -o meshgate-agent main.go

# Build control plane
cd control-plane
go build -o meshgate-cp main.go
```

### Running Locally

```bash
# Start control plane
cd control-plane
go run main.go

# Start agent (in another terminal)
cd agent
go run main.go -config config.json
```

### Current Status

**Production-ready foundation** with:
- ✅ Complete control plane API with JWT auth
- ✅ Multi-tenant database with migrations
- ✅ WireGuard agent with self-healing
- ✅ Policy engine with audit logging
- ✅ Prometheus metrics and monitoring
- ✅ Terraform infrastructure for AWS/GCP
- ✅ Cross-platform support (Windows/Linux)

Ready for deployment and demonstration of enterprise-level mesh networking capabilities.
# In another terminal, start agent
cd agent
go run main.go
```

### Infrastructure Configuration

#### AWS Configuration
Edit `terraform/aws/terraform.tfvars`:
```hcl
aws_region = "us-east-1"
aws_instance_type = "t3.micro"
aws_key_name = "your-key-pair-name"
```

#### GCP Configuration
Edit `terraform/gcp/terraform.tfvars`:
```hcl
gcp_project = "your-gcp-project-id"
gcp_region = "us-east1"
gcp_zone = "us-east1-b"
gcp_machine_type = "e2-micro"
```

## 📊 Monitoring

The system provides:
- Node registration tracking
- Heartbeat monitoring
- Policy enforcement logging
- WireGuard interface status

Check logs for operational insights:
```bash
# Control plane logs
tail -f /var/log/meshgate-cp.log

# WireGuard interface status
wg show
```

## 🔒 Security Considerations

- All communication uses Bearer token authentication
- WireGuard keys are stored securely with proper permissions
- Policy-based access control prevents unauthorized connections
- Heartbeat monitoring detects offline nodes

## 🤝 Contributing

This is a learning project demonstrating mesh networking concepts. Feel free to explore the code and use it as a reference for understanding distributed systems and zero-trust architectures.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Inspired by Tailscale's excellent work in mesh networking.
