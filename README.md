# MeshGate - Zero-Trust VPN Mesh Network

A Go-powered overlay network for connecting private infrastructure across clouds, using WireGuard and a custom zero-trust control plane. **MeshGate is a learning project inspired by Tailscale** that demonstrates deep understanding of mesh networking, distributed systems, and zero-trust security principles.

## 🎯 One-liner
A Go-powered overlay network for connecting private infrastructure across clouds, using WireGuard and a custom zero-trust control plane.

## 🎓 About This Project

This project was built as a **learning exercise and portfolio piece** to demonstrate understanding of modern mesh networking concepts, distributed systems architecture, and zero-trust security principles. It's inspired by Tailscale's excellent work in this space and serves as a practical exploration of the challenges they solve.

**Key Learning Objectives:**
- Deep dive into WireGuard protocol and mesh networking
- Understanding zero-trust security architectures
- Building distributed systems with Go
- Multi-cloud infrastructure management
- Service discovery and health monitoring

This project showcases the ability to architect, build, and deploy complex distributed systems while demonstrating practical knowledge of the technologies and patterns used in production environments.

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AWS Cloud     │    │   GCP Cloud     │    │   On-Premises   │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ MeshGate    │ │    │ │ MeshGate    │ │    │ │ MeshGate    │ │
│ │ Agent       │◄┼────┼►│ Agent       │◄┼────┼►│ Agent       │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │ Control Plane   │
                    │ (Zero-Trust)    │
                    └─────────────────┘
```

## 🔧 Tech Stack

### Core Components
- **Go**: WireGuard config daemon + control plane
- **WireGuard**: Fast, modern VPN protocol for mesh networking
- **Zero-Trust**: Custom control plane with identity-based access control
- **BoltDB**: Embedded key-value database for node persistence

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
- Identity-based access control
- Certificate-based authentication
- Automatic key rotation
- Policy-based peer authorization

### 🌐 Multi-Cloud Support
- AWS VPC integration
- Google Cloud VPC integration
- On-premises deployment
- Hybrid cloud scenarios

### 🔄 Service Discovery
- Automatic peer discovery via control plane
- Health checking and failover
- Real-time configuration updates
- Heartbeat monitoring

### 🚀 Infrastructure as Code
- Terraform for AWS and GCP
- Automated instance provisioning
- Security group configuration
- Multi-cloud deployment patterns

## 📁 Project Structure

```
meshgate/
├── agent/                 # WireGuard mesh agent
│   └── main.go           # Agent entry point with key management
├── control-plane/         # Zero-trust control plane
│   ├── main.go           # Control plane server with policy enforcement
│   └── config/           # Configuration files
│       ├── local.json    # Local development config
│       └── policy.json   # Access control policies
├── terraform/             # Infrastructure as Code
│   ├── aws/              # AWS resources
│   │   ├── main.tf       # VPC, security groups, EC2 instances
│   │   ├── variables.tf  # AWS-specific variables
│   │   ├── outputs.tf    # Output values
│   │   └── terraform.tfvars # AWS configuration
│   └── gcp/              # GCP resources
│       ├── main.tf       # VPC, firewall rules, Compute instances
│       ├── variables.tf  # GCP-specific variables
│       ├── outputs.tf    # Output values
│       └── terraform.tfvars # GCP configuration
├── go.mod                 # Go module dependencies
├── go.sum                 # Dependency checksums
├── meshgate.db           # BoltDB database file
└── README.md             # This file
```

## 🔧 Configuration

### Agent Configuration

The agent automatically:
- Generates and manages WireGuard key pairs
- Registers with the control plane
- Fetches peer configurations
- Applies WireGuard interface settings
- Sends heartbeat signals

Environment variables:
- `CONTROL_PLANE`: Control plane endpoint (default: http://localhost:8080)
- `NODE_TOKEN`: Authentication token (default: meshgate-secret)

### Control Plane Configuration

The control plane provides:
- Node registration and management
- Policy-based peer authorization
- Configuration distribution
- Health monitoring

Configuration files:
- `config/policy.json`: Access control policies
- `config/local.json`: Local development settings

### Policy Configuration

```json
{
  "<NODE_A_PUBLIC_KEY>": [
    "<NODE_B_PUBLIC_KEY>",
    "<NODE_C_PUBLIC_KEY>"
  ],
  "<NODE_B_PUBLIC_KEY>": [
    "<NODE_A_PUBLIC_KEY>"
  ]
}
```

## 🔍 API Endpoints

### Control Plane API

- `POST /register` - Register a new node
- `GET /config/{id}` - Get WireGuard configuration for a node
- `POST /heartbeat/{id}` - Update node heartbeat

### Example Usage

```bash
# Register a new node
curl -X POST http://localhost:8080/register \
  -H "Authorization: Bearer meshgate-secret" \
  -H "Content-Type: application/json" \
  -d '{"publicKey": "your-public-key"}'

# Get configuration for a node
curl http://localhost:8080/config/node-id \
  -H "Authorization: Bearer meshgate-secret"
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
