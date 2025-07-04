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

> **For detailed local development setup, see [QUICKSTART.md](QUICKSTART.md)**

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
# Start the control plane (see QUICKSTART.md for detailed local setup)
cd control-plane
NODE_TOKEN=meshgate-secret go run main.go
```

### 3. Deploy Agents

```bash
# Build and deploy agents
cd agent
go build -o meshgate-agent main.go

# Deploy to your infrastructure
CONTROL_PLANE_URL=http://your-control-plane:8080 NODE_TOKEN=meshgate-secret ./meshgate-agent
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
- `CONTROL_PLANE_URL`: Control plane endpoint (default: http://localhost:8080)
- `NODE_TOKEN`: Authentication token (default: meshgate-secret)

### Control Plane Configuration

The control plane provides:
- Node registration and management
- Policy-based peer authorization
- Configuration distribution
- Health monitoring

Configuration files:
- `config/policy.json`: Access control policies

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

**Cross-Platform (Recommended):**
```bash
# Build all components
make build

# Run local tests
make test

# Clean build artifacts
make clean
```

**Platform-Specific:**
```bash
# Linux/macOS
./build.sh
./test-local.sh

# Windows PowerShell
.\build.ps1
.\test-local.ps1
```

### Running Locally

```bash
# Start control plane
cd control-plane
$env:NODE_TOKEN="meshgate-secret"; go run main.go

# Or on Linux/macOS:
cd control-plane
NODE_TOKEN="meshgate-secret" go run main.go

# In another terminal, start agent
cd agent
go run main.go
```

**Required Environment Variables:**
- `NODE_TOKEN`: Authentication token for the control plane (default: "meshgate-secret")
- `POLICY_PATH`: Path to policy configuration (default: "config/policy.json")
- `SUBNET`: Network subnet for IP allocation (default: "10.10.10.0/24")

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

## 🛡️ Antivirus Considerations

Some antivirus software (like McAfee, Norton, Windows Defender) may flag Go binaries or WireGuard operations as suspicious. If you encounter issues:

### Option 1: Temporarily Disable Antivirus
- Temporarily disable real-time protection during testing
- Add the project directory to antivirus exclusions
- Re-enable protection after testing

### Option 2: Use Build-Safe Script
```bash
# Use the antivirus-friendly build script
./build-safe.sh

# Or on Windows PowerShell
.\build-safe.ps1
```

The `build-safe.sh` script uses `-ldflags="-s -w"` to strip debug information and reduce antivirus false positives.

### Common Issues
- **"Access denied" errors**: Antivirus blocking file operations
- **WireGuard interface creation fails**: Antivirus blocking network operations
- **Process termination**: Antivirus quarantining binaries

## 🤝 Contributing

This is a learning project demonstrating mesh networking concepts. Feel free to explore the code and use it as a reference for understanding distributed systems and zero-trust architectures.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Inspired by Tailscale's excellent work in mesh networking.
