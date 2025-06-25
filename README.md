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
- Modern web development with Next.js and TypeScript

This project showcases the ability to architect, build, and deploy complex distributed systems while demonstrating practical knowledge of the technologies and patterns used in production environments.

## ��️ Architecture

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

### Infrastructure & Operations
- **Terraform**: Multi-cloud setup across AWS + GCP
- **Consul**: Service discovery and health checking
- **CI/CD**: GitHub Actions + ArgoCD (for push-to-deploy infra)

### Management Interface
- **Next.js**: Web dashboard to manage peer configurations
- **TypeScript**: Type-safe frontend development
- **Tailwind UI**: Modern, responsive interface

## 🚀 Quick Start

### Prerequisites
- Go 1.21+
- Terraform 1.5+
- Docker & Docker Compose
- Node.js 18+ (for dashboard)
- WireGuard tools (`wg`, `wg-quick`)

### 1. Deploy Infrastructure

```bash
# Clone the repository
git clone https://github.com/your-org/meshgate.git
cd meshgate

# Initialize Terraform
cd terraform
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

### 4. Access Dashboard

```bash
# Start the Next.js dashboard
cd dashboard
npm install
npm run dev
```

Visit `http://localhost:3000` to manage your mesh network.

## 📋 Features

### 🔐 Zero-Trust Security
- Identity-based access control
- Certificate-based authentication
- Automatic key rotation
- Audit logging and compliance

### 🌐 Multi-Cloud Support
- AWS VPC integration
- Google Cloud VPC integration
- On-premises deployment
- Hybrid cloud scenarios

### 🔄 Service Discovery
- Consul integration for service registration
- Automatic peer discovery
- Health checking and failover
- Load balancing across mesh

### 🎛️ Management Dashboard
- Real-time network topology visualization
- Peer configuration management
- Traffic monitoring and analytics
- User and access management

### 🚀 CI/CD Integration
- GitHub Actions for automated testing
- ArgoCD for GitOps deployment
- Infrastructure as Code with Terraform
- Automated security scanning

## 📁 Project Structure

```
meshgate/
├── agent/                 # WireGuard mesh agent
│   ├── main.go           # Agent entry point
│   └── config/           # Agent configurations
├── control-plane/         # Zero-trust control plane
│   ├── main.go           # Control plane server
│   ├── config/           # Control plane configs
│   └── api/              # REST API handlers
├── dashboard/             # Next.js web dashboard
│   ├── app/              # App Router pages
│   ├── components/       # React components
│   └── lib/              # Utilities and helpers
├── terraform/             # Infrastructure as Code
│   ├── aws/              # AWS resources
│   ├── gcp/              # GCP resources
│   └── modules/          # Reusable modules
├── consul/                # Service discovery config
├── .github/               # GitHub Actions workflows
└── docs/                  # Documentation
```

## 🔧 Configuration

### Agent Configuration

```json
{
  "interfaceAddress": "10.42.0.2/32",
  "listenPort": 51820,
  "controlPlane": {
    "endpoint": "https://control.meshgate.local",
    "authToken": "your-auth-token"
  },
  "consul": {
    "address": "consul.meshgate.local:8500",
    "serviceName": "meshgate-agent"
  }
}
```

### Control Plane Configuration

```json
{
  "server": {
    "port": 8080,
    "tls": {
      "certFile": "/path/to/cert.pem",
      "keyFile": "/path/to/key.pem"
    }
  },
  "consul": {
    "address": "localhost:8500"
  },
  "auth": {
    "jwtSecret": "your-jwt-secret",
    "sessionTimeout": "24h"
  }
}
```

## 🧪 Development

### Running Locally

```bash
# Start Consul for service discovery
docker run -d --name consul -p 8500:8500 consul:latest

# Start control plane
cd control-plane
go run main.go -config config/local.json

# Start agent
cd agent
go run main.go -config config/local.json

# Start dashboard
cd dashboard
npm run dev
```

### Testing

```bash
# Run unit tests
go test ./...

# Run integration tests
go test -tags=integration ./...

# Run dashboard tests
cd dashboard
npm test
```

## 📊 Monitoring & Observability

- **Metrics**: Prometheus integration for mesh metrics
- **Logging**: Structured logging with correlation IDs
- **Tracing**: Distributed tracing across mesh nodes
- **Health Checks**: Comprehensive health monitoring

## 🔒 Security

- **Zero-Trust**: No implicit trust between services
- **Certificate Management**: Automatic certificate rotation
- **Audit Logging**: Complete audit trail of all operations
- **Compliance**: SOC 2, GDPR, and HIPAA ready

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


## 🆘 Support

- **Documentation**: [docs.meshgate.dev](https://docs.meshgate.dev)
- **Issues**: [GitHub Issues](https://github.com/your-org/meshgate/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/meshgate/discussions)
- **Community**: [Discord](https://discord.gg/meshgate)
