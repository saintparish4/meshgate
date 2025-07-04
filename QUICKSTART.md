# MeshGate Quick Start Guide

This guide will help you get MeshGate running locally for development and testing.

## Prerequisites

- Go 1.21+
- WireGuard tools (`wg`, `wg-quick`, `ip`)
- Linux kernel with WireGuard support

## Local Development

1. **Build the components:**
   ```bash
   chmod +x build.sh
   ./build.sh
   ```

2. **Start the control plane:**
   ```bash
   cd control-plane
   NODE_TOKEN=meshgate-secret go run main.go
   ```

3. **In another terminal, start an agent:**
   ```bash
   cd agent
   CONTROL_PLANE_URL=http://localhost:8080 NODE_TOKEN=meshgate-secret go run main.go
   ```

## Testing the Mesh Network

1. **Check control plane health:**
   ```bash
   curl http://localhost:8080/health
   ```

2. **List registered nodes:**
   ```bash
   curl -H "Authorization: Bearer meshgate-secret" http://localhost:8080/nodes
   ```

3. **Test connectivity between agents:**
   ```bash
   # From one agent terminal
   ping 10.10.10.2
   
   # From another agent terminal  
   ping 10.10.10.1
   ```

## Configuration

### Environment Variables

**Control Plane:**
- `NODE_TOKEN`: Authentication token (required)
- `SUBNET`: IP subnet for mesh (default: 10.10.10.0/24)
- `PORT`: HTTP port (default: 8080)
- `POLICY_PATH`: Path to policy file (default: config/policy.json)

**Agent:**
- `CONTROL_PLANE_URL`: Control plane endpoint (default: http://localhost:8080)
- `NODE_TOKEN`: Authentication token (default: meshgate-secret)

### Policy Configuration

Edit `control-plane/config/policy.json` to control which nodes can connect to each other:

```json
{
  "NODE_A_PUBLIC_KEY": [
    "NODE_B_PUBLIC_KEY",
    "NODE_C_PUBLIC_KEY"
  ],
  "NODE_B_PUBLIC_KEY": [
    "NODE_A_PUBLIC_KEY"
  ]
}
```

## Troubleshooting

1. **Permission denied errors:**
   - Ensure WireGuard tools are installed
   - Run with appropriate privileges (sudo for local testing)

2. **Connection refused:**
   - Check if control plane is running
   - Verify CONTROL_PLANE_URL environment variable

3. **Interface creation fails:**
   - Ensure WireGuard kernel module is loaded
   - Check for existing wg0 interface

## Next Steps

- Deploy to cloud infrastructure using Terraform
- Configure production policies
- Set up monitoring and logging
- Implement additional security features
- Add Docker support for containerized deployment 