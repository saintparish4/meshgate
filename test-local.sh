#!/bin/bash

set -e

echo "🧪 Testing MeshGate Local Setup"
echo "================================"

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go 1.21+"
    exit 1
fi

# Check if WireGuard tools are available
if ! command -v wg &> /dev/null; then
    echo "⚠️  WireGuard tools not found. Install with:"
    echo "   Ubuntu/Debian: sudo apt install wireguard"
    echo "   macOS: brew install wireguard-tools"
    echo "   Windows: Download from https://www.wireguard.com/install/"
fi

echo "✅ Prerequisites check complete"

# Build components
echo "🔨 Building components..."
./build.sh

# Create test directory
mkdir -p test-run
cd test-run

echo "🚀 Starting control plane..."
export NODE_TOKEN="test-token-123"
export POLICY_PATH="../control-plane/config/policy.json"
export SUBNET="10.10.10.0/24"

# Start control plane in background
../bin/control-plane > control-plane.log 2>&1 &
CP_PID=$!

# Wait for control plane to start
sleep 3

echo "🔍 Testing control plane API..."
# Test health endpoint
curl -s http://localhost:8080/health || echo "❌ Health check failed"

# Test nodes endpoint
curl -s http://localhost:8080/nodes -H "Authorization: Bearer test-token-123" || echo "❌ Nodes endpoint failed"

echo "🤖 Starting test agent..."
export CONTROL_PLANE_URL="http://localhost:8080"
export NODE_TOKEN="test-token-123"

# Start agent in background
../bin/meshgate-agent > agent.log 2>&1 &
AGENT_PID=$!

# Wait for agent to register
sleep 5

echo "📊 Checking logs..."
echo "Control Plane Logs:"
tail -5 control-plane.log

echo ""
echo "Agent Logs:"
tail -5 agent.log

echo ""
echo "🔧 WireGuard Interface Status:"
wg show 2>/dev/null || echo "No WireGuard interfaces found"

# Cleanup
echo "🧹 Cleaning up..."
kill $CP_PID $AGENT_PID 2>/dev/null || true
cd ..
rm -rf test-run

echo "✅ Test complete!" 