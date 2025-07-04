#!/bin/bash

set -e

echo "Building MeshGate components (antivirus-friendly)..."

# Build control-plane with antivirus-friendly flags
echo "Building control-plane..."
cd control-plane
go build -ldflags="-s -w" -o ../bin/control-plane .
cd ..

# Build agent with antivirus-friendly flags
echo "Building agent..."
cd agent
go build -ldflags="-s -w" -o ../bin/meshgate-agent .
cd ..

echo "Build complete! Binaries are in the bin/ directory:"
echo "  - bin/control-plane"
echo "  - bin/meshgate-agent" 