#!/bin/bash

set -e

echo "Building MeshGate components..."

# Build control-plane
echo "Building control-plane..."
cd control-plane
go build -o ../bin/control-plane .
cd ..

# Build agent
echo "Building agent..."
cd agent
go build -o ../bin/meshgate-agent .
cd ..

echo "Build complete! Binaries are in the bin/ directory:"
echo "  - bin/control-plane"
echo "  - bin/meshgate-agent" 