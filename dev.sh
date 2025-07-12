#!/bin/bash

# MeshGate Development Script
# Usage: ./dev.sh [agent|control-plane]

set -e

# Check if air is installed
if ! command -v air &> /dev/null; then
    echo "Air is not installed. Installing..."
    go install github.com/cosmtrek/air@latest
fi

# Create tmp directory if it doesn't exist
mkdir -p tmp

case "${1:-control-plane}" in
    "agent")
        echo "Starting MeshGate Agent with Air..."
        cd agent
        air
        ;;
    "control-plane")
        echo "Starting MeshGate Control Plane with Air..."
        cd control-plane
        air
        ;;
    *)
        echo "Usage: ./dev.sh [agent|control-plane]"
        echo "Default: control-plane"
        exit 1
        ;;
esac 