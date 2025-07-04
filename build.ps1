# PowerShell script for building MeshGate components
# Equivalent to build.sh but for Windows PowerShell

$ErrorActionPreference = "Stop"

Write-Host "Building MeshGate components..." -ForegroundColor Yellow

# Build control-plane
Write-Host "Building control-plane..." -ForegroundColor Cyan
Set-Location control-plane
go build -o ../bin/control-plane.exe .
Set-Location ..

# Build agent
Write-Host "Building agent..." -ForegroundColor Cyan
Set-Location agent
go build -o ../bin/meshgate-agent.exe .
Set-Location ..

Write-Host "Build complete! Binaries are in the bin/ directory:" -ForegroundColor Green
Write-Host "  - bin/control-plane.exe" -ForegroundColor White
Write-Host "  - bin/meshgate-agent.exe" -ForegroundColor White 