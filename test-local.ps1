# PowerShell script for testing MeshGate Local Setup
# Equivalent to test-local.sh but for Windows PowerShell

$ErrorActionPreference = "Stop"

Write-Host "🧪 Testing MeshGate Local Setup" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

# Check if Go is installed
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Go is not installed. Please install Go 1.21+" -ForegroundColor Red
    exit 1
}

# Check if WireGuard tools are available
if (-not (Get-Command wg -ErrorAction SilentlyContinue)) {
    Write-Host "⚠️  WireGuard tools not found. Install with:" -ForegroundColor Yellow
    Write-Host "   Windows: Download from https://www.wireguard.com/install/" -ForegroundColor Yellow
}

Write-Host "✅ Prerequisites check complete" -ForegroundColor Green

# Build components
Write-Host "🔨 Building components..." -ForegroundColor Yellow
& .\build.ps1

# Store original directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$originalDir = $scriptDir

Write-Host "Original directory: $originalDir" -ForegroundColor Gray

# Validate that originalDir is not null
if (-not $originalDir) {
    Write-Host "❌ Failed to get original directory" -ForegroundColor Red
    exit 1
}

# Create test directory
$testRunPath = Join-Path $originalDir "test-run"
Write-Host "Test run path: $testRunPath" -ForegroundColor Gray

try {
    New-Item -ItemType Directory -Force -Path $testRunPath | Out-Null
    Set-Location $testRunPath
    Write-Host "Changed to test directory: $(Get-Location)" -ForegroundColor Gray
} catch {
    Write-Host "❌ Failed to create or change to test directory: $_" -ForegroundColor Red
    exit 1
}

Write-Host "🚀 Starting control plane..." -ForegroundColor Yellow

# Set environment variables
$env:NODE_TOKEN = "test-token-123"
$env:POLICY_PATH = Join-Path $originalDir "control-plane\config\policy.json"
$env:SUBNET = "10.10.10.0/24"

Write-Host "Environment variables set:" -ForegroundColor Gray
Write-Host "  NODE_TOKEN: $env:NODE_TOKEN" -ForegroundColor Gray
Write-Host "  POLICY_PATH: $env:POLICY_PATH" -ForegroundColor Gray
Write-Host "  SUBNET: $env:SUBNET" -ForegroundColor Gray

# Start control plane in background
$controlPlaneExePath = Join-Path $originalDir "bin\control-plane.exe"
Write-Host "Control plane path: $controlPlaneExePath" -ForegroundColor Gray

# Validate that the executable exists
if (-not (Test-Path $controlPlaneExePath)) {
    Write-Host "❌ Control plane executable not found at: $controlPlaneExePath" -ForegroundColor Red
    Write-Host "Make sure the build completed successfully" -ForegroundColor Red
    Set-Location $originalDir
    Remove-Item -Path $testRunPath -Recurse -Force -ErrorAction SilentlyContinue
    exit 1
}

# Start the control plane process
Write-Host "Starting control plane process..." -ForegroundColor Gray
$controlPlaneProcess = Start-Process -FilePath $controlPlaneExePath -RedirectStandardOutput "control-plane.log" -RedirectStandardError "control-plane-error.log" -PassThru -WindowStyle Hidden

# Wait longer for control plane to start and check if it's actually running
Write-Host "Waiting for control plane to start..." -ForegroundColor Gray
Start-Sleep -Seconds 2

# Check if the process is still running
if ($controlPlaneProcess.HasExited) {
    Write-Host "❌ Control plane process exited immediately" -ForegroundColor Red
    Write-Host "Exit code: $($controlPlaneProcess.ExitCode)" -ForegroundColor Red
    
    # Show error logs
    if (Test-Path "control-plane-error.log") {
        Write-Host "Control plane error log:" -ForegroundColor Red
        Get-Content "control-plane-error.log"
    }
    
    Set-Location $originalDir
    Remove-Item -Path $testRunPath -Recurse -Force -ErrorAction SilentlyContinue
    exit 1
}

# Give it more time to fully start
Start-Sleep -Seconds 3

# Check if port 8080 is listening
Write-Host "Checking if port 8080 is listening..." -ForegroundColor Gray
$portCheck = Test-NetConnection -ComputerName localhost -Port 8080 -InformationLevel Quiet -WarningAction SilentlyContinue
if (-not $portCheck) {
    Write-Host "❌ Control plane is not listening on port 8080" -ForegroundColor Red
    Write-Host "Process status: Running=$(-not $controlPlaneProcess.HasExited)" -ForegroundColor Red
    
    # Show logs for debugging
    if (Test-Path "control-plane.log") {
        Write-Host "Control plane output:" -ForegroundColor Yellow
        Get-Content "control-plane.log"
    }
    if (Test-Path "control-plane-error.log") {
        Write-Host "Control plane errors:" -ForegroundColor Red
        Get-Content "control-plane-error.log"
    }
}

Write-Host "🔍 Testing control plane API..." -ForegroundColor Yellow

# Test health endpoint
try {
    $healthResponse = Invoke-RestMethod -Uri "http://localhost:8080/health" -Method Get -TimeoutSec 10
    Write-Host "Health check: $healthResponse" -ForegroundColor Green
} catch {
    Write-Host "❌ Health check failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test nodes endpoint
try {
    $headers = @{ "Authorization" = "Bearer test-token-123" }
    $nodesResponse = Invoke-RestMethod -Uri "http://localhost:8080/nodes" -Method Get -Headers $headers -TimeoutSec 10
    Write-Host "Nodes response: $($nodesResponse | ConvertTo-Json)" -ForegroundColor Green
} catch {
    Write-Host "❌ Nodes endpoint failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "🤖 Starting test agent..." -ForegroundColor Yellow

# Set environment variables for agent
$env:CONTROL_PLANE_URL = "http://localhost:8080"
$env:NODE_TOKEN = "test-token-123"

# Start agent in background
$agentExePath = Join-Path $originalDir "bin\meshgate-agent.exe"
Write-Host "Agent path: $agentExePath" -ForegroundColor Gray

# Validate that the agent executable exists
if (-not (Test-Path $agentExePath)) {
    Write-Host "❌ Agent executable not found at: $agentExePath" -ForegroundColor Red
    Write-Host "Make sure the build completed successfully" -ForegroundColor Red
    # Cleanup
    if ($controlPlaneProcess -and -not $controlPlaneProcess.HasExited) {
        Stop-Process -Id $controlPlaneProcess.Id -Force -ErrorAction SilentlyContinue
    }
    Set-Location $originalDir
    Remove-Item -Path $testRunPath -Recurse -Force -ErrorAction SilentlyContinue
    exit 1
}

$agentProcess = Start-Process -FilePath $agentExePath -RedirectStandardOutput "agent.log" -RedirectStandardError "agent-error.log" -PassThru -WindowStyle Hidden

# Wait for agent to register
Write-Host "Waiting for agent to register..." -ForegroundColor Gray
Start-Sleep -Seconds 5

Write-Host "📊 Checking logs..." -ForegroundColor Yellow
Write-Host "Control Plane Logs:" -ForegroundColor Cyan
if (Test-Path "control-plane.log") {
    Get-Content "control-plane.log" | Select-Object -Last 5
} else {
    Write-Host "No control-plane.log found" -ForegroundColor Yellow
}

if (Test-Path "control-plane-error.log") {
    $errorContent = Get-Content "control-plane-error.log"
    if ($errorContent) {
        Write-Host "Control Plane Errors:" -ForegroundColor Red
        $errorContent | Select-Object -Last 5
    }
}

Write-Host ""
Write-Host "Agent Logs:" -ForegroundColor Cyan
if (Test-Path "agent.log") {
    Get-Content "agent.log" | Select-Object -Last 5
} else {
    Write-Host "No agent.log found" -ForegroundColor Yellow
}

if (Test-Path "agent-error.log") {
    $agentErrorContent = Get-Content "agent-error.log"
    if ($agentErrorContent) {
        Write-Host "Agent Errors:" -ForegroundColor Red
        $agentErrorContent | Select-Object -Last 5
    }
}

Write-Host ""
Write-Host "🔧 WireGuard Interface Status:" -ForegroundColor Cyan
try {
    $wgOutput = & wg show 2>$null
    if ($wgOutput) {
        Write-Host $wgOutput
    } else {
        Write-Host "No WireGuard interfaces found"
    }
} catch {
    Write-Host "No WireGuard interfaces found or WireGuard not available"
}

# Cleanup
Write-Host "🧹 Cleaning up..." -ForegroundColor Yellow
if ($controlPlaneProcess -and -not $controlPlaneProcess.HasExited) {
    Write-Host "Stopping control plane process..." -ForegroundColor Gray
    Stop-Process -Id $controlPlaneProcess.Id -Force -ErrorAction SilentlyContinue
}
if ($agentProcess -and -not $agentProcess.HasExited) {
    Write-Host "Stopping agent process..." -ForegroundColor Gray
    Stop-Process -Id $agentProcess.Id -Force -ErrorAction SilentlyContinue
}

# Return to original directory
Set-Location $originalDir

# Clean up test directory
if ($testRunPath -and (Test-Path $testRunPath)) {
    Remove-Item -Path $testRunPath -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "✅ Test complete!" -ForegroundColor Green