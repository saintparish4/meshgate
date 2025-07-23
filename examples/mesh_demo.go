package main

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	"github.com/saintparish4/meshgate/agent/mesh"
)

// MeshDemo demonstrates the enhanced mesh network capabilities
type MeshDemo struct {
	meshManager   *mesh.MeshManager
	logger        *slog.Logger
	ctx           context.Context
	cancel        context.CancelFunc
	concurrentOps int
	successCount  int64
	failureCount  int64
	mu            sync.RWMutex
}

// NewMeshDemo creates a new mesh demonstration
func NewMeshDemo() *MeshDemo {
	ctx, cancel := context.WithCancel(context.Background())

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create enhanced mesh manager configuration
	config := &mesh.MeshManagerConfig{
		HeartbeatTimeout:         30 * time.Second,
		TopologyUpdateInterval:   60 * time.Second,
		MaxNodesPerSegment:       100,
		MaxConnectionsPerNode:    50,
		MaxConcurrentConnections: 200, // Support 100+ concurrent connections
		EnableAutoSegmentation:   true,
		EnableLoadBalancing:      true,
		EnableFailover:           true,
		EnableNATTraversal:       true,
		DefaultTopologyType:      mesh.TopologyHybrid,
		ConnectionPoolSize:       200,
		EnableConnectionReuse:    true,
		MaxRetryAttempts:         3,
		RetryBackoffMultiplier:   2.0,
	}

	meshManager := mesh.NewMeshManager(config, logger)

	return &MeshDemo{
		meshManager:   meshManager,
		logger:        logger,
		ctx:           ctx,
		cancel:        cancel,
		concurrentOps: 100, // Simulate 100 concurrent operations
	}
}

// Start begins the mesh demonstration
func (md *MeshDemo) Start() error {
	md.logger.Info("Starting Mesh Network Demonstration",
		"concurrent_operations", md.concurrentOps,
		"max_connections", md.meshManager.GetConfig().MaxConcurrentConnections)

	// Start the mesh manager
	if err := md.meshManager.Start(); err != nil {
		return fmt.Errorf("failed to start mesh manager: %w", err)
	}

	// Register demo nodes
	if err := md.registerDemoNodes(); err != nil {
		return fmt.Errorf("failed to register demo nodes: %w", err)
	}

	// Start concurrent operations simulation
	go md.simulateConcurrentOperations()

	// Start monitoring
	go md.monitorMeshHealth()

	md.logger.Info("Mesh demonstration started successfully")
	return nil
}

// Stop stops the mesh demonstration
func (md *MeshDemo) Stop() error {
	md.logger.Info("Stopping mesh demonstration")
	md.cancel()

	if err := md.meshManager.Stop(); err != nil {
		md.logger.Warn("Failed to stop mesh manager", "error", err)
	}

	md.logger.Info("Mesh demonstration stopped")
	return nil
}

// registerDemoNodes registers demo nodes in the mesh
func (md *MeshDemo) registerDemoNodes() error {
	// Create demo nodes across different regions
	regions := []string{"us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"}

	for i := 0; i < 50; i++ { // Register 50 nodes
		region := regions[i%len(regions)]
		node := &mesh.MeshNode{
			ID:           fmt.Sprintf("demo-node-%d", i),
			Name:         fmt.Sprintf("Demo Node %d", i),
			TenantID:     "demo-tenant",
			PublicKey:    fmt.Sprintf("demo-key-%d", i),
			IPAddress:    fmt.Sprintf("10.0.%d.%d", i/256, i%256),
			Endpoint:     fmt.Sprintf("node-%d.%s.demo.com:51820", i, region),
			Status:       mesh.NodeOnline,
			Capabilities: []string{"wireguard", "nat-traversal", "failover"},
			Region:       region,
			Zone:         fmt.Sprintf("%s-a", region),
			SegmentID:    fmt.Sprintf("segment-%d", i/10),
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		if err := md.meshManager.RegisterNode(node); err != nil {
			md.logger.Warn("Failed to register demo node", "node_id", node.ID, "error", err)
		} else {
			md.logger.Debug("Registered demo node", "node_id", node.ID, "region", region)
		}
	}

	md.logger.Info("Demo nodes registered", "count", 50)
	return nil
}

// simulateConcurrentOperations simulates 100+ concurrent operations
func (md *MeshDemo) simulateConcurrentOperations() {
	md.logger.Info("Starting concurrent operations simulation")

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, md.concurrentOps)

	for i := 0; i < md.concurrentOps; i++ {
		wg.Add(1)
		go func(operationID int) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore

			md.simulateOperation(operationID)
		}(i)
	}

	wg.Wait()
	md.logger.Info("Concurrent operations simulation completed")
}

// simulateOperation simulates a single mesh operation
func (md *MeshDemo) simulateOperation(operationID int) {
	// Simulate different types of operations
	operationType := operationID % 4

	switch operationType {
	case 0:
		md.simulateConnectionEstablishment(operationID)
	case 1:
		md.simulateDataTransfer(operationID)
	case 2:
		md.simulateFailoverScenario(operationID)
	case 3:
		md.simulateNATTraversal(operationID)
	}
}

// simulateConnectionEstablishment simulates establishing a connection
func (md *MeshDemo) simulateConnectionEstablishment(operationID int) {
	start := time.Now()

	// Get connection from pool
	pooledConn, err := md.meshManager.GetConnectionPool().GetConnection(
		fmt.Sprintf("source-%d", operationID),
		fmt.Sprintf("target-%d", operationID),
	)

	if err != nil {
		md.recordFailure()
		md.logger.Warn("Failed to get connection", "operation_id", operationID, "error", err)
		return
	}

	// Simulate connection establishment time
	time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)

	// Return connection to pool
	md.meshManager.GetConnectionPool().ReturnConnection(pooledConn)

	duration := time.Since(start)
	md.recordSuccess(duration)

	md.logger.Debug("Connection established",
		"operation_id", operationID,
		"duration", duration,
		"connection_id", pooledConn.ID)
}

// simulateDataTransfer simulates data transfer over mesh
func (md *MeshDemo) simulateDataTransfer(operationID int) {
	start := time.Now()

	// Simulate data transfer
	dataSize := rand.Intn(1000) + 100 // 100-1100 bytes
	transferTime := time.Duration(dataSize) * time.Microsecond
	time.Sleep(transferTime)

	duration := time.Since(start)
	md.recordSuccess(duration)

	md.logger.Debug("Data transfer completed",
		"operation_id", operationID,
		"data_size", dataSize,
		"duration", duration)
}

// simulateFailoverScenario simulates a failover scenario
func (md *MeshDemo) simulateFailoverScenario(operationID int) {
	start := time.Now()

	// Simulate failover trigger
	if rand.Float64() < 0.1 { // 10% chance of failover
		routeID := fmt.Sprintf("route-%d", operationID)

		if err := md.meshManager.GetFailoverManager().TriggerFailover(routeID); err != nil {
			md.logger.Warn("Failover simulation failed", "route_id", routeID, "error", err)
		} else {
			md.logger.Debug("Failover triggered", "route_id", routeID)
		}
	}

	duration := time.Since(start)
	md.recordSuccess(duration)
}

// simulateNATTraversal simulates NAT traversal
func (md *MeshDemo) simulateNATTraversal(operationID int) {
	start := time.Now()

	// Simulate NAT mapping discovery
	mapping, err := md.meshManager.GetNATTraversal().DiscoverNATMapping()
	if err != nil {
		md.recordFailure()
		md.logger.Warn("NAT traversal failed", "operation_id", operationID, "error", err)
		return
	}

	// Simulate hole punching
	peerAddr := &net.UDPAddr{
		IP:   net.ParseIP("192.168.1.1"),
		Port: 51820,
	}

	if err := md.meshManager.GetNATTraversal().AttemptHolePunch(
		fmt.Sprintf("peer-%d", operationID),
		peerAddr,
	); err != nil {
		md.logger.Debug("Hole punch failed (expected in demo)", "operation_id", operationID)
	}

	duration := time.Since(start)
	md.recordSuccess(duration)

	md.logger.Debug("NAT traversal completed",
		"operation_id", operationID,
		"mapping", mapping.ExternalAddr,
		"duration", duration)
}

// monitorMeshHealth monitors the health of the mesh network
func (md *MeshDemo) monitorMeshHealth() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-md.ctx.Done():
			return
		case <-ticker.C:
			md.reportMeshHealth()
		}
	}
}

// reportMeshHealth reports the current health of the mesh
func (md *MeshDemo) reportMeshHealth() {
	stats := md.meshManager.GetStats()

	md.mu.RLock()
	successRate := float64(md.successCount) / float64(md.successCount+md.failureCount) * 100
	md.mu.RUnlock()

	md.logger.Info("Mesh Health Report",
		"total_nodes", stats["total_nodes"],
		"online_nodes", stats["online_nodes"],
		"total_connections", stats["total_connections"],
		"active_connections", stats["active_connections"],
		"success_rate", fmt.Sprintf("%.2f%%", successRate),
		"nat_traversal_enabled", md.meshManager.GetConfig().EnableNATTraversal,
		"failover_enabled", md.meshManager.GetConfig().EnableFailover,
		"load_balancing_enabled", md.meshManager.GetConfig().EnableLoadBalancing,
	)
}

// recordSuccess records a successful operation
func (md *MeshDemo) recordSuccess(duration time.Duration) {
	md.mu.Lock()
	defer md.mu.Unlock()
	md.successCount++
	_ = duration // Avoid unused parameter warning
}

// recordFailure records a failed operation
func (md *MeshDemo) recordFailure() {
	md.mu.Lock()
	defer md.mu.Unlock()
	md.failureCount++
}

// GetStats returns demonstration statistics
func (md *MeshDemo) GetStats() map[string]interface{} {
	md.mu.RLock()
	defer md.mu.RUnlock()

	total := md.successCount + md.failureCount
	successRate := 0.0
	if total > 0 {
		successRate = float64(md.successCount) / float64(total) * 100
	}

	return map[string]interface{}{
		"concurrent_operations": md.concurrentOps,
		"total_operations":      total,
		"successful_operations": md.successCount,
		"failed_operations":     md.failureCount,
		"success_rate":          successRate,
		"mesh_stats":            md.meshManager.GetStats(),
	}
}

func main() {
	demo := NewMeshDemo()

	// Start the demonstration
	if err := demo.Start(); err != nil {
		slog.Error("Failed to start mesh demonstration", "error", err)
		return
	}

	// Run for 5 minutes
	time.Sleep(5 * time.Minute)

	// Stop and report final stats
	if err := demo.Stop(); err != nil {
		slog.Error("Failed to stop mesh demonstration", "error", err)
		return
	}

	// Print final statistics
	finalStats := demo.GetStats()
	slog.Info("Mesh Demonstration Completed",
		"total_operations", finalStats["total_operations"],
		"success_rate", finalStats["success_rate"],
		"concurrent_operations", finalStats["concurrent_operations"],
	)
}
