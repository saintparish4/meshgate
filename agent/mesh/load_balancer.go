package mesh

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// LoadBalancingStrategy represents different load balancing strategies
type LoadBalancingStrategy int

const (
	StrategyRoundRobin LoadBalancingStrategy = iota
	StrategyLeastConnections
	StrategyWeightedRoundRobin
	StrategyLeastResponseTime
	StrategyIPHash
	StrategyRandom
)

// LoadBalancerConfig holds configuration for the load balancer
type LoadBalancerConfig struct {
	Strategy                LoadBalancingStrategy `json:"strategy"`
	HealthCheckInterval     time.Duration         `json:"health_check_interval"`
	MaxRetries              int                   `json:"max_retries"`
	RetryTimeout            time.Duration         `json:"retry_timeout"`
	EnableStickySessions    bool                  `json:"enable_sticky_sessions"`
	StickySessionTimeout    time.Duration         `json:"sticky_session_timeout"`
	MaxConnectionsPerNode   int                   `json:"max_connections_per_node"`
	EnableCircuitBreaker    bool                  `json:"enable_circuit_breaker"`
	CircuitBreakerThreshold int                   `json:"circuit_breaker_threshold"`
}

// LoadBalancedNode represents a node in the load balancer
type LoadBalancedNode struct {
	NodeID          string
	Weight          int
	CurrentLoad     int
	ResponseTime    time.Duration
	HealthScore     float64
	IsAvailable     bool
	LastHealthCheck time.Time
	FailCount       int
	SuccessCount    int
	CircuitBreaker  *CircuitBreaker
	Metadata        map[string]string
}

// CircuitBreaker implements circuit breaker pattern
type CircuitBreaker struct {
	State           CircuitBreakerState
	FailureCount    int
	SuccessCount    int
	Threshold       int
	Timeout         time.Duration
	LastFailureTime time.Time
	mu              sync.RWMutex
}

// CircuitBreakerState represents the state of a circuit breaker
type CircuitBreakerState int

const (
	CircuitBreakerClosed CircuitBreakerState = iota
	CircuitBreakerOpen
	CircuitBreakerHalfOpen
)

// LoadBalancer manages load balancing across mesh nodes
type LoadBalancer struct {
	config          *LoadBalancerConfig
	logger          *slog.Logger
	nodes           map[string]*LoadBalancedNode
	callbacks       []LoadBalancerCallback
	mu              sync.RWMutex
	ctx             context.Context
	cancel          context.CancelFunc
	roundRobinIndex int
}

// LoadBalancerCallback is called when load balancer events occur
type LoadBalancerCallback func(event LoadBalancerEvent, node *LoadBalancedNode)

// LoadBalancerEvent represents different load balancer events
type LoadBalancerEvent int

const (
	NodeAddedEvent LoadBalancerEvent = iota
	NodeRemovedEvent
	NodeUnhealthyEvent
	NodeHealthyEvent
	LoadBalancerStatsEvent
)

// NewLoadBalancer creates a new load balancer
func NewLoadBalancer(config *LoadBalancerConfig, logger *slog.Logger) *LoadBalancer {
	if config == nil {
		config = &LoadBalancerConfig{
			Strategy:                StrategyRoundRobin,
			HealthCheckInterval:     30 * time.Second,
			MaxRetries:              3,
			RetryTimeout:            5 * time.Second,
			EnableStickySessions:    false,
			StickySessionTimeout:    300 * time.Second,
			MaxConnectionsPerNode:   50,
			EnableCircuitBreaker:    true,
			CircuitBreakerThreshold: 5,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &LoadBalancer{
		config:    config,
		logger:    logger,
		nodes:     make(map[string]*LoadBalancedNode),
		callbacks: make([]LoadBalancerCallback, 0),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Start begins the load balancer
func (lb *LoadBalancer) Start() error {
	lb.logger.Info("Starting load balancer", "strategy", lb.config.Strategy)

	// Start background services
	go lb.healthCheckLoop()
	go lb.loadBalancingLoop()

	lb.logger.Info("Load balancer started")
	return nil
}

// Stop stops the load balancer
func (lb *LoadBalancer) Stop() error {
	lb.logger.Info("Stopping load balancer")
	lb.cancel()
	lb.logger.Info("Load balancer stopped")
	return nil
}

// AddNode adds a node to the load balancer
func (lb *LoadBalancer) AddNode(nodeID string, weight int) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	if _, exists := lb.nodes[nodeID]; exists {
		return fmt.Errorf("node %s already exists in load balancer", nodeID)
	}

	node := &LoadBalancedNode{
		NodeID:          nodeID,
		Weight:          weight,
		CurrentLoad:     0,
		ResponseTime:    0,
		HealthScore:     1.0,
		IsAvailable:     true,
		LastHealthCheck: time.Now(),
		FailCount:       0,
		SuccessCount:    0,
		Metadata:        make(map[string]string),
	}

	if lb.config.EnableCircuitBreaker {
		node.CircuitBreaker = &CircuitBreaker{
			State:     CircuitBreakerClosed,
			Threshold: lb.config.CircuitBreakerThreshold,
			Timeout:   lb.config.RetryTimeout,
		}
	}

	lb.nodes[nodeID] = node
	lb.notifyCallbacks(NodeAddedEvent, node)

	lb.logger.Info("Node added to load balancer", "node_id", nodeID, "weight", weight)
	return nil
}

// RemoveNode removes a node from the load balancer
func (lb *LoadBalancer) RemoveNode(nodeID string) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	node, exists := lb.nodes[nodeID]
	if !exists {
		return fmt.Errorf("node %s does not exist in load balancer", nodeID)
	}

	delete(lb.nodes, nodeID)
	lb.notifyCallbacks(NodeRemovedEvent, node)

	lb.logger.Info("Node removed from load balancer", "node_id", nodeID)
	return nil
}

// SelectNode selects a node based on the load balancing strategy
func (lb *LoadBalancer) SelectNode(clientID string) (*LoadBalancedNode, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	availableNodes := lb.getAvailableNodes()
	if len(availableNodes) == 0 {
		return nil, fmt.Errorf("no available nodes in load balancer")
	}

	var selectedNode *LoadBalancedNode

	switch lb.config.Strategy {
	case StrategyRoundRobin:
		selectedNode = lb.selectRoundRobin(availableNodes)
	case StrategyLeastConnections:
		selectedNode = lb.selectLeastConnections(availableNodes)
	case StrategyWeightedRoundRobin:
		selectedNode = lb.selectWeightedRoundRobin(availableNodes)
	case StrategyLeastResponseTime:
		selectedNode = lb.selectLeastResponseTime(availableNodes)
	case StrategyIPHash:
		selectedNode = lb.selectIPHash(availableNodes, clientID)
	case StrategyRandom:
		selectedNode = lb.selectRandom(availableNodes)
	default:
		selectedNode = lb.selectRoundRobin(availableNodes)
	}

	if selectedNode == nil {
		return nil, fmt.Errorf("failed to select node with strategy %v", lb.config.Strategy)
	}

	// Update load
	lb.mu.RUnlock()
	lb.mu.Lock()
	selectedNode.CurrentLoad++
	lb.mu.Unlock()
	lb.mu.RLock()

	lb.logger.Debug("Node selected", "node_id", selectedNode.NodeID, "strategy", lb.config.Strategy)
	return selectedNode, nil
}

// ReleaseNode releases a node (decreases its load)
func (lb *LoadBalancer) ReleaseNode(nodeID string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	if node, exists := lb.nodes[nodeID]; exists {
		if node.CurrentLoad > 0 {
			node.CurrentLoad--
		}
	}
}

// ReportSuccess reports a successful operation for a node
func (lb *LoadBalancer) ReportSuccess(nodeID string, responseTime time.Duration) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	if node, exists := lb.nodes[nodeID]; exists {
		node.SuccessCount++
		node.ResponseTime = responseTime
		node.HealthScore = lb.calculateHealthScore(node)

		if node.CircuitBreaker != nil {
			node.CircuitBreaker.ReportSuccess()
		}

		lb.logger.Debug("Success reported", "node_id", nodeID, "response_time", responseTime)
	}
}

// ReportFailure reports a failed operation for a node
func (lb *LoadBalancer) ReportFailure(nodeID string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	if node, exists := lb.nodes[nodeID]; exists {
		node.FailCount++
		node.HealthScore = lb.calculateHealthScore(node)

		if node.CircuitBreaker != nil {
			node.CircuitBreaker.ReportFailure()
		}

		lb.logger.Warn("Failure reported", "node_id", nodeID, "fail_count", node.FailCount)
	}
}

// getAvailableNodes returns all available nodes
func (lb *LoadBalancer) getAvailableNodes() []*LoadBalancedNode {
	var available []*LoadBalancedNode
	for _, node := range lb.nodes {
		if node.IsAvailable &&
			node.CurrentLoad < lb.config.MaxConnectionsPerNode &&
			(node.CircuitBreaker == nil || node.CircuitBreaker.IsAvailable()) {
			available = append(available, node)
		}
	}
	return available
}

// selectRoundRobin selects a node using round-robin strategy
func (lb *LoadBalancer) selectRoundRobin(nodes []*LoadBalancedNode) *LoadBalancedNode {
	if len(nodes) == 0 {
		return nil
	}

	lb.roundRobinIndex = (lb.roundRobinIndex + 1) % len(nodes)
	return nodes[lb.roundRobinIndex]
}

// selectLeastConnections selects a node with the least connections
func (lb *LoadBalancer) selectLeastConnections(nodes []*LoadBalancedNode) *LoadBalancedNode {
	if len(nodes) == 0 {
		return nil
	}

	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].CurrentLoad < nodes[j].CurrentLoad
	})

	return nodes[0]
}

// selectWeightedRoundRobin selects a node using weighted round-robin
func (lb *LoadBalancer) selectWeightedRoundRobin(nodes []*LoadBalancedNode) *LoadBalancedNode {
	if len(nodes) == 0 {
		return nil
	}

	// Calculate total weight
	totalWeight := 0
	for _, node := range nodes {
		totalWeight += node.Weight
	}

	if totalWeight == 0 {
		return lb.selectRoundRobin(nodes)
	}

	// Use weighted selection
	lb.roundRobinIndex = (lb.roundRobinIndex + 1) % totalWeight
	currentWeight := 0

	for _, node := range nodes {
		currentWeight += node.Weight
		if lb.roundRobinIndex < currentWeight {
			return node
		}
	}

	return nodes[0] // Fallback
}

// selectLeastResponseTime selects a node with the least response time
func (lb *LoadBalancer) selectLeastResponseTime(nodes []*LoadBalancedNode) *LoadBalancedNode {
	if len(nodes) == 0 {
		return nil
	}

	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].ResponseTime < nodes[j].ResponseTime
	})

	return nodes[0]
}

// selectIPHash selects a node based on client IP hash
func (lb *LoadBalancer) selectIPHash(nodes []*LoadBalancedNode, clientID string) *LoadBalancedNode {
	if len(nodes) == 0 {
		return nil
	}

	// Simple hash function
	hash := 0
	for _, char := range clientID {
		hash = (hash*31 + int(char)) % len(nodes)
	}

	return nodes[hash]
}

// selectRandom selects a random node
func (lb *LoadBalancer) selectRandom(nodes []*LoadBalancedNode) *LoadBalancedNode {
	if len(nodes) == 0 {
		return nil
	}

	return nodes[rand.Intn(len(nodes))]
}

// calculateHealthScore calculates the health score of a node
func (lb *LoadBalancer) calculateHealthScore(node *LoadBalancedNode) float64 {
	total := node.SuccessCount + node.FailCount
	if total == 0 {
		return 1.0
	}

	successRate := float64(node.SuccessCount) / float64(total)

	// Factor in response time
	responseTimeScore := 1.0
	if node.ResponseTime > 100*time.Millisecond {
		responseTimeScore = 0.8
	}
	if node.ResponseTime > 500*time.Millisecond {
		responseTimeScore = 0.6
	}

	return successRate * responseTimeScore
}

// healthCheckLoop runs the health check loop
func (lb *LoadBalancer) healthCheckLoop() {
	ticker := time.NewTicker(lb.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-lb.ctx.Done():
			return
		case <-ticker.C:
			lb.performHealthChecks()
		}
	}
}

// loadBalancingLoop runs the load balancing loop
func (lb *LoadBalancer) loadBalancingLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-lb.ctx.Done():
			return
		case <-ticker.C:
			lb.performLoadBalancing()
		}
	}
}

// performHealthChecks performs health checks on all nodes
func (lb *LoadBalancer) performHealthChecks() {
	lb.mu.RLock()
	nodes := make([]*LoadBalancedNode, 0, len(lb.nodes))
	for _, node := range lb.nodes {
		nodes = append(nodes, node)
	}
	lb.mu.RUnlock()

	for _, node := range nodes {
		lb.checkNodeHealth(node)
	}
}

// checkNodeHealth checks the health of a specific node
func (lb *LoadBalancer) checkNodeHealth(node *LoadBalancedNode) {
	// In a real implementation, you would perform actual health checks
	// For now, simulate health check based on success/failure ratio

	node.HealthScore = lb.calculateHealthScore(node)
	node.LastHealthCheck = time.Now()

	// Update availability based on health score
	wasAvailable := node.IsAvailable
	node.IsAvailable = node.HealthScore > 0.3

	if wasAvailable && !node.IsAvailable {
		lb.notifyCallbacks(NodeUnhealthyEvent, node)
		lb.logger.Warn("Node marked as unhealthy", "node_id", node.NodeID, "health_score", node.HealthScore)
	} else if !wasAvailable && node.IsAvailable {
		lb.notifyCallbacks(NodeHealthyEvent, node)
		lb.logger.Info("Node marked as healthy", "node_id", node.NodeID, "health_score", node.HealthScore)
	}
}

// performLoadBalancing performs load balancing operations
func (lb *LoadBalancer) performLoadBalancing() {
	lb.mu.RLock()
	nodes := make([]*LoadBalancedNode, 0, len(lb.nodes))
	for _, node := range lb.nodes {
		nodes = append(nodes, node)
	}
	lb.mu.RUnlock()

	// Log load balancing statistics
	var totalLoad int
	for _, node := range nodes {
		totalLoad += node.CurrentLoad
	}

	lb.logger.Info("Load balancing stats",
		"total_nodes", len(nodes),
		"total_load", totalLoad,
		"average_load", totalLoad/len(nodes))

	lb.notifyCallbacks(LoadBalancerStatsEvent, nil)
}

// AddCallback adds a callback for load balancer events
func (lb *LoadBalancer) AddCallback(callback LoadBalancerCallback) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.callbacks = append(lb.callbacks, callback)
}

// notifyCallbacks notifies registered callbacks
func (lb *LoadBalancer) notifyCallbacks(event LoadBalancerEvent, node *LoadBalancedNode) {
	lb.mu.RLock()
	callbacks := make([]LoadBalancerCallback, len(lb.callbacks))
	copy(callbacks, lb.callbacks)
	lb.mu.RUnlock()

	for _, callback := range callbacks {
		go callback(event, node)
	}
}

// GetStats returns load balancer statistics
func (lb *LoadBalancer) GetStats() map[string]interface{} {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	var totalLoad, availableNodes, unhealthyNodes int
	var totalWeight int

	for _, node := range lb.nodes {
		totalLoad += node.CurrentLoad
		totalWeight += node.Weight
		if node.IsAvailable {
			availableNodes++
		} else {
			unhealthyNodes++
		}
	}

	return map[string]interface{}{
		"total_nodes":              len(lb.nodes),
		"available_nodes":          availableNodes,
		"unhealthy_nodes":          unhealthyNodes,
		"total_load":               totalLoad,
		"total_weight":             totalWeight,
		"strategy":                 lb.config.Strategy,
		"max_connections_per_node": lb.config.MaxConnectionsPerNode,
		"enable_circuit_breaker":   lb.config.EnableCircuitBreaker,
	}
}

// Circuit Breaker Methods

// IsAvailable checks if the circuit breaker allows requests
func (cb *CircuitBreaker) IsAvailable() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	switch cb.State {
	case CircuitBreakerClosed:
		return true
	case CircuitBreakerOpen:
		// Check if timeout has passed
		if time.Since(cb.LastFailureTime) > cb.Timeout {
			cb.State = CircuitBreakerHalfOpen
			return true
		}
		return false
	case CircuitBreakerHalfOpen:
		return true
	default:
		return false
	}
}

// ReportSuccess reports a successful operation
func (cb *CircuitBreaker) ReportSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.SuccessCount++
	if cb.State == CircuitBreakerHalfOpen {
		cb.State = CircuitBreakerClosed
		cb.FailureCount = 0
	}
}

// ReportFailure reports a failed operation
func (cb *CircuitBreaker) ReportFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.FailureCount++
	cb.LastFailureTime = time.Now()

	if cb.State == CircuitBreakerClosed && cb.FailureCount >= cb.Threshold {
		cb.State = CircuitBreakerOpen
	} else if cb.State == CircuitBreakerHalfOpen {
		cb.State = CircuitBreakerOpen
	}
}

// String returns string representation of load balancing strategy
func (lbs LoadBalancingStrategy) String() string {
	switch lbs {
	case StrategyRoundRobin:
		return "Round Robin"
	case StrategyLeastConnections:
		return "Least Connections"
	case StrategyWeightedRoundRobin:
		return "Weighted Round Robin"
	case StrategyLeastResponseTime:
		return "Least Response Time"
	case StrategyIPHash:
		return "IP Hash"
	case StrategyRandom:
		return "Random"
	default:
		return "Unknown"
	}
}
