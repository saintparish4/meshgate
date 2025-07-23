package mesh

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// FailoverConfig holds configuration for failover management
type FailoverConfig struct {
	HealthCheckInterval    time.Duration `json:"health_check_interval"`
	FailoverTimeout        time.Duration `json:"failover_timeout"`
	RecoveryTimeout        time.Duration `json:"recovery_timeout"`
	MaxFailoverAttempts    int           `json:"max_failover_attempts"`
	EnableAutoRecovery     bool          `json:"enable_auto_recovery"`
	LoadBalancingEnabled   bool          `json:"load_balancing_enabled"`
	MaxConcurrentFailovers int           `json:"max_concurrent_failovers"`
	PriorityBasedRouting   bool          `json:"priority_based_routing"`
}

// FailoverRoute represents a failover route
type FailoverRoute struct {
	ID              string            `json:"id"`
	SourceNodeID    string            `json:"source_node_id"`
	TargetNodeID    string            `json:"target_node_id"`
	PrimaryPath     []string          `json:"primary_path"`
	BackupPaths     [][]string        `json:"backup_paths"`
	CurrentPath     []string          `json:"current_path"`
	Status          RouteStatus       `json:"status"`
	Priority        int               `json:"priority"`
	LoadBalanced    bool              `json:"load_balanced"`
	LastHealthCheck time.Time         `json:"last_health_check"`
	FailoverCount   int               `json:"failover_count"`
	Metadata        map[string]string `json:"metadata"`
}

// RouteStatus represents the status of a failover route
type RouteStatus int

const (
	RouteActive RouteStatus = iota
	RouteDegraded
	RouteFailed
	RouteRecovering
	RouteMaintenance
)

// FailoverEvent represents different failover events
type FailoverEvent int

const (
	RouteFailedEvent FailoverEvent = iota
	RouteRecoveredEvent
	FailoverTriggeredEvent
	LoadBalancingEvent
	HealthCheckFailedEvent
)

// FailoverManager manages failover and load balancing for the mesh
type FailoverManager struct {
	config          *FailoverConfig
	logger          *slog.Logger
	routes          map[string]*FailoverRoute
	callbacks       []FailoverCallback
	mu              sync.RWMutex
	ctx             context.Context
	cancel          context.CancelFunc
	activeFailovers int
}

// FailoverCallback is called when failover events occur
type FailoverCallback func(event FailoverEvent, route *FailoverRoute)

// NewFailoverManager creates a new failover manager
func NewFailoverManager(config *FailoverConfig, logger *slog.Logger) *FailoverManager {
	if config == nil {
		config = &FailoverConfig{
			HealthCheckInterval:    30 * time.Second,
			FailoverTimeout:        10 * time.Second,
			RecoveryTimeout:        60 * time.Second,
			MaxFailoverAttempts:    3,
			EnableAutoRecovery:     true,
			LoadBalancingEnabled:   true,
			MaxConcurrentFailovers: 10,
			PriorityBasedRouting:   true,
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &FailoverManager{
		config:    config,
		logger:    logger,
		routes:    make(map[string]*FailoverRoute),
		callbacks: make([]FailoverCallback, 0),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Start begins failover management
func (fm *FailoverManager) Start() error {
	fm.logger.Info("Starting failover manager")

	// Start background services
	go fm.healthCheckLoop()
	go fm.recoveryLoop()
	go fm.loadBalancingLoop()

	fm.logger.Info("Failover manager started")
	return nil
}

// Stop ends failover management
func (fm *FailoverManager) Stop() error {
	fm.logger.Info("Stopping failover manager")
	fm.cancel()
	fm.logger.Info("Failover manager stopped")
	return nil
}

// AddRoute adds a failover route
func (fm *FailoverManager) AddRoute(route *FailoverRoute) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if route.ID == "" {
		return fmt.Errorf("route ID cannot be empty")
	}

	if _, exists := fm.routes[route.ID]; exists {
		return fmt.Errorf("route with ID %s already exists", route.ID)
	}

	// Set default values
	if route.Status == 0 {
		route.Status = RouteActive
	}
	if route.Priority == 0 {
		route.Priority = 100
	}
	if route.CurrentPath == nil {
		route.CurrentPath = route.PrimaryPath
	}
	if route.Metadata == nil {
		route.Metadata = make(map[string]string)
	}

	fm.routes[route.ID] = route
	fm.logger.Info("Failover route added", "route_id", route.ID, "source", route.SourceNodeID, "target", route.TargetNodeID)
	return nil
}

// RemoveRoute removes a failover route
func (fm *FailoverManager) RemoveRoute(routeID string) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if _, exists := fm.routes[routeID]; !exists {
		return fmt.Errorf("route with ID %s does not exist", routeID)
	}

	delete(fm.routes, routeID)
	fm.logger.Info("Failover route removed", "route_id", routeID)
	return nil
}

// GetRoute gets a failover route by ID
func (fm *FailoverManager) GetRoute(routeID string) (*FailoverRoute, bool) {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	route, exists := fm.routes[routeID]
	return route, exists
}

// GetAllRoutes gets all failover routes
func (fm *FailoverManager) GetAllRoutes() []*FailoverRoute {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	routes := make([]*FailoverRoute, 0, len(fm.routes))
	for _, route := range fm.routes {
		routes = append(routes, route)
	}
	return routes
}

// TriggerFailover triggers a failover for a specific route
func (fm *FailoverManager) TriggerFailover(routeID string) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	route, exists := fm.routes[routeID]
	if !exists {
		return fmt.Errorf("route with ID %s does not exist", routeID)
	}

	if fm.activeFailovers >= fm.config.MaxConcurrentFailovers {
		return fmt.Errorf("maximum concurrent failovers reached")
	}

	return fm.performFailover(route)
}

// performFailover performs the actual failover operation
func (fm *FailoverManager) performFailover(route *FailoverRoute) error {
	fm.logger.Info("Performing failover", "route_id", route.ID, "current_status", route.Status)

	// Check if we have backup paths
	if len(route.BackupPaths) == 0 {
		route.Status = RouteFailed
		fm.notifyCallbacks(RouteFailedEvent, route)
		return fmt.Errorf("no backup paths available for route %s", route.ID)
	}

	// Find the best backup path
	bestPath := fm.selectBestBackupPath(route)
	if bestPath == nil {
		route.Status = RouteFailed
		fm.notifyCallbacks(RouteFailedEvent, route)
		return fmt.Errorf("no viable backup path found for route %s", route.ID)
	}

	// Update route
	route.CurrentPath = bestPath
	route.Status = RouteDegraded
	route.FailoverCount++
	route.LastHealthCheck = time.Now()

	fm.activeFailovers++
	fm.logger.Info("Failover completed", "route_id", route.ID, "new_path", bestPath)
	fm.notifyCallbacks(FailoverTriggeredEvent, route)

	// Start recovery monitoring
	go fm.monitorRouteRecovery(route)

	return nil
}

// selectBestBackupPath selects the best backup path based on priority and health
func (fm *FailoverManager) selectBestBackupPath(route *FailoverRoute) []string {
	var viablePaths [][]string

	// Filter viable paths
	for _, path := range route.BackupPaths {
		if fm.isPathViable(path) {
			viablePaths = append(viablePaths, path)
		}
	}

	if len(viablePaths) == 0 {
		return nil
	}

	// Sort by priority (lower number = higher priority)
	sort.Slice(viablePaths, func(i, j int) bool {
		priorityI := fm.calculatePathPriority(viablePaths[i])
		priorityJ := fm.calculatePathPriority(viablePaths[j])
		return priorityI < priorityJ
	})

	return viablePaths[0]
}

// isPathViable checks if a path is viable for failover
func (fm *FailoverManager) isPathViable(path []string) bool {
	// Check if all nodes in the path are healthy
	for _, nodeID := range path {
		// In a real implementation, you would check node health
		// For now, assume all paths are viable
		_ = nodeID
	}
	return true
}

// calculatePathPriority calculates the priority of a path
func (fm *FailoverManager) calculatePathPriority(path []string) int {
	// Simple priority calculation based on path length
	// Shorter paths have higher priority
	return len(path)
}

// monitorRouteRecovery monitors a route for recovery
func (fm *FailoverManager) monitorRouteRecovery(route *FailoverRoute) {
	ticker := time.NewTicker(fm.config.HealthCheckInterval)
	defer ticker.Stop()

	recoveryAttempts := 0
	for {
		select {
		case <-fm.ctx.Done():
			return
		case <-ticker.C:
			if fm.checkRouteHealth(route) {
				fm.mu.Lock()
				route.Status = RouteActive
				route.CurrentPath = route.PrimaryPath
				fm.activeFailovers--
				fm.mu.Unlock()

				fm.logger.Info("Route recovered", "route_id", route.ID)
				fm.notifyCallbacks(RouteRecoveredEvent, route)
				return
			}

			recoveryAttempts++
			if recoveryAttempts >= fm.config.MaxFailoverAttempts {
				fm.mu.Lock()
				route.Status = RouteFailed
				fm.activeFailovers--
				fm.mu.Unlock()

				fm.logger.Error("Route recovery failed", "route_id", route.ID, "attempts", recoveryAttempts)
				fm.notifyCallbacks(RouteFailedEvent, route)
				return
			}
		}
	}
}

// checkRouteHealth checks the health of a route
func (fm *FailoverManager) checkRouteHealth(route *FailoverRoute) bool {
	// In a real implementation, you would perform actual health checks
	// For now, simulate health check with some probability
	route.LastHealthCheck = time.Now()

	// Simulate health check (90% success rate for primary path)
	if len(route.CurrentPath) == len(route.PrimaryPath) {
		// Simple comparison - in real implementation, you would do deep comparison
		return true // Assume primary path is healthy
	}

	// For backup paths, simulate some recovery
	return false // Keep using backup path for now
}

// healthCheckLoop runs the health check loop
func (fm *FailoverManager) healthCheckLoop() {
	ticker := time.NewTicker(fm.config.HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-fm.ctx.Done():
			return
		case <-ticker.C:
			fm.performHealthChecks()
		}
	}
}

// recoveryLoop runs the recovery loop
func (fm *FailoverManager) recoveryLoop() {
	ticker := time.NewTicker(fm.config.RecoveryTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-fm.ctx.Done():
			return
		case <-ticker.C:
			fm.attemptRecoveries()
		}
	}
}

// loadBalancingLoop runs the load balancing loop
func (fm *FailoverManager) loadBalancingLoop() {
	if !fm.config.LoadBalancingEnabled {
		return
	}

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-fm.ctx.Done():
			return
		case <-ticker.C:
			fm.performLoadBalancing()
		}
	}
}

// performHealthChecks performs health checks on all routes
func (fm *FailoverManager) performHealthChecks() {
	fm.mu.RLock()
	routes := make([]*FailoverRoute, 0, len(fm.routes))
	for _, route := range fm.routes {
		routes = append(routes, route)
	}
	fm.mu.RUnlock()

	for _, route := range routes {
		if !fm.checkRouteHealth(route) {
			fm.logger.Warn("Route health check failed", "route_id", route.ID)
			fm.notifyCallbacks(HealthCheckFailedEvent, route)

			// Trigger failover if route is active
			if route.Status == RouteActive {
				go fm.TriggerFailover(route.ID)
			}
		}
	}
}

// attemptRecoveries attempts to recover failed routes
func (fm *FailoverManager) attemptRecoveries() {
	if !fm.config.EnableAutoRecovery {
		return
	}

	fm.mu.RLock()
	var failedRoutes []*FailoverRoute
	for _, route := range fm.routes {
		if route.Status == RouteFailed {
			failedRoutes = append(failedRoutes, route)
		}
	}
	fm.mu.RUnlock()

	for _, route := range failedRoutes {
		go fm.attemptRouteRecovery(route)
	}
}

// attemptRouteRecovery attempts to recover a specific route
func (fm *FailoverManager) attemptRouteRecovery(route *FailoverRoute) {
	fm.logger.Info("Attempting route recovery", "route_id", route.ID)

	// Check if primary path is healthy
	if fm.checkRouteHealth(route) {
		fm.mu.Lock()
		route.Status = RouteActive
		// Copy primary path to current path
		route.CurrentPath = make([]string, len(route.PrimaryPath))
		copy(route.CurrentPath, route.PrimaryPath)
		fm.mu.Unlock()

		fm.logger.Info("Route recovery successful", "route_id", route.ID)
		fm.notifyCallbacks(RouteRecoveredEvent, route)
	}
}

// performLoadBalancing performs load balancing across routes
func (fm *FailoverManager) performLoadBalancing() {
	if !fm.config.LoadBalancingEnabled {
		return
	}

	fm.mu.RLock()
	routes := make([]*FailoverRoute, 0, len(fm.routes))
	for _, route := range fm.routes {
		if route.LoadBalanced {
			routes = append(routes, route)
		}
	}
	fm.mu.RUnlock()

	for _, route := range routes {
		fm.balanceRouteLoad(route)
	}
}

// balanceRouteLoad balances load for a specific route
func (fm *FailoverManager) balanceRouteLoad(route *FailoverRoute) {
	// In a real implementation, you would analyze load metrics
	// and redistribute traffic across available paths

	fm.logger.Debug("Load balancing route", "route_id", route.ID)
	fm.notifyCallbacks(LoadBalancingEvent, route)
}

// AddCallback adds a callback for failover events
func (fm *FailoverManager) AddCallback(callback FailoverCallback) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	fm.callbacks = append(fm.callbacks, callback)
}

// notifyCallbacks notifies registered callbacks
func (fm *FailoverManager) notifyCallbacks(event FailoverEvent, route *FailoverRoute) {
	fm.mu.RLock()
	callbacks := make([]FailoverCallback, len(fm.callbacks))
	copy(callbacks, fm.callbacks)
	fm.mu.RUnlock()

	for _, callback := range callbacks {
		go callback(event, route)
	}
}

// GetStats returns failover manager statistics
func (fm *FailoverManager) GetStats() map[string]interface{} {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	var activeRoutes, failedRoutes, degradedRoutes int
	for _, route := range fm.routes {
		switch route.Status {
		case RouteActive:
			activeRoutes++
		case RouteFailed:
			failedRoutes++
		case RouteDegraded:
			degradedRoutes++
		}
	}

	return map[string]interface{}{
		"total_routes":             len(fm.routes),
		"active_routes":            activeRoutes,
		"failed_routes":            failedRoutes,
		"degraded_routes":          degradedRoutes,
		"active_failovers":         fm.activeFailovers,
		"max_concurrent_failovers": fm.config.MaxConcurrentFailovers,
		"load_balancing_enabled":   fm.config.LoadBalancingEnabled,
		"auto_recovery_enabled":    fm.config.EnableAutoRecovery,
	}
}

// String returns string representation of route status
func (rs RouteStatus) String() string {
	switch rs {
	case RouteActive:
		return "Active"
	case RouteDegraded:
		return "Degraded"
	case RouteFailed:
		return "Failed"
	case RouteRecovering:
		return "Recovering"
	case RouteMaintenance:
		return "Maintenance"
	default:
		return "Unknown"
	}
}
