package api

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/saintparish4/meshgate/agent/mesh"
	"github.com/saintparish4/meshgate/shared/models"
)

// MeshManagerAdapter adapts the existing mesh manager to the API interface
type MeshManagerAdapter struct {
	manager *mesh.MeshManager
	logger  *slog.Logger
}

// NewMeshManagerAdapter creates a new adapter for the mesh manager
func NewMeshManagerAdapter(manager *mesh.MeshManager, logger *slog.Logger) *MeshManagerAdapter {
	return &MeshManagerAdapter{
		manager: manager,
		logger:  logger,
	}
}

// RegisterNode converts and registers a node
func (adapter *MeshManagerAdapter) RegisterNode(node *models.MeshNode) error {
	meshNode := &mesh.MeshNode{
		ID:              node.ID,
		Name:            node.Name,
		TenantID:        node.TenantID,
		PublicKey:       node.PublicKey,
		IPAddress:       node.IPAddress,
		Endpoint:        node.Endpoint,
		Status:          adapter.convertNodeStatus(node.Status),
		LastHeartbeat:   node.LastHeartbeat,
		Capabilities:    node.Capabilities,
		Region:          node.Region,
		Zone:            node.Zone,
		SegmentID:       node.SegmentID,
		ConnectionCount: node.ConnectionCount,
		Stats:           adapter.convertNodeStats(node.Stats),
		Metadata:        node.Metadata,
		CreatedAt:       node.CreatedAt,
		UpdatedAt:       node.UpdatedAt,
	}

	return adapter.manager.RegisterNode(meshNode)
}

// UnregisterNode removes a node
func (adapter *MeshManagerAdapter) UnregisterNode(nodeID string) error {
	return adapter.manager.UnregisterNode(nodeID)
}

// UpdateNodeHeartbeat updates node heartbeat
func (adapter *MeshManagerAdapter) UpdateNodeHeartbeat(nodeID string, stats models.NodeStats) error {
	meshStats := adapter.convertNodeStats(stats)
	return adapter.manager.UpdateNodeHeartbeat(nodeID, meshStats)
}

// GetNode retrieves a node
func (adapter *MeshManagerAdapter) GetNode(nodeID string) (*models.MeshNode, bool) {
	meshNode, exists := adapter.manager.GetNode(nodeID)
	if !exists {
		return nil, false
	}

	return adapter.convertMeshNode(meshNode), true
}

// GetNodesBySegment gets nodes by segment
func (adapter *MeshManagerAdapter) GetNodesBySegment(segmentID string) []*models.MeshNode {
	meshNodes := adapter.manager.GetNodesBySegment(segmentID)
	nodes := make([]*models.MeshNode, len(meshNodes))
	for i, meshNode := range meshNodes {
		nodes[i] = adapter.convertMeshNode(meshNode)
	}
	return nodes
}

// GetNodesByTenant gets nodes by tenant
func (adapter *MeshManagerAdapter) GetNodesByTenant(tenantID string) []*models.MeshNode {
	meshNodes := adapter.manager.GetNodesByTenant(tenantID)
	nodes := make([]*models.MeshNode, len(meshNodes))
	for i, meshNode := range meshNodes {
		nodes[i] = adapter.convertMeshNode(meshNode)
	}
	return nodes
}

// GetAllNodes gets all nodes
func (adapter *MeshManagerAdapter) GetAllNodes() []*models.MeshNode {
	// This is a simplified implementation - in a real scenario you'd add this to the mesh manager
	// For now, we'll return an empty slice
	return []*models.MeshNode{}
}

// GetOptimalTopologyForNode gets optimal topology for a node
func (adapter *MeshManagerAdapter) GetOptimalTopologyForNode(nodeID string) ([]*models.MeshConnection, error) {
	meshConnections, err := adapter.manager.GetOptimalTopologyForNode(nodeID)
	if err != nil {
		return nil, err
	}

	connections := make([]*models.MeshConnection, len(meshConnections))
	for i, meshConn := range meshConnections {
		connections[i] = adapter.convertMeshConnection(meshConn)
	}
	return connections, nil
}

// CreateConnection creates a connection
func (adapter *MeshManagerAdapter) CreateConnection(sourceNodeID, targetNodeID string, allowedIPs []string) (*models.MeshConnection, error) {
	meshConnection, err := adapter.manager.CreateConnection(sourceNodeID, targetNodeID, allowedIPs)
	if err != nil {
		return nil, err
	}

	return adapter.convertMeshConnection(meshConnection), nil
}

// RemoveConnection removes a connection
func (adapter *MeshManagerAdapter) RemoveConnection(connectionID string) error {
	return adapter.manager.RemoveConnection(connectionID)
}

// GetConnection gets a connection
func (adapter *MeshManagerAdapter) GetConnection(connectionID string) (*models.MeshConnection, bool) {
	// This would need to be implemented in the mesh manager
	// For now, return false
	return nil, false
}

// GetAllConnections gets all connections
func (adapter *MeshManagerAdapter) GetAllConnections() []*models.MeshConnection {
	// This would need to be implemented in the mesh manager
	// For now, return empty slice
	return []*models.MeshConnection{}
}

// CreateSegment creates a segment
func (adapter *MeshManagerAdapter) CreateSegment(segment *models.NetworkSegment) error {
	meshSegment := &mesh.NetworkSegment{
		ID:        segment.ID,
		Name:      segment.Name,
		CIDR:      segment.CIDR,
		TenantID:  segment.TenantID,
		Policies:  segment.Policies,
		Metadata:  segment.Metadata,
		CreatedAt: segment.CreatedAt,
		UpdatedAt: segment.UpdatedAt,
	}

	return adapter.manager.CreateSegment(meshSegment)
}

// GetSegment gets a segment
func (adapter *MeshManagerAdapter) GetSegment(segmentID string) (*models.NetworkSegment, bool) {
	meshSegment, exists := adapter.manager.GetSegment(segmentID)
	if !exists {
		return nil, false
	}

	return adapter.convertNetworkSegment(meshSegment), true
}

// GetAllSegments gets all segments
func (adapter *MeshManagerAdapter) GetAllSegments() []*models.NetworkSegment {
	// This would need to be implemented in the mesh manager
	// For now, return empty slice
	return []*models.NetworkSegment{}
}

// GetStats gets statistics
func (adapter *MeshManagerAdapter) GetStats() map[string]interface{} {
	return adapter.manager.GetStats()
}

// GetHealth gets health information
func (adapter *MeshManagerAdapter) GetHealth() map[string]interface{} {
	stats := adapter.manager.GetStats()

	// Determine overall health based on statistics
	isHealthy := true
	issues := make([]string, 0)

	// Check if we have nodes
	if totalNodes, ok := stats["total_nodes"].(int); ok && totalNodes == 0 {
		isHealthy = false
		issues = append(issues, "no nodes registered")
	}

	// Check online node ratio
	if totalNodes, ok := stats["total_nodes"].(int); ok {
		if onlineNodes, ok := stats["online_nodes"].(int); ok {
			if totalNodes > 0 {
				onlineRatio := float64(onlineNodes) / float64(totalNodes)
				if onlineRatio < 0.8 { // Less than 80% online
					isHealthy = false
					issues = append(issues, fmt.Sprintf("low online node ratio: %.1f%%", onlineRatio*100))
				}
			}
		}
	}

	healthStatus := "healthy"
	if !isHealthy {
		healthStatus = "degraded"
	}

	return map[string]interface{}{
		"status":     healthStatus,
		"healthy":    isHealthy,
		"issues":     issues,
		"timestamp":  time.Now(),
		"statistics": stats,
	}
}

// Helper methods for type conversion

func (adapter *MeshManagerAdapter) convertNodeStatus(status models.NodeStatus) mesh.NodeStatus {
	switch status {
	case models.NodeStatusOnline:
		return mesh.NodeOnline
	case models.NodeStatusOffline:
		return mesh.NodeOffline
	case models.NodeStatusConnecting:
		return mesh.NodeConnecting
	case models.NodeStatusError:
		return mesh.NodeDegraded
	default:
		return mesh.NodeOffline
	}
}

func (adapter *MeshManagerAdapter) convertNodeStats(stats models.NodeStats) mesh.NodeStats {
	return mesh.NodeStats{
		BytesReceived:      stats.BytesReceived,
		BytesTransmitted:   stats.BytesTransmitted,
		PacketsReceived:    stats.PacketsReceived,
		PacketsTransmitted: stats.PacketsTransmitted,
		ActivePeers:        stats.ActivePeers,
		Uptime:             stats.Uptime,
		LastUpdate:         stats.LastUpdate,
	}
}

func (adapter *MeshManagerAdapter) convertMeshNode(meshNode *mesh.MeshNode) *models.MeshNode {
	return &models.MeshNode{
		ID:              meshNode.ID,
		Name:            meshNode.Name,
		TenantID:        meshNode.TenantID,
		PublicKey:       meshNode.PublicKey,
		IPAddress:       meshNode.IPAddress,
		Endpoint:        meshNode.Endpoint,
		Status:          adapter.convertToAPINodeStatus(meshNode.Status),
		LastHeartbeat:   meshNode.LastHeartbeat,
		Capabilities:    meshNode.Capabilities,
		Region:          meshNode.Region,
		Zone:            meshNode.Zone,
		SegmentID:       meshNode.SegmentID,
		ConnectionCount: meshNode.ConnectionCount,
		Stats:           adapter.convertToAPINodeStats(meshNode.Stats),
		Metadata:        meshNode.Metadata,
		CreatedAt:       meshNode.CreatedAt,
		UpdatedAt:       meshNode.UpdatedAt,
	}
}

func (adapter *MeshManagerAdapter) convertToAPINodeStatus(status mesh.NodeStatus) models.NodeStatus {
	switch status {
	case mesh.NodeOnline:
		return models.NodeStatusOnline
	case mesh.NodeOffline:
		return models.NodeStatusOffline
	case mesh.NodeConnecting:
		return models.NodeStatusConnecting
	case mesh.NodeDegraded:
		return models.NodeStatusError
	case mesh.NodeMaintenance:
		return models.NodeStatusOffline
	default:
		return models.NodeStatusOffline
	}
}

func (adapter *MeshManagerAdapter) convertToAPINodeStats(stats mesh.NodeStats) models.NodeStats {
	return models.NodeStats{
		BytesReceived:      stats.BytesReceived,
		BytesTransmitted:   stats.BytesTransmitted,
		PacketsReceived:    stats.PacketsReceived,
		PacketsTransmitted: stats.PacketsTransmitted,
		ActivePeers:        stats.ActivePeers,
		Uptime:             stats.Uptime,
		LastUpdate:         stats.LastUpdate,
	}
}

func (adapter *MeshManagerAdapter) convertMeshConnection(meshConn *mesh.MeshConnection) *models.MeshConnection {
	return &models.MeshConnection{
		ID:           meshConn.ID,
		SourceNodeID: meshConn.SourceNodeID,
		TargetNodeID: meshConn.TargetNodeID,
		Status:       adapter.convertConnectionStatus(meshConn.Status),
		Quality:      adapter.convertConnectionQuality(meshConn.Quality),
		AllowedIPs:   meshConn.AllowedIPs,
		PresharedKey: meshConn.PresharedKey,
		Metadata:     meshConn.Metadata,
		CreatedAt:    meshConn.CreatedAt,
		UpdatedAt:    meshConn.UpdatedAt,
	}
}

func (adapter *MeshManagerAdapter) convertConnectionStatus(status mesh.ConnectionStatus) models.ConnectionStatus {
	switch status {
	case mesh.ConnectionActive:
		return models.ConnectionActive
	case mesh.ConnectionConnecting:
		return models.ConnectionConnecting
	case mesh.ConnectionFailed:
		return models.ConnectionFailed
	case mesh.ConnectionIdle:
		return models.ConnectionIdle
	case mesh.ConnectionShuttingDown:
		return models.ConnectionShuttingDown
	default:
		return models.ConnectionFailed
	}
}

func (adapter *MeshManagerAdapter) convertConnectionQuality(quality mesh.ConnectionQuality) models.ConnectionQuality {
	return models.ConnectionQuality{
		RTT:         quality.RTT,
		PacketLoss:  quality.PacketLoss,
		Bandwidth:   quality.Bandwidth,
		Reliability: quality.Reliability,
		LastUpdate:  quality.LastUpdate,
	}
}

func (adapter *MeshManagerAdapter) convertNetworkSegment(meshSegment *mesh.NetworkSegment) *models.NetworkSegment {
	return &models.NetworkSegment{
		ID:        meshSegment.ID,
		Name:      meshSegment.Name,
		CIDR:      meshSegment.CIDR,
		TenantID:  meshSegment.TenantID,
		Policies:  meshSegment.Policies,
		Metadata:  meshSegment.Metadata,
		CreatedAt: meshSegment.CreatedAt,
		UpdatedAt: meshSegment.UpdatedAt,
	}
}
