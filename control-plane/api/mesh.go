package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/saintparish4/meshgate/shared/models"
	"github.com/saintparish4/meshgate/shared/utils"
)

// MeshAPI provides HTTP endpoints for mesh management
type MeshAPI struct {
	meshManager MeshManagerInterface
	logger      *slog.Logger
}

// MeshManagerInterface defines the interface for mesh management
type MeshManagerInterface interface {
	// Node Management
	RegisterNode(node *models.MeshNode) error
	UnregisterNode(nodeID string) error
	UpdateNodeHeartbeat(nodeID string, stats models.NodeStats) error
	GetNode(nodeID string) (*models.MeshNode, bool)
	GetNodesBySegment(segmentID string) []*models.MeshNode
	GetNodesByTenant(tenantID string) []*models.MeshNode
	GetAllNodes() []*models.MeshNode

	// Connection Management
	GetOptimalTopologyForNode(nodeID string) ([]*models.MeshConnection, error)
	CreateConnection(sourceNodeID, targetNodeID string, allowedIPs []string) (*models.MeshConnection, error)
	RemoveConnection(connectionID string) error
	GetConnection(connectionID string) (*models.MeshConnection, bool)
	GetAllConnections() []*models.MeshConnection

	// Segment Management
	CreateSegment(segment *models.NetworkSegment) error
	GetSegment(segmentID string) (*models.NetworkSegment, bool)
	GetAllSegments() []*models.NetworkSegment

	// Statistics and Monitoring
	GetStats() map[string]interface{}
	GetHealth() map[string]interface{}
}

// NewMeshAPI creates a new mesh API instance
func NewMeshAPI(meshManager MeshManagerInterface, logger *slog.Logger) *MeshAPI {
	return &MeshAPI{
		meshManager: meshManager,
		logger:      logger,
	}
}

// RegisterRoutes registers mesh API routes
func (api *MeshAPI) RegisterRoutes(router *mux.Router) {
	// Node management
	router.HandleFunc("/api/v1/mesh/nodes", api.handleCreateNode).Methods("POST")
	router.HandleFunc("/api/v1/mesh/nodes", api.handleListNodes).Methods("GET")
	router.HandleFunc("/api/v1/mesh/nodes/{nodeId}", api.handleGetNode).Methods("GET")
	router.HandleFunc("/api/v1/mesh/nodes/{nodeId}", api.handleUpdateNode).Methods("PUT")
	router.HandleFunc("/api/v1/mesh/nodes/{nodeId}", api.handleDeleteNode).Methods("DELETE")
	router.HandleFunc("/api/v1/mesh/nodes/{nodeId}/heartbeat", api.handleNodeHeartbeat).Methods("POST")
	router.HandleFunc("/api/v1/mesh/nodes/{nodeId}/config", api.handleGetNodeConfig).Methods("GET")
	router.HandleFunc("/api/v1/mesh/nodes/{nodeId}/topology", api.handleGetNodeTopology).Methods("GET")

	// Connection management
	router.HandleFunc("/api/v1/mesh/connections", api.handleCreateConnection).Methods("POST")
	router.HandleFunc("/api/v1/mesh/connections", api.handleListConnections).Methods("GET")
	router.HandleFunc("/api/v1/mesh/connections/{connectionId}", api.handleDeleteConnection).Methods("DELETE")

	// Segment management
	router.HandleFunc("/api/v1/mesh/segments", api.handleCreateSegment).Methods("POST")
	router.HandleFunc("/api/v1/mesh/segments", api.handleListSegments).Methods("GET")
	router.HandleFunc("/api/v1/mesh/segments/{segmentId}", api.handleGetSegment).Methods("GET")
	router.HandleFunc("/api/v1/mesh/segments/{segmentId}/nodes", api.handleGetSegmentNodes).Methods("GET")

	// Statistics and monitoring
	router.HandleFunc("/api/v1/mesh/stats", api.handleGetMeshStats).Methods("GET")
	router.HandleFunc("/api/v1/mesh/health", api.handleGetMeshHealth).Methods("GET")

	api.logger.Info("Mesh API routes registered")
}

// =============================================================================
// Node Management Endpoints
// =============================================================================

func (api *MeshAPI) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string            `json:"name"`
		TenantID     string            `json:"tenant_id"`
		PublicKey    string            `json:"public_key"`
		IPAddress    string            `json:"ip_address"`
		Endpoint     string            `json:"endpoint"`
		Capabilities []string          `json:"capabilities"`
		Region       string            `json:"region"`
		Zone         string            `json:"zone"`
		SegmentID    string            `json:"segment_id"`
		Metadata     map[string]string `json:"metadata"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate required fields
	if err := api.validateCreateNodeRequest(req); err != nil {
		api.writeError(w, http.StatusBadRequest, err.Error(), nil)
		return
	}

	// Generate node ID
	nodeID := utils.GenerateID()

	node := &models.MeshNode{
		ID:           nodeID,
		Name:         req.Name,
		TenantID:     req.TenantID,
		PublicKey:    req.PublicKey,
		IPAddress:    req.IPAddress,
		Endpoint:     req.Endpoint,
		Capabilities: req.Capabilities,
		Region:       req.Region,
		Zone:         req.Zone,
		SegmentID:    req.SegmentID,
		Metadata:     req.Metadata,
		Status:       models.NodeStatusOnline,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := api.meshManager.RegisterNode(node); err != nil {
		api.writeError(w, http.StatusInternalServerError, "Failed to register node", err)
		return
	}

	api.writeJSON(w, http.StatusCreated, map[string]interface{}{
		"node_id": nodeID,
		"message": "Node registered successfully",
	})

	api.logger.Info("Node registered via API",
		"node_id", nodeID,
		"tenant_id", req.TenantID)
}

func (api *MeshAPI) handleListNodes(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	tenantID := r.URL.Query().Get("tenant_id")
	segmentID := r.URL.Query().Get("segment_id")
	status := r.URL.Query().Get("status")

	var nodes []*models.MeshNode

	// Get nodes based on filters
	switch {
	case segmentID != "":
		nodes = api.meshManager.GetNodesBySegment(segmentID)
	case tenantID != "":
		nodes = api.meshManager.GetNodesByTenant(tenantID)
	default:
		nodes = api.meshManager.GetAllNodes()
	}

	// Filter by status if specified
	if status != "" {
		nodes = api.filterNodesByStatus(nodes, status)
	}

	api.writeJSON(w, http.StatusOK, map[string]interface{}{
		"nodes": nodes,
		"count": len(nodes),
	})
}

func (api *MeshAPI) handleGetNode(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nodeID := vars["nodeId"]

	node, exists := api.meshManager.GetNode(nodeID)
	if !exists {
		api.writeError(w, http.StatusNotFound, "Node not found", nil)
		return
	}

	api.writeJSON(w, http.StatusOK, node)
}

func (api *MeshAPI) handleUpdateNode(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nodeID := vars["nodeId"]

	// Get existing node
	existingNode, exists := api.meshManager.GetNode(nodeID)
	if !exists {
		api.writeError(w, http.StatusNotFound, "Node not found", nil)
		return
	}

	var req struct {
		Name         string            `json:"name,omitempty"`
		Endpoint     string            `json:"endpoint,omitempty"`
		Capabilities []string          `json:"capabilities,omitempty"`
		Region       string            `json:"region,omitempty"`
		Zone         string            `json:"zone,omitempty"`
		Metadata     map[string]string `json:"metadata,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Update fields if provided
	api.updateNodeFields(existingNode, req)
	existingNode.UpdatedAt = time.Now()

	if err := api.meshManager.RegisterNode(existingNode); err != nil {
		api.writeError(w, http.StatusInternalServerError, "Failed to update node", err)
		return
	}

	api.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Node updated successfully",
	})

	api.logger.Info("Node updated via API", "node_id", nodeID)
}

func (api *MeshAPI) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nodeID := vars["nodeId"]

	if err := api.meshManager.UnregisterNode(nodeID); err != nil {
		api.writeError(w, http.StatusInternalServerError, "Failed to unregister node", err)
		return
	}

	api.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Node unregistered successfully",
	})

	api.logger.Info("Node unregistered via API", "node_id", nodeID)
}

func (api *MeshAPI) handleNodeHeartbeat(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nodeID := vars["nodeId"]

	var req struct {
		Stats models.NodeStats `json:"stats"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := api.meshManager.UpdateNodeHeartbeat(nodeID, req.Stats); err != nil {
		api.writeError(w, http.StatusInternalServerError, "Failed to update heartbeat", err)
		return
	}

	api.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Heartbeat updated successfully",
	})
}

func (api *MeshAPI) handleGetNodeConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nodeID := vars["nodeId"]

	node, exists := api.meshManager.GetNode(nodeID)
	if !exists {
		api.writeError(w, http.StatusNotFound, "Node not found", nil)
		return
	}

	// Get optimal topology for this node
	connections, err := api.meshManager.GetOptimalTopologyForNode(nodeID)
	if err != nil {
		api.writeError(w, http.StatusInternalServerError, "Failed to get topology", err)
		return
	}

	config := map[string]interface{}{
		"node":        node,
		"connections": connections,
		"config_time": time.Now(),
	}

	api.writeJSON(w, http.StatusOK, config)
}

func (api *MeshAPI) handleGetNodeTopology(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nodeID := vars["nodeId"]

	connections, err := api.meshManager.GetOptimalTopologyForNode(nodeID)
	if err != nil {
		api.writeError(w, http.StatusInternalServerError, "Failed to get topology", err)
		return
	}

	api.writeJSON(w, http.StatusOK, map[string]interface{}{
		"node_id":     nodeID,
		"connections": connections,
	})
}

// =============================================================================
// Connection Management Endpoints
// =============================================================================

func (api *MeshAPI) handleCreateConnection(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SourceNodeID string   `json:"source_node_id"`
		TargetNodeID string   `json:"target_node_id"`
		AllowedIPs   []string `json:"allowed_ips"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate required fields
	if req.SourceNodeID == "" || req.TargetNodeID == "" {
		api.writeError(w, http.StatusBadRequest, "Source and target node IDs are required", nil)
		return
	}

	connection, err := api.meshManager.CreateConnection(req.SourceNodeID, req.TargetNodeID, req.AllowedIPs)
	if err != nil {
		api.writeError(w, http.StatusInternalServerError, "Failed to create connection", err)
		return
	}

	api.writeJSON(w, http.StatusCreated, connection)
}

func (api *MeshAPI) handleListConnections(w http.ResponseWriter, r *http.Request) {
	connections := api.meshManager.GetAllConnections()

	api.writeJSON(w, http.StatusOK, map[string]interface{}{
		"connections": connections,
		"count":       len(connections),
	})
}

func (api *MeshAPI) handleDeleteConnection(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	connectionID := vars["connectionId"]

	if err := api.meshManager.RemoveConnection(connectionID); err != nil {
		api.writeError(w, http.StatusInternalServerError, "Failed to remove connection", err)
		return
	}

	api.writeJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Connection removed successfully",
	})
}

// =============================================================================
// Segment Management Endpoints
// =============================================================================

func (api *MeshAPI) handleCreateSegment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string            `json:"name"`
		CIDR     string            `json:"cidr"`
		TenantID string            `json:"tenant_id"`
		Policies []string          `json:"policies"`
		Metadata map[string]string `json:"metadata"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.writeError(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	// Validate required fields
	if req.Name == "" || req.CIDR == "" || req.TenantID == "" {
		api.writeError(w, http.StatusBadRequest, "Name, CIDR, and tenant ID are required", nil)
		return
	}

	segment := &models.NetworkSegment{
		ID:        utils.GenerateID(),
		Name:      req.Name,
		CIDR:      req.CIDR,
		TenantID:  req.TenantID,
		Policies:  req.Policies,
		Metadata:  req.Metadata,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := api.meshManager.CreateSegment(segment); err != nil {
		api.writeError(w, http.StatusInternalServerError, "Failed to create segment", err)
		return
	}

	api.writeJSON(w, http.StatusCreated, segment)
}

func (api *MeshAPI) handleListSegments(w http.ResponseWriter, r *http.Request) {
	segments := api.meshManager.GetAllSegments()

	api.writeJSON(w, http.StatusOK, map[string]interface{}{
		"segments": segments,
		"count":    len(segments),
	})
}

func (api *MeshAPI) handleGetSegment(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	segmentID := vars["segmentId"]

	segment, exists := api.meshManager.GetSegment(segmentID)
	if !exists {
		api.writeError(w, http.StatusNotFound, "Segment not found", nil)
		return
	}

	api.writeJSON(w, http.StatusOK, segment)
}

func (api *MeshAPI) handleGetSegmentNodes(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	segmentID := vars["segmentId"]

	nodes := api.meshManager.GetNodesBySegment(segmentID)

	api.writeJSON(w, http.StatusOK, map[string]interface{}{
		"segment_id": segmentID,
		"nodes":      nodes,
		"count":      len(nodes),
	})
}

// =============================================================================
// Statistics and Monitoring Endpoints
// =============================================================================

func (api *MeshAPI) handleGetMeshStats(w http.ResponseWriter, r *http.Request) {
	stats := api.meshManager.GetStats()

	api.writeJSON(w, http.StatusOK, stats)
}

func (api *MeshAPI) handleGetMeshHealth(w http.ResponseWriter, r *http.Request) {
	health := api.meshManager.GetHealth()

	api.writeJSON(w, http.StatusOK, health)
}

// =============================================================================
// Helper Methods
// =============================================================================

func (api *MeshAPI) writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		api.logger.Error("Failed to encode JSON response", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (api *MeshAPI) writeError(w http.ResponseWriter, statusCode int, message string, err error) {
	response := map[string]interface{}{
		"error":   message,
		"success": false,
	}

	if err != nil {
		response["details"] = err.Error()
		api.logger.Error("API error", "message", message, "error", err)
	} else {
		api.logger.Warn("API error", "message", message)
	}

	api.writeJSON(w, statusCode, response)
}

func (api *MeshAPI) validateCreateNodeRequest(req struct {
	Name         string            `json:"name"`
	TenantID     string            `json:"tenant_id"`
	PublicKey    string            `json:"public_key"`
	IPAddress    string            `json:"ip_address"`
	Endpoint     string            `json:"endpoint"`
	Capabilities []string          `json:"capabilities"`
	Region       string            `json:"region"`
	Zone         string            `json:"zone"`
	SegmentID    string            `json:"segment_id"`
	Metadata     map[string]string `json:"metadata"`
}) error {
	if req.Name == "" {
		return fmt.Errorf("name is required")
	}
	if req.TenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}
	if req.PublicKey == "" {
		return fmt.Errorf("public_key is required")
	}
	return nil
}

func (api *MeshAPI) filterNodesByStatus(nodes []*models.MeshNode, status string) []*models.MeshNode {
	filtered := make([]*models.MeshNode, 0)
	for _, node := range nodes {
		if string(node.Status) == status {
			filtered = append(filtered, node)
		}
	}
	return filtered
}

func (api *MeshAPI) updateNodeFields(node *models.MeshNode, req struct {
	Name         string            `json:"name,omitempty"`
	Endpoint     string            `json:"endpoint,omitempty"`
	Capabilities []string          `json:"capabilities,omitempty"`
	Region       string            `json:"region,omitempty"`
	Zone         string            `json:"zone,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}) {
	if req.Name != "" {
		node.Name = req.Name
	}
	if req.Endpoint != "" {
		node.Endpoint = req.Endpoint
	}
	if req.Capabilities != nil {
		node.Capabilities = req.Capabilities
	}
	if req.Region != "" {
		node.Region = req.Region
	}
	if req.Zone != "" {
		node.Zone = req.Zone
	}
	if req.Metadata != nil {
		node.Metadata = req.Metadata
	}
}
