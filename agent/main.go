// agent/main.go - Enhanced version with WireGuard interface management
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/saintparish4/meshgate/agent/mesh"
	"github.com/saintparish4/meshgate/agent/wireguard" // Import our WireGuard interface management package
)

// Configuration
type AgentConfig struct {
	ControlPlaneURL      string        `json:"control_plane_url"`
	NodeID               string        `json:"node_id"`
	NodeName             string        `json:"node_name"`
	TenantID             string        `json:"tenant_id"`
	AuthToken            string        `json:"auth_token"`
	InterfaceName        string        `json:"interface_name"`
	ListenPort           int           `json:"listen_port"`
	MetricsPort          int           `json:"metrics_port"`
	HeartbeatInterval    time.Duration `json:"heartbeat_interval"`
	ConfigPollInterval   time.Duration `json:"config_poll_interval"`
	MTU                  int           `json:"mtu"`
	EnableAutoReconnect  bool          `json:"enable_auto_reconnect"`
	MaxReconnectAttempts int           `json:"max_reconnect_attempts"`

	// Enhanced mesh capabilities
	MaxConcurrentConnections int     `json:"max_concurrent_connections"`
	EnableNATTraversal       bool    `json:"enable_nat_traversal"`
	EnableFailover           bool    `json:"enable_failover"`
	EnableLoadBalancing      bool    `json:"enable_load_balancing"`
	ConnectionPoolSize       int     `json:"connection_pool_size"`
	EnableConnectionReuse    bool    `json:"enable_connection_reuse"`
	MaxRetryAttempts         int     `json:"max_retry_attempts"`
	RetryBackoffMultiplier   float64 `json:"retry_backoff_multiplier"`
}

// API Models
type NodeRegistration struct {
	Name      string            `json:"name"`
	PublicKey string            `json:"public_key"`
	Metadata  map[string]string `json:"metadata"`
}

type NodeConfig struct {
	IPAddress string       `json:"ip_address"`
	Peers     []PeerConfig `json:"peers"`
	DNS       []string     `json:"dns"`
	Routes    []string     `json:"routes"`
}

type PeerConfig struct {
	PublicKey    string   `json:"public_key"`
	Endpoint     string   `json:"endpoint"`
	AllowedIPs   []string `json:"allowed_ips"`
	PresharedKey string   `json:"preshared_key,omitempty"`
}

type HeartbeatData struct {
	Status    string            `json:"status"`
	Timestamp time.Time         `json:"timestamp"`
	Stats     ConnectionStats   `json:"stats"`
	Metadata  map[string]string `json:"metadata"`
}

type ConnectionStats struct {
	BytesReceived    int64 `json:"bytes_received"`
	BytesTransmitted int64 `json:"bytes_transmitted"`
	ActivePeers      int   `json:"active_peers"`
	Uptime           int64 `json:"uptime"`
}

// Enhanced Agent with WireGuard interface management and mesh capabilities
type Agent struct {
	config           *AgentConfig
	wgClient         *wgctrl.Client
	interfaceManager *wireguard.Manager
	httpClient       *http.Client
	privateKey       wgtypes.Key
	publicKey        wgtypes.Key
	startTime        time.Time

	// State
	currentConfig     *NodeConfig
	lastStats         ConnectionStats
	reconnectAttempts int
	isInterfaceUp     bool

	// Enhanced mesh components
	meshManager    *mesh.MeshManager
	natTraversal   *mesh.NATTraversal
	failoverMgr    *mesh.FailoverManager
	connectionPool *mesh.ConnectionPool
	loadBalancer   *mesh.LoadBalancer
}

// Enhanced metrics with more detailed monitoring
var (
	agentUptime = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ordinalgate_agent_uptime_seconds",
		Help: "Time the agent has been running",
	})

	connectionStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ordinalgate_agent_connection_status",
			Help: "Connection status (1 = connected, 0 = disconnected)",
		},
		[]string{"tenant_id", "node_id"},
	)

	activePeers = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ordinalgate_agent_active_peers",
			Help: "Number of active WireGuard peers",
		},
		[]string{"tenant_id", "node_id"},
	)

	bytesTransferred = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ordinalgate_agent_bytes_transferred_total",
			Help: "Total bytes transferred through WireGuard interface",
		},
		[]string{"tenant_id", "node_id", "direction"},
	)

	configUpdates = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ordinalgate_agent_config_updates_total",
			Help: "Total number of configuration updates",
		},
		[]string{"tenant_id", "node_id", "status"},
	)

	heartbeatSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ordinalgate_agent_heartbeats_sent_total",
			Help: "Total number of heartbeats sent",
		},
		[]string{"tenant_id", "node_id", "status"},
	)

	interfaceStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ordinalgate_interface_status",
			Help: "WireGuard interface status (1 = up, 0 = down)",
		},
		[]string{"interface_name"},
	)

	reconnectAttempts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ordinalgate_reconnect_attempts_total",
			Help: "Total number of reconnection attempts",
		},
		[]string{"tenant_id", "node_id"},
	)
)

func NewAgent(configPath string) (*Agent, error) {
	config, err := loadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Setup platform-specific environment
	if err := setupPlatformEnvironment(); err != nil {
		return nil, fmt.Errorf("failed to setup platform environment: %w", err)
	}

	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create WireGuard client: %w", err)
	}

	// Create WireGuard interface manager
	interfaceManager, err := wireguard.NewManager()
	if err != nil {
		return nil, fmt.Errorf("failed to create interface manager: %w", err)
	}

	// Generate or load key pair
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // FOR DEVELOPMENT ONLY
			},
		},
	}

	agent := &Agent{
		config:           config,
		wgClient:         wgClient,
		interfaceManager: interfaceManager,
		httpClient:       httpClient,
		privateKey:       privateKey,
		publicKey:        privateKey.PublicKey(),
		startTime:        time.Now(),
	}

	// Register metrics
	prometheus.MustRegister(
		agentUptime,
		connectionStatus,
		activePeers,
		bytesTransferred,
		configUpdates,
		heartbeatSent,
		interfaceStatus,
		reconnectAttempts,
	)

	return agent, nil
}

func (a *Agent) Start(ctx context.Context) error {
	log.Println("Starting OrdinalGate agent with enhanced WireGuard management")
	log.Printf("Node ID: %s", a.config.NodeID)
	log.Printf("Tenant ID: %s", a.config.TenantID)
	log.Printf("Public Key: %s", a.publicKey.String())
	log.Printf("Platform: %s", runtime.GOOS)

	// Create WireGuard interface
	if err := a.createWireGuardInterface(); err != nil {
		return fmt.Errorf("failed to create WireGuard interface: %w", err)
	}

	// Start metrics server
	if a.config.MetricsPort > 0 {
		go a.startMetricsServer()
	}

	// Register with control plane
	if err := a.register(); err != nil {
		return fmt.Errorf("failed to register: %w", err)
	}

	// Start background tasks
	go a.heartbeatLoop(ctx)
	go a.configPollLoop(ctx)
	go a.metricsUpdateLoop(ctx)
	go a.interfaceMonitorLoop(ctx)

	// Wait for context cancellation
	<-ctx.Done()

	// Cleanup
	return a.cleanup()
}

// createWireGuardInterface creates and configures the WireGuard interface
func (a *Agent) createWireGuardInterface() error {
	// Parse IP address with default if not configured
	defaultIP := "10.0.0.1/24"
	_, ipNet, err := net.ParseCIDR(defaultIP)
	if err != nil {
		return fmt.Errorf("invalid default IP: %w", err)
	}

	// Set default MTU if not configured
	mtu := a.config.MTU
	if mtu <= 0 {
		mtu = 1420 // Standard WireGuard MTU
	}

	// Create interface configuration
	interfaceConfig := &wireguard.InterfaceConfig{
		Name:       a.config.InterfaceName,
		PrivateKey: a.privateKey,
		PublicKey:  a.publicKey,
		ListenPort: a.config.ListenPort,
		IPAddress:  ipNet,
		MTU:        mtu,
		Routes:     []wireguard.Route{}, // Will be populated by control plane
	}

	// Validate configuration
	if err := wireguard.ValidateConfig(interfaceConfig); err != nil {
		return fmt.Errorf("invalid interface config: %w", err)
	}

	// Create the interface
	if err := a.interfaceManager.CreateInterface(interfaceConfig); err != nil {
		return fmt.Errorf("failed to create interface: %w", err)
	}

	a.isInterfaceUp = true
	interfaceStatus.WithLabelValues(a.config.InterfaceName).Set(1)
	log.Printf("WireGuard interface %s created successfully", a.config.InterfaceName)

	return nil
}

// cleanup performs cleanup when shutting down
func (a *Agent) cleanup() error {
	log.Println("Cleaning up agent resources...")

	// Remove WireGuard interface
	if err := a.interfaceManager.DeleteInterface(a.config.InterfaceName); err != nil {
		log.Printf("Warning: failed to delete interface: %v", err)
	}

	// Close managers
	if err := a.interfaceManager.Close(); err != nil {
		log.Printf("Warning: failed to close interface manager: %v", err)
	}

	if err := a.wgClient.Close(); err != nil {
		log.Printf("Warning: failed to close WireGuard client: %v", err)
	}

	return nil
}

func (a *Agent) register() error {
	registration := &NodeRegistration{
		Name:      a.config.NodeName,
		PublicKey: a.publicKey.String(),
		Metadata: map[string]string{
			"platform":    getPlatform(),
			"version":     "2.1.0", // Updated version
			"agent_type":  "ordinalgate-agent",
			"listen_port": fmt.Sprintf("%d", a.config.ListenPort),
			"mtu":         fmt.Sprintf("%d", a.config.MTU),
			"interface":   a.config.InterfaceName,
		},
	}

	resp, err := a.makeAPIRequest("POST", "/nodes", registration)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration failed: %d %s", resp.StatusCode, string(body))
	}

	log.Printf("Successfully registered with control plane")
	connectionStatus.WithLabelValues(a.config.TenantID, a.config.NodeID).Set(1)
	return nil
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(a.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.sendHeartbeat(); err != nil {
				log.Printf("Heartbeat failed: %v", err)
				connectionStatus.WithLabelValues(a.config.TenantID, a.config.NodeID).Set(0)
				heartbeatSent.WithLabelValues(a.config.TenantID, a.config.NodeID, "failed").Inc()

				// Attempt reconnection if enabled
				if a.config.EnableAutoReconnect {
					go a.attemptReconnection()
				}
			} else {
				connectionStatus.WithLabelValues(a.config.TenantID, a.config.NodeID).Set(1)
				heartbeatSent.WithLabelValues(a.config.TenantID, a.config.NodeID, "success").Inc()
				a.reconnectAttempts = 0 // Reset on success
			}
		}
	}
}

func (a *Agent) configPollLoop(ctx context.Context) {
	ticker := time.NewTicker(a.config.ConfigPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.fetchAndApplyConfig(); err != nil {
				log.Printf("Config update failed: %v", err)
				configUpdates.WithLabelValues(a.config.TenantID, a.config.NodeID, "failed").Inc()
			} else {
				configUpdates.WithLabelValues(a.config.TenantID, a.config.NodeID, "success").Inc()
			}
		}
	}
}

func (a *Agent) metricsUpdateLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.updateMetrics()
		}
	}
}

// interfaceMonitorLoop monitors the WireGuard interface health
func (a *Agent) interfaceMonitorLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.monitorInterface(); err != nil {
				log.Printf("Interface monitoring error: %v", err)
			}
		}
	}
}

// monitorInterface checks interface health and attempts recovery
func (a *Agent) monitorInterface() error {
	isUp, err := a.interfaceManager.IsInterfaceUp(a.config.InterfaceName)
	if err != nil {
		interfaceStatus.WithLabelValues(a.config.InterfaceName).Set(0)
		return fmt.Errorf("failed to check interface status: %w", err)
	}

	if isUp != a.isInterfaceUp {
		a.isInterfaceUp = isUp
		if isUp {
			interfaceStatus.WithLabelValues(a.config.InterfaceName).Set(1)
			log.Printf("Interface %s is up", a.config.InterfaceName)
		} else {
			interfaceStatus.WithLabelValues(a.config.InterfaceName).Set(0)
			log.Printf("Interface %s is down", a.config.InterfaceName)

			// Attempt to bring interface back up
			if a.config.EnableAutoReconnect {
				go a.recoverInterface()
			}
		}
	}

	return nil
}

// recoverInterface attempts to recover a failed interface
func (a *Agent) recoverInterface() {
	log.Printf("Attempting to recover interface %s", a.config.InterfaceName)

	if err := a.interfaceManager.BringUp(a.config.InterfaceName); err != nil {
		log.Printf("Failed to bring up interface, attempting full recreation: %v", err)

		// Try to recreate the interface
		if err := a.createWireGuardInterface(); err != nil {
			log.Printf("Failed to recreate interface: %v", err)
		} else {
			log.Printf("Interface %s recreated successfully", a.config.InterfaceName)
		}
	} else {
		log.Printf("Interface %s brought up successfully", a.config.InterfaceName)
	}
}

// attemptReconnection attempts to reconnect to the control plane
func (a *Agent) attemptReconnection() {
	if a.reconnectAttempts >= a.config.MaxReconnectAttempts {
		log.Printf("Max reconnection attempts reached (%d)", a.config.MaxReconnectAttempts)
		return
	}

	a.reconnectAttempts++
	reconnectAttempts.WithLabelValues(a.config.TenantID, a.config.NodeID).Inc()

	log.Printf("Attempting reconnection (%d/%d)", a.reconnectAttempts, a.config.MaxReconnectAttempts)

	// Wait before attempting reconnection
	time.Sleep(time.Duration(a.reconnectAttempts) * 30 * time.Second)

	if err := a.register(); err != nil {
		log.Printf("Reconnection attempt %d failed: %v", a.reconnectAttempts, err)
	} else {
		log.Printf("Reconnection successful")
		a.reconnectAttempts = 0
	}
}

func (a *Agent) sendHeartbeat() error {
	stats, err := a.getConnectionStats()
	if err != nil {
		log.Printf("Failed to get connection stats: %v", err)
		stats = ConnectionStats{} // Send empty stats on error
	}

	heartbeat := &HeartbeatData{
		Status:    "online",
		Timestamp: time.Now(),
		Stats:     stats,
		Metadata: map[string]string{
			"uptime":             fmt.Sprintf("%d", int64(time.Since(a.startTime).Seconds())),
			"interface_up":       fmt.Sprintf("%t", a.isInterfaceUp),
			"reconnect_attempts": fmt.Sprintf("%d", a.reconnectAttempts),
		},
	}

	url := fmt.Sprintf("/nodes/%s/heartbeat", a.config.NodeID)
	resp, err := a.makeAPIRequest("POST", url, heartbeat)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("heartbeat failed: %d %s", resp.StatusCode, string(body))
	}
	return nil
}

func (a *Agent) fetchAndApplyConfig() error {
	url := fmt.Sprintf("/nodes/%s/config", a.config.NodeID)
	resp, err := a.makeAPIRequest("GET", url, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("config fetch failed: %d %s", resp.StatusCode, string(body))
	}

	var config NodeConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return fmt.Errorf("failed to decode config: %w", err)
	}

	// Apply configuration
	if err := a.applyWireGuardConfig(&config); err != nil {
		return fmt.Errorf("failed to apply config: %w", err)
	}

	a.currentConfig = &config
	log.Printf("Configuration updated successfully")
	return nil
}

func (a *Agent) applyWireGuardConfig(config *NodeConfig) error {
	// Convert peers to WireGuard format
	var peers []wgtypes.PeerConfig
	for _, p := range config.Peers {
		publicKey, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			log.Printf("Invalid peer public key %s: %v", p.PublicKey, err)
			continue
		}

		var allowedIPs []net.IPNet
		for _, ip := range p.AllowedIPs {
			_, ipNet, err := net.ParseCIDR(ip)
			if err != nil {
				log.Printf("Invalid allowed IP %s: %v", ip, err)
				continue
			}
			allowedIPs = append(allowedIPs, *ipNet)
		}

		peerConfig := wgtypes.PeerConfig{
			PublicKey:  publicKey,
			AllowedIPs: allowedIPs,
		}

		if p.Endpoint != "" {
			endpoint, err := net.ResolveUDPAddr("udp", p.Endpoint)
			if err != nil {
				log.Printf("Invalid endpoint %s: %v", p.Endpoint, err)
				continue
			}
			peerConfig.Endpoint = endpoint
		}

		if p.PresharedKey != "" {
			psk, err := wgtypes.ParseKey(p.PresharedKey)
			if err != nil {
				log.Printf("Invalid preshared key: %v", err)
			} else {
				peerConfig.PresharedKey = &psk
			}
		}

		peers = append(peers, peerConfig)
	}

	// Update IP address if changed
	if config.IPAddress != "" {
		_, ipNet, err := net.ParseCIDR(config.IPAddress)
		if err != nil {
			return fmt.Errorf("invalid IP address %s: %w", config.IPAddress, err)
		}

		if err := a.interfaceManager.SetIPAddress(a.config.InterfaceName, ipNet); err != nil {
			return fmt.Errorf("failed to set IP address: %w", err)
		}
	}

	// Configure WireGuard peers
	wgConfig := wgtypes.Config{
		PrivateKey:   &a.privateKey,
		ListenPort:   &a.config.ListenPort,
		Peers:        peers,
		ReplacePeers: true,
	}

	if err := a.wgClient.ConfigureDevice(a.config.InterfaceName, wgConfig); err != nil {
		return fmt.Errorf("failed to configure WireGuard device: %w", err)
	}

	// Apply routes
	for _, routeStr := range config.Routes {
		_, ipNet, err := net.ParseCIDR(routeStr)
		if err != nil {
			log.Printf("Invalid route %s: %v", routeStr, err)
			continue
		}

		route := wireguard.Route{
			Destination: ipNet,
			// Gateway will be determined by the system
		}

		if err := a.interfaceManager.AddRoute(route); err != nil {
			log.Printf("Failed to add route %s: %v", routeStr, err)
		}
	}

	log.Printf("WireGuard interface configured with IP %s and %d peers", config.IPAddress, len(peers))
	return nil
}

func (a *Agent) getConnectionStats() (ConnectionStats, error) {
	device, err := a.wgClient.Device(a.config.InterfaceName)
	if err != nil {
		return ConnectionStats{}, err
	}

	var totalRx, totalTx int64
	activePeers := 0

	for _, peer := range device.Peers {
		totalRx += peer.ReceiveBytes
		totalTx += peer.TransmitBytes

		// Consider peer active if it has recent handshake
		if time.Since(peer.LastHandshakeTime) < 3*time.Minute {
			activePeers++
		}
	}

	return ConnectionStats{
		BytesReceived:    totalRx,
		BytesTransmitted: totalTx,
		ActivePeers:      activePeers,
		Uptime:           int64(time.Since(a.startTime).Seconds()),
	}, nil
}

func (a *Agent) updateMetrics() {
	// Update uptime
	agentUptime.Set(time.Since(a.startTime).Seconds())

	// Update connection stats
	stats, err := a.getConnectionStats()
	if err != nil {
		log.Printf("Failed to get stats for metrics: %v", err)
		return
	}

	activePeers.WithLabelValues(a.config.TenantID, a.config.NodeID).Set(float64(stats.ActivePeers))

	// Update bytes transferred (calculate delta)
	if a.lastStats.BytesReceived > 0 {
		rxDelta := stats.BytesReceived - a.lastStats.BytesReceived
		txDelta := stats.BytesTransmitted - a.lastStats.BytesTransmitted

		if rxDelta >= 0 {
			bytesTransferred.WithLabelValues(a.config.TenantID, a.config.NodeID, "rx").Add(float64(rxDelta))
		}
		if txDelta >= 0 {
			bytesTransferred.WithLabelValues(a.config.TenantID, a.config.NodeID, "tx").Add(float64(txDelta))
		}
	}

	a.lastStats = stats

	// Update interface status
	if isUp, err := a.interfaceManager.IsInterfaceUp(a.config.InterfaceName); err == nil {
		if isUp {
			interfaceStatus.WithLabelValues(a.config.InterfaceName).Set(1)
		} else {
			interfaceStatus.WithLabelValues(a.config.InterfaceName).Set(0)
		}
	}
}

func (a *Agent) makeAPIRequest(method, path string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	url := a.config.ControlPlaneURL + "/api/v1" + path
	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.config.AuthToken)
	req.Header.Set("User-Agent", "ordinalgate-agent/2.1.0")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

func (a *Agent) startMetricsServer() {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":             "healthy",
			"uptime":             time.Since(a.startTime).Seconds(),
			"node_id":            a.config.NodeID,
			"tenant_id":          a.config.TenantID,
			"interface_up":       a.isInterfaceUp,
			"reconnect_attempts": a.reconnectAttempts,
		})
	})

	addr := fmt.Sprintf(":%d", a.config.MetricsPort)
	log.Printf("Starting metrics server on %s", addr)

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Printf("Metrics server error: %v", err)
	}
}

func loadConfig(configPath string) (*AgentConfig, error) {
	// Default configuration with enhanced settings
	config := &AgentConfig{
		ControlPlaneURL:      "https://localhost:8080",
		NodeID:               generateNodeID(),
		NodeName:             getHostname(),
		InterfaceName:        "wg-ordinalgate",
		ListenPort:           51820,
		MetricsPort:          9101,
		HeartbeatInterval:    30 * time.Second,
		ConfigPollInterval:   60 * time.Second,
		MTU:                  1420,
		EnableAutoReconnect:  true,
		MaxReconnectAttempts: 5,
	}

	// Load from environment variables
	if url := os.Getenv("ORDINALGATE_CONTROL_PLANE_URL"); url != "" {
		config.ControlPlaneURL = url
	}
	if nodeID := os.Getenv("ORDINALGATE_NODE_ID"); nodeID != "" {
		config.NodeID = nodeID
	}
	if nodeName := os.Getenv("ORDINALGATE_NODE_NAME"); nodeName != "" {
		config.NodeName = nodeName
	}
	if tenantID := os.Getenv("ORDINALGATE_TENANT_ID"); tenantID != "" {
		config.TenantID = tenantID
	}
	if token := os.Getenv("ORDINALGATE_AUTH_TOKEN"); token != "" {
		config.AuthToken = token
	}
	if iface := os.Getenv("ORDINALGATE_INTERFACE"); iface != "" {
		config.InterfaceName = iface
	}

	// Load from file if it exists
	if configPath != "" && fileExists(configPath) {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		var fileConfig AgentConfig
		if err := json.Unmarshal(data, &fileConfig); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}

		// Merge configurations
		mergeConfigs(config, &fileConfig)
	}

	// Validation
	if config.TenantID == "" {
		return nil, fmt.Errorf("tenant ID is required")
	}
	if config.AuthToken == "" {
		return nil, fmt.Errorf("auth token is required")
	}

	return config, nil
}

func mergeConfigs(base, override *AgentConfig) {
	if override.ControlPlaneURL != "" {
		base.ControlPlaneURL = override.ControlPlaneURL
	}
	if override.NodeID != "" {
		base.NodeID = override.NodeID
	}
	if override.NodeName != "" {
		base.NodeName = override.NodeName
	}
	if override.TenantID != "" {
		base.TenantID = override.TenantID
	}
	if override.AuthToken != "" {
		base.AuthToken = override.AuthToken
	}
	if override.InterfaceName != "" {
		base.InterfaceName = override.InterfaceName
	}
	if override.ListenPort > 0 {
		base.ListenPort = override.ListenPort
	}
	if override.MetricsPort > 0 {
		base.MetricsPort = override.MetricsPort
	}
	if override.HeartbeatInterval > 0 {
		base.HeartbeatInterval = override.HeartbeatInterval
	}
	if override.ConfigPollInterval > 0 {
		base.ConfigPollInterval = override.ConfigPollInterval
	}
	if override.MTU > 0 {
		base.MTU = override.MTU
	}
	if override.MaxReconnectAttempts > 0 {
		base.MaxReconnectAttempts = override.MaxReconnectAttempts
	}
	// EnableAutoReconnect is a bool, so we need to check if it's set
	base.EnableAutoReconnect = override.EnableAutoReconnect
}

// Utility functions
func generateNodeID() string {
	hostname := getHostname()
	timestamp := time.Now().Unix()
	return fmt.Sprintf("%s-%d", hostname, timestamp)
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown-host"
	}
	return hostname
}

func getPlatform() string {
	return fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func main() {
	configPath := ""
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	agent, err := NewAgent(configPath)
	if err != nil {
		log.Fatal("Failed to create agent:", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		log.Println("Shutting down agent...")
		cancel()
	}()

	if err := agent.Start(ctx); err != nil {
		log.Fatal("Agent failed:", err)
	}
}
