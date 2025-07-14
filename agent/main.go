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
)

// Configuration
type AgentConfig struct {
	ControlPlaneURL    string        `json:"control_plane_url"`
	NodeID             string        `json:"node_id"`
	NodeName           string        `json:"node_name"`
	TenantID           string        `json:"tenant_id"`
	AuthToken          string        `json:"auth_token"`
	InterfaceName      string        `json:"interface_name"`
	ListenPort         int           `json:"listen_port"`
	MetricsPort        int           `json:"metrics_port"`
	HeartbeatInterval  time.Duration `json:"heartbeat_interval"`
	ConfigPollInterval time.Duration `json:"config_poll_interval"`
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

type Route struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
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

// Metrics
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
)

// Agent
type Agent struct {
	config     *AgentConfig
	wgClient   *wgctrl.Client
	httpClient *http.Client
	privateKey wgtypes.Key
	publicKey  wgtypes.Key
	startTime  time.Time

	// State
	currentConfig *NodeConfig
	lastStats     ConnectionStats
}

func NewAgent(configPath string) (*Agent, error) {
	config, err := loadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create WireGuard client: %w", err)
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
				InsecureSkipVerify: true, // FOR DEVELOPMENT ONLY !!!!
			},
		},
	}

	agent := &Agent{
		config:     config,
		wgClient:   wgClient,
		httpClient: httpClient,
		privateKey: privateKey,
		publicKey:  privateKey.PublicKey(),
		startTime:  time.Now(),
	}

	// Register metrics
	prometheus.MustRegister(
		agentUptime,
		connectionStatus,
		activePeers,
		bytesTransferred,
		configUpdates,
		heartbeatSent,
	)
	return agent, nil
}

func (a *Agent) Start(ctx context.Context) error {
	log.Println("Starting OrdinalGate agent")
	log.Printf("Node ID: %s", a.config.NodeID)
	log.Printf("Tenant ID: %s", a.config.TenantID)
	log.Printf("Public Key: %s", a.publicKey.String())

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

	// Wait for context cancellation
	<-ctx.Done()
	return nil
}

func (a *Agent) register() error {
	registration := &NodeRegistration{
		Name:      a.config.NodeName,
		PublicKey: a.publicKey.String(),
		Metadata: map[string]string{
			"platform":    getPlatform(),
			"version":     "2.0.0",
			"agent_type":  "ordinalgate-agent",
			"listen_port": fmt.Sprintf("%d", a.config.ListenPort),
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
			} else {
				connectionStatus.WithLabelValues(a.config.TenantID, a.config.NodeID).Set(1)
				heartbeatSent.WithLabelValues(a.config.TenantID, a.config.NodeID, "success").Inc()
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
			"uptime": fmt.Sprintf("%d", time.Since(a.startTime).Seconds()),
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
	// Convert peers
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

	// Parse IP address
	_, ipNet, err := net.ParseCIDR(config.IPAddress)
	if err != nil {
		return fmt.Errorf("invalid IP address %s: %w", config.IPAddress, err)
	}

	// Configure WireGuard interface
	wgConfig := wgtypes.Config{
		PrivateKey:   &a.privateKey,
		ListenPort:   &a.config.ListenPort,
		Peers:        peers,
		ReplacePeers: true,
	}

	// Try to configure existing interface, create if it doesn't exist
	err = a.wgClient.ConfigureDevice(a.config.InterfaceName, wgConfig)
	if err != nil {
		log.Printf("Failed to configure existing interface, will try to create new one: %v", err)
		// Interface doesn't exist, this is expected on first run
		// The interface creation should be handled by the OS-specific implementation
	}

	// Configure IP address (OS-specific)
	if err := a.configureInterface(ipNet); err != nil {
		return fmt.Errorf("failed to configure interface IP: %w", err)
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
	req.Header.Set("User-Agent", "meshgate-agent/2.0.0")

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
			"status":    "healthy",
			"uptime":    time.Since(a.startTime).Seconds(),
			"node_id":   a.config.NodeID,
			"tenant_id": a.config.TenantID,
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

// OS-specific interface configuration
func (a *Agent) configureInterface(ipNet *net.IPNet) error {
	// This is a simplified version - in production, you'd have OS-specific implementations
	// For Linux: use netlink
	// For Windows: use WinTun or similar

	log.Printf("Interface configuration not implemented for this platform")
	log.Printf("Please manually configure interface %s with IP %s", a.config.InterfaceName, ipNet.String())
	return nil
}

func loadConfig(configPath string) (*AgentConfig, error) {
	// Default configuration
	config := &AgentConfig{
		ControlPlaneURL:    "https://localhost:8080",
		NodeID:             generateNodeID(),
		NodeName:           getHostname(),
		InterfaceName:      "wg-meshgate",
		ListenPort:         51820,
		MetricsPort:        9101,
		HeartbeatInterval:  30 * time.Second,
		ConfigPollInterval: 60 * time.Second,
	}

	// Load from environment variables
	if url := os.Getenv("MESHGATE_CONTROL_PLANE_URL"); url != "" {
		config.ControlPlaneURL = url
	}
	if nodeID := os.Getenv("MESHGATE_NODE_ID"); nodeID != "" {
		config.NodeID = nodeID
	}
	if nodeName := os.Getenv("MESHGATE_NODE_NAME"); nodeName != "" {
		config.NodeName = nodeName
	}
	if tenantID := os.Getenv("MESHGATE_TENANT_ID"); tenantID != "" {
		config.TenantID = tenantID
	}
	if token := os.Getenv("MESHGATE_AUTH_TOKEN"); token != "" {
		config.AuthToken = token
	}
	if iface := os.Getenv("MESHGATE_INTERFACE"); iface != "" {
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

		// Merge file config with defaults (file takes precedence)
		if fileConfig.ControlPlaneURL != "" {
			config.ControlPlaneURL = fileConfig.ControlPlaneURL
		}
		if fileConfig.NodeID != "" {
			config.NodeID = fileConfig.NodeID
		}
		if fileConfig.NodeName != "" {
			config.NodeName = fileConfig.NodeName
		}
		if fileConfig.TenantID != "" {
			config.TenantID = fileConfig.TenantID
		}
		if fileConfig.AuthToken != "" {
			config.AuthToken = fileConfig.AuthToken
		}
		if fileConfig.InterfaceName != "" {
			config.InterfaceName = fileConfig.InterfaceName
		}
		if fileConfig.ListenPort > 0 {
			config.ListenPort = fileConfig.ListenPort
		}
		if fileConfig.MetricsPort > 0 {
			config.MetricsPort = fileConfig.MetricsPort
		}
		if fileConfig.HeartbeatInterval > 0 {
			config.HeartbeatInterval = fileConfig.HeartbeatInterval
		}
		if fileConfig.ConfigPollInterval > 0 {
			config.ConfigPollInterval = fileConfig.ConfigPollInterval
		}
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

// Utility functions
func generateNodeID() string {
	// Generate a unique node ID based on hostname and timestamp
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
