package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Configuration constants
const (
	defaultKeyPath = "/etc/wireguard/meshgate.key"
	defaultInterface = "wg0"
	heartbeatInterval = 30 * time.Second
	configPollInterval = 60 * time.Second
	httpTimeout = 10 * time.Second
	maxRetries = 3
	retryDelay = 5 * time.Second
)

// Data Structures
type Peer struct {
	PublicKey string `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
	Endpoint string `json:"endpoint"`
}

type Config struct {
	InterfaceAddress string `json:"interface_address"`
	ListenPort int `json:"listen_port"`
	Peers []Peer `json:"peers"`
}

type Node struct {
	ID string `json:"id"`
	IP string `json:"ip"`
}

// Client wraps HTTP operations with proper error handling and retries
type Client struct {
	baseURL string
	token string
	httpClient *http.Client
}

// MeshGate represents the main application
type MeshGate struct {
	client *Client
	keyPath string
	interfaceName string
	privateKey string
	publicKey string
	node Node
	currentConfig Config
	mu sync.RWMutex
	ctx context.Context
	cancel context.CancelFunc
	wg sync.WaitGroup
}

// NewClient creates a new HTTP client
func NewClient() *Client {
	return &Client{
		baseURL: getControlPlaneURL(),
		token: getNodeToken(),
		httpClient: &http.Client{
			Timeout: httpTimeout,
		},
	}
}

// Enviroment Helpers
func getControlPlaneURL() string {
	if u := os.Getenv("CONTROL_PLANE_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://localhost:8080"
}

func getNodeToken() string {
	if t := os.Getenv("NODE_TOKEN"); t != "" {
		return t 
	}
	return "meshgate-secret"
}

// KEY MANAGEMENT
func generateKeyPair() (private, public string, err error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate key pair: %w", err)
	}
	return key.String(), key.PublicKey().String(), nil
}

func (mg *MeshGate) ensureKeys() error {
	// Tryr to read exisiting key
	if data, err := os.ReadFile(mg.keyPath); err == nil {
		privateKey := strings.TrimSpace(string(data))
		key, err := wgtypes.ParseKey(privateKey)
		if err != nil {
			return fmt.Errorf("failed to parse existing key: %w", err)
		}
		mg.privateKey = privateKey
		mg.publicKey = key.PublicKey().String()
		return nil
	}

	// Generate new key pair
	private, public, err := generateKeyPair()
	if err != nil {
		return err
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(mg.keyPath), 0700); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	// Write new key to file
	if err := os.WriteFile(mg.keyPath, []byte(private+"\n"), 0600); err != nil {
		return fmt.Errorf("failed to write key to file: %w", err)
	}

	mg.privateKey = private
	mg.publicKey = public
	return nil
}

// HTTP CLIENT METHODS WITH RETRY LOGIC
func (c *Client) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+c.token)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			if i < maxRetries - 1 {
				select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-time.After(retryDelay):
						continue
				}
			}
			continue
		}
        
		// Check for HTTP errors
		if resp.StatusCode >= 400 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
			if i < maxRetries - 1 && resp.StatusCode >= 500 {
				select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-time.After(retryDelay):
						continue
				}
			} 
		continue
	}
	return resp, nil
}
return nil, fmt.Errorf("max retries exceeded: %w", lastErr
}

// CONTROL PLANE OPERATIONS
func (mg *MeshGate) register(ctx context.Context) error {
	payload := map[string]string{"publicKey": mg.publicKey}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	resp, err := mg.client.do(ctx, "POST", "/register", body)
	if err != nil {
		return fmt.Errorf("failed to register node: %w", err)
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&mg.node); err != nil {
		return fmt.Errorf("failed to decode node response: %w", err)
	}

	log.Printf("Registered successfully: id=%s, ip=%s", mg.node.ID, mg.node.IP)
	return nil
}

func (mg *MeshGate) fetchConfig(ctx context.Context) (Config, error) {
	resp, err := mg.client.do(ctx, "GET", "/config/"+mg.node.ID, nil)
	if err != nil {
		return Config{}, fmt.Errorf("Failed to decode config response: %w", err)
	}
	return config, nil
}

func (mg *MeshGate) sendHeartbeat(ctx context.Context) error {
	_, err := mg.client.do(ctx, "POST", "/heartbeat/"+mg.node.ID, nil)
	if err != nil {
		return fmt.Errorf("heartbeat failed: %w", err)
	}
	return nil
}

// WireGuard Interface Management
func (mg *MeshGate) createInterface() error {
	// Check if interface already exists
	if err := exec.Command("ip", "link", "show", mg.interfaceName).Run(); err == nil {
		log.Printf("Interface %s already exists, removing it first", mg.interfaceName)
		if err := mg.removeInterface(); err != nil {
			return fmt.Errorf("failed to remove existing interface: %w", err)
		}
	}

	if err := exec.Command("ip", "link", "add", mg.interfaceName, "type", "wireguard").Run(); err != nil {
		return fmt.Errorf("failed to create interface: %w", err)
	}

	return nil
}

func (mg *MeshGate) removeInterface() error {
	if err := exec.Command("ip", "link", "delete", mg.interfaceName).Run(); err != nil {
		return fmt.Errorf("failed to remove interface: %w", err)
	}
	return nil
}

func (mg *MeshGate) applyConfig(config Config) error {
	mg.mu.Lock()
	defer mg.mu.Unlock()

	// Create interface if it doesn't exist
	if err := mg.createInterface(); err != nil {
		return err
	}

	// Set interface address
	if err := exec.Command("ip", "addr", "replace", config.InterfaceAddress, "dev", mg.interfaceName).Run(); err != nil {
		return fmt.Errorf("failed to set interface address: %w", err)
	}

	// Configure WireGuard
	wgArgs := []string{"set", mg.interfaceName, "listen-port", fmt.Sprint(config.ListenPort), "private-key", mg.keyPath}
	if err := exec.Command("wg", wgArgs...).Run(); err != nil {
		return fmt.Errorf("failed to configure WireGuard: %w", err)
	}

	// Add peers
	for _, peer := range config.Peers {
		peerArgs := []string{"set", mg.interfaceName, "peer", peer.PublicKey}
		if len(peer.AllowedIPs) > 0 {
			peerArgs = append(peerArgs, "allowed-ips", strings.Join(peer.AllowedIPs, ","))
		}
		if peer.Endpoint != "" {
			peerArgs = append(peerArgs, "endpoint", peer.Endpoint)
		}
		
		if err := exec.Command("wg", peerArgs...).Run(); err != nil {
			return fmt.Errorf("failed to add peer %s: %w", peer.PublicKey, err)
		}
	}

	// Bring interface up
	if err := exec.Command("ip", "link", "set", "up", mg.interfaceName).Run(); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	mg.currentConfig = config
	log.Printf("Applied configuration: %d peers, listen port %d", len(config.Peers), config.ListenPort)
	return nil
}

// Background workers
func (mg *MeshGate) heartbeatWorker() {
	defer mg.wg.Done()
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-mg.ctx.Done():
			return
		case <-ticker.C:
			if err := mg.sendHeartbeat(mg.ctx); err != nil {
				log.Printf("Heartbeat failed: %v", err)
			}
		}
	}
}

func (mg *MeshGate) configWatcher() {
	defer mg.wg.Done()
	ticker := time.NewTicker(configPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-mg.ctx.Done():
			return
		case <-ticker.C:
			config, err := mg.fetchConfig(mg.ctx)
			if err != nil {
				log.Printf("Failed to fetch config: %v", err)
				continue
			}

			// Check if config has changed
			mg.mu.RLock()
			configChanged := !mg.configEqual(mg.currentConfig, config)
			mg.mu.RUnlock()

			if configChanged {
				log.Printf("Configuration changed, applying updates...")
				if err := mg.applyConfig(config); err != nil {
					log.Printf("Failed to apply config: %v", err)
				}
			}
		}
	}
}

// Helper to compare configs
func (mg *MeshGate) configEqual(a, b Config) bool {
	if a.InterfaceAddress != b.InterfaceAddress || a.ListenPort != b.ListenPort || len(a.Peers) != len(b.Peers) {
		return false
	}

	for i, peer := range a.Peers {
		if i >= len(b.Peers) || peer.PublicKey != b.Peers[i].PublicKey {
			return false
		}
		if len(peer.AllowedIPs) != len(b.Peers[i].AllowedIPs) {
			return false
		}
		for j, ip := range peer.AllowedIPs {
			if j >= len(b.Peers[i].AllowedIPs) || ip != b.Peers[i].AllowedIPs[j] {
				return false
			}
		}
	}
	return true
}

// Cleanup
func (mg *MeshGate) cleanup() {
	log.Println("Cleaning up...")
	if err := mg.removeInterface(); err != nil {
		log.Printf("Failed to remove interface during cleanup: %v", err)
	}
}

// Initialize and run
func NewMeshGate() *MeshGate {
	ctx, cancel := context.WithCancel(context.Background())
	return &MeshGate{
		client:        NewClient(),
		keyPath:       defaultKeyPath,
		interfaceName: defaultInterface,
		ctx:           ctx,
		cancel:        cancel,
	}
}

func (mg *MeshGate) Run() error {
	// Ensure keys exist
	if err := mg.ensureKeys(); err != nil {
		return fmt.Errorf("failed to ensure keys: %w", err)
	}

	// Register with control plane
	if err := mg.register(mg.ctx); err != nil {
		return fmt.Errorf("failed to register: %w", err)
	}

	// Fetch initial configuration
	config, err := mg.fetchConfig(mg.ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch initial config: %w", err)
	}

	// Apply initial configuration
	if err := mg.applyConfig(config); err != nil {
		return fmt.Errorf("failed to apply initial config: %w", err)
	}

	// Start background workers
	mg.wg.Add(2)
	go mg.heartbeatWorker()
	go mg.configWatcher()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigChan:
		log.Println("Received shutdown signal")
	case <-mg.ctx.Done():
		log.Println("Context cancelled")
	}

	// Shutdown gracefully
	mg.cancel()
	mg.wg.Wait()
	mg.cleanup()

	return nil
}

func main() {
	meshgate := NewMeshGate()
	if err := meshgate.Run(); err != nil {
		log.Fatalf("MeshGate failed: %v", err)
	}
}

