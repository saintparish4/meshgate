package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

type Node struct {
	ID           string `json:"id"`
	PublicKey    string `json:"public_key"`
	IP           string `json:"ip"`
	Endpoint     string `json:"endpoint,omitempty"`
	LastSeen     int64  `json:"last_seen"`
	RegisteredAt int64  `json:"registered_at"`
}

type Peer struct {
	PublicKey  string   `json:"public_key"`
	Endpoint   string   `json:"endpoint,omitempty"`
	AllowedIPs []string `json:"allowed_ips"`
}

type Config struct {
	InterfaceAddress string `json:"interface_address"`
	ListenPort       int    `json:"listen_port"`
	Peers            []Peer `json:"peers"`
}

type RegisterRequest struct {
	PublicKey string `json:"publicKey"`
	Endpoint  string `json:"endpoint,omitempty"`
}

type RegisterResponse struct {
	NodeID string `json:"id"`
	IP     string `json:"ip"`
}

type HeartbeatRequest struct {
	Endpoint string `json:"endpoint,omitempty"`
}

const (
	dbFile          = "meshgate.db"
	defaultSubnet   = "10.10.10.0/24"
	nodeTimeout     = 5 * time.Minute
	cleanupInterval = 1 * time.Minute
)

var (
	db        *bolt.DB
	mu        sync.RWMutex
	policy    map[string][]string
	ipPool    *IPPool
	authToken string
)

type IPPool struct {
	subnet   *net.IPNet
	baseIP   net.IP
	assigned map[string]bool
	mu       sync.Mutex
}

func NewIPPool(cidr string) (*IPPool, error) {
	ip, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	return &IPPool{
		subnet:   subnet,
		baseIP:   ip,
		assigned: make(map[string]bool),
	}, nil
}

func (p *IPPool) AllocateIP() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Start from .1 and skip .0 (network) and .255 (broadcast)
	for i := 1; i < 254; i++ {
		ip := net.IPv4(
			p.baseIP[0],
			p.baseIP[1],
			p.baseIP[2],
			byte(i),
		)
		ipStr := ip.String()

		if !p.assigned[ipStr] {
			p.assigned[ipStr] = true
			return ipStr + "/24", nil
		}
	}
	return "", fmt.Errorf("no available IP addresses")
}

func (p *IPPool) ReleaseIP(ipStr string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Remove CIDR suffix is present
	if strings.Contains(ipStr, "/") {
		ipStr = strings.Split(ipStr, "/")[0]
	}

	delete(p.assigned, ipStr)
}

func (p *IPPool) LoadAssignedIPs(db *bolt.DB) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		if b == nil {
			return nil
		}

		return b.ForEach(func(k, v []byte) error {
			var node Node
			if err := json.Unmarshal(v, &node); err != nil {
				return err
			}

			// Extract IP without CIDR
			ip := strings.Split(node.IP, "/")[0]
			p.assigned[ip] = true
			return nil
		})
	})
}

func generateNodeID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func main() {
	// Load Authenication Token
	authToken = os.Getenv("NODE_TOKEN")
	if authToken == "" {
		log.Fatal("NODE_TOKEN environment variable is required")
	}

	// Load Policy
	policyPath := os.Getenv("POLICY_PATH")
	if policyPath == "" {
		policyPath = "config/policy.json"
	}
	if err := loadPolicy(policyPath); err != nil {
		log.Fatalf("Failed to load policy: %v", err)
	}

	// Initialize IP Pool
	subnet := os.Getenv("SUBNET")
	if subnet == "" {
		subnet = defaultSubnet
	}

	var err error
	ipPool, err = NewIPPool(subnet)
	if err != nil {
		log.Fatalf("Failed to create IP pool: %v", err)
	}

	// Open DATABASE
	db, err = bolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Initialize database buckets
	db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("nodes"))
		return err
	})

	// Load exisiting IP assignments
	if err := ipPool.LoadAssignedIPs(db); err != nil {
		log.Printf("WARNING: Failed to load existing IP assignments: %v", err)
	}

	// Start cleanup goroutine
	go cleanupStaleNodes()

	// Setup HTTP Routes
	http.HandleFunc("/register", authMiddleware(handleRegister))
	http.HandleFunc("/config/", authMiddleware(handleConfig))
	http.HandleFunc("/heartbeat/", authMiddleware(handleHeartbeat))
	http.HandleFunc("/nodes", authMiddleware(handleNodes))
	http.HandleFunc("/health", handleHealth)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("MeshGate Control-Plane listening on :%s with policy enforcement", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func authMiddleware(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token != "Bearer "+authToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		handler(w, r)
	}
}

func loadPolicy(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		//Create default policy if file doesn't exist
		policy = make(map[string][]string)
		log.Printf("warning: policy file not found, using default allow-all policy")
		return nil
	}
	return json.Unmarshal(data, &policy)
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.PublicKey == "" {
		http.Error(w, "public key is required", http.StatusBadRequest)
		return
	}

	// Check if node already exists
	var existingNode Node
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		return b.ForEach(func(k, v []byte) error {
			var n Node
			if err := json.Unmarshal(v, &n); err == nil && n.PublicKey == req.PublicKey {
				existingNode = n
			}
			return nil
		})
	})

	if existingNode.ID != "" {
		// Update existing node
		existingNode.LastSeen = time.Now().Unix()
		existingNode.Endpoint = req.Endpoint

		data, _ := json.Marshal(existingNode)
		db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("nodes"))
			return b.Put([]byte(existingNode.ID), data)
		})

		json.NewEncoder(w).Encode(RegisterResponse{
			NodeID: existingNode.ID,
			IP:     existingNode.IP,
		})
		return
	}

	// Create new Node
	nodeID := generateNodeID()
	assignedIP, err := ipPool.AllocateIP()
	if err != nil {
		http.Error(w, "failed to allocate IP", http.StatusInternalServerError)
		return
	}

	node := Node{
		ID:           nodeID,
		PublicKey:    req.PublicKey,
		IP:           assignedIP,
		Endpoint:     req.Endpoint,
		LastSeen:     time.Now().Unix(),
		RegisteredAt: time.Now().Unix(),
	}

	data, _ := json.Marshal(node)
	if err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		return b.Put([]byte(nodeID), data)
	}); err != nil {
		ipPool.ReleaseIP(assignedIP)
		http.Error(w, "failed to save node", http.StatusInternalServerError)
		return
	}

	log.Printf("Registered new node: %s (%s)", node.ID, assignedIP)
	json.NewEncoder(w).Encode(RegisterResponse{
		NodeID: nodeID,
		IP:     assignedIP,
	})
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	nodeID := strings.TrimPrefix(r.URL.Path, "/config/")
	if nodeID == "" {
		http.Error(w, "node ID is required", http.StatusBadRequest)
		return
	}

	mu.RLock()
	defer mu.RUnlock()

	var self Node
	var allNodes []Node

	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		return b.ForEach(func(k, v []byte) error {
			var n Node
			if err := json.Unmarshal(v, &n); err == nil {
				// Only include active nodes
				if time.Now().Unix()-n.LastSeen < int64(nodeTimeout.Seconds()) {
					allNodes = append(allNodes, n)
					if string(k) == nodeID {
						self = n
					}
				}
			}
			return nil
		})
	})

	if self.ID == "" {
		http.Error(w, "node not found", http.StatusNotFound)
		return
	}

	// Apply policy
	allowed := policy[self.PublicKey]
	allowedAll := len(allowed) == 0

	var cfg Config
	cfg.InterfaceAddress = self.IP
	cfg.ListenPort = 51820

	for _, peer := range allNodes {
		if peer.ID == self.ID {
			continue
		}

		if allowedAll || contains(allowed, peer.PublicKey) {
			cfg.Peers = append(cfg.Peers, Peer{
				PublicKey:  peer.PublicKey,
				Endpoint:   peer.Endpoint,
				AllowedIPs: []string{strings.Split(peer.IP, "/")[0] + "/32"},
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cfg)
}

func handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	nodeID := strings.TrimPrefix(r.URL.Path, "/heartbeat/")
	if nodeID == "" {
		http.Error(w, "node ID is required", http.StatusBadRequest)
		return
	}

	var req HeartbeatRequest
	json.NewDecoder(r.Body).Decode(&req)

	var node Node
	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		data := b.Get([]byte(nodeID))
		if data == nil {
			return fmt.Errorf("node not found")
		}

		if err := json.Unmarshal(data, &node); err != nil {
			return err
		}

		node.LastSeen = time.Now().Unix()
		if req.Endpoint != "" {
			node.Endpoint = req.Endpoint
		}

		updatedData, _ := json.Marshal(node)
		return b.Put([]byte(nodeID), updatedData)
	})

	if err != nil {
		http.Error(w, "node not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleNodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var nodes []Node
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		return b.ForEach(func(k, v []byte) error {
			var n Node
			if err := json.Unmarshal(v, &n); err == nil {
				nodes = append(nodes, n)
			}
			return nil
		})
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(nodes)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func cleanupStaleNodes() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		mu.Lock()
		var staleNodeIDs []string

		db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte("nodes"))
			return b.ForEach(func(k, v []byte) error {
				var n Node
				if err := json.Unmarshal(v, &n); err == nil {
					if time.Now().Unix()-n.LastSeen > int64(nodeTimeout.Seconds()) {
						staleNodeIDs = append(staleNodeIDs, string(k))
					}
				}
				return nil
			})
		})

		for _, nodeID := range staleNodeIDs {
			var node Node
			db.View(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte("nodes"))
				data := b.Get([]byte(nodeID))
				if data != nil {
					json.Unmarshal(data, &node)
				}
				return nil
			})

			db.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte("nodes"))
				return b.Delete([]byte(nodeID))
			})

			if node.IP != "" {
				ipPool.ReleaseIP(node.IP)
			}

			log.Printf("cleaned up stale node: %s", nodeID)
		}
		mu.Unlock()
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
