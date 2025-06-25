package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	"github.com/google/uuid"
)

type Node struct {
	ID        string `json:"id"`
	PublicKey string `json:"publicKey"`
	IP        string `json:"ip"`
	LastSeen  int64  `json:"lastSeen"`
}

type Peer struct {
	PublicKey  string   `json:"publicKey"`
	Endpoint   string   `json:"endpoint"`
	AllowedIPs []string `json:"allowedIPs"`
}

type Config struct {
	InterfaceAddress string `json:"interfaceAddress"`
	ListenPort       int    `json:"listenPort"`
	Peers            []Peer `json:"peers"`
}

const dbFile = "meshgate.db"

var (
	db          *bolt.DB
	mu          sync.Mutex
	sharedToken string
)

func main() {
	// one shared secret for now (env var CP_SHARED_TOKEN or default)
	sharedToken = os.Getenv("CP_SHARED_TOKEN")
	if sharedToken == "" {
		sharedToken = "meshgate-secret"
	}

	var err error
	db, err = bolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	db.Update(func(tx *bolt.Tx) error { _, _ = tx.CreateBucketIfNotExists([]byte("nodes")); return nil })

	http.HandleFunc("/register", handleRegister)
	http.HandleFunc("/config/", handleConfig)     // GET /config/{nodeID}
	http.HandleFunc("/heartbeat/", handleHB)     // POST /heartbeat/{nodeID}

	log.Println("control-plane listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// ------------------------------------------------------------------ helpers --

func authorised(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") != "Bearer "+sharedToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

// stable /16 allocator: 10.42.X.Y, skipping .0.* & .1.*
func allocateIP(n uint64) string {
	idx := n + 2 // reserve .0 & .1 blocks
	octet3 := idx / 254
	octet4 := idx % 254
	return fmt.Sprintf("10.42.%d.%d/32", octet3, octet4)
}

// ------------------------------------------------------------- HTTP handlers --

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if !authorised(w, r) { return }

	var in struct{ PublicKey string `json:"publicKey"` }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		http.Error(w, err.Error(), 400); return
	}

	node := Node{
		ID:        uuid.NewString(),
		PublicKey: in.PublicKey,
		LastSeen:  time.Now().Unix(),
	}

	mu.Lock()
	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		node.IP = allocateIP(uint64(b.Stats().KeyN))
		buf, _ := json.Marshal(node)
		return b.Put([]byte(node.ID), buf)
	})
	mu.Unlock()
	if err != nil { http.Error(w, err.Error(), 500); return }

	json.NewEncoder(w).Encode(node)
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	if !authorised(w, r) { return }

	id := strings.TrimPrefix(r.URL.Path, "/config/")

	var self Node
	var all  []Node
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		_ = b.ForEach(func(k, v []byte) error {
			var n Node
			if err := json.Unmarshal(v, &n); err == nil {
				all = append(all, n)
				if string(k) == id { self = n }
			}
			return nil
		})
		return nil
	})
	if self.ID == "" { http.NotFound(w, r); return }

	cfg := Config{InterfaceAddress: self.IP, ListenPort: 51820}
	for _, p := range all {
		if p.ID == self.ID { continue }
		cfg.Peers = append(cfg.Peers, Peer{
			PublicKey:  p.PublicKey,
			AllowedIPs: []string{p.IP},
		})
	}
	json.NewEncoder(w).Encode(cfg)
}

func handleHB(w http.ResponseWriter, r *http.Request) {
	if !authorised(w, r) { return }

	id := strings.TrimPrefix(r.URL.Path, "/heartbeat/")
	_ = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		v := b.Get([]byte(id))
		if v == nil { return nil }
		var n Node
		if err := json.Unmarshal(v, &n); err != nil { return err }
		n.LastSeen = time.Now().Unix()
		buf, _ := json.Marshal(n)
		return b.Put([]byte(id), buf)
	})
	w.WriteHeader(http.StatusOK)
}
