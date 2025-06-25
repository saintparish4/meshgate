package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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

const (
	dbFile   = "meshgate.db"
	cidrBase = "10.42.0."
)

var (
	db *bolt.DB
	mu sync.Mutex
)

func main() {
	var err error
	db, err = bolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	db.Update(func(tx *bolt.Tx) error { _, _ = tx.CreateBucketIfNotExists([]byte("nodes")); return nil })

	http.HandleFunc("/register", handleRegister)         // POST
	http.HandleFunc("/config/", handleConfig)            // GET /config/{nodeID}
	http.HandleFunc("/heartbeat/", handleHeartbeat)      // POST /heartbeat/{nodeID}

	log.Println("control-plane listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// ---------- handlers ---------------------------------------------------------

func handleRegister(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PublicKey string `json:"publicKey"`
	}
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
		nextIP := 2 + b.Stats().KeyN // .2, .3, .4, ...
		node.IP = fmt.Sprintf("%s%d/32", cidrBase, nextIP)
		buf, _ := json.Marshal(node)
		return b.Put([]byte(node.ID), buf)
	})
	mu.Unlock()
	if err != nil { http.Error(w, err.Error(), 500); return }

	json.NewEncoder(w).Encode(node)
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/config/")

	var self Node
	var all []Node
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

	cfg := Config{
		InterfaceAddress: self.IP,
		ListenPort:       51820,
	}
	for _, peer := range all {
		if peer.ID == self.ID { continue }
		cfg.Peers = append(cfg.Peers, Peer{
			PublicKey:  peer.PublicKey,
			Endpoint:   "",                     // can be filled later
			AllowedIPs: []string{peer.IP},
		})
	}
	json.NewEncoder(w).Encode(cfg)
}

func handleHeartbeat(w http.ResponseWriter, r *http.Request) {
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
