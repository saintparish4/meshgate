package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	bolt "go.etcd.io/bbolt"
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
	db     *bolt.DB
	mu     sync.Mutex
	policy map[string][]string
)

func main() {
	if err := loadPolicy("../config/policy.json"); err != nil {
		log.Fatalf("failed to load policy: %v", err)
	}

	var err error
	db, err = bolt.Open(dbFile, 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	db.Update(func(tx *bolt.Tx) error {
		_, _ = tx.CreateBucketIfNotExists([]byte("nodes"))
		return nil
	})

	http.HandleFunc("/register", handleRegister)
	http.HandleFunc("/config/", handleConfig)
	http.HandleFunc("/heartbeat/", handleHB)

	log.Println("control-plane listening on :8080 with policy enforcement")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func loadPolicy(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &policy)
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
				if string(k) == id {
					self = n
				}
			}
			return nil
		})
		return nil
	})
	if self.ID == "" {
		http.NotFound(w, r)
		return
	}

	allowed := policy[self.PublicKey]
	allowAll := len(allowed) == 0

	var cfg Config
	cfg.InterfaceAddress = self.IP
	cfg.ListenPort = 51820

	for _, peer := range all {
		if peer.ID == self.ID {
			continue
		}
		if allowAll || contains(allowed, peer.PublicKey) {
			cfg.Peers = append(cfg.Peers, Peer{
				PublicKey:  peer.PublicKey,
				AllowedIPs: []string{peer.IP},
			})
		}
	}

	json.NewEncoder(w).Encode(cfg)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func handleRegister(w http.ResponseWriter, r *http.Request) {}
func handleHB(w http.ResponseWriter, r *http.Request)       {}
