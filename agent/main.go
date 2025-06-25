package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	wgtypes "golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

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
type Node struct {
	ID string `json:"id"`
	IP string `json:"ip"`
}

const keyPath = "/etc/wireguard/meshgate.key"

func controlPlane() string {
	if u := os.Getenv("CONTROL_PLANE"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://localhost:8080"
}

// ---------------------------------------------------------------------------
// key management (unchanged logic, just extracted)

func getOrCreateKeys() (priv, pub string) {
	if b, err := ioutil.ReadFile(keyPath); err == nil {
		priv = strings.TrimSpace(string(b))
		k, _ := wgtypes.ParseKey(priv)
		return priv, k.PublicKey().String()
	}
	priv, pub, err := generateKeyPair()
	if err != nil { log.Fatalf("keygen: %v", err) }
	_ = os.MkdirAll("/etc/wireguard", 0700)
	_ = ioutil.WriteFile(keyPath, []byte(priv+"\n"), 0600)
	return priv, pub
}

// ---------------------------------------------------------------------------
// control-plane helpers

func register(pub string) Node {
	body, _ := json.Marshal(map[string]string{"publicKey": pub})
	resp, err := http.Post(controlPlane()+"/register", "application/json", bytes.NewReader(body))
	if err != nil { log.Fatalf("register: %v", err) }
	defer resp.Body.Close()
	var n Node
	if err := json.NewDecoder(resp.Body).Decode(&n); err != nil { log.Fatalf("decode register: %v", err) }
	return n
}

func fetchConfig(id string) Config {
	resp, err := http.Get(controlPlane() + "/config/" + id)
	if err != nil { log.Fatalf("config: %v", err) }
	defer resp.Body.Close()
	var cfg Config
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil { log.Fatalf("decode cfg: %v", err) }
	return cfg
}

func heartbeat(id string) {
	for {
		_, _ = http.Post(controlPlane()+"/heartbeat/"+id, "text/plain", nil)
		time.Sleep(30 * time.Second)
	}
}

// ---------------------------------------------------------------------------
// WireGuard helpers (applyConfig + generateKeyPair exactly as in Day 1)

func generateKeyPair() (string, string, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil { return "", "", err }
	return key.String(), key.PublicKey().String(), nil
}

func applyConfig(cfg Config) error {
	_ = exec.Command("ip", "link", "add", "wg0", "type", "wireguard").Run()

	if err := exec.Command("ip", "address", "replace", cfg.InterfaceAddress, "dev", "wg0").Run(); err != nil {
		return err
	}
	if err := exec.Command("wg", "set", "wg0",
		"listen-port", fmt.Sprint(cfg.ListenPort),
		"private-key", keyPath).Run(); err != nil {
		return err
	}
	for _, p := range cfg.Peers {
		args := []string{"set", "wg0", "peer", p.PublicKey}
		if p.Endpoint != "" {
			args = append(args, "endpoint", p.Endpoint)
		}
		for _, ip := range p.AllowedIPs {
			args = append(args, "allowed-ips", ip)
		}
		if err := exec.Command("wg", args...).Run(); err != nil {
			return err
		}
	}
	return exec.Command("ip", "link", "set", "up", "wg0").Run()
}

// ---------------------------------------------------------------------------

func main() {
	_, pub := getOrCreateKeys()

	// 1️⃣ register & obtain node ID
	node := register(pub)
	log.Printf("registered: nodeID=%s ip=%s", node.ID, node.IP)

	// 2️⃣ fetch mesh config & apply
	cfg := fetchConfig(node.ID)
	if err := applyConfig(cfg); err != nil {
		log.Fatalf("apply cfg: %v", err)
	}

	// 3️⃣ heartbeat loop
	go heartbeat(node.ID)

	select {} // block forever
}
