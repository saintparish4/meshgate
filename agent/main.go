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

// ------------- env helpers ---------------------------------------------------

func cpURL() string {
	if u := os.Getenv("CONTROL_PLANE"); u != "" { return strings.TrimRight(u, "/") }
	return "http://localhost:8080"
}
func token() string {
	if t := os.Getenv("NODE_TOKEN"); t != "" { return t }
	return "meshgate-secret"
}

// ------------- key management -----------------------------------------------

func generatePair() (priv, pub string) {
	k, _ := wgtypes.GeneratePrivateKey()
	return k.String(), k.PublicKey().String()
}
func ensureKeys() (priv, pub string) {
	if b, err := ioutil.ReadFile(keyPath); err == nil {
		priv = strings.TrimSpace(string(b))
		k, _ := wgtypes.ParseKey(priv)
		return priv, k.PublicKey().String()
	}
	priv, pub = generatePair()
	_ = os.MkdirAll("/etc/wireguard", 0700)
	_ = ioutil.WriteFile(keyPath, []byte(priv+"\n"), 0600)
	return
}

// ------------- tiny HTTP helper ---------------------------------------------

func call(method, path string, body []byte) (*http.Response, error) {
	req, _ := http.NewRequest(method, cpURL()+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token())
	if body != nil { req.Header.Set("Content-Type", "application/json") }
	return http.DefaultClient.Do(req)
}

// ------------- control-plane ops --------------------------------------------

func register(pub string) Node {
	b, _ := json.Marshal(map[string]string{"publicKey": pub})
	resp, err := call("POST", "/register", b)
	if err != nil { log.Fatalf("register: %v", err) }
	defer resp.Body.Close()
	var n Node
	if err := json.NewDecoder(resp.Body).Decode(&n); err != nil { log.Fatalf("decode reg: %v", err) }
	return n
}
func fetchCfg(id string) Config {
	resp, err := call("GET", "/config/"+id, nil)
	if err != nil { log.Fatalf("config: %v", err) }
	defer resp.Body.Close()
	var c Config
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil { log.Fatalf("decode cfg: %v", err) }
	return c
}
func hb(id string) {
	for {
		_, _ = call("POST", "/heartbeat/"+id, nil)
		time.Sleep(30 * time.Second)
	}
}

// ------------- WireGuard helpers --------------------------------------------

func apply(cfg Config) error {
	_ = exec.Command("ip", "link", "add", "wg0", "type", "wireguard").Run()
	if err := exec.Command("ip", "addr", "replace", cfg.InterfaceAddress, "dev", "wg0").Run(); err != nil {
		return err
	}
	if err := exec.Command("wg", "set", "wg0", "listen-port", fmt.Sprint(cfg.ListenPort),
		"private-key", keyPath).Run(); err != nil {
		return err
	}
	for _, p := range cfg.Peers {
		args := []string{"set", "wg0", "peer", p.PublicKey}
		for _, ip := range p.AllowedIPs { args = append(args, "allowed-ips", ip) }
		if err := exec.Command("wg", args...).Run(); err != nil { return err }
	}
	return exec.Command("ip", "link", "set", "up", "wg0").Run()
}

// ------------- main ----------------------------------------------------------

func main() {
	_, pub := ensureKeys()

	node := register(pub)
	log.Printf("registered: id=%s ip=%s", node.ID, node.IP)

	cfg := fetchCfg(node.ID)
	if err := apply(cfg); err != nil { log.Fatalf("apply: %v", err) }

	go hb(node.ID)
	select {} // keep running
}
