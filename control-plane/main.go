package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"

	"github.com/saintparish4/meshgate/control-plane/database"
)

// Models - using types from database package
type User = database.User
type Tenant = database.Tenant
type TenantSettings = database.TenantSettings
type Node = database.Node

type contextKey string

const claimsContextKey contextKey = "claims"

type AuthClaims struct {
	UserID   string `json:"user_id"`
	TenantID string `json:"tenant_id"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// Metrics

var (
	activeNodes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "meshgate_active_nodes",
			Help: "Number of active nodes per tenant",
		},
		[]string{"tenant_id"},
	)

	authAttempts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "meshgate_auth_attempts_total",
			Help: "Total number of authentication attempts",
		},
		[]string{"status", "tenant_id"},
	)

	apiRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "meshgate_api_requests_total",
			Help: "Total number of API requests",
		},
		[]string{"method", "endpoint", "status", "tenant_id"},
	)

	nodeHeartbeats = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "meshgate_node_heartbeats_total",
			Help: "Total number of node heartbeats",
		},
		[]string{"node_id", "tenant_id"},
	)
)

// Server

type Server struct {
	db        *database.DatabaseManager
	jwtSecret []byte
	router    *mux.Router
}

func NewServer(dbPath string) (*Server, error) {
	db, err := database.NewDatabaseManager(dbPath)
	if err != nil {
		return nil, err
	}

	// Generate JWT Secret
	jwtSecret := make([]byte, 32)
	if _, err := rand.Read(jwtSecret); err != nil {
		return nil, err
	}

	server := &Server{
		db:        db,
		jwtSecret: jwtSecret,
		router:    mux.NewRouter(),
	}

	// Register metrics
	prometheus.MustRegister(activeNodes, authAttempts, apiRequests, nodeHeartbeats)

	server.setupRoutes()
	return server, nil
}

func (s *Server) setupRoutes() {
	// Public Routes
	s.router.HandleFunc("/api/v1/auth/login", s.handleLogin).Methods("POST")
	s.router.HandleFunc("/api/v1/auth/register", s.handleRegister).Methods("POST")
	s.router.HandleFunc("/api/v1/auth/tenants", s.handleCreateTenant).Methods("POST")

	// Metrics endpoint
	s.router.Handle("/metrics", promhttp.Handler())

	// Health check
	s.router.HandleFunc("/health", s.handleHealth).Methods("GET")

	// Protected Routes
	api := s.router.PathPrefix("/api/v1").Subrouter()
	api.Use(s.authMiddleware)
	api.Use(s.metricsMiddleware)

	// User Management
	api.HandleFunc("/users", s.handleListUsers).Methods("GET")
	api.HandleFunc("/users/{id}", s.handleGetUser).Methods("GET")
	api.HandleFunc("/users/{id}", s.handleUpdateUser).Methods("PUT")

	// Tenant Management
	api.HandleFunc("/tenants", s.handleGetTenants).Methods("GET")
	api.HandleFunc("/tenants", s.handleUpdateTenant).Methods("PUT")
	api.HandleFunc("/tenants/users", s.handleListTenantUsers).Methods("GET")

	// Node Management
	api.HandleFunc("/nodes", s.handleListNodes).Methods("GET")
	api.HandleFunc("/nodes", s.handleCreateNode).Methods("POST")
	api.HandleFunc("/nodes/{id}", s.handleGetNode).Methods("GET")
	api.HandleFunc("/nodes/{id}", s.handleUpdateNode).Methods("PUT")
	api.HandleFunc("/nodes/{id}", s.handleDeleteNode).Methods("DELETE")
	api.HandleFunc("/nodes/{id}/heartbeat", s.handleNodeHeartbeat).Methods("POST")

	// Configuration
	api.HandleFunc("/nodes/{id}/config", s.handleGetNodeConfig).Methods("GET")
	api.HandleFunc("/policies", s.handleGetPolicies).Methods("GET")
	api.HandleFunc("/policies", s.handleUpdatePolicies).Methods("PUT")
}

// Authentication Handlers
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var loginReq struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	user, err := s.getUserByEmail(loginReq.Email)
	if err != nil {
		authAttempts.WithLabelValues("failed", "unknown").Inc()
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(loginReq.Password)); err != nil {
		authAttempts.WithLabelValues("failed", user.TenantID).Inc()
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Update last login
	user.LastLogin = time.Now()
	s.saveUser(user)

	token, err := s.generateJWT(user)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	authAttempts.WithLabelValues("success", user.TenantID).Inc()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token": token,
		"user": map[string]interface{}{
			"id":        user.ID,
			"email":     user.Email,
			"role":      user.Role,
			"tenant_id": user.TenantID,
		},
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var registerReq struct {
		Email      string `json:"email"`
		Password   string `json:"password"`
		TenantName string `json:"tenant_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&registerReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Check if user exists
	if _, err := s.getUserByEmail(registerReq.Email); err == nil {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	// CREATE TENANT
	tenant := &database.Tenant{
		ID:     generateID(),
		Name:   registerReq.TenantName,
		Domain: strings.Split(registerReq.Email, "@")[1],
		Settings: database.TenantSettings{
			SubnetCIDR:        "10.0.0.0/24",
			MaxNodes:          100,
			PolicyMode:        "strict",
			HeartbeatInterval: 30,
		},
		CreatedAt: time.Now(),
		IsActive:  true,
		NodeLimit: 100,
	}

	if err := s.saveTenant(tenant); err != nil {
		http.Error(w, "Failed to create tenant", http.StatusInternalServerError)
		return
	}

	// Create User
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(registerReq.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	user := &database.User{
		ID:           generateID(),
		Email:        registerReq.Email,
		PasswordHash: string(hashedPassword),
		Role:         "admin",
		TenantID:     tenant.ID,
		CreatedAt:    time.Now(),
	}

	if err := s.saveUser(user); err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":   "Registration successful",
		"user_id":   user.ID,
		"tenant_id": tenant.ID,
	})
}

// Node Management
func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(claimsContextKey).(*AuthClaims)

	nodes, err := s.getNodesByTenant(claims.TenantID)
	if err != nil {
		http.Error(w, "Failed to fetch nodes", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(nodes)
}

func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(claimsContextKey).(*AuthClaims)

	var nodeReq struct {
		Name      string            `json:"name"`
		PublicKey string            `json:"public_key"`
		Metadata  map[string]string `json:"metadata"`
	}

	if err := json.NewDecoder(r.Body).Decode(&nodeReq); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Check tenant node limit
	tenant, err := s.getTenant(claims.TenantID)
	if err != nil {
		http.Error(w, "Tenant not found", http.StatusNotFound)
		return
	}

	if tenant.UsedNodes >= tenant.NodeLimit {
		http.Error(w, "Node limit reached", http.StatusForbidden)
		return
	}

	node := &database.Node{
		ID:        generateID(),
		TenantID:  claims.TenantID,
		Name:      nodeReq.Name,
		PublicKey: nodeReq.PublicKey,
		IPAddress: s.allocateIP(claims.TenantID),
		Status:    "offline",
		CreatedAt: time.Now(),
		Metadata:  nodeReq.Metadata,
	}

	if err := s.saveNode(node); err != nil {
		http.Error(w, "Failed to create node", http.StatusInternalServerError)
		return
	}

	// Update tenant used nodes
	tenant.UsedNodes++
	s.saveTenant(tenant)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(node)
}

func (s *Server) handleNodeHeartbeat(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(claimsContextKey).(*AuthClaims)
	nodeID := mux.Vars(r)["id"]

	node, err := s.getNode(nodeID)
	if err != nil || node.TenantID != claims.TenantID {
		http.Error(w, "Node not found", http.StatusNotFound)
		return
	}

	node.Status = "online"
	node.LastSeen = time.Now()
	s.saveNode(node)

	nodeHeartbeats.WithLabelValues(nodeID, claims.TenantID).Inc()
	activeNodes.WithLabelValues(claims.TenantID).Inc()

	w.WriteHeader(http.StatusOK)
}

// Middleware
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.ParseWithClaims(tokenString, &AuthClaims{}, func(token *jwt.Token) (interface{}, error) {
			return s.jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims := token.Claims.(*AuthClaims)
		ctx := context.WithValue(r.Context(), claimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := r.Context().Value(claimsContextKey).(*AuthClaims)

		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(recorder, r)

		duration := time.Since(start)

		apiRequests.WithLabelValues(
			r.Method,
			r.URL.Path,
			strconv.Itoa(recorder.statusCode),
			claims.TenantID,
		).Inc()

		log.Printf("API: %s %s %d %v tenant: %s",
			r.Method, r.URL.Path, recorder.statusCode, duration, claims.TenantID)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

// Database Operations
func (s *Server) saveUser(user *database.User) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		data, err := json.Marshal(user)
		if err != nil {
			return err
		}
		return b.Put([]byte(user.ID), data)
	})
}

func (s *Server) getUserByEmail(email string) (*database.User, error) {
	var user *database.User
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("users"))
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var u database.User
			if err := json.Unmarshal(v, &u); err != nil {
				continue
			}
			if u.Email == email {
				user = &u
				return nil
			}
		}
		return fmt.Errorf("user not found")
	})
	return user, err
}

func (s *Server) saveTenant(tenant *database.Tenant) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("tenants"))
		data, err := json.Marshal(tenant)
		if err != nil {
			return err
		}
		return b.Put([]byte(tenant.ID), data)
	})
}

func (s *Server) getTenant(id string) (*database.Tenant, error) {
	var tenant *database.Tenant
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("tenants"))
		data := b.Get([]byte(id))
		if data == nil {
			return fmt.Errorf("tenant not found")
		}
		tenant = &database.Tenant{}
		return json.Unmarshal(data, tenant)
	})
	return tenant, err
}

func (s *Server) saveNode(node *database.Node) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		data, err := json.Marshal(node)
		if err != nil {
			return err
		}
		return b.Put([]byte(node.ID), data)
	})
}

func (s *Server) getNode(id string) (*database.Node, error) {
	var node *database.Node
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		data := b.Get([]byte(id))
		if data == nil {
			return fmt.Errorf("node not found")
		}
		node = &database.Node{}
		return json.Unmarshal(data, node)
	})
	return node, err
}

func (s *Server) getNodesByTenant(tenantID string) ([]*database.Node, error) {
	var nodes []*database.Node
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("nodes"))
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var node database.Node
			if err := json.Unmarshal(v, &node); err != nil {
				continue
			}
			if node.TenantID == tenantID {
				nodes = append(nodes, &node)
			}
		}
		return nil
	})
	return nodes, err
}

// Utility Functions
func generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (s *Server) generateJWT(user *database.User) (string, error) {
	claims := &AuthClaims{
		UserID:   user.ID,
		TenantID: user.TenantID,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

func (s *Server) allocateIP(_ string) string {
	// Simple IP allocation - in production use proper IPAM
	return "10.10.10.100" // Placeholder
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// Placeholder handlers for remaining endpoints
func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (s *Server) handleGetTenants(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(claimsContextKey).(*AuthClaims)

	tenant, err := s.getTenant(claims.TenantID)
	if err != nil {
		http.Error(w, "Tenant not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tenant)
}

func (s *Server) handleUpdateTenant(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (s *Server) handleListTenantUsers(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (s *Server) handleUpdateNode(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (s *Server) handleGetNodeConfig(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (s *Server) handleGetPolicies(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func (s *Server) handleUpdatePolicies(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

func main() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "meshgate.db"
	}

	server, err := NewServer(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}
	defer server.db.Close()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting OrdinalGate Control Plane on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, server.router))
}
