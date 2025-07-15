// agent/wireguard/interface.go
package wireguard

import (
	"fmt"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// InterfaceConfig represents the configuration for a WireGuard interface
type InterfaceConfig struct {
	Name       string
	PrivateKey wgtypes.Key
	PublicKey  wgtypes.Key
	ListenPort int
	IPAddress  *net.IPNet
	DNS        []net.IP
	Routes     []Route
	MTU        int
}

// Route represents a network route
type Route struct {
	Destination *net.IPNet
	Gateway     net.IP
	Metric      int
}

// InterfaceManager manages WireGuard interfaces across platforms
type InterfaceManager interface {
	// CreateInterface creates a new WireGuard interface
	CreateInterface(config *InterfaceConfig) error

	// DeleteInterface removes a WireGuard interface
	DeleteInterface(name string) error

	// ConfigureInterface applies configuration to an interface
	ConfigureInterface(name string, config *InterfaceConfig) error

	// SetIPAddress assigns an IP address to the interface
	SetIPAddress(name string, ip *net.IPNet) error

	// AddRoute adds a route to the routing table
	AddRoute(route Route) error

	// RemoveRoute removes a route from the routing table
	RemoveRoute(route Route) error

	// SetMTU sets the MTU of the interface
	SetMTU(name string, mtu int) error

	// BringUp brings the interface up
	BringUp(name string) error

	// BringDown brings the interface down
	BringDown(name string) error

	// IsInterfaceUp checks if the interface is up
	IsInterfaceUp(name string) (bool, error)

	// GetInterfaceStats gets interface statistics
	GetInterfaceStats(name string) (*InterfaceStats, error)
}

// InterfaceStats represents interface statistics
type InterfaceStats struct {
	BytesReceived    uint64
	BytesTransmitted uint64
	PacketsReceived  uint64
	PacketsDropped   uint64
	Errors           uint64
	LastSeen         time.Time
}

// Manager implements InterfaceManager for the current platform
type Manager struct {
	wgClient wgctrl.Client
	impl     platformImpl
}

// platformImpl interface for platform-specific implementations
type platformImpl interface {
	createInterface(name string) error
	deleteInterface(name string) error
	setIPAddress(name string, ip *net.IPNet) error
	addRoute(route Route) error
	removeRoute(route Route) error
	setMTU(name string, mtu int) error
	bringUp(name string) error
	bringDown(name string) error
	isInterfaceUp(name string) (bool, error)
	getInterfaceStats(name string) (*InterfaceStats, error)
}

// CreateInterface creates a new WireGuard interface
func (m *Manager) CreateInterface(config *InterfaceConfig) error {
	// Create the interface using platform-specific implementation
	if err := m.impl.createInterface(config.Name); err != nil {
		return fmt.Errorf("failed to create interface %s: %w", config.Name, err)
	}

	// Configure WireGuard
	if err := m.ConfigureInterface(config.Name, config); err != nil {
		// Clean up on failure
		m.impl.deleteInterface(config.Name)
		return fmt.Errorf("failed to configure interface %s: %w", config.Name, err)
	}

	return nil
}

// DeleteInterface removes a WireGuard interface
func (m *Manager) DeleteInterface(name string) error {
	// Bring interface down first
	if err := m.impl.bringDown(name); err != nil {
		// Log error but continue with deletion
		fmt.Printf("Warning: failed to bring down interface %s: %v\n", name, err)
	}

	// Delete the interface
	if err := m.impl.deleteInterface(name); err != nil {
		return fmt.Errorf("failed to delete interface %s: %w", name, err)
	}

	return nil
}

// ConfigureInterface applies configuration to an interface
func (m *Manager) ConfigureInterface(name string, config *InterfaceConfig) error {
	// Configure WireGuard settings
	wgConfig := wgtypes.Config{
		PrivateKey: &config.PrivateKey,
		ListenPort: &config.ListenPort,
	}

	if err := m.wgClient.ConfigureDevice(name, wgConfig); err != nil {
		return fmt.Errorf("failed to configure WireGuard device: %w", err)
	}

	// Set IP address
	if config.IPAddress != nil {
		if err := m.impl.setIPAddress(name, config.IPAddress); err != nil {
			return fmt.Errorf("failed to set IP address: %w", err)
		}
	}

	// Set MTU
	if config.MTU > 0 {
		if err := m.impl.setMTU(name, config.MTU); err != nil {
			return fmt.Errorf("failed to set MTU: %w", err)
		}
	}

	// Add routes
	for _, route := range config.Routes {
		if err := m.impl.addRoute(route); err != nil {
			return fmt.Errorf("failed to add route %s: %w", route.Destination.String(), err)
		}
	}

	// Bring interface up
	if err := m.impl.bringUp(name); err != nil {
		return fmt.Errorf("failed to bring up interface: %w", err)
	}

	return nil
}

// SetIPAddress assigns an IP address to the interface
func (m *Manager) SetIPAddress(name string, ip *net.IPNet) error {
	return m.impl.setIPAddress(name, ip)
}

// AddRoute adds a route to the routing table
func (m *Manager) AddRoute(route Route) error {
	return m.impl.addRoute(route)
}

// RemoveRoute removes a route from the routing table
func (m *Manager) RemoveRoute(route Route) error {
	return m.impl.removeRoute(route)
}

// SetMTU sets the MTU of the interface
func (m *Manager) SetMTU(name string, mtu int) error {
	return m.impl.setMTU(name, mtu)
}

// BringUp brings the interface up
func (m *Manager) BringUp(name string) error {
	return m.impl.bringUp(name)
}

// BringDown brings the interface down
func (m *Manager) BringDown(name string) error {
	return m.impl.bringDown(name)
}

// IsInterfaceUp checks if the interface is up
func (m *Manager) IsInterfaceUp(name string) (bool, error) {
	return m.impl.isInterfaceUp(name)
}

// GetInterfaceStats gets interface statistics
func (m *Manager) GetInterfaceStats(name string) (*InterfaceStats, error) {
	return m.impl.getInterfaceStats(name)
}

// Close closes the manager and cleans up resources
func (m *Manager) Close() error {
	return m.wgClient.Close()
}

// ValidateConfig validates the interface configuration
func ValidateConfig(config *InterfaceConfig) error {
	if config.Name == "" {
		return fmt.Errorf("interface name is required")
	}

	if config.ListenPort < 1 || config.ListenPort > 65535 {
		return fmt.Errorf("invalid listen port: %d", config.ListenPort)
	}

	if config.IPAddress == nil {
		return fmt.Errorf("IP address is required")
	}

	if config.MTU > 0 && (config.MTU < 576 || config.MTU > 9000) {
		return fmt.Errorf("invalid MTU: %d (must be between 576 and 9000)", config.MTU)
	}

	return nil
}
