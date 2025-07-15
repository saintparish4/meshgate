// agent/wireguard/windows.go
//go:build windows

package wireguard

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// Windows API constants
const (
	MIB_IF_TYPE_OTHER      = 1
	MIB_IF_TYPE_TUNNEL     = 131
	IF_TYPE_IEEE80211      = 71
	ERROR_BUFFER_TOO_SMALL = 122
)

// windowsImpl implements platform-specific WireGuard interface management for Windows
type windowsImpl struct{}

// Windows API structures
type MibIfRow2 struct {
	InterfaceLuid               uint64
	InterfaceIndex              uint32
	InterfaceGuid               windows.GUID
	Alias                       [257]uint16
	Description                 [257]uint16
	PhysicalAddressLength       uint32
	PhysicalAddress             [32]uint8
	PermanentPhysicalAddress    [32]uint8
	Mtu                         uint32
	Type                        uint32
	TunnelType                  uint32
	MediaType                   uint32
	PhysicalMediumType          uint32
	AccessType                  uint32
	DirectionType               uint32
	InterfaceAndOperStatusFlags struct {
		HardwareInterface uint8
		FilterInterface   uint8
		ConnectorPresent  uint8
		NotAuthenticated  uint8
		NotMediaConnected uint8
		Paused            uint8
		LowPower          uint8
		EndPointInterface uint8
	}
	OperStatus         uint32
	AdminStatus        uint32
	MediaConnectState  uint32
	NetworkGuid        windows.GUID
	ConnectionType     uint32
	TransmitLinkSpeed  uint64
	ReceiveLinkSpeed   uint64
	InOctets           uint64
	InUcastPkts        uint64
	InNUcastPkts       uint64
	InDiscards         uint64
	InErrors           uint64
	InUnknownProtos    uint64
	InUcastOctets      uint64
	InMulticastOctets  uint64
	InBroadcastOctets  uint64
	OutOctets          uint64
	OutUcastPkts       uint64
	OutNUcastPkts      uint64
	OutDiscards        uint64
	OutErrors          uint64
	OutUcastOctets     uint64
	OutMulticastOctets uint64
	OutBroadcastOctets uint64
	OutQLen            uint64
}

// Windows DLL imports
var (
	iphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procGetIfTable2                 = iphlpapi.NewProc("GetIfTable2")
	procGetIfEntry2                 = iphlpapi.NewProc("GetIfEntry2")
	procCreateUnicastIpAddressEntry = iphlpapi.NewProc("CreateUnicastIpAddressEntry")
	procDeleteUnicastIpAddressEntry = iphlpapi.NewProc("DeleteUnicastIpAddressEntry")
	procCreateIpForwardEntry2       = iphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2       = iphlpapi.NewProc("DeleteIpForwardEntry2")
)

// createInterface creates a new WireGuard interface on Windows using WinTun
func (w *windowsImpl) createInterface(name string) error {
	// On Windows, we use the wg.exe command line tool or WinTun API
	// For simplicity, we'll use the command line approach

	// Check if WireGuard is installed
	if err := checkWireGuardInstalled(); err != nil {
		return fmt.Errorf("WireGuard not installed: %w", err)
	}

	// Create interface using wg-quick or manual approach
	// For manual approach, we need to create a WinTun adapter

	// Use netsh to create a TAP adapter (alternative approach)
	cmd := exec.Command("netsh", "interface", "ipv6", "add", "interface", name)
	if err := cmd.Run(); err != nil {
		// Try creating with PowerShell
		return w.createInterfaceWithPowerShell(name)
	}

	return nil
}

// createInterfaceWithPowerShell creates interface using PowerShell
func (w *windowsImpl) createInterfaceWithPowerShell(name string) error {
	script := fmt.Sprintf(`
		New-NetAdapter -Name "%s" -InterfaceDescription "WireGuard Tunnel"
	`, name)

	cmd := exec.Command("powershell", "-Command", script)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create interface with PowerShell: %w", err)
	}

	return nil
}

// deleteInterface removes a WireGuard interface on Windows
func (w *windowsImpl) deleteInterface(name string) error {
	// Try multiple methods to remove the interface

	// Method 1: Use netsh
	cmd := exec.Command("netsh", "interface", "delete", "interface", name)
	if err := cmd.Run(); err == nil {
		return nil
	}

	// Method 2: Use PowerShell
	script := fmt.Sprintf(`Remove-NetAdapter -Name "%s" -Confirm:$false`, name)
	cmd = exec.Command("powershell", "-Command", script)
	if err := cmd.Run(); err == nil {
		return nil
	}

	// Method 3: Use wg.exe if available
	cmd = exec.Command("wg", "del", name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to delete interface %s: %w", name, err)
	}

	return nil
}

// setIPAddress assigns an IP address to the interface on Windows
func (w *windowsImpl) setIPAddress(name string, ip *net.IPNet) error {
	// Get interface index
	index, err := w.getInterfaceIndex(name)
	if err != nil {
		return fmt.Errorf("failed to get interface index: %w", err)
	}

	// Remove existing IP addresses
	if err := w.removeExistingAddresses(index); err != nil {
		fmt.Printf("Warning: failed to remove existing addresses: %v\n", err)
	}

	// Add new IP address using netsh
	mask := net.IP(ip.Mask).String()
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		fmt.Sprintf("name=%s", name), "static", ip.IP.String(), mask)

	if err := cmd.Run(); err != nil {
		// Try alternative method with PowerShell
		return w.setIPAddressWithPowerShell(name, ip)
	}

	return nil
}

// setIPAddressWithPowerShell sets IP address using PowerShell
func (w *windowsImpl) setIPAddressWithPowerShell(name string, ip *net.IPNet) error {
	ones, _ := ip.Mask.Size()
	script := fmt.Sprintf(`
		Remove-NetIPAddress -InterfaceAlias "%s" -Confirm:$false -ErrorAction SilentlyContinue
		New-NetIPAddress -InterfaceAlias "%s" -IPAddress "%s" -PrefixLength %d
	`, name, name, ip.IP.String(), ones)

	cmd := exec.Command("powershell", "-Command", script)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set IP address with PowerShell: %w", err)
	}

	return nil
}

// addRoute adds a route to the routing table on Windows
func (w *windowsImpl) addRoute(route Route) error {
	destination := route.Destination.String()

	var cmd *exec.Cmd
	if route.Gateway != nil {
		// Route with gateway
		cmd = exec.Command("route", "add", destination, route.Gateway.String())
	} else {
		// Direct route
		cmd = exec.Command("route", "add", destination, "0.0.0.0")
	}

	if route.Metric > 0 {
		cmd.Args = append(cmd.Args, "metric", strconv.Itoa(route.Metric))
	}

	if err := cmd.Run(); err != nil {
		// Try with PowerShell
		return w.addRouteWithPowerShell(route)
	}

	return nil
}

// addRouteWithPowerShell adds route using PowerShell
func (w *windowsImpl) addRouteWithPowerShell(route Route) error {
	destination := route.Destination.String()

	var script string
	if route.Gateway != nil {
		script = fmt.Sprintf(`New-NetRoute -DestinationPrefix "%s" -NextHop "%s"`,
			destination, route.Gateway.String())
	} else {
		script = fmt.Sprintf(`New-NetRoute -DestinationPrefix "%s"`, destination)
	}

	if route.Metric > 0 {
		script += fmt.Sprintf(` -RouteMetric %d`, route.Metric)
	}

	cmd := exec.Command("powershell", "-Command", script)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add route with PowerShell: %w", err)
	}

	return nil
}

// removeRoute removes a route from the routing table on Windows
func (w *windowsImpl) removeRoute(route Route) error {
	destination := route.Destination.String()

	cmd := exec.Command("route", "delete", destination)
	if err := cmd.Run(); err != nil {
		// Try with PowerShell
		script := fmt.Sprintf(`Remove-NetRoute -DestinationPrefix "%s" -Confirm:$false`, destination)
		cmd = exec.Command("powershell", "-Command", script)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to remove route: %w", err)
		}
	}

	return nil
}

// setMTU sets the MTU of the interface on Windows
func (w *windowsImpl) setMTU(name string, mtu int) error {
	// Use netsh to set MTU
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
		fmt.Sprintf("interface=%s", name), fmt.Sprintf("mtu=%d", mtu))

	if err := cmd.Run(); err != nil {
		// Try with PowerShell
		script := fmt.Sprintf(`Set-NetIPInterface -InterfaceAlias "%s" -NlMtu %d`, name, mtu)
		cmd = exec.Command("powershell", "-Command", script)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to set MTU: %w", err)
		}
	}

	return nil
}

// bringUp brings the interface up on Windows
func (w *windowsImpl) bringUp(name string) error {
	// Use netsh to enable interface
	cmd := exec.Command("netsh", "interface", "set", "interface", name, "admin=enabled")
	if err := cmd.Run(); err != nil {
		// Try with PowerShell
		script := fmt.Sprintf(`Enable-NetAdapter -Name "%s" -Confirm:$false`, name)
		cmd = exec.Command("powershell", "-Command", script)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to bring up interface: %w", err)
		}
	}

	return nil
}

// bringDown brings the interface down on Windows
func (w *windowsImpl) bringDown(name string) error {
	// Use netsh to disable interface
	cmd := exec.Command("netsh", "interface", "set", "interface", name, "admin=disabled")
	if err := cmd.Run(); err != nil {
		// Try with PowerShell
		script := fmt.Sprintf(`Disable-NetAdapter -Name "%s" -Confirm:$false`, name)
		cmd = exec.Command("powershell", "-Command", script)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to bring down interface: %w", err)
		}
	}

	return nil
}

// isInterfaceUp checks if the interface is up on Windows
func (w *windowsImpl) isInterfaceUp(name string) (bool, error) {
	// Use PowerShell to check interface status
	script := fmt.Sprintf(`(Get-NetAdapter -Name "%s" -ErrorAction SilentlyContinue).Status`, name)
	cmd := exec.Command("powershell", "-Command", script)

	output, err := cmd.Output()
	if err != nil {
		return false, nil // Interface doesn't exist
	}

	status := strings.TrimSpace(string(output))
	return status == "Up", nil
}

// getInterfaceStats gets interface statistics on Windows
func (w *windowsImpl) getInterfaceStats(name string) (*InterfaceStats, error) {
	// Get interface index first
	index, err := w.getInterfaceIndex(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface index: %w", err)
	}

	// Get interface statistics using Windows API
	var ifRow MibIfRow2
	ifRow.InterfaceIndex = index

	ret, _, _ := procGetIfEntry2.Call(uintptr(unsafe.Pointer(&ifRow)))
	if ret != 0 {
		return nil, fmt.Errorf("GetIfEntry2 failed with error: %d", ret)
	}

	stats := &InterfaceStats{
		BytesReceived:    ifRow.InOctets,
		BytesTransmitted: ifRow.OutOctets,
		PacketsReceived:  ifRow.InUcastPkts + ifRow.InNUcastPkts,
		PacketsDropped:   ifRow.InDiscards + ifRow.OutDiscards,
		Errors:           ifRow.InErrors + ifRow.OutErrors,
		LastSeen:         time.Now(),
	}

	return stats, nil
}

// Helper functions for Windows-specific operations

// getInterfaceIndex gets the interface index by name
func (w *windowsImpl) getInterfaceIndex(name string) (uint32, error) {
	// Use PowerShell to get interface index
	script := fmt.Sprintf(`(Get-NetAdapter -Name "%s" -ErrorAction SilentlyContinue).InterfaceIndex`, name)
	cmd := exec.Command("powershell", "-Command", script)

	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("interface not found: %s", name)
	}

	indexStr := strings.TrimSpace(string(output))
	index, err := strconv.ParseUint(indexStr, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid interface index: %s", indexStr)
	}

	return uint32(index), nil
}

// removeExistingAddresses removes existing IP addresses from interface
func (w *windowsImpl) removeExistingAddresses(index uint32) error {
	// Use PowerShell to remove existing addresses
	script := fmt.Sprintf(`Get-NetIPAddress -InterfaceIndex %d | Remove-NetIPAddress -Confirm:$false`, index)
	cmd := exec.Command("powershell", "-Command", script)

	// Ignore errors as the interface might not have any addresses
	cmd.Run()
	return nil
}

// checkWireGuardInstalled checks if WireGuard is installed on Windows
func checkWireGuardInstalled() error {
	// Check if wg.exe is available
	cmd := exec.Command("wg", "version")
	if err := cmd.Run(); err == nil {
		return nil
	}

	// Check if WireGuard service is installed
	cmd = exec.Command("sc", "query", "WireGuardManager")
	if err := cmd.Run(); err == nil {
		return nil
	}

	return fmt.Errorf("WireGuard not found. Please install WireGuard for Windows")
}

// isRunningAsAdmin checks if the process is running with administrator privileges
func isRunningAsAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}

	return member
}

// enableWindowsIPForwarding enables IP forwarding on Windows
func enableWindowsIPForwarding() error {
	// Enable IPv4 forwarding
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "global", "forwarding=enabled")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable IPv4 forwarding: %w", err)
	}

	// Enable IPv6 forwarding
	cmd = exec.Command("netsh", "interface", "ipv6", "set", "global", "forwarding=enabled")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable IPv6 forwarding: %w", err)
	}

	return nil
}

// getWindowsVersion returns the Windows version
func getWindowsVersion() (string, error) {
	cmd := exec.Command("cmd", "/c", "ver")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get Windows version: %w", err)
	}

	return strings.TrimSpace(string(output)), nil
}

// installWinTun installs WinTun driver if not present
func installWinTun() error {
	// This would typically download and install WinTun
	// For production use, you'd want to bundle WinTun with your application
	return fmt.Errorf("WinTun installation not implemented - please install WireGuard for Windows")
}

// setupWindowsEnvironment prepares the Windows environment for WireGuard
// This is the internal function called by the exported SetupWindowsEnvironment
func setupWindowsEnvironment() error {
	// Check if running as administrator
	if !isRunningAsAdmin() {
		return fmt.Errorf("WireGuard interface management requires administrator privileges")
	}

	// Check if WireGuard is installed
	if err := checkWireGuardInstalled(); err != nil {
		return fmt.Errorf("WireGuard not available: %w", err)
	}

	// Enable IP forwarding on Windows
	if err := enableWindowsIPForwarding(); err != nil {
		fmt.Printf("Warning: failed to enable IP forwarding: %v\n", err)
	}

	return nil
}

// NewManager creates a new interface manager for Windows
func NewManager() (*Manager, error) {
	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create WireGuard client: %w", err)
	}

	return &Manager{
		wgClient: *wgClient,
		impl:     &windowsImpl{},
	}, nil
}

// SetupEnvironment prepares the environment for WireGuard on Windows
func SetupEnvironment() error {
	return SetupWindowsEnvironment()
}
