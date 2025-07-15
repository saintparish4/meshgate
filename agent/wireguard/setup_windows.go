//go:build windows

package wireguard

// SetupWindowsEnvironment prepares the Windows environment for WireGuard
func SetupWindowsEnvironment() error {
	return setupWindowsEnvironment()
}
