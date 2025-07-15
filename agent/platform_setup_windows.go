package main

import "github.com/saintparish4/meshgate/agent/wireguard"

func setupPlatformEnvironment() error {
	return wireguard.SetupWindowsEnvironment()
}
