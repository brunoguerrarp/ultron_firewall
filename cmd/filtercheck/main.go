//go:build windows

// Command filtercheck validates candidate WinDivert SOCKET-layer filter strings
// in user mode (no driver/admin needed), to diagnose WinDivertOpen parameter
// errors. Run: go run ./cmd/filtercheck
package main

import (
	"fmt"

	"ultron_firewall/internal/windivert"
)

func main() {
	candidates := []string{
		"event == CONNECT or event == ACCEPT",
		"(event == CONNECT) or (event == ACCEPT)",
		"event = CONNECT or event = ACCEPT",
		"event == CONNECT",
		"event == ACCEPT",
		"tcp or udp",
		"outbound or inbound",
		"true",
	}
	fmt.Println("Validating SOCKET-layer filters (layer =", windivert.LayerSocket, ")")
	for _, f := range candidates {
		if err := windivert.CompileFilter(f, windivert.LayerSocket); err != nil {
			fmt.Printf("  FAIL  %-45q -> %v\n", f, err)
		} else {
			fmt.Printf("  OK    %-45q\n", f)
		}
	}
}
