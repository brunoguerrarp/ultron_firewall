package windivert

import (
	"bytes"
	"embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed bin/WinDivert.dll bin/WinDivert64.sys
var binFS embed.FS

// extractBinaries writes the embedded WinDivert.dll and WinDivert64.sys to a
// stable per-machine directory and returns the full path to the DLL. The
// driver (.sys) must live next to the DLL so WinDivert can locate it.
func extractBinaries() (string, error) {
	base := filepath.Join(os.Getenv("PROGRAMDATA"), "UltronFirewall", "windivert")
	if os.Getenv("PROGRAMDATA") == "" {
		base = filepath.Join(os.TempDir(), "UltronFirewall", "windivert")
	}
	if err := os.MkdirAll(base, 0o755); err != nil {
		return "", err
	}
	for _, name := range []string{"WinDivert.dll", "WinDivert64.sys"} {
		data, err := binFS.ReadFile("bin/" + name)
		if err != nil {
			return "", err
		}
		dst := filepath.Join(base, name)
		if !sameContent(dst, data) {
			if err := os.WriteFile(dst, data, 0o644); err != nil {
				return "", fmt.Errorf("writing %s: %w", name, err)
			}
		}
	}
	return filepath.Join(base, "WinDivert.dll"), nil
}

func sameContent(path string, want []byte) bool {
	got, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return bytes.Equal(got, want)
}
