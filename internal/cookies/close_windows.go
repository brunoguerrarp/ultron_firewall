//go:build windows

package cookies

import (
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// browserImages are the process image names we close before wiping cookies.
var browserImages = []string{
	"chrome.exe",
	"msedge.exe",
	"brave.exe",
	"opera.exe",
	"opera_gx.exe",
	"vivaldi.exe",
	"firefox.exe",
}

// CloseBrowsers closes every running browser: first a graceful request (so the
// browser can flush and exit cleanly), then a forced kill for any that remain.
// It returns the image names it acted on. Browsers must be gone for their
// cookie files to become removable.
func CloseBrowsers() []string {
	var closed []string
	for _, img := range browserImages {
		if processRunning(img) {
			taskkill(img, false) // graceful (WM_CLOSE to the window tree)
			closed = append(closed, img)
		}
	}
	if len(closed) == 0 {
		return nil
	}
	// Wait up to ~3s for graceful exit.
	for i := 0; i < 10; i++ {
		time.Sleep(300 * time.Millisecond)
		stillOpen := false
		for _, img := range closed {
			if processRunning(img) {
				stillOpen = true
				break
			}
		}
		if !stillOpen {
			break
		}
	}
	// Force-kill whatever is still hanging on.
	for _, img := range closed {
		if processRunning(img) {
			taskkill(img, true)
		}
	}
	time.Sleep(500 * time.Millisecond) // let the OS release the file handles
	return closed
}

const createNoWindow = 0x08000000 // CREATE_NO_WINDOW: don't flash a console

func taskkill(image string, force bool) {
	args := []string{"/IM", image, "/T"}
	if force {
		args = append(args, "/F")
	}
	cmd := exec.Command("taskkill", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	_ = cmd.Run()
}

func processRunning(image string) bool {
	cmd := exec.Command("tasklist", "/FI", "IMAGENAME eq "+image, "/NH")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), strings.ToLower(image))
}
