// Package cookies removes browser cookie stores from disk. It targets
// Chromium-based browsers (Chrome, Edge, Brave, Vivaldi, Opera, Chromium) and
// Firefox, across all of their profiles.
//
// Deletion works by removing the cookie SQLite database files (and their WAL/
// journal sidecars). This requires the browser to be closed: while it runs it
// holds an exclusive lock and the file cannot be removed. Any browser found
// locked is reported so the caller can ask the user to close it and retry.
package cookies

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Result summarizes a cleaning run.
type Result struct {
	Removed  int      `json:"removed"`  // cookie database files deleted
	Browsers []string `json:"browsers"` // browsers something was cleaned from
	Locked   []string `json:"locked"`   // browsers whose files were locked (still open)
}

// Summary renders a human-readable (Portuguese) one-line summary.
func (r Result) Summary() string {
	if r.Removed == 0 && len(r.Locked) == 0 {
		return "Nenhum cookie encontrado para limpar."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d arquivo(s) de cookies removido(s)", r.Removed)
	if len(r.Browsers) > 0 {
		fmt.Fprintf(&b, " de: %s", strings.Join(r.Browsers, ", "))
	}
	b.WriteString(".")
	if len(r.Locked) > 0 {
		fmt.Fprintf(&b, " ⚠ Feche e clique de novo para limpar: %s.", strings.Join(r.Locked, ", "))
	}
	return b.String()
}

type browser struct {
	name string
	root string // Chromium "User Data" root
}

// CleanAll removes every cookie store it can find and returns a summary.
func CleanAll() Result {
	var res Result
	for _, b := range chromiumBrowsers() {
		files := chromiumCookieFiles(b.root)
		if len(files) == 0 {
			continue
		}
		cleaned, locked := 0, false
		for _, f := range files {
			n, lk := removeDBFamily(f)
			cleaned += n
			locked = locked || lk
		}
		if cleaned > 0 {
			res.Removed += cleaned
			res.Browsers = appendUniq(res.Browsers, b.name)
		}
		if locked {
			res.Locked = appendUniq(res.Locked, b.name)
		}
	}
	for _, f := range firefoxCookieFiles() {
		n, lk := removeDBFamily(f)
		if n > 0 {
			res.Removed += n
			res.Browsers = appendUniq(res.Browsers, "Firefox")
		}
		if lk {
			res.Locked = appendUniq(res.Locked, "Firefox")
		}
	}
	return res
}

func chromiumBrowsers() []browser {
	la := os.Getenv("LOCALAPPDATA")
	ap := os.Getenv("APPDATA")
	cands := []browser{
		{"Google Chrome", filepath.Join(la, "Google", "Chrome", "User Data")},
		{"Microsoft Edge", filepath.Join(la, "Microsoft", "Edge", "User Data")},
		{"Brave", filepath.Join(la, "BraveSoftware", "Brave-Browser", "User Data")},
		{"Vivaldi", filepath.Join(la, "Vivaldi", "User Data")},
		{"Chromium", filepath.Join(la, "Chromium", "User Data")},
		{"Opera", filepath.Join(ap, "Opera Software", "Opera Stable")},
		{"Opera GX", filepath.Join(ap, "Opera Software", "Opera GX Stable")},
	}
	var out []browser
	for _, c := range cands {
		if c.root != "" && dirExists(c.root) {
			out = append(out, c)
		}
	}
	return out
}

// chromiumCookieFiles finds the cookie DBs under a User Data root: both the
// modern "<Profile>/Network/Cookies" and the legacy "<Profile>/Cookies", for
// every profile directory (Default, Profile 1, ...), plus the root itself for
// single-profile layouts like Opera.
func chromiumCookieFiles(root string) []string {
	var files []string
	add := func(p string) {
		if fileExists(p) {
			files = append(files, p)
		}
	}
	add(filepath.Join(root, "Network", "Cookies"))
	add(filepath.Join(root, "Cookies"))
	if entries, err := os.ReadDir(root); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			p := filepath.Join(root, e.Name())
			add(filepath.Join(p, "Network", "Cookies"))
			add(filepath.Join(p, "Cookies"))
		}
	}
	return dedup(files)
}

func firefoxCookieFiles() []string {
	ap := os.Getenv("APPDATA")
	if ap == "" {
		return nil
	}
	matches, _ := filepath.Glob(filepath.Join(ap, "Mozilla", "Firefox", "Profiles", "*", "cookies.sqlite"))
	return matches
}

// removeDBFamily deletes a SQLite DB file and its WAL/journal sidecars. It
// returns 1 if the main file was deleted and whether any file was locked (the
// browser is still open).
func removeDBFamily(path string) (removed int, locked bool) {
	for _, p := range []string{path, path + "-journal", path + "-wal", path + "-shm"} {
		if !fileExists(p) {
			continue
		}
		if err := os.Remove(p); err != nil {
			if isLocked(err) {
				locked = true
			}
			continue
		}
		if p == path {
			removed = 1
		}
	}
	return removed, locked
}

// isLocked reports whether an error means the file is held open by a running
// process (Windows sharing/lock/access-denied errors).
func isLocked(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case 5, 32, 33: // ACCESS_DENIED, SHARING_VIOLATION, LOCK_VIOLATION
			return true
		}
	}
	return errors.Is(err, os.ErrPermission) ||
		strings.Contains(strings.ToLower(err.Error()), "being used by another process")
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func appendUniq(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func dedup(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
