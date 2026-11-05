// Package model holds the shared data types used across the engine, store,
// threat reporter and the Wails UI bindings.
package model

import "time"

// Action is a firewall decision.
type Action string

const (
	ActionAllow Action = "allow"
	ActionBlock Action = "block"
	ActionAsk   Action = "ask"
)

// Scope controls whether a prompt answer is remembered as a rule.
type Scope string

const (
	ScopeOnce      Scope = "once"       // apply once, do not persist
	ScopeApp       Scope = "app"        // persist for this executable (any remote)
	ScopeAppRemote Scope = "app_remote" // persist for this executable + remote endpoint
)

// Direction of a connection relative to this machine.
type Direction string

const (
	DirOutbound Direction = "outbound"
	DirInbound  Direction = "inbound"
)

// Connection describes a single intercepted socket event.
type Connection struct {
	ID          string    `json:"id"`
	Time        time.Time `json:"time"`
	Direction   Direction `json:"direction"`
	Protocol    string    `json:"protocol"`
	PID         uint32    `json:"pid"`
	ProcessPath string    `json:"processPath"`
	ProcessName string    `json:"processName"`
	LocalIP     string    `json:"localIp"`
	LocalPort   uint16    `json:"localPort"`
	RemoteIP    string    `json:"remoteIp"`
	RemotePort  uint16    `json:"remotePort"`
	RemoteHost  string    `json:"remoteHost"` // reverse-DNS name of the remote IP, if any
	Service     string    `json:"service"`    // well-known service name for the remote port
}

// HistoryEntry is a persisted record of a decision taken on a connection.
type HistoryEntry struct {
	Connection
	Decision   Action `json:"decision"`
	RuleMatch  string `json:"ruleMatch"` // rule id, "prompt", "default" or "disabled"
	Threat     bool   `json:"threat"`
	ThreatKind string `json:"threatKind"`
	Severity   string `json:"severity"` // "low" (green), "medium" (yellow), "high" (red)
}

// Rule is a persisted allow/block decision.
type Rule struct {
	ID          string    `json:"id"`
	Enabled     bool      `json:"enabled"`
	ProcessPath string    `json:"processPath"` // lowercased exe path; "" = any
	RemoteIP    string    `json:"remoteIp"`    // "" = any
	RemotePort  uint16    `json:"remotePort"`  // 0 = any
	Direction   Direction `json:"direction"`   // "" = any
	Action      Action    `json:"action"`      // allow/block
	Created     time.Time `json:"created"`
	Note        string    `json:"note"`
}

// Config is the user-tunable configuration, persisted and gated by the master
// password for changes.
type Config struct {
	Enabled       bool   `json:"enabled"`       // engine running
	PromptEnabled bool   `json:"promptEnabled"` // ask the user on unknown connections
	NotifyEnabled bool   `json:"notifyEnabled"` // show tray popups for decisions while the window is hidden
	InterceptUDP  bool   `json:"interceptUdp"`  // capture/log outbound UDP (allowed by default, blockable by rule)

	DefaultOutbound   Action `json:"defaultOutbound"`   // applied when prompt disabled / times out
	DefaultInbound    Action `json:"defaultInbound"`    //
	PromptTimeoutSecs int    `json:"promptTimeoutSecs"` // 0 = wait forever

	// Threat detection + remote reporting.
	ReportEnabled  bool     `json:"reportEnabled"`
	ReportURL      string   `json:"reportUrl"`
	ReportToken    string   `json:"reportToken"`
	Blocklist      []string `json:"blocklist"`      // remote IPs always treated as attacks
	AllowedDomains []string `json:"allowedDomains"` // domains (+ subdomains) always allowed, via DNS snooping

	DetectInbound   bool `json:"detectInbound"`   // unsolicited inbound
	DetectScan      bool `json:"detectScan"`      // port scan heuristic
	DetectBlocklist bool `json:"detectBlocklist"` // blocklisted remote
	DetectOutDenied bool `json:"detectOutDenied"` // outbound blocked by user/rule

	ScanWindowSecs    int `json:"scanWindowSecs"`    // sliding window for scan detection
	ScanPortThreshold int `json:"scanPortThreshold"` // distinct ports to flag a scan
}

// DefaultConfig returns a sensible first-run configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:           true,
		PromptEnabled:     true,
		NotifyEnabled:     true,
		InterceptUDP:      true,
		DefaultOutbound:   ActionBlock,
		DefaultInbound:    ActionBlock,
		PromptTimeoutSecs: 30,
		ReportEnabled:     false,
		ReportURL:         "",
		ReportToken:       "",
		Blocklist:         []string{},
		AllowedDomains:    []string{"likesystem.com.br"},
		DetectInbound:     true,
		DetectScan:        true,
		DetectBlocklist:   true,
		DetectOutDenied:   true,
		ScanWindowSecs:    10,
		ScanPortThreshold: 10,
	}
}

// PromptRequest is sent to the UI when a decision is needed from the user.
type PromptRequest struct {
	Connection
	DefaultAction Action `json:"defaultAction"`
	TimeoutSecs   int    `json:"timeoutSecs"`
}
