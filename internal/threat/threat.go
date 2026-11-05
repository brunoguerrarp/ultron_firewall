// Package threat classifies connections as attack attempts and reports them to
// a remote server via HTTP POST. The endpoint, token and which categories are
// active are all driven by the user configuration.
package threat

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"ultron_firewall/internal/model"
)

// Categories of attack.
const (
	CatInbound   = "inbound_unsolicited"
	CatScan      = "port_scan"
	CatBlocklist = "blocklist"
	CatOutDenied = "outbound_denied"
)

// Endpoint is a host:port pair in a report.
type Endpoint struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

// Report is the JSON payload POSTed to the remote server. The shape is kept
// explicit and easy to adjust once the server contract is known.
type Report struct {
	EventID   string `json:"event_id"`
	Timestamp string `json:"timestamp"`
	Host      string `json:"host"`
	Category  string `json:"category"`
	Direction string `json:"direction"`
	Protocol  string `json:"protocol"`
	Decision  string `json:"decision"`
	Detail    string `json:"detail"`
	Process   struct {
		PID  uint32 `json:"pid"`
		Path string `json:"path"`
		Name string `json:"name"`
	} `json:"process"`
	Local  Endpoint `json:"local"`
	Remote Endpoint `json:"remote"`
}

// Service performs detection and asynchronous reporting.
type Service struct {
	client   *http.Client
	hostname string

	mu    sync.Mutex
	scans map[string]*scanState

	queue  chan queued
	stopCh chan struct{}
	wg     sync.WaitGroup
}

type queued struct {
	report Report
	url    string
	token  string
}

type scanState struct {
	ports map[uint16]time.Time
}

// New creates a reporting service and starts its worker.
func New() *Service {
	host, _ := os.Hostname()
	s := &Service{
		client:   &http.Client{Timeout: 10 * time.Second},
		hostname: host,
		scans:    make(map[string]*scanState),
		queue:    make(chan queued, 256),
		stopCh:   make(chan struct{}),
	}
	s.wg.Add(1)
	go s.worker()
	return s
}

// Stop shuts the worker down.
func (s *Service) Stop() {
	close(s.stopCh)
	s.wg.Wait()
}

// Inspect classifies a decided connection. It mutates the history entry in
// place (setting Threat/ThreatKind) and, when reporting is enabled, enqueues a
// report. The blocklist match is also returned so the caller can force a block.
func (s *Service) Inspect(e *model.HistoryEntry, cfg model.Config) {
	kind, detail := s.classify(e, cfg)
	if kind == "" {
		return
	}
	e.Threat = true
	e.ThreatKind = kind

	if !cfg.ReportEnabled || cfg.ReportURL == "" {
		return
	}
	r := Report{
		EventID:   e.ID,
		Timestamp: e.Time.UTC().Format(time.RFC3339Nano),
		Host:      s.hostname,
		Category:  kind,
		Direction: string(e.Direction),
		Protocol:  e.Protocol,
		Decision:  string(e.Decision),
		Detail:    detail,
		Local:     Endpoint{IP: e.LocalIP, Port: e.LocalPort},
		Remote:    Endpoint{IP: e.RemoteIP, Port: e.RemotePort},
	}
	r.Process.PID = e.PID
	r.Process.Path = e.ProcessPath
	r.Process.Name = e.ProcessName

	select {
	case s.queue <- queued{report: r, url: cfg.ReportURL, token: cfg.ReportToken}:
	default:
		log.Printf("threat: report queue full, dropping event %s", e.ID)
	}
}

// IsBlocklisted reports whether ip is on the configured blocklist.
func (s *Service) IsBlocklisted(ip string, cfg model.Config) bool {
	for _, b := range cfg.Blocklist {
		if b != "" && b == ip {
			return true
		}
	}
	return false
}

func (s *Service) classify(e *model.HistoryEntry, cfg model.Config) (kind, detail string) {
	// Blocklist has priority.
	if cfg.DetectBlocklist && s.IsBlocklisted(e.RemoteIP, cfg) {
		return CatBlocklist, "remote address is on the blocklist"
	}
	// Port scan: a single remote touching many distinct local ports quickly.
	if cfg.DetectScan && e.Direction == model.DirInbound {
		if n := s.recordScan(e.RemoteIP, e.LocalPort, cfg); n >= cfg.ScanPortThreshold && cfg.ScanPortThreshold > 0 {
			return CatScan, "many distinct ports targeted in a short window"
		}
	}
	// Unsolicited inbound that was blocked.
	if cfg.DetectInbound && e.Direction == model.DirInbound && e.Decision == model.ActionBlock {
		return CatInbound, "unsolicited inbound connection was blocked"
	}
	// Outbound connection the user/rules denied.
	if cfg.DetectOutDenied && e.Direction == model.DirOutbound && e.Decision == model.ActionBlock {
		return CatOutDenied, "outbound connection was denied"
	}
	return "", ""
}

// recordScan tracks distinct local ports hit by remoteIP within the window and
// returns the current distinct count.
func (s *Service) recordScan(remoteIP string, localPort uint16, cfg model.Config) int {
	if remoteIP == "" {
		return 0
	}
	window := time.Duration(cfg.ScanWindowSecs) * time.Second
	if window <= 0 {
		window = 10 * time.Second
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.scans[remoteIP]
	if st == nil {
		st = &scanState{ports: make(map[uint16]time.Time)}
		s.scans[remoteIP] = st
	}
	st.ports[localPort] = now
	for p, t := range st.ports {
		if now.Sub(t) > window {
			delete(st.ports, p)
		}
	}
	return len(st.ports)
}

func (s *Service) worker() {
	defer s.wg.Done()
	for {
		select {
		case <-s.stopCh:
			return
		case q := <-s.queue:
			s.post(q)
		}
	}
}

func (s *Service) post(q queued) {
	body, err := json.Marshal(q.report)
	if err != nil {
		log.Printf("threat: marshal: %v", err)
		return
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-s.stopCh:
				return
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, q.url, bytes.NewReader(body))
		if err != nil {
			cancel()
			log.Printf("threat: build request: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "UltronFirewall")
		if q.token != "" {
			req.Header.Set("Authorization", "Bearer "+q.token)
			req.Header.Set("X-Ultron-Token", q.token)
		}
		resp, err := s.client.Do(req)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return
		}
		lastErr = &httpError{code: resp.StatusCode}
	}
	if lastErr != nil {
		log.Printf("threat: report failed for %s: %v", q.report.EventID, lastErr)
	}
}

type httpError struct{ code int }

func (e *httpError) Error() string { return http.StatusText(e.code) }
