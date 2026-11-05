//go:build windows

// Package engine is the core of the firewall: it captures socket events via
// WinDivert, decides allow/block (by rule, by prompting the user, or by the
// configured default), enforces the decision, records history and feeds the
// threat reporter.
package engine

import (
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"ultron_firewall/internal/model"
	"ultron_firewall/internal/store"
	"ultron_firewall/internal/threat"
	"ultron_firewall/internal/windivert"
)

// socketFilter captures outbound connect and inbound accept socket events.
const socketFilter = "event == CONNECT or event == ACCEPT"

type decision struct {
	action model.Action
	scope  model.Scope
}

type pending struct {
	conn   *model.Connection
	respCh chan decision
}

// Engine drives interception and decision-making.
type Engine struct {
	store  *store.Store
	threat *threat.Service

	mu      sync.Mutex
	handle  *windivert.Handle
	running bool
	pending map[string]*pending

	stopCh chan struct{}
	wg     sync.WaitGroup

	// Callbacks wired by the application layer to reach the UI.
	OnPrompt         func(model.PromptRequest)
	OnPromptResolved func(id string)
	OnHistory        func(model.HistoryEntry)
	OnStatus         func(running bool, errMsg string)
}

// New creates an engine.
func New(s *store.Store, t *threat.Service) *Engine {
	return &Engine{
		store:   s,
		threat:  t,
		pending: make(map[string]*pending),
	}
}

// Running reports whether interception is active.
func (e *Engine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

// Start opens the WinDivert handle and begins intercepting. Requires admin.
func (e *Engine) Start() error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return nil
	}
	h, err := windivert.Open(socketFilter, windivert.LayerSocket, 0, 0)
	if err != nil {
		e.mu.Unlock()
		e.status(false, err.Error())
		return err
	}
	e.handle = h
	e.running = true
	e.stopCh = make(chan struct{})
	e.mu.Unlock()

	e.wg.Add(1)
	go e.recvLoop(h)
	e.status(true, "")
	return nil
}

// Stop halts interception and releases the handle.
func (e *Engine) Stop() {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return
	}
	e.running = false
	h := e.handle
	close(e.stopCh)
	e.mu.Unlock()

	if h != nil {
		_ = h.Shutdown(windivert.ShutdownBoth)
	}
	e.wg.Wait()
	if h != nil {
		_ = h.Close()
	}
	e.mu.Lock()
	e.handle = nil
	e.mu.Unlock()
	e.status(false, "")
}

func (e *Engine) recvLoop(h *windivert.Handle) {
	defer e.wg.Done()
	for {
		var addr windivert.Address
		if err := h.Recv(&addr); err != nil {
			select {
			case <-e.stopCh:
				return // expected: shut down
			default:
				log.Printf("engine: recv error: %v", err)
				return
			}
		}
		a := addr // per-event copy; each handler owns its address
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			e.handleEvent(&a)
		}()
	}
}

func (e *Engine) handleEvent(addr *windivert.Address) {
	conn := e.buildConn(addr)
	cfg := e.store.Config()

	// Allow loopback silently to avoid breaking local IPC and the UI itself.
	if addr.Loopback() {
		_ = e.handle.Allow(addr)
		return
	}

	action := model.ActionAllow
	ruleMatch := "default"

	switch {
	case cfg.DetectBlocklist && e.threat.IsBlocklisted(conn.RemoteIP, cfg):
		action = model.ActionBlock
		ruleMatch = "blocklist"
	default:
		if r := e.matchRule(conn); r != nil {
			action = r.Action
			ruleMatch = r.ID
		} else if cfg.PromptEnabled {
			action = e.prompt(conn, cfg)
			ruleMatch = "prompt"
		} else {
			action = e.defaultAction(conn.Direction, cfg)
			ruleMatch = "default"
		}
	}

	// Enforce.
	if action == model.ActionAllow {
		if err := e.handle.Allow(addr); err != nil {
			log.Printf("engine: allow failed: %v", err)
		}
	}
	// Block == do not re-inject; the pended operation is dropped.

	entry := model.HistoryEntry{
		Connection: *conn,
		Decision:   action,
		RuleMatch:  ruleMatch,
	}
	e.threat.Inspect(&entry, cfg)

	if err := e.store.AppendHistory(entry); err != nil {
		log.Printf("engine: append history: %v", err)
	}
	if e.OnHistory != nil {
		e.OnHistory(entry)
	}
}

// prompt asks the user and (optionally) persists the answer as a rule.
func (e *Engine) prompt(conn *model.Connection, cfg model.Config) model.Action {
	def := e.defaultAction(conn.Direction, cfg)

	p := &pending{conn: conn, respCh: make(chan decision, 1)}
	e.mu.Lock()
	e.pending[conn.ID] = p
	e.mu.Unlock()

	if e.OnPrompt != nil {
		e.OnPrompt(model.PromptRequest{
			Connection:    *conn,
			DefaultAction: def,
			TimeoutSecs:   cfg.PromptTimeoutSecs,
		})
	}

	var d decision
	if cfg.PromptTimeoutSecs > 0 {
		timer := time.NewTimer(time.Duration(cfg.PromptTimeoutSecs) * time.Second)
		defer timer.Stop()
		select {
		case d = <-p.respCh:
		case <-timer.C:
			d = decision{action: def, scope: model.ScopeOnce}
		case <-e.stopCh:
			d = decision{action: def, scope: model.ScopeOnce}
		}
	} else {
		select {
		case d = <-p.respCh:
		case <-e.stopCh:
			d = decision{action: def, scope: model.ScopeOnce}
		}
	}

	e.mu.Lock()
	delete(e.pending, conn.ID)
	e.mu.Unlock()
	if e.OnPromptResolved != nil {
		e.OnPromptResolved(conn.ID)
	}

	if d.scope == model.ScopeApp || d.scope == model.ScopeAppRemote {
		e.persistRule(conn, d.action, d.scope)
	}
	return d.action
}

// Respond resolves a pending prompt. Returns false if no such prompt exists.
func (e *Engine) Respond(id string, action model.Action, scope model.Scope) bool {
	e.mu.Lock()
	p := e.pending[id]
	e.mu.Unlock()
	if p == nil {
		return false
	}
	select {
	case p.respCh <- decision{action: action, scope: scope}:
		return true
	default:
		return false
	}
}

// PendingPrompts returns the connections currently awaiting a decision.
func (e *Engine) PendingPrompts() []model.Connection {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]model.Connection, 0, len(e.pending))
	for _, p := range e.pending {
		out = append(out, *p.conn)
	}
	return out
}

func (e *Engine) persistRule(conn *model.Connection, action model.Action, scope model.Scope) {
	r := model.Rule{
		ID:          uuid.NewString(),
		Enabled:     true,
		ProcessPath: strings.ToLower(conn.ProcessPath),
		Direction:   conn.Direction,
		Action:      action,
		Created:     time.Now(),
		Note:        "created from prompt",
	}
	if scope == model.ScopeAppRemote {
		r.RemoteIP = conn.RemoteIP
		r.RemotePort = conn.RemotePort
	}
	if err := e.store.PutRule(r); err != nil {
		log.Printf("engine: persist rule: %v", err)
	}
}

func (e *Engine) matchRule(conn *model.Connection) *model.Rule {
	rules, err := e.store.ListRules()
	if err != nil {
		log.Printf("engine: list rules: %v", err)
		return nil
	}
	cp := strings.ToLower(conn.ProcessPath)
	var allow *model.Rule
	for i := range rules {
		r := rules[i]
		if !r.Enabled {
			continue
		}
		if r.ProcessPath != "" && r.ProcessPath != cp {
			continue
		}
		if r.RemoteIP != "" && r.RemoteIP != conn.RemoteIP {
			continue
		}
		if r.RemotePort != 0 && r.RemotePort != conn.RemotePort {
			continue
		}
		if r.Direction != "" && r.Direction != conn.Direction {
			continue
		}
		if r.Action == model.ActionBlock {
			return &rules[i] // block wins immediately
		}
		if allow == nil {
			allow = &rules[i]
		}
	}
	return allow
}

func (e *Engine) defaultAction(dir model.Direction, cfg model.Config) model.Action {
	if dir == model.DirInbound {
		return normalizeAction(cfg.DefaultInbound)
	}
	return normalizeAction(cfg.DefaultOutbound)
}

func normalizeAction(a model.Action) model.Action {
	if a == model.ActionAllow {
		return model.ActionAllow
	}
	return model.ActionBlock
}

func (e *Engine) buildConn(addr *windivert.Address) *model.Connection {
	s := addr.Socket()
	dir := model.DirOutbound
	if addr.Event() == windivert.EventSocketAccept {
		dir = model.DirInbound
	}
	path := processPath(s.ProcessID)
	return &model.Connection{
		ID:          uuid.NewString(),
		Time:        time.Now(),
		Direction:   dir,
		Protocol:    protocolName(s.Protocol),
		PID:         s.ProcessID,
		ProcessPath: path,
		ProcessName: baseName(path),
		LocalIP:     addr.LocalIP(),
		LocalPort:   s.LocalPort,
		RemoteIP:    addr.RemoteIP(),
		RemotePort:  s.RemotePort,
	}
}

func baseName(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Base(p)
}

func protocolName(p uint8) string {
	switch p {
	case windivert.ProtoTCP:
		return "tcp"
	case windivert.ProtoUDP:
		return "udp"
	default:
		return "other"
	}
}

func (e *Engine) status(running bool, errMsg string) {
	if e.OnStatus != nil {
		e.OnStatus(running, errMsg)
	}
}
