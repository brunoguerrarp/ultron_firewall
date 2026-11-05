package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	wrt "github.com/wailsapp/wails/v2/pkg/runtime"

	"ultron_firewall/internal/engine"
	"ultron_firewall/internal/model"
	"ultron_firewall/internal/store"
	"ultron_firewall/internal/threat"
)

// App is the Wails-bound application object.
type App struct {
	ctx context.Context

	store  *store.Store
	engine *engine.Engine
	threat *threat.Service

	mu       sync.Mutex
	unlocked bool
	startErr string
}

// UIState is the snapshot the frontend uses to render.
type UIState struct {
	Running       bool   `json:"running"`
	EngineError   string `json:"engineError"`
	NeedsSetup    bool   `json:"needsSetup"`
	Unlocked      bool   `json:"unlocked"`
	PromptEnabled bool   `json:"promptEnabled"`
	Enabled       bool   `json:"enabled"`
}

// NewApp creates the application object.
func NewApp() *App { return &App{} }

func dataDir() string {
	base := os.Getenv("PROGRAMDATA")
	if base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "UltronFirewall")
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

// startup wires the store, engine and reporter, and begins interception if the
// saved configuration has the firewall enabled.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	st, err := store.Open(filepath.Join(dataDir(), "ultron.db"))
	if err != nil {
		a.startErr = fmt.Sprintf("failed to open database: %v", err)
		log.Printf("startup: %s", a.startErr)
		return
	}
	a.store = st
	a.threat = threat.New()
	a.engine = engine.New(st, a.threat)

	a.engine.OnPrompt = func(p model.PromptRequest) {
		wrt.EventsEmit(a.ctx, "prompt:new", p)
	}
	a.engine.OnPromptResolved = func(id string) {
		wrt.EventsEmit(a.ctx, "prompt:resolved", id)
	}
	a.engine.OnHistory = func(h model.HistoryEntry) {
		wrt.EventsEmit(a.ctx, "history:new", h)
	}
	a.engine.OnStatus = func(running bool, errMsg string) {
		a.mu.Lock()
		a.startErr = errMsg
		a.mu.Unlock()
		wrt.EventsEmit(a.ctx, "engine:status", map[string]any{
			"running": running,
			"error":   errMsg,
		})
	}

	if st.Config().Enabled {
		go func() {
			if err := a.engine.Start(); err != nil {
				log.Printf("startup: engine start: %v", err)
			}
		}()
	}
}

func (a *App) shutdown(ctx context.Context) {
	if a.engine != nil {
		a.engine.Stop()
	}
	if a.threat != nil {
		a.threat.Stop()
	}
	if a.store != nil {
		_ = a.store.Close()
	}
}

func (a *App) ready() error {
	if a.store == nil {
		return errors.New("firewall not initialized: " + a.startErr)
	}
	return nil
}

func (a *App) isUnlocked() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.unlocked
}

func (a *App) requireUnlock() error {
	if err := a.ready(); err != nil {
		return err
	}
	// If no master password is set yet, changes are allowed (setup phase).
	if !a.store.HasAuth() {
		return nil
	}
	if !a.isUnlocked() {
		return errors.New("locked: enter the master password to make changes")
	}
	return nil
}

// ---- State / auth ----

// GetState returns the current UI state snapshot.
func (a *App) GetState() UIState {
	s := UIState{}
	if a.store == nil {
		s.EngineError = a.startErr
		return s
	}
	cfg := a.store.Config()
	s.Running = a.engine.Running()
	a.mu.Lock()
	s.EngineError = a.startErr
	s.Unlocked = a.unlocked
	a.mu.Unlock()
	s.NeedsSetup = !a.store.HasAuth()
	s.PromptEnabled = cfg.PromptEnabled
	s.Enabled = cfg.Enabled
	return s
}

// SetMasterPassword sets or changes the master password. When none exists yet,
// current is ignored.
func (a *App) SetMasterPassword(current, newPass string) error {
	if err := a.ready(); err != nil {
		return err
	}
	if len(newPass) < 4 {
		return errors.New("password must be at least 4 characters")
	}
	if a.store.HasAuth() {
		if bcrypt.CompareHashAndPassword(a.store.AuthHash(), []byte(current)) != nil {
			return errors.New("current password is incorrect")
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if err := a.store.SetAuthHash(hash); err != nil {
		return err
	}
	a.mu.Lock()
	a.unlocked = true
	a.mu.Unlock()
	return nil
}

// Unlock verifies the master password and unlocks changes.
func (a *App) Unlock(pass string) error {
	if err := a.ready(); err != nil {
		return err
	}
	if !a.store.HasAuth() {
		return errors.New("no master password set")
	}
	if bcrypt.CompareHashAndPassword(a.store.AuthHash(), []byte(pass)) != nil {
		return errors.New("incorrect password")
	}
	a.mu.Lock()
	a.unlocked = true
	a.mu.Unlock()
	return nil
}

// Lock re-locks changes.
func (a *App) Lock() {
	a.mu.Lock()
	a.unlocked = false
	a.mu.Unlock()
}

// ---- Config ----

// GetConfig returns the configuration (the report token is hidden while locked).
func (a *App) GetConfig() (model.Config, error) {
	if err := a.ready(); err != nil {
		return model.Config{}, err
	}
	cfg := a.store.Config()
	if !a.isUnlocked() {
		cfg.ReportToken = ""
	}
	return cfg, nil
}

// SaveConfig persists configuration changes (requires unlock) and applies the
// enabled flag to the running engine.
func (a *App) SaveConfig(cfg model.Config) error {
	if err := a.requireUnlock(); err != nil {
		return err
	}
	// Preserve the stored token if the UI sent it back blank.
	old := a.store.Config()
	if cfg.ReportToken == "" {
		cfg.ReportToken = old.ReportToken
	}
	if err := a.store.SetConfig(cfg); err != nil {
		return err
	}
	a.applyEnabled(cfg.Enabled)
	return nil
}

// SetEnabled turns interception on or off (requires unlock).
func (a *App) SetEnabled(on bool) error {
	if err := a.requireUnlock(); err != nil {
		return err
	}
	cfg := a.store.Config()
	cfg.Enabled = on
	if err := a.store.SetConfig(cfg); err != nil {
		return err
	}
	a.applyEnabled(on)
	return nil
}

func (a *App) applyEnabled(on bool) {
	if on {
		go func() {
			if err := a.engine.Start(); err != nil {
				log.Printf("engine start: %v", err)
			}
		}()
	} else {
		go a.engine.Stop()
	}
}

// ---- Rules ----

// ListRules returns all persisted rules.
func (a *App) ListRules() ([]model.Rule, error) {
	if err := a.ready(); err != nil {
		return nil, err
	}
	rules, err := a.store.ListRules()
	if rules == nil {
		rules = []model.Rule{}
	}
	return rules, err
}

// SaveRule creates or updates a rule (requires unlock).
func (a *App) SaveRule(r model.Rule) error {
	if err := a.requireUnlock(); err != nil {
		return err
	}
	if r.ID == "" {
		r.Created = time.Now()
	}
	if r.Action != model.ActionAllow && r.Action != model.ActionBlock {
		return errors.New("action must be allow or block")
	}
	if r.ID == "" {
		r.ID = fmt.Sprintf("rule-%d", time.Now().UnixNano())
	}
	return a.store.PutRule(r)
}

// DeleteRule removes a rule (requires unlock).
func (a *App) DeleteRule(id string) error {
	if err := a.requireUnlock(); err != nil {
		return err
	}
	return a.store.DeleteRule(id)
}

// ---- History ----

// ListHistory returns up to limit history entries, newest first.
func (a *App) ListHistory(limit int) ([]model.HistoryEntry, error) {
	if err := a.ready(); err != nil {
		return nil, err
	}
	h, err := a.store.ListHistory(limit)
	if h == nil {
		h = []model.HistoryEntry{}
	}
	return h, err
}

// ClearHistory deletes all history (requires unlock).
func (a *App) ClearHistory() error {
	if err := a.requireUnlock(); err != nil {
		return err
	}
	return a.store.ClearHistory()
}

// ---- Prompts ----

// PendingPrompts returns connections awaiting a decision.
func (a *App) PendingPrompts() ([]model.Connection, error) {
	if err := a.ready(); err != nil {
		return nil, err
	}
	p := a.engine.PendingPrompts()
	if p == nil {
		p = []model.Connection{}
	}
	return p, nil
}

// RespondPrompt answers a pending prompt. action is "allow"/"block"; scope is
// "once"/"app"/"app_remote".
func (a *App) RespondPrompt(id, action, scope string) bool {
	if a.engine == nil {
		return false
	}
	act := model.Action(action)
	if act != model.ActionAllow && act != model.ActionBlock {
		return false
	}
	sc := model.Scope(scope)
	switch sc {
	case model.ScopeOnce, model.ScopeApp, model.ScopeAppRemote:
	default:
		sc = model.ScopeOnce
	}
	return a.engine.Respond(id, act, sc)
}

// ---- Reporting ----

// TestReport sends a synthetic report to the configured endpoint (requires
// unlock) so the user can validate connectivity.
func (a *App) TestReport() error {
	if err := a.requireUnlock(); err != nil {
		return err
	}
	cfg := a.store.Config()
	if cfg.ReportURL == "" {
		return errors.New("no report URL configured")
	}
	cfg.ReportEnabled = true
	entry := model.HistoryEntry{
		Connection: model.Connection{
			ID:          fmt.Sprintf("test-%d", time.Now().UnixNano()),
			Time:        time.Now(),
			Direction:   model.DirInbound,
			Protocol:    "tcp",
			ProcessName: "ultron-test",
			LocalIP:     "0.0.0.0",
			LocalPort:   0,
			RemoteIP:    "203.0.113.1",
			RemotePort:  12345,
		},
		Decision: model.ActionBlock,
	}
	// Force the blocklist category for a deterministic test payload.
	cfg.DetectBlocklist = true
	cfg.Blocklist = append(cfg.Blocklist, "203.0.113.1")
	a.threat.Inspect(&entry, cfg)
	if !entry.Threat {
		return errors.New("test payload was not classified; check detection settings")
	}
	return nil
}
