package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
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
	hidden   bool
	quitting bool
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
// setupLogging routes logs (and recovered-panic traces) to a file, since a GUI
// build has no visible console. Path: %ProgramData%\UltronFirewall\ultron.log
func setupLogging() string {
	path := filepath.Join(dataDir(), "ultron.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return ""
	}
	log.SetOutput(f)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Printf("==== Ultron Firewall started ====")
	return path
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	setupLogging()

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
		a.notifyPrompt(p)
	}
	a.engine.OnPromptResolved = func(id string) {
		wrt.EventsEmit(a.ctx, "prompt:resolved", id)
	}
	a.engine.OnHistory = func(h model.HistoryEntry) {
		wrt.EventsEmit(a.ctx, "history:new", h)
		a.notifyDecision(h)
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

	a.initToast()
	go a.runTray()

	if st.Config().Enabled {
		go func() {
			if err := a.engine.Start(); err != nil {
				log.Printf("startup: engine start: %v", err)
			}
		}()
	}
}

// setHidden records whether the window is hidden (running in the tray). Prompts
// still happen in the background; we just alert the user with a popup so they
// can open the panel and decide.
func (a *App) setHidden(h bool) {
	a.mu.Lock()
	a.hidden = h
	a.mu.Unlock()
}

func (a *App) isHidden() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.hidden
}

// onBeforeClose intercepts the window close: instead of quitting, Ultron hides
// to the system tray and keeps protecting in the background. Returning true
// tells Wails to prevent the default close/quit. It is panic-guarded and always
// returns true, so a failure in the hide path can never let the app quit.
func (a *App) onBeforeClose(ctx context.Context) (prevent bool) {
	a.mu.Lock()
	quitting := a.quitting
	a.mu.Unlock()
	if quitting {
		// A deliberate, password-authorized quit: let the app actually close.
		log.Printf("onBeforeClose: authorized quit, allowing close")
		return false
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("onBeforeClose: recovered: %v", r)
		}
		prevent = true // closing the window just hides to tray
	}()
	log.Printf("onBeforeClose: hiding window to tray")
	wrt.WindowHide(ctx)
	a.setHidden(true)
	a.toast("Ultron Firewall", "Continua protegendo em segundo plano. Clique no ícone da bandeja para reabrir.")
	return true
}

// notifyPrompt alerts the user about a connection awaiting a decision while the
// window is hidden, so they can open the panel and respond.
func (a *App) notifyPrompt(p model.PromptRequest) {
	if !a.isHidden() || a.store == nil || !a.store.Config().NotifyEnabled {
		return
	}
	who := p.ProcessName
	if who == "" {
		if p.PID != 0 {
			who = fmt.Sprintf("PID %d", p.PID)
		} else {
			who = "Um processo"
		}
	}
	dest := p.RemoteIP
	if p.RemoteHost != "" {
		dest = p.RemoteHost
	}
	a.toast("🔔 Conexão aguardando decisão",
		fmt.Sprintf("%s → %s:%d — abra o Ultron para liberar ou bloquear.", who, dest, p.RemotePort))
}

// TestToast shows a sample notification so the user can confirm popups work.
func (a *App) TestToast() {
	a.toast("Ultron Firewall", "Notificação de teste — se você está vendo isto, os popups funcionam. ✅")
}

// notifyDecision shows a tray popup for a decision while the window is hidden.
func (a *App) notifyDecision(h model.HistoryEntry) {
	if !a.isHidden() || a.store == nil || !a.store.Config().NotifyEnabled {
		return
	}
	who := h.ProcessName
	if who == "" {
		if h.PID != 0 {
			who = fmt.Sprintf("PID %d", h.PID)
		} else {
			who = "processo desconhecido"
		}
	}
	dest := h.RemoteIP
	if h.RemoteHost != "" {
		dest = h.RemoteHost
	}
	title := "✅ Liberado"
	if h.Decision == model.ActionBlock {
		title = "🚫 Bloqueado"
	}
	if h.Threat {
		title = "⚠ Ameaça: " + h.ThreatKind
	}
	a.toast(title, fmt.Sprintf("%s → %s:%d", who, dest, h.RemotePort))
}

func (a *App) shutdown(ctx context.Context) {
	log.Printf("shutdown: app terminating")
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

// ---- Window / lifecycle ----

// ShowWindow brings the window back from the tray.
func (a *App) ShowWindow() {
	if a.ctx == nil {
		return
	}
	log.Printf("ShowWindow: restoring window from tray")
	wrt.WindowShow(a.ctx)
	wrt.WindowUnminimise(a.ctx)
	a.setHidden(false)
}

// QuitApp fully terminates Ultron. Requires the master password (unlock). Sets
// the quitting flag so onBeforeClose allows the close instead of hiding.
func (a *App) QuitApp() error {
	if err := a.requireUnlock(); err != nil {
		return err
	}
	a.mu.Lock()
	a.quitting = true
	a.mu.Unlock()
	log.Printf("QuitApp: authorized quit requested")
	wrt.Quit(a.ctx)
	return nil
}

// ---- Process reputation ----

// CheckProcess opens the user's browser to check whether a process is safe:
// VirusTotal by file hash when the path is known, otherwise a web search by
// name. Returns the URL that was opened.
func (a *App) CheckProcess(path, name string) (string, error) {
	if a.ctx == nil {
		return "", errors.New("not ready")
	}
	var u string
	if path != "" {
		if h := fileSHA256(path); h != "" {
			u = "https://www.virustotal.com/gui/file/" + h
		}
	}
	if u == "" {
		q := name
		if q == "" {
			q = filepath.Base(path)
		}
		if q == "" || q == "." {
			return "", errors.New("sem processo para pesquisar")
		}
		u = "https://www.google.com/search?q=" + url.QueryEscape(q+" process safe or malware?")
	}
	wrt.BrowserOpenURL(a.ctx, u)
	return u, nil
}

func fileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
