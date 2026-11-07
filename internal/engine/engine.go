//go:build windows

// Package engine is the core of the firewall. It captures the first packet
// (TCP SYN) of new connections via WinDivert's NETWORK layer, holds it, finds
// the owning process, decides allow/block (by rule, by prompting the user, or
// by the configured default), then re-injects (allow) or drops (block). A
// per-flow decision cache makes the decision stick across TCP SYN retransmits.
package engine

import (
	"context"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"ultron_firewall/internal/model"
	"ultron_firewall/internal/procinfo"
	"ultron_firewall/internal/store"
	"ultron_firewall/internal/threat"
	"ultron_firewall/internal/windivert"
)

// networkFilter captures the first packet of new TCP connections (SYN without
// ACK, both directions), outbound UDP, and inbound DNS responses (UDP src port
// 53, snooped to learn domain→IP for the domain allowlist, then always
// re-injected). Everything else flows untouched.
const networkFilter = "(tcp.Syn and !tcp.Ack) or (udp and outbound) or (inbound and udp.SrcPort == 53)"

const maxPacket = 65535

type decision struct {
	action model.Action
	scope  model.Scope
}

type pending struct {
	conn   *model.Connection
	respCh chan decision
}

type cachedDecision struct {
	action  model.Action
	expires time.Time
}

// Engine drives interception and decision-making.
type Engine struct {
	store  *store.Store
	threat *threat.Service

	mu      sync.Mutex
	handle  *windivert.Handle
	running bool
	pending map[string]*pending

	decMu     sync.Mutex
	decisions map[string]cachedDecision
	prompting map[string]bool

	domainMu    sync.Mutex
	domainAllow map[string]time.Time // remote IP -> expiry, learned from DNS snooping
	domainBlock map[string]time.Time // remote IP -> expiry, learned for tracker domains

	interactive atomic.Bool // true = window open, prompt the user; false = background, apply defaults

	stopCh chan struct{}
	wg     sync.WaitGroup

	ownPID uint32 // our own process, exempt from interception

	// Callbacks wired by the application layer to reach the UI.
	OnPrompt         func(model.PromptRequest)
	OnPromptResolved func(id string)
	OnHistory        func(model.HistoryEntry)
	OnStatus         func(running bool, errMsg string)
}

// New creates an engine.
func New(s *store.Store, t *threat.Service) *Engine {
	e := &Engine{
		store:     s,
		threat:    t,
		pending:     make(map[string]*pending),
		decisions:   make(map[string]cachedDecision),
		prompting:   make(map[string]bool),
		domainAllow: make(map[string]time.Time),
		domainBlock: make(map[string]time.Time),
		ownPID:      uint32(os.Getpid()),
	}
	e.interactive.Store(true)
	return e
}

// SetInteractive controls whether unknown outbound connections prompt the user
// (window open) or silently apply the configured default (running in the tray).
func (e *Engine) SetInteractive(on bool) { e.interactive.Store(on) }

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
	// Validate the filter up-front for a clear error if it is ever changed.
	if err := windivert.CompileFilter(networkFilter, windivert.LayerNetwork); err != nil {
		e.mu.Unlock()
		e.status(false, err.Error())
		return err
	}
	h, err := windivert.Open(networkFilter, windivert.LayerNetwork, 0, 0)
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

// recoverLog turns a panic in a goroutine into a logged error instead of a
// process crash. Used on every spawned goroutine in the packet path.
func recoverLog(where string) {
	if r := recover(); r != nil {
		log.Printf("PANIC recovered in %s: %v\n%s", where, r, debug.Stack())
	}
}

func (e *Engine) recvLoop(h *windivert.Handle) {
	defer e.wg.Done()
	defer recoverLog("recvLoop")
	for {
		buf := make([]byte, maxPacket)
		var addr windivert.Address
		n, err := h.RecvPacket(buf, &addr)
		if err != nil {
			select {
			case <-e.stopCh:
				return // expected on shutdown
			default:
				log.Printf("engine: recv error: %v", err)
				return
			}
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		a := addr

		// Inbound DNS responses are snooped synchronously (and re-injected)
		// here, so the domain allowlist is updated before the following
		// connection's SYN is processed by a worker goroutine.
		if info, ok := windivert.ParsePacket(pkt); ok &&
			info.Protocol == windivert.ProtoUDP && !a.Outbound() {
			if off := info.L4PayloadOffset; off > 0 && off <= len(pkt) {
				func() {
					defer recoverLog("snoopDNS")
					e.snoopDNS(pkt[off:])
				}()
			}
			e.reinject(h, &a, pkt)
			continue
		}

		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			defer recoverLog("handlePacket")
			e.handlePacket(h, &a, pkt)
		}()
	}
}

func (e *Engine) handlePacket(h *windivert.Handle, addr *windivert.Address, pkt []byte) {
	// Loopback traffic (and anything we can't parse) is allowed untouched.
	if addr.Loopback() {
		e.reinject(h, addr, pkt)
		return
	}
	info, ok := windivert.ParsePacket(pkt)
	if !ok {
		e.reinject(h, addr, pkt)
		return
	}
	switch info.Protocol {
	case windivert.ProtoTCP:
		if !info.SYN || info.ACK {
			e.reinject(h, addr, pkt) // only the opening SYN starts a decision
			return
		}
		e.handleTCP(h, addr, pkt, info)
	case windivert.ProtoUDP:
		e.handleUDP(h, addr, pkt, info)
	default:
		e.reinject(h, addr, pkt)
	}
}

func (e *Engine) handleTCP(h *windivert.Handle, addr *windivert.Address, pkt []byte, info windivert.PacketInfo) {
	conn := e.buildConn(addr, info)
	if conn.PID == e.ownPID && e.ownPID != 0 {
		e.reinject(h, addr, pkt)
		return
	}
	inbound := conn.Direction == model.DirInbound

	// Fast path: a cached decision for this flow (handles SYN retransmits).
	if act, ok := e.getDecision(conn.ID); ok {
		e.enforce(h, act, addr, pkt)
		return
	}

	cfg := e.store.Config()

	// Blocklisted remote: always block.
	if cfg.DetectBlocklist && e.threat.IsBlocklisted(conn.RemoteIP, cfg) {
		e.decide(h, conn, model.ActionBlock, "blocklist", addr, pkt, cfg, time.Minute)
		return
	}

	// Explicit rule.
	if r := e.matchRule(conn); r != nil {
		e.decide(h, conn, r.Action, r.ID, addr, pkt, cfg, time.Minute)
		return
	}

	// Allowlisted domain (learned via DNS snooping): auto-allow.
	if e.allowIP(conn.RemoteIP) {
		e.decide(h, conn, model.ActionAllow, "domínio liberado", addr, pkt, cfg, time.Minute)
		return
	}

	// Tracker/ad domain (learned via DNS snooping): block so no cookie is set.
	if cfg.BlockTrackers && e.blockIP(conn.RemoteIP) {
		e.decide(h, conn, model.ActionBlock, "rastreador bloqueado", addr, pkt, cfg, time.Minute)
		return
	}

	// Inbound connections are not prompted (would flood on scans); apply the
	// default and let threat detection flag them.
	if inbound {
		e.decide(h, conn, e.defaultAction(model.DirInbound, cfg), "default", addr, pkt, cfg, 30*time.Second)
		return
	}

	// Outbound unknown connection: prompt the user, unless prompting is off or
	// we are running in the background (window hidden) where no one can answer.
	if !cfg.PromptEnabled || !e.interactive.Load() {
		e.decide(h, conn, e.defaultAction(model.DirOutbound, cfg), "default", addr, pkt, cfg, 30*time.Second)
		return
	}

	if !e.beginPrompt(conn.ID) {
		// Another goroutine already owns the prompt for this flow: drop this
		// retransmitted SYN silently until a decision is made.
		return
	}
	// Enrich the connection with a reverse-DNS name so the user can tell what
	// the remote endpoint is (done once per prompted flow).
	conn.RemoteHost = reverseDNS(conn.RemoteIP)
	// We drop the triggering SYN and rely on the TCP retransmit (which will hit
	// the decision cache) once the user answers.
	act := e.prompt(conn, cfg)
	e.endPrompt(conn.ID)
	e.setDecision(conn.ID, act, time.Minute)
	e.record(conn, act, "prompt", cfg)
}

// handleUDP handles a new outbound UDP flow. UDP is connectionless, so we do
// not prompt (it would flood and lose packets); instead we log it, apply rules
// and threat detection, and allow by default (blocking UDP wholesale would
// break DNS/QUIC). Decisions are cached per flow so the bulk of packets take
// the fast path.
func (e *Engine) handleUDP(h *windivert.Handle, addr *windivert.Address, pkt []byte, info windivert.PacketInfo) {
	conn := e.buildConn(addr, info)
	if conn.PID == e.ownPID && e.ownPID != 0 {
		e.reinject(h, addr, pkt) // our own traffic (e.g. reverse-DNS) — never touch
		return
	}

	cfg := e.store.Config()
	if !cfg.InterceptUDP {
		e.reinject(h, addr, pkt)
		return
	}

	if act, ok := e.getDecision(conn.ID); ok {
		e.enforce(h, act, addr, pkt)
		return
	}

	const udpTTL = 5 * time.Minute
	if cfg.DetectBlocklist && e.threat.IsBlocklisted(conn.RemoteIP, cfg) {
		e.decide(h, conn, model.ActionBlock, "blocklist", addr, pkt, cfg, udpTTL)
		return
	}
	if r := e.matchRule(conn); r != nil {
		e.decide(h, conn, r.Action, r.ID, addr, pkt, cfg, udpTTL)
		return
	}
	if e.allowIP(conn.RemoteIP) {
		e.decide(h, conn, model.ActionAllow, "domínio liberado", addr, pkt, cfg, udpTTL)
		return
	}
	if cfg.BlockTrackers && e.blockIP(conn.RemoteIP) {
		e.decide(h, conn, model.ActionBlock, "rastreador bloqueado", addr, pkt, cfg, udpTTL)
		return
	}
	// Unknown UDP: allow + log (blocking by default would break DNS/QUIC).
	e.decide(h, conn, model.ActionAllow, "udp-auto", addr, pkt, cfg, udpTTL)
}

// decide caches, records and enforces a decision for a connection.
func (e *Engine) decide(h *windivert.Handle, conn *model.Connection, act model.Action, ruleMatch string, addr *windivert.Address, pkt []byte, cfg model.Config, ttl time.Duration) {
	e.setDecision(conn.ID, act, ttl)
	e.record(conn, act, ruleMatch, cfg)
	e.enforce(h, act, addr, pkt)
}

func (e *Engine) enforce(h *windivert.Handle, act model.Action, addr *windivert.Address, pkt []byte) {
	if act == model.ActionAllow {
		e.reinject(h, addr, pkt)
	}
	// Block == drop (do not re-inject).
}

func (e *Engine) reinject(h *windivert.Handle, addr *windivert.Address, pkt []byte) {
	if err := h.SendPacket(pkt, addr); err != nil {
		log.Printf("engine: reinject failed: %v", err)
	}
}

func (e *Engine) record(conn *model.Connection, act model.Action, ruleMatch string, cfg model.Config) {
	entry := model.HistoryEntry{Connection: *conn, Decision: act, RuleMatch: ruleMatch}
	// The connection ID is a per-flow key (not unique per event); give each
	// stored history record its own unique ID so DB keys and UI list keys never
	// collide.
	entry.ID = uuid.NewString()
	e.threat.Inspect(&entry, cfg)
	entry.Severity = severityOf(&entry)
	if err := e.store.AppendHistory(entry); err != nil {
		log.Printf("engine: append history: %v", err)
	}
	if e.OnHistory != nil {
		e.OnHistory(entry)
	}
}

// ---- domain allowlist (DNS snooping) ----

// allowIP reports whether ip is currently allowlisted because it was returned
// by a DNS response for one of the configured allowed domains.
func (e *Engine) allowIP(ip string) bool {
	e.domainMu.Lock()
	defer e.domainMu.Unlock()
	exp, ok := e.domainAllow[ip]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(e.domainAllow, ip)
		return false
	}
	return true
}

// blockIP reports whether ip is currently blocklisted because it was returned
// by a DNS response for one of the configured tracker domains.
func (e *Engine) blockIP(ip string) bool {
	e.domainMu.Lock()
	defer e.domainMu.Unlock()
	exp, ok := e.domainBlock[ip]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(e.domainBlock, ip)
		return false
	}
	return true
}

// snoopDNS inspects a DNS response payload. If the queried name belongs to a
// configured allowed domain, the returned A/AAAA IPs are added to the allow
// set so subsequent connections to them are permitted automatically. If it
// belongs to a tracker domain, the IPs are added to the block set instead so
// connections to them are dropped (preventing trackers from setting cookies).
func (e *Engine) snoopDNS(payload []byte) {
	cfg := e.store.Config()
	hasAllow := len(cfg.AllowedDomains) > 0
	hasTrackers := cfg.BlockTrackers && len(cfg.TrackerDomains) > 0
	if !hasAllow && !hasTrackers {
		return
	}
	qname, ips, ttl := parseDNSResponse(payload)
	if qname == "" || len(ips) == 0 {
		return
	}

	d := time.Duration(ttl) * time.Second
	if d < 10*time.Minute {
		d = 10 * time.Minute
	}
	if d > 24*time.Hour {
		d = 24 * time.Hour
	}
	exp := time.Now().Add(d)

	// An explicit allow always wins over the tracker list, so check it first.
	if hasAllow && domainMatches(qname, cfg.AllowedDomains) {
		e.domainMu.Lock()
		for _, ip := range ips {
			e.domainAllow[ip] = exp
		}
		e.domainMu.Unlock()
		log.Printf("domain-allow: %s -> %v", qname, ips)
		return
	}
	if hasTrackers && domainMatches(qname, cfg.TrackerDomains) {
		e.domainMu.Lock()
		for _, ip := range ips {
			e.domainBlock[ip] = exp
		}
		e.domainMu.Unlock()
		log.Printf("tracker-block: %s -> %v", qname, ips)
	}
}

// ---- decision cache + prompt dedupe ----

func (e *Engine) getDecision(key string) (model.Action, bool) {
	e.decMu.Lock()
	defer e.decMu.Unlock()
	d, ok := e.decisions[key]
	if !ok {
		return "", false
	}
	if time.Now().After(d.expires) {
		delete(e.decisions, key)
		return "", false
	}
	return d.action, true
}

func (e *Engine) setDecision(key string, act model.Action, ttl time.Duration) {
	e.decMu.Lock()
	e.decisions[key] = cachedDecision{action: act, expires: time.Now().Add(ttl)}
	e.decMu.Unlock()
}

func (e *Engine) beginPrompt(key string) bool {
	e.decMu.Lock()
	defer e.decMu.Unlock()
	if e.prompting[key] {
		return false
	}
	e.prompting[key] = true
	return true
}

func (e *Engine) endPrompt(key string) {
	e.decMu.Lock()
	delete(e.prompting, key)
	e.decMu.Unlock()
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

func (e *Engine) buildConn(addr *windivert.Address, info windivert.PacketInfo) *model.Connection {
	outbound := addr.Outbound()
	var localIP, remoteIP net.IP
	var localPort, remotePort uint16
	if outbound {
		localIP, localPort = info.SrcIP, info.SrcPort
		remoteIP, remotePort = info.DstIP, info.DstPort
	} else {
		localIP, localPort = info.DstIP, info.DstPort
		remoteIP, remotePort = info.SrcIP, info.SrcPort
	}

	dir := model.DirOutbound
	if !outbound {
		dir = model.DirInbound
	}

	var pid uint32
	switch info.Protocol {
	case windivert.ProtoUDP:
		pid = procinfo.OwnerPIDUDP(localIP, localPort)
	default: // TCP
		if outbound {
			pid = procinfo.OwnerPIDOutbound(localIP, localPort, remoteIP, remotePort)
		} else {
			pid = procinfo.OwnerPIDListener(localIP, localPort)
		}
	}
	path := processPath(pid)

	proto := protocolName(info.Protocol)
	// Flow key (used for the decision cache and prompt dedupe). For UDP the
	// local port is ephemeral and changes per datagram, so we key by
	// process+remote instead to avoid treating every datagram as a new flow.
	var flowKey string
	if info.Protocol == windivert.ProtoUDP {
		flowKey = "udp|" + string(dir) + "|pid" + strconv.Itoa(int(pid)) +
			"|" + remoteIP.String() + ":" + strconv.Itoa(int(remotePort))
	} else {
		flowKey = proto + "|" + string(dir) + "|" + localIP.String() + ":" + strconv.Itoa(int(localPort)) +
			"|" + remoteIP.String() + ":" + strconv.Itoa(int(remotePort))
	}

	return &model.Connection{
		ID:          flowKey,
		Time:        time.Now(),
		Direction:   dir,
		Protocol:    proto,
		PID:         pid,
		ProcessPath: path,
		ProcessName: baseName(path),
		LocalIP:     localIP.String(),
		LocalPort:   localPort,
		RemoteIP:    remoteIP.String(),
		RemotePort:  remotePort,
		Service:     serviceName(remotePort),
	}
}

// reverseDNS does a best-effort PTR lookup of ip with a short timeout. Our own
// DNS queries are UDP and are not intercepted, so there is no recursion.
func reverseDNS(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// serviceName maps a well-known port to a human-readable service name.
func serviceName(port uint16) string {
	switch port {
	case 20, 21:
		return "FTP"
	case 22:
		return "SSH"
	case 23:
		return "Telnet"
	case 25, 465, 587:
		return "SMTP (e-mail)"
	case 53:
		return "DNS"
	case 80:
		return "HTTP"
	case 110, 995:
		return "POP3 (e-mail)"
	case 143, 993:
		return "IMAP (e-mail)"
	case 389, 636:
		return "LDAP"
	case 443:
		return "HTTPS"
	case 445:
		return "SMB (compart.)"
	case 1433:
		return "SQL Server"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP (área remota)"
	case 5432:
		return "PostgreSQL"
	case 5900:
		return "VNC"
	case 6379:
		return "Redis"
	case 8080, 8443:
		return "HTTP (alt)"
	case 27017:
		return "MongoDB"
	default:
		return ""
	}
}

// severityOf triages a decided connection for the UI signal:
//   - high (red):    confirmed attack signals (blocklist, port scan, unsolicited inbound)
//   - medium (yellow): blocked connections, unknown process, or any other threat flag
//   - low (green):   allowed traffic from an identified process
func severityOf(e *model.HistoryEntry) string {
	if e.Threat {
		switch e.ThreatKind {
		case threat.CatBlocklist, threat.CatScan, threat.CatInbound:
			return "high"
		default:
			return "medium"
		}
	}
	if e.Decision == model.ActionBlock || e.ProcessName == "" {
		return "medium"
	}
	return "low"
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

func baseName(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Base(p)
}

func (e *Engine) status(running bool, errMsg string) {
	if e.OnStatus != nil {
		e.OnStatus(running, errMsg)
	}
}
