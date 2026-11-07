<script>
  import { onMount, onDestroy } from 'svelte'

  // Wails injects these on window at runtime.
  const api = () => (window.go && window.go.main && window.go.main.App) || null
  const rt = () => window.runtime || null

  let state = { running: false, engineError: '', needsSetup: false, unlocked: false, promptEnabled: true, enabled: true }
  let config = null
  let rules = []
  let history = []
  let prompts = []

  let tab = 'prompts'
  let toast = ''
  let toastTimer = null

  // Unlock modal
  let showUnlock = false
  let unlockPw = ''
  let unlockErr = ''

  // Setup modal (first run)
  let setupPw = ''
  let setupPw2 = ''
  let setupErr = ''

  // Change password
  let showChangePw = false
  let curPw = '', newPw = '', newPw2 = '', changeErr = ''

  // New rule form
  let nr = newRule()
  let blocklistText = ''
  let allowedText = ''
  let trackerText = ''

  // History filter
  let filter = ''

  // Live clock for prompt countdowns
  let now = Date.now()
  let clock = null

  function newRule() {
    return { processPath: '', remoteIp: '', remotePort: 0, direction: '', action: 'block', enabled: true, note: '' }
  }

  function notify(msg) {
    toast = msg
    if (toastTimer) clearTimeout(toastTimer)
    toastTimer = setTimeout(() => (toast = ''), 3500)
  }

  async function call(fn, ...args) {
    const a = api()
    if (!a || typeof a[fn] !== 'function') throw new Error('backend não disponível (' + fn + ')')
    return await a[fn](...args)
  }

  async function refreshState() { try { state = await call('GetState') } catch (e) { /* ignore */ } }
  async function loadConfig() {
    try {
      config = await call('GetConfig')
      blocklistText = (config.blocklist || []).join('\n')
      allowedText = (config.allowedDomains || []).join('\n')
      trackerText = (config.trackerDomains || []).join('\n')
    } catch (e) { notify('' + e) }
  }
  async function loadRules() { try { rules = await call('ListRules') } catch (e) { notify('' + e) } }
  async function loadHistory() { try { history = await call('ListHistory', 500) } catch (e) { notify('' + e) } }
  async function loadPrompts() {
    try {
      const p = await call('PendingPrompts')
      prompts = (p || []).map(x => ({ ...x, _received: Date.now() }))
    } catch (e) { /* engine may be off */ }
  }

  $: canEdit = state && (state.unlocked || state.needsSetup)
  $: filteredHistory = history.filter(h => {
    if (!filter) return true
    const f = filter.toLowerCase()
    return (h.processName || '').toLowerCase().includes(f)
      || (h.remoteIp || '').toLowerCase().includes(f)
      || (h.processPath || '').toLowerCase().includes(f)
  })

  // History sorting (clickable column headers).
  let sortKey = 'time'
  let sortDir = 'desc'
  const riskRank = { low: 0, medium: 1, high: 2 }
  function setSort(key) {
    if (sortKey === key) {
      sortDir = sortDir === 'asc' ? 'desc' : 'asc'
    } else {
      sortKey = key
      sortDir = key === 'time' ? 'desc' : 'asc'
    }
  }
  function arrow(key) {
    return sortKey === key ? (sortDir === 'asc' ? ' ▲' : ' ▼') : ''
  }
  function sortVal(h, key) {
    switch (key) {
      case 'risk': return riskRank[h.severity || 'low']
      case 'time': return new Date(h.time).getTime() || 0
      case 'dir': return h.direction || ''
      case 'proc': return (h.processName || '').toLowerCase()
      case 'remote': return (h.remoteHost || h.remoteIp || '').toLowerCase()
      case 'local': return h.localIp || ''
      case 'proto': return h.protocol || ''
      case 'decision': return h.decision || ''
      case 'threat': return h.threatKind || ''
      default: return 0
    }
  }
  $: sortedHistory = [...filteredHistory].sort((a, b) => {
    const va = sortVal(a, sortKey), vb = sortVal(b, sortKey)
    const c = va < vb ? -1 : va > vb ? 1 : 0
    return sortDir === 'asc' ? c : -c
  })

  onMount(async () => {
    await refreshState()
    await loadConfig()
    await loadRules()
    await loadHistory()
    await loadPrompts()

    const r = rt()
    if (r) {
      r.EventsOn('prompt:new', (p) => {
        prompts = [...prompts.filter(x => x.id !== p.id), { ...p, _received: Date.now() }]
      })
      r.EventsOn('prompt:resolved', (id) => { prompts = prompts.filter(x => x.id !== id) })
      r.EventsOn('history:new', (h) => { history = [h, ...history].slice(0, 500) })
      r.EventsOn('engine:status', (s) => {
        state = { ...state, running: s.running, engineError: s.error }
      })
    }
    clock = setInterval(() => (now = Date.now()), 1000)
  })

  onDestroy(() => { if (clock) clearInterval(clock) })

  function remaining(p) {
    if (!p.timeoutSecs) return null
    const left = Math.ceil(p.timeoutSecs - (now - p._received) / 1000)
    return left > 0 ? left : 0
  }

  async function respond(p, action, scope) {
    try {
      await call('RespondPrompt', p.id, action, scope)
    } catch (e) { notify('' + e) }
    prompts = prompts.filter(x => x.id !== p.id)
  }

  async function checkSafe(x) {
    try {
      await call('CheckProcess', x.processPath || '', x.processName || '')
      notify('Abrindo verificação de reputação no navegador...')
    } catch (e) { notify('' + e) }
  }

  async function quitApp() {
    if (!guardEdit()) return
    try { await call('QuitApp') } catch (e) { notify('' + e) }
  }

  // ---- Auth ----
  async function doSetup() {
    setupErr = ''
    if (setupPw.length < 4) { setupErr = 'Mínimo de 4 caracteres.'; return }
    if (setupPw !== setupPw2) { setupErr = 'As senhas não conferem.'; return }
    try {
      await call('SetMasterPassword', '', setupPw)
      setupPw = setupPw2 = ''
      await refreshState()
      notify('Senha master definida.')
    } catch (e) { setupErr = '' + e }
  }

  async function doUnlock() {
    unlockErr = ''
    try {
      await call('Unlock', unlockPw)
      unlockPw = ''
      showUnlock = false
      await refreshState()
      await loadConfig()
      notify('Destravado.')
    } catch (e) { unlockErr = '' + e }
  }

  async function doLock() {
    try { await call('Lock'); await refreshState(); await loadConfig() } catch (e) { notify('' + e) }
  }

  async function doChangePw() {
    changeErr = ''
    if (newPw.length < 4) { changeErr = 'Mínimo de 4 caracteres.'; return }
    if (newPw !== newPw2) { changeErr = 'As senhas não conferem.'; return }
    try {
      await call('SetMasterPassword', curPw, newPw)
      curPw = newPw = newPw2 = ''
      showChangePw = false
      await refreshState()
      notify('Senha alterada.')
    } catch (e) { changeErr = '' + e }
  }

  function guardEdit() {
    if (canEdit) return true
    showUnlock = true
    return false
  }

  // ---- Engine / config ----
  async function toggleEngine() {
    if (!guardEdit()) return
    try { await call('SetEnabled', !state.running); await refreshState() }
    catch (e) { notify('' + e) }
  }

  async function saveConfig() {
    if (!guardEdit()) return
    config.blocklist = blocklistText.split('\n').map(s => s.trim()).filter(Boolean)
    config.allowedDomains = allowedText.split('\n').map(s => s.trim()).filter(Boolean)
    config.trackerDomains = trackerText.split('\n').map(s => s.trim()).filter(Boolean)
    config.promptTimeoutSecs = Number(config.promptTimeoutSecs) || 0
    config.scanWindowSecs = Number(config.scanWindowSecs) || 0
    config.scanPortThreshold = Number(config.scanPortThreshold) || 0
    try {
      await call('SaveConfig', config)
      await refreshState()
      await loadConfig()
      notify('Configurações salvas.')
    } catch (e) { notify('' + e) }
  }

  async function testReport() {
    if (!guardEdit()) return
    try { await call('TestReport'); notify('Report de teste enviado (ver servidor).') }
    catch (e) { notify('' + e) }
  }

  // ---- Rules ----
  async function saveRule() {
    if (!guardEdit()) return
    const r = { ...nr, remotePort: Number(nr.remotePort) || 0 }
    try {
      await call('SaveRule', r)
      nr = newRule()
      await loadRules()
      notify('Regra salva.')
    } catch (e) { notify('' + e) }
  }

  async function toggleRule(r) {
    if (!guardEdit()) return
    try { await call('SaveRule', { ...r, enabled: !r.enabled }); await loadRules() }
    catch (e) { notify('' + e) }
  }

  async function deleteRule(r) {
    if (!guardEdit()) return
    try { await call('DeleteRule', r.id); await loadRules() }
    catch (e) { notify('' + e) }
  }

  async function clearHistory() {
    if (!guardEdit()) return
    try { await call('ClearHistory'); history = []; notify('Histórico limpo.') }
    catch (e) { notify('' + e) }
  }

  function fmtTime(t) {
    try { return new Date(t).toLocaleString() } catch (e) { return t }
  }
  function fmtTimeShort(t) {
    try { return new Date(t).toLocaleTimeString() } catch (e) { return t }
  }
  const BUILD_TAG = 'build 1106-a (correção clique na bandeja)'
  function isV6(ip) { return ip && ip.indexOf(':') !== -1 }
  function endpoint(ip, port) {
    if (!ip) return '—'
    const h = isV6(ip) ? '[' + ip + ']' : ip
    return port ? h + ':' + port : h
  }
  function procLabel(x) {
    return x.processName || (x.pid ? 'PID ' + x.pid : 'Processo desconhecido')
  }
  function riskLabel(s) {
    return s === 'high' ? 'Possível ataque' : s === 'medium' ? 'Atenção' : 'Baixa periculosidade'
  }
  async function testToast() {
    try { await call('TestToast') } catch (e) { notify('' + e) }
  }
  async function restoreTrackers() {
    try {
      const list = await call('DefaultTrackerDomains')
      trackerText = (list || []).join('\n')
      notify('Lista padrão restaurada — clique em Salvar para aplicar.')
    } catch (e) { notify('' + e) }
  }
  let showCloseBrowsers = false
  let lockedBrowsers = []
  async function cleanCookies() {
    notify('Limpando cookies...')
    try {
      const r = await call('CleanCookies')
      notify((r && r.message) || 'Cookies limpos.')
      if (r && r.locked && r.locked.length) {
        lockedBrowsers = r.locked
        showCloseBrowsers = true
      }
    } catch (e) { notify('' + e) }
  }
  async function closeBrowsersAndClean() {
    showCloseBrowsers = false
    notify('Fechando navegadores e limpando...')
    try {
      const r = await call('CloseBrowsersAndClean')
      notify((r && r.message) || 'Cookies limpos.')
    } catch (e) { notify('' + e) }
  }
</script>

<div class="layout">
  <aside class="sidebar">
    <div class="brand">
      <div class="logo">🛡️</div>
      <div class="name">ULTRON<small>Firewall</small></div>
    </div>

    <nav class="nav">
      <button class:active={tab === 'prompts'} on:click={() => tab = 'prompts'}>
        <span>🔔</span> Prompts {#if prompts.length}<span class="badge">{prompts.length}</span>{/if}
      </button>
      <button class:active={tab === 'history'} on:click={() => tab = 'history'}>
        <span>📜</span> Histórico
      </button>
      <button class:active={tab === 'rules'} on:click={() => tab = 'rules'}>
        <span>📑</span> Regras
      </button>
      <button class:active={tab === 'settings'} on:click={() => tab = 'settings'}>
        <span>⚙️</span> Configurações
      </button>
    </nav>

    <div class="spacer"></div>

    <div class="status-chip" style="margin-bottom:10px">
      <span class="dot {state.engineError ? 'err' : (state.running ? 'on' : 'off')}"></span>
      {state.engineError ? 'Erro no motor' : (state.running ? 'Interceptando' : 'Parado')}
    </div>

    {#if !state.needsSetup}
      {#if state.unlocked}
        <button class="btn sm ghost" on:click={doLock}>🔓 Travar alterações</button>
      {:else}
        <button class="btn sm accent" on:click={() => showUnlock = true}>🔒 Destravar</button>
      {/if}
    {/if}

    <div style="margin-top:10px;font-size:10px;color:var(--muted);text-align:center">{BUILD_TAG}</div>
  </aside>

  <main class="main">
    {#if toast}
      <div class="banner">{toast}</div>
    {/if}

    {#if state.engineError}
      <div class="banner err">
        ⚠️ {state.engineError}
        <span class="grow"></span>
        <span class="sub" style="color:var(--muted)">O motor precisa de privilégios de administrador (WinDivert).</span>
      </div>
    {/if}

    {#if state.needsSetup}
      <div class="panel" style="max-width:460px;margin:40px auto">
        <h3>🔐 Defina a senha master</h3>
        <p style="color:var(--muted)">Ela protege alterações de regras e configurações. Guarde-a bem.</p>
        <div style="display:flex;flex-direction:column;gap:12px">
          <label class="field"><span>Senha</span><input type="password" bind:value={setupPw} /></label>
          <label class="field"><span>Confirmar senha</span><input type="password" bind:value={setupPw2} /></label>
          <div class="err-text">{setupErr}</div>
          <button class="btn accent" on:click={doSetup}>Definir e começar</button>
        </div>
      </div>
    {:else if tab === 'prompts'}
      <div class="page-title"><h1>🔔 Solicitações de conexão</h1></div>
      {#if prompts.length === 0}
        <div class="empty"><div class="big">✅</div>Nenhuma conexão aguardando decisão.</div>
      {:else}
        {#each prompts as p (p.id)}
          <div class="prompt-card">
            <div class="head">
              <span class="proc">{procLabel(p)}</span>
              <span class="tag {p.direction}">{p.direction === 'inbound' ? '↓ entrada' : '↑ saída'}</span>
              <span class="tag" style="background:var(--panel-2);color:var(--muted)">{p.protocol}</span>
              {#if p.service}<span class="tag" style="background:rgba(74,163,255,.15);color:var(--inbound)">{p.service}</span>{/if}
              {#if remaining(p) !== null}
                <span class="countdown">auto ({p.defaultAction === 'allow' ? 'liberar' : 'bloquear'}) em {remaining(p)}s</span>
              {/if}
            </div>
            <div class="detail">
              <b>{p.direction === 'inbound' ? 'De' : 'Para'}:</b> {endpoint(p.remoteIp, p.remotePort)}
              {#if p.remoteHost}<span style="color:var(--text)"> &nbsp;→&nbsp; {p.remoteHost}</span>{/if}
              <br/><b>Local:</b> {endpoint(p.localIp, p.localPort)}
              <br/><span style="font-size:12px">{p.processPath ? p.processPath : 'processo não identificado'}{p.pid ? ' · PID ' + p.pid : ''}</span>
            </div>
            <div class="prompt-actions">
              <button class="btn allow" on:click={() => respond(p, 'allow', 'once')}>Liberar uma vez</button>
              <button class="btn block" on:click={() => respond(p, 'block', 'once')}>Bloquear uma vez</button>
              <span class="sep"></span>
              <button class="btn allow" on:click={() => respond(p, 'allow', 'app')}>Sempre liberar app</button>
              <button class="btn block" on:click={() => respond(p, 'block', 'app')}>Sempre bloquear app</button>
              <button class="btn ghost sm" on:click={() => respond(p, 'allow', 'app_remote')}>Liberar só este destino</button>
              <button class="btn ghost sm" on:click={() => checkSafe(p)} title="Pesquisar a reputação do processo na internet">🔍 É seguro?</button>
            </div>
          </div>
        {/each}
      {/if}

    {:else if tab === 'history'}
      <div class="page-title"><h1>📜 Histórico</h1><span class="sub">tentativas de conexão (entrada e saída)</span></div>
      <div class="toolbar">
        <input class="grow" placeholder="Filtrar por processo, IP..." bind:value={filter} />
        <button class="btn" on:click={loadHistory}>Atualizar</button>
        <button class="btn ghost" on:click={clearHistory} disabled={!canEdit}>Limpar</button>
      </div>
      <div class="panel" style="padding:0;overflow:auto">
        <table>
          <thead>
            <tr>
              <th title="Risco" style="cursor:pointer" on:click={() => setSort('risk')}>●{arrow('risk')}</th>
              <th style="cursor:pointer" on:click={() => setSort('proto')}>Proto{arrow('proto')}</th>
              <th style="cursor:pointer" on:click={() => setSort('time')}>Hora{arrow('time')}</th>
              <th style="cursor:pointer" on:click={() => setSort('dir')}>Dir.{arrow('dir')}</th>
              <th style="cursor:pointer" on:click={() => setSort('proc')}>Processo / arquivo{arrow('proc')}</th>
              <th style="cursor:pointer" on:click={() => setSort('remote')}>Remoto{arrow('remote')}</th>
              <th style="cursor:pointer" on:click={() => setSort('local')}>Local{arrow('local')}</th>
              <th style="cursor:pointer" on:click={() => setSort('decision')}>Decisão{arrow('decision')}</th>
              <th style="cursor:pointer" on:click={() => setSort('threat')}>Ameaça{arrow('threat')}</th>
            </tr>
          </thead>
          <tbody>
            {#each sortedHistory as h}
              <tr>
                <td><span class="risk {h.severity || 'low'}" title={riskLabel(h.severity || 'low')}></span></td>
                <td><span class="tag" style="text-transform:uppercase;font-weight:800;background:{h.protocol === 'udp' ? 'rgba(183,140,255,.18)' : 'rgba(74,163,255,.15)'};color:{h.protocol === 'udp' ? 'var(--outbound)' : 'var(--inbound)'}">{h.protocol || '?'}</span></td>
                <td title={fmtTime(h.time)} style="white-space:nowrap">{fmtTimeShort(h.time)}</td>
                <td><span class="tag {h.direction}">{h.direction === 'inbound' ? '↓' : '↑'}</span></td>
                <td class="proccell" title={h.processPath || 'caminho não identificado'}>
                  <div class="procline">
                    <span>{h.processName || (h.pid ? 'PID ' + h.pid : '—')}</span>
                    {#if h.processPath || h.processName}<button class="btn ghost sm" style="padding:1px 6px" on:click={() => checkSafe(h)} title="É seguro?">🔍</button>{/if}
                  </div>
                  <div class="procpath">{h.processPath || 'caminho não identificado'}{h.pid ? ' · PID ' + h.pid : ''}</div>
                </td>
                <td class="ellip" title={h.remoteHost}>
                  {endpoint(h.remoteIp, h.remotePort)}
                  {#if h.remoteHost}<span style="color:var(--muted)"> · {h.remoteHost}</span>{/if}
                  {#if h.service}<span style="color:var(--inbound)"> · {h.service}</span>{/if}
                </td>
                <td>{endpoint(h.localIp, h.localPort)}</td>
                <td><span class="tag {h.decision}">{h.decision === 'allow' ? 'liberado' : 'bloqueado'}</span></td>
                <td>{#if h.threat}<span class="tag threat" title={h.threatKind}>⚠ {h.threatKind}</span>{:else}—{/if}</td>
              </tr>
            {/each}
            {#if filteredHistory.length === 0}
              <tr><td colspan="9"><div class="empty" style="padding:30px">Sem registros.</div></td></tr>
            {/if}
          </tbody>
        </table>
      </div>

    {:else if tab === 'rules'}
      <div class="page-title"><h1>📑 Regras</h1></div>
      {#if !canEdit}
        <div class="banner warn">🔒 Travado — destrave para criar ou alterar regras. <span class="grow"></span><button class="btn sm accent" on:click={() => showUnlock = true}>Destravar</button></div>
      {/if}

      <div class="panel">
        <h3>Nova regra</h3>
        <div class="grid">
          <label class="field"><span>Caminho do app (vazio = qualquer)</span><input bind:value={nr.processPath} placeholder="C:\\...\\app.exe" disabled={!canEdit} /></label>
          <label class="field"><span>IP remoto (vazio = qualquer)</span><input bind:value={nr.remoteIp} placeholder="1.2.3.4" disabled={!canEdit} /></label>
          <label class="field"><span>Porta remota (0 = qualquer)</span><input type="number" bind:value={nr.remotePort} disabled={!canEdit} /></label>
          <label class="field"><span>Direção</span>
            <select bind:value={nr.direction} disabled={!canEdit}>
              <option value="">Qualquer</option>
              <option value="outbound">Saída</option>
              <option value="inbound">Entrada</option>
            </select>
          </label>
          <label class="field"><span>Ação</span>
            <select bind:value={nr.action} disabled={!canEdit}>
              <option value="block">Bloquear</option>
              <option value="allow">Liberar</option>
            </select>
          </label>
        </div>
        <div style="margin-top:14px"><button class="btn accent" on:click={saveRule} disabled={!canEdit}>Adicionar regra</button></div>
      </div>

      <div class="panel" style="padding:0;overflow:auto">
        <table>
          <thead><tr><th>Ativa</th><th>App</th><th>Remoto</th><th>Direção</th><th>Ação</th><th></th></tr></thead>
          <tbody>
            {#each rules as r (r.id)}
              <tr>
                <td><input type="checkbox" checked={r.enabled} on:change={() => toggleRule(r)} disabled={!canEdit} /></td>
                <td class="ellip" title={r.processPath}>{r.processPath || 'qualquer'}</td>
                <td>{r.remoteIp ? endpoint(r.remoteIp, r.remotePort) : 'qualquer'}</td>
                <td>{r.direction || 'qualquer'}</td>
                <td><span class="tag {r.action}">{r.action === 'allow' ? 'liberar' : 'bloquear'}</span></td>
                <td><button class="btn sm ghost" on:click={() => deleteRule(r)} disabled={!canEdit}>🗑</button></td>
              </tr>
            {/each}
            {#if rules.length === 0}
              <tr><td colspan="6"><div class="empty" style="padding:30px">Nenhuma regra. As respostas "sempre" dos prompts aparecem aqui.</div></td></tr>
            {/if}
          </tbody>
        </table>
      </div>

    {:else if tab === 'settings'}
      <div class="page-title"><h1>⚙️ Configurações</h1></div>
      {#if !canEdit}
        <div class="banner warn">🔒 Travado — destrave para alterar. <span class="grow"></span><button class="btn sm accent" on:click={() => showUnlock = true}>Destravar</button></div>
      {/if}

      {#if config}
      <div class="panel">
        <h3>Motor</h3>
        <div class="grid">
          <label class="switch"><input type="checkbox" checked={state.running} on:change={toggleEngine} disabled={!canEdit} /><span class="track"></span> Interceptação ativa</label>
          <label class="switch"><input type="checkbox" bind:checked={config.promptEnabled} disabled={!canEdit} /><span class="track"></span> Perguntar em conexões novas</label>
          <label class="switch"><input type="checkbox" bind:checked={config.notifyEnabled} disabled={!canEdit} /><span class="track"></span> Popups em segundo plano</label>
          <label class="switch"><input type="checkbox" bind:checked={config.interceptUdp} disabled={!canEdit} /><span class="track"></span> Interceptar UDP (registrar + regras)</label>
        </div>
        <div class="grid" style="margin-top:14px">
          <label class="field"><span>Padrão saída (sem regra)</span>
            <select bind:value={config.defaultOutbound} disabled={!canEdit}><option value="block">Bloquear</option><option value="allow">Liberar</option></select></label>
          <label class="field"><span>Padrão entrada (sem regra)</span>
            <select bind:value={config.defaultInbound} disabled={!canEdit}><option value="block">Bloquear</option><option value="allow">Liberar</option></select></label>
          <label class="field"><span>Timeout do prompt (s, 0 = infinito)</span>
            <input type="number" bind:value={config.promptTimeoutSecs} disabled={!canEdit} /></label>
        </div>
      </div>

      <div class="panel">
        <h3>Detecção de ataque & envio ao servidor</h3>
        <div class="grid">
          <label class="switch"><input type="checkbox" bind:checked={config.reportEnabled} disabled={!canEdit} /><span class="track"></span> Enviar report (POST)</label>
        </div>
        <div class="grid" style="margin-top:14px">
          <label class="field" style="grid-column:1/-1"><span>URL do servidor (POST)</span>
            <input bind:value={config.reportUrl} placeholder="https://seu-servidor/eventos" disabled={!canEdit} /></label>
          <label class="field"><span>Token (Authorization: Bearer)</span>
            <input type="password" bind:value={config.reportToken} placeholder={state.unlocked ? 'definir...' : '•••• (travado)'} disabled={!canEdit} /></label>
        </div>
        <h3 style="margin-top:18px">Categorias consideradas ataque</h3>
        <div class="grid">
          <label class="switch"><input type="checkbox" bind:checked={config.detectInbound} disabled={!canEdit} /><span class="track"></span> Entrada não solicitada</label>
          <label class="switch"><input type="checkbox" bind:checked={config.detectScan} disabled={!canEdit} /><span class="track"></span> Port scan</label>
          <label class="switch"><input type="checkbox" bind:checked={config.detectBlocklist} disabled={!canEdit} /><span class="track"></span> IP em lista negra</label>
          <label class="switch"><input type="checkbox" bind:checked={config.detectOutDenied} disabled={!canEdit} /><span class="track"></span> Saída negada</label>
        </div>
        <div class="grid" style="margin-top:14px">
          <label class="field"><span>Janela do scan (s)</span><input type="number" bind:value={config.scanWindowSecs} disabled={!canEdit} /></label>
          <label class="field"><span>Limite de portas (scan)</span><input type="number" bind:value={config.scanPortThreshold} disabled={!canEdit} /></label>
          <label class="field" style="grid-column:1/-1"><span>Lista negra de IPs (um por linha)</span>
            <textarea rows="3" bind:value={blocklistText} disabled={!canEdit}></textarea></label>
        </div>
        <div style="margin-top:14px;display:flex;gap:10px">
          <button class="btn accent" on:click={saveConfig} disabled={!canEdit}>Salvar configurações</button>
          <button class="btn" on:click={testReport} disabled={!canEdit}>Testar envio</button>
        </div>
      </div>

      <div class="panel">
        <h3>Domínios sempre liberados</h3>
        <p style="color:var(--muted);margin:0 0 12px;font-size:12px">
          Um domínio por linha. Qualquer subdomínio também é liberado (ex.: <code>likesystem.com.br</code>
          libera <code>gkn.likesystem.com.br</code>, <code>vmcpool.likesystem.com.br</code> etc.).
          Funciona espionando as respostas de DNS — se o sistema usar DNS-over-HTTPS, me avise.
        </p>
        <label class="field">
          <span>Domínios liberados</span>
          <textarea rows="3" bind:value={allowedText} disabled={!canEdit} placeholder="likesystem.com.br"></textarea>
        </label>
        <div style="margin-top:12px"><button class="btn accent" on:click={saveConfig} disabled={!canEdit}>Salvar</button></div>
      </div>

      <div class="panel">
        <h3>🛡️ Rastreamento & cookies</h3>
        <div class="grid">
          <label class="switch"><input type="checkbox" bind:checked={config.blockTrackers} disabled={!canEdit} /><span class="track"></span> Bloquear rastreadores (anúncios/analytics)</label>
        </div>
        <p style="color:var(--muted);margin:12px 0;font-size:12px">
          Derruba as conexões para domínios de rastreamento conhecidos (detectados via DNS), então eles nem chegam a gravar
          cookies no seu navegador. Um domínio por linha — subdomínios já entram juntos (ex.: <code>doubleclick.net</code>).
        </p>
        <label class="field">
          <span>Domínios de rastreadores bloqueados</span>
          <textarea rows="5" bind:value={trackerText} disabled={!canEdit} placeholder="doubleclick.net"></textarea>
        </label>
        <div style="margin-top:12px;display:flex;gap:10px;flex-wrap:wrap">
          <button class="btn accent" on:click={saveConfig} disabled={!canEdit}>Salvar</button>
          <button class="btn ghost" on:click={restoreTrackers} disabled={!canEdit}>Restaurar lista padrão</button>
        </div>

        <hr style="border:none;border-top:1px solid var(--border);margin:18px 0" />

        <h3 style="margin:0 0 8px">🧹 Limpar cookies do sistema</h3>
        <p style="color:var(--muted);margin:0 0 12px;font-size:12px">
          Apaga <b>todos</b> os cookies dos navegadores instalados (Chrome, Edge, Brave, Opera, Vivaldi e Firefox, em todos os perfis).
          Isso vai <b>desconectar você de todos os sites</b>. Para funcionar, <b>feche os navegadores</b> antes — os que ficarem abertos
          serão informados para você fechar e tentar de novo.
        </p>
        <button class="btn block" on:click={cleanCookies}>🧹 Limpar todos os cookies agora</button>
      </div>

      <div class="panel">
        <h3>Segurança</h3>
        <div style="display:flex;gap:10px;flex-wrap:wrap">
          <button class="btn" on:click={() => showChangePw = true} disabled={!canEdit}>Alterar senha master</button>
          <button class="btn" on:click={testToast}>Testar notificação</button>
          <button class="btn block" on:click={quitApp}>Encerrar Ultron (requer senha)</button>
        </div>
        <p style="color:var(--muted);margin-top:12px;font-size:12px">
          Fechar a janela (X) apenas minimiza para a bandeja — o Ultron continua protegendo em segundo plano e avisa por popups.
          Para encerrar de vez, use o botão acima (exige a senha master).
        </p>
      </div>
      {/if}
    {/if}
  </main>
</div>

{#if showUnlock}
  <div class="modal-bg" on:click|self={() => showUnlock = false}>
    <div class="modal">
      <h3>🔒 Destravar alterações</h3>
      <p>Digite a senha master.</p>
      <input type="password" bind:value={unlockPw} placeholder="Senha master" style="width:100%" on:keydown={(e) => e.key === 'Enter' && doUnlock()} />
      <div class="err-text">{unlockErr}</div>
      <div class="row">
        <button class="btn accent grow" on:click={doUnlock}>Destravar</button>
        <button class="btn ghost" on:click={() => showUnlock = false}>Cancelar</button>
      </div>
    </div>
  </div>
{/if}

{#if showCloseBrowsers}
  <div class="modal-bg" on:click|self={() => showCloseBrowsers = false}>
    <div class="modal">
      <h3>🧹 Fechar navegadores para limpar</h3>
      <p>
        Estes navegadores estão abertos e seguram os cookies:
        <b>{lockedBrowsers.join(', ')}</b>.
        Para limpar de verdade, preciso <b>fechá-los</b> agora — você vai perder as abas abertas.
      </p>
      <div class="row">
        <button class="btn block grow" on:click={closeBrowsersAndClean}>Fechar e limpar agora</button>
        <button class="btn ghost" on:click={() => showCloseBrowsers = false}>Cancelar</button>
      </div>
    </div>
  </div>
{/if}

{#if showChangePw}
  <div class="modal-bg" on:click|self={() => showChangePw = false}>
    <div class="modal">
      <h3>Alterar senha master</h3>
      <div style="display:flex;flex-direction:column;gap:10px">
        <input type="password" bind:value={curPw} placeholder="Senha atual" />
        <input type="password" bind:value={newPw} placeholder="Nova senha" />
        <input type="password" bind:value={newPw2} placeholder="Confirmar nova senha" />
      </div>
      <div class="err-text">{changeErr}</div>
      <div class="row">
        <button class="btn accent grow" on:click={doChangePw}>Salvar</button>
        <button class="btn ghost" on:click={() => showChangePw = false}>Cancelar</button>
      </div>
    </div>
  </div>
{/if}
