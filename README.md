# Ultron Firewall 🛡️

Firewall pessoal **"pergunta antes de liberar"** para Windows — enxuto e focado.
Inspirado no [Portmaster](https://github.com/safing/portmaster): mantém a espinha
em **Go**, mas sem a dor de manter um driver de kernel próprio (usa o WinDivert,
que é assinado e carregado só enquanto o app roda).

A ideia central é simples: **toda conexão nova é segurada até você decidir.**
Nada sai nem entra pela primeira vez sem passar por você (ou por uma regra que
você já criou).

---

## O que faz

- **Pergunta (liberar / bloquear)** em cada conexão TCP nova de saída — você
  escolhe o escopo da decisão:
  - **uma vez** (só esta conexão),
  - **por app** (sempre que este programa conectar),
  - **por app + destino** (este programa, apenas para este IP/porta).
- **Senha master** (hash bcrypt) protege *toda* alteração de regra/configuração
  e também o **encerramento** do app — fechar sem senha só manda para a bandeja.
- **Histórico** completo de tentativas de entrada e saída, com:
  - sinal de risco (🟢 baixo / 🟡 médio / 🔴 alto),
  - processo + caminho do executável, protocolo (TCP/UDP), destino (com
    DNS reverso quando possível) e a decisão tomada,
  - ordenação por qualquer coluna.
- **UDP**: captura e registra saída UDP (liberada por padrão, bloqueável por
  regra — bloquear tudo quebraria DNS/QUIC).
- **Liberação por domínio**: tudo para `*.dominio.com` é liberado
  automaticamente, via *DNS snooping* (lê as respostas DNS e libera os IPs
  resolvidos). Já vem com `likesystem.com.br`.
- **Bloqueio de rastreadores/anúncios**: ~40 domínios conhecidos (Google
  Analytics, DoubleClick, Facebook pixel, Criteo, Taboola, Hotjar, etc.),
  editável, pelo mesmo mecanismo de DNS. Um domínio liberado sempre vence o
  bloqueio.
- **Limpeza de cookies**: apaga os cookies de Chrome/Edge/Brave/Vivaldi/Opera/
  Opera GX/Chromium (todos os perfis) e Firefox. Botão manual; exige o navegador
  **fechado** (arquivo travado) — os que estiverem abertos são listados.
- **"É seguro?"**: abre o VirusTotal pelo SHA-256 do executável (ou uma busca
  pelo nome) para checar a reputação de um processo.
- **Detecção de ataque** (entrada não solicitada, *port scan*, IP em lista
  negra, saída negada) com **POST** opcional para um servidor de registro.
- **Bandeja do sistema**: fechar a janela esconde na bandeja e o firewall
  continua protegendo. Clique **esquerdo** reabre o painel; **direito** abre o
  menu (Abrir / Encerrar). Encerrar de verdade exige a senha.
- **Notificações (toast)**: enquanto está na bandeja, avisa sobre conexões
  aguardando decisão e sobre bloqueios/ameaças; clicar no aviso reabre o painel.
- **IPv4 e IPv6**.

---

## Como funciona (arquitetura)

Processo único e elevado (a UI do Wails contém o motor + a interface — dá para
separar em serviço + UI depois, como o Portmaster).

1. **Interceptação:** [WinDivert 2.2](https://reqrypt.org/windivert.html) na
   **camada NETWORK** (o driver `.sys` + a `.dll` ficam embutidos no `.exe` e
   são extraídos/carregados em runtime; some quando o app fecha — nada fica
   instalado).
   O filtro é:

   ```
   (tcp.Syn and !tcp.Ack) or (udp and outbound) or (inbound and udp.SrcPort == 53)
   ```

   - `tcp.Syn and !tcp.Ack` pega **só o primeiro SYN** de cada conexão TCP nova.
   - `udp and outbound` registra UDP de saída.
   - `inbound and udp.SrcPort == 53` deixa espiar as respostas DNS (para as
     listas de domínios).

   > **Por que NETWORK e não SOCKET?** A camada SOCKET exige
   > `WINDIVERT_FLAG_RECV_ONLY` e **não consegue re-injetar** o pacote — ou seja,
   > só observa/bloqueia-por-filtro, nunca "segura e depois libera esta
   > conexão". O verdadeiro *ask-first* precisa da camada NETWORK.

2. **Segurar → identificar → decidir:** o SYN é **segurado** (não re-injetado).
   Descobrimos o PID dono da conexão via `GetExtendedTcpTable`/`...UdpTable`
   (iphlpapi), resolvemos nome do processo, serviço pela porta e DNS reverso do
   destino (*best-effort*). Então aplicamos: **regra existente → prompt →
   padrão**.
   - **Liberar** = re-injeta o pacote (a conexão segue normalmente).
   - **Bloquear** = descarta o pacote (a conexão nunca se estabelece).
   - Um **cache por fluxo** cobre as retransmissões do SYN carregando a mesma
     decisão.

3. **Entrada (inbound)** não é perguntada (evita enxurrada de scans): aplica o
   padrão + registra, e dispara a classificação de ameaça.

4. **Robustez:** cada pacote é tratado em goroutine com `recover` (um pacote
   ruim nunca derruba o processo), os toasts rodam numa **thread dedicada e
   travada** (`LockOSThread`) para não corromper o COM da thread principal do
   WebView2, e a **bandeja também roda em thread travada** — no Windows os
   cliques no ícone só chegam à thread que criou a janela.

Tudo é logado em `%ProgramData%\UltronFirewall\ultron.log`.

---

## Requisitos

- **Windows 10/11 x64.**
- Rodar **como Administrador** — o manifesto já pede UAC. É obrigatório para
  carregar o WinDivert; não há firewall real no Windows sem isso.
- **WebView2** (já vem no Windows 11).

Limitações conscientes: **DNS-over-HTTPS (DoH)** passa por fora do *snooping*
(o navegador resolve por HTTPS, não dá para ler); UDP de **entrada** não é
capturado; *loopback* é liberado automaticamente.

---

## Como compilar

### 1. Pré-requisitos (uma vez)

- **Go 1.26+** (desenvolvido com go1.27.3). — <https://go.dev/dl/>
- **Node.js + npm** (para o frontend Svelte).
- **Wails CLI v2:**
  ```powershell
  go install github.com/wailsapp/wails/v2/cmd/wails@v2.17.1
  ```
  Garanta que `%USERPROFILE%\go\bin` está no `PATH`. Confira com `wails doctor`.
- **Não precisa de gcc / cgo** — no Windows o Wails dispensa cgo; o WinDivert é
  acessado via `LazyDLL`.

### 2. Build

Em máquinas com pouca RAM (ex.: 8 GB), **compile em etapas** — o `wails build`
inteiro pode ser morto por falta de memória:

```powershell
# a) frontend (gera frontend/dist)
cd frontend
npm install        # só na primeira vez, ou quando mudar dependências
npm run build
cd ..

# b) Go — reaproveita o dist já pronto (-s = skip frontend)
wails build -s
```

Ou, se tiver RAM sobrando, tudo de uma vez:

```powershell
wails build
```

**Saída:** `build\bin\ultron_firewall.exe` (~12 MB, exe único — driver e DLL
embutidos).

> **Marcador de build:** o rodapé da barra lateral mostra uma tag (ex.:
> `build 1106-a`). Ela fica em `frontend/src/App.svelte` (`BUILD_TAG`).
> **Incremente-a a cada build de UI** — ajuda a confirmar qual versão está
> rodando e a evitar confusão com exe antigo em cache.

### 3. Validar o filtro (sem admin)

Há uma ferramenta de dev que valida/compila o filtro do WinDivert sem precisar
de admin nem de tráfego real:

```powershell
go run ./cmd/filtercheck
```

### 4. Desenvolvimento com hot-reload

```powershell
wails dev
```
(Precisa de admin para o motor de interceptação funcionar.)

---

## Como instalar / executar (importante)

O exe que você realmente usa no dia a dia é uma **cópia de produção** fora da
pasta do projeto, por exemplo:

```
X:\HSTECH\Prototipos\Ultron Firewall\Ultron Firewall.exe
```

Há um atalho na Área de Trabalho e outro na pasta **Inicializar** (Startup)
apontando para lá. Portanto, **depois de cada `wails build`, copie o exe novo
por cima da cópia de produção** — senão você continua rodando o antigo:

```powershell
Copy-Item "build\bin\ultron_firewall.exe" "X:\HSTECH\Prototipos\Ultron Firewall\Ultron Firewall.exe" -Force
```

> ⚠️ **O exe fica travado enquanto roda, e roda elevado.** Não dá para
> substituí-lo com o app aberto, e um `taskkill` de um shell comum dá *Access
> Denied*. Para atualizar:
> 1. **Feche o Ultron:** Configurações → **Encerrar** (com a senha), ou
>    Gerenciador de Tarefas → **Finalizar tarefa** em `Ultron Firewall.exe`.
> 2. Copie o exe novo (comando acima).
> 3. Abra de novo (vai pedir UAC).

> **Ícone "velho" após trocar?** É cache do Explorer. Apague
> `%LOCALAPPDATA%\...\Explorer\iconcache_*.db` e reinicie o explorer (ou faça
> logoff/login).

---

## Estrutura do projeto

```
main.go                       # bootstrap do Wails (janela, bind, UAC, hooks de ciclo de vida)
app.go                        # métodos expostos à UI; senha master; esconder-na-bandeja / quit com senha
tray_windows.go               # ícone e menu da bandeja (energye/systray), em thread travada
notify_windows.go             # toasts do Windows (go-toast) numa thread dedicada

internal/
  model/      model.go        # tipos compartilhados (Config, Connection, Rule, HistoryEntry, ...)
  windivert/                  # binding Go puro do WinDivert
    windivert.go              #   Open / RecvPacket / SendPacket / CompileFilter
    parse.go                  #   parser IPv4/IPv6 + TCP/UDP
    assets.go                 #   dll + sys embutidos (bin/WinDivert.dll, bin/WinDivert64.sys)
  procinfo/   tcptable_windows.go  # PID dono da conexão (GetExtended{Tcp,Udp}Table, v4 e v6)
  engine/
    engine.go                 # laço de captura, decisão, enforcement, histórico, cache por fluxo
    dns.go                    # DNS snooping: parse das respostas + match de domínio (allow/tracker)
    proc_windows.go           # auxiliares de processo
  store/      store.go        # bbolt: config, regras, histórico, auth (defaults sobre JSON salvo)
  threat/     threat.go       # classificação de ataque + fila de POST (retry) ao servidor
  cookies/                    # limpeza de cookies dos navegadores (+ fechar navegadores)

frontend/                     # UI Svelte — abas Prompts / Histórico / Regras / Configurações
cmd/filtercheck/              # ferramenta de dev: valida o filtro do WinDivert sem admin
build/
  windows/icon.ico            # ícone (também embutido para a bandeja)
  windows/wails.exe.manifest  # manifesto com requireAdministrator (UAC)
```

---

## Dados e logs

Tudo em `%ProgramData%\UltronFirewall\`:

| Arquivo        | Conteúdo                                              |
|----------------|-------------------------------------------------------|
| `ultron.db`    | banco bbolt: config, regras, histórico, hash da senha |
| `ultron.log`   | log do app + traços de pânico recuperados             |

> Config nova sempre é sobreposta aos **padrões** ao carregar, então campos que
> ainda não existiam numa config salva antiga assumem o default (ex.:
> `InterceptUDP`, `NotifyEnabled`).

---

## Principais configurações

(Painel **Configurações**, ou struct `model.Config`.)

- `enabled` — motor ligado/desligado.
- `promptEnabled` — perguntar em conexões desconhecidas.
- `defaultOutbound` / `promptTimeoutSecs` — o que fazer quando o prompt está
  desligado ou expira (`0` = esperar para sempre).
- `interceptUdp` — capturar/registrar UDP de saída.
- `notifyEnabled` — toasts enquanto escondido na bandeja.
- `allowedDomains` — domínios (e subdomínios) sempre liberados.
- `blockTrackers` / `trackerDomains` — bloqueio de rastreadores/anúncios.
- `blocklist` — IPs remotos sempre tratados como ataque.
- `detectInbound` / `detectScan` / `detectBlocklist` / `detectOutDenied` — quais
  heurísticas de ameaça ligar.
- `reportEnabled` / `reportUrl` / `reportToken` — envio dos eventos de ataque.

---

## Reporte de ataque (POST)

Quando um evento é classificado como ataque e o envio está ligado, um `POST`
JSON vai para a URL configurada, com header `Authorization: Bearer <token>`,
com fila e **3 tentativas** de reenvio. O corpo
(`internal/threat/threat.go`, struct `Report`) é facilmente ajustável ao
contrato do seu servidor. Há um botão **"Testar envio"** nas Configurações.

---

## Solução de problemas

- **Clique na bandeja não responde (esquerdo ou direito) / app congela:**
  corrigido na build `1106-a` — a goroutine da bandeja agora é presa à sua
  thread (`runtime.LockOSThread`), pois no Windows os cliques do ícone só chegam
  à thread dona da janela. Confirme a tag no rodapé e, se persistir, veja o
  `ultron.log`.
- **UDP ou domínio não aparece/não libera na primeira vez:** o cache de DNS do
  SO (anterior ao start) pode não ter sido espiado. Rode `ipconfig /flushdns` —
  depois disso se resolve sozinho conforme o TTL.
- **Cookies não limparam:** o navegador estava aberto (arquivo travado). Feche-o
  (ou use a opção que fecha os navegadores) e tente de novo.
- **Para diagnosticar qualquer travamento/fechamento:** mande o
  `%ProgramData%\UltronFirewall\ultron.log`.

---

## Avisos

Qualquer firewall real no Windows precisa de **privilégio de administrador** e
**carrega um driver de kernel** (aqui, o WinDivert assinado, só enquanto o app
roda). Isso é inerente ao problema, não uma escolha deste projeto.
