# Ultron Firewall 🛡️

Firewall pessoal "pergunta antes de liberar" para Windows, enxuto e focado.
Inspirado no [Portmaster](https://github.com/safing/portmaster), mantendo a
espinha em **Go**, mas sem a dor de um driver de kernel próprio.

## O que faz

- **Pergunta** (allow/block) em conexões novas: uma vez, ou sempre (por app ou por app+destino).
- **Senha master** (hash bcrypt) protege alterações de regras e configurações.
- **Histórico** de todas as tentativas de entrada e saída.
- **Detecção de ataque** (entrada não solicitada, port scan, IP em lista negra, saída negada) com **POST** para um servidor de registro (URL/token configuráveis).

## Stack

- **Core:** Go (sem cgo).
- **Interceptação:** [WinDivert 2.2](https://reqrypt.org/windivert.html) na camada SOCKET
  (driver assinado, embutido no `.exe` e carregado em runtime — removido ao fechar; nada permanente).
- **UI:** [Wails v2](https://wails.io) + Svelte.
- **Persistência:** bbolt (KV puro em Go) em `%ProgramData%\UltronFirewall\ultron.db`.

## Requisitos

- Rodar **como Administrador** (o manifesto já pede UAC) — necessário para carregar o WinDivert.
- WebView2 (já presente no Windows 11).

## Desenvolvimento

Ferramentas: Go + Wails CLI (`go install github.com/wailsapp/wails/v2/cmd/wails@latest`). Node/npm para o frontend. **Não precisa de gcc** (sem cgo).

```powershell
# Build completo (em máquinas com pouca RAM, rode em etapas):
cd frontend; npm install; npm run build; cd ..
wails build -s          # compila o Go e empacota, usando o dist já pronto

# ou tudo de uma vez:
wails build
```

Saída: `build\bin\ultron_firewall.exe`.

Para desenvolvimento com hot-reload: `wails dev` (precisa de admin para o motor funcionar).

## Estrutura

```
app.go                 # métodos expostos à UI (Wails), senha master
main.go                # bootstrap Wails (janela, bind, UAC)
internal/
  model/               # tipos compartilhados
  windivert/           # binding Go puro do WinDivert (+ dll/sys embutidos em bin/)
  engine/              # captura, decisão (regra/prompt/padrão), enforcement
  store/               # bbolt: config, regras, histórico, auth
  threat/              # classificação de ataque + POST ao servidor
frontend/              # UI Svelte (Prompts / Histórico / Regras / Configurações)
```

## Reporte de ataque (POST)

Quando um evento é classificado como ataque e o envio está ligado, um `POST`
JSON é enviado para a URL configurada, com header `Authorization: Bearer <token>`.
O corpo (`internal/threat/threat.go`, struct `Report`) é facilmente ajustável
ao contrato do seu servidor.
