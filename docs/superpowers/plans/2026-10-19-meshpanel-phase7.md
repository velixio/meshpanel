# meshpanel phase 7: device info and browser SSH

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Two optional features, both off by default:
- a host-info agent that shows OS, version and connection details for each machine;
- a browser SSH terminal.

**Architecture:** A new package, `internal/tailnet`, embeds `tailscale.com/tsnet` in the meshpanel binary.

- **Agent:** one long-lived node registered under a dedicated headscale user (default `meshpanel`). Its state is kept in `<db dir>/tailnet/agent`. It calls `WhoIs` for every peer every 60 seconds and caches the host info.
- **SSH:** each terminal session starts an ephemeral tsnet node registered under the signed-in person's own headscale user. That node dials `<node ip>:22`, runs an `x/crypto/ssh` client, and relays the session to xterm.js over a WebSocket.
  - Tailscale SSH policy is evaluated against the person's identity, not the panel's.
  - The ephemeral node is deleted when the session closes.

This deliberately differs from Headplane's in-browser WebAssembly client, which costs more than 20 MB in the browser and needs DERP over WebSocket.

**Tech:**
- `tailscale.com/tsnet` v1.104.1, built with `ts_omit_*` tags; the list is in `Makefile`'s `TSTAGS`.
- `golang.org/x/crypto/ssh`
- xterm.js 5.5 and xterm-addon-fit, vendored into `internal/web/static/vendor/`

**Spec:** `docs/superpowers/specs/2026-10-19-headscale-panel-design.md` §6.1 (optional tsnet agent, web SSH) and §9 phase 7.

## Global Constraints

- The single binary, embedded assets and no CDN still apply.
- The release build with `TSTAGS` must stay under 40 MB.
- Both features are off unless `agent.enabled` / `web_ssh.enabled` are set.
- When off, they cost nothing: no tsnet node starts and no memory is used.
- SSH needs the new `web_ssh` capability, and the target machine must be in the caller's scope.
- The caller must have a linked headscale user; SSH identity is that person.
- Session limits: 10 sessions in total and 3 per account, both configurable.
- Audit `ssh.open` and `ssh.close`, with duration.

## Review Focus

1. A member opens SSH to someone else's machine by ID. Expect a 404 before any node starts (`TestSSHScope`).
2. A session-limit overflow. Expect a clear refusal (`TestSSHLimits`).
3. The browser closes mid-session. The node and SSH connection are torn down and the slot is freed (`TestRelayClosesOnClientGone`).
4. A password or keyboard-interactive prompt reaches the browser and the answer comes back (`TestRelayPasswordPrompt`).
5. The agent is unreachable or not started. Pages still render with no device-info block (covered by the page smoke test).

## Tasks

### Task A: Relay core (`internal/tailnet/relay.go`)

- `type Term interface { io.ReadWriter; Resizes() <-chan Size; Prompt(ctx, question string, echo bool) (string, error); Status(state, msg string) }`
- `Relay(ctx, conn net.Conn, user string, t Term, initial Size) error`. It runs an SSH client over `conn` with these auth methods:
  - none, which Tailscale SSH accepts
  - password, asked through `Prompt`
  - keyboard-interactive
- It requests a PTY of type `xterm-256color`, starts a shell, and copies data both ways. It applies resizes and returns when either side ends.
- Tests use an in-process `x/crypto/ssh` server over `net.Pipe`:
  - `TestRelayEcho`
  - `TestRelayPasswordPrompt`
  - `TestRelayClosesOnClientGone`
  - `TestRelayResize`

### Task B: SSH manager (`internal/tailnet/ssh.go`)

- `Manager{Keys KeyMaker, Nodes NodeFactory, MaxTotal, MaxPerUser}`.
- `Open(ctx, accountID, hsUser, targetIP, sshUser, term) error` checks the limits, creates an ephemeral key, starts the node, dials, relays, and cleans up.
- `NodeFactory` is an interface. The real implementation is tsnet; the fake is `net.Pipe`.
- Tests:
  - `TestSSHLimits`
  - `TestSSHCleanupOnError`

### Task C: Agent (`internal/tailnet/agent.go`)

- `Agent{…}.Run(ctx)`:
  - ensures the headscale user exists;
  - creates a pre-auth key only when no saved state exists;
  - runs `Up`, then refreshes every 60 seconds.
- `Info(nodeKey) (HostInfo, bool)` and `State() AgentState`.
- `HostInfo{OS, OSVersion, Distro, DistroVersion, DeviceModel, IPNVersion, Hostname, Endpoints, HomeDERP, Updated}`.
- The tsnet calls can't be unit-tested without a control server. The pure parts (merge, cache) are tested: `TestHostInfoFromHostinfo`.

### Task D: Wiring

- **Config:**
  - `agent{enabled, hs_user, control_url, state_dir, hostname}`
  - `web_ssh{enabled, max_sessions, max_per_user, default_user}`
- **Capability:** `perm.WebSSH`, named `web_ssh`. Roles: owner, admin, network_admin, it_admin, member.
- **Web routes:**
  - `GET /admin/machines/{id}/ssh`: terminal page
  - `GET /admin/machines/{id}/ssh/ws`: WebSocket
- **WebSocket protocol:**
  - binary frames carry terminal data
  - text JSON `{t:"resize",c,r}` and `{t:"answer",v}` from the client
  - text JSON `{t:"prompt",q,echo}` and `{t:"status",s,m}` from the server
- **Machine page:**
  - a "Device" card when agent info exists
  - an "SSH" button when SSH is enabled and allowed
- **Machines list:** an OS line under the name.
- **Settings:** agent status.
- **Tests:**
  - `TestSSHScope`
  - `TestSSHRequiresHSUser`
  - `TestSSHDisabled`
  - the smoke test extended with the agent on
- **Build:** `TSTAGS` in the Makefile, `.goreleaser.yaml` and CI.
- **Docs:** README, install guide and config example updated, including the policy snippet that gives the agent visibility.
