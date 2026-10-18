# Headscale control panel: design

Status: final draft, awaiting approval · Date: 2026-10-19
Working name: **meshpanel** (placeholder; the final name is still open)

## 1. Intent

This panel replaces **Headplane** as the web UI and control panel for a self-hosted **headscale** server. It does not replace headscale itself. A company uses it: many people, each with their own phones and laptops.

**Why this is needed.** Adding a device, a phone in particular, is painful today. You type the server URL into the Tailscale app, the phone shows a `headscale … register --auth-id …` command, and someone has to SSH into the server and run it with sudo. The panel removes the terminal from that loop:

1. A person signs in on the phone with their own account (password + 2FA).
2. Approvers get a Telegram message with **Approve / Deny** buttons, or they approve in the web dashboard.
3. The phone joins.

Headplane also logs in with a headscale API key, which expires and has to be re-pasted. The panel runs on the same machine as headscale and talks to it through headscale's local unix socket, which needs no API key and gives full access.

## 2. Goals

- **Feature parity with Headplane.** Everything it does except the Docker and Kubernetes integrations; the inventory is in §6.
- **Terminal-free device registration.** A custom `/register/<id>` page with sign-in, 2FA and approval. Approval works from Telegram or the web.
- **Local accounts.** Username + password, mandatory TOTP 2FA, and roles built from fine-grained permissions. "Approve devices" is one permission that can be granted to anyone, not only admins.
- **Configurable Telegram notifications.** People "watch" a device, user or tag and pick which events they hear about.
- **Live UI.** Node status and activity update in open browser tabs over WebSocket, without reloading.
- **Good ideas from other headscale UIs, done better.** These are listed in §7.

## 3. Non-goals

- Replacing headscale, or bundling or launching it.
- Docker or Kubernetes integrations, container images or Helm charts.
- Built-in HTTPS or automatic Let's Encrypt. The panel serves plain HTTP behind the user's existing reverse proxy.
- OIDC/SSO and external identity providers. Accounts are local only. *My call:* the code shouldn't make adding OIDC later impossible, but nothing is built for it now.
- Letting people without an account request device registration.
- Multiple headscale servers from one panel.

## 4. Anti-goals: this is a failure even if it works

The user named five failures:

1. **It isn't beautiful.** It has to look designed and polished, not like a generic admin template.
2. **It's hard to manage.** It should be one binary and one config file, with sensible defaults and clear errors.
3. **It isn't secure.**
4. **It uses a lot of resources.**
5. **It needs rebuilding.** Wasted tokens and time on rework are a failure. The architecture and theming must be right from the start (theme tokens, version-adapter layer, event bus), so later phases add to the code instead of rewriting it.

Concrete resource targets (*my call*):
- idle RSS under 60 MB without the optional tsnet agent
- binary under 40 MB without the SSH WASM bundle
- under 1% CPU at idle with 100 nodes

## 5. Constraints and decided "how"

The user decided these:

- **Language:** Go, compiled to a **single binary**. Templates, CSS, JS and icons are embedded with `go:embed`. There is no Node toolchain or Node build step.
- **Deployment:** the panel runs on the same machine as headscale. There is no Docker or K8s.
- **Port:** listens on **port 8030 by default**, over plain HTTP.
- **Reverse proxy:** an existing proxy (Caddy or nginx) sits in front of the panel. It routes three paths to the panel:
  - `/register/*`
  - `/auth/*`
  - the dashboard prefix, `/admin/*` by default

  Everything else, including Tailscale control traffic, goes to headscale as before. The panel ships tested, copy-paste Caddy and nginx snippets.
- **Headscale access:** through the **unix socket**, with no API key. headscale trusts socket requests locally (`WithLocalTrust`).
- **Accounts:** local username + password with 2FA. Many users.
- **Registration:** requires signing in. No account means no request.
- **Approvals:** come from admins **and anyone granted the approve permission**.
- **Notifications:** **configurable per watched device or user**, not one fixed stream.
- **Live updates:** the browser receives them over WebSocket. The server polls headscale, because headscale has no event stream.
- **Themes:** all three of **Paper, Midnight and Console**, selectable per user. **Paper is the default** for new users. The approved mockups are in `docs/superpowers/specs/mockups/visual-style.html` and `phone-flow.html`.
- **The phone flow and the Telegram card match the approved mockup:** sign in → 2FA → waiting (with a countdown) → connected ("approved by X"). The Telegram card has Approve / Deny / "Approve as another user…", and it changes to "Approved by X" for everyone.
- **Prior art is used for ideas only.** Do not copy code from other projects.

### 5.1 Target headscale version

The reference checkout in `info/headscale` is headscale **0.30.0-dev**. That version has **removed gRPC** and uses an HTTP API (`/api/v1`, `/api/v2`) on both TCP and the unix socket. The panel targets this HTTP API over the socket.

Every headscale call goes through a small **version-adapter package**, `internal/hs`. Other UIs broke on every headscale release from 0.25 to 0.28, and this layer is the protection against that. At startup the panel:
- reads the headscale version,
- checks it against a supported range,
- shows a clear banner and log line when the version is unsupported.

**Decided:** the panel supports **headscale 0.30.x only** (the HTTP API over the socket). The production server will be on 0.30 once it is released. There is no gRPC backend. The startup check refuses to run, with a clear message, on anything older than 0.30.0.

### 5.2 Relevant facts about headscale

These come from reading `info/headscale`:

- **Interactive registration URL:** `GET /register/{auth_id}`. The auth ID is `hskey-authreq-` followed by 24 hex characters. Pending requests expire after **15 minutes** (`tuning.register_cache_expiration`).
- **Completing a registration:** `POST /api/v1/auth/register` with `{user, authId}`.
- **SSH-check approvals:** `/auth/{auth_id}`, completed through `POST /api/v1/auth/approve` or `/auth/reject`.
- **The register page can't be customized.** headscale's HTML is hard-coded, so the proxy has to send these paths to the panel.
- **Node status:** `GET /api/v1/node` returns `online` and `lastSeen`. headscale has no webhook or event stream, so the panel polls.
- **Policy edits:** `PUT /api/v1/policy` works only when `policy.mode: database`. In file mode the panel writes the HuJSON file and reloads headscale; see §8.4.
- **Config-file settings:** DNS, DERP and most other settings live in `config.yaml` and have no API. Changing them means editing the file and restarting headscale.

## 6. Feature scope

### 6.1 Headplane parity (everything except Docker and K8s)

- **Machines**
  - List with filtering and search, and a detail page.
  - Rename, delete, expire key, disable or enable key expiry.
  - Set tags, approve subnet and exit-node routes. *My call:* "move to another user" is dropped, because headscale removed it in 0.28. The machine page offers "re-register under another user" instead: expire the node, then the person adds it again.
  - Badges: expiry, exit node, subnet, Tailscale SSH, agent.
- **Users** (headscale users): create, rename, delete, a "machines seen" count, and editing ACL group membership.
- **ACL/policy**
  - A raw HuJSON editor with syntax highlighting.
  - Visual editors for ACL rules, SSH rules, hosts, tags and groups.
  - The page stays readable when the policy is empty or in file mode.
- **DNS**
  - base domain/tailnet name, MagicDNS, override local DNS
  - global and split nameservers, with reordering
  - search domains
  - extra records, inline or in `extra_records_path`
- **Pre-auth keys:** list, create (user or tags, reusable, ephemeral, expiry), and expire. A role can be allowed to create keys only for its own linked user.
- **Settings:** an overview page, and the agent status page if the agent is enabled.
- **Roles and permissions:** the capabilities from Headplane's bitmask (§8.2).
- **Optional tsnet agent:** host info such as OS and version for each peer through WhoIs. *Off by default (my call),* because it adds memory use.
- **Web SSH terminal:** a WASM Tailscale client in the browser opens an SSH session to a node. *Optional and last phase (my call);* its WASM bundle is the biggest size cost.
- **Applying config changes:** the panel reloads or restarts headscale through a configurable command, systemd by default (§8.4).
- **Health:** `/healthz`, plus detection of the headscale version and its capabilities.

### 6.2 New beyond Headplane

- **Registration approval flow:** the phone pages plus Telegram and web approval (§8.3).
- **SSH-check approvals:** `/auth/{id}` uses the same sign-in flow. headscale doesn't tell the panel whose SSH session a link belongs to, so **only people with the `approve_ssh` permission can approve or reject**. Others see "You don't have permission to approve SSH access". SSH-check requests can also be sent to Telegram approvers like device requests.
- **Local accounts:** password + TOTP, backup codes, lockout, a session list with revoke, and invite links (§8.1).
- **Telegram bot:** account linking, approvals, watch notifications, and a security alert channel (§8.5).
- **Watch rules:** per device, user or tag, with event selection, debouncing and quiet hours (§8.6).
- **Audit log:** every change records who made it, through which channel (web or Telegram), the target, and before/after values. It is filterable and exportable to CSV.
- **Live dashboard:** online/offline/pending counts, a recent-activity feed, and warnings for keys and nodes about to expire.
- **Health watchdog:** if the headscale socket or API stops responding, the panel shows a banner and sends a Telegram alert, and it tells you when headscale recovers.
- **Invite flow:** for onboarding a new employee. An admin creates an invite, and the new person sets their own password and 2FA. The panel can also generate a pre-auth key as a QR code with a ready `tailscale up --login-server=…` command and per-OS steps.
- **Three ways to add a device in the dashboard:** pending request, pre-auth key, or pasting an auth ID. The ID format is validated with a clear error.
- **Safer policy edits:** validate with `POST /api/v1/policy/check`, show a diff, apply, and roll back automatically if headscale rejects the change.
- **Route approval with risk hints:** exit nodes and wide subnets such as /8 or 0.0.0.0/0 stand out visually.
- **Command palette (Ctrl/Cmd-K)** and keyboard navigation.
- **Themes:** Paper (default), Midnight and Console, per user, plus a "follow system" option that uses Paper for light and Midnight for dark. An admin sets the company accent color and logo once, and they apply inside every theme.

## 7. Lessons from other headscale UIs

Projects reviewed: gurucomputing/headscale-ui, GoodiesHQ/headscale-admin, Headscale-Admin-Pro, headtower, NodeRoost, and Telegram bots (headscale-buddy, headlauncher). The panel avoids the problems they had:

- **API keys stored in the browser.** The panel keeps no secrets in the browser; all headscale calls are made on the server.
- **CORS and proxy setup pain,** the most-filed issue across these projects. The UI and its API come from the same origin, the panel ships tested proxy snippets, and it runs correctly under a path prefix.
- **Breaking on headscale upgrades.** The version-adapter layer and startup check handle this, and CI tests run against a real headscale.
- **Vague errors.** Errors say exactly what failed, for example "socket /var/run/headscale/headscale.sock: permission denied; add user meshpanel to group headscale".
- **Telegram bots that trust a list of allowed IDs.** Telegram buttons are signed and single-use, tied to a linked panel account and checked against its permissions on every tap.

## 8. Design details

### 8.1 Accounts and security

- **Passwords:** hashed with argon2id. Minimum length is 10. The panel refuses to start with a weak or default session secret, and the first-run setup forces creating the owner account.
- **2FA:** TOTP (RFC 6238), **mandatory for every account**. Setup is a QR code plus 10 single-use backup codes. An admin can reset a user's 2FA, and the reset is audited.
- **Sessions:**
  - stored on the server in SQLite, with only a random session ID in a cookie (`HttpOnly`, `Secure` by default, `SameSite=Lax`)
  - idle timeout 7 days, absolute lifetime 30 days (*my call; configurable*)
  - users see their sessions and can revoke them; admins can revoke anyone's
- **CSRF:** a token on every state-changing request. WebSocket connections check `Origin`.
- **Brute force:** attempts are limited per IP and per account. After 5 failed attempts the account locks with exponential backoff, and Telegram alerts admins about repeated failures (*my call on thresholds*).
- **Client IP:** taken from `X-Forwarded-For` only when the request comes from configured `trusted_proxies`.
- **Last-owner guard:** the last remaining owner can't be removed or demoted.
- **Linking to headscale users:** each panel account is linked to one headscale user. Creating a panel account automatically creates the headscale user with the same name, unless an admin links an existing one (*my call*).
- **Invites:** single-use links that expire after 72 hours. The invited person sets their own password and TOTP.

### 8.2 Roles and permissions

Permissions are a set of capability flags. The flags start from Headplane's list:
- `ui_access`
- `read_policy` / `write_policy`
- `read_network` / `write_network` (DNS, routes)
- `read_feature` / `write_feature`
- `configure_iam`
- `read_machines` / `write_machines`
- `read_users` / `write_users`
- `generate_authkeys` / `generate_own_authkeys`
- `use_tags`
- `write_tailnet`
- `owner`

The panel adds:
- `approve_devices`
- `approve_devices_own` (*my call:* lets a person self-approve only their own devices)
- `manage_notifications`
- `read_audit`
- `approve_ssh` (approves SSH-check requests at `/auth/{id}`)

**Roles:** owner, admin, network_admin, it_admin, auditor, viewer, member. A role is a named bundle of permissions. An admin can grant **extra permissions per person** on top of their role, for example `approve_devices` for a team lead.

**Scope by ownership (decided).** A person without the global `read_machines` permission sees **only their own devices** (those of their linked headscale user), plus their own alerts, sessions and pending requests. Admins and auditors see everything. The ownership filter lives in one place, the permission/query layer, from phase 1. It applies to every list, detail page, WebSocket push and command-palette result. The `member` role gets `ui_access` plus self-scoped read access, and can manage its own devices (rename, expire, delete).

**Self-approval:** a person who has `approve_devices` (or `approve_devices_own`) can register their own device without waiting.

*My call:* a later option could limit approval to devices of users in certain groups. It is not built in phase 1, but the permission check is a function, so adding it later doesn't need a rewrite.

### 8.3 Registration flow

1. The phone opens `/register/{auth_id}`, which the proxy routes to the panel. The panel can only validate the ID format, because headscale exposes no lookup for pending requests.
   - An unknown or expired ID shows up only when `auth/register` fails at approval time. The page and the Telegram card then show "This request expired. Reopen the Tailscale app to get a new link."
2. The person signs in with password and TOTP. The page shows device context:
   - the IP and user agent of the browser making the request
   - the hostname and OS if the panel can get them (see §12)
3. A pending request is created in SQLite with requester, auth ID, device info, `expires_at` (15 minutes from when the page loads; headscale's own timer started slightly earlier, so the countdown is approximate and labelled "about") and status.
   - If the requester has `approve_devices` or `approve_devices_own`, the panel approves immediately (step 5).
   - Otherwise every user with `approve_devices` who has linked Telegram gets the request card. The card also appears in the dashboard, with a badge and live push.
4. The phone page shows "Waiting for approval" with a countdown. A WebSocket updates it live, with long-polling as a fallback. The requester can cancel.
5. On approval (web or Telegram), the panel calls `POST /api/v1/auth/register {user: <requester's headscale user>, authId}`.
   - "Approve as another user…" picks a different headscale user.
   - The pending row is marked approved or denied **once**, in an atomic compare-and-set. Any later tap gets "already approved by X".
   - Every Telegram copy of the card is edited to "✅ Approved by anna · 10:42", with the buttons removed.
   - The phone page shows "You're connected" with the device name and IP.
6. On denial or expiry, the page and the Telegram cards update, and the event is audited.

### 8.4 Applying headscale config and policy changes

- **Config edits** (DNS, and anything else with no API) are made to `config.yaml` with Go's yaml.v3 node API, so comments and key order are kept.
  - Writes are serialized, and each change keeps a timestamped backup of the previous file.
  - The panel validates the result before applying it, by running `headscale configtest` if available (*builder to verify that command exists*), and otherwise by schema checks.
- **Applying:** the panel runs a configured `reload_command` (for policy files) or `restart_command` (for config changes).
  - The defaults are `systemctl reload headscale` and `systemctl restart headscale`, run through a documented sudoers rule that allows only those exact commands.
  - The panel then waits for `/api/v1/health` to pass, and rolls back from the backup if it doesn't.
- **Policy:** in `database` mode it goes through the API. In `file` mode the panel writes `policy.path` and runs the reload command. If neither works, the editor is read-only and explains why.
- **Permissions on disk:** the panel runs as its own system user, `meshpanel`, in the `headscale` group. It needs write access to `config.yaml` and the policy file only if those features are used. The installer docs give the exact `chmod`/`chgrp` commands.

### 8.5 Telegram bot

- **Configuration:** the bot token goes in the config file. The bot uses **long polling** (*my call*), so it needs no public webhook endpoint or extra proxy route.
- **Linking an account:** on the account page, the person taps a single-use `t.me/<bot>?start=<token>` link that is valid for 10 minutes. This binds their Telegram chat ID to their panel account. Unlinking is possible from either side.
- **Button security:** the callback data holds a short random ID. That ID points to a stored action row containing the request, action, intended account and expiry.
  - On every tap the panel checks that the tapping chat is linked to an account that **currently** has the permission.
  - Actions are single-use, and every tap is audited with channel `telegram`.
- **Message types:**
  - approval cards
  - watch notifications
  - security alerts: lockouts, repeated failed logins, 2FA resets, new owner/admin, headscale down or recovered
- **Group chat:** *my call:* an admin can optionally set a company group chat that also receives approval cards. Taps there still require a linked account with the permission.
- **Rate limiting:** sends go through a queue that respects Telegram's rate limits, with retries.

### 8.6 Watch rules and notifications

- **Rule format:**
  - subject: device, user, tag, or "everything" (admins only)
  - events (chosen per rule): online, offline, new device registered, device deleted, key expiring in N days, key expired, route advertised or approved, not seen for N hours, tags changed
  - delivery: Telegram, plus a feed in the dashboard
- **Ownership:** each rule belongs to the person who made it, and people manage their own. Admins can create rules for others if they have `manage_notifications`.
- **Anti-spam:**
  - debounce: offline must last 2 minutes before alerting, configurable per rule
  - a flapping detector that collapses repeats into one "flapping" message
  - per-user quiet hours, with security alerts exempt
- **Source of events:** a poller diffs `GET /api/v1/node` and `/user` every **5 seconds** (configurable) and publishes typed events on an in-process **event bus**. The WebSocket hub, the notification engine, the audit log and the dashboard feed all subscribe to the bus. Changes made through the panel publish events immediately, without waiting for the next poll.

### 8.7 Live UI

- Pages are rendered on the server with Go `html/template` plus **htmx**, and a small amount of hand-written JS for the WebSocket client, the command palette and the editors.
- One WebSocket per tab carries event messages. htmx swaps the affected fragments: rows, counters, pending cards.
- If the WebSocket fails, the page falls back to polling every 15 seconds.
- **ACL editor:** a vendored, pre-built CodeMirror ESM bundle, embedded in the binary (*my call*).

### 8.8 Theming and design

- **Design tokens:** every color, font, radius, spacing step and shadow is a CSS custom property, defined once per theme, so components never hard-code a color.
- **Themes:**
  - **Paper (default):** light, warm neutrals, near-black accent.
  - **Midnight:** dark, violet accent.
  - **Console:** monospace, terminal green, denser spacing.
- **Theme choice:** "Follow system" switches between Paper and Midnight. The choice is stored on the account, with a cookie for the sign-in page.
- **Company branding:** the admin's accent color and logo override the accent in all themes. The panel warns when the accent has poor contrast.
- **Layout:** a sidebar with Overview, Machines, Users, Access, DNS, Keys, Alerts, Audit and Settings, as in the mockup. It is fully responsive, and the phone registration pages are designed mobile-first.
- **Icons:** inline SVG (for example Lucide, MIT-licensed), embedded. Interface text is in English only.
- **Fonts:** Inter for text and a monospace font for Console and code, both self-hosted in the binary. No external CDN calls.

### 8.9 Storage and config

- **Database:** SQLite through a pure-Go driver (`modernc.org/sqlite`), so the binary builds without cgo and is static. It runs in WAL mode, with versioned migrations embedded.
  - **Tables:** users, sessions, totp/backup_codes, invites, roles/permissions, telegram_links, pending_registrations, telegram_actions, watch_rules, notifications, audit_log, settings, host_info.
- **Config:** a single YAML file, `/etc/meshpanel/config.yaml`, where every key can be overridden by environment variables (`MESHPANEL_…`). Settings that don't belong in the file can be edited in the UI (accent, logo, group chat), and those are stored in the DB.
- **Secrets:** the session secret and bot token can be given inline or as `*_path` file references.
- **Backups:** `meshpanel backup` is a CLI subcommand that takes a consistent SQLite snapshot (*my call*).

### 8.10 Packaging

- Static binaries for linux/amd64 and linux/arm64.
- A systemd unit with hardening: `ProtectSystem=strict`, `NoNewPrivileges` (not set when the restart command needs sudo), and `ReadWritePaths` for only the needed files.
- A sudoers snippet, Caddy and nginx snippets, and an install guide that works on a plain LAN IP for a trial.
- CLI subcommands:
  - `serve`
  - `setup` (creates the first owner)
  - `user reset-2fa` (recovery if every owner is locked out)
  - `backup`
  - `doctor` (checks socket access, file permissions, headscale version and proxy routes)

## 9. Phases

The order is chosen so no phase rewrites an earlier one.

1. **Foundation:**
   - config loading, SQLite and migrations
   - the `internal/hs` socket client with version check
   - accounts, TOTP and sessions; roles and permissions
   - the event bus and poller, the WebSocket hub
   - the layout and design tokens with the **Paper** theme
   - read-only machines and users
2. **Machine and user management:** all write actions on machines, users, routes and pre-auth keys, with the audit log.
3. **Registration and approvals:** the `/register` and `/auth` pages, pending requests, web approval, the Telegram bot (linking, approval cards, the single-use model), and the proxy snippets.
4. **Notifications and safety:** watch rules, debounce and quiet hours, security alerts, the health watchdog, the dashboard feed and expiry warnings.
5. **Network config:** the policy editors (raw and visual, with diff and rollback), DNS editing, config-apply with rollback, and invites with QR.
6. **Polish:** the Midnight and Console themes, company branding, the command palette, and `doctor`.
7. **Optional extras:** the tsnet host-info agent and the web SSH terminal.

## 10. Testing

- Unit tests for permissions, the registration state machine, the Telegram action model, watch-rule debouncing, and config YAML round-trips.
- Integration tests run against a **real headscale** built from `info/headscale` and started on a temporary socket. They cover registration, approval, node actions and policy apply/rollback.
- The Telegram bot is tested against a fake Bot API server.
- A resource check in CI measures idle RSS and binary size against the targets in §4.

## 11. Left to the builder

- The Go package layout, and the choice of HTTP router and htmx version.
- Exact SQL schema details and migration tooling.
- Exact proxy snippet syntax, which must be tested.
- Error wording, empty states, and micro-interactions within the approved visual direction.
- Whether `extra_records_path` uses JSON or YAML, matching what headscale accepts.
- Confirmed in the headscale source: `headscale configtest` exists, SIGHUP reloads the policy only (config changes need a restart), and `/api/v1/policy/check` exists.

## 12. Open questions

- **Final product name**, to replace "meshpanel".

Resolved:
- **headscale version:** 0.30.x only (§5.1).
- **Device details before approval:** headscale doesn't expose pending registrations; its `registration-cache` debug page only shows counts. The approval card shows the requester, IP and user agent. The device name and OS appear after approval.
- **Changes to headscale itself:** nothing depends on an upstream change. *Optional bonus:* propose upstream a read endpoint for pending auth requests. If it is accepted, it adds the device name and OS to the approval card, rejects expired links before sign-in, and gives an exact countdown, behind a capability check.
- **headscale config:** edited by hand on a normal systemd Linux, so in-place editing with backups and rollback (§8.4) is a real feature, not view-only.
