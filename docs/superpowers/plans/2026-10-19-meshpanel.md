# meshpanel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build meshpanel. It is a single-binary Go control panel for headscale 0.30 that replaces Headplane. It adds local accounts with TOTP, terminal-free device registration approved from the web or Telegram, watch-rule notifications, and a live UI.

**Architecture:** One Go module, one binary (`cmd/meshpanel`). All headscale access goes through `internal/hs`, which calls headscale's HTTP API over the unix socket. A poller diffs the socket state and publishes onto `internal/events.Bus`; the WebSocket hub, the notifier, the audit log and the dashboard feed subscribe to it. The UI is server-rendered with `html/template`, htmx, and themes defined as CSS tokens. Templates and assets are embedded with `go:embed`.

**Tech Stack:**
- Go 1.24+ standard library, with a `net/http` ServeMux using method and path patterns
- `modernc.org/sqlite` (pure Go, no cgo)
- `gopkg.in/yaml.v3`
- `golang.org/x/crypto/argon2`
- `github.com/coder/websocket`
- `github.com/pquerna/otp` (TOTP)
- `github.com/skip2/go-qrcode`
- vendored `htmx.min.js` 2.x
- hand-written CSS/JS

**Spec:** `docs/superpowers/specs/2026-10-19-headscale-panel-design.md`

## Global Constraints

- **Binary and listener:** one static binary built with `CGO_ENABLED=0`. Listens on `:8030` by default over plain HTTP. No built-in TLS. Dashboard prefix is `/admin`.
- **headscale access:** only through the unix socket (default `/var/run/headscale/headscale.sock`). No API key. headscale 0.30.x only; refuse to run on anything older than 0.30.0, with a clear message.
- **No external calls from the browser:** no CDN. Fonts, icons and JS are embedded.
- **2FA is mandatory** for every account. Passwords use argon2id, minimum length 10.
- **Sessions:** server-side, 7 days idle and 30 days absolute. Cookie flags `HttpOnly`, `SameSite=Lax`, and `Secure` by default (configurable).
- **Lockout:** 5 failed attempts triggers exponential backoff.
- **Pending registrations** expire 15 minutes after the page loads.
- **Invites** expire after 72 hours. Telegram link tokens expire after 10 minutes.
- **Default watch-rule offline debounce:** 2 minutes. Poll interval 5 seconds; browser fallback poll 15 seconds.
- **Themes:** `paper` (default), `midnight`, `console`, and `system` (paper/midnight).
- **Resource targets:** idle RSS under 60 MB; binary under 40 MB.
- **Interface text:** English only.
- **Excluded from this build:** OIDC, Docker/K8s integrations, multiple servers.
- **Config:** `/etc/meshpanel/config.yaml`, with `MESHPANEL_*` environment overrides and `*_path` secret files.
- **Repo:** ready for open source. MIT LICENSE, README, CONTRIBUTING, SECURITY, CI, release config (goreleaser), systemd unit, sudoers snippet, and Caddy/nginx snippets.

## Review Focus

1. **Double approval race.** Telegram and web approve the same request at the same moment. Exactly one calls headscale and the other gets "already approved by X". Pinned by `TestRegistrationApproveOnce` in Task 6.
2. **A Telegram tap from a chat whose account has since lost the permission.** It must be refused. Pinned by `TestTelegramActionRechecksPermission` in Task 8.
3. **A member reading another person's device** by guessing its ID in the URL or seeing it in a WebSocket push. Both must be filtered. Pinned by `TestScopeFiltersNodes` in Task 3.
4. **A config.yaml edit that breaks headscale.** The panel must restore the backup. Pinned by `TestApplyRollsBackOnFailure` in Task 10.
5. **A flapping device spamming Telegram.** It must produce at most one offline alert per debounce window. Pinned by `TestDebounceSuppressesFlap` in Task 9.

---

## File map

```
cmd/meshpanel/main.go            CLI: serve | setup | user reset-2fa | backup | doctor | version
internal/config/                 Config struct, Load(path) with env overrides and secret files, Validate()
internal/db/                     Open(path) and embedded migrations (migrations/*.sql); store methods by domain:
                                 users.go sessions.go invites.go registrations.go telegram.go watches.go audit.go settings.go
internal/auth/                   password.go (argon2id), totp.go, session.go (manager and middleware), ratelimit.go, csrf.go
internal/perm/                   perm.go (capability flags, roles, Has), scope.go (ownership filtering)
internal/hs/                     client.go (unix socket HTTP), types.go, nodes.go users.go keys.go policy.go auth.go, version.go
internal/events/                 bus.go (pub/sub), poller.go (diff to events)
internal/registration/           service.go (pending request state machine, approve-once)
internal/telegram/               api.go (Bot API client), bot.go (long poll, linking, callbacks), cards.go (message text)
internal/notify/                 engine.go (watch rules, debounce, quiet hours, flap), security.go
internal/hsconfig/               editor.go (yaml.v3 node patch, backups), apply.go (reload/restart, health wait, rollback)
internal/audit/                  audit.go (Record helper and CSV export)
internal/web/                    server.go (routes), middleware.go, render.go, handlers_*.go, ws.go
internal/web/templates/          layout, pages, partials (*.html)
internal/web/static/             css/tokens.css css/app.css js/app.js js/editor.js htmx.min.js fonts/ icons.svg
deploy/                          meshpanel.service, sudoers, Caddyfile, nginx.conf, config.example.yaml
.github/workflows/ci.yml, .goreleaser.yaml, Makefile, README.md, LICENSE, CONTRIBUTING.md, SECURITY.md
```

## Tasks

### Task 1: Module, config and CLI skeleton
**Files:** `go.mod`, `cmd/meshpanel/main.go`, `internal/config/config.go`, `internal/config/config_test.go`, `deploy/config.example.yaml`
**Produces:**
- `config.Load(path string) (*Config, error)`. Overrides use `MESHPANEL_` plus the upper-snake key path, for example `MESHPANEL_SERVER_LISTEN`.
- `Config.Validate() error`, which rejects a session secret shorter than 32 bytes or equal to the example value.
- Fields:
  - `Server{Listen, BasePath, PublicURL, CookieSecure, TrustedProxies, SessionSecret}`
  - `Headscale{Socket, HTTPURL, ConfigPath, PolicyPath, ReloadCommand, RestartCommand, PollInterval}`
  - `DB{Path}`
  - `Telegram{Token, GroupChatID}`
  - `Agent{Enabled}`
- Defaults:
  - Listen `:8030`, BasePath `/admin`
  - Socket `/var/run/headscale/headscale.sock`, HTTPURL `http://127.0.0.1:8080`
  - ReloadCommand `sudo systemctl reload headscale`, RestartCommand `sudo systemctl restart headscale`
  - PollInterval `5s`, DB path `/var/lib/meshpanel/meshpanel.db`

- [ ] Tests:
  - `TestLoadDefaults`
  - `TestEnvOverride`: `MESHPANEL_SERVER_LISTEN=:9000` gives `:9000`
  - `TestSecretPath`: `session_secret_path` reads the file and trims it
  - `TestValidateWeakSecret`
- [ ] Implement, run `go test ./internal/config/`, commit.

### Task 2: Database and auth primitives
**Files:** `internal/db/*.go`, `internal/db/migrations/0001_init.sql`, `internal/auth/{password,totp,ratelimit,csrf,session}.go` plus tests
**Produces:**
- `db.Open(path) (*DB, error)`: WAL mode, `foreign_keys=on`, runs migrations.
- Tables: `accounts`, `sessions`, `backup_codes`, `invites`, `pending_registrations`, `telegram_links`, `telegram_link_tokens`, `telegram_actions`, `telegram_messages`, `watch_rules`, `notifications`, `audit_log`, `settings`, `login_attempts`.
- `auth.HashPassword(pw) (string, error)` and `auth.VerifyPassword(hash, pw) bool`. Both use argon2id with m=64MB, t=3, p=2, and a PHC-format string.
- `auth.NewTOTPSecret(account) (secret, otpauthURL string)`, `auth.ValidateTOTP(secret, code) bool` (±1 step), `auth.NewBackupCodes() []string` (10 codes, stored hashed).
- `auth.Limiter.Allow(key string) (ok bool, retryAfter time.Duration)` with `Fail(key)` and `Reset(key)`. The first 5 failures are free; after that the backoff is `2^(n-5)` seconds, capped at 15 minutes.
- `auth.Sessions`: `Create(accountID, ip, ua) (token)`, `Lookup(token) (*db.Session, *db.Account, error)` (enforces idle and absolute expiry), `Revoke(id)`. The cookie name is `mp_session`.
- CSRF: a per-session token, checked for every non-GET request in the `X-CSRF-Token` header or the `_csrf` form field.

- [ ] Tests:
  - `TestPasswordRoundTrip`
  - `TestTOTPWindow`
  - `TestBackupCodeSingleUse`
  - `TestLimiterBackoff`: after 6 failures, `retryAfter` is 2s
  - `TestSessionIdleExpiry`
  - `TestMigrationsIdempotent`
- [ ] Implement, test, commit.

### Task 3: Permissions and ownership scope
**Files:** `internal/perm/perm.go`, `internal/perm/scope.go`, `perm_test.go`
**Produces:**
- `type Cap uint64` with the flags from spec §8.2:
  - UIAccess, ReadPolicy, WritePolicy, ReadNetwork, WriteNetwork, ReadFeature, WriteFeature, ConfigureIAM
  - ReadMachines, WriteMachines, ReadUsers, WriteUsers, GenerateAuthkeys, GenerateOwnAuthkeys, UseTags, WriteTailnet, Owner
  - ApproveDevices, ApproveDevicesOwn, ManageNotifications, ReadAudit, ApproveSSH
- `Roles map[string]Cap` for owner, admin, network_admin, it_admin, auditor, viewer and member.
- `Effective(role string, extra Cap) Cap` and `(Cap) Has(c Cap) bool`.
- `Scope{AccountID int64; HSUser string; All bool}`, built by `ScopeFor(caps, hsUser)`. `All` is set when the account has ReadMachines.
- `(Scope) Node(n hs.Node) bool`, `(Scope) Nodes([]hs.Node) []hs.Node`, `(Scope) CanApprove(caps, requesterHSUser) bool`.

- [ ] Tests:
  - `TestRolesMatrix`: member lacks ReadMachines; owner has every flag
  - `TestScopeFiltersNodes`: a member sees only nodes whose `User.Name` equals their own headscale user, and tagged nodes are hidden
  - `TestCanApproveOwn`
- [ ] Implement, test, commit.

### Task 4: headscale client (`internal/hs`)
**Files:** `client.go`, `types.go`, `nodes.go`, `users.go`, `keys.go`, `policy.go`, `auth.go`, `version.go`, `client_test.go`
**Produces:**
- `hs.New(socket, httpURL string) *Client`. The transport dials the unix socket; requests use the `http://unix` host.
- The types match the headscale v1 JSON exactly:
  - `Node{ID, Name, GivenName, User *User, IPAddresses, Online, LastSeen *time.Time, Expiry *time.Time, CreatedAt, RegisterMethod, ApprovedRoutes, AvailableRoutes, SubnetRoutes, Tags []string, MachineKey, NodeKey}`
  - `User{ID, Name, DisplayName, Email, CreatedAt}`
  - `PreAuthKey{ID, Key, User *User, Reusable, Ephemeral, Used, Expiration, CreatedAt, ACLTags}`
- Methods, each with `ctx` as the first argument:
  - `ListNodes(ctx, user string) ([]Node, error)` → `GET /api/v1/node`, then `.nodes`
  - `GetNode(ctx, id)`
  - `DeleteNode`
  - `ExpireNode(ctx, id, disable bool)`: body `{"disableExpiry":true}` or no body
  - `RenameNode(ctx, id, name)`
  - `SetTags(ctx, id, []string)`
  - `ApproveRoutes(ctx, id, []string)`
  - `ListUsers`, `CreateUser(ctx, name, display, email)`, `RenameUser(ctx, id, name)`, `DeleteUser(ctx, id)`
  - `ListPreAuthKeys`, `CreatePreAuthKey(ctx, CreateKeyReq{User id string, Reusable, Ephemeral, Expiration *time.Time, ACLTags})`, `ExpirePreAuthKey(ctx, id)`, `DeletePreAuthKey(ctx, id)`
  - `GetPolicy(ctx) (Policy{Policy string, UpdatedAt}, error)`, `SetPolicy(ctx, s)`, `CheckPolicy(ctx, s)`
  - `AuthRegister(ctx, user, authID) (Node, error)`, `AuthApprove(ctx, authID)`, `AuthReject(ctx, authID)`
  - `Health(ctx) error` → `GET /api/v1/health`
  - `Version(ctx) (string, error)` → `GET {httpURL}/version`, then `.version`. This is plain TCP, because the socket doesn't serve `/version`.
- `CheckSupported(v string) error`: accepts `0.30.x` and `dev`/`main` builds, and rejects anything older with `ErrUnsupportedVersion`.
- Errors: a non-2xx response is decoded as RFC 7807 into `*APIError{Status int, Title, Detail string}`.
- `ValidAuthID(s) bool`: `^hskey-authreq-[0-9a-f]{24}$`.

- [ ] Tests, run against an `httptest` server on a temporary unix socket:
  - `TestListNodesDecodes`, using a fixture JSON copied from the headscale v1 shape
  - `TestAuthRegisterBody`, which asserts the body `{"user":"ravi","authId":"hskey-authreq-…"}`
  - `TestProblemJSONError`
  - `TestCheckSupported`
  - `TestValidAuthID`
- [ ] Implement, test, commit.

### Task 5: Event bus and poller
**Files:** `internal/events/bus.go`, `poller.go`, `poller_test.go`
**Produces:**
- `type Event struct{Kind Kind; At time.Time; NodeID, NodeName, HSUser string; Actor string; Channel string; Data map[string]any}`.
- Kinds:
  - NodeOnline, NodeOffline, NodeAdded, NodeDeleted, NodeRenamed, NodeTagsChanged
  - RouteAdvertised, RouteApproved, KeyExpiring, KeyExpired
  - UserAdded, UserDeleted
  - RegistrationPending, RegistrationDecided
  - HeadscaleDown, HeadscaleUp, Security, AuditWritten
- `Bus.Subscribe(buf int) (<-chan Event, func())` and `Bus.Publish(Event)`. Publishing never blocks; it drops for slow subscribers and logs.
- `Poller{Client, Bus, Interval}.Run(ctx)`.
- `Diff(prev, next []hs.Node, now time.Time) []Event`, a pure function.
  - KeyExpiring fires once per node when the expiry is under 7 days away.
  - The latest snapshot is exposed through `Poller.Snapshot() []hs.Node`, so pages render without calling headscale again.
  - When headscale health fails, HeadscaleDown fires once; HeadscaleUp fires on recovery.

- [ ] Tests:
  - `TestDiffOnlineOffline`
  - `TestDiffAddedDeleted`
  - `TestDiffRoutesAdvertised`
  - `TestDiffKeyExpiringOnce`
- [ ] Implement, test, commit.

### Task 6: Registration service
**Files:** `internal/registration/service.go`, `service_test.go`
**Produces:**
- `Service{DB, HS registrar, Bus}`, where `registrar` is the interface `AuthRegister(ctx, user, id) (hs.Node, error)` plus `AuthApprove` and `AuthReject`.
- `Kind`: `register` or `ssh`.
- `Create(ctx, kind, authID, requester *db.Account, ip, ua) (*db.Pending, error)`. It is idempotent for the same authID and requester.
- `Decide(ctx, id int64, approve bool, actor *db.Account, channel string, asHSUser string) (*db.Pending, error)`.
  - The status changes `pending` → `approving` with a SQL `UPDATE … WHERE status='pending'` (atomic compare-and-set), then headscale is called, then the status is set to `approved` or `failed`.
  - When the update matches no row, it returns `ErrAlreadyDecided`, carrying `DecidedBy`.
- `Cancel` and `ExpireSweep(now)`.
- Statuses: `pending`, `approving`, `approved`, `denied`, `expired`, `cancelled`, `failed`.
- Publishes RegistrationPending and RegistrationDecided.

- [ ] Tests:
  - `TestRegistrationApproveOnce`: two goroutines call `Decide` concurrently; exactly one `AuthRegister` call happens and the other gets `ErrAlreadyDecided`
  - `TestRegistrationExpiry`
  - `TestApproveAsOtherUser`
  - `TestHeadscaleFailureMarksFailed`
- [ ] Implement, test, commit.

### Task 7: Web server, layout, themes, auth pages
**Files:**
- `internal/web/{server,middleware,render,ws}.go`
- `handlers_auth.go`, `handlers_setup.go`
- `templates/layout.html`, `templates/auth/*.html`
- `static/css/tokens.css`, `static/css/app.css`, `static/js/app.js`, `static/htmx.min.js`, `static/icons.svg`
- tests

**Produces:**
- `web.New(deps Deps) http.Handler`, with `Deps{Cfg, DB, HS, Bus, Poller, Reg, Notify, TG, Sessions, Limiter, HSConfig}`.
- Routes under BasePath: `/login`, `/login/2fa`, `/logout`, `/setup` (only while there are no accounts), `/invite/{token}`, `/2fa/enroll`, `/ws`, `/static/*`.
- Middleware chain: real IP (honours `X-Forwarded-For` only from TrustedProxies) → session → CSRF → `require(cap)`.
- Security headers: CSP `default-src 'self'`, `X-Frame-Options DENY`, `Referrer-Policy same-origin`.
- `render(w, r, name, data)` injects `.Me`, `.Caps`, `.Theme`, `.CSRF`, `.Base` and `.Brand`.
- Themes: `<html data-theme>` set to paper, midnight or console. `system` uses a media query.
- The tokens are taken from the approved mockups:
  - paper: background `#f7f7f5`, surface `#fff`, border `#e8e7e3`, text `#1c1c1a`, accent `#1c1c1a`
  - midnight: background `#0b0d12`, accent `#7c5cff`
  - console: background `#0a0f0d`, accent `#3ddc84`, monospace font
- WebSocket `/ws`:
  - checks Origin
  - sends JSON `{kind, html?, target?}` events, filtered by the viewer's Scope
  - the client in `app.js` triggers an htmx refresh of elements with a `data-live="<kind>"` attribute
  - when the WebSocket fails, the client falls back to polling every 15 seconds

- [ ] Tests:
  - `TestSetupOnlyWhenEmpty`
  - `TestLoginRequires2FA`
  - `TestCSRFRejected`
  - `TestTrustedProxyIP`
  - `TestLockoutAfterFailures`
- [ ] Implement, test, commit.

### Task 8: Telegram bot
**Files:** `internal/telegram/{api,bot,cards}.go`, plus tests using a fake Bot API (`httptest`)
**Produces:**
- `API{Token, BaseURL}` with `GetUpdates(ctx, offset, timeout)`, `SendMessage(ctx, chatID, text, kb *InlineKeyboard) (msgID int, err)`, `EditMessage(ctx, chatID, msgID, text, kb)` and `AnswerCallback(ctx, id, text)`.
- Messages use HTML parse mode, and every interpolated value is escaped.
- `Bot.Run(ctx)` long-polls with a 30-second timeout.
- `/start <token>` links the chat to an account through a `telegram_link_tokens` token (10 minutes, single use).
- Callback data is `a:<random 16-byte base64url id>`, looked up in `telegram_actions{id, kind, target_id, account_id, expires_at, used_at}`.
- On every tap the bot re-checks that the chat is linked to an account that **currently** has the permission. On a pass it calls `Reg.Decide`, edits every recorded message (from `telegram_messages`) to the decided text, and removes the buttons.
- `Bot.NotifyPending(p)` sends a card to every linked approver, and to the group chat if one is set.
- `Bot.Send(accountID, text)` is used for notifications.
- A token bucket limits sends to 25 messages per second overall and 1 per second per chat.

- [ ] Tests:
  - `TestLinkTokenSingleUse`
  - `TestTelegramActionRechecksPermission`
  - `TestDecisionEditsAllCards`
  - `TestCardEscapesHTML`
- [ ] Implement, test, commit.

### Task 9: Notification engine
**Files:** `internal/notify/{engine,security}.go`, `engine_test.go`
**Produces:**
- `WatchRule{ID, AccountID, SubjectType (node|user|tag|all), Subject, Events []events.Kind, OfflineDebounce time.Duration, NotSeenHours int, ExpiryDays int}`.
- Account quiet hours: `quiet_start` and `quiet_end` as `HH:MM`, plus a timezone.
- `Engine.Handle(ev events.Event) []Delivery`, a pure function with an injected clock.
- `Engine.Run(ctx)`, which subscribes to the bus and sends through `Sender`.
- Offline alerts are delayed by the debounce and cancelled if the device comes back online in time.
- More than 3 offline/online transitions in 10 minutes produce one "flapping" message, then silence for 30 minutes.
- Quiet hours suppress everything except `Security`.
- Every delivery also writes a `notifications` row, which feeds the dashboard.

- [ ] Tests:
  - `TestDebounceSuppressesFlap`
  - `TestQuietHoursSecurityBypass`
  - `TestRuleMatchesUserSubject`
  - `TestFlappingCollapse`
- [ ] Implement, test, commit.

### Task 10: headscale config and policy editing
**Files:** `internal/hsconfig/{editor,apply,dns}.go` plus tests
**Produces:**
- `Editor{Path}` with `Load() (*yaml.Node, error)`, `Get(path string) any` and `Patch(changes []Change) error`.
  - `Change{Path string; Value any}`, where the path uses dots, for example `dns.nameservers.global`.
  - Edits go through the node API, which keeps comments.
  - The file is written atomically (temp file plus rename), with a backup at `<path>.meshpanel-<unix>.bak`. The 10 most recent backups are kept.
- `DNSConfig` view: `{BaseDomain, MagicDNS, OverrideLocal, Global []string, Split map[string][]string, Search []string, Extra []Record}`, with `ReadDNS` and `WriteDNS`.
- `Applier{Restart, Reload []string; Health func(ctx) error; Timeout 30s}` with `ApplyConfig(ctx, ed, changes)`.
  - Order: patch → `headscale configtest` (if the binary is found) → restart → wait for health → on failure restore the backup, restart again, and return the error.
- `ApplyPolicyFile(ctx, path, content)` writes the file, reloads, and rolls back on failure.

- [ ] Tests:
  - `TestPatchKeepsComments`
  - `TestApplyRollsBackOnFailure`, with fake commands and a health check that fails
  - `TestDNSRoundTrip`
- [ ] Implement, test, commit.

### Task 11: Dashboard pages
**Files:**
- `internal/web/handlers_{overview,machines,users,keys,access,dns,alerts,audit,settings,account,register}.go`
- `templates/pages/*.html`, `templates/partials/*.html`
- `internal/audit/audit.go`
- `static/js/editor.js`

Pages and behaviour:
- **Overview:**
  - online, offline and pending counts
  - pending approval cards
  - recent activity (from the bus and notifications)
  - nodes with keys expiring soon
  - a headscale health banner
- **Machines:**
  - list with filter and search; detail page
  - actions: rename, delete, expire, expiry on/off, tags, routes (with risk badges for `0.0.0.0/0`, `::/0`, and prefixes shorter than /16), re-register guidance
  - every action calls `audit.Record(ctx, actor, channel, action, target, before, after)`
- **Users:** headscale users plus panel accounts. Create (optionally as an invite), role, extra caps, link to a headscale user, reset 2FA, revoke sessions. The last-owner guard is enforced in the DB layer.
- **Keys:** pre-auth keys (list, create, expire). Creating one shows a QR code (go-qrcode PNG as a data URI) and the command `tailscale up --login-server=<PublicURL> --authkey=<key>`.
- **Access:**
  - a raw HuJSON editor (`editor.js`: textarea with a highlighted overlay, line numbers, Tab key)
  - visual lists for groups, tagOwners, hosts, ACL rules and SSH rules, parsed with `github.com/tailscale/hujson`, standardized and then edited as JSON
  - check → diff → apply, through the API in database mode or `ApplyPolicyFile` in file mode
  - read-only with an explanation when neither is available
- **DNS:** a form backed by `hsconfig.DNSConfig` and `ApplyConfig`.
- **Alerts:** your own watch rules (create and delete), quiet hours, the Telegram link button, and the notification feed.
- **Audit:** a filterable table and CSV export, gated by ReadAudit.
- **Settings:**
  - brand accent and logo (stored in `settings`)
  - the Telegram group chat
  - headscale status: version, socket, policy mode
  - an "Add device by auth ID" form
- **Account:** theme, password, 2FA reset with new backup codes, sessions with revoke.
- **Register pages** (`/register/{id}` and `/auth/{id}`, at the root, outside BasePath):
  - sign in → 2FA → waiting (WebSocket plus countdown) → done, matching `docs/superpowers/specs/mockups/phone-flow.html`
  - `/auth/{id}` requires ApproveSSH
- **Command palette:** Ctrl/Cmd-K in `app.js`, searching nodes, users and pages through `GET /admin/search?q=`, scoped.

- [ ] Tests:
  - `TestMemberCannotOpenOthersNode`, which expects a 404
  - `TestRegisterPageInvalidID`
  - `TestRegisterSelfApprove`
  - `TestLastOwnerGuard`
  - `TestAuditOnRename`
- [ ] Implement, test, commit.

### Task 12: CLI subcommands, wiring and agent stub
**Files:** `cmd/meshpanel/{main,serve,setup,doctor,backup}.go`
- `serve`:
  - load config, open the DB, create the hs client
  - check the version: on unsupported, exit 1 with "headscale X is not supported; meshpanel needs 0.30.x"
  - start the poller, notifier, bot and HTTP server, with a graceful shutdown on SIGTERM
- `setup --username` creates the first owner interactively and prints the TOTP URI.
- `user reset-2fa <name>`.
- `backup <dest>` uses `VACUUM INTO`.
- `doctor` checks:
  - the socket exists and is accessible
  - the headscale version
  - whether the config and policy files are writable
  - the Telegram token, via `getMe`
  - that `public_url` returns this panel for `/register/hskey-authreq-000000000000000000000000`, using a header probe `X-Meshpanel: 1`
- `version`, with the version set through ldflags.
- The agent (tsnet) and web SSH are **not built** in this pass. The config key `agent.enabled` logs "agent not included in this build". This is documented as a roadmap item.

- [ ] `go build ./... && go vet ./...`, then commit.

### Task 13: Open-source packaging
**Files:**
- `README.md`: features, screenshots placeholder, quick start, proxy snippets, permissions
- `LICENSE` (MIT), `CONTRIBUTING.md`, `SECURITY.md`
- `Makefile`: build, test, lint, release-snapshot
- `.goreleaser.yaml`: linux amd64/arm64, `CGO_ENABLED=0`, `-trimpath -ldflags "-s -w -X main.version"`
- `.github/workflows/ci.yml`: vet, test, build, size check under 40 MB
- `deploy/meshpanel.service`, `deploy/sudoers`, `deploy/Caddyfile`, `deploy/nginx.conf`

- [ ] Build the release binary, check its size, smoke-run `meshpanel version` and `meshpanel serve` with a nonexistent socket (it must exit with a clear error), then commit.
