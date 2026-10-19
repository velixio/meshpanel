# Installing meshpanel

This guide assumes headscale 0.30+ runs on the same machine as a systemd
service, with its config at `/etc/headscale/config.yaml`.

## 1. Binary and user

Packages (`.deb` / `.rpm`) from the releases page do all of this. By hand:

```sh
sudo install -m 0755 meshpanel /usr/bin/meshpanel
sudo useradd --system --home-dir /var/lib/meshpanel --shell /usr/sbin/nologin meshpanel
sudo usermod -a -G headscale meshpanel          # socket access
sudo install -d -o meshpanel -g meshpanel -m 0750 /var/lib/meshpanel
sudo install -d -m 0755 /etc/meshpanel
sudo install -m 0640 -g meshpanel deploy/config.example.yaml /etc/meshpanel/config.yaml
sudo install -m 0644 deploy/meshpanel.service /etc/systemd/system/meshpanel.service
```

headscale's socket must be group-accessible. In headscale's config:

```yaml
unix_socket: /var/run/headscale/headscale.sock
unix_socket_permission: "0770"
```

## 2. Configure

In `/etc/meshpanel/config.yaml`:

- `server.session_secret`: output of `openssl rand -hex 32`.
- `server.public_url`: headscale's `server_url`, for example `https://headscale.example.com`.
- `server.trusted_proxies`: your reverse proxy's address. The default is localhost.
- `headscale.http_url`: headscale's `listen_addr`. meshpanel reads `/version` there.

## 3. Optional: DNS and policy editing

```sh
sudo chgrp meshpanel /etc/headscale/config.yaml && sudo chmod g+w /etc/headscale/config.yaml
```

Then let meshpanel restart headscale. Choose one of these:

**sudo** (the default commands in the example config):

```sh
sudo install -m 0440 deploy/sudoers /etc/sudoers.d/meshpanel && sudo visudo -c
```

**polkit** (lets you set `NoNewPrivileges=yes` in the unit). Create
`/etc/polkit-1/rules.d/50-meshpanel.rules`:

```js
polkit.addRule(function(action, subject) {
  if (action.id == "org.freedesktop.systemd1.manage-units" &&
      action.lookup("unit") == "headscale.service" &&
      subject.user == "meshpanel" &&
      (action.lookup("verb") == "restart" || action.lookup("verb") == "reload")) {
    return polkit.Result.YES;
  }
});
```

Then set `restart_command: "systemctl restart headscale"` and
`reload_command: "systemctl reload headscale"`.

Before every change meshpanel saves a backup next to the file
(`config.yaml.meshpanel-<time>.bak`, last 10 kept). It runs
`headscale configtest` when the binary is available, and restores the backup
if headscale doesn't come back healthy within 45 seconds.

## 3b. Optional: device info and browser SSH

Set `agent.enabled: true` and/or `web_ssh.enabled: true`.

- Both connect to headscale at `headscale.http_url`, its local listener. No proxy change is needed.
- State is kept in `/var/lib/meshpanel/tailnet/`.
- The agent registers once as headscale user `meshpanel` and keeps that identity across restarts.
- With a restrictive policy, allow the agent to see devices:

```json
{"action": "accept", "src": ["meshpanel@"], "dst": ["*:*"], "proto": "icmp"}
```

- **Browser SSH sessions** run as the signed-in person's headscale user. Each one creates a single-use ephemeral key and deletes its node when it closes.
- **Tailscale SSH:** for it to accept them, the policy needs an `ssh` rule for that person (for example `"src": ["ravi@"], "dst": ["tag:server"], "users": ["root"]`).
- **Regular sshd:** if the machine runs a normal SSH server on port 22 instead, the terminal prompts for the password.

## 4. Proxy and start

Route `/register/*`, `/auth/*` and `/admin/*` to `127.0.0.1:8030`; see
`deploy/Caddyfile` and `deploy/nginx.conf`. Then:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now meshpanel
sudo -u meshpanel meshpanel doctor -c /etc/meshpanel/config.yaml
```

Open `https://headscale.example.com/admin/setup` to create the owner account,
or run `sudo -u meshpanel meshpanel setup -u yourname`.

## Trying it on a LAN without HTTPS

Set `server.cookie_secure: false` and `server.listen: "0.0.0.0:8030"`, then
open `http://<server-ip>:8030/admin/`. Phones still need headscale's URL to
route `/register/*` to meshpanel, so for a real phone test put a proxy in
front.

## Backups

```sh
sudo -u meshpanel meshpanel backup /var/lib/meshpanel/backup-$(date +%F).db
```
