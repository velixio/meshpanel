#!/bin/sh
# Creates the meshpanel system user and gives it access to headscale's socket.
set -e
if ! getent passwd meshpanel >/dev/null; then
    useradd --system --home-dir /var/lib/meshpanel --shell /usr/sbin/nologin meshpanel
fi
if getent group headscale >/dev/null; then
    usermod -a -G headscale meshpanel
fi
install -d -o meshpanel -g meshpanel -m 0750 /var/lib/meshpanel
chown root:meshpanel /etc/meshpanel/config.yaml 2>/dev/null || true
if command -v systemctl >/dev/null; then
    systemctl daemon-reload || true
fi
echo "meshpanel installed. Edit /etc/meshpanel/config.yaml (set server.session_secret), then: systemctl enable --now meshpanel"
