# Third-party notices

meshpanel embeds these assets in its binary:

| Asset | License | Source |
|---|---|---|
| htmx 2.0.4 (`internal/web/static/js/htmx.min.js`) | BSD Zero Clause (0BSD) | https://github.com/bigskysoftware/htmx |
| Inter variable font (`internal/web/static/fonts/inter-*.woff2`) | SIL Open Font License 1.1 | https://github.com/rsms/inter |
| xterm.js 5.5.0 and @xterm/addon-fit 0.10.0 (`internal/web/static/vendor/`) | MIT | https://github.com/xtermjs/xterm.js |
| JetBrains Mono variable font (`internal/web/static/fonts/jetbrains-mono-*.woff2`) | SIL Open Font License 1.1 | https://github.com/JetBrains/JetBrainsMono |

Go module dependencies (including tailscale.com, BSD-3-Clause, used for the optional agent and browser SSH) and their licenses are listed in `go.mod`; run
`go list -m all` to see them.
