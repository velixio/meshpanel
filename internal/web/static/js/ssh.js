// Browser SSH terminal: xterm.js over meshpanel's WebSocket relay.
// Binary frames carry terminal bytes; text frames carry JSON control
// messages ({t:"status"|"prompt"} from the server, {t:"resize"|"answer"} to it).
(function () {
  "use strict";
  const host = document.getElementById("terminal");
  if (!host || !window.Terminal) return;
  const stateEl = document.getElementById("ssh-state");
  const userEl = document.getElementById("ssh-user");
  const connectBtn = document.getElementById("ssh-connect");
  const discBtn = document.getElementById("ssh-disconnect");
  const enc = new TextEncoder();

  const term = new Terminal({
    cursorBlink: true, fontFamily: '"JetBrains Mono", ui-monospace, monospace', fontSize: 13.5,
    theme: { background: "#0b0d12", foreground: "#e6e8ee", cursor: "#7c5cff", selectionBackground: "#7c5cff55" },
    scrollback: 5000,
  });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open(host);
  fit.fit();
  term.writeln("\x1b[2mPress Connect to open a session.\x1b[0m");

  let ws = null;
  let prompt = null; // {echo, buf} while answering a password/OTP question

  function setState(text, kind) {
    stateEl.textContent = text;
    stateEl.className = "badge " + (kind || "");
  }

  function send(obj) { if (ws && ws.readyState === 1) ws.send(JSON.stringify(obj)); }

  function connect() {
    if (ws) return;
    if (!userEl.checkValidity()) { userEl.reportValidity(); return; }
    fit.fit();
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const url = proto + "//" + location.host + host.dataset.ws + "?user=" + encodeURIComponent(userEl.value) + "&c=" + term.cols + "&r=" + term.rows;
    term.reset();
    ws = new WebSocket(url);
    ws.binaryType = "arraybuffer";
    setState("connecting…", "warn");
    connectBtn.hidden = true; discBtn.hidden = false; userEl.disabled = true;
    ws.onmessage = (ev) => {
      if (typeof ev.data !== "string") { term.write(new Uint8Array(ev.data)); return; }
      let m; try { m = JSON.parse(ev.data); } catch (_) { return; }
      if (m.t === "status") {
        if (m.s === "connected") { setState("connected", "ok"); term.focus(); }
        else if (m.s === "closed") {
          setState("closed", "");
          term.writeln("\r\n\x1b[2m[" + (m.m ? "\x1b[31m" + m.m + "\x1b[0m\x1b[2m" : "session closed") + "]\x1b[0m");
        } else { setState(m.s, "warn"); if (m.m) term.writeln("\x1b[2m" + m.m + "\x1b[0m"); }
      } else if (m.t === "prompt") {
        prompt = { echo: !!m.echo, buf: "" };
        term.write("\r\n" + m.q);
        term.focus();
      }
    };
    ws.onclose = () => {
      ws = null; prompt = null;
      if (stateEl.textContent !== "closed") setState("disconnected", "");
      connectBtn.hidden = false; discBtn.hidden = true; userEl.disabled = false;
    };
  }

  term.onData((d) => {
    if (!ws || ws.readyState !== 1) return;
    if (prompt) {
      // Answer locally, then send the whole line.
      for (const ch of d) {
        if (ch === "\r") {
          send({ t: "answer", v: prompt.buf });
          prompt = null;
          term.write("\r\n");
          return;
        } else if (ch === "\x7f") {
          if (prompt.buf.length) { prompt.buf = prompt.buf.slice(0, -1); if (prompt.echo) term.write("\b \b"); }
        } else if (ch >= " ") {
          prompt.buf += ch;
          if (prompt.echo) term.write(ch);
        }
      }
      return;
    }
    ws.send(enc.encode(d));
  });

  term.onResize(({ cols, rows }) => send({ t: "resize", c: cols, r: rows }));
  let rt;
  window.addEventListener("resize", () => { clearTimeout(rt); rt = setTimeout(() => fit.fit(), 120); });

  document.getElementById("ssh-form").addEventListener("submit", (e) => { e.preventDefault(); connect(); });
  discBtn.addEventListener("click", () => { if (ws) ws.close(); });
  window.addEventListener("beforeunload", () => { if (ws) ws.close(); });
})();
