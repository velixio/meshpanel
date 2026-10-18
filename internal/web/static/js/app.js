// meshpanel client: live updates over WebSocket (with polling fallback),
// command palette, confirmations, copy buttons, filters, countdowns.
(function () {
  "use strict";
  const doc = document.documentElement;
  const base = doc.dataset.base || "/admin";
  const csrf = doc.dataset.csrf || "";
  const icons = base + "/static/icons.svg?v=" + (doc.dataset.v || "");

  // Every htmx request carries the CSRF token.
  document.addEventListener("htmx:configRequest", (e) => {
    e.detail.headers["X-CSRF-Token"] = csrf;
  });

  // ---------- live updates ----------
  // Elements with data-live refresh themselves (via htmx hx-select) when an
  // event they care about arrives. data-live="*" refreshes on anything.
  let liveTimer = null;
  const pendingKinds = new Set();
  function fireLive(kind) {
    pendingKinds.add(kind);
    if (liveTimer) return;
    liveTimer = setTimeout(() => {
      const kinds = Array.from(pendingKinds);
      pendingKinds.clear();
      liveTimer = null;
      document.querySelectorAll("[data-live]").forEach((el) => {
        const want = el.dataset.live.split(/\s+/);
        if (want.includes("*") || kinds.some((k) => want.includes(k) || want.includes(k.split("_")[0]))) {
          if (!el.closest("form:focus-within") && window.htmx) htmx.trigger(el, "mp-live");
        }
      });
      document.dispatchEvent(new CustomEvent("mp:live", { detail: kinds }));
    }, 400);
  }

  let ws = null, wsOK = false, retry = 1000, fallback = null;
  function startFallback() {
    if (fallback) return;
    fallback = setInterval(() => fireLive("*"), 15000);
  }
  function stopFallback() {
    if (fallback) clearInterval(fallback);
    fallback = null;
  }
  function setLiveDot(ok) {
    document.querySelectorAll("[data-ws-dot]").forEach((d) => {
      d.title = ok ? "Live" : "Reconnecting… (refreshing every 15s)";
    });
  }
  function connect() {
    if (!doc.dataset.me) return;
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    try {
      ws = new WebSocket(proto + "//" + location.host + base + "/ws");
    } catch (_) {
      startFallback();
      return;
    }
    ws.onopen = () => { wsOK = true; retry = 1000; stopFallback(); setLiveDot(true); };
    ws.onmessage = (m) => {
      try {
        const ev = JSON.parse(m.data);
        if (ev.kind === "health") updateHealth(ev.ok);
        fireLive(ev.kind);
      } catch (_) {}
    };
    ws.onclose = () => {
      wsOK = false;
      setLiveDot(false);
      startFallback();
      setTimeout(connect, retry);
      retry = Math.min(retry * 2, 30000);
    };
  }
  function updateHealth(ok) {
    document.querySelectorAll("[data-health]").forEach((el) => {
      const dot = el.querySelector(".dot");
      if (dot) dot.className = "dot " + (ok ? "on" : "danger");
      const t = el.querySelector(".txt");
      if (t) t.textContent = ok ? "headscale online" : "headscale unreachable";
    });
  }

  // ---------- toasts ----------
  function toast(msg, kind) {
    let zone = document.querySelector(".flash-zone");
    if (!zone) {
      zone = document.createElement("div");
      zone.className = "flash-zone";
      document.body.appendChild(zone);
    }
    const t = document.createElement("div");
    t.className = "toast " + (kind || "ok");
    t.setAttribute("role", "status");
    t.innerHTML = '<svg class="icon"><use href="' + icons + '#' + (kind === "danger" ? "alert" : "check") + '"/></svg><div></div>';
    t.lastChild.textContent = msg;
    zone.appendChild(t);
    setTimeout(() => { t.classList.add("leaving"); setTimeout(() => t.remove(), 300); }, kind === "danger" ? 7000 : 3500);
  }
  window.mpToast = toast;
  function autoDismiss(root) {
    root.querySelectorAll(".toast[data-auto]").forEach((t) => {
      setTimeout(() => { t.classList.add("leaving"); setTimeout(() => t.remove(), 300); }, t.classList.contains("danger") ? 8000 : 4000);
    });
  }

  // ---------- confirm / copy / misc ----------
  // Boosted forms confirm through htmx's hx-confirm; this covers forms htmx
  // doesn't handle (hx-boost="false") and the no-htmx fallback.
  document.addEventListener("submit", (e) => {
    const f = e.target;
    const boosted = window.htmx && f.closest("[hx-boost=true]") && !f.closest("[hx-boost=false]");
    const msg = f.getAttribute("hx-confirm");
    if (msg && !boosted && !window.confirm(msg)) e.preventDefault();
  }, true);

  document.addEventListener("click", (e) => {
    const c = e.target.closest("[data-copy]");
    if (c) {
      e.preventDefault();
      const text = c.dataset.copy || (document.querySelector(c.dataset.copyFrom || "") || {}).textContent || "";
      navigator.clipboard.writeText(text.trim()).then(() => toast("Copied"), () => toast("Copy failed", "danger"));
      return;
    }
    const row = e.target.closest("tr[data-href]");
    if (row && !e.target.closest("a,button,input,select,label,form,summary")) {
      if (window.htmx) htmx.ajax("GET", row.dataset.href, { target: "body", swap: "outerHTML", push: true });
      else location.href = row.dataset.href;
      return;
    }
    if (e.target.closest("[data-nav-toggle]")) {
      document.body.classList.toggle("nav-open");
      return;
    }
    if (document.body.classList.contains("nav-open") && !e.target.closest(".side")) {
      document.body.classList.remove("nav-open");
    }
    // Close other open dropdown menus.
    document.querySelectorAll("details[open][data-menu]").forEach((d) => {
      if (!d.contains(e.target)) d.removeAttribute("open");
    });
  });

  // Client-side table filtering: <input data-filter="#table"> and
  // chips <button data-chip="online" data-filter-target="#table">.
  function applyFilter(table) {
    const input = document.querySelector('[data-filter="' + table + '"]');
    const q = input ? input.value.trim().toLowerCase() : "";
    const chip = document.querySelector('[data-chip-for="' + table + '"].on');
    const state = chip ? chip.dataset.chip : "all";
    let shown = 0;
    document.querySelectorAll(table + " tbody tr[data-search]").forEach((tr) => {
      const okText = !q || tr.dataset.search.includes(q);
      const okState = state === "all" || (tr.dataset.state || "").split(" ").includes(state);
      tr.classList.toggle("hidden", !(okText && okState));
      if (okText && okState) shown++;
    });
    const empty = document.querySelector(table + "-empty");
    if (empty) empty.classList.toggle("hidden", shown > 0);
  }
  document.addEventListener("input", (e) => {
    const t = e.target.dataset && e.target.dataset.filter;
    if (t) applyFilter(t);
  });
  document.addEventListener("click", (e) => {
    const chip = e.target.closest("[data-chip-for]");
    if (!chip) return;
    document.querySelectorAll('[data-chip-for="' + chip.dataset.chipFor + '"]').forEach((c) => c.classList.toggle("on", c === chip));
    applyFilter(chip.dataset.chipFor);
  });

  // Countdowns: <span data-countdown="unix-seconds">
  function tick() {
    const now = Date.now() / 1000;
    document.querySelectorAll("[data-countdown]").forEach((el) => {
      const left = Math.max(0, Math.round(+el.dataset.countdown - now));
      el.textContent = Math.floor(left / 60) + ":" + String(left % 60).padStart(2, "0");
      if (left === 0 && el.dataset.onZero === "reload") location.reload();
    });
    document.querySelectorAll("[data-ago]").forEach((el) => {
      el.textContent = ago(+el.dataset.ago, now);
    });
  }
  function ago(t, now) {
    const s = Math.max(0, now - t);
    if (s < 45) return "just now";
    if (s < 3600) return Math.round(s / 60) + "m ago";
    if (s < 86400) return Math.round(s / 3600) + "h ago";
    return Math.round(s / 86400) + "d ago";
  }
  setInterval(tick, 1000);

  // Sticky top bar border once scrolled.
  window.addEventListener("scroll", () => {
    const top = document.querySelector(".top");
    if (top) top.classList.toggle("scrolled", window.scrollY > 4);
  }, { passive: true });

  // ---------- command palette ----------
  let pal, palInput, palList, results = [], sel = 0, palTimer;
  function buildPalette() {
    pal = document.createElement("div");
    pal.className = "palette-wrap";
    pal.innerHTML = '<div class="palette" role="dialog" aria-label="Search"><input type="search" placeholder="Search machines, users, pages…" aria-label="Search"><div class="results"></div><div class="hint"><span><kbd>↑</kbd> <kbd>↓</kbd> move</span><span><kbd>Enter</kbd> open</span><span><kbd>Esc</kbd> close</span></div></div>';
    document.body.appendChild(pal);
    palInput = pal.querySelector("input");
    palList = pal.querySelector(".results");
    pal.addEventListener("click", (e) => {
      if (e.target === pal) closePalette();
      const r = e.target.closest(".res");
      if (r) go(+r.dataset.i);
    });
    palInput.addEventListener("input", () => {
      clearTimeout(palTimer);
      palTimer = setTimeout(search, 120);
    });
    palInput.addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown") { sel = Math.min(sel + 1, results.length - 1); render(); e.preventDefault(); }
      if (e.key === "ArrowUp") { sel = Math.max(sel - 1, 0); render(); e.preventDefault(); }
      if (e.key === "Enter") { go(sel); e.preventDefault(); }
      if (e.key === "Escape") closePalette();
    });
  }
  function openPalette() {
    if (!doc.dataset.me) return;
    if (!pal) buildPalette();
    pal.classList.add("open");
    palInput.value = "";
    search();
    setTimeout(() => palInput.focus(), 0);
  }
  function closePalette() { if (pal) pal.classList.remove("open"); }
  function search() {
    fetch(base + "/search?q=" + encodeURIComponent(palInput.value), { headers: { Accept: "application/json" } })
      .then((r) => r.json())
      .then((r) => { results = r || []; sel = 0; render(); })
      .catch(() => {});
  }
  function render() {
    palList.innerHTML = "";
    if (!results.length) {
      palList.innerHTML = '<div class="empty small">No matches</div>';
      return;
    }
    results.forEach((r, i) => {
      const d = document.createElement("div");
      d.className = "res" + (i === sel ? " sel" : "");
      d.dataset.i = i;
      d.innerHTML = '<svg class="icon"><use href="' + icons + "#" + (r.icon || "chev") + '"/></svg><span></span><span class="sub"></span>';
      d.children[1].textContent = r.label;
      d.children[2].textContent = r.sub || "";
      palList.appendChild(d);
    });
    const s = palList.querySelector(".sel");
    if (s) s.scrollIntoView({ block: "nearest" });
  }
  function go(i) {
    const r = results[i];
    if (!r) return;
    closePalette();
    location.href = r.url;
  }
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openPalette(); }
    else if (e.key === "/" && !e.target.closest("input,textarea,select,[contenteditable]")) { e.preventDefault(); openPalette(); }
  });
  document.addEventListener("click", (e) => { if (e.target.closest("[data-palette]")) openPalette(); });

  // Phone "waiting for approval" page: poll until decided, then reload.
  function pollStatus() {
    const el = document.querySelector("[data-poll-status]");
    if (!el) return;
    const check = () => {
      fetch(el.dataset.pollStatus, { headers: { Accept: "application/json" }, cache: "no-store" })
        .then((r) => r.json())
        .then((s) => {
          if (s.status && s.status !== "pending" && s.status !== "approving") location.reload();
          else setTimeout(check, 2500);
        })
        .catch(() => setTimeout(check, 5000));
    };
    setTimeout(check, 2500);
  }

  document.addEventListener("DOMContentLoaded", () => { connect(); tick(); autoDismiss(document); pollStatus(); });
  document.addEventListener("htmx:afterSwap", (e) => { tick(); autoDismiss(e.target); });
})();
