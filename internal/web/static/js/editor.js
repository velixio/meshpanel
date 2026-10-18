// A small HuJSON editor: a transparent textarea over a highlighted <pre>,
// with line numbers and Tab indentation. No build step, no dependencies.
(function () {
  "use strict";
  function esc(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }
  // Tokenizer for JSON with comments and trailing commas.
  function highlight(src) {
    const re = /(\/\/[^\n]*|\/\*[\s\S]*?\*\/)|("(?:\\.|[^"\\])*")(\s*:)?|(-?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b|\btrue\b|\bfalse\b|\bnull\b)|([{}\[\],])/g;
    let out = "", last = 0, m;
    while ((m = re.exec(src))) {
      out += esc(src.slice(last, m.index));
      if (m[1]) out += '<span class="tk-c">' + esc(m[1]) + "</span>";
      else if (m[2]) out += '<span class="' + (m[3] ? "tk-k" : "tk-s") + '">' + esc(m[2]) + "</span>" + (m[3] ? esc(m[3]) : "");
      else if (m[4]) out += '<span class="tk-n">' + esc(m[4]) + "</span>";
      else if (m[5]) out += '<span class="tk-p">' + esc(m[5]) + "</span>";
      last = re.lastIndex;
    }
    return out + esc(src.slice(last)) + "\n";
  }
  function mount(root) {
    const ta = root.querySelector("textarea");
    const pre = root.querySelector("pre");
    const gutter = root.querySelector(".gutter");
    const area = root.querySelector(".area");
    function sync() {
      pre.innerHTML = highlight(ta.value);
      const n = ta.value.split("\n").length;
      let g = "";
      for (let i = 1; i <= n; i++) g += i + "\n";
      gutter.textContent = g;
      ta.style.height = pre.scrollHeight + "px";
      ta.style.width = Math.max(pre.scrollWidth, area.clientWidth) + "px";
    }
    ta.addEventListener("input", sync);
    ta.addEventListener("keydown", (e) => {
      if (e.key === "Tab" && !e.shiftKey) {
        e.preventDefault();
        const s = ta.selectionStart, en = ta.selectionEnd;
        ta.value = ta.value.slice(0, s) + "  " + ta.value.slice(en);
        ta.selectionStart = ta.selectionEnd = s + 2;
        sync();
      } else if (e.key === "Enter") {
        // Keep the current line's indentation.
        const s = ta.selectionStart;
        const lineStart = ta.value.lastIndexOf("\n", s - 1) + 1;
        const indent = (ta.value.slice(lineStart, s).match(/^\s*/) || [""])[0];
        const extra = /[{\[]\s*$/.test(ta.value.slice(lineStart, s)) ? "  " : "";
        e.preventDefault();
        ta.value = ta.value.slice(0, s) + "\n" + indent + extra + ta.value.slice(ta.selectionEnd);
        ta.selectionStart = ta.selectionEnd = s + 1 + indent.length + extra.length;
        sync();
      } else if ((e.metaKey || e.ctrlKey) && e.key === "s") {
        e.preventDefault();
        const btn = ta.form && ta.form.querySelector("[data-default]");
        if (btn) btn.click();
      }
    });
    area.addEventListener("scroll", () => { gutter.scrollTop = area.scrollTop; });
    sync();
  }
  function init(root) {
    (root || document).querySelectorAll(".editor:not([data-ready])").forEach((el) => {
      el.dataset.ready = "1";
      mount(el);
    });
  }
  document.addEventListener("DOMContentLoaded", () => init());
  document.addEventListener("htmx:afterSwap", (e) => init(e.target));
})();
