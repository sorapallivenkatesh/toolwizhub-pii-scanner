/* ui/render.js — build the scan report DOM. Untrusted pasted values go in via
   textContent / text nodes; only static labels/snippets are trusted.
   Stateful actions (dismiss, allowlist, export) are passed in as `opts`. */

import { TYPE_META } from "../core/rules.js";

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

/* small copy-to-clipboard button; flips its label briefly on success */
function copyBtn(getText, label = "Copy") {
  const b = el("button", "copy", label);
  b.type = "button";
  b.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(getText()); } catch { return; }
    b.textContent = "Copied ✓"; b.classList.add("is-done");
    setTimeout(() => { b.textContent = label; b.classList.remove("is-done"); }, 1400);
  });
  return b;
}

const sevClass = (s) => (s === "critical" || s === "high" ? "fail" : s === "medium" ? "warn" : "low");

export function renderReport(result, opts = {}) {
  const frag = document.createDocumentFragment();
  // live view filters via opts.isIgnored; a shared report carries the flag per finding
  const ignoredOf = opts.shared ? (f) => !!f.ignored : (opts.isIgnored || (() => false));
  const visible = result.findings.filter((f) => !ignoredOf(f));
  const ignored = result.findings.filter(ignoredOf);

  frag.append(summaryBar(result, visible, ignored.length, opts));

  if (!result.findings.length) {
    frag.append(el("div", "clean", "✓ No PII detected. Looks clean!"));
    return frag;
  }

  if (opts.rawInput) frag.append(highlightCard(opts.rawInput, visible));

  if (result.suggested_masking) {
    const s = el("div", "suggest");
    s.append(el("span", "suggest__k", "Suggested masking"));
    s.append(el("code", "suggest__v", result.suggested_masking));
    frag.append(s);
  }

  if (opts.masked && opts.masked !== opts.rawInput) frag.append(maskedCard(opts.masked));

  if (visible.length) frag.append(findingsCard(visible, opts));
  else if (ignored.length) frag.append(el("div", "clean", "All findings ignored — restore any below."));

  if (ignored.length) frag.append(ignoredCard(ignored, opts));

  const types = [...new Set(visible.filter((f) => !f.masked).map((f) => f.type))];
  if (types.length) frag.append(snippetsCard(types));

  return frag;
}

/* recompute counts from the findings actually shown, so ignoring one drops its tally */
function summarize(findings) {
  const unmasked = findings.filter((f) => !f.masked);
  const by = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of unmasked) by[f.severity] = (by[f.severity] || 0) + 1;
  const status = by.critical || by.high ? "fail" : by.medium || by.low ? "warn" : "ok";
  return { unmasked: unmasked.length, masked: findings.length - unmasked.length, by, status };
}

function summaryBar(result, visible, ignoredCount, opts) {
  const s = summarize(visible);
  const bar = el("div", "summary");
  bar.append(el("span", `pill pill--${s.status}`,
    s.status === "fail" ? "Exposure found" : s.status === "warn" ? "Review needed" : "Clean"));

  const counts = el("div", "summary__counts");
  for (const sev of ["critical", "high", "medium", "low"]) {
    if (s.by[sev]) counts.append(el("span", `tally tally--${sev}`, `${s.by[sev]} ${sev}`));
  }
  if (s.masked) counts.append(el("span", "tally tally--masked", `${s.masked} masked`));
  if (ignoredCount) {
    if (opts.onResetIgnores) {
      const ig = el("button", "tally tally--ignored", `${ignoredCount} ignored · reset`);
      ig.type = "button"; ig.addEventListener("click", opts.onResetIgnores);
      counts.append(ig);
    } else {
      counts.append(el("span", "tally tally--ignored", `${ignoredCount} ignored`));
    }
  }
  bar.append(counts);

  const tools = el("div", "summary__tools");
  if (opts.onExport) {
    const j = el("button", "ghost", "Export JSON"); j.type = "button"; j.addEventListener("click", () => opts.onExport("json"));
    const m = el("button", "ghost", "Export MD"); m.type = "button"; m.addEventListener("click", () => opts.onExport("md"));
    tools.append(j, m);
  }
  if (opts.buildShareLink) {
    const sh = el("button", "ghost ghost--share", "Share ↗"); sh.type = "button";
    sh.addEventListener("click", () => {
      const link = opts.buildShareLink();
      navigator.clipboard?.writeText(link).catch(() => {});
      shareBanner(bar, link);
      sh.textContent = "Link copied ✓"; sh.classList.add("is-done");
      setTimeout(() => { sh.textContent = "Share ↗"; sh.classList.remove("is-done"); }, 1600);
    });
    tools.append(sh);
  }
  tools.append(el("span", "summary__fmt", `${result.format} · ${s.unmasked} unmasked`));
  bar.append(tools);
  return bar;
}

/* reveal a copyable share link (inserted right after the summary bar) */
function shareBanner(afterEl, link) {
  document.querySelector(".share-banner")?.remove();
  const b = el("div", "share-banner");
  b.append(el("span", "share-banner__k", "🔗 Share with your team"));
  const inp = el("input", "share-banner__link");
  inp.value = link; inp.readOnly = true; inp.spellcheck = false;
  inp.addEventListener("focus", () => inp.select());
  b.append(inp, copyBtn(() => link, "Copy link"));
  b.append(el("span", "share-banner__note", "PII values are masked — safe to share."));
  afterEl.after(b);
  inp.focus();
}

/* the pasted input, escaped, with each detected value wrapped in a <mark> */
function highlightCard(raw, findings) {
  const card = el("section", "card");
  card.append(cardHead("Input with PII highlighted"));
  const body = el("div", "card__body");
  body.append(highlight(raw, findings));
  card.append(body);
  return card;
}

function highlight(raw, findings) {
  // map each (unique, non-truncated) matched value → its highest severity
  const needles = new Map();
  for (const f of findings) {
    const s = f.sample;
    if (!s || s.length < 3 || s.includes("…")) continue;
    const cur = needles.get(s);
    if (!cur || rank(f.severity) > rank(cur)) needles.set(s, f.severity);
  }
  const ranges = [];
  for (const [needle, severity] of needles) {
    let i = 0, p;
    while ((p = raw.indexOf(needle, i)) >= 0) { ranges.push([p, p + needle.length, severity]); i = p + needle.length; }
  }
  ranges.sort((a, b) => a[0] - b[0] || (b[1] - b[0]) - (a[1] - a[0]));

  const pre = el("pre", "highlight");
  let pos = 0;
  for (const [start, end, severity] of ranges) {
    if (start < pos) continue; // overlap — keep the first
    if (start > pos) pre.append(document.createTextNode(raw.slice(pos, start)));
    pre.append(el("mark", `hl hl--${sevClass(severity)}`, raw.slice(start, end)));
    pos = end;
  }
  if (pos < raw.length) pre.append(document.createTextNode(raw.slice(pos)));
  return pre;
}
const rank = (s) => ({ critical: 4, high: 3, medium: 2, low: 1 }[s] || 0);

function maskedCard(masked) {
  const card = el("section", "card");
  const head = cardHead("Masked copy");
  head.append(copyBtn(() => masked, "Copy masked"));
  card.append(head);
  const body = el("div", "card__body");
  const pre = el("pre", "masked-out");
  pre.append(el("code", null, masked));
  body.append(pre);
  card.append(body);
  return card;
}

function findingsCard(findings, opts) {
  const card = el("section", "card");
  card.append(cardHead("Findings"));
  const grid = el("div", "finding-grid");
  for (const f of findings) grid.append(findingCard(f, opts));
  card.append(grid);
  return card;
}

/* the masked value to show on a card (raw is struck through, never shown for shares) */
function exampleOf(f, opts) {
  if (opts.shared) return f.example ? { masked: f.example } : null;
  if (f.masked) return { masked: f.sample };
  if (f.suggested_masking) return { raw: f.sample, masked: f.suggested_masking };
  return null;
}

function findingCard(f, opts) {
  const sc = sevClass(f.severity);
  const c = el("div", `fcard fcard--${f.masked ? "ok" : sc}`);

  const top = el("div", "fcard__top");
  top.append(f.masked
    ? el("span", "pill pill--ok pill--sm", "masked")
    : el("span", `pill pill--${sc} pill--sm`, f.severity));
  if (!opts.shared && (opts.onAllowType || opts.onDismiss)) {
    const acts = el("div", "fcard__acts");
    if (opts.onAllowType) {
      const a = el("button", "mini", "allow"); a.type = "button"; a.title = `Whitelist all "${f.label}" findings`;
      a.addEventListener("click", () => opts.onAllowType(f)); acts.append(a);
    }
    if (opts.onDismiss) {
      const d = el("button", "mini mini--x", "✕"); d.type = "button"; d.title = "Ignore this finding";
      d.addEventListener("click", () => opts.onDismiss(f)); acts.append(d);
    }
    top.append(acts);
  }
  c.append(top);

  c.append(el("div", "fcard__type", f.label));
  c.append(el("code", "fcard__field", f.field));

  const ex = exampleOf(f, opts);
  if (ex) {
    const e = el("div", "fcard__ex");
    if (ex.raw) e.append(el("span", "fcard__raw", ex.raw), el("span", "fcard__arrow", "→"));
    e.append(el("code", "fcard__masked", ex.masked));
    c.append(e);
  }

  if (f.regulations?.length || f.via === "field-name") {
    const regs = el("div", "fcard__regs");
    for (const r of f.regulations || []) regs.append(el("span", "reg", r));
    if (f.via === "field-name") regs.append(el("span", "reg reg--hint", "field-name"));
    c.append(regs);
  }
  return c;
}

/* ignored findings, kept visible below as muted cards with a per-item restore */
function ignoredCard(findings, opts) {
  const card = el("section", "card card--ignored");
  card.append(cardHead(`Ignored (${findings.length})`));
  const grid = el("div", "finding-grid");
  for (const f of findings) grid.append(ignoredCardItem(f, opts));
  card.append(grid);
  return card;
}

function ignoredCardItem(f, opts) {
  const c = el("div", "fcard fcard--ignored");
  const top = el("div", "fcard__top");
  top.append(el("span", `pill pill--${sevClass(f.severity)} pill--sm`, f.severity));
  if (!opts.shared && opts.onRestore) {
    const b = el("button", "mini mini--restore", "↺ restore"); b.type = "button"; b.title = "Restore this finding";
    b.addEventListener("click", () => opts.onRestore(f));
    top.append(b);
  } else {
    top.append(el("span", "reg", "ignored"));
  }
  c.append(top);
  c.append(el("div", "fcard__type", f.label));
  c.append(el("code", "fcard__field", f.field));
  return c;
}

function snippetsCard(types) {
  const card = el("section", "card");
  card.append(cardHead("Masking snippets (TypeScript)"));
  const body = el("div", "card__body");
  let any = false;
  for (const t of types) {
    const meta = TYPE_META[t];
    if (!meta?.snippet) continue;
    any = true;
    const block = el("div", "snippet");
    const title = el("div", "snippet__title", meta.label);
    title.append(copyBtn(() => meta.snippet));
    block.append(title);
    const pre = el("pre", "snippet__code");
    pre.append(el("code", null, meta.snippet));
    block.append(pre);
    body.append(block);
  }
  if (!any) return document.createDocumentFragment();
  card.append(body);
  return card;
}

function cardHead(title) {
  const h = el("div", "card__head");
  h.append(el("span", "card__title", title));
  return h;
}

export function renderError(message) {
  return el("div", "clean clean--error", `⚠ ${message}`);
}
