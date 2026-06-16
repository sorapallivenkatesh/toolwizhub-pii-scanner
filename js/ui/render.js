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
  const isIgnored = opts.isIgnored || (() => false);
  const visible = result.findings.filter((f) => !isIgnored(f));
  const ignoredCount = result.findings.length - visible.length;

  frag.append(summaryBar(result, visible, ignoredCount, opts));

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
  else frag.append(el("div", "clean", ignoredCount ? "All findings ignored. Reset to review them again." : "✓ No PII detected."));

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
    const ig = el("button", "tally tally--ignored", `${ignoredCount} ignored · reset`);
    ig.type = "button";
    if (opts.onResetIgnores) ig.addEventListener("click", opts.onResetIgnores);
    counts.append(ig);
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
  const body = el("div", "card__body");
  for (const f of findings) body.append(findingRow(f, opts));
  card.append(body);
  return card;
}

function findingRow(f, opts) {
  const row = el("div", "finding" + (f.masked ? " finding--ok" : ""));

  const left = el("div", "finding__main");
  left.append(el("code", "finding__field", f.field));
  const meta = el("div", "finding__meta");
  meta.append(el("span", "finding__type", f.label));
  for (const r of f.regulations) meta.append(el("span", "reg", r));
  if (f.via === "field-name") meta.append(el("span", "reg reg--hint", "field-name"));
  left.append(meta);
  if (opts.shared) {
    if (f.example) {
      const fix = el("div", "finding__fix");
      fix.append(el("span", "finding__masked-k", f.masked ? "value" : "masked as"), el("code", "finding__masked", f.example));
      left.append(fix);
    }
  } else if (!f.masked && f.suggested_masking) {
    const fix = el("div", "finding__fix");
    fix.append(el("span", "finding__sample", f.sample), el("span", "finding__arrow", "→"), el("code", "finding__masked", f.suggested_masking));
    left.append(fix);
  }

  const right = el("div", "finding__right");
  right.append(f.masked
    ? el("span", "pill pill--ok pill--sm", "masked")
    : el("span", `pill pill--${sevClass(f.severity)} pill--sm`, f.severity));
  if (!opts.shared && (opts.onDismiss || opts.onAllowType)) {
    const acts = el("div", "finding__acts");
    if (opts.onAllowType) {
      const a = el("button", "mini", "allow type"); a.type = "button"; a.title = `Whitelist all "${f.label}" findings`;
      a.addEventListener("click", () => opts.onAllowType(f)); acts.append(a);
    }
    if (opts.onDismiss) {
      const d = el("button", "mini mini--x", "✕"); d.type = "button"; d.title = "Ignore this finding";
      d.addEventListener("click", () => opts.onDismiss(f)); acts.append(d);
    }
    right.append(acts);
  }
  row.append(left, right);
  return row;
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
