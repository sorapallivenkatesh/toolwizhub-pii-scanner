/* ui/render.js — build the scan report DOM. Untrusted pasted values go in via
   textContent; only static labels/snippets are trusted. */

import { TYPE_META } from "../core/rules.js";

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
}

export function renderReport(result) {
  const frag = document.createDocumentFragment();
  frag.append(summaryBar(result));

  if (!result.findings.length) {
    frag.append(el("div", "clean", "✓ No PII detected. Looks clean!"));
    return frag;
  }

  if (result.suggested_masking) {
    const s = el("div", "suggest");
    s.append(el("span", "suggest__k", "Suggested masking"));
    s.append(el("code", "suggest__v", result.suggested_masking));
    frag.append(s);
  }

  frag.append(findingsCard(result.findings));

  const types = [...new Set(result.findings.filter((f) => !f.masked).map((f) => f.type))];
  if (types.length) frag.append(snippetsCard(types));

  return frag;
}

function summaryBar(result) {
  const bar = el("div", "summary");
  const status = result.summary.status;
  const pill = el("span", `pill pill--${status}`,
    status === "fail" ? "Exposure found" : status === "warn" ? "Review needed" : "Clean");
  bar.append(pill);

  const counts = el("div", "summary__counts");
  const b = result.summary.by;
  for (const sev of ["critical", "high", "medium", "low"]) {
    if (b[sev]) counts.append(el("span", `tally tally--${sev}`, `${b[sev]} ${sev}`));
  }
  if (result.summary.masked) counts.append(el("span", "tally tally--masked", `${result.summary.masked} masked`));
  bar.append(counts);

  bar.append(el("span", "summary__fmt", `${result.format} · ${result.summary.unmasked} unmasked`));
  return bar;
}

function findingsCard(findings) {
  const card = el("section", "card");
  card.append(cardHead("Findings"));
  const body = el("div", "card__body");
  for (const f of findings) body.append(findingRow(f));
  card.append(body);
  return card;
}

function findingRow(f) {
  const row = el("div", "finding" + (f.masked ? " finding--ok" : ""));

  const left = el("div", "finding__main");
  const field = el("code", "finding__field", f.field);
  left.append(field);
  const meta = el("div", "finding__meta");
  meta.append(el("span", "finding__type", f.label));
  for (const r of f.regulations) meta.append(el("span", "reg", r));
  if (f.via === "field-name") meta.append(el("span", "reg reg--hint", "field-name"));
  left.append(meta);
  if (!f.masked && f.suggested_masking) {
    const fix = el("div", "finding__fix");
    fix.append(el("span", "finding__sample", f.sample), el("span", "finding__arrow", "→"), el("code", "finding__masked", f.suggested_masking));
    left.append(fix);
  }

  const right = el("div", "finding__right");
  right.append(f.masked
    ? el("span", "pill pill--ok pill--sm", "masked")
    : el("span", `pill pill--${sevClass(f.severity)} pill--sm`, f.severity));
  row.append(left, right);
  return row;
}

function snippetsCard(types) {
  const card = el("section", "card");
  card.append(cardHead("Masking snippets (TypeScript)"));
  const body = el("div", "card__body");
  for (const t of types) {
    const meta = TYPE_META[t];
    if (!meta?.snippet) continue;
    const block = el("div", "snippet");
    block.append(el("div", "snippet__title", meta.label));
    const pre = el("pre", "snippet__code");
    pre.append(el("code", null, meta.snippet));
    block.append(pre);
    body.append(block);
  }
  card.append(body);
  return card;
}

function cardHead(title) {
  const h = el("div", "card__head");
  h.append(el("span", "card__title", title));
  return h;
}

const sevClass = (s) => (s === "critical" || s === "high" ? "fail" : s === "medium" ? "warn" : "low");

export function renderError(message) {
  return el("div", "clean clean--error", `⚠ ${message}`);
}
