/* core/scan.js — PURE scan + mask engine. Parse JSON / NDJSON / log-text, walk
   to values with field paths, detect PII (with span-level dedup), and either
   report findings or produce a masked copy. Supports user custom rules.
   No DOM, no I/O. */

import { TYPE_META, VALUE_DETECTORS, KEY_HINTS, isMasked, SEVERITY_ORDER } from "./rules.js";

const MAX_FINDINGS = 1000;
// don't add a generic field-hint type when a more specific value match already exists
const SUPPRESS = { device_id: ["imei", "uuid"], location: ["precise_location"], possible_dob: ["date_of_birth"] };
const sev = (f) => SEVERITY_ORDER[f.severity] || 0;
const truncate = (s, n = 120) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

/* Build the active detector list + type metadata: built-ins plus any user
   custom rules ({label, pattern, severity}). Custom detectors run last, so the
   precise built-ins claim their spans first. */
function buildContext(customRules = []) {
  const detectors = [...VALUE_DETECTORS];
  const meta = { ...TYPE_META };
  (customRules || []).forEach((rule, i) => {
    if (!rule || !rule.pattern) return;
    let compiled;
    try { compiled = new RegExp(rule.pattern, "g"); } catch { return; } // skip invalid regex
    const type = "custom:" + (rule.label || `rule-${i + 1}`);
    meta[type] = { label: rule.label || "Custom rule", severity: rule.severity || "high", regs: ["custom"], mask: () => "[redacted]", custom: true };
    detectors.push({ type, regex: () => new RegExp(compiled.source, "g") });
  });
  return { detectors, meta };
}

function safeMask(meta, type, value) {
  try { return meta[type].mask(value); } catch { return "‹masked›"; }
}

/* find PII spans in a string; first (most specific) detector claims a range so
   overlapping weaker matches are dropped */
function detectSpans(valueStr, ctx) {
  const claimed = [];
  const overlaps = (s, e) => claimed.some(([cs, ce]) => s < ce && e > cs);
  const spans = [];
  for (const det of ctx.detectors) {
    const re = det.regex();
    let m;
    while ((m = re.exec(valueStr)) !== null) {
      const text = m[0];
      if (text === "") { re.lastIndex++; continue; }
      const start = m.index, end = start + text.length;
      if (det.validate && !det.validate(text)) continue;
      if (overlaps(start, end)) continue;
      claimed.push([start, end]);
      spans.push({ type: det.type, text, start, end });
    }
  }
  return spans.sort((a, b) => a.start - b.start);
}

function makeFinding(field, type, matched, via, ctx) {
  const meta = ctx.meta[type];
  const masked = isMasked(matched);
  return {
    field, type, label: meta.label, masked,
    severity: meta.severity, regulations: meta.regs,
    sample: truncate(String(matched)),
    suggested_masking: masked ? null : safeMask(ctx.meta, type, matched),
    via, // "pattern" | "field-name"
  };
}

/* first matching field-name hint for a key, skipping types we already have */
function keyHint(hintKey, have) {
  if (!hintKey) return null;
  for (const h of KEY_HINTS) {
    if (h.re.test(hintKey) && !have.has(h.type) && !(SUPPRESS[h.type] || []).some((t) => have.has(t))) return h.type;
  }
  return null;
}

// loose detectors that often misread another ID type's value (12-digit Aadhaar
// looks phone-shaped; a DOB looks like a generic date)
const GENERIC_VALUE_TYPES = new Set(["phone_number", "possible_dob"]);
// field names confident enough to override a loose, whole-value pattern match
const AUTHORITATIVE_FIELD_TYPES = new Set([
  "aadhaar", "credit_card", "bank_account", "pan", "ssn", "passport", "voter_id",
  "driver_license", "government_id", "date_of_birth", "ifsc", "upi_id", "tax_id", "imei",
]);

function detectInValue(field, hintKey, value, ctx) {
  const valueStr = String(value);
  let spans = detectSpans(valueStr, ctx);
  if ((typeof value === "string" || typeof value === "number") && valueStr.trim()) {
    const t = keyHint(hintKey, new Set(spans.map((s) => s.type)));
    if (t) {
      // an authoritative field name wins over a generic pattern that matched the WHOLE value
      if (AUTHORITATIVE_FIELD_TYPES.has(t)) {
        const whole = valueStr.trim();
        spans = spans.filter((s) => !(GENERIC_VALUE_TYPES.has(s.type) && s.text.trim() === whole));
      }
      const out = spans.map((s) => makeFinding(field, s.type, s.text, "pattern", ctx));
      out.push(makeFinding(field, t, valueStr, "field-name", ctx));
      return out;
    }
  }
  return spans.map((s) => makeFinding(field, s.type, s.text, "pattern", ctx));
}

/* masked version of one scalar: replace each matched span (or the whole value
   when only a field-name hint applies). Returns the original value untouched if
   nothing matched, so JSON types are preserved where possible. */
function maskScalar(value, hintKey, ctx) {
  const valueStr = String(value);
  const spans = detectSpans(valueStr, ctx);
  if (spans.length) {
    let out = valueStr;
    for (const s of [...spans].sort((a, b) => b.start - a.start)) {
      if (isMasked(s.text)) continue;
      out = out.slice(0, s.start) + safeMask(ctx.meta, s.type, s.text) + out.slice(s.end);
    }
    return out;
  }
  if ((typeof value === "string" || typeof value === "number") && valueStr.trim() && !isMasked(valueStr)) {
    const t = keyHint(hintKey, new Set());
    if (t) return safeMask(ctx.meta, t, valueStr);
  }
  return value;
}

/* ── JSON walking ─────────────────────────────────── */
function walk(node, path, hintKey, out, ctx) {
  if (node === null || node === undefined) return;
  if (Array.isArray(node)) node.forEach((v, i) => walk(v, `${path}[${i}]`, hintKey, out, ctx));
  else if (typeof node === "object") for (const [k, v] of Object.entries(node)) walk(v, path ? `${path}.${k}` : k, k, out, ctx);
  else out.push(...detectInValue(path || "(root)", hintKey || "", node, ctx));
}
function maskNode(node, hintKey, ctx) {
  if (node === null || node === undefined) return node;
  if (Array.isArray(node)) return node.map((v) => maskNode(v, hintKey, ctx));
  if (typeof node === "object") { const o = {}; for (const [k, v] of Object.entries(node)) o[k] = maskNode(v, k, ctx); return o; }
  return maskScalar(node, hintKey, ctx);
}

/* ── log / text lines ─────────────────────────────── */
const PAIR_RE = () => /([A-Za-z_][\w.-]*)\s*[=:]\s*(?:"([^"]*)"|'([^']*)'|([^\s,;}]+))/g;
function scanLogLine(line, i, ctx, findings) {
  const field = `line ${i + 1}`;
  const seen = new Set();
  const push = (f) => { const sig = `${f.type}|${f.sample}`; if (!seen.has(sig)) { seen.add(sig); findings.push(f); } };
  let m;
  const re = PAIR_RE();
  while ((m = re.exec(line)) !== null) {
    const val = m[2] ?? m[3] ?? m[4] ?? "";
    detectInValue(`${field} · ${m[1]}`, m[1], val, ctx).forEach(push);
  }
  detectInValue(field, "", line, ctx).forEach(push); // bare PII not in key=value form
}
function maskLine(line, ctx) {
  // pattern-mask first (emails, IPs, cards…), then key=value hints for what regex
  // can't catch on its own (password=hunter2)
  let out = String(maskScalar(line, "", ctx));
  out = out.replace(PAIR_RE(), (full, key, dq, sq, bare) => {
    const raw = dq ?? sq ?? bare ?? "";
    if (!raw || isMasked(raw)) return full;
    const t = keyHint(key, new Set());
    return t ? full.replace(raw, safeMask(ctx.meta, t, raw)) : full;
  });
  return out;
}

const looksNdjson = (text) => {
  const lines = text.split(/\r?\n/).filter((l) => l.trim());
  return lines.length > 1 && lines.every((l) => /^\s*\{.*\}\s*$/.test(l));
};

function summarize(findings) {
  const unmasked = findings.filter((f) => !f.masked);
  const by = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of unmasked) by[f.severity] = (by[f.severity] || 0) + 1;
  const status = by.critical || by.high ? "fail" : by.medium || by.low ? "warn" : "ok";
  return { total: findings.length, unmasked: unmasked.length, masked: findings.length - unmasked.length, by, status };
}

/** Scan API-response JSON, NDJSON, or raw log/text.
 *  opts.customRules = [{label, pattern, severity}] (optional). */
export function scanText(input, opts = {}) {
  const ctx = buildContext(opts.customRules);
  const text = String(input ?? "");
  const trimmed = text.trim();
  let findings = [];
  let format = "text";

  if (trimmed && (trimmed[0] === "{" || trimmed[0] === "[")) {
    try { walk(JSON.parse(text), "", "", findings, ctx); format = "json"; } catch { /* fall through */ }
  }
  if (format === "text" && looksNdjson(text)) {
    format = "ndjson";
    text.split(/\r?\n/).forEach((line, i) => {
      if (!line.trim()) return;
      try { walk(JSON.parse(line), `line ${i + 1}`, "", findings, ctx); } catch { scanLogLine(line, i, ctx, findings); }
    });
  }
  if (format === "text") {
    format = "logs";
    text.split(/\r?\n/).forEach((line, i) => { if (line.trim()) scanLogLine(line, i, ctx, findings); });
  }

  if (findings.length > MAX_FINDINGS) findings = findings.slice(0, MAX_FINDINGS);
  findings.sort((a, b) => Number(a.masked) - Number(b.masked) || sev(b) - sev(a));
  const top = findings.find((f) => !f.masked && f.suggested_masking);
  return { format, findings, suggested_masking: top ? top.suggested_masking : null, summary: summarize(findings) };
}

/** Produce a masked copy of the input (same parsing rules as scanText). */
export function maskText(input, opts = {}) {
  const ctx = buildContext(opts.customRules);
  const text = String(input ?? "");
  const trimmed = text.trim();
  if (trimmed && (trimmed[0] === "{" || trimmed[0] === "[")) {
    try { return JSON.stringify(maskNode(JSON.parse(text), "", ctx), null, 2); } catch { /* fall through */ }
  }
  if (looksNdjson(text)) {
    return text.split(/\r?\n/).map((line) => {
      if (!line.trim()) return line;
      try { return JSON.stringify(maskNode(JSON.parse(line), "", ctx)); } catch { return maskLine(line, ctx); }
    }).join("\n");
  }
  return text.split(/\r?\n/).map((line) => (line.trim() ? maskLine(line, ctx) : line)).join("\n");
}

/** CI helper: non-zero exit warranted at this threshold? */
export function failsAt(result, threshold = "high") {
  const min = SEVERITY_ORDER[threshold] || 3;
  return result.findings.some((f) => !f.masked && (SEVERITY_ORDER[f.severity] || 0) >= min);
}
