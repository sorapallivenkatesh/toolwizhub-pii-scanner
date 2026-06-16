/* core/scan.js — PURE scan engine. Parse JSON (or fall back to log/text),
   walk to values with field paths, run detectors with span-level dedup so a
   value isn't double-flagged, and return structured findings. No DOM/I-O. */

import { TYPE_META, VALUE_DETECTORS, KEY_HINTS, isMasked, SEVERITY_ORDER } from "./rules.js";

const MAX_FINDINGS = 1000;
// don't add a generic field-hint type when a more specific value match already exists
const SUPPRESS = { device_id: ["imei", "uuid"], location: ["precise_location"], possible_dob: ["date_of_birth"] };
const sev = (f) => SEVERITY_ORDER[f.severity] || 0;
const truncate = (s, n = 120) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

function safeMask(type, value) {
  try { return TYPE_META[type].mask(value); } catch { return "‹masked›"; }
}

function makeFinding(field, type, matched, via) {
  const meta = TYPE_META[type];
  const masked = isMasked(matched);
  return {
    field, type,
    label: meta.label,
    masked,
    severity: meta.severity,
    regulations: meta.regs,
    sample: truncate(String(matched)),
    suggested_masking: masked ? null : safeMask(type, matched),
    via, // "pattern" | "field-name"
  };
}

/* run all value detectors over one string, claiming character spans so the
   first (most specific) match wins and overlapping weaker matches are dropped */
function detectInValue(field, hintKey, value) {
  const out = [];
  const valueStr = String(value);
  const claimed = [];
  const overlaps = (s, e) => claimed.some(([cs, ce]) => s < ce && e > cs);

  for (const det of VALUE_DETECTORS) {
    const re = det.regex();
    let m;
    while ((m = re.exec(valueStr)) !== null) {
      const text = m[0];
      if (text === "") { re.lastIndex++; continue; }
      const start = m.index, end = start + text.length;
      if (det.validate && !det.validate(text)) continue;
      if (overlaps(start, end)) continue;
      claimed.push([start, end]);
      out.push(makeFinding(field, det.type, text, "pattern"));
    }
  }

  // field-name hint (one per key) — catches name/address/password/etc. the regex can't,
  // and bare values (e.g. an unformatted phone) sitting in a clearly-PII field.
  if ((typeof value === "string" || typeof value === "number") && valueStr.trim()) {
    const have = new Set(out.map((f) => f.type));
    for (const hint of KEY_HINTS) {
      if (hint.re.test(hintKey) && !have.has(hint.type) && !(SUPPRESS[hint.type] || []).some((t) => have.has(t))) {
        out.push(makeFinding(field, hint.type, valueStr, "field-name"));
        break;
      }
    }
  }
  return out;
}

/* recurse parsed JSON. hintKey = the key that holds a scalar (for array items
   it's the array's key, so ["phones"][0] still gets the phone hint). */
function walk(node, path, hintKey, out) {
  if (node === null || node === undefined) return;
  if (Array.isArray(node)) {
    node.forEach((v, i) => walk(v, `${path}[${i}]`, hintKey, out));
  } else if (typeof node === "object") {
    for (const [k, v] of Object.entries(node)) walk(v, path ? `${path}.${k}` : k, k, out);
  } else {
    out.push({ field: path || "(root)", key: hintKey || "", value: node });
  }
}

const PAIR_RE = () => /([A-Za-z_][\w.-]*)\s*[=:]\s*(?:"([^"]*)"|'([^']*)'|([^\s,;}]+))/g;

function scanLogs(text) {
  const findings = [];
  text.split(/\r?\n/).forEach((line, i) => {
    if (!line.trim()) return;
    const field = `line ${i + 1}`;
    const seen = new Set();
    // 1) key=value / key:value pairs — gives field names + catches key-hint-only PII
    let m;
    const re = PAIR_RE();
    while ((m = re.exec(line)) !== null) {
      const key = m[1];
      const val = m[2] ?? m[3] ?? m[4] ?? "";
      for (const f of detectInValue(`${field} · ${key}`, key, val)) {
        const sig = `${f.type}|${f.sample}`;
        if (!seen.has(sig)) { seen.add(sig); findings.push(f); }
      }
    }
    // 2) whole-line pattern scan for bare PII not in key=value form
    for (const f of detectInValue(field, "", line)) {
      const sig = `${f.type}|${f.sample}`;
      if (!seen.has(sig)) { seen.add(sig); findings.push(f); }
    }
  });
  return findings;
}

function summarize(findings) {
  const unmasked = findings.filter((f) => !f.masked);
  const by = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of unmasked) by[f.severity] = (by[f.severity] || 0) + 1;
  const status = by.critical || by.high ? "fail" : by.medium || by.low ? "warn" : "ok";
  return { total: findings.length, unmasked: unmasked.length, masked: findings.length - unmasked.length, by, status };
}

/** Scan API-response JSON or raw log/text. */
export function scanText(input) {
  const text = String(input ?? "");
  let findings = [];
  let format = "text";

  const trimmed = text.trim();
  if (trimmed && (trimmed[0] === "{" || trimmed[0] === "[")) {
    try {
      const leaves = [];
      walk(JSON.parse(text), "", "", leaves);
      for (const lf of leaves) findings.push(...detectInValue(lf.field, lf.key, lf.value));
      format = "json";
    } catch { /* malformed JSON → fall through to text scan */ }
  }
  if (format !== "json") {
    findings = scanLogs(text);
    format = "logs";
  }

  if (findings.length > MAX_FINDINGS) findings = findings.slice(0, MAX_FINDINGS);
  findings.sort((a, b) => Number(a.masked) - Number(b.masked) || sev(b) - sev(a));

  const top = findings.find((f) => !f.masked && f.suggested_masking);
  return { format, findings, suggested_masking: top ? top.suggested_masking : null, summary: summarize(findings) };
}

/** CI helper: non-zero exit warranted at this threshold? */
export function failsAt(result, threshold = "high") {
  const min = SEVERITY_ORDER[threshold] || 3;
  return result.findings.some((f) => !f.masked && (SEVERITY_ORDER[f.severity] || 0) >= min);
}
