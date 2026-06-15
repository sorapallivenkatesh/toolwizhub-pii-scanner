/* core/scan.js — PURE scan engine. Parse JSON (or fall back to log lines),
   walk to leaf values with field paths, run detectors, return structured
   findings + a suggested masking. No DOM, no I/O. Shared by UI and CLI. */

import { TYPE_META, VALUE_DETECTORS, KEY_HINTS, isMasked, SEVERITY_ORDER } from "./rules.js";

const sev = (f) => SEVERITY_ORDER[f.severity] || 0;
const truncate = (s, n = 96) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

function safeMask(type, value) {
  try { return TYPE_META[type].mask(value); } catch { return "‹masked›"; }
}

function makeFinding(field, type, value, via) {
  const meta = TYPE_META[type];
  const masked = isMasked(value);
  return {
    field,
    type,
    label: meta.label,
    masked,
    severity: meta.severity,
    regulations: meta.regs,
    sample: truncate(String(value)),
    suggested_masking: masked ? null : safeMask(type, value),
    via, // "pattern" | "field-name"
  };
}

/* recurse a parsed JSON value to (field-path, key, leaf-value) tuples */
function walkJson(node, path, out) {
  if (node === null || node === undefined) return;
  if (Array.isArray(node)) {
    node.forEach((v, i) => walkJson(v, `${path}[${i}]`, out));
  } else if (typeof node === "object") {
    for (const [k, v] of Object.entries(node)) {
      const p = path ? `${path}.${k}` : k;
      if (v !== null && typeof v === "object") walkJson(v, p, out);
      else out.push({ field: p, key: k, value: v });
    }
  } else {
    out.push({ field: path || "(root)", key: "", value: node });
  }
}

function detectInValue(field, key, value) {
  const out = [];
  const seen = new Set();
  const valueStr = String(value);

  // 1) regex/pattern detectors on the value
  for (const det of VALUE_DETECTORS) {
    const re = det.regex();
    let m;
    while ((m = re.exec(valueStr)) !== null) {
      if (m[0] === "") { re.lastIndex++; continue; }
      if (det.validate && !det.validate(m[0])) continue;
      if (seen.has(det.type)) continue;
      seen.add(det.type);
      out.push(makeFinding(field, det.type, m[0], "pattern"));
    }
  }

  // 2) field-name hint (catches name/address/dob/etc. regex can't) — one per field
  if ((typeof value === "string" || typeof value === "number") && valueStr.trim()) {
    for (const hint of KEY_HINTS) {
      if (hint.re.test(key) && !seen.has(hint.type)) {
        out.push(makeFinding(field, hint.type, valueStr, "field-name"));
        break;
      }
    }
  }
  return out;
}

function summarize(findings) {
  const unmasked = findings.filter((f) => !f.masked);
  const by = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of unmasked) by[f.severity] = (by[f.severity] || 0) + 1;
  const status = by.critical || by.high ? "fail" : by.medium || by.low ? "warn" : "ok";
  return { total: findings.length, unmasked: unmasked.length, masked: findings.length - unmasked.length, by, status };
}

/** Scan API-response JSON or raw log text. */
export function scanText(input) {
  const text = String(input ?? "");
  const leaves = [];
  let format = "logs";

  try {
    walkJson(JSON.parse(text), "", leaves);
    format = "json";
  } catch {
    text.split(/\r?\n/).forEach((line, i) => {
      if (line.trim()) leaves.push({ field: `line ${i + 1}`, key: "", value: line });
    });
  }

  const findings = [];
  for (const leaf of leaves) findings.push(...detectInValue(leaf.field, leaf.key, leaf.value));

  // unmasked first, then by severity (desc)
  findings.sort((a, b) => Number(a.masked) - Number(b.masked) || sev(b) - sev(a));

  const top = findings.find((f) => !f.masked && f.suggested_masking);
  return {
    format,
    findings,
    suggested_masking: top ? top.suggested_masking : null,
    summary: summarize(findings),
  };
}

/** CI helper: does the result warrant a non-zero exit at the given threshold? */
export function failsAt(result, threshold = "high") {
  const min = SEVERITY_ORDER[threshold] || 3;
  return result.findings.some((f) => !f.masked && (SEVERITY_ORDER[f.severity] || 0) >= min);
}
