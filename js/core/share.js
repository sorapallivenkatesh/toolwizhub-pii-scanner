/* core/share.js — encode a sanitized report into a URL-safe string and back,
   for "share with your team" links. CRITICAL: no raw PII travels in the link —
   unmasked samples are dropped, only the masked example/suggestion is kept.
   No DOM, no network (the link rides in the URL hash, like the Tickbox share). */

const pad = (s) => s + "=".repeat((4 - (s.length % 4)) % 4);
const b64e = (s) => btoa(unescape(encodeURIComponent(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64d = (s) => decodeURIComponent(escape(atob(pad(String(s).replace(/-/g, "+").replace(/_/g, "/")))));

/** Strip raw values; keep only what's safe to send to a teammate. */
export function sanitizeReport(result) {
  return {
    v: 1,
    format: result.format,
    summary: result.summary,
    findings: (result.findings || []).map((f) => ({
      field: f.field, type: f.type, label: f.label,
      severity: f.severity, regulations: f.regulations,
      via: f.via, masked: f.masked, ignored: !!f.ignored,
      // never the raw value — an already-masked sample is fine, otherwise the masked suggestion
      example: f.masked ? f.sample : (f.suggested_masking || null),
    })),
  };
}

export function encodeReport(result) {
  return b64e(JSON.stringify(sanitizeReport(result)));
}

export function decodeReport(str) {
  try {
    const obj = JSON.parse(b64d(str));
    return obj && Array.isArray(obj.findings) ? obj : null;
  } catch { return null; }
}
