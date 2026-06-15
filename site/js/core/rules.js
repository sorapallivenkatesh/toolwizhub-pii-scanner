/* core/rules.js — PURE PII detection rules. No DOM, no I/O.
   Single source of truth for: what PII types exist, how to find them (regex),
   their severity + regulation mapping, and how to mask them. Shared by the
   browser UI and the CI CLI. */

/* ── helpers ──────────────────────────────────────── */
export function luhnValid(s) {
  const d = String(s).replace(/\D/g, "");
  if (d.length < 13 || d.length > 19) return false;
  let sum = 0, alt = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = +d[i];
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return sum % 10 === 0;
}

/** Does this value already look masked/redacted? */
export function isMasked(value) {
  const s = String(value);
  return (
    /(?:[X*•●#]\s?){3,}/i.test(s) ||
    /\*{3,}/.test(s) ||
    /\b(?:redacted|masked|hidden|null)\b/i.test(s) ||
    /\[(?:redacted|masked|hidden|filtered)\]/i.test(s)
  );
}

const keepEnds = (value, head, tail, ch = "X") => {
  const v = String(value);
  if (v.length <= head + tail) return ch.repeat(v.length);
  return v.slice(0, head) + ch.repeat(Math.max(2, v.length - head - tail)) + v.slice(v.length - tail);
};

/* ── per-type metadata: severity, regulations, masking, TS snippet ──────── */
export const TYPE_META = {
  email: {
    label: "Email address", severity: "medium", regs: ["DPDP", "GDPR"],
    mask: (v) => { const [u, d] = String(v).split("@"); return (u ? u[0] : "") + "***@" + (d || "***"); },
    snippet: "const maskEmail = (e: string): string => {\n  const [u, d] = e.split('@');\n  return u.slice(0, 1) + '***@' + (d ?? '');\n};",
  },
  phone_number: {
    label: "Phone number", severity: "high", regs: ["DPDP", "GDPR"],
    mask: (v) => keepEnds(String(v).replace(/\s+/g, " ").trim(), 3, 2),
    snippet: "const maskPhone = (p: string): string =>\n  p.replace(/(?<=.{3})\\d(?=.*\\d{2})/g, 'X');",
  },
  precise_location: {
    label: "Precise location", severity: "high", regs: ["DPDP", "GDPR"],
    mask: (v) => String(v).replace(/-?\d+\.\d+/g, (n) => (+n).toFixed(1).replace(/\d$/, "X")),
    snippet: "// Round coordinates to ~11km (1 decimal) instead of storing precise lat/lng\nconst coarse = (n: number): number => Math.round(n * 10) / 10;",
  },
  credit_card: {
    label: "Credit card number", severity: "critical", regs: ["DPDP", "GDPR", "PCI-DSS"],
    mask: (v) => { const d = String(v).replace(/\D/g, ""); return "•••• •••• •••• " + d.slice(-4); },
    snippet: "const maskCard = (c: string): string =>\n  '**** **** **** ' + c.replace(/\\D/g, '').slice(-4);",
  },
  ip_address: {
    label: "IP address", severity: "low", regs: ["GDPR"],
    mask: (v) => String(v).includes(":") ? String(v).split(":").slice(0, 2).join(":") + "::X" : String(v).split(".").slice(0, 1).concat(["X", "X", "X"]).join("."),
    snippet: "const maskIp = (ip: string): string =>\n  ip.replace(/\\.\\d+\\.\\d+\\.\\d+$/, '.x.x.x');",
  },
  aadhaar: {
    label: "Aadhaar number (India)", severity: "critical", regs: ["DPDP"],
    mask: (v) => { const d = String(v).replace(/\D/g, ""); return "XXXX XXXX " + d.slice(-4); },
    snippet: "const maskAadhaar = (a: string): string =>\n  'XXXX XXXX ' + a.replace(/\\D/g, '').slice(-4);",
  },
  pan: {
    label: "PAN (India)", severity: "high", regs: ["DPDP"],
    mask: (v) => { const s = String(v); return s.slice(0, 3) + "XXXX" + s.slice(-1); },
    snippet: "const maskPan = (p: string): string => p.slice(0, 3) + 'XXXX' + p.slice(-1);",
  },
  ssn: {
    label: "US Social Security Number", severity: "critical", regs: ["GDPR"],
    mask: (v) => "XXX-XX-" + String(v).replace(/\D/g, "").slice(-4),
    snippet: "const maskSsn = (s: string): string => 'XXX-XX-' + s.replace(/\\D/g, '').slice(-4);",
  },
  jwt_token: {
    label: "JWT / bearer token", severity: "critical", regs: ["DPDP", "GDPR"],
    mask: (v) => String(v).slice(0, 8) + "…<redacted>",
    snippet: "// Never log tokens. If you must, keep only a short prefix:\nconst maskToken = (t: string): string => t.slice(0, 6) + '…';",
  },
  secret_key: {
    label: "API key / secret", severity: "critical", regs: ["DPDP", "GDPR"],
    mask: (v) => { const s = String(v); const i = s.indexOf("_"); return (i > 0 ? s.slice(0, i + 1) : s.slice(0, 4)) + "••••••"; },
    snippet: "const maskSecret = (k: string): string => k.slice(0, 4) + '••••••';",
  },
  name: {
    label: "Personal name", severity: "medium", regs: ["DPDP", "GDPR"],
    mask: (v) => String(v).split(/\s+/).map((w) => (w ? w[0] + "." : w)).join(" "),
    snippet: "const maskName = (n: string): string =>\n  n.split(' ').map(w => w[0] + '.').join(' ');",
  },
  address: {
    label: "Postal address", severity: "medium", regs: ["DPDP", "GDPR"],
    mask: () => "[address redacted]",
    snippet: "const maskAddress = (): string => '[redacted]';",
  },
  date_of_birth: {
    label: "Date of birth", severity: "high", regs: ["DPDP", "GDPR"],
    mask: (v) => String(v).replace(/\d/g, "X"),
    snippet: "// Store age range or year only, not full DOB\nconst maskDob = (d: string): string => d.replace(/\\d/g, 'X');",
  },
  password: {
    label: "Password / credential", severity: "critical", regs: ["DPDP", "GDPR"],
    mask: () => "••••••••",
    snippet: "// Never store or log raw passwords — hash them (bcrypt/argon2).",
  },
};

/* ── value detectors: regex applied to string values ───────────────────── */
export const VALUE_DETECTORS = [
  { type: "jwt_token", regex: () => /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b/g },
  { type: "secret_key", regex: () => /\b(?:sk|pk|rk|api|key|ghp|xox[baprs])[._-][A-Za-z0-9]{16,}\b/gi },
  { type: "email", regex: () => /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { type: "credit_card", regex: () => /\b(?:\d[ -]?){13,19}\b/g, validate: (m) => luhnValid(m) },
  { type: "ssn", regex: () => /\b\d{3}-\d{2}-\d{4}\b/g },
  { type: "pan", regex: () => /\b[A-Z]{5}\d{4}[A-Z]\b/g },
  { type: "aadhaar", regex: () => /\b\d{4}\s?\d{4}\s?\d{4}\b/g, validate: (m) => !luhnValid(m) },
  { type: "precise_location", regex: () => /-?\d{1,3}\.\d{3,},\s?-?\d{1,3}\.\d{3,}/g },
  { type: "phone_number", regex: () => /\+?\d[\d\s().-]{8,}\d/g, validate: (m) => { const d = m.replace(/\D/g, ""); return d.length >= 10 && d.length <= 15; } },
  { type: "ip_address", regex: () => /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g },
];

/* ── key-name hints: infer PII from the field name even if the value regex
      misses it (e.g. "user.full_name": "Asha Rao"). ─────────────────────── */
export const KEY_HINTS = [
  { re: /pass(word|wd|phrase)|pwd/i, type: "password" },
  { re: /secret|api[_-]?key|access[_-]?token|client[_-]?secret/i, type: "secret_key" },
  { re: /aadhaar|aadhar|uidai/i, type: "aadhaar" },
  { re: /\bpan\b|pan[_-]?(no|number|card)/i, type: "pan" },
  { re: /ssn|social[_-]?security/i, type: "ssn" },
  { re: /\bdob\b|date[_-]?of[_-]?birth|birth[_-]?date/i, type: "date_of_birth" },
  { re: /lat|lng|long|lat[_-]?lng|geo|coords?|location/i, type: "precise_location" },
  { re: /phone|mobile|msisdn|contact[_-]?no/i, type: "phone_number" },
  { re: /e-?mail/i, type: "email" },
  { re: /first[_-]?name|last[_-]?name|full[_-]?name|\bname\b/i, type: "name" },
  { re: /address|street|city|zip|postal|pincode/i, type: "address" },
];

export const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };
