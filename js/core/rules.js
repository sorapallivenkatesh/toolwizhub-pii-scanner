/* core/rules.js — PURE PII detection rules. No DOM, no I/O.
   VALUE-FIRST: keys are arbitrary, so detection is driven by value patterns +
   checksums; field-name hints are only a secondary safety net (and the only
   signal for word-based PII like gender/religion/salary that has no pattern). */

/* ── checksum / format validators ─────────────────── */
export function luhnValid(s) {
  const d = String(s).replace(/\D/g, "");
  if (d.length < 12 || d.length > 19) return false;
  let sum = 0, alt = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = +d[i];
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return sum % 10 === 0;
}
export function luhn15(s) { const d = String(s).replace(/\D/g, ""); return d.length === 15 && luhnLike(d); }
function luhnLike(d) { let s = 0, a = false; for (let i = d.length - 1; i >= 0; i--) { let n = +d[i]; if (a) { n *= 2; if (n > 9) n -= 9; } s += n; a = !a; } return s % 10 === 0; }

const VH_D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
const VH_P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
export function aadhaarValid(s) {
  const d = String(s).replace(/\D/g, "");
  if (d.length !== 12 || !/^[2-9]/.test(d)) return false;
  let c = 0; const arr = d.split("").reverse().map(Number);
  for (let i = 0; i < arr.length; i++) c = VH_D[c][VH_P[i % 8][arr[i]]];
  return c === 0;
}
export function abaValid(s) {
  const d = String(s).replace(/\D/g, "");
  if (d.length !== 9) return false;
  const n = d.split("").map(Number);
  return (3 * (n[0] + n[3] + n[6]) + 7 * (n[1] + n[4] + n[7]) + (n[2] + n[5] + n[8])) % 10 === 0;
}
export function publicIPv4(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  const [a, b] = p;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 192 && b === 0 && p[2] === 2) return false;
  return true;
}
const publicIPv6 = (ip) => { const s = ip.toLowerCase(); return !(s === "::1" || s === "::" || s.startsWith("fe80") || s.startsWith("fc") || s.startsWith("fd")); };
// Real card networks have fixed lengths — this rejects e.g. a 15-digit IMEI that
// happens to start with 4 and pass Luhn (Visa is 13/16/19, never 15).
function creditCardValid(m) {
  const d = m.replace(/\D/g, "");
  if (!luhnLike(d)) return false;
  const L = d.length;
  if (/^3[47]/.test(d)) return L === 15;                 // Amex
  if (/^4/.test(d)) return L === 13 || L === 16 || L === 19; // Visa
  if (/^(?:5[1-5]|2[2-7])/.test(d)) return L === 16;     // Mastercard
  if (/^6(?:011|5)/.test(d)) return L === 16 || L === 19; // Discover
  if (/^35/.test(d)) return L === 16;                    // JCB
  return false;
}
function ibanValid(raw) {
  const s = raw.replace(/\s/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(s)) return false;
  const re = (s.slice(4) + s.slice(0, 4)).replace(/[A-Z]/g, (c) => c.charCodeAt(0) - 55);
  let rem = 0; for (const ch of re) rem = (rem * 10 + +ch) % 97;
  return rem === 1;
}
// plausible date-of-birth (older than ~13y, after 1900) — keeps recent timestamps out
function plausibleDob(m) {
  const y = +(m.match(/(?:19|20)\d{2}/) || [0])[0];
  return y >= 1900 && y <= new Date().getFullYear() - 13;
}

/** Already masked / redacted? */
export function isMasked(value) {
  const s = String(value);
  return /[X*•●#]{2,}/i.test(s) || /(?:[X*•●]\s){2,}/i.test(s) ||
    /\b(?:redacted|masked|hidden|filtered)\b/i.test(s) || /\[(?:redacted|masked|hidden|filtered|\.{2,}|…)\]/i.test(s);
}
const keepEnds = (value, head, tail, ch = "X") => {
  const v = String(value);
  if (v.length <= head + tail) return ch.repeat(v.length);
  return v.slice(0, head) + ch.repeat(Math.max(2, v.length - head - tail)) + v.slice(v.length - tail);
};
const redact = () => "[redacted]";

/* ── per-type metadata: severity, regulations, masking, optional TS snippet ─ */
const SENSITIVE = ["DPDP", "GDPR (special category)"];
export const TYPE_META = {
  // direct identifiers
  name: { label: "Personal name", severity: "medium", regs: ["DPDP", "GDPR"], mask: (v) => String(v).split(/\s+/).map((w) => w ? w[0] + "." : w).join(" ") },
  email: { label: "Email address", severity: "medium", regs: ["DPDP", "GDPR"], mask: (v) => { const [u, d] = String(v).split("@"); return (u ? u[0] : "") + "***@" + (d || "***"); },
    snippet: "const maskEmail = (e: string) => e.replace(/^(.).*(@.*)$/, (_, a, b) => a + '***' + b);" },
  phone_number: { label: "Phone number", severity: "high", regs: ["DPDP", "GDPR"], mask: (v) => keepEnds(String(v).replace(/\s+/g, " ").trim(), 3, 2),
    snippet: "const maskPhone = (p: string) => p.replace(/(?<=.{3})\\d(?=.*\\d{2})/g, 'X');" },
  address: { label: "Postal address", severity: "medium", regs: ["DPDP", "GDPR"], mask: redact },
  username: { label: "Username / login", severity: "low", regs: ["DPDP", "GDPR"], mask: (v) => keepEnds(String(v), 2, 0) },
  ssn: { label: "US Social Security Number", severity: "critical", regs: ["GDPR"], mask: (v) => "XXX-XX-" + String(v).replace(/\D/g, "").slice(-4) },
  aadhaar: { label: "Aadhaar (India)", severity: "critical", regs: ["DPDP"], mask: (v) => "XXXX XXXX " + String(v).replace(/\D/g, "").slice(-4) },
  pan: { label: "PAN (India)", severity: "high", regs: ["DPDP"], mask: (v) => { const s = String(v); return s.slice(0, 3) + "XXXX" + s.slice(-1); } },
  passport: { label: "Passport number", severity: "high", regs: ["DPDP", "GDPR"], mask: (v) => String(v).slice(0, 2) + "XXXXXX" },
  driver_license: { label: "Driver's license", severity: "high", regs: ["DPDP", "GDPR"], mask: (v) => keepEnds(String(v), 2, 2) },
  voter_id: { label: "Voter ID (India EPIC)", severity: "high", regs: ["DPDP"], mask: (v) => String(v).slice(0, 3) + "XXXXXXX" },
  government_id: { label: "Government ID", severity: "high", regs: ["DPDP", "GDPR"], mask: (v) => keepEnds(String(v), 2, 2) },

  // quasi-identifiers (mostly field-name driven; value detection is weak)
  date_of_birth: { label: "Date of birth", severity: "high", regs: ["DPDP", "GDPR"], mask: (v) => String(v).replace(/\d/g, "X") },
  possible_dob: { label: "Date (possible DOB)", severity: "low", regs: ["DPDP", "GDPR"], mask: (v) => String(v).replace(/\d/g, "X") },
  gender: { label: "Gender", severity: "low", regs: ["DPDP", "GDPR"], mask: redact },
  age: { label: "Age", severity: "low", regs: ["DPDP", "GDPR"], mask: redact },
  place_of_birth: { label: "Place of birth", severity: "low", regs: ["DPDP", "GDPR"], mask: redact },
  job_employer: { label: "Job / employer", severity: "low", regs: ["DPDP", "GDPR"], mask: redact },

  // financial
  credit_card: { label: "Credit card number", severity: "critical", regs: ["DPDP", "GDPR", "PCI-DSS"], mask: (v) => "•••• •••• •••• " + String(v).replace(/\D/g, "").slice(-4),
    snippet: "const maskCard = (c: string) => '**** **** **** ' + c.replace(/\\D/g,'').slice(-4);" },
  cvv: { label: "Card CVV", severity: "critical", regs: ["PCI-DSS"], mask: () => "•••" },
  card_expiry: { label: "Card expiry", severity: "medium", regs: ["PCI-DSS"], mask: () => "XX/XX" },
  bank_account: { label: "Bank account number", severity: "critical", regs: ["DPDP", "GDPR", "PCI-DSS"], mask: (v) => keepEnds(String(v).replace(/\s/g, ""), 0, 4) },
  ifsc: { label: "IFSC code (India bank)", severity: "high", regs: ["DPDP"], mask: (v) => String(v).slice(0, 4) + "XXXXXXX" },
  routing_number: { label: "Bank routing (US ABA)", severity: "high", regs: ["GDPR"], mask: (v) => "XXXXX" + String(v).replace(/\D/g, "").slice(-4) },
  iban: { label: "IBAN", severity: "critical", regs: ["DPDP", "GDPR", "PCI-DSS"], mask: (v) => { const s = String(v).replace(/\s/g, ""); return s.slice(0, 4) + " •••• " + s.slice(-4); } },
  upi_id: { label: "UPI ID (India)", severity: "high", regs: ["DPDP"], mask: (v) => { const [u, h] = String(v).split("@"); return (u ? u[0] : "") + "***@" + (h || ""); } },
  tax_id: { label: "Tax ID (EIN)", severity: "high", regs: ["GDPR"], mask: (v) => "XX-XXX" + String(v).replace(/\D/g, "").slice(-4) },
  salary: { label: "Salary / income", severity: "medium", regs: ["DPDP", "GDPR"], mask: redact },

  // digital identifiers
  ip_address: { label: "IP address", severity: "low", regs: ["GDPR"], mask: (v) => String(v).includes(":") ? String(v).split(":").slice(0, 2).join(":") + "::x" : String(v).split(".").slice(0, 1).concat(["x","x","x"]).join("."),
    snippet: "const maskIp = (ip: string) => ip.replace(/(\\.\\d+){3}$/, '.x.x.x');" },
  mac_address: { label: "MAC address", severity: "medium", regs: ["GDPR"], mask: (v) => String(v).slice(0, 8) + ":XX:XX:XX" },
  imei: { label: "IMEI (device)", severity: "high", regs: ["DPDP", "GDPR"], mask: (v) => String(v).replace(/\D/g, "").slice(0, 8) + "XXXXXXX" },
  device_id: { label: "Device / advertising ID", severity: "medium", regs: ["DPDP", "GDPR"], mask: redact },
  uuid: { label: "Identifier (UUID)", severity: "low", regs: ["DPDP", "GDPR"], mask: (v) => String(v).slice(0, 8) + "-…" },
  session_token: { label: "Session / cookie token", severity: "critical", regs: ["DPDP", "GDPR"], mask: (v) => String(v).slice(0, 6) + "…" },
  jwt_token: { label: "JWT / bearer token", severity: "critical", regs: ["DPDP", "GDPR"], mask: (v) => String(v).slice(0, 8) + "…<redacted>",
    snippet: "// Never log tokens; keep at most a short prefix.\nconst maskToken = (t: string) => t.slice(0, 6) + '…';" },
  secret_key: { label: "API key / secret", severity: "critical", regs: ["DPDP", "GDPR"], mask: (v) => { const s = String(v); const i = s.search(/[_-]/); return (i > 0 ? s.slice(0, i + 1) : s.slice(0, 4)) + "••••••"; } },
  social_profile: { label: "Social media profile", severity: "medium", regs: ["DPDP", "GDPR"], mask: redact },
  profile_image: { label: "Profile image URL", severity: "low", regs: ["DPDP", "GDPR"], mask: redact },
  precise_location: { label: "Precise location (GPS)", severity: "high", regs: ["DPDP", "GDPR"], mask: (v) => String(v).replace(/-?\d+\.\d+/g, (n) => (Math.round(+n * 10) / 10).toFixed(1)),
    snippet: "// Round coords before logging\nconst coarse = (n: number) => Math.round(n * 10) / 10;" },
  location: { label: "Location / address hint", severity: "medium", regs: ["DPDP", "GDPR"], mask: redact },

  // sensitive / special-category + biometric
  biometric: { label: "Biometric data", severity: "critical", regs: SENSITIVE, mask: redact },
  health_data: { label: "Health / medical data", severity: "critical", regs: SENSITIVE, mask: redact },
  religion: { label: "Religious belief", severity: "critical", regs: SENSITIVE, mask: redact },
  ethnicity: { label: "Race / ethnicity", severity: "critical", regs: SENSITIVE, mask: redact },
  political: { label: "Political affiliation", severity: "critical", regs: SENSITIVE, mask: redact },
  sexual_orientation: { label: "Sexual orientation", severity: "critical", regs: SENSITIVE, mask: redact },
  criminal_record: { label: "Criminal history", severity: "critical", regs: SENSITIVE, mask: redact },
  password: { label: "Password / credential", severity: "critical", regs: ["DPDP", "GDPR"], mask: () => "••••••••" },
};

/* ── value detectors, ordered most-specific → most-general (first claims span) ─ */
export const VALUE_DETECTORS = [
  { type: "jwt_token", regex: () => /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}\b/g },
  { type: "secret_key", regex: () => /\b(?:sk|pk|rk|ghp|gho|xox[baprs])[._-][A-Za-z0-9_-]{12,}\b/g },
  { type: "secret_key", regex: () => /\bAKIA[0-9A-Z]{16}\b/g },
  { type: "social_profile", regex: () => /\bhttps?:\/\/(?:www\.)?(?:twitter|x|instagram|facebook|fb|linkedin|github|tiktok|reddit|t\.me)\.com\/[A-Za-z0-9_.\/-]{2,}/gi },
  { type: "profile_image", regex: () => /\bhttps?:\/\/\S+\.(?:jpg|jpeg|png|webp|gif)\b\S*/gi, validate: (m) => /avatar|profile|photo|user|face|dp/i.test(m) },
  { type: "iban", regex: () => /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g, validate: ibanValid },
  { type: "credit_card", regex: () => /\b(?:\d[ -]?){13,19}\b/g, validate: creditCardValid },
  { type: "imei", regex: () => /\b\d{15}\b/g, validate: luhn15 },
  { type: "ifsc", regex: () => /\b[A-Z]{4}0[A-Z0-9]{6}\b/g },
  { type: "voter_id", regex: () => /\b[A-Z]{3}[0-9]{7}\b/g },
  { type: "passport", regex: () => /\b[A-PR-WY][0-9]{7}\b/g },
  { type: "ssn", regex: () => /\b\d{3}-\d{2}-\d{4}\b/g },
  { type: "tax_id", regex: () => /\b\d{2}-\d{7}\b/g },
  { type: "pan", regex: () => /\b[A-Z]{5}\d{4}[A-Z]\b/g },
  { type: "aadhaar", regex: () => /\b\d{4}\s?\d{4}\s?\d{4}\b/g, validate: aadhaarValid },
  { type: "upi_id", regex: () => /\b[a-z0-9.\-]{2,}@(?:ok(?:axis|hdfcbank|icici|sbi)|paytm|ybl|apl|ibl|upi|axl|hdfc|sbi|icici)\b/gi },
  { type: "email", regex: () => /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { type: "mac_address", regex: () => /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g },
  { type: "uuid", regex: () => /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi },
  { type: "precise_location", regex: () => /-?\d{1,2}\.\d{4,},\s?-?\d{1,3}\.\d{4,}/g },
  { type: "ip_address", regex: () => /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g, validate: publicIPv4 },
  { type: "ip_address", regex: () => /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b/g, validate: publicIPv6 },
  { type: "routing_number", regex: () => /(?<![\d-])\d{9}(?![\d-])/g, validate: abaValid },
  { type: "possible_dob", regex: () => /\b(?:19\d{2}|20[0-2]\d)-\d{2}-\d{2}\b|\b\d{2}\/\d{2}\/(?:19|20)\d{2}\b/g, validate: plausibleDob },
  { type: "phone_number", regex: () => /(?<![\w.])\+?\d[\d\s().-]{7,}\d(?![\w.])/g,
    validate: (m) => { const d = m.replace(/\D/g, ""); return d.length >= 10 && d.length <= 15 && (/[+]/.test(m) || /[\s().-]/.test(m)); } },
];

/* ── field-name hints — secondary net + only signal for word-based PII ───── */
export const KEY_HINTS = [
  { re: /pass(?:word|wd|phrase)|(?:^|[._-])pwd(?:$|[._-])/i, type: "password" },
  { re: /secret|api[._-]?key|access[._-]?token|client[._-]?secret|private[._-]?key|auth[._-]?token|bearer/i, type: "secret_key" },
  { re: /session|cookie|csrf|(?:^|[._-])sid(?:$|[._-])|refresh[._-]?token/i, type: "session_token" },
  { re: /aadhaar|aadhar|uidai/i, type: "aadhaar" },
  { re: /(?:^|[._-])pan(?:$|[._-])|pan[._-]?(?:no|num|number|card)/i, type: "pan" },
  { re: /ssn|social[._-]?security/i, type: "ssn" },
  { re: /passport/i, type: "passport" },
  { re: /(?:driv(?:er|ing)|dl)[._-]?(?:license|licence|no|number)|licen[cs]e[._-]?(?:no|number)/i, type: "driver_license" },
  { re: /voter|epic[._-]?(?:no|id)/i, type: "voter_id" },
  { re: /(?:gov(?:ernment)?|national)[._-]?id|nin\b|nid\b/i, type: "government_id" },
  { re: /(?:^|[._-])dob(?:$|[._-])|date[._-]?of[._-]?birth|birth[._-]?date|birthday/i, type: "date_of_birth" },
  { re: /(?:^|[._-])(?:gender|sex)(?:$|[._-])/i, type: "gender" },
  { re: /(?:^|[._-])age(?:$|[._-])/i, type: "age" },
  { re: /place[._-]?of[._-]?birth|birth[._-]?place/i, type: "place_of_birth" },
  { re: /job[._-]?title|employer|company[._-]?name|occupation|designation/i, type: "job_employer" },
  { re: /salary|income|ctc|compensation/i, type: "salary" },
  { re: /(?:^|[._-])cvv(?:$|[._-])|cvc|cvv2|card[._-]?(?:sec|verif)/i, type: "cvv" },
  { re: /(?:card[._-]?)?expir|exp[._-]?(?:date|month|year)/i, type: "card_expiry" },
  { re: /account[._-]?(?:no|num|number)|acct[._-]?no|bank[._-]?account/i, type: "bank_account" },
  { re: /ifsc/i, type: "ifsc" },
  { re: /routing[._-]?(?:no|number)|aba/i, type: "routing_number" },
  { re: /upi(?:[._-]?id)?|vpa/i, type: "upi_id" },
  { re: /tax[._-]?(?:id|no|number)|\bein\b|\btin\b/i, type: "tax_id" },
  { re: /(?:^|[._-])(?:lat|lng|lon|long|latitude|longitude)(?:$|[._-])|lat[._-]?lng|geo(?:location)?|coord|gps/i, type: "precise_location" },
  { re: /imei|device[._-]?id|udid|idfa|gaid|advertis(?:ing)?[._-]?id/i, type: "device_id" },
  { re: /(?:profile|avatar|user)[._-]?(?:image|img|pic|photo)|photo[._-]?url/i, type: "profile_image" },
  { re: /(?:^|[._-])(?:first|last|full|middle|sur|given|display|nick)[._-]?name(?:$|[._-])|^name$/i, type: "name" },
  { re: /address|street|(?:^|[._-])(?:city|state|zip)(?:$|[._-])|postal|pin[._-]?code|pincode/i, type: "address" },
  { re: /phone|mobile|msisdn|whatsapp|(?:^|[._-])tel(?:ephone)?(?:$|[._-])|contact[._-]?(?:no|number)/i, type: "phone_number" },
  { re: /e-?mail/i, type: "email" },
  { re: /user(?:_?name|_?id|_?login)|login[._-]?id|handle/i, type: "username" },
  { re: /(?:^|[._-])ip(?:[._-]?addr(?:ess)?)?(?:$|[._-])|client[._-]?ip|remote[._-]?addr/i, type: "ip_address" },
  // sensitive / special-category
  { re: /biometric|fingerprint|face[._-]?(?:data|id|print|scan)|voice[._-]?print|iris|retina|\bdna\b/i, type: "biometric" },
  { re: /health|medical|diagnos|disease|blood[._-]?group|prescription|patient/i, type: "health_data" },
  { re: /religion|religious|faith/i, type: "religion" },
  { re: /ethnicit|race|caste/i, type: "ethnicity" },
  { re: /politic/i, type: "political" },
  { re: /sexual[._-]?orientation|\blgbt/i, type: "sexual_orientation" },
  { re: /criminal|conviction|offen[cs]e[._-]?record|arrest/i, type: "criminal_record" },
];

export const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };
