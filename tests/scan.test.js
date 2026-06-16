/* Edge-case tests for the scan engine. Run: npm test */
import assert from "node:assert";
import { scanText, failsAt } from "../site/js/core/scan.js";
import { aadhaarValid, luhnValid, publicIPv4 } from "../site/js/core/rules.js";

let pass = 0;
const has = (r, t) => r.findings.some((f) => f.type === t && !f.masked);
const hasMasked = (r, t) => r.findings.some((f) => f.type === t && f.masked);
const ok = (cond, msg) => { assert.ok(cond, msg); pass++; };

/* ── true positives ───────────────────────────────── */
const json = JSON.stringify({
  user: { fullName: "Asha Rao", phone: "+91 9876543210", email: "asha@example.com", upi: "asha@okhdfcbank" },
  geo: { lat_lng: "12.9716,77.5946" },
  pay: { card: "4111 1111 1111 1111", iban: "DE89370400440532013000" },
  net: { ipv4: "203.0.113.42", ipv6: "2606:4700:4700::1111", mac: "AA:BB:CC:DD:EE:FF" },
  auth: { token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.7xK2pQwErT1aZ9bC3dEf", apiKey: "AKIAIOSFODNN7EXAMPLE" },
});
const r = scanText(json);
ok(r.format === "json", "json format");
for (const t of ["name", "phone_number", "email", "upi_id", "precise_location", "credit_card", "iban", "ip_address", "mac_address", "jwt_token", "secret_key"]) {
  ok(has(r, t), `detects ${t}`);
}
ok(r.findings.find((f) => f.type === "phone_number").field === "user.phone", "phone field path");
ok(r.suggested_masking, "offers masking");

/* card must NOT also be reported as a phone (span dedup) */
ok(!scanText('{"card":"4111 1111 1111 1111"}').findings.some((f) => f.type === "phone_number"), "card not double-flagged as phone");

/* ── false positives that must NOT flag ───────────── */
const fp = scanText(JSON.stringify({
  ts: 1718533620, count: 9876543210, orderId: "1234567890123",
  version: "1.0", localIp: "192.168.1.10", loopback: "127.0.0.1", internal: "10.0.0.5",
  filename: "report-2024.pdf", hostname: "api-prod-03",
  sku: "1234567812345678", refCode: "111122223333",
}));
ok(!has(fp, "phone_number"), "unix ts / bare ints / order id not phones");
ok(!has(fp, "credit_card"), "non-Luhn 16-digit not a card");
ok(!has(fp, "aadhaar"), "invalid-Verhoeff 12-digit not Aadhaar");
ok(!has(fp, "ip_address"), "private/loopback IPs not flagged");
ok(!has(fp, "name"), "filename/hostname not names");

/* ── masked awareness ─────────────────────────────── */
const mk = scanText('{"phone":"+91 98XXXXXX21","email":"a***@example.com"}');
ok(hasMasked(mk, "phone_number"), "masked phone via field name → masked:true");
ok(!failsAt(mk, "high"), "fully-masked payload does not fail CI");

/* ── arrays + nested + key propagation ────────────── */
const arr = scanText('{"contacts":{"phones":["9876543210","9123456780"]}}');
ok(arr.findings.filter((f) => f.type === "phone_number").length === 2, "bare phones in array caught via parent key");

/* ── logs: multi-match + key=value hints ──────────── */
const logs = scanText([
  "2026-06-16T10:22:01Z INFO from=alice@corp.com to=bob@corp.com ip=198.51.100.7",
  "DEBUG auth password=hunter2 token set",
].join("\n"));
ok(logs.format === "logs", "logs format");
ok(logs.findings.filter((f) => f.type === "email").length === 2, "two emails in one line");
ok(has(logs, "ip_address"), "public ip in log");
ok(has(logs, "password"), "password=… caught via key-hint (regex can't)");

/* ── validators (unit) ────────────────────────────── */
ok(luhnValid("4111111111111111"), "luhn valid card");
ok(!luhnValid("4111111111111112"), "luhn rejects bad card");
ok(!aadhaarValid("111122223333"), "aadhaar rejects bad checksum");
ok(publicIPv4("203.0.113.42") && !publicIPv4("10.0.0.1"), "public vs private ipv4");

/* a constructed valid Aadhaar (correct Verhoeff digit) is detected */
let validAadhaar;
for (let c = 0; c < 10; c++) { const cand = "23412341234" + c; if (aadhaarValid(cand)) { validAadhaar = cand; break; } }
ok(validAadhaar && has(scanText(`{"uid":"${validAadhaar}"}`), "aadhaar"), "valid Aadhaar detected");

/* ── expanded value detectors ─────────────────────── */
const adv = scanText(JSON.stringify({
  a: "ABC1234567",                                  // voter id (EPIC)
  b: "HDFC0001234",                                 // IFSC
  c: "490154203237518",                             // IMEI (15-digit Luhn)
  d: "12-3456789",                                  // EIN tax id
  e: "550e8400-e29b-41d4-a716-446655440000",         // UUID
  f: "see https://twitter.com/asharao for updates",  // social profile URL
  g: "P1234567",                                    // passport
  h: "021000021",                                   // ABA routing
}));
for (const t of ["voter_id", "ifsc", "imei", "tax_id", "uuid", "social_profile", "passport", "routing_number"]) ok(has(adv, t), `detects ${t}`);
ok(!has(adv, "credit_card"), "15-digit IMEI not mis-flagged as a card");

/* ── word-based PII via field-name hints ──────────── */
const sens = scanText(JSON.stringify({
  religion: "Hindu", ethnicity: "Asian", political_view: "left",
  health: { diagnosis: "Type 2 diabetes" }, face_data: "<blob>",
  sessionId: "abc123def456", cvv: "123", gender: "female", deviceId: "GAID-xyz",
}));
for (const t of ["religion", "ethnicity", "political", "health_data", "biometric", "session_token", "cvv", "gender", "device_id"]) ok(has(sens, t), `field-hint ${t}`);

/* ── CI gate ──────────────────────────────────────── */
ok(failsAt(r, "high"), "fails at high");
ok(!failsAt(scanText('{"ok":true,"count":5}'), "high"), "clean payload passes");

console.log(`✓ all ${pass} scan assertions passed`);
