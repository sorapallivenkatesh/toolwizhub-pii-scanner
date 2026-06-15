/* Offline tests for the scan engine. Run: npm test */
import assert from "node:assert";
import { scanText, failsAt } from "../site/js/core/scan.js";

const byType = (r, t) => r.findings.find((f) => f.type === t);

/* ── JSON: field paths, types, masked flag ────────── */
const json = JSON.stringify({
  user: { phone: "+91 9876543210", email: "asha@example.com", full_name: "Asha Rao" },
  meta: { lat_lng: "12.9716,77.5946", masked_phone: "+91 98XXXXXX21" },
  card: "4111 1111 1111 1111",
});
const r = scanText(json);

assert.equal(r.format, "json");
assert.ok(byType(r, "phone_number"), "detects phone");
assert.equal(byType(r, "phone_number").field, "user.phone");
assert.equal(byType(r, "phone_number").masked, false);
assert.ok(byType(r, "email"), "detects email");
assert.ok(byType(r, "precise_location"), "detects lat_lng via field name");
assert.ok(byType(r, "name"), "detects name via field name");
assert.equal(byType(r, "credit_card").severity, "critical");
assert.ok(r.suggested_masking, "offers a masking suggestion");

// the already-masked phone should be flagged masked:true, not counted as unmasked
const maskedOne = r.findings.find((f) => f.field === "meta.masked_phone");
assert.ok(maskedOne && maskedOne.masked === true, "recognizes an already-masked value");

/* ── logs: line-based detection ───────────────────── */
const logs = scanText("2026-06-15 INFO login user=bob@corp.com ip=203.0.113.9 ok\nplain line");
assert.equal(logs.format, "logs");
assert.ok(byType(logs, "email"), "email in log line");
assert.equal(byType(logs, "email").field, "line 1");
assert.ok(byType(logs, "ip_address"), "ip in log line");

/* ── CI gate ──────────────────────────────────────── */
assert.equal(failsAt(r, "high"), true, "fails at high (phone/card present)");
assert.equal(failsAt(scanText('{"ok":true,"count":5}'), "high"), false, "clean payload passes");

console.log("✓ all scan tests passed");
