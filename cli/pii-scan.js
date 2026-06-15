#!/usr/bin/env node
/* CI mode for the PII Exposure Scanner.
   Scans files (or stdin) and exits non-zero if unmasked PII at/above a
   severity threshold is found — drop it into a pipeline to fail builds.

   Usage:
     pii-scan response.json logs.txt          # human report
     cat app.log | pii-scan                    # from stdin
     pii-scan --json --threshold=critical *.log
*/
import { readFileSync } from "node:fs";
import { scanText, failsAt } from "../site/js/core/scan.js";

const C = process.stdout.isTTY
  ? { red: "\x1b[31m", yel: "\x1b[33m", grn: "\x1b[32m", dim: "\x1b[2m", bold: "\x1b[1m", off: "\x1b[0m" }
  : { red: "", yel: "", grn: "", dim: "", bold: "", off: "" };
const SEV_COLOR = { critical: C.red, high: C.red, medium: C.yel, low: C.dim };

const args = process.argv.slice(2);
const opts = { json: false, threshold: "high", files: [] };
for (const a of args) {
  if (a === "--json") opts.json = true;
  else if (a.startsWith("--threshold=")) opts.threshold = a.split("=")[1];
  else if (a === "-h" || a === "--help") { help(); process.exit(0); }
  else opts.files.push(a);
}

function help() {
  console.log(`pii-scan — fail builds on unmasked PII

  pii-scan [files...] [--json] [--threshold=critical|high|medium|low]

  Reads the given files (or stdin). Exits 1 if unmasked PII at/above the
  threshold (default: high) is found, else 0.`);
}

let text;
try {
  text = opts.files.length
    ? opts.files.map((f) => readFileSync(f, "utf8")).join("\n")
    : readFileSync(0, "utf8");
} catch (e) {
  console.error(`pii-scan: ${e.message}`);
  process.exit(2);
}

const result = scanText(text);

if (opts.json) {
  console.log(JSON.stringify(result, null, 2));
} else {
  const s = result.summary;
  console.log(`${C.bold}PII scan${C.off} — ${result.format}, ${s.total} finding(s), ${s.unmasked} unmasked`);
  for (const f of result.findings) {
    const tag = f.masked ? `${C.grn}[masked]${C.off}` : `${SEV_COLOR[f.severity] || ""}[${f.severity}]${C.off}`;
    const fix = f.suggested_masking ? ` ${C.dim}→ ${f.suggested_masking}${C.off}` : "";
    console.log(`  ${tag} ${f.field}  ${C.dim}${f.type} (${f.regulations.join(", ")})${C.off}${fix}`);
  }
}

const failed = failsAt(result, opts.threshold);
if (!opts.json) {
  console.log(failed
    ? `${C.red}✗ unmasked PII at/above ${opts.threshold} — failing.${C.off}`
    : `${C.grn}✓ no unmasked PII at/above ${opts.threshold}.${C.off}`);
}
process.exit(failed ? 1 : 0);
