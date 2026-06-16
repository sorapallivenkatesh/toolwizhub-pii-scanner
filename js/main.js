/* main.js — wire the scanner UI. All detection runs locally in the browser. */

import { scanText, maskText } from "./core/scan.js";
import { encodeReport, decodeReport } from "./core/share.js";
import { renderReport, renderError } from "./ui/render.js";
import { playSplash } from "./ui/splash.js";

const input = document.getElementById("pii-input");
const btn = document.getElementById("scan-btn");
const results = document.getElementById("results");
const drop = document.getElementById("dropzone");

/* ── persisted state ──────────────────────────────── */
const LS_RULES = "pii:customRules";
const LS_IGNORE = "pii:ignore";
const load = (k, fallback) => { try { return JSON.parse(localStorage.getItem(k)) ?? fallback; } catch { return fallback; } };
const save = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* private mode */ } };

let customRules = load(LS_RULES, []);
let ignore = new Set(load(LS_IGNORE, []));

const sigOne = (f) => `one:${f.type}|${f.field}|${f.sample}`;
const isIgnored = (f) => ignore.has(`type:${f.type}`) || ignore.has(sigOne(f));
const persistIgnore = () => save(LS_IGNORE, [...ignore]);

const SAMPLES = {
  json: JSON.stringify({
    user: { id: "u_8821", full_name: "Asha Rao", phone: "+91 9876543210", email: "asha@example.com" },
    session: { ip: "203.0.113.42", token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1Xzg4MjEifQ.7xK2pQwErT1aZ9bC3dEf" },
    meta: { lat_lng: "12.9716,77.5946", masked_card: "•••• •••• •••• 4242" },
  }, null, 2),
  logs: [
    "2026-06-16T10:22:01Z INFO  checkout user=raj@corp.com card=4111 1111 1111 1111 status=ok",
    "2026-06-16T10:22:03Z DEBUG geo ip=198.51.100.7 lat_lng=19.0760,72.8777",
    "2026-06-16T10:22:05Z INFO  otp sent to +91 9123456780",
  ].join("\n"),
};

/* ── exports (download report) ────────────────────── */
function download(name, text, mime) {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function toMarkdown(result) {
  const lines = [
    `# PII Exposure Report`, "",
    `- Format: \`${result.format}\``,
    `- Status: **${result.summary.status}** — ${result.summary.unmasked} unmasked, ${result.summary.masked} masked`, "",
    `| Field | Type | Severity | Regulations | Masked? | Suggested |`,
    `|---|---|---|---|---|---|`,
    ...result.findings.map((f) =>
      `| \`${f.field}\` | ${f.label} | ${f.severity} | ${f.regulations.join(", ")} | ${f.masked ? "yes" : "no"} | ${f.suggested_masking ? "`" + f.suggested_masking + "`" : "—"} |`),
  ];
  return lines.join("\n") + "\n";
}

/* ── scan + render ────────────────────────────────── */
function scan() {
  const text = input.value.trim();
  results.hidden = false;
  if (!text) {
    results.replaceChildren(renderError("Paste a JSON response or some log lines first."));
    return;
  }
  try {
    const result = scanText(text, { customRules });
    const masked = maskText(text, { customRules });
    results.replaceChildren(renderReport(result, {
      rawInput: text,
      masked,
      isIgnored,
      onDismiss: (f) => { ignore.add(sigOne(f)); persistIgnore(); rescan(); },
      onAllowType: (f) => { ignore.add(`type:${f.type}`); persistIgnore(); rescan(); },
      onRestore: (f) => { ignore.delete(sigOne(f)); ignore.delete(`type:${f.type}`); persistIgnore(); rescan(); },
      onResetIgnores: () => { ignore.clear(); persistIgnore(); rescan(); },
      onExport: (fmt) => fmt === "md"
        ? download("pii-report.md", toMarkdown(result), "text/markdown")
        : download("pii-report.json", JSON.stringify(result, null, 2), "application/json"),
      buildShareLink: () => {
        // carry ignored findings too (flagged), so the team sees what was dismissed
        const shared = { ...result, findings: result.findings.map((f) => ({ ...f, ignored: isIgnored(f) })) };
        return `${location.origin}${location.pathname}#report=${encodeReport(shared)}`;
      },
    }));
  } catch (e) {
    results.replaceChildren(renderError(e.message));
  }
}

/* re-render after ignore/allowlist changes without the page jumping —
   a shorter report would otherwise let the browser clamp scroll upward */
function rescan() {
  const y = window.scrollY;
  scan();
  window.scrollTo({ top: y });
}

/* ── custom rules panel ───────────────────────────── */
const ruleLabel = document.getElementById("rule-label");
const rulePattern = document.getElementById("rule-pattern");
const ruleSev = document.getElementById("rule-sev");
const ruleAdd = document.getElementById("rule-add");
const ruleList = document.getElementById("rule-list");
const ruleErr = document.getElementById("rule-err");

function renderRules() {
  ruleList.replaceChildren();
  customRules.forEach((r, i) => {
    const li = document.createElement("li");
    li.className = "rule";
    const meta = document.createElement("span");
    meta.className = "rule__meta";
    const name = document.createElement("strong"); name.textContent = r.label;
    const pat = document.createElement("code"); pat.textContent = r.pattern;
    const sev = document.createElement("span"); sev.className = `rule__sev rule__sev--${r.severity}`; sev.textContent = r.severity;
    meta.append(name, pat, sev);
    const del = document.createElement("button"); del.type = "button"; del.className = "mini mini--x"; del.textContent = "✕"; del.title = "Remove rule";
    del.addEventListener("click", () => { customRules.splice(i, 1); save(LS_RULES, customRules); renderRules(); if (!results.hidden) scan(); });
    li.append(meta, del);
    ruleList.append(li);
  });
}

function addRule() {
  ruleErr.textContent = "";
  const label = ruleLabel.value.trim();
  const pattern = rulePattern.value.trim();
  if (!label || !pattern) { ruleErr.textContent = "Both a name and a regex are required."; return; }
  try { new RegExp(pattern); } catch (e) { ruleErr.textContent = "Invalid regex: " + e.message; return; }
  customRules.push({ label, pattern, severity: ruleSev.value });
  save(LS_RULES, customRules);
  ruleLabel.value = ""; rulePattern.value = "";
  renderRules();
  if (!results.hidden) scan();
}

ruleAdd.addEventListener("click", addRule);
rulePattern.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); addRule(); } });
renderRules();

/* ── input mode tabs (Paste / From URL / Upload) ──── */
const tabs = [...document.querySelectorAll(".tab")];
const panes = [...document.querySelectorAll(".pane")];
const urlInput = document.getElementById("url-input");
const urlFetch = document.getElementById("url-fetch");
const urlNote = document.getElementById("url-note");
const DEFAULT_NOTE = urlNote.textContent;

function setMode(mode) {
  tabs.forEach((t) => t.classList.toggle("is-active", t.dataset.mode === mode));
  panes.forEach((p) => { p.hidden = p.dataset.pane !== mode; });
  (mode === "url" ? urlInput : mode === "paste" ? input : null)?.focus();
}
tabs.forEach((t) => t.addEventListener("click", () => setMode(t.dataset.mode)));

/* ── URL fetch — runs in the browser, response scanned locally ── */
async function fetchUrl() {
  const raw = urlInput.value.trim();
  const fail = (msg) => { urlNote.textContent = msg; urlNote.classList.add("url-note--err"); };
  urlNote.classList.remove("url-note--err");
  if (!raw) return fail("Enter a URL first.");
  let u;
  try { u = new URL(raw); } catch { return fail("That doesn't look like a valid URL."); }
  if (!/^https?:$/.test(u.protocol)) return fail("Only http(s) URLs are supported.");

  urlFetch.disabled = true; urlFetch.textContent = "Fetching…";
  try {
    const res = await fetch(raw, { redirect: "follow" });
    input.value = await res.text();
    urlNote.textContent = DEFAULT_NOTE;
    setMode("paste");
    scan();
  } catch (e) {
    fail("Couldn't fetch that URL — usually CORS (the server must allow cross-origin reads). " + (e.message || ""));
  } finally {
    urlFetch.disabled = false; urlFetch.textContent = "Fetch & scan";
  }
}
urlFetch.addEventListener("click", fetchUrl);
urlInput.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); fetchUrl(); } });

/* ── file drop / read ─────────────────────────────── */
function readFile(file) {
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => { input.value = String(reader.result); setMode("paste"); scan(); };
  reader.readAsText(file);
}
function wireDrop(zone) {
  if (!zone) return;
  ["dragenter", "dragover"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add("is-drag"); }));
  ["dragleave", "drop"].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); if (ev === "dragleave" && zone.contains(e.relatedTarget)) return; zone.classList.remove("is-drag"); }));
  zone.addEventListener("drop", (e) => { const f = e.dataTransfer?.files?.[0]; if (f) readFile(f); });
}
wireDrop(drop);
wireDrop(document.getElementById("filedrop"));
document.getElementById("file-input").addEventListener("change", (e) => readFile(e.target.files[0]));

/* ── chrome wiring ────────────────────────────────── */
btn.addEventListener("click", scan);
input.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); scan(); }
});
document.querySelectorAll("[data-sample]").forEach((b) =>
  b.addEventListener("click", () => { input.value = SAMPLES[b.dataset.sample]; setMode("paste"); scan(); })
);

/* ── shared report view (opened from a #report= link) ── */
function maybeRenderShared() {
  if (!location.hash.startsWith("#report=")) return;
  const decoded = decodeReport(location.hash.slice("#report=".length));
  if (!decoded) return;
  results.hidden = false;
  results.replaceChildren(renderReport(decoded, { shared: true }));
  const banner = document.createElement("div");
  banner.className = "shared-note";
  banner.append(Object.assign(document.createElement("span"), { textContent: "📤 Shared report — PII values are masked. Read-only." }));
  const own = document.createElement("button");
  own.type = "button"; own.className = "ghost"; own.textContent = "Scan your own →";
  own.addEventListener("click", () => { history.replaceState(null, "", location.pathname); results.hidden = true; setMode("paste"); input.focus(); });
  banner.append(own);
  results.prepend(banner);
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}
maybeRenderShared();

playSplash();
