# 🕵️ ToolWizHub — PII Exposure Scanner

Paste an API response, **fetch a URL**, or **drop a file** and flag **unmasked PII** —
phone numbers, emails, precise location, cards, IDs, tokens — with **DPDP/GDPR severity**,
**masking fixes**, and **shareable reports**. A ToolWizHub tool for **pii.toolwizhub.com**.

```
user.phone        phone_number       high      → +91XXXXXXXX10   (DPDP, GDPR)
meta.lat_lng      precise_location   high      → 12.X,77.X       (DPDP, GDPR)
session.token     jwt_token          critical  → eyJhbGci…       (DPDP, GDPR)
meta.masked_card  —                  masked ✓
```

## Runs entirely in your browser

For a tool whose job is finding sensitive data, that data must **not** leave your machine.
All detection runs **100% client-side** — nothing is uploaded, no backend, no tracking.
(Even "From URL" fetches in your browser and scans the response locally.)

## Input

Three ways in, all scanned locally:

- **Paste** — JSON, NDJSON, or raw log lines (you can also drag-drop a file onto the box).
- **From URL** — fetch a response in your browser and scan it (cross-origin needs CORS).
- **Upload** — drop or pick a `.json` / `.ndjson` / `.log` / `.txt` file.

Formats handled: **JSON** (walked to field paths), **NDJSON** (per-line field paths), and
**key=value / freeform logs**.

## What it detects (value-first)

Keys are arbitrary, so detection is driven by **value patterns + checksums**; field names are
only a secondary hint.

- **Patterns:** email, phone, precise location (lat/lng), credit card (Luhn + network length),
  IBAN, UPI, Aadhaar (Verhoeff), PAN, voter ID, passport, US SSN, EIN, IFSC, ABA routing,
  IMEI, MAC, public IPv4/IPv6, UUID, JWT/bearer tokens, API keys, social-profile URLs.
- **Field-name hints** (word-based PII with no pattern): name, address, DOB, gender, age,
  job/salary, religion, ethnicity, political view, health, biometric, sexual orientation,
  password, session/cookie, device id, CVV, etc.
- **Custom rules:** add your own regex + severity (saved in your browser).
- **Masked-value awareness:** `+91 98XXXXXX21`, `•••• 4242` recognised as already masked.
- **Severity + regulation mapping:** `low | medium | high | critical` × DPDP / GDPR / PCI-DSS.

## Working with findings

- **Card-grid report** — each finding as a compact card: severity, type, field path,
  `raw → masked` example, and the regulations it implicates.
- **Inline highlighting** — your input echoed back with every match marked, coloured by severity.
- **Masked copy** — one click produces a fully redacted copy of the payload, ready to copy.
- **Ignore / allowlist** — dismiss a finding or whitelist a whole type; ignored items move to an
  "Ignored" section with a ↺ restore (persists in `localStorage`).
- **Export** — download the report as JSON or Markdown.
- **Share** — copy a link that encodes a **PII-masked** report (no raw values travel); opening it
  shows a read-only view for your team.
- **Masking snippets** — copy-ready **TypeScript** helpers per type.

## Architecture

Static site (no backend) — files live at the repo root, deployed to Cloudflare Pages.
Full-width, dark-glass theme.

```
index.html              markup + brand + splash
css/styles.css          dark glass theme, full-width layout, card grid
assets/                 ToolWizHub WebP brand
js/main.js              wiring: input modes, scan → render, ignore / share / export (no network)
js/ui/{render,splash}.js
js/core/                PURE engine — no DOM, no I/O
  rules.js              detectors, checksum validators, severity/regulation map, masking + snippets
  scan.js               parse JSON / NDJSON / logs → field-pathed findings, masked copy, failsAt()
  share.js              encode/decode a sanitised (PII-masked) report for share links
dev-server.js           dev-only: static serve + live reload (Node built-ins, no deps)
tests/scan.test.js      offline engine tests
package.json            type:module
```

## Run locally

```bash
npm test        # engine unit tests
npm run site    # live-reload dev server → http://localhost:8080 (auto-refresh on save)
npm run serve   # plain python static server (no reload)
```

## Deploy

Cloudflare Pages — Build command: *(empty)*, output dir: `/` (root). Custom domain
`pii.toolwizhub.com`.

## CI use (engine helper)

The engine exports `failsAt(result, "high")` — `true` if any unmasked finding is at or above a
severity. Useful if you wrap the engine in a CLI to gate a pipeline (fail the build on exposed
PII). The browser UI itself is detection-only.

## Roadmap

1. ✅ Client-side scanner — value-based detection, severity, masking suggestions
2. ✅ Custom rules + ignore / allowlist
3. ✅ Masked copy, inline highlighting, export, share links, URL / file input
4. *(optional)* AI-assisted pass for free-text names/addresses — only with explicit opt-in,
   since it would send data to an LLM (against the default privacy stance)
