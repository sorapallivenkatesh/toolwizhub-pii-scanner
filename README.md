# 🕵️ ToolWizHub — PII Exposure Scanner

Paste an API response or log sample and flag **unmasked PII** — phone numbers, emails,
precise location, cards, IDs, tokens — with **DPDP/GDPR severity** and **masking fixes**.
A ToolWizHub tool for **pii.toolwizhub.com**.

```
user.phone        phone_number       high      → +91XXXXXXXX10   (DPDP, GDPR)
meta.lat_lng      precise_location   high      → 12.X,77.X       (DPDP, GDPR)
session.token     jwt_token          critical  → eyJhbGci…       (DPDP, GDPR)
meta.masked_card  —                  masked ✓
```

## Runs in your browser

For a tool whose job is finding sensitive data, that data must **not** leave your machine.
All regex/heuristic detection runs **100% client-side** — nothing is uploaded. The same engine
also powers a **CI CLI** so you can fail builds on unmasked PII.

> The optional **AI hybrid** pass (catching what regex misses) is **Phase 2** and is opt-in,
> because it necessarily sends text to an LLM — the opposite of the default privacy stance.

## What it detects

- **Patterns:** email, phone, precise location (lat/lng), credit card (Luhn-checked), IPv4,
  Aadhaar, PAN, US SSN, JWT/bearer tokens, API keys/secrets.
- **Field-name hints:** catches `name`, `address`, `dob`, `password`, etc. the value regex can't.
- **Masked-value awareness:** values like `+91 98XXXXXX21` or `•••• 4242` are recognized as
  already masked (not flagged as exposures).
- **Severity + regulation mapping:** each type → `low|medium|high|critical` and the regimes it
  implicates (DPDP, GDPR, PCI-DSS).
- **Masking suggestions:** a masked example per finding + copy-ready **TypeScript** snippets.

## Architecture

```
site/                 static frontend → Cloudflare Pages (brand + splash, dark glass theme)
  index.html, css/, assets/
  js/main.js          paste → scan → render (no network)
  js/ui/{render,splash}.js
  js/core/            PURE engine — shared with the CLI
    rules.js          detectors, severity, regulation map, masking + TS snippets
    scan.js           parse JSON / log lines → field-pathed findings + suggested masking
cli/pii-scan.js       CI mode — scan files/stdin, exit 1 on unmasked PII
tests/scan.test.js    offline engine tests
package.json          type:module · bin: pii-scan
```

## Run locally

```bash
npm test                      # engine unit tests
npm run site                  # serve the UI → http://localhost:8080
npm run api -- sample.json    # run the scanner CLI on a file
```

## CI mode

Fail a build when logs/responses contain unmasked PII:

```bash
cat dist/**/*.log | node cli/pii-scan.js --threshold=high
# or against fixtures:
node cli/pii-scan.js fixtures/*.json --json
```

Exit code is `1` if any unmasked finding is at/above the threshold (default `high`), else `0`.

GitHub Actions:

```yaml
- run: cat logs/*.log | node cli/pii-scan.js --threshold=high
```

## Deploy

- **Frontend** → Cloudflare Pages. Build command: *(empty)*, output dir: `site`. Domain
  `pii.toolwizhub.com`.
- **CLI** → run via `node cli/pii-scan.js` (or publish to npm as `pii-scan`).

## Roadmap

1. ✅ **MVP** — client-side regex/heuristic scanner + masking + severity + CI CLI *(this)*
2. **AI hybrid** (opt-in) — a backend pass to catch regex misses (names/addresses in free text)
3. More detectors (passport, IBAN, IMEI), custom rules, allowlist/ignore config
4. Inline "apply masking" + export a masked copy of the payload
