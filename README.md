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

## Runs entirely in your browser

For a tool whose job is finding sensitive data, that data must **not** leave your machine.
All detection runs **100% client-side** — nothing is uploaded, no backend, no tracking.

## What it detects (value-first)

Keys are arbitrary, so detection is driven by **value patterns + checksums**; field names are
only a secondary hint.

- **Patterns:** email, phone, precise location (lat/lng), credit card (Luhn + network length),
  IBAN, UPI, Aadhaar (Verhoeff), PAN, voter ID, passport, US SSN, EIN, IFSC, ABA routing,
  IMEI, MAC, public IPv4/IPv6, UUID, JWT/bearer tokens, API keys, social-profile URLs.
- **Field-name hints** (for word-based PII with no pattern): name, address, DOB, gender, age,
  job/salary, religion, ethnicity, political view, health, biometric, sexual orientation,
  password, session/cookie, device id, CVV, etc.
- **Masked-value awareness:** `+91 98XXXXXX21`, `•••• 4242` recognized as already masked.
- **Severity + regulation mapping:** `low|medium|high|critical` × DPDP / GDPR / PCI-DSS.
- **Masking suggestions:** a masked example per finding + copy-ready **TypeScript** snippets.

## Architecture

Static site (no backend) — files live at the repo root, deployed to Cloudflare Pages.

```
index.html            markup + brand + splash
css/styles.css        dark glass theme
assets/               ToolWizHub WebP brand
js/main.js            paste → scan → render (no network)
js/ui/{render,splash}.js
js/core/              PURE engine — no DOM, no I/O
  rules.js            detectors, checksum validators, severity/regulation map, masking + snippets
  scan.js             parse JSON / log lines → field-pathed findings + suggested masking
tests/scan.test.js    offline engine tests
package.json          type:module
```

## Run locally

```bash
npm test       # engine unit tests
npm run site   # serve the UI → http://localhost:8080
```

## Deploy

Cloudflare Pages — Build command: *(empty)*, output dir: `/` (root). Custom domain
`pii.toolwizhub.com`.

## Roadmap

1. ✅ **Client-side scanner** — value-based detection, masking suggestions, DPDP/GDPR severity
2. Custom rules + allowlist / ignore config
3. Inline "apply masking" → export a masked copy of the payload
4. *(optional)* AI-assisted pass for free-text names/addresses — only with explicit opt-in,
   since it would send data to an LLM (against the default privacy stance)
