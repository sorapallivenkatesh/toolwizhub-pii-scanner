/* main.js — wire the scanner UI. All detection runs locally in the browser. */

import { scanText } from "./core/scan.js";
import { renderReport, renderError } from "./ui/render.js";
import { playSplash } from "./ui/splash.js";

const input = document.getElementById("pii-input");
const btn = document.getElementById("scan-btn");
const results = document.getElementById("results");

const SAMPLES = {
  json: JSON.stringify({
    user: { id: "u_8821", full_name: "Asha Rao", phone: "+91 9876543210", email: "asha@example.com" },
    session: { ip: "203.0.113.42", token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1Xzg4MjEifQ.7xK2pQwErT1aZ9bC3dEf" },
    meta: { lat_lng: "12.9716,77.5946", masked_card: "•••• •••• •••• 4242" },
  }, null, 2),
  logs: [
    "2026-06-15T10:22:01Z INFO  checkout user=raj@corp.com card=4111 1111 1111 1111 status=ok",
    "2026-06-15T10:22:03Z DEBUG geo ip=198.51.100.7 lat_lng=19.0760,72.8777",
    "2026-06-15T10:22:05Z INFO  otp sent to +91 9123456780",
  ].join("\n"),
};

function scan() {
  const text = input.value.trim();
  results.hidden = false;
  if (!text) {
    results.replaceChildren(renderError("Paste a JSON response or some log lines first."));
    return;
  }
  try {
    results.replaceChildren(renderReport(scanText(text)));
  } catch (e) {
    results.replaceChildren(renderError(e.message));
  }
}

btn.addEventListener("click", scan);
input.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); scan(); }
});
document.querySelectorAll("[data-sample]").forEach((b) =>
  b.addEventListener("click", () => { input.value = SAMPLES[b.dataset.sample]; scan(); })
);

playSplash();
