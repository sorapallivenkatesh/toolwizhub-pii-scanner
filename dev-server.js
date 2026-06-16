/* dev-server.js — static server with live-reload, Node built-ins only (no deps).
   Serves the repo root and reloads the browser over Server-Sent Events whenever
   a file changes. Dev-only: production is plain static files on Cloudflare Pages.
   Run: npm run site   (PORT=xxxx to override) */

import http from "node:http";
import { readFile, stat } from "node:fs/promises";
import { watch } from "node:fs";
import { extname, join, normalize, sep } from "node:path";

const ROOT = process.cwd();
const PORT = Number(process.env.PORT) || 8080;
const IGNORE = /(?:^|[\\/])(?:\.git|node_modules|\.wrangler|\.claude)(?:[\\/]|$)/;

const MIME = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8",
  ".webp": "image/webp", ".png": "image/png", ".jpg": "image/jpeg", ".svg": "image/svg+xml",
  ".ico": "image/x-icon", ".txt": "text/plain; charset=utf-8", ".map": "application/json",
  ".woff2": "font/woff2", ".xml": "application/xml",
};

// injected into every HTML page; reconnects automatically if the server restarts
const RELOAD_SNIPPET = `
<script>(() => { const es = new EventSource("/__reload");
  es.onmessage = () => location.reload(); es.onerror = () => {}; })();</script>`;

const clients = new Set();
function notifyReload() { for (const res of clients) res.write("data: reload\n\n"); }

const server = http.createServer(async (req, res) => {
  const url = decodeURIComponent((req.url || "/").split("?")[0]);

  if (url === "/__reload") { // SSE channel
    res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });
    res.write("retry: 1000\n\n");
    clients.add(res);
    req.on("close", () => clients.delete(res));
    return;
  }

  // resolve path, block traversal outside ROOT
  let path = normalize(join(ROOT, url));
  if (path !== ROOT && !path.startsWith(ROOT + sep)) { res.writeHead(403).end("Forbidden"); return; }
  try {
    if ((await stat(path)).isDirectory()) path = join(path, "index.html");
  } catch { /* fall through to read error */ }

  try {
    let body = await readFile(path);
    const type = MIME[extname(path).toLowerCase()] || "application/octet-stream";
    if (type.startsWith("text/html")) {
      const html = body.toString("utf8");
      body = html.includes("</body>") ? html.replace("</body>", RELOAD_SNIPPET + "\n</body>") : html + RELOAD_SNIPPET;
    }
    res.writeHead(200, { "Content-Type": type, "Cache-Control": "no-store" });
    res.end(body);
  } catch {
    res.writeHead(404, { "Content-Type": "text/html; charset=utf-8" });
    res.end(`<h1>404</h1><p>${url}</p>` + RELOAD_SNIPPET);
  }
});

// coalesce bursts of fs events into one reload
let timer = null;
watch(ROOT, { recursive: true }, (_evt, file) => {
  if (file && IGNORE.test(file)) return;
  clearTimeout(timer);
  timer = setTimeout(() => { console.log(`↻ reload (${file || "change"})`); notifyReload(); }, 120);
});

server.listen(PORT, () => console.log(`▶ dev server (live reload) → http://localhost:${PORT}`));
