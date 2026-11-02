// Serve the mempool frontend's production build with SPA fallback, proxying
// /api and its websocket to the backend. `ng serve` would do the same with far
// more memory. Bare node 22, no packages.
//
//   node serve.mjs <dist dir> <port> <backend port>
import http from "node:http";
import net from "node:net";
import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve(process.argv[2]);
const PORT = Number(process.argv[3] ?? 4200);
const BACKEND = { host: "127.0.0.1", port: Number(process.argv[4] ?? 8999) };

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".mjs": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".webmanifest": "application/manifest+json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".gif": "image/gif",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
  ".txt": "text/plain; charset=utf-8",
  ".map": "application/json; charset=utf-8",
};

function send(res, status, body, type) {
  res.writeHead(status, {
    "Content-Type": type,
    "Content-Length": body.length,
  });
  res.end(body);
}

function proxy(req, res) {
  const upstream = http.request(
    {
      ...BACKEND,
      method: req.method,
      path: req.url,
      headers: { ...req.headers, host: `${BACKEND.host}:${BACKEND.port}` },
    },
    (upRes) => {
      res.writeHead(upRes.statusCode ?? 502, upRes.headers);
      upRes.pipe(res);
    },
  );
  upstream.on("error", (e) =>
    send(res, 502, Buffer.from(String(e)), "text/plain"),
  );
  req.pipe(upstream);
}

const server = http.createServer((req, res) => {
  const { pathname } = new URL(req.url, "http://localhost");
  if (pathname.startsWith("/api")) return proxy(req, res);

  const file = path.join(ROOT, path.normalize(decodeURIComponent(pathname)));
  if (!file.startsWith(ROOT))
    return send(res, 403, Buffer.from("no"), "text/plain");
  fs.readFile(file, (err, body) => {
    if (!err)
      return send(
        res,
        200,
        body,
        TYPES[path.extname(file)] ?? "application/octet-stream",
      );
    // Angular routes such as /tx/<txid> are not files on disk.
    fs.readFile(path.join(ROOT, "index.html"), (e, index) =>
      e
        ? send(res, 404, Buffer.from("not found"), "text/plain")
        : send(res, 200, index, TYPES[".html"]),
    );
  });
});

// The frontend opens a websocket at /api/v1/ws for live updates.
server.on("upgrade", (req, socket, head) => {
  const upstream = net.connect(BACKEND.port, BACKEND.host, () => {
    const headers = Object.entries(req.headers).map(([k, v]) => `${k}: ${v}`);
    upstream.write(
      `${req.method} ${req.url} HTTP/1.1\r\n${headers.join("\r\n")}\r\n\r\n`,
    );
    if (head?.length) upstream.write(head);
    upstream.pipe(socket);
    socket.pipe(upstream);
  });
  upstream.on("error", () => socket.destroy());
  socket.on("error", () => upstream.destroy());
});

server.listen(PORT, "127.0.0.1", () =>
  console.log(`serving ${ROOT} on http://127.0.0.1:${PORT}`),
);
