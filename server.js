// server.js
// Simple Admin-approved HWID key server

const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public"))); // serve admin UI files

// CONFIG - set via environment in production
const PORT = process.env.PORT; // remove the fallback 3000/8080
const SECRET = process.env.SECRET || "b4f19c8e6d2a4f7e9d3b2a7f0c8d5e6f4b1a2c3d6e7f8a90b1c2d3e4f5a6b7c";
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "9f7e6b8c4a2d1f3e5b6c7d8a0f1e2c3b4d5a6f7b8c9e0d1f2a3b4c5d6e7f8a9";
const DATA_FILE = path.join(__dirname, "data.json");

// DB init (simple JSON persistence)
let DB = { requests: [], issued: {} };
if (fs.existsSync(DATA_FILE)) {
  try {
    DB = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  } catch (e) {
    console.error("Failed to read data.json; starting fresh.", e);
  }
}
function saveDB() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(DB, null, 2));
}

// Helpers
function hmacFor(hwid) {
  return crypto.createHmac("sha256", SECRET).update(hwid).digest("hex");
}
function makeKeyFromHmac(hmac) {
  const short = hmac.slice(0, 20).toUpperCase();
  return short.match(/.{1,4}/g).join("-");
}

// ========== PUBLIC ENDPOINTS ==========
// Root route
app.get("/", (req, res) => {
  res.send("HWID server is running! Visit /ping to check status.");
});

// Client requests a key
app.post("/request", (req, res) => {
  const { hwid, userid, username, note } = req.body;
  if (!hwid) return res.status(400).json({ status: "error", message: "missing hwid" });

  const id = Date.now().toString(36) + "-" + crypto.randomBytes(3).toString("hex");
  const reqEntry = { id, hwid: String(hwid), userid, username, note, ts: Date.now(), status: "pending" };
  DB.requests.push(reqEntry);
  saveDB();
  res.json({ status: "ok", message: "request stored", requestId: id });
});

// Verify a key (client provides key + hwid)
app.post("/verify", (req, res) => {
  const { key, hwid } = req.body;
  if (!key || !hwid) return res.status(400).json({ status: "error", message: "missing fields" });

  const expected = makeKeyFromHmac(hmacFor(String(hwid)));
  if (key.replace(/\s+/g, "").toUpperCase() === expected.replace(/\s+/g, "").toUpperCase()) {
    res.json({ status: "ok", message: "valid" });
  } else {
    res.json({ status: "error", message: "invalid" });
  }
});

// ========== ADMIN API ==========
function isAdmin(req) {
  const token = req.get("x-admin-token");
  return token && token === ADMIN_TOKEN;
}

app.get("/admin/requests", (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ status: "error", message: "unauthorized" });
  res.json({ status: "ok", requests: DB.requests, issued: DB.issued });
});

app.post("/admin/generate", (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ status: "error", message: "unauthorized" });
  const { hwid, requestId } = req.body;
  if (!hwid) return res.status(400).json({ status: "error", message: "missing hwid" });

  const sig = hmacFor(String(hwid));
  const key = makeKeyFromHmac(sig);

  DB.issued[key] = { hwid: String(hwid), issuedAt: Date.now(), requestId: requestId || null };
  if (requestId) {
    const r = DB.requests.find(x => x.id === requestId);
    if (r) r.status = "issued";
  }
  saveDB();
  res.json({ status: "ok", key });
});

app.post("/admin/revoke", (req, res) => {
  if (!isAdmin(req)) return res.status(401).json({ status: "error", message: "unauthorized" });
  const { key } = req.body;
  if (!key) return res.status(400).json({ status: "error", message: "missing key" });
  if (DB.issued[key]) {
    DB.issued[key].revoked = true;
    DB.issued[key].revokedAt = Date.now();
    saveDB();
    res.json({ status: "ok", message: "revoked" });
  } else {
    res.status(404).json({ status: "error", message: "key not found" });
  }
});

// Basic ping
app.get("/ping", (req, res) => res.json({ status: "ok", time: Date.now() }));

// Serve admin UI
app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Start server
app.listen(PORT, () => console.log(`HWID server listening on port ${PORT} (PID ${process.pid})`));
