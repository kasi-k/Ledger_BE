require("dotenv").config();
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { PDFDocument, StandardFonts, rgb } = require("pdf-lib");
const { MongoClient, GridFSBucket, ObjectId } = require("mongodb");

const app = express();
const PORT = process.env.PORT || 4100;
const DATA_FILE = path.join(__dirname, "ledger.json");
const UPLOADS_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// Editing window: the current month is always open; every other month is locked
// unless the admin has explicitly unlocked it. (Defined early — defaults() uses it.)
const EDIT_GRACE_DAY = Number(process.env.EDIT_GRACE_DAY || 5);

// --- Auth config (override with env vars in production) ------------------
const AUTH_USER = process.env.AUTH_USER || "admin";
const AUTH_PASS = process.env.AUTH_PASS || "maarr123";
const EMP_USER = process.env.EMP_USER || "employee";
const EMP_PASS = process.env.EMP_PASS || "employee123";
const AUTH_SECRET = process.env.AUTH_SECRET || "maarr-smart-ledger-secret";

// Users and their roles. admin = full access (download, audit, controls);
// accounts = data entry only (no download, no audit, no controls). The login
// name stays "employee"; the app just shows this role as "Accounts".
const USERS = {
  [AUTH_USER]: { password: AUTH_PASS, role: "admin" },
  [EMP_USER]: { password: EMP_PASS, role: "accounts" },
};

// Stateless token = base64(user).hmac(user). Verified on every request.
function signToken(user) {
  const mac = crypto.createHmac("sha256", AUTH_SECRET).update(user).digest("hex");
  return Buffer.from(user).toString("base64") + "." + mac;
}

function verifyToken(token) {
  if (!token || !token.includes(".")) return null;
  const [b64, mac] = token.split(".");
  let user;
  try {
    user = Buffer.from(b64, "base64").toString("utf-8");
  } catch {
    return null;
  }
  const expected = crypto.createHmac("sha256", AUTH_SECRET).update(user).digest("hex");
  if (mac.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expected))) return null;
  return user;
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  const user = verifyToken(token);
  if (!user || !USERS[user]) return res.status(401).json({ error: "unauthorized" });
  req.user = user;
  req.role = USERS[user].role;
  next();
}

// Admin is read-only for data entry: only non-admin roles (employee) may write.
function blockReadOnly(req, res) {
  if (req.role === "admin") {
    res.status(403).json({ error: "Admin is read-only — data entry is done by employees." });
    return true;
  }
  return false;
}

// Admin-only controls (grace period, month locks, opening balance).
function requireAdmin(req, res) {
  if (req.role !== "admin") {
    res.status(403).json({ error: "Admin only." });
    return true;
  }
  return false;
}

// CORS: restrict to the frontend origin(s) in production (comma-separated in
// CORS_ORIGIN, e.g. "https://maarr-ledger.vercel.app"); open in dev if unset.
const CORS_ORIGINS = (process.env.CORS_ORIGIN || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
app.use(cors(CORS_ORIGINS.length ? { origin: CORS_ORIGINS } : {}));

// Larger limit so base64-encoded invoice images fit in the JSON body.
app.use(express.json({ limit: "15mb" }));

// Health check (public) — used by Render / uptime pings.
app.get("/health", (req, res) => res.json({ ok: true }));

// Invoice files are served publicly by their (random, unguessable) id so that
// <img> tags and PDF viewers can load them without auth headers. Streams from
// GridFS (Atlas) or local disk depending on where the file was saved.
app.get("/uploads/:id", async (req, res) => {
  const rec = findInvoiceRec(req.params.id);
  if (!rec) return res.status(404).end();
  try {
    const bytes = await readInvoiceBytes(rec);
    if (!bytes) return res.status(404).end();
    res.setHeader("Content-Type", rec.mime || "application/octet-stream");
    res.setHeader("Cache-Control", "private, max-age=3600");
    res.send(bytes);
  } catch (err) {
    console.error("Failed to serve invoice:", err.message);
    res.status(500).end();
  }
});

// Public: login. Returns a bearer token on valid credentials.
app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  const u = USERS[username];
  if (u && u.password === password) {
    audit("login", username);
    return res.json({ token: signToken(username), username, role: u.role });
  }
  audit("login_failed", username || "(blank)");
  res.status(401).json({ error: "Invalid username or password" });
});

// Everything under /api below this line requires a valid token.
app.use("/api", requireAuth);

// --- Simple JSON-file persistence ---------------------------------------
// Stored shape: { startingBalance, entries, graceDay, unlockedMonths }
// Also tolerates the older shape where the file was a bare entries array.
function defaults() {
  return {
    startingBalance: 0,
    entries: [],
    graceDay: EDIT_GRACE_DAY,
    unlockedMonths: [],
    claimed: [],
    // Saved snapshots of each claimed statement, for re-download later.
    reports: [],
    // Invoice images attached to entries, keyed by entry signature.
    invoices: {},
  };
}

// Coerce any stored/parsed blob into the canonical shape.
function normalizeData(parsed) {
  if (!parsed || typeof parsed !== "object") return defaults();
  if (Array.isArray(parsed)) return { ...defaults(), entries: parsed };
  return {
    startingBalance: Number(parsed.startingBalance) || 0,
    entries: Array.isArray(parsed.entries) ? parsed.entries : [],
    graceDay: Number(parsed.graceDay) || EDIT_GRACE_DAY,
    unlockedMonths: Array.isArray(parsed.unlockedMonths) ? parsed.unlockedMonths : [],
    claimed: Array.isArray(parsed.claimed) ? parsed.claimed : [],
    reports: Array.isArray(parsed.reports) ? parsed.reports : [],
    invoices:
      parsed.invoices && typeof parsed.invoices === "object" ? parsed.invoices : {},
  };
}

// --- Storage: MongoDB Atlas if MONGODB_URI is set, else the local JSON file ---
// The whole ledger lives in one document. It's cached in memory (so the many
// synchronous readData() calls keep working) and every writeData() persists it.
let cache = defaults();
let mongoColl = null;
let gridfs = null; // GridFS bucket for invoice files (Atlas mode)
let auditColl = null; // audit-log collection (Atlas mode)
let writeChain = Promise.resolve();

function readData() {
  // Deep copy so handlers can mutate freely without corrupting the cache.
  return JSON.parse(JSON.stringify(cache));
}

function writeData(data) {
  cache = data;
  if (mongoColl) {
    writeChain = writeChain
      .then(() =>
        mongoColl.updateOne({ _id: "ledger" }, { $set: { data } }, { upsert: true })
      )
      .catch((err) => console.error("MongoDB write failed:", err.message));
  } else {
    try {
      fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
    } catch (err) {
      console.error("Failed to write ledger file:", err);
    }
  }
}

// Read whatever is in the local JSON file (used as seed / fallback).
function readFileData() {
  try {
    if (!fs.existsSync(DATA_FILE)) return null;
    const raw = fs.readFileSync(DATA_FILE, "utf-8").trim();
    if (!raw) return null;
    return normalizeData(JSON.parse(raw));
  } catch (err) {
    console.error("Failed to read local ledger file:", err);
    return null;
  }
}

// Connect to Atlas (if configured) and load the ledger into the cache. Starts
// fresh (empty ledger) when the Atlas collection has no document yet — the local
// ledger.json is NOT imported. Called once before the server starts.
async function initStorage() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    // No Atlas configured: fall back to the local JSON file.
    cache = readFileData() || defaults();
    console.log("Storage: local ledger.json (set MONGODB_URI to use Atlas).");
    return;
  }
  const client = new MongoClient(uri);
  await client.connect();
  const dbName = process.env.MONGODB_DB || "maarr_ledger";
  const db = client.db(dbName);
  mongoColl = db.collection("ledger");
  gridfs = new GridFSBucket(db, { bucketName: "invoices" });
  auditColl = db.collection("audit");
  const doc = await mongoColl.findOne({ _id: "ledger" });
  if (doc && doc.data) {
    cache = normalizeData(doc.data);
    console.log(`Storage: MongoDB Atlas (db "${dbName}").`);
  } else {
    // Fresh start — empty ledger, persisted so the document exists.
    cache = defaults();
    await mongoColl.updateOne(
      { _id: "ledger" },
      { $set: { data: cache } },
      { upsert: true }
    );
    console.log(`Storage: MongoDB Atlas (db "${dbName}") — fresh empty ledger created.`);
  }
}

// --- Invoice file storage: GridFS in Atlas mode, local disk otherwise --------
// Save bytes; returns a reference merged into the invoice record.
async function saveInvoiceFile(buffer, meta) {
  if (gridfs) {
    const stream = gridfs.openUploadStream(meta.name || "invoice", {
      contentType: meta.mime,
    });
    stream.end(buffer);
    await new Promise((resolve, reject) => {
      stream.on("finish", resolve);
      stream.on("error", reject);
    });
    return { gridfsId: stream.id.toString() };
  }
  const ext = (meta.mime.split("/")[1] || "bin").replace(/[^a-z0-9]/gi, "").slice(0, 5);
  const file = `inv_${crypto.randomBytes(8).toString("hex")}.${ext}`;
  fs.writeFileSync(path.join(UPLOADS_DIR, file), buffer);
  return { file };
}

async function readInvoiceBytes(rec) {
  if (rec.gridfsId && gridfs) {
    const chunks = [];
    const stream = gridfs.openDownloadStream(new ObjectId(rec.gridfsId));
    return await new Promise((resolve, reject) => {
      stream.on("data", (c) => chunks.push(c));
      stream.on("end", () => resolve(Buffer.concat(chunks)));
      stream.on("error", reject);
    });
  }
  if (rec.file) {
    const fpath = path.join(UPLOADS_DIR, rec.file);
    return fs.existsSync(fpath) ? fs.readFileSync(fpath) : null;
  }
  return null;
}

async function deleteInvoiceFile(rec) {
  try {
    if (rec.gridfsId && gridfs) {
      await gridfs.delete(new ObjectId(rec.gridfsId));
    } else if (rec.file) {
      fs.unlinkSync(path.join(UPLOADS_DIR, rec.file));
    }
  } catch {
    /* already gone */
  }
}

// Remove every file in the local uploads folder. Used after a file is stored in
// Atlas (GridFS) so the server's disk never accumulates invoice files.
function purgeUploadsDir() {
  try {
    for (const f of fs.readdirSync(UPLOADS_DIR)) {
      try {
        fs.unlinkSync(path.join(UPLOADS_DIR, f));
      } catch {
        /* ignore */
      }
    }
  } catch {
    /* uploads dir may not exist */
  }
}

// Find an invoice record (with its storage ref) by its public id.
function findInvoiceRec(id) {
  const inv = cache.invoices || {};
  for (const sig of Object.keys(inv)) {
    const found = (inv[sig] || []).find((x) => String(x.id) === String(id));
    if (found) return found;
  }
  return null;
}

// Signature identifying an entry's content (survives id reassignment on save).
function entrySig(e) {
  return `${e.month}|${e.date}|${e.particulars}|${e.debit}|${e.credit}`;
}

// Invoice attachments for an entry, as public {id, name, mime, url} objects.
function invoicesFor(e, data) {
  const list = (data.invoices && data.invoices[entrySig(e)]) || [];
  return list.map((inv) => ({
    id: inv.id,
    name: inv.name,
    mime: inv.mime,
    url: `/uploads/${inv.id}`,
  }));
}

function readEntries() {
  return readData().entries;
}

function nextId(entries) {
  return entries.reduce((max, e) => Math.max(max, e.id), 0) + 1;
}

// Only the current month is open; every other month is locked unless the
// admin has explicitly unlocked it.
function isMonthEditable(month, data) {
  const unlocked = (data && data.unlockedMonths) || [];
  if (unlocked.includes(month)) return true; // admin override
  const now = new Date();
  const cur = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`;
  return month === cur;
}

// Sort chronologically within/across months: by date, then insertion id.
function chronological(a, b) {
  if (a.date !== b.date) return a.date < b.date ? -1 : 1;
  return a.id - b.id;
}

// Build a statement of the PENDING (not-yet-claimed) entries in [from, to].
// The opening balance is the true running balance right BEFORE the first
// pending row (so already-claimed entries inside the range are accounted for
// in the opening rather than silently dropped). Running balance then flows over
// the pending rows, so opening + net(pending) == closing always holds.
function buildStatement(data, from, to) {
  const { startingBalance, entries } = data;
  const claimedSet = new Set(data.claimed || []);
  const isClaimed = (e) => claimedSet.has(entrySig(e));

  const pending = entries
    .filter((e) => e.date >= from && e.date <= to && !isClaimed(e))
    .sort(chronological);

  let opening;
  if (pending.length) {
    // Net of every entry (claimed or not) that comes before the first pending row.
    const first = pending[0];
    opening = entries.reduce(
      (bal, e) => (chronological(e, first) < 0 ? bal + e.credit - e.debit : bal),
      startingBalance
    );
  } else {
    opening = entries
      .filter((e) => e.date < from)
      .reduce((bal, e) => bal + e.credit - e.debit, startingBalance);
  }

  let balance = opening;
  let totalDebit = 0;
  let totalCredit = 0;
  const withBalance = pending.map((e) => {
    balance += e.credit - e.debit;
    totalDebit += e.debit;
    totalCredit += e.credit;
    return { ...e, balance, invoices: invoicesFor(e, data) };
  });

  return {
    opening,
    entries: withBalance,
    totals: { debit: totalDebit, credit: totalCredit, closing: balance },
  };
}

// --- PDF statement (with invoices merged in) ----------------------------
const MONTHS_ABBR = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
function fmtDate(d) {
  if (!d) return "";
  const [y, m, day] = d.split("-");
  return `${day}${MONTHS_ABBR[Number(m) - 1]}${y.slice(2)}`;
}
function fmtMoney(n) {
  return Number(n || 0).toLocaleString("en-US", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
}

// Maarr logo for the PDF header (PNG so pdf-lib can embed it reliably).
let LOGO_BYTES = null;
try {
  LOGO_BYTES = fs.readFileSync(path.join(__dirname, "logo.png"));
} catch {
  /* header just falls back to text if the logo isn't present */
}

// Build a single PDF: the statement table, then each entry's invoices — images
// as full pages, and PDF invoices with their real pages appended.
async function generateStatementPdf(statement, meta) {
  const pdf = await PDFDocument.create();
  const font = await pdf.embedFont(StandardFonts.Helvetica);
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);

  const PW = 595.28;
  const PH = 841.89; // A4
  const M = 42;
  const ink = rgb(0.06, 0.09, 0.16);
  const grey = rgb(0.42, 0.45, 0.5);

  // --- Table geometry ---
  const tableLeft = M;
  const tableRight = PW - M;
  const wCol = { no: 26, date: 62, debit: 84, credit: 84, bal: 80 };
  wCol.part =
    tableRight - tableLeft - (wCol.no + wCol.date + wCol.debit + wCol.credit + wCol.bal);
  // cx: cell boundaries [left, #|date, date|part, part|debit, debit|credit, credit|bal, right]
  const cx = [tableLeft];
  [wCol.no, wCol.date, wCol.part, wCol.debit, wCol.credit, wCol.bal].forEach((w) =>
    cx.push(cx[cx.length - 1] + w)
  );

  const ROW_H = 18;
  const HEAD_H = 21;
  const gridClr = rgb(0.82, 0.84, 0.88);
  const borderClr = rgb(0.5, 0.53, 0.58);
  const zebra = rgb(0.972, 0.98, 0.99);
  const headBg = rgb(0.12, 0.16, 0.22);
  const white = rgb(1, 1, 1);

  let page, y, tableTopY;
  const newPage = () => {
    page = pdf.addPage([PW, PH]);
    y = PH - M;
  };
  const putL = (t, x, size, f, color) =>
    page.drawText(String(t), { x, y, size, font: f || font, color: color || ink });
  const putR = (t, xr, size, f, color) => {
    const s = String(t);
    const w = (f || font).widthOfTextAtSize(s, size);
    page.drawText(s, { x: xr - w, y, size, font: f || font, color: color || ink });
  };
  const clip = (s, maxW, size) => {
    let p = String(s || "");
    while (p && font.widthOfTextAtSize(p, size) > maxW) p = p.slice(0, -1);
    return p;
  };

  const drawHeaderBand = () => {
    const top = y;
    page.drawRectangle({
      x: cx[0],
      y: top - HEAD_H,
      width: cx[6] - cx[0],
      height: HEAD_H,
      color: headBg,
    });
    y = top - 14;
    putL("#", cx[0] + 6, 9, bold, white);
    putL("Date", cx[1] + 6, 9, bold, white);
    putL("Particulars", cx[2] + 6, 9, bold, white);
    putR("Debit", cx[4] - 6, 9, bold, white);
    putR("Credit", cx[5] - 6, 9, bold, white);
    putR("Balance", cx[6] - 6, 9, bold, white);
    tableTopY = top;
    y = top - HEAD_H;
  };

  const closeTable = () => {
    const bottom = y;
    for (let i = 1; i < cx.length - 1; i++) {
      page.drawLine({
        start: { x: cx[i], y: tableTopY - HEAD_H },
        end: { x: cx[i], y: bottom },
        thickness: 0.5,
        color: gridClr,
      });
    }
    page.drawRectangle({
      x: cx[0],
      y: bottom,
      width: cx[6] - cx[0],
      height: tableTopY - bottom,
      borderColor: borderClr,
      borderWidth: 1,
    });
  };

  const drawRow = (cells, opts = {}) => {
    if (y - ROW_H < M + 46) {
      closeTable();
      newPage();
      y = PH - M;
      drawHeaderBand();
    }
    const top = y;
    const f = opts.bold ? bold : font;
    if (opts.fill) {
      page.drawRectangle({
        x: cx[0],
        y: top - ROW_H,
        width: cx[6] - cx[0],
        height: ROW_H,
        color: opts.fill,
      });
    }
    y = top - 13; // baseline
    if (cells.no !== undefined && cells.no !== "") putL(cells.no, cx[0] + 6, 9, f);
    if (cells.date) putL(cells.date, cx[1] + 6, 9, f);
    if (cells.part) putL(clip(cells.part, wCol.part - 12, 9), cx[2] + 6, 9, f);
    if (cells.debit !== undefined && cells.debit !== "")
      putR(fmtMoney(cells.debit), cx[4] - 6, 9, f);
    if (cells.credit !== undefined && cells.credit !== "")
      putR(fmtMoney(cells.credit), cx[5] - 6, 9, f);
    if (cells.bal !== undefined && cells.bal !== "")
      putR(fmtMoney(cells.bal), cx[6] - 6, 9, f);
    page.drawLine({
      start: { x: cx[0], y: top - ROW_H },
      end: { x: cx[6], y: top - ROW_H },
      thickness: 0.5,
      color: gridClr,
    });
    y = top - ROW_H;
  };

  newPage();

  // Logo top-left with the statement title beside it.
  let logo = null;
  if (LOGO_BYTES) {
    try {
      logo = await pdf.embedPng(LOGO_BYTES);
    } catch {
      logo = null;
    }
  }
  if (logo) {
    const logoH = 34;
    const logoW = (logo.width / logo.height) * logoH;
    // Logo left, statement title + dates right-aligned to the right margin.
    page.drawImage(logo, { x: M, y: PH - M - logoH, width: logoW, height: logoH });
    const rx = PW - M;
    const title = "Monthly Statement";
    const tw = bold.widthOfTextAtSize(title, 15);
    page.drawText(title, { x: rx - tw, y: PH - M - 13, size: 15, font: bold, color: ink });
    const dr = `${fmtDate(meta.from)}  to  ${fmtDate(meta.to)}`;
    const dw = font.widthOfTextAtSize(dr, 10);
    page.drawText(dr, { x: rx - dw, y: PH - M - 30, size: 10, font, color: grey });
    y = PH - M - logoH - 22;
  } else {
    putL("Maarr Smart — Statement", M, 16, bold);
    y -= 20;
    putL(`${fmtDate(meta.from)}  to  ${fmtDate(meta.to)}`, M, 11, font, grey);
    y -= 24;
  }

  drawHeaderBand();

  const opening = statement.opening || 0;
  drawRow(
    {
      part: "Opening balance (b/f)",
      debit: opening < 0 ? -opening : "",
      credit: opening > 0 ? opening : "",
      bal: opening,
    },
    { fill: rgb(0.996, 0.984, 0.929) }
  );
  statement.entries.forEach((e, i) => {
    drawRow(
      {
        no: i + 1,
        date: fmtDate(e.date),
        part: e.particulars,
        debit: e.debit || "",
        credit: e.credit || "",
        bal: e.balance,
      },
      { fill: i % 2 === 1 ? zebra : undefined }
    );
  });

  const opening_ = opening;
  const openingCr = opening_ >= 0 ? opening_ : 0;
  const openingDr = opening_ < 0 ? -opening_ : 0;
  const totalDebit = (statement.totals.debit || 0) + openingDr;
  const totalCredit = (statement.totals.credit || 0) + openingCr;

  drawRow(
    { part: "Totals", debit: totalDebit, credit: totalCredit },
    { bold: true, fill: rgb(0.93, 0.95, 0.98) }
  );
  drawRow(
    { part: "Closing balance (c/f)", bal: statement.totals.closing },
    { bold: true, fill: rgb(0.93, 0.95, 0.98) }
  );
  closeTable();

  // --- Highlighted "Amount Claimed" callout (right-aligned box) ---
  y -= 20;
  const cbW = 250;
  const cbH = 48;
  if (y - cbH < M) {
    newPage();
    y = PH - M;
  }
  const cbX = tableRight - cbW;
  const cbTop = y;
  const cbBot = y - cbH;
  page.drawRectangle({
    x: cbX,
    y: cbBot,
    width: cbW,
    height: cbH,
    color: rgb(1, 0.953, 0.69),
    borderColor: rgb(0.82, 0.6, 0.12),
    borderWidth: 1.3,
  });
  const padL = cbX + 14;
  const padR = cbX + cbW - 14;
  page.drawText("AMOUNT CLAIMED", {
    x: padL,
    y: cbTop - 17,
    size: 9,
    font: bold,
    color: rgb(0.42, 0.3, 0),
  });
  // Claim amount = total Debit.
  const claimStr = fmtMoney(totalDebit);
  page.drawText(claimStr, {
    x: padR - bold.widthOfTextAtSize(claimStr, 17),
    y: cbTop - 37,
    size: 17,
    font: bold,
    color: ink,
  });
  y = cbBot - 12;

  // Invoices — images as full pages, PDFs with their real pages appended.
  for (const e of statement.entries) {
    for (const inv of e.invoices || []) {
      const rec = findInvoiceRec(inv.id);
      if (!rec) continue;
      let bytes = null;
      try {
        bytes = await readInvoiceBytes(rec);
      } catch {
        bytes = null;
      }
      if (!bytes) continue;
      const caption = `Invoice — ${fmtDate(e.date)} · ${e.particulars} · ${inv.name}`;
      try {
        if (inv.mime === "application/pdf") {
          const src = await PDFDocument.load(bytes);
          const pages = await pdf.copyPages(src, src.getPageIndices());
          pages.forEach((p) => pdf.addPage(p));
        } else {
          const img =
            inv.mime === "image/png"
              ? await pdf.embedPng(bytes)
              : await pdf.embedJpg(bytes);
          const ip = pdf.addPage([PW, PH]);
          ip.drawText(caption, { x: M, y: PH - M, size: 10, font: bold, color: ink });
          const maxW = PW - 2 * M;
          const maxH = PH - 2 * M - 24;
          const scale = Math.min(maxW / img.width, maxH / img.height, 1);
          const w = img.width * scale;
          const h = img.height * scale;
          ip.drawImage(img, { x: M, y: PH - M - 24 - h, width: w, height: h });
        }
      } catch {
        const np = pdf.addPage([PW, PH]);
        np.drawText(`${caption} (could not embed this file)`, {
          x: M,
          y: PH - M,
          size: 10,
          font,
          color: ink,
        });
      }
    }
  }

  return pdf.save();
}

// --- Audit log: Atlas "audit" collection, else append-only JSONL file ------
const AUDIT_FILE = path.join(__dirname, "audit.log");

function audit(action, user, details = {}) {
  const entry = {
    ts: new Date().toISOString(),
    user: user || "unknown",
    action,
    ...details,
  };
  if (auditColl) {
    auditColl
      .insertOne(entry)
      .catch((err) => console.error("Audit write failed:", err.message));
  } else {
    try {
      fs.appendFileSync(AUDIT_FILE, JSON.stringify(entry) + "\n");
    } catch (err) {
      console.error("Failed to write audit log:", err);
    }
  }
}

function monthTotals(entries) {
  return entries.reduce(
    (t, e) => {
      t.count += 1;
      t.debit += e.debit;
      t.credit += e.credit;
      return t;
    },
    { count: 0, debit: 0, credit: 0 }
  );
}

// Diff two lists of entries by content. An edited row shows up as a removed
// (old value) + added (new value) pair. Matches ignore the internal id.
function diffEntries(oldRows, newRows) {
  const sig = (e) => `${e.date}|${e.particulars}|${e.debit}|${e.credit}`;
  const pick = (e) => ({
    date: e.date,
    particulars: e.particulars,
    debit: e.debit,
    credit: e.credit,
  });

  const remaining = {};
  oldRows.forEach((e) => {
    const s = sig(e);
    remaining[s] = (remaining[s] || 0) + 1;
  });
  const added = [];
  newRows.forEach((e) => {
    const s = sig(e);
    if (remaining[s] > 0) remaining[s] -= 1;
    else added.push(pick(e));
  });

  const remaining2 = {};
  newRows.forEach((e) => {
    const s = sig(e);
    remaining2[s] = (remaining2[s] || 0) + 1;
  });
  const removed = [];
  oldRows.forEach((e) => {
    const s = sig(e);
    if (remaining2[s] > 0) remaining2[s] -= 1;
    else removed.push(pick(e));
  });

  return { added, removed };
}

// --- Routes --------------------------------------------------------------

// Distinct months that have entries (newest first) — for the month selector.
app.get("/api/months", (req, res) => {
  const months = [...new Set(readEntries().map((e) => e.month))].sort().reverse();
  res.json(months);
});

// Dashboard summary: per-month debit/credit totals with carried opening/closing.
app.get("/api/summary", (req, res) => {
  const { startingBalance, entries } = readData();

  const byMonth = {};
  for (const e of entries) {
    if (!byMonth[e.month]) byMonth[e.month] = { month: e.month, debit: 0, credit: 0 };
    byMonth[e.month].debit += e.debit;
    byMonth[e.month].credit += e.credit;
  }

  const sorted = Object.values(byMonth).sort((a, b) =>
    a.month < b.month ? -1 : 1
  );

  let closing = startingBalance;
  let totalDebit = 0;
  let totalCredit = 0;
  const months = sorted.map((m) => {
    const opening = closing;
    const net = m.credit - m.debit;
    closing = opening + net;
    totalDebit += m.debit;
    totalCredit += m.credit;
    return { month: m.month, opening, debit: m.debit, credit: m.credit, net, closing };
  });

  res.json({
    startingBalance,
    months,
    totals: { debit: totalDebit, credit: totalCredit, closing },
  });
});

// Date-range report: entries between from..to (inclusive) with a running
// balance that starts from the balance as of the day before `from`.
app.get("/api/report", (req, res) => {
  const { from, to } = req.query;
  const dateRe = /^\d{4}-\d{2}-\d{2}$/;
  if (!dateRe.test(from || "") || !dateRe.test(to || "")) {
    return res.status(400).json({ error: "from and to are required (YYYY-MM-DD)" });
  }
  if (from > to) {
    return res.status(400).json({ error: "'from' must be on or before 'to'" });
  }

  const data = readData();
  const statement = buildStatement(data, from, to);

  res.json({
    from,
    to,
    opening: statement.opening,
    entries: statement.entries,
    totals: statement.totals,
  });
});

// Ledger for one month, with the opening balance carried forward from all prior
// months (starting balance + net of every earlier month). Running Balance on
// every row, plus month totals + closing balance.
app.get("/api/ledger", (req, res) => {
  const month = req.query.month;
  if (!month) return res.status(400).json({ error: "month is required (YYYY-MM)" });

  const data = readData();
  const { startingBalance, entries } = data;

  // Opening balance = the overall starting balance plus the net of every entry
  // in a month strictly before this one (carried forward).
  const opening = entries
    .filter((e) => e.month < month)
    .reduce((bal, e) => bal + e.credit - e.debit, startingBalance);

  const rows = entries
    .filter((e) => e.month === month)
    .sort(chronological);

  const claimedSet = new Set(data.claimed || []);
  let balance = opening;
  let totalDebit = 0;
  let totalCredit = 0;
  const withBalance = rows.map((e) => {
    balance += e.credit - e.debit;
    totalDebit += e.debit;
    totalCredit += e.credit;
    return {
      ...e,
      balance,
      claimed: claimedSet.has(entrySig(e)),
      invoices: invoicesFor(e, data),
    };
  });

  res.json({
    month,
    opening,
    editable: isMonthEditable(month, data),
    entries: withBalance,
    totals: { debit: totalDebit, credit: totalCredit, closing: balance },
  });
});

// Add a ledger entry (Particulars + Debit and/or Credit for a given month).
app.post("/api/entries", (req, res) => {
  const { month, date, particulars, debit, credit } = req.body;

  if (!month || !/^\d{4}-\d{2}$/.test(month)) {
    return res.status(400).json({ error: "month is required (YYYY-MM)" });
  }
  if (!particulars || !String(particulars).trim()) {
    return res.status(400).json({ error: "particulars is required" });
  }

  const debitNum = Number(debit) || 0;
  const creditNum = Number(credit) || 0;
  if (debitNum < 0 || creditNum < 0) {
    return res.status(400).json({ error: "debit/credit cannot be negative" });
  }
  if (debitNum === 0 && creditNum === 0) {
    return res.status(400).json({ error: "enter a debit or a credit amount" });
  }

  const data = readData();
  const entry = {
    id: nextId(data.entries),
    month,
    date: date || `${month}-01`,
    particulars: String(particulars).trim(),
    debit: debitNum,
    credit: creditNum,
  };

  data.entries.push(entry);
  writeData(data);
  res.status(201).json(entry);
});

// Delete an entry.
app.delete("/api/entries/:id", (req, res) => {
  if (blockReadOnly(req, res)) return;
  const id = Number(req.params.id);
  const data = readData();
  const removed = data.entries.find((e) => e.id === id);
  const filtered = data.entries.filter((e) => e.id !== id);

  if (filtered.length === data.entries.length) {
    return res.status(404).json({ error: "entry not found" });
  }
  if (removed && !isMonthEditable(removed.month, data)) {
    return res.status(403).json({
      error: `${removed.month} is closed for edits.`,
    });
  }

  data.entries = filtered;
  writeData(data);
  audit("delete_entry", req.user, { entry: removed });
  res.status(204).end();
});

// Replace ALL entries for a month at once (the "save the sheet" action).
// Body: { entries: [{ date, particulars, debit, credit }, ...] }
// Rows that are completely blank are ignored; other months are untouched.
app.put("/api/months/:month", (req, res) => {
  if (blockReadOnly(req, res)) return;
  const month = req.params.month;
  if (!/^\d{4}-\d{2}$/.test(month)) {
    return res.status(400).json({ error: "month must be YYYY-MM" });
  }
  if (!isMonthEditable(month, readData())) {
    return res.status(403).json({
      error: `${month} is closed for edits (past the grace period).`,
    });
  }

  const incoming = Array.isArray(req.body.entries) ? req.body.entries : [];
  const cleaned = [];

  for (const row of incoming) {
    const particulars = String(row.particulars || "").trim();
    const debit = Number(row.debit) || 0;
    const credit = Number(row.credit) || 0;

    // Skip fully-empty rows silently (blank sheet lines).
    if (!particulars && debit === 0 && credit === 0) continue;

    if (!particulars) {
      return res.status(400).json({ error: "every filled row needs particulars" });
    }
    if (debit < 0 || credit < 0) {
      return res.status(400).json({ error: "debit/credit cannot be negative" });
    }
    if (debit === 0 && credit === 0) {
      return res.status(400).json({ error: `"${particulars}" needs a debit or credit` });
    }

    cleaned.push({
      month,
      date: row.date || `${month}-01`,
      particulars,
      debit,
      credit,
    });
  }

  // Reject exact duplicate lines (same date + particulars + debit + credit).
  const seen = new Set();
  for (const e of cleaned) {
    const k = entrySig(e);
    if (seen.has(k)) {
      return res.status(409).json({
        error: `Duplicate entry: "${e.particulars}" on ${e.date} (${
          e.debit ? "Dr " + e.debit : "Cr " + e.credit
        }) appears more than once.`,
      });
    }
    seen.add(k);
  }

  const data = readData();
  const claimedSet = new Set(data.claimed || []);
  // Keep every other month, drop this month's old rows, then append the new ones.
  const others = data.entries.filter((e) => e.month !== month);
  const oldRows = data.entries.filter((e) => e.month === month);

  // A claimed entry cannot be removed or modified: every claimed row that
  // belonged to this month must still be present, unchanged, in the new set.
  for (const old of oldRows) {
    const sig = entrySig(old);
    if (claimedSet.has(sig) && !seen.has(sig)) {
      return res.status(403).json({
        error: `"${old.particulars}" (${old.date}) is claimed and can't be removed or changed. Ask admin to unclaim it first.`,
      });
    }
  }

  let id = others.reduce((max, e) => Math.max(max, e.id), 0);
  const saved = cleaned.map((e) => ({ id: ++id, ...e }));

  data.entries = [...others, ...saved];
  writeData(data);
  const { added, removed } = diffEntries(oldRows, saved);
  audit("save_month", req.user, {
    month,
    added,
    removed,
    before: monthTotals(oldRows),
    after: monthTotals(saved),
  });
  res.json({ month, count: saved.length });
});

// Admin: set the overall starting balance (the opening of your very first
// month). It then carries forward into every following month automatically.
app.put("/api/starting-balance", (req, res) => {
  if (requireAdmin(req, res)) return;
  const value = Number(req.body.startingBalance);
  if (Number.isNaN(value)) {
    return res.status(400).json({ error: "startingBalance must be a number" });
  }
  const data = readData();
  const from = data.startingBalance;
  data.startingBalance = value;
  writeData(data);
  audit("set_starting_balance", req.user, { from, to: value });
  res.json({ startingBalance: value });
});

// --- Admin controls -----------------------------------------------------

// Settings snapshot (grace period, unlocked months, starting balance).
app.get("/api/settings", (req, res) => {
  const d = readData();
  res.json({
    graceDay: d.graceDay,
    unlockedMonths: d.unlockedMonths,
    startingBalance: d.startingBalance,
  });
});

// Admin: set the grace-period day (previous month stays open until this day).
app.put("/api/settings/grace-day", (req, res) => {
  if (requireAdmin(req, res)) return;
  const value = Math.floor(Number(req.body.graceDay));
  if (!Number.isFinite(value) || value < 1 || value > 28) {
    return res.status(400).json({ error: "graceDay must be a number from 1 to 28" });
  }
  const data = readData();
  const from = data.graceDay;
  data.graceDay = value;
  writeData(data);
  audit("set_grace_day", req.user, { from, to: value });
  res.json({ graceDay: value });
});

// Admin: unlock a locked month for corrections.
app.post("/api/months/:month/unlock", (req, res) => {
  if (requireAdmin(req, res)) return;
  const month = req.params.month;
  if (!/^\d{4}-\d{2}$/.test(month)) {
    return res.status(400).json({ error: "month must be YYYY-MM" });
  }
  const data = readData();
  if (!data.unlockedMonths.includes(month)) data.unlockedMonths.push(month);
  writeData(data);
  audit("unlock_month", req.user, { month });
  res.json({ month, unlocked: true });
});

// Admin: re-lock a previously unlocked month.
app.post("/api/months/:month/lock", (req, res) => {
  if (requireAdmin(req, res)) return;
  const month = req.params.month;
  const data = readData();
  data.unlockedMonths = data.unlockedMonths.filter((m) => m !== month);
  writeData(data);
  audit("lock_month", req.user, { month });
  res.json({ month, unlocked: false });
});

// Admin: mark an entry as claimed (approved) — locks it against edits.
function entryFromBody(b) {
  return {
    month: b.month,
    date: b.date,
    particulars: String(b.particulars || "").trim(),
    debit: Number(b.debit) || 0,
    credit: Number(b.credit) || 0,
  };
}

app.post("/api/claim", (req, res) => {
  if (requireAdmin(req, res)) return;
  const e = entryFromBody(req.body || {});
  if (!e.month || !e.date || !e.particulars) {
    return res.status(400).json({ error: "month, date and particulars are required" });
  }
  const sig = entrySig(e);
  const data = readData();
  const exists = data.entries.some((x) => entrySig(x) === sig);
  if (!exists) return res.status(404).json({ error: "entry not found" });
  if (!data.claimed.includes(sig)) data.claimed.push(sig);
  writeData(data);
  audit("claim_entry", req.user, { entry: e });
  res.json({ claimed: true });
});

app.post("/api/unclaim", (req, res) => {
  if (requireAdmin(req, res)) return;
  const e = entryFromBody(req.body || {});
  const sig = entrySig(e);
  const data = readData();
  data.claimed = data.claimed.filter((s) => s !== sig);
  writeData(data);
  audit("unclaim_entry", req.user, { entry: e });
  res.json({ claimed: false });
});

// Admin: claim every pending entry in a date range at once — this is what
// "Download & claim" calls. Claimed entries are locked and never listed on a
// future statement, and a snapshot of the statement is saved so it can be
// re-downloaded any time later.
app.post("/api/claim-range", (req, res) => {
  if (requireAdmin(req, res)) return;
  const { from, to } = req.body || {};
  const dateRe = /^\d{4}-\d{2}-\d{2}$/;
  if (!dateRe.test(from || "") || !dateRe.test(to || "")) {
    return res.status(400).json({ error: "from and to are required (YYYY-MM-DD)" });
  }
  if (from > to) {
    return res.status(400).json({ error: "'from' must be on or before 'to'" });
  }
  const data = readData();

  // Build the statement snapshot from the PENDING entries (same math as the
  // /api/report endpoint) BEFORE marking them claimed.
  const statement = buildStatement(data, from, to);
  const snapshotEntries = statement.entries;

  const count = snapshotEntries.length;
  if (count === 0) {
    return res.status(400).json({ error: "No pending entries in that range to claim." });
  }

  // Mark them claimed.
  const claimedSet = new Set(data.claimed || []);
  for (const e of snapshotEntries) claimedSet.add(entrySig(e));
  data.claimed = [...claimedSet];

  // Save the report snapshot for future re-download.
  const nextReportId =
    (data.reports || []).reduce((max, r) => Math.max(max, r.id || 0), 0) + 1;
  const report = {
    id: nextReportId,
    from,
    to,
    claimedAt: new Date().toISOString(),
    claimedBy: req.user,
    opening: statement.opening,
    entries: snapshotEntries,
    totals: statement.totals,
  };
  data.reports = [...(data.reports || []), report];

  writeData(data);
  audit("claim_range", req.user, { from, to, count, reportId: nextReportId });
  res.json({ from, to, count, reportId: nextReportId });
});

// List saved claimed-report snapshots (newest first, metadata only). Admin only.
app.get("/api/reports", (req, res) => {
  if (requireAdmin(req, res)) return;
  const reports = (readData().reports || [])
    .map((r) => ({
      id: r.id,
      from: r.from,
      to: r.to,
      claimedAt: r.claimedAt,
      claimedBy: r.claimedBy,
      count: (r.entries || []).length,
      opening: r.opening,
      totals: r.totals,
    }))
    .sort((a, b) => (a.id < b.id ? 1 : -1));
  res.json(reports);
});

// Fetch one saved report snapshot in full (for re-download). Admin only.
app.get("/api/reports/:id", (req, res) => {
  if (requireAdmin(req, res)) return;
  const id = Number(req.params.id);
  const report = (readData().reports || []).find((r) => r.id === id);
  if (!report) return res.status(404).json({ error: "report not found" });
  res.json(report);
});

// Download the PDF for a date range (statement + merged invoices). Admin only.
app.get("/api/statement.pdf", async (req, res) => {
  if (requireAdmin(req, res)) return;
  const { from, to } = req.query;
  const dateRe = /^\d{4}-\d{2}-\d{2}$/;
  if (!dateRe.test(from || "") || !dateRe.test(to || "")) {
    return res.status(400).json({ error: "from and to are required (YYYY-MM-DD)" });
  }
  if (from > to) {
    return res.status(400).json({ error: "'from' must be on or before 'to'" });
  }
  const statement = buildStatement(readData(), from, to);
  if (!statement.entries.length) {
    return res.status(400).json({ error: "No pending entries in that range." });
  }
  try {
    const bytes = await generateStatementPdf(statement, { from, to });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="Statement_${from}_to_${to}.pdf"`
    );
    res.send(Buffer.from(bytes));
  } catch (err) {
    console.error("PDF generation failed:", err);
    res.status(500).json({ error: "Failed to generate the PDF" });
  }
});

// Download the PDF for a saved report. Admin only.
app.get("/api/reports/:id/pdf", async (req, res) => {
  if (requireAdmin(req, res)) return;
  const id = Number(req.params.id);
  const report = (readData().reports || []).find((r) => r.id === id);
  if (!report) return res.status(404).json({ error: "report not found" });
  try {
    const bytes = await generateStatementPdf(report, { from: report.from, to: report.to });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="Statement_${report.from}_to_${report.to}.pdf"`
    );
    res.send(Buffer.from(bytes));
  } catch (err) {
    console.error("PDF generation failed:", err);
    res.status(500).json({ error: "Failed to generate the PDF" });
  }
});

// Attach an invoice image to an entry. Body: the entry fields plus
// { name, dataUrl } where dataUrl is a base64 "data:image/...;base64,..." string.
app.post("/api/invoice", async (req, res) => {
  const b = req.body || {};
  const e = {
    month: b.month,
    date: b.date,
    particulars: String(b.particulars || "").trim(),
    debit: Number(b.debit) || 0,
    credit: Number(b.credit) || 0,
  };
  if (!e.month || !e.date || !e.particulars) {
    return res.status(400).json({ error: "entry (month, date, particulars) is required" });
  }
  const m = /^data:([^;]+);base64,(.+)$/s.exec(b.dataUrl || "");
  if (!m) return res.status(400).json({ error: "a base64 file is required" });
  const mime = m[1];
  if (!mime.startsWith("image/") && mime !== "application/pdf") {
    return res.status(400).json({ error: "only image (JPG/PNG) or PDF invoices are supported" });
  }
  const buf = Buffer.from(m[2], "base64");
  if (buf.length > 10 * 1024 * 1024) {
    return res.status(413).json({ error: "file too large (max 10 MB)" });
  }

  const data = readData();
  const sig = entrySig(e);
  if (!data.entries.some((x) => entrySig(x) === sig)) {
    return res.status(404).json({ error: "Save the entry first, then attach its invoice." });
  }

  try {
    const idHex = crypto.randomBytes(8).toString("hex");
    // Compress images hard (resize + re-encode) before storing; PDFs are kept
    // as-is (already compressed). Falls back to the original if sharp fails.
    let outBuf = buf;
    let outMime = mime;
    if (mime.startsWith("image/")) {
      const before = buf.length;
      try {
        const sharp = require("sharp");
        outBuf = await sharp(buf)
          .rotate() // honour EXIF orientation
          .resize({ width: 1800, height: 1800, fit: "inside", withoutEnlargement: true })
          .jpeg({ quality: 65, mozjpeg: true })
          .toBuffer();
        outMime = "image/jpeg";
        console.log(
          `Invoice compressed: ${(before / 1024).toFixed(0)}KB -> ${(outBuf.length / 1024).toFixed(0)}KB`
        );
      } catch (err) {
        console.error("Image compression skipped:", err.message);
        outBuf = buf;
        outMime = mime;
      }
    }
    const ref = await saveInvoiceFile(outBuf, { mime: outMime, name: b.name });
    if (!data.invoices[sig]) data.invoices[sig] = [];
    const rec = {
      id: idHex,
      name: String(b.name || "invoice").slice(0, 120),
      mime: outMime,
      ...ref,
    };
    data.invoices[sig].push(rec);
    writeData(data);
    audit("upload_invoice", req.user, { entry: e, name: rec.name });
    // Stored in Atlas (GridFS) — keep the local uploads folder empty.
    if (ref.gridfsId) purgeUploadsDir();
    res.status(201).json({ id: rec.id, name: rec.name, mime: outMime, url: `/uploads/${idHex}` });
  } catch (err) {
    console.error("Invoice upload failed:", err.message);
    res.status(500).json({ error: "Failed to store the invoice file" });
  }
});

// Remove an invoice by id.
app.delete("/api/invoice/:id", async (req, res) => {
  const id = String(req.params.id);
  const data = readData();
  let removed = null;
  for (const sig of Object.keys(data.invoices || {})) {
    const arr = data.invoices[sig];
    const idx = arr.findIndex((x) => String(x.id) === id);
    if (idx >= 0) {
      removed = arr.splice(idx, 1)[0];
      if (arr.length === 0) delete data.invoices[sig];
      break;
    }
  }
  if (!removed) return res.status(404).json({ error: "invoice not found" });
  await deleteInvoiceFile(removed);
  writeData(data);
  audit("delete_invoice", req.user, { id, name: removed.name });
  res.status(204).end();
});

// Audit log (most recent first). Admin only.
app.get("/api/audit", async (req, res) => {
  if (requireAdmin(req, res)) return;
  const limit = Math.min(Number(req.query.limit) || 200, 1000);

  if (auditColl) {
    try {
      const entries = await auditColl
        .find({}, { projection: { _id: 0 } })
        .sort({ _id: -1 }) // newest first (ObjectId is time-ordered)
        .limit(limit)
        .toArray();
      return res.json(entries);
    } catch (err) {
      console.error("Failed to read audit log:", err.message);
      return res.json([]);
    }
  }

  let lines = [];
  try {
    if (fs.existsSync(AUDIT_FILE)) {
      lines = fs.readFileSync(AUDIT_FILE, "utf-8").trim().split("\n").filter(Boolean);
    }
  } catch (err) {
    console.error("Failed to read audit log:", err);
  }
  const entries = lines
    .slice(-limit)
    .map((l) => {
      try {
        return JSON.parse(l);
      } catch {
        return null;
      }
    })
    .filter(Boolean)
    .reverse();
  res.json(entries);
});

initStorage()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Ledger backend running on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error("Failed to initialise storage:", err.message);
    process.exit(1);
  });
