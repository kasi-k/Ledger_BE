# Maarr Ledger — Backend API

Node.js + Express REST API for the Maarr Smart Monthly Ledger.
Stores everything in **MongoDB Atlas** (ledger data, saved reports, invoice files
via GridFS, and the audit log). Generates the downloadable PDF statement
(with the logo, a professional table, and invoices merged in) using `pdf-lib`,
and compresses uploaded images with `sharp`.

## Requirements

- Node.js **>= 18.18**
- A MongoDB Atlas connection string (optional for local dev — falls back to a
  local `ledger.json` file if `MONGODB_URI` is unset).

## Setup

```bash
npm install
cp .env.example .env      # then fill in MONGODB_URI etc.
npm start                 # or: npm run dev  (auto-restart)
```

Runs on `http://localhost:4100` by default (override with `PORT`).
Health check: `GET /health` → `{"ok":true}`.

## Environment variables

| Key | Required | Notes |
|---|---|---|
| `MONGODB_URI` | prod | Atlas connection string. Unset = local JSON file. |
| `MONGODB_DB` | – | Database name (default `maarr_ledger`). |
| `AUTH_SECRET` | prod | Long random string for signing tokens. |
| `AUTH_USER` / `AUTH_PASS` | – | Admin login (default `admin` / `maarr123`). |
| `EMP_USER` / `EMP_PASS` | – | Accounts login (default `employee` / `employee123`). |
| `CORS_ORIGIN` | prod | Frontend origin(s), comma-separated. Unset = allow all. |
| `PORT` | – | Default `4100`. |

> Change `AUTH_SECRET`, `AUTH_PASS`, and `EMP_PASS` before going live.

## Roles

- **admin** — full access: download & claim statements, reports, audit, controls.
- **accounts** (login name `employee`) — data entry only.

## Deploy to Render

This repo includes `render.yaml` (a Render Blueprint). Create a **Blueprint**
from the repo, or a **Web Service** manually:

- Build command: `npm install`
- Start command: `node server.js`
- Health check path: `/health`
- **Instances: 1** (the ledger is cached in memory — do not autoscale)

Set the environment variables above in the Render dashboard, and add `0.0.0.0/0`
under **Atlas → Network Access** (cloud hosts use dynamic IPs).

## Notes

- `uploads/`, `audit.log`, and `ledger.json` are **dev-only fallbacks** and are
  gitignored — in production all of this lives in Atlas.
- `logo.png` is used in the PDF header; keep it committed.
