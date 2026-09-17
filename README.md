# DeskWise — Vulnerable Backend Server 🛡️⚡

**DeskWise Server** is a deliberately vulnerable, CTF-style Node.js/Express backend implementation designed to teach the **OWASP Top 10:2025** web security vulnerabilities. Every vulnerability category is implemented as a genuine, exploitable flaw (not a simulation). Successfully exploiting a vulnerability awards a unique flag formatted as `CATEGORY{...}`.

The server supports a flexible `VULN_MODES` toggle system, allowing it to run either as a vulnerable target application or a fully-patched reference implementation.

---

## 🛠 Tech Stack

- **Runtime**: Node.js (ESM — `"type": "module"`)
- **Framework**: Express 5
- **Database**: MongoDB via Mongoose + Native `MongoClient` (Better Auth adapter)
- **Authentication**: Better Auth (`toNodeHandler`)
- **Encryption Helpers**: `crypto-js`, Node `crypto`

---

## ☣️ OWASP Top 10:2025 Vulnerabilities Implemented

| Category | Vulnerability Flaw | Flag Format |
|---|---|---|
| **A01: Broken Access Control** | **BOLA (IDOR)**: `GET /api/tickets/:id` permits unauthorized access to any ticket by ID.<br>**BFLA**: `requireAdmin` trusts client-supplied `X-User-Role` header; `POST /api/profile/complete` allows role mass assignment. | `IDOR{...}`<br>`BFLA{...}` |
| **A02: Security Misconfiguration** | `GET /api/debug/env` dumps `process.env` (leaking admin secret); global error handler outputs verbose stack traces. | `MISCONFIG{...}` |
| **A03: Supply Chain Failures** | Pinned vulnerable package (`lodash@4.17.4` affected by CVE-2019-10744 prototype pollution) listed on `GET /api/system/dependencies`. | `SUPPLYCHAIN{...}` |
| **A04: Cryptographic Failures** | Profile `internalNotesMd5` saved using unsalted MD5 hashing; exposed via `GET /api/profile/me`. | `CRYPTOFAIL{...}` |
| **A05: Injection (NoSQL)** | `GET /api/tickets/search` passes unsanitized `req.query` directly into `Ticket.find()`, allowing MongoDB operator injection (`?title[$ne]=null`). | `INJECT{...}` |
| **A06: Insecure Design** | Password reset tokens generated as 4-digit sequential integers without rate limiting (`/api/auth-ext/reset-request` & `/reset-verify`). | `INSECUREDESIGN{...}` |
| **A07: Authentication Failures** | `POST /api/auth-ext/login` has zero rate-limiting, combined with a seeded weak password account (`weakuser@deskwise.local` / `password123`). | `AUTHFAIL{...}` |
| **A08: Software & Data Integrity** | `POST /api/tickets/import` accepts JSON payloads with `verified: true` without validating an HMAC signature header. | `INTEGRITYFAIL{...}` |
| **A09: Logging & Alerting Failures** | Privilege escalation via `PATCH /api/profile/promote` is never written to `AuditLog`, leaving a blind spot in `GET /api/admin/audit-log`. | `LOGFAIL{...}` |
| **A10: Exceptional Conditions** | Malformed ticket IDs trigger errors in `GET /api/tickets/:id` where the `catch` block fails open and grants access. | `EXCEPTFAIL{...}` |

---

## 🎛️ Vulnerability Mode System (`VULN_MODES`)

All vulnerabilities are controlled via environment variables defined in [`src/config/vulnModes.js`](file:///d:/project/DeskWise1/DeskWise-server/src/config/vulnModes.js):

```js
export const VULN_MODES = {
  IDOR_TICKETS:      process.env.VULN_IDOR_TICKETS      || "vulnerable", // vulnerable | patched
  BFLA_PROMOTE:      process.env.VULN_BFLA_PROMOTE      || "vulnerable",
  MISCONFIG_DEBUG:   process.env.VULN_MISCONFIG_DEBUG   || "vulnerable",
  SUPPLY_CHAIN:      process.env.VULN_SUPPLY_CHAIN      || "vulnerable",
  CRYPTO_FAIL:       process.env.VULN_CRYPTO_FAIL       || "vulnerable",
  NOSQL_INJECTION:   process.env.VULN_NOSQL_INJECTION   || "vulnerable",
  INSECURE_DESIGN:   process.env.VULN_INSECURE_DESIGN   || "vulnerable",
  AUTH_FAIL:         process.env.VULN_AUTH_FAIL         || "vulnerable",
  INTEGRITY_FAIL:    process.env.VULN_INTEGRITY_FAIL    || "vulnerable",
  LOG_FAIL:          process.env.VULN_LOG_FAIL          || "vulnerable",
  EXCEPT_FAIL:       process.env.VULN_EXCEPT_FAIL       || "vulnerable",
};
```

---

## 📁 Directory Structure

```text
DeskWise-server/
├── scripts/
│   └── seed.js              # Database seed script for CTF environment
├── src/
│   ├── config/
│   │   ├── flags.js         # Authoritative flag registry
│   │   └── vulnModes.js     # Central VULN_MODES configuration
│   ├── middleware/
│   │   ├── auditLog.js      # Audit log recorder
│   │   ├── requireAdmin.js  # Vulnerable admin check (header-trusting)
│   │   ├── requireAdminSecure.js # Secure admin check (DB lookup)
│   │   └── requireAuth.js   # Session authentication middleware
│   ├── models/
│   │   ├── AuditLog.js      # Audit log collection
│   │   ├── Flag.js          # Known flags collection
│   │   ├── Profile.js       # User profile model (with MD5 internalNotes)
│   │   ├── ResetToken.js    # Password reset tokens (sequential)
│   │   ├── SolvedFlag.js    # User solved challenge records
│   │   └── Ticket.js        # Support ticket model
│   ├── routes/
│   │   ├── admin.js         # BFLA target & audit log endpoint
│   │   ├── auth-ext.js      # Predictable reset & weak login routes
│   │   ├── debug.js         # Env disclosure & error test routes
│   │   ├── flags.js         # POST /submit & GET /progress
│   │   ├── profile.js       # Profile management & role escalation
│   │   ├── system.js        # Dependency disclosure route (A03)
│   │   └── tickets.js       # Ticket CRUD, BOLA, NoSQL, Integrity, Fail-Open
│   ├── auth.js              # Better Auth initialization
│   └── server.js            # Express app entry point & error handler
├── .env.example
├── package.json
└── VULNS.md                 # Private instructor reference (gitignored)
```

---

## ⚙️ Setup & Execution

### 1. Requirements
- Node.js (v18+)
- MongoDB running locally at `mongodb://localhost:27017/deskwise`

### 2. Environment Configuration
Copy `.env.example` to `.env`:

```env
MONGODB_URI=mongodb://localhost:27017/deskwise
PORT=5000
BETTER_AUTH_SECRET=79bfb472346b29ed50448f9dc12306c8d58376f5a57611212f6abc4ef353f59b
BETTER_AUTH_URL=http://localhost:5000
FRONTEND_URL=http://localhost:3000

MONGO_ADMIN_TOKEN=MISCONFIG{env_vars_exposed_in_production}
IMPORT_HMAC_SECRET=supersecrethmackey123
```

### 3. Install Dependencies
```bash
npm install
```

### 4. Seed Database
Populates MongoDB with initial users, tickets, and flags:

```bash
node scripts/seed.js
```

### 5. Start Server
```bash
npm run dev
```

---

## 🔑 Pre-configured Seed Accounts

| Account Role | Email | Password | Purpose |
|---|---|---|---|
| Admin | `admin@deskwise.local` | `Password123!` | Privileged administrator |
| Agent | `agent@deskwise.local` | `Password123!` | Helpdesk agent |
| User | `john@deskwise.local` | `Password123!` | Standard user (MD5 note target) |
| Victim | `victim@deskwise.local` | `Password123!` | Password reset target (A06) |
| Weak User | `weakuser@deskwise.local` | `password123` | Credential stuffing target (A07) |

---

## 🚩 Flag Submission API

Players submit flags to `POST /api/flags/submit`:

```json
// Request
POST /api/flags/submit
Content-Type: application/json

{
  "flag": "IDOR{y0u_acc3ssed_s0me0ne_elses_tick3t}"
}

// Response
{
  "success": true,
  "alreadySolved": false,
  "vulnId": "IDOR_TICKETS",
  "name": "A01 – BOLA: Insecure Direct Object Reference",
  "message": "🎉 Correct! Flag accepted."
}
```

Check progress via `GET /api/flags/progress`.

---

## ⚠️ Disclaimer

This repository is strictly for **educational security training and authorized laboratory environments**. Do not deploy this application with `VULN_MODE="vulnerable"` in production environments.
