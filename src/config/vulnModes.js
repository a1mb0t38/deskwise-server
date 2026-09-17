/**
 * VULN_MODES — Central control panel for all DeskWise vulnerability toggles.
 *
 * Each key maps to an environment variable. Allowed values:
 *   "vulnerable" — the intentional bug is active (default, CTF mode)
 *   "patched"    — a correct, secure implementation is used instead
 *
 * To flip a single vuln to patched without touching others:
 *   VULN_IDOR_TICKETS=patched node src/server.js
 */
export const VULN_MODES = {
  // A01: Broken Access Control — BOLA (IDOR on ticket access)
  IDOR_TICKETS: process.env.VULN_IDOR_TICKETS || "vulnerable",

  // A01: Broken Access Control — BFLA (mass assignment + header-trusting admin check)
  BFLA_PROMOTE: process.env.VULN_BFLA_PROMOTE || "vulnerable",

  // A02: Security Misconfiguration — debug env dump endpoint
  MISCONFIG_DEBUG: process.env.VULN_MISCONFIG_DEBUG || "vulnerable",

  // A03: Software Supply Chain — listed via /api/system/dependencies, knowledge-based flag
  SUPPLY_CHAIN: process.env.VULN_SUPPLY_CHAIN || "vulnerable",

  // A04: Cryptographic Failures — broken MD5/XOR on internalNotes field
  CRYPTO_FAIL: process.env.VULN_CRYPTO_FAIL || "vulnerable",

  // A05: Injection — NoSQL injection on ticket search
  NOSQL_INJECTION: process.env.VULN_NOSQL_INJECTION || "vulnerable",

  // A06: Insecure Design — predictable sequential reset tokens
  INSECURE_DESIGN: process.env.VULN_INSECURE_DESIGN || "vulnerable",

  // A07: Authentication Failures — no rate limiting on login
  AUTH_FAIL: process.env.VULN_AUTH_FAIL || "vulnerable",

  // A08: Software/Data Integrity Failures — unsigned import payload trusted
  INTEGRITY_FAIL: process.env.VULN_INTEGRITY_FAIL || "vulnerable",

  // A09: Security Logging & Alerting Failures — promote action not logged
  LOG_FAIL: process.env.VULN_LOG_FAIL || "vulnerable",

  // A10: Mishandling of Exceptional Conditions — fail-open on malformed ObjectId
  EXCEPT_FAIL: process.env.VULN_EXCEPT_FAIL || "vulnerable",
};
