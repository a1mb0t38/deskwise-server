import express from "express";
import { VULN_MODES } from "../config/vulnModes.js";

const router = express.Router();

/**
 * GET /api/debug/env
 *
 * VULNERABILITY (A02 — Security Misconfiguration, CWE-215):
 * A diagnostics/debug endpoint left active in production mode. When
 * VULN_MODES.MISCONFIG_DEBUG is "vulnerable", it dumps the full
 * process.env object — including secrets, tokens, and the deliberately
 * placed MONGO_ADMIN_TOKEN that contains the A02 flag.
 *
 * Note: process.env is not filtered or redacted in any way.
 *
 * Exploit:
 *   curl http://localhost:5000/api/debug/env
 *   Look for MONGO_ADMIN_TOKEN in the response body.
 *
 * Flag: MISCONFIG{env_vars_exposed_in_production}
 *   (embedded inside the MONGO_ADMIN_TOKEN env var — see .env)
 *
 * Fix (VULN_MODES.MISCONFIG_DEBUG = "patched"): disable this route entirely,
 * returning 404 as if it does not exist.
 */
router.get("/env", (req, res) => {
  if (VULN_MODES.MISCONFIG_DEBUG === "patched") {
    return res.status(404).json({ error: "Not found" });
  }

  // VULNERABLE: dumps entire process.env with no filtering
  return res.json({
    message: "Debug diagnostics — DO NOT expose in production",
    environment: process.env,
    nodeVersion: process.version,
    platform: process.platform,
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
  });
});

/**
 * GET /api/debug/error-test
 *
 * Triggers an unhandled error to demonstrate verbose stack-trace leakage
 * in the global error handler when VULN_MODE is vulnerable.
 */
router.get("/error-test", (req, res, next) => {
  if (VULN_MODES.MISCONFIG_DEBUG === "patched") {
    return res.status(404).json({ error: "Not found" });
  }

  // Intentionally throw to exercise the verbose error handler
  throw new Error(
    "Intentional test error — stack trace should NOT appear in production responses"
  );
});

export default router;
