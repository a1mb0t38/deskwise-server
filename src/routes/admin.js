import express from "express";
import { requireAuth } from "../middleware/requireAuth.js";
import requireAdmin from "../middleware/requireAdmin.js";
import requireAdminSecure from "../middleware/requireAdminSecure.js";
import AuditLog from "../models/AuditLog.js";
import { VULN_MODES } from "../config/vulnModes.js";
import { FLAG_REGISTRY } from "../config/flags.js";

const router = express.Router();

/**
 * GET /api/admin/flag
 *
 * VULNERABILITY (A01 — Broken Function Level Authorization / BFLA, CWE-285):
 * This admin-only route is guarded by the broken `requireAdmin` middleware,
 * which checks the client-supplied `X-User-Role: admin` header rather than
 * looking up the user's actual role in the database.
 *
 * Exploit:
 *   curl -H "X-User-Role: admin" -H "Authorization: Bearer <token>" \
 *        http://localhost:5000/api/admin/flag
 *
 * Fix (VULN_MODES.BFLA_PROMOTE = "patched"): replace requireAdmin with
 * requireAdminSecure, which does a real DB lookup.
 *
 * Flag: BFLA{x_user_role_h34der_bypasses_admin_check}
 */
router.get(
  "/flag",
  requireAuth,
  // Intentionally using the broken middleware (A01-BFLA target)
  VULN_MODES.BFLA_PROMOTE === "patched" ? requireAdminSecure : requireAdmin,
  (req, res) => {
    const { flag, name } = FLAG_REGISTRY.BFLA_PROMOTE;
    return res.json({
      message: "Welcome, admin. Here is your prize.",
      flag,
      vuln: name,
    });
  }
);

/**
 * GET /api/admin/audit-log
 *
 * Returns recent audit log entries. Uses the SECURE admin middleware (DB lookup).
 *
 * VULNERABILITY NOTE (A09 — Security Logging & Alerting Failures):
 * This route correctly gates access, but the PATCH /api/profile/promote route
 * never writes to the audit log. Players can notice that privilege escalation
 * actions are invisible in this log — that absence IS the vulnerability.
 */
router.get("/audit-log", requireAuth, requireAdminSecure, async (req, res) => {
  try {
    const logs = await AuditLog.find({})
      .sort({ timestamp: -1 })
      .limit(100);

    return res.json({
      logs,
      note:
        "Notice anything missing? Privilege escalation via /api/profile/promote is never logged here.",
    });
  } catch (err) {
    console.error("Audit log fetch error:", err);
    return res.status(500).json({ error: "Failed to fetch audit log" });
  }
});

export default router;
