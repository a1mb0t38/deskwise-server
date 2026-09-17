import AuditLog from "../models/AuditLog.js";

/**
 * auditLog — middleware factory that writes an entry to the AuditLog collection.
 *
 * Usage:
 *   router.patch("/promote", requireAuth, auditLog("PROMOTE_USER"), handler);
 *
 * VULNERABILITY NOTE (A09 — Security Logging & Alerting Failures):
 * This middleware is intentionally NOT applied to PATCH /api/profile/promote,
 * creating a gap in the audit trail. The GET /api/admin/audit-log endpoint
 * will therefore contain no record of privilege escalation actions performed
 * through that route — demonstrating the logging blindspot.
 */
export function auditLog(action) {
  return async function auditLogMiddleware(req, res, next) {
    try {
      await AuditLog.create({
        action,
        performedBy: req.user?.id || "unknown",
        targetId: req.params?.id || req.body?.userId || null,
        details: {
          method: req.method,
          path: req.path,
          body: req.body,
        },
      });
    } catch (err) {
      // Non-fatal: log errors should not block the request
      console.error("Audit log write failed:", err.message);
    }
    next();
  };
}

export default auditLog;
