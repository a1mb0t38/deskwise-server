import mongoose from "mongoose";

/**
 * AuditLog — records security-relevant admin actions.
 *
 * VULNERABILITY NOTE (A09):
 * The PATCH /api/profile/promote route intentionally does NOT write
 * an audit log entry, creating a blind spot in the audit trail.
 * The GET /api/admin/audit-log endpoint will therefore show no record
 * of any privilege escalation performed through that route.
 */
const auditLogSchema = new mongoose.Schema({
  action: {
    type: String,
    required: true,
  },
  performedBy: {
    type: String, // Better Auth user ID (string)
    required: true,
  },
  targetId: {
    type: String,
    default: null,
  },
  details: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
});

const AuditLog = mongoose.model("AuditLog", auditLogSchema);
export default AuditLog;
