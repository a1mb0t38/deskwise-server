import Profile from "../models/Profile.js";

/**
 * requireAdminSecure — correct admin middleware.
 *
 * Looks up the authenticated user's role from the database rather than
 * trusting a client-supplied header. Used for legitimately-gated routes
 * (e.g. GET /api/admin/audit-log) that should NOT be exploitable.
 *
 * Contrast with requireAdmin.js (the deliberately broken one used for
 * the A01-BFLA challenge target).
 */
async function requireAdminSecure(req, res, next) {
  try {
    const profile = await Profile.findOne({ userId: req.user.id });

    if (!profile || profile.role !== "admin") {
      return res.status(403).json({ error: "Forbidden" });
    }

    req.profile = profile;
    next();
  } catch (err) {
    console.error("requireAdminSecure error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
}

export default requireAdminSecure;
