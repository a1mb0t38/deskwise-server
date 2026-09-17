import Profile from "../models/Profile.js";

/**
 * requireAdmin
 *
 * Intended purpose: only allow admins to proceed.
 *
 * VULNERABILITY (Broken Access Control - CWE-807: Reliance on Untrusted
 * Inputs in a Security Decision):
 * This middleware checks the client-supplied `X-User-Role` header instead
 * of looking up the authenticated user's actual role from the database.
 * A request is trusted to self-report its own privilege level.
 *
 * Exploit: any authenticated user can bypass this check entirely by simply
 * setting `X-User-Role: admin` on their request — no privilege escalation
 * via the database is even required, unlike vuln #3.
 *
 * Fix: look up req.user.id in the Profile collection and check the
 * server-recorded role, e.g.:
 *   const profile = await Profile.findOne({ userId: req.user.id });
 *   if (!profile || profile.role !== "admin") {
 *     return res.status(403).json({ error: "Forbidden" });
 *   }
 *   next();
 */
async function requireAdmin(req, res, next) {
  const claimedRole = req.headers["x-user-role"];

  if (claimedRole !== "admin") {
    return res.status(403).json({ error: "Forbidden" });
  }

  next();
}

export default requireAdmin;