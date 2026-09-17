import express from "express";
import Profile from "../models/Profile.js";
import { requireAuth } from "../middleware/requireAuth.js";
import requireAdmin from "../middleware/requireAdmin.js";
import requireAdminSecure from "../middleware/requireAdminSecure.js";
import { VULN_MODES } from "../config/vulnModes.js";

const router = express.Router();

/**
 * GET /api/profile/me — Get authenticated user's profile
 *
 * VULNERABILITY (A04 — Cryptographic Failures, CWE-328):
 * In vulnerable mode, internalNotes is exposed in its unsalted MD5 hex format
 * (e.g. "a54fd98485295c2bf318db497e59f8a3"). The player can crack this hash offline
 * using MD5 rainbow tables to reveal the plaintext flag CRYPTOFAIL{w34k_md5_n0_s4lt_ez_crack}.
 */
router.get("/me", requireAuth, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.user.id });
    if (!profile) {
      return res.status(404).json({ error: "Profile not found" });
    }

    const result = profile.toObject();
    if (VULN_MODES.CRYPTO_FAIL === "patched") {
      delete result.internalNotesMd5;
    }

    return res.json(result);
  } catch (err) {
    console.error("Error fetching profile:", err);
    return res.status(500).json({ error: "Failed to fetch profile" });
  }
});

/**
 * POST /api/profile/complete — Complete initial profile setup
 *
 * VULNERABILITY (A01 — Mass Assignment / BFLA, CWE-915):
 * When VULN_MODES.BFLA_PROMOTE is "vulnerable", client-supplied `role` is untrusted
 * and saved directly without validation, allowing a normal user to assign themselves "admin".
 */
router.post("/complete", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { role, department } = req.body;

    // Check if profile already exists
    const existing = await Profile.findOne({ userId });
    if (existing) {
      return res.status(409).json({ error: "Profile already exists" });
    }

    let assignedRole = "user";
    if (VULN_MODES.BFLA_PROMOTE === "vulnerable") {
      // VULNERABLE: accepts client-supplied role
      assignedRole = role || "user";
    }

    const profile = await Profile.create({
      userId,
      role: assignedRole,
      department: department || "General",
    });

    return res.status(201).json(profile);
  } catch (err) {
    console.error("Profile creation error:", err);
    return res.status(500).json({ error: "Failed to create profile" });
  }
});

/**
 * PATCH /api/profile/promote — Admin endpoint to promote user roles
 *
 * VULNERABILITY (A01 — BFLA via header trust & A09 — Lack of Logging):
 * 1. Controlled by `requireAdmin` which trusts `X-User-Role: admin` header when vulnerable.
 * 2. Does NOT log to AuditLog, creating a security logging failure (A09).
 */
router.patch(
  "/promote",
  requireAuth,
  VULN_MODES.BFLA_PROMOTE === "patched" ? requireAdminSecure : requireAdmin,
  async (req, res) => {
    try {
      const { userId, role } = req.body;

      if (!userId || !role) {
        return res.status(400).json({ error: "userId and role are required" });
      }

      if (!["user", "agent", "admin"].includes(role)) {
        return res.status(400).json({ error: "Invalid role" });
      }

      const profile = await Profile.findOneAndUpdate(
        { userId },
        { role },
        { new: true }
      );

      if (!profile) {
        return res.status(404).json({ error: "Profile not found" });
      }

      // NOTE: Intentionally missing AuditLog.create() here for A09 demonstration

      return res.json(profile);
    } catch (err) {
      console.error("Error promoting user:", err);
      return res.status(500).json({ error: "Failed to promote user" });
    }
  }
);

export default router;