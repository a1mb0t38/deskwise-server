import express from "express";
import Profile from "../models/profile.js";
import { requireAuth } from "../middleware/requireAuth.js";
import requireAdmin from "../middleware/requireAdmin.js";

const router = express.Router();

// VULNERABLE: trusts client-supplied `role` with no validation.
router.post("/complete", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    // const { department } = req.body;  role intentionally NOT destructured from client input
    const { role, department } = req.body; // <-- unguarded, this is the vuln

    // Check if profile already exists for the user
    const existing = await Profile.findOne({ userId });
    if (existing) {
      return res.status(409).json({ error: "Profile already exists" });
    }

    const profile = await Profile.create({
      userId,
      // role: "user", // <-- this should be hardcoded or validated, not taken from req.body
      role, // <-- unguarded, this is the vuln
      department,
    });

    res.status(201).json(profile);
  } catch (err) {
    console.error("Profile creation error:", err);
    res.status(500).json({ error: "Failed to create profile" });
  }
});

router.patch("/promote", requireAuth, requireAdmin, async (req, res) => {
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

    return res.json(profile);
  } catch (err) {
    console.error("Error promoting user:", err);
    return res.status(500).json({ error: "Failed to promote user" });
  }
});

export default router;