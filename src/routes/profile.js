import express from "express";
import Profile from "../models/profile.js";
import { requireAuth } from "../middleware/requireAuth.js";

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

export default router;