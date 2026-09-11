import express from "express";
import Profile from "../models/profile.js";
import { requireAuth } from "../middleware/requireAuth.js";

const router = express.Router();

// VULNERABLE: trusts client-supplied `role` with no validation.
router.post("/complete", requireAuth, async (req, res) => {pp
  try {
    const userId = req.user.id;
    const { role, department } = req.body;

    const existing = await Profile.findOne({ userId });
    if (existing) {
      return res.status(409).json({ error: "Profile already exists" });
    }

    const profile = await Profile.create({
      userId,
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