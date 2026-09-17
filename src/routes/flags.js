import express from "express";
import { requireAuth } from "../middleware/requireAuth.js";
import { FLAG_LOOKUP, FLAG_REGISTRY } from "../config/flags.js";
import SolvedFlag from "../models/SolvedFlag.js";

const router = express.Router();

/**
 * POST /api/flags/submit
 *
 * Accepts { flag } and checks it against the known flag registry.
 * On a valid match, creates a SolvedFlag record and returns the vuln name.
 */
router.post("/submit", requireAuth, async (req, res) => {
  try {
    const { flag } = req.body;

    if (!flag || typeof flag !== "string") {
      return res.status(400).json({ error: "flag is required" });
    }

    const vulnId = FLAG_LOOKUP[flag.trim()];

    if (!vulnId) {
      return res.status(400).json({
        success: false,
        message: "Incorrect flag. Keep trying!",
      });
    }

    const vulnInfo = FLAG_REGISTRY[vulnId];
    const userId = req.user.id;

    // Upsert — ignore duplicate-solve errors gracefully
    let alreadySolved = false;
    try {
      await SolvedFlag.create({ userId, vulnId });
    } catch (err) {
      if (err.code === 11000) {
        alreadySolved = true; // duplicate key — already solved
      } else {
        throw err;
      }
    }

    return res.json({
      success: true,
      alreadySolved,
      vulnId,
      name: vulnInfo.name,
      description: vulnInfo.description,
      message: alreadySolved
        ? "You already solved this one!"
        : "🎉 Correct! Flag accepted.",
    });
  } catch (err) {
    console.error("Flag submit error:", err);
    return res.status(500).json({ error: "Failed to submit flag" });
  }
});

/**
 * GET /api/flags/progress
 *
 * Returns the authenticated user's list of solved challenges.
 */
router.get("/progress", requireAuth, async (req, res) => {
  try {
    const solved = await SolvedFlag.find({ userId: req.user.id }).sort({
      solvedAt: -1,
    });

    const total = Object.keys(FLAG_REGISTRY).length;

    const enriched = solved.map((s) => ({
      vulnId: s.vulnId,
      name: FLAG_REGISTRY[s.vulnId]?.name || s.vulnId,
      description: FLAG_REGISTRY[s.vulnId]?.description || "",
      solvedAt: s.solvedAt,
    }));

    return res.json({
      solved: enriched,
      solvedCount: enriched.length,
      total,
      percentage: Math.round((enriched.length / total) * 100),
    });
  } catch (err) {
    console.error("Progress fetch error:", err);
    return res.status(500).json({ error: "Failed to fetch progress" });
  }
});

export default router;
