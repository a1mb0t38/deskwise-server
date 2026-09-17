import express from "express";
import mongoose from "mongoose";
import crypto from "crypto";
import Ticket from "../models/Ticket.js";
import Profile from "../models/Profile.js";
import { requireAuth } from "../middleware/requireAuth.js";
import { VULN_MODES } from "../config/vulnModes.js";
import { FLAG_REGISTRY } from "../config/flags.js";

const router = express.Router();

// Helper: fetch the caller's profile (role) once per request
async function getCallerProfile(userId) {
  return Profile.findOne({ userId });
}

/**
 * POST /api/tickets — create a ticket (any authenticated user)
 */
router.post("/", requireAuth, async (req, res) => {
  try {
    const { title, description, priority } = req.body;

    if (!title || !description) {
      return res.status(400).json({ error: "title and description are required" });
    }

    const ticket = await Ticket.create({
      title,
      description,
      priority: priority || "medium",
      createdBy: req.user.id,
    });

    return res.status(201).json(ticket);
  } catch (err) {
    console.error("Error creating ticket:", err);
    return res.status(500).json({ error: "Failed to create ticket" });
  }
});

/**
 * GET /api/tickets/search — Search tickets
 *
 * VULNERABILITY (A05 — Injection / NoSQL Injection, CWE-943):
 * When VULN_MODES.NOSQL_INJECTION is "vulnerable", req.query is passed directly
 * into Ticket.find() without sanitization. Passing Mongo operators like `?title[$ne]=null`
 * allows attackers to bypass search criteria and retrieve all tickets (including seeded flag tickets).
 *
 * Exploit:
 *   GET /api/tickets/search?title[$ne]=null
 *   Returns all tickets, including the hidden ticket with INJECT{m0ng0_0p3r4t0r_byp4ss}.
 */
router.get("/search", requireAuth, async (req, res) => {
  try {
    let query = {};

    if (VULN_MODES.NOSQL_INJECTION === "vulnerable") {
      // VULNERABLE: Direct query assignment without type checking / sanitization
      query = req.query;
    } else {
      // PATCHED: Enforce string type to prevent Mongo operator injection
      if (req.query.title) {
        query.title = String(req.query.title);
      }
      if (req.query.status) {
        query.status = String(req.query.status);
      }
    }

    const tickets = await Ticket.find(query);
    return res.json(tickets);
  } catch (err) {
    console.error("Search error:", err);
    return res.status(500).json({ error: "Search failed" });
  }
});

/**
 * POST /api/tickets/import — Bulk ticket import endpoint
 *
 * VULNERABILITY (A08 — Software and Data Integrity Failures, CWE-345):
 * When VULN_MODES.INTEGRITY_FAIL is "vulnerable", the server accepts JSON payloads
 * with `verified: true` without validating any HMAC signature. An attacker can submit
 * a forged import payload claiming to be verified.
 *
 * Exploit:
 *   POST /api/tickets/import
 *   Body: { "verified": true, "title": "Forged Ticket", "description": "test" }
 *   Returns INTEGRITYFAIL{no_hmac_4ny0ne_c4n_f0rge_imports}
 */
router.post("/import", requireAuth, async (req, res) => {
  try {
    const { title, description, verified } = req.body;

    if (VULN_MODES.INTEGRITY_FAIL === "vulnerable") {
      // VULNERABLE: Blindly trust `verified` flag in payload without signature verification
      if (verified === true) {
        const flagInfo = FLAG_REGISTRY.INTEGRITY_FAIL;
        return res.status(200).json({
          message: "Import accepted (Integrity Check Bypassed)",
          flag: flagInfo.flag,
          vuln: flagInfo.name,
        });
      }
    } else {
      // PATCHED: Require HMAC signature header verification
      const signature = req.headers["x-signature"];
      const secret = process.env.IMPORT_HMAC_SECRET || "supersecrethmackey123";
      const expectedSignature = crypto
        .createHmac("sha256", secret)
        .update(JSON.stringify(req.body))
        .digest("hex");

      if (!signature || signature !== expectedSignature) {
        return res.status(401).json({ error: "Invalid or missing payload signature" });
      }
    }

    const ticket = await Ticket.create({
      title: title || "Imported Ticket",
      description: description || "Imported via integration API",
      createdBy: req.user.id,
    });

    return res.status(201).json({ message: "Import successful", ticket });
  } catch (err) {
    console.error("Import error:", err);
    return res.status(500).json({ error: "Import failed" });
  }
});

/**
 * GET /api/tickets — list tickets, scoped by role
 */
router.get("/", requireAuth, async (req, res) => {
  try {
    const profile = await getCallerProfile(req.user.id);
    const isStaff = profile && (profile.role === "agent" || profile.role === "admin");

    // Regular users only see their own tickets; agents/admins see all
    const filter = isStaff ? {} : { createdBy: req.user.id };

    const tickets = await Ticket.find(filter).sort({ createdAt: -1 });
    return res.json(tickets);
  } catch (err) {
    console.error("Error listing tickets:", err);
    return res.status(500).json({ error: "Failed to list tickets" });
  }
});

/**
 * GET /api/tickets/:id — get a single ticket
 *
 * VULNERABILITY (A01 — BOLA / IDOR, CWE-639) & (A10 — Exceptional Conditions Fail-Open, CWE-703):
 *
 * BOLA (A01):
 * When VULN_MODES.IDOR_TICKETS is "vulnerable", ticket access checks are bypassed. Any user
 * can fetch any ticket by ID. Accessing the seeded admin flag ticket reveals IDOR{...}.
 *
 * Exceptional Conditions (A10):
 * If a malformed ID (e.g. invalid ObjectId format like "invalid-id-format") is passed,
 * an error occurs during lookup. In vulnerable mode, the catch block FAILS OPEN:
 * instead of returning 400 Bad Request or 403, it catches the error and grants access / returns
 * the EXCEPTFAIL{...} flag!
 */
router.get("/:id", requireAuth, async (req, res) => {
  const { id } = req.params;

  // A10: Exception handling check
  if (VULN_MODES.EXCEPT_FAIL === "vulnerable") {
    try {
      // Validate ObjectId explicitly inside try block
      if (!mongoose.Types.ObjectId.isValid(id)) {
        throw new Error("Invalid ObjectId format passed to ticket lookup");
      }
    } catch (err) {
      // VULNERABLE FAIL-OPEN: The catch block fails OPEN instead of returning 400/403!
      console.warn("Auth/validation error caught, failing open:", err.message);
      const flagInfo = FLAG_REGISTRY.EXCEPT_FAIL;
      return res.status(200).json({
        message: "Exception handled (Fails Open Granted Access)",
        flag: flagInfo.flag,
        vuln: flagInfo.name,
      });
    }
  }

  try {
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid ticket ID format" });
    }

    const ticket = await Ticket.findById(id);
    if (!ticket) {
      return res.status(404).json({ error: "Ticket not found" });
    }

    // A01: BOLA / IDOR Check
    if (VULN_MODES.IDOR_TICKETS === "patched") {
      const profile = await getCallerProfile(req.user.id);
      const isStaff = profile && (profile.role === "agent" || profile.role === "admin");
      const isOwner = ticket.createdBy.toString() === req.user.id;

      if (!isStaff && !isOwner) {
        return res.status(403).json({ error: "Forbidden" });
      }
    }

    return res.json(ticket);
  } catch (err) {
    console.error("Error fetching ticket:", err);
    return res.status(500).json({ error: "Failed to fetch ticket" });
  }
});

/**
 * PATCH /api/tickets/:id — update status/priority/assignment (agent/admin only)
 */
router.patch("/:id", requireAuth, async (req, res) => {
  try {
    const profile = await getCallerProfile(req.user.id);
    const isStaff = profile && (profile.role === "agent" || profile.role === "admin");

    if (!isStaff) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const { status, priority, assignedTo } = req.body;
    const updates = {};
    if (status) updates.status = status;
    if (priority) updates.priority = priority;
    if (assignedTo !== undefined) updates.assignedTo = assignedTo;

    const ticket = await Ticket.findByIdAndUpdate(req.params.id, updates, {
      new: true,
      runValidators: true,
    });

    if (!ticket) {
      return res.status(404).json({ error: "Ticket not found" });
    }

    return res.json(ticket);
  } catch (err) {
    console.error("Error updating ticket:", err);
    return res.status(500).json({ error: "Failed to update ticket" });
  }
});

/**
 * DELETE /api/tickets/:id — admin only
 */
router.delete("/:id", requireAuth, async (req, res) => {
  try {
    const profile = await getCallerProfile(req.user.id);
    const isAdmin = profile && profile.role === "admin";

    if (!isAdmin) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const ticket = await Ticket.findByIdAndDelete(req.params.id);
    if (!ticket) {
      return res.status(404).json({ error: "Ticket not found" });
    }

    return res.status(204).send();
  } catch (err) {
    console.error("Error deleting ticket:", err);
    return res.status(500).json({ error: "Failed to delete ticket" });
  }
});

export default router;