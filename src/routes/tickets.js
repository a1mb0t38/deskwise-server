import express from "express";
import Ticket from "../models/Ticket.js";
import Profile from "../models/profile.js";
import requireAuth from "../middleware/requireAuth.js";

const router = express.Router();

// Helper: fetch the caller's profile (role) once per request
async function getCallerProfile(userId) {
  return Profile.findOne({ userId });
}

// POST /api/tickets — create a ticket (any authenticated user)
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

// GET /api/tickets — list tickets, scoped by role
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

// GET /api/tickets/:id — get a single ticket, scoped by role
router.get("/:id", requireAuth, async (req, res) => {
  try {
    const ticket = await Ticket.findById(req.params.id);
    if (!ticket) {
      return res.status(404).json({ error: "Ticket not found" });
    }

    const profile = await getCallerProfile(req.user.id);
    const isStaff = profile && (profile.role === "agent" || profile.role === "admin");
    const isOwner = ticket.createdBy.toString() === req.user.id;

    if (!isStaff && !isOwner) {
      return res.status(403).json({ error: "Forbidden" });
    }

    return res.json(ticket);
  } catch (err) {
    console.error("Error fetching ticket:", err);
    return res.status(500).json({ error: "Failed to fetch ticket" });
  }
});

// PATCH /api/tickets/:id — update status/priority/assignment (agent/admin only)
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

// DELETE /api/tickets/:id — admin only
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