import mongoose from "mongoose";

const profileSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "user",
    required: true,
    unique: true,
  },
  role: {
    type: String,
    enum: ["user", "agent", "admin"],
    default: "user",
  },
  department: {
    type: String,
    required: false,
  },

  /**
   * VULNERABILITY (A04 — Cryptographic Failures, CWE-328):
   * internalNotes is stored as an unsalted MD5 hex digest of the original text.
   * MD5 is a broken hash function with no salt, making it trivially reversible
   * via rainbow tables or offline dictionary attacks.
   *
   * Exploit: retrieve internalNotesMd5 from GET /api/profile/me, crack offline
   * (e.g. via CrackStation or hashcat), recover the flag embedded in the note.
   *
   * Fix: use bcrypt or Argon2 with a per-record salt, or encrypt with AES-256-GCM.
   */
  internalNotesMd5: {
    type: String,
    required: false,
    // Stored as unsalted MD5 hex — intentionally weak
  },

  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const Profile = mongoose.model("Profile", profileSchema);

export default Profile;