import mongoose from "mongoose";

const solvedFlagSchema = new mongoose.Schema({
  userId: {
    type: String, // Better Auth user IDs are strings
    required: true,
  },
  vulnId: {
    type: String,
    required: true,
  },
  solvedAt: {
    type: Date,
    default: Date.now,
  },
});

// Prevent duplicate solve entries
solvedFlagSchema.index({ userId: 1, vulnId: 1 }, { unique: true });

const SolvedFlag = mongoose.model("SolvedFlag", solvedFlagSchema);
export default SolvedFlag;
