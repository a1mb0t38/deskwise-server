import mongoose from "mongoose";

const flagSchema = new mongoose.Schema({
  vulnId: {
    type: String,
    required: true,
    unique: true,
  },
  flag: {
    type: String,
    required: true,
  },
  name: {
    type: String,
    required: true,
  },
  description: {
    type: String,
  },
});

const Flag = mongoose.model("Flag", flagSchema);
export default Flag;
