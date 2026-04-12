const mongoose = require("mongoose");

const scanSchema = new mongoose.Schema(
  {
    url: {
      type: String,
      required: true,
      trim: true,
    },
    verdict: {
      type: String,
      enum: ["SAFE", "PHISHING", "SAFE (whitelisted)"],
      required: true,
    },
    p_legitimate: { type: Number, required: true },
    p_phishing:   { type: Number, required: true },
    confidence:   { type: Number, required: true },
    reason:       { type: String, default: "model" },
    scannedAt:    { type: Date, default: Date.now },
  },
  { timestamps: true }
);

// Index for fast history queries
scanSchema.index({ scannedAt: -1 });
scanSchema.index({ verdict: 1 });

module.exports = mongoose.model("Scan", scanSchema);
