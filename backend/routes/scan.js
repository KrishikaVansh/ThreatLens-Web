const express = require("express");
const axios   = require("axios");
const Scan    = require("../models/Scan");

const router = express.Router();
const ML_URL = process.env.ML_API_URL || "http://localhost:5000";

// ── POST /api/check  — single URL ──────────────────────────────
router.post("/check", async (req, res) => {
  const { url } = req.body;
  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "url is required" });
  }

  try {
    // Call Flask ML service
    const mlRes = await axios.post(`${ML_URL}/predict`, { url });
    const result = mlRes.data.results[0];

    // Save to MongoDB
    const scan = await Scan.create({
      url:          result.url,
      verdict:      result.verdict,
      p_legitimate: result.p_legitimate,
      p_phishing:   result.p_phishing,
      confidence:   result.confidence,
      reason:       result.reason || "model",
    });

    res.json({ scan });
  } catch (err) {
    console.error("check error:", err.message);
    res.status(500).json({ error: "ML service unavailable or internal error" });
  }
});

// ── POST /api/bulk  — multiple URLs ────────────────────────────
router.post("/bulk", async (req, res) => {
  const { urls } = req.body;
  if (!Array.isArray(urls) || urls.length === 0) {
    return res.status(400).json({ error: "urls array is required" });
  }
  if (urls.length > 50) {
    return res.status(400).json({ error: "Max 50 URLs per bulk request" });
  }

  try {
    const mlRes = await axios.post(`${ML_URL}/predict`, { urls });
    const results = mlRes.data.results;

    // Save all to MongoDB
    const docs = await Scan.insertMany(
      results.map((r) => ({
        url:          r.url,
        verdict:      r.verdict,
        p_legitimate: r.p_legitimate,
        p_phishing:   r.p_phishing,
        confidence:   r.confidence,
        reason:       r.reason || "model",
      }))
    );

    res.json({ count: docs.length, scans: docs });
  } catch (err) {
    console.error("bulk error:", err.message);
    res.status(500).json({ error: "ML service unavailable or internal error" });
  }
});

// ── GET /api/history  — paginated history ──────────────────────
router.get("/history", async (req, res) => {
  const page    = Math.max(1, parseInt(req.query.page)  || 1);
  const limit   = Math.min(50, parseInt(req.query.limit) || 10);
  const verdict = req.query.verdict; // optional filter: SAFE | PHISHING
  const search  = req.query.search;  // optional URL search

  const query = {};
  if (verdict && ["SAFE", "PHISHING"].includes(verdict)) {
    query.verdict = verdict === "SAFE"
      ? { $in: ["SAFE", "SAFE (whitelisted)"] }
      : "PHISHING";
  }
  if (search) {
    query.url = { $regex: search, $options: "i" };
  }

  try {
    const [scans, total] = await Promise.all([
      Scan.find(query)
        .sort({ scannedAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
      Scan.countDocuments(query),
    ]);

    res.json({
      scans,
      total,
      page,
      pages: Math.ceil(total / limit),
    });
  } catch (err) {
    console.error("history error:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

// ── GET /api/stats  — dashboard numbers ────────────────────────
router.get("/stats", async (req, res) => {
  try {
    const [total, phishing, safe, recent] = await Promise.all([
      Scan.countDocuments(),
      Scan.countDocuments({ verdict: "PHISHING" }),
      Scan.countDocuments({ verdict: { $in: ["SAFE", "SAFE (whitelisted)"] } }),
      // Last 7 days grouped by day
      Scan.aggregate([
        {
          $match: {
            scannedAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) },
          },
        },
        {
          $group: {
            _id: {
              $dateToString: { format: "%Y-%m-%d", date: "$scannedAt" },
            },
            count:    { $sum: 1 },
            phishing: { $sum: { $cond: [{ $eq: ["$verdict", "PHISHING"] }, 1, 0] } },
            safe:     { $sum: { $cond: [{ $ne:  ["$verdict", "PHISHING"] }, 1, 0] } },
          },
        },
        { $sort: { _id: 1 } },
      ]),
    ]);

    res.json({
      total,
      phishing,
      safe,
      phishingRate: total > 0 ? ((phishing / total) * 100).toFixed(1) : 0,
      daily: recent,
    });
  } catch (err) {
    console.error("stats error:", err.message);
    res.status(500).json({ error: "Database error" });
  }
});

// ── DELETE /api/history/:id  — delete one scan ─────────────────
router.delete("/history/:id", async (req, res) => {
  try {
    await Scan.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Delete failed" });
  }
});

module.exports = router;
