require("dotenv").config();
const express   = require("express");
const cors      = require("cors");
const mongoose  = require("mongoose");
const rateLimit = require("express-rate-limit");
const scanRoutes = require("./routes/scan");

const app  = express();
const PORT = process.env.PORT || 3001;

// ── Middleware ──────────────────────────────────────────────────
app.use(cors({ origin: "http://localhost:5173" }));
app.use(express.json());

// Rate limiting — max 60 requests per minute per IP
app.use(
  "/api/",
  rateLimit({
    windowMs: 60 * 1000,
    max: 60,
    message: { error: "Too many requests, please slow down." },
  })
);

// ── Routes ──────────────────────────────────────────────────────
app.use("/api", scanRoutes);

app.get("/api/health", (req, res) => {
  res.json({
    status:   "ok",
    mongo:    mongoose.connection.readyState === 1 ? "connected" : "disconnected",
    ml_url:   process.env.ML_API_URL,
  });
});

// ── MongoDB ─────────────────────────────────────────────────────
mongoose
  .connect(process.env.MONGO_URI || "mongodb://localhost:27017/threatlens")
  .then(() => {
    console.log("[MongoDB] Connected");
    app.listen(PORT, () => {
      console.log(`[Server]  Running on http://localhost:${PORT}`);
      console.log(`[ML API]  Forwarding to ${process.env.ML_API_URL || "http://localhost:5000"}`);
    });
  })
  .catch((err) => {
    console.error("[MongoDB] Connection failed:", err.message);
    process.exit(1);
  });
