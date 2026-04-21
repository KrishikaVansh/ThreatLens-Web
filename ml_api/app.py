"""
ThreatLens - Flask API
======================
Endpoints:
  POST /predict        - predict one or multiple URLs
  GET  /health         - check server + model status
  GET  /               - simple web UI to test URLs in browser

Install & Run:
  pip install flask
  python app.py
"""

import re
import os
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# ===========================================================
# MODEL LOADING  (loaded once at startup, reused for all requests)
# ===========================================================

def find_results_dir(start):
    current = os.path.abspath(start)
    for _ in range(6):
        candidate = os.path.join(current, "threatlens_results")
        if os.path.isdir(candidate):
            return candidate
        current = os.path.dirname(current)
    raise FileNotFoundError("Could not find 'threatlens_results' folder. Run trainModel.py first.")

def find_latest_model(results_dir):
    runs = sorted([
        d for d in os.listdir(results_dir)
        if os.path.isdir(os.path.join(results_dir, d))
    ], reverse=True)
    for run in runs:
        pkl = os.path.join(results_dir, run, "threatlens_phishing_ensemble.pkl")
        if os.path.exists(pkl):
            return pkl
    raise FileNotFoundError("No .pkl found. Run trainModel.py first.")

# RESULTS_DIR = find_results_dir(os.path.dirname(os.path.abspath(__file__)))
# MODEL_PATH  = find_latest_model(RESULTS_DIR)
MODEL_PATH=r"C:\Users\kinu\Downloads\ThreatLens-Web\ThreatLens-Web\ml_api\threatlens_phishing_ensemble.pkl"
print(f"[ThreatLens] Loading model from: {MODEL_PATH}")
BUNDLE    = joblib.load(MODEL_PATH)
SCALER    = BUNDLE["scaler"]
TFIDF     = BUNDLE["tfidf"]
SOFT_VOTE = BUNDLE["soft_vote"]
LR        = BUNDLE["lr"]
THRESHOLD = BUNDLE.get("threshold", 0.5)
print(f"[ThreatLens] Model loaded. Threshold = {THRESHOLD}")

# ===========================================================
# FEATURE EXTRACTION  (must match trainModel.py exactly)
# ===========================================================
ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work"}
BRAND_KEYWORDS  = ["paypal", "amazon", "apple", "google", "microsoft",
                   "netflix", "facebook", "instagram", "bank", "secure"]
TRUSTED_DOMAINS = {
    "google.com", "google.co.in", "google.co.uk",
    "amazon.com", "amazon.in", "amazon.co.uk",
    "apple.com", "microsoft.com", "paypal.com",
    "facebook.com", "instagram.com", "netflix.com",
    "github.com", "stackoverflow.com", "youtube.com",
    "twitter.com", "x.com", "linkedin.com", "reddit.com",
    "wikipedia.org", "yahoo.com", "bing.com",
}

def get_registered_domain(host):
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()

def extract_url_features(urls):
    rows = []
    for url in urls:
        url = str(url).strip()
        full = url if "//" in url else "http://" + url
        try:
            parsed = urlparse(full)
            host   = parsed.netloc or ""
            path   = parsed.path   or ""
        except Exception:
            host = path = ""

        reg_domain = get_registered_domain(host)
        is_trusted = reg_domain in TRUSTED_DOMAINS
        has_suspicious_tld = int(any(host.endswith(t) for t in SUSPICIOUS_TLDS))
        subdomains = host.split(".")[:-2] if host else []
        has_brand_kw = 0 if is_trusted else int(any(k in url.lower() for k in BRAND_KEYWORDS))

        rows.append({
            "url_len":            len(url),
            "host_len":           len(host),
            "path_len":           len(path),
            "num_dots":           url.count("."),
            "num_hyphens":        url.count("-"),
            "num_digits":         sum(c.isdigit() for c in url),
            "num_special":        sum(not c.isalnum() for c in url),
            "num_slashes":        url.count("/"),
            "num_subdomains":     len(subdomains),
            "num_params":         url.count("?") + url.count("&"),
            "num_at":             url.count("@"),
            "num_percent":        url.count("%"),
            "num_eq":             url.count("="),
            "has_https":          int(url.lower().startswith("https")),
            "has_ip":             int(bool(ip_pattern.match(host))),
            "has_at":             int("@" in url),
            "has_double_slash":   int("//" in url[8:]),
            "has_suspicious_tld": has_suspicious_tld,
            "has_brand_kw":       has_brand_kw,
            "digit_ratio":        sum(c.isdigit() for c in url) / max(len(url), 1),
            "special_ratio":      sum(not c.isalnum() for c in url) / max(len(url), 1),
        })
    return pd.DataFrame(rows)

# ===========================================================
# CORE PREDICTION
# ===========================================================
def run_prediction(urls):
    X_feat   = extract_url_features(urls)
    X_dense  = SCALER.transform(X_feat)
    X_tfidf  = TFIDF.transform(urls)

    sv_prob  = SOFT_VOTE.predict_proba(X_dense)[:, 1]
    lr_prob  = LR.predict_proba(X_tfidf)[:, 1]
    final_p  = 0.55 * sv_prob + 0.45 * lr_prob

    results = []
    for url, p in zip(urls, final_p):
        try:
            _host = urlparse(url if "//" in url else "http://" + url).netloc
            _reg  = get_registered_domain(_host)
        except Exception:
            _reg = ""

        if _reg in TRUSTED_DOMAINS:
            results.append({
                "url":          url,
                "verdict":      "SAFE",
                "reason":       "whitelisted",
                "p_legitimate": 0.99,
                "p_phishing":   0.01,
                "confidence":   0.99,
            })
        else:
            is_safe = bool(p >= THRESHOLD)
            results.append({
                "url":          url,
                "verdict":      "SAFE" if is_safe else "PHISHING",
                "reason":       "model",
                "p_legitimate": round(float(p),       4),
                "p_phishing":   round(float(1 - p),   4),
                "confidence":   round(float(p) if is_safe else float(1 - p), 4),
            })
    return results

# ===========================================================
# ROUTES
# ===========================================================

# --- Health check -----------------------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":    "ok",
        "model":     MODEL_PATH,
        "threshold": THRESHOLD,
    })


# --- Predict (JSON API) ------------------------------------
@app.route("/predict", methods=["POST"])
def predict():
    """
    Accepts JSON body in two formats:

    Single URL:
        { "url": "https://example.com" }

    Multiple URLs:
        { "urls": ["https://example.com", "http://phish.tk/login"] }

    Returns:
        { "results": [ { url, verdict, p_legitimate, p_phishing, confidence, reason }, ... ] }
    """
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    # Accept both "url" (single) and "urls" (list)
    if "url" in data:
        urls = [data["url"]]
    elif "urls" in data:
        urls = data["urls"]
    else:
        return jsonify({"error": 'JSON must contain "url" or "urls" key'}), 400

    if not isinstance(urls, list) or len(urls) == 0:
        return jsonify({"error": '"urls" must be a non-empty list'}), 400

    if len(urls) > 100:
        return jsonify({"error": "Max 100 URLs per request"}), 400

    try:
        results = run_prediction(urls)
        return jsonify({
            "count":   len(results),
            "results": results,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# --- Simple browser UI ------------------------------------
UI_HTML = """
<!DOCTYPE html>
<html>
<head>
  <title>ThreatLens - URL Checker</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: #0f1117; color: #e0e0e0; min-height: 100vh; padding: 40px 20px; }
    h1 { text-align: center; font-size: 2rem; margin-bottom: 4px; color: #fff; }
    .sub { text-align: center; color: #888; margin-bottom: 32px; font-size: 0.9rem; }
    .card { background: #1a1d27; border-radius: 12px; padding: 28px; max-width: 700px; margin: 0 auto 24px; }
    textarea { width: 100%; background: #0f1117; border: 1px solid #333; border-radius: 8px;
               color: #e0e0e0; padding: 12px; font-size: 0.95rem; resize: vertical; min-height: 120px; }
    button { margin-top: 14px; width: 100%; padding: 12px; background: #4f46e5;
             border: none; border-radius: 8px; color: #fff; font-size: 1rem; cursor: pointer; font-weight: 600; }
    button:hover { background: #4338ca; }
    button:disabled { background: #333; cursor: not-allowed; }
    .result-row { display: flex; align-items: center; gap: 12px; padding: 12px 16px;
                  border-radius: 8px; margin-bottom: 8px; background: #0f1117; }
    .badge { padding: 4px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: 700; white-space: nowrap; }
    .safe     { background: #14532d; color: #4ade80; }
    .phishing { background: #7f1d1d; color: #f87171; }
    .url-text { font-size: 0.85rem; word-break: break-all; flex: 1; color: #ccc; }
    .probs { font-size: 0.78rem; color: #888; white-space: nowrap; text-align: right; }
    .probs span { display: block; }
    #results { max-width: 700px; margin: 0 auto; }
    .spinner { text-align: center; color: #888; padding: 20px; display: none; }
    .error-msg { background: #7f1d1d; color: #f87171; padding: 12px 16px; border-radius: 8px; margin-bottom: 8px; }
  </style>
</head>
<body>
  <h1>ThreatLens</h1>
  <p class="sub">Phishing URL Detection &mdash; Paste one URL per line</p>

  <div class="card">
    <textarea id="urlInput" placeholder="https://www.google.com&#10;http://paypal-secure-login.tk/confirm&#10;https://github.com/openai/gpt-4"></textarea>
    <button id="checkBtn" onclick="checkURLs()">Check URLs</button>
  </div>

  <div class="spinner" id="spinner">Analyzing...</div>
  <div id="results"></div>

  <script>
    async function checkURLs() {
      const raw = document.getElementById('urlInput').value.trim();
      if (!raw) return;
      const urls = raw.split('\\n').map(u => u.trim()).filter(Boolean);

      document.getElementById('results').innerHTML = '';
      document.getElementById('spinner').style.display = 'block';
      document.getElementById('checkBtn').disabled = true;

      try {
        const res = await fetch('/predict', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ urls })
        });
        const data = await res.json();
        document.getElementById('spinner').style.display = 'none';
        document.getElementById('checkBtn').disabled = false;

        if (data.error) {
          document.getElementById('results').innerHTML =
            `<div class="error-msg">${data.error}</div>`;
          return;
        }

        let html = '';
        for (const r of data.results) {
          const isSafe = r.verdict === 'SAFE';
          html += `
            <div class="result-row">
              <span class="badge ${isSafe ? 'safe' : 'phishing'}">${r.verdict}</span>
              <span class="url-text">${r.url}</span>
              <span class="probs">
                <span>Safe: ${(r.p_legitimate * 100).toFixed(1)}%</span>
                <span>Phish: ${(r.p_phishing * 100).toFixed(1)}%</span>
              </span>
            </div>`;
        }
        document.getElementById('results').innerHTML = html;
      } catch (e) {
        document.getElementById('spinner').style.display = 'none';
        document.getElementById('checkBtn').disabled = false;
        document.getElementById('results').innerHTML =
          `<div class="error-msg">Request failed: ${e.message}</div>`;
      }
    }

    // Allow Ctrl+Enter to submit
    document.getElementById('urlInput').addEventListener('keydown', e => {
      if (e.ctrlKey && e.key === 'Enter') checkURLs();
    });
  </script>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def index():
    return render_template_string(UI_HTML)


# ===========================================================
# RUN
# ===========================================================
if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("  ThreatLens API running!")
    print("  Browser UI : http://127.0.0.1:5000")
    print("  Health     : http://127.0.0.1:5000/health")
    print("  API        : POST http://127.0.0.1:5000/predict")
    print("=" * 50 + "\n")
    app.run(debug=False, host="0.0.0.0", port=5000)