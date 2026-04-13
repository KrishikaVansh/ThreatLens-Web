import { useState } from "react";
import { checkURL } from "../utils/api";
import styles from "./Scan.module.css";

export default function Scan() {
  const [url, setUrl]         = useState("");
  const [result, setResult]   = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState("");

  async function handleCheck(e) {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true); setError(""); setResult(null);
    try {
      const res = await checkURL(url.trim());
      setResult(res.data.scan);
    } catch (err) {
      setError(err.response?.data?.error || "Failed to connect. Is the backend running?");
    } finally {
      setLoading(false);
    }
  }

  const isSafe = result && result.verdict !== "PHISHING";
  const riskScore = result ? Math.round(result.p_phishing * 100) : 0;

  return (
    <div className={styles.page}>
      <div className={styles.top}>
        <span className={styles.pill}>Forensic URL analysis</span>
        <h1 className={styles.title}>Scan a URL</h1>
        <p className={styles.sub}>Paste any link below — our ML ensemble will analyse it in under a second.</p>
      </div>

      <div className={styles.card}>
        <form onSubmit={handleCheck}>
          <label className={styles.label}>URL to scan</label>
          <div className={styles.inputRow}>
            <input
              className={styles.input}
              type="text"
              placeholder="https://example.com/path?query=value"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              spellCheck={false}
            />
            <button className={styles.btn} disabled={loading}>
              {loading ? <span className={styles.spinner}/> : null}
              {loading ? "Scanning…" : "Scan Now"}
            </button>
          </div>
        </form>

        <div className={styles.examples}>
          <span className={styles.exLabel}>Try:</span>
          {["https://www.google.com","http://paypal-secure-login.tk/confirm","https://github.com/openai/gpt-4"].map(u => (
            <button key={u} className={styles.exBtn} onClick={() => setUrl(u)}>{u}</button>
          ))}
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {result && (
        <div className={`${styles.result} ${isSafe ? styles.resultSafe : styles.resultPhish}`}>
          <div className={styles.resultHeader}>
            <div>
              <div className={styles.resultUrl}>{result.url}</div>
              <div className={styles.resultTime}>{new Date(result.scannedAt || Date.now()).toLocaleString()}</div>
            </div>
            <span className={`${styles.verdict} ${isSafe ? styles.verdictSafe : styles.verdictPhish}`}>
              {isSafe ? "✓ Verified Safe" : "⚠ Phishing Detected"}
            </span>
          </div>

          <div className={styles.metricsGrid}>
            <div className={styles.metric}>
              <div className={styles.metricVal}>{riskScore}/100</div>
              <div className={styles.metricLabel}>Risk score</div>
            </div>
            <div className={styles.metric}>
              <div className={styles.metricVal} style={{ color: isSafe ? "var(--safe)" : "var(--phish)" }}>
                {(result.p_legitimate * 100).toFixed(1)}%
              </div>
              <div className={styles.metricLabel}>P(Legitimate)</div>
            </div>
            <div className={styles.metric}>
              <div className={styles.metricVal} style={{ color: isSafe ? "var(--muted)" : "var(--phish)" }}>
                {(result.p_phishing * 100).toFixed(1)}%
              </div>
              <div className={styles.metricLabel}>P(Phishing)</div>
            </div>
            <div className={styles.metric}>
              <div className={styles.metricVal}>{(result.confidence * 100).toFixed(1)}%</div>
              <div className={styles.metricLabel}>Confidence</div>
            </div>
          </div>

          <div className={styles.barWrap}>
            <div className={styles.barLabel}>
              <span>Threat level</span><span>{riskScore}%</span>
            </div>
            <div className={styles.barTrack}>
              <div
                className={`${styles.barFill} ${isSafe ? styles.barSafe : styles.barDanger}`}
                style={{ width: `${riskScore}%` }}
              />
            </div>
          </div>

          {result.reason === "whitelisted" && (
            <p className={styles.whitelistNote}>This domain is in the trusted whitelist and was not sent to the model.</p>
          )}
        </div>
      )}
    </div>
  );
}
