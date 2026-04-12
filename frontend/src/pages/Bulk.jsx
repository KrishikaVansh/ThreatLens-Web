import { useState } from "react";
import { checkBulk } from "../utils/api";
import ResultCard from "../components/ResultCard";
import styles from "./Bulk.module.css";

export default function Bulk() {
  const [text, setText]       = useState("");
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState("");
  const [stats, setStats]     = useState(null);

  async function handleScan(e) {
    e.preventDefault();
    const urls = text
      .split("\n")
      .map((u) => u.trim())
      .filter(Boolean);

    if (urls.length === 0) return;
    if (urls.length > 50) {
      setError("Max 50 URLs at once.");
      return;
    }

    setLoading(true);
    setError("");
    setResults([]);
    setStats(null);

    try {
      const res = await checkBulk(urls);
      const scans = res.data.scans;
      setResults(scans);
      const phishing = scans.filter((s) => s.verdict === "PHISHING").length;
      setStats({ total: scans.length, phishing, safe: scans.length - phishing });
    } catch (err) {
      setError(err.response?.data?.error || "Server error. Is the backend running?");
    } finally {
      setLoading(false);
    }
  }

  function handleClear() {
    setText("");
    setResults([]);
    setStats(null);
    setError("");
  }

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <h1 className={styles.title}>Bulk URL Scanner</h1>
        <p className={styles.subtitle}>Paste up to 50 URLs — one per line</p>
      </div>

      <form onSubmit={handleScan} className={styles.form}>
        <textarea
          className={styles.textarea}
          rows={10}
          placeholder={"https://www.google.com\nhttp://paypal-secure-login.tk/confirm\nhttps://github.com/openai/gpt-4"}
          value={text}
          onChange={(e) => setText(e.target.value)}
          spellCheck={false}
        />
        <div className={styles.actions}>
          <span className={styles.count}>
            {text.split("\n").filter((l) => l.trim()).length} URLs
          </span>
          <div className={styles.btns}>
            <button type="button" className={styles.clearBtn} onClick={handleClear}>
              Clear
            </button>
            <button className={styles.scanBtn} disabled={loading}>
              {loading ? "Scanning…" : "Scan All"}
            </button>
          </div>
        </div>
      </form>

      {error && <div className={styles.error}>{error}</div>}

      {loading && (
        <div className={styles.loadingWrap}>
          <div className={styles.spinner} />
          <span>Analyzing {text.split("\n").filter((l) => l.trim()).length} URLs…</span>
        </div>
      )}

      {stats && (
        <div className={styles.summary}>
          <div className={styles.statBox}>
            <span className={styles.statNum}>{stats.total}</span>
            <span className={styles.statLabel}>Total</span>
          </div>
          <div className={`${styles.statBox} ${styles.statSafe}`}>
            <span className={styles.statNum}>{stats.safe}</span>
            <span className={styles.statLabel}>Safe</span>
          </div>
          <div className={`${styles.statBox} ${styles.statPhish}`}>
            <span className={styles.statNum}>{stats.phishing}</span>
            <span className={styles.statLabel}>Phishing</span>
          </div>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.results}>
          {results.map((scan, i) => (
            <ResultCard key={i} scan={scan} />
          ))}
        </div>
      )}
    </div>
  );
}
