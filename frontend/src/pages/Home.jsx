import { useState } from "react";
import { checkURL } from "../utils/api";
import ResultCard from "../components/ResultCard";
import styles from "./Home.module.css";

export default function Home() {
  const [url, setUrl]         = useState("");
  const [result, setResult]   = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState("");

  async function handleCheck(e) {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const res = await checkURL(url.trim());
      setResult(res.data.scan);
    } catch (err) {
      setError(err.response?.data?.error || "Failed to connect to server. Is the backend running?");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className={styles.page}>
      <div className={styles.hero}>
        <h1 className={styles.title}>
          <span className={styles.shield}>🛡</span>
          Is this URL safe?
        </h1>
        <p className={styles.subtitle}>
          Powered by a stacked ML ensemble — 97% accuracy, AUC 0.995
        </p>
      </div>

      <form className={styles.form} onSubmit={handleCheck}>
        <div className={styles.inputRow}>
          <input
            className={styles.input}
            type="text"
            placeholder="Paste any URL here — https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            spellCheck={false}
          />
          <button className={styles.btn} disabled={loading}>
            {loading ? "Scanning…" : "Check"}
          </button>
        </div>
      </form>

      {error && <div className={styles.error}>{error}</div>}

      {loading && (
        <div className={styles.loadingWrap}>
          <div className={styles.spinner} />
          <span>Analyzing URL…</span>
        </div>
      )}

      {result && (
        <div className={styles.resultWrap}>
          <ResultCard scan={result} />
        </div>
      )}

      <div className={styles.examples}>
        <p className={styles.exLabel}>Try an example:</p>
        <div className={styles.exBtns}>
          {[
            "https://www.google.com",
            "http://paypal-secure-login.tk/confirm",
            "https://github.com/openai/gpt-4",
          ].map((u) => (
            <button
              key={u}
              className={styles.exBtn}
              onClick={() => setUrl(u)}
            >
              {u}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
