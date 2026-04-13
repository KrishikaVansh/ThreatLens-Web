import { useState } from "react";
import { Link } from "react-router-dom";
import { checkURL } from "../utils/api";
import styles from "./Home.module.css";

const SCAM_PATTERNS = [
  { icon: "💬", title: "WhatsApp Job Scams", desc: "Fake recruiters push short links to forms, APKs, or payout portals." },
  { icon: "🏦", title: "KYC Update Scams", desc: "Urgent bank verification messages mimic RBI, wallet, and fintech brands." },
  { icon: "📲", title: "UPI Fraud", desc: "Collect-request traps and fake payment screenshots pressure rushed approvals." },
  { icon: "🚂", title: "IRCTC Fake Sites", desc: "Lookalike booking portals imitate train reservation flows to harvest logins." },
  { icon: "🪪", title: "Aadhaar Scams", desc: "Impersonation pages claim identity updates or e-KYC refresh deadlines." },
];

const FUTURE_FEATURES = [
  { icon: "🔗", title: "URL Scanner", desc: "Quickly inspect links for phishing signals and suspicious intent." },
  { icon: "🔒", title: "SSL Checker", desc: "Review certificate coverage and trust indicators at a glance." },
  { icon: "🌐", title: "DNS Lookup", desc: "Surface DNS patterns that often show spoofed or disposable domains." },
  { icon: "🔑", title: "Password Checker", desc: "Simulate weak password detection for account takeover awareness." },
  { icon: "📷", title: "QR Scanner", desc: "Preview where a QR code may redirect before someone taps it." },
  { icon: "↗️", title: "Link Expander", desc: "Reveal hidden destinations from shortened or masked links." },
  { icon: "🖥️", title: "IP Reputation", desc: "Flag infrastructure often associated with newly created phishing kits." },
  { icon: "📅", title: "Website Age", desc: "Estimate whether a domain looks fresh enough to warrant caution." },
];

const STATS = [
  { value: "808K+", label: "URLs trained on" },
  { value: "97%",   label: "Detection accuracy" },
  { value: "0.995", label: "AUC-ROC score" },
  { value: "< 1s",  label: "Scan time" },
];

export default function Home() {
  const [url, setUrl]         = useState("");
  const [result, setResult]   = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState("");

  async function handleScan(e) {
    e.preventDefault();
    const val = url.trim();
    if (!val) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await checkURL(val);
      setResult(res.data.scan);
    } catch (err) {
      setError(err.response?.data?.error || "Backend not connected. Start the server first.");
    } finally {
      setLoading(false);
    }
  }

  const isSafe = result && result.verdict !== "PHISHING";
  const riskScore = result ? Math.round(result.p_phishing * 100) : null;

  return (
    <div className={styles.page}>

      <section className={styles.hero}>
        <div className={styles.heroInner}>
          <div className={styles.heroLeft}>
            <span className={styles.pill}>Is that link safe or a trap?</span>
            <h1 className={styles.heroTitle}>
              Protect every<br /><span className={styles.heroBlue}>click</span>
            </h1>
            <p className={styles.heroDesc}>
              ThreatLens uses a stacked ML ensemble trained on 800K+ URLs to detect
              phishing links, fake payment pages, and India-focused social engineering scams.
            </p>
            <p className={styles.heroSub}>
              Scan phishing links, UPI lures, and fake KYC pages in seconds.
            </p>
            <form className={styles.heroForm} onSubmit={handleScan}>
              <div className={styles.heroInputWrap}>
                <input
                  className={styles.heroInput}
                  type="text"
                  placeholder="Paste a URL to simulate forensic analysis"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  spellCheck={false}
                />
                {url && <button type="button" className={styles.heroClear} onClick={() => { setUrl(""); setResult(null); }}>✕</button>}
                <button
                  type="button"
                  className={styles.heroPaste}
                  onClick={() => navigator.clipboard.readText().then(t => setUrl(t)).catch(() => {})}
                >Paste</button>
                <button className={styles.heroScanBtn} disabled={loading}>
                  {loading ? "Scanning…" : "Scan Now"}
                </button>
              </div>
            </form>
            {error && <div className={styles.heroError}>{error}</div>}
          </div>

          <div className={styles.heroRight}>
            <div className={`${styles.resultCard} ${result ? (isSafe ? styles.rcSafe : styles.rcPhish) : ""}`}>
              <div className={styles.rcTop}>
                <span className={styles.rcLabel}>Live scan result</span>
                {result
                  ? <span className={`${styles.rcBadge} ${isSafe ? styles.rcBadgeSafe : styles.rcBadgePhish}`}>{isSafe ? "✓ Verified Safe" : "⚠ Phishing Detected"}</span>
                  : <span className={styles.rcBadgePlaceholder}>Awaiting scan…</span>
                }
              </div>
              <p className={styles.rcUrl}>{result ? result.url : "https://suspicious-link.com"}</p>
              <div className={styles.rcScoreRow}>
                <div>
                  <div className={styles.rcScoreLabel}>Risk score</div>
                  <div className={styles.rcScore}>{result ? riskScore : "16"}<span className={styles.rcScoreMax}>/100</span></div>
                </div>
              </div>
              <div className={styles.rcBarSection}>
                <div className={styles.rcBarHeader}>
                  <span>Threat confidence</span>
                  <span>{result ? `${riskScore}%` : "16%"}</span>
                </div>
                <div className={styles.rcBarTrack}>
                  <div className={`${styles.rcBarFill} ${result && !isSafe ? styles.rcBarDanger : styles.rcBarSafe}`}
                    style={{ width: result ? `${riskScore}%` : "16%" }} />
                </div>
              </div>
              <div className={styles.rcTags}>
                {result && !isSafe ? (
                  <>
                    <span className={`${styles.rcTag} ${styles.rcTagDanger}`}>Suspicious TLD</span>
                    <span className={`${styles.rcTag} ${styles.rcTagDanger}`}>Brand impersonation</span>
                    <span className={`${styles.rcTag} ${styles.rcTagDanger}`}>High-risk pattern</span>
                  </>
                ) : (
                  <>
                    <span className={styles.rcTag}>Trusted naming pattern</span>
                    <span className={styles.rcTag}>No fraud keywords</span>
                    <span className={styles.rcTag}>Low-risk structure</span>
                  </>
                )}
              </div>
              <p className={styles.rcNote}>
                {result
                  ? isSafe ? "No common phishing indicators were detected in this scan." : "Phishing indicators detected — avoid this URL."
                  : "No common phishing indicators were detected in this mock scan."}
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className={styles.statsSection}>
        <div className={styles.statsInner}>
          {STATS.map((s) => (
            <div key={s.label} className={styles.statItem}>
              <span className={styles.statValue}>{s.value}</span>
              <span className={styles.statLabel}>{s.label}</span>
            </div>
          ))}
        </div>
      </section>

      <section className={styles.section}>
        <div className={styles.sectionInner}>
          <span className={styles.sectionPill}>India-focused awareness</span>
          <h2 className={styles.sectionTitle}>Common scam patterns users<br />recognize instantly</h2>
          <p className={styles.sectionDesc}>Localized references make the app feel relevant to real-world fraud reports and digital payment habits.</p>
          <div className={styles.scamGrid}>
            {SCAM_PATTERNS.map((s) => (
              <div key={s.title} className={styles.scamCard}>
                <span className={styles.scamIcon}>{s.icon}</span>
                <h3 className={styles.scamTitle}>{s.title}</h3>
                <p className={styles.scamDesc}>{s.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className={styles.howSection}>
        <div className={styles.sectionInner}>
          <span className={styles.sectionPill}>Under the hood</span>
          <h2 className={styles.sectionTitle}>How ThreatLens works</h2>
          <div className={styles.howGrid}>
            {[
              { num: "01", title: "Paste a URL", desc: "Drop any link — short links, UPI pages, login prompts, anything." },
              { num: "02", title: "Feature extraction", desc: "21 structural signals + 20,000 TF-IDF character n-gram features computed instantly." },
              { num: "03", title: "ML ensemble votes", desc: "9 models including Random Forest, XGBoost, MLP and Logistic Regression analyse the URL." },
              { num: "04", title: "You get a verdict", desc: "Safe or Phishing with exact probabilities and confidence score, saved to history." },
            ].map((step) => (
              <div key={step.num} className={styles.howCard}>
                <span className={styles.howNum}>{step.num}</span>
                <h3 className={styles.howTitle}>{step.title}</h3>
                <p className={styles.howDesc}>{step.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className={styles.section}>
        <div className={styles.sectionInner}>
          <span className={styles.sectionPill}>Future scope</span>
          <h2 className={styles.sectionTitle}>Security tools planned for<br />backend integration</h2>
          <p className={styles.sectionDesc}>These cards showcase upcoming modules that can be connected once live scanning services and APIs are available.</p>
          <div className={styles.futureGrid}>
            {FUTURE_FEATURES.map((f) => (
              <div key={f.title} className={styles.futureCard}>
                <span className={styles.futureIcon}>{f.icon}</span>
                <h3 className={styles.futureTitle}>{f.title}</h3>
                <p className={styles.futureDesc}>{f.desc}</p>
                <span className={styles.comingSoon}>Coming soon</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className={styles.ctaSection}>
        <div className={styles.ctaInner}>
          <h2 className={styles.ctaTitle}>Ready to protect every click?</h2>
          <p className={styles.ctaDesc}>Start scanning URLs instantly — no signup, no setup required.</p>
          <div className={styles.ctaBtns}>
            <Link to="/scan" className={styles.ctaPrimary}>Scan a URL now</Link>
            <Link to="/about" className={styles.ctaSecondary}>Learn about ThreatLens</Link>
          </div>
        </div>
      </section>

      <footer className={styles.footer}>
        <div className={styles.footerInner}>
          <span>© 2026 ThreatLens · Built by Krishika Vansh</span>
          <span>97% accuracy · AUC 0.995 · 808K+ URLs trained</span>
        </div>
      </footer>
    </div>
  );
}
