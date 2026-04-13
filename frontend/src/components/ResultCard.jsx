import styles from "./ResultCard.module.css";

export default function ResultCard({ scan }) {
  const isSafe = scan.verdict !== "PHISHING";
  return (
    <div className={`${styles.card} ${isSafe ? styles.safe : styles.phish}`}>
      <div className={styles.top}>
        <span className={`${styles.badge} ${isSafe ? styles.badgeSafe : styles.badgePhish}`}>
          {isSafe ? "✓ SAFE" : "⚠ PHISHING"}
        </span>
        {scan.reason === "whitelisted" && (
          <span className={styles.whitelist}>whitelisted</span>
        )}
      </div>

      <p className={styles.url}>{scan.url}</p>

      <div className={styles.bars}>
        <div className={styles.barRow}>
          <span className={styles.barLabel}>Safe</span>
          <div className={styles.barTrack}>
            <div className={`${styles.barFill} ${styles.barSafe}`}
              style={{ width: `${(scan.p_legitimate * 100).toFixed(1)}%` }} />
          </div>
          <span className={styles.barPct}>{(scan.p_legitimate * 100).toFixed(1)}%</span>
        </div>
        <div className={styles.barRow}>
          <span className={styles.barLabel}>Phish</span>
          <div className={styles.barTrack}>
            <div className={`${styles.barFill} ${styles.barPhish}`}
              style={{ width: `${(scan.p_phishing * 100).toFixed(1)}%` }} />
          </div>
          <span className={styles.barPct}>{(scan.p_phishing * 100).toFixed(1)}%</span>
        </div>
      </div>

      <div className={styles.meta}>
        <span>Confidence: <strong>{(scan.confidence * 100).toFixed(1)}%</strong></span>
        {scan.scannedAt && (
          <span>{new Date(scan.scannedAt).toLocaleString()}</span>
        )}
      </div>
    </div>
  );
}
