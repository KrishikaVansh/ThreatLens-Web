import { useState, useEffect, useCallback } from "react";
import { getHistory, deleteScan } from "../utils/api";
import styles from "./History.module.css";

export default function History() {
  const [scans, setScans]     = useState([]);
  const [total, setTotal]     = useState(0);
  const [pages, setPages]     = useState(1);
  const [page, setPage]       = useState(1);
  const [loading, setLoading] = useState(false);
  const [verdict, setVerdict] = useState("");
  const [search, setSearch]   = useState("");
  const [searchInput, setSearchInput] = useState("");

  const fetchHistory = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getHistory({ page, limit: 10, verdict, search });
      setScans(res.data.scans);
      setTotal(res.data.total);
      setPages(res.data.pages);
    } catch { /* ignore */ }
    finally { setLoading(false); }
  }, [page, verdict, search]);

  useEffect(() => { fetchHistory(); }, [fetchHistory]);

  async function handleDelete(id) {
    await deleteScan(id);
    fetchHistory();
  }

  function handleSearch(e) {
    e.preventDefault();
    setPage(1);
    setSearch(searchInput);
  }

  function handleVerdictFilter(v) {
    setVerdict(v === verdict ? "" : v);
    setPage(1);
  }

  const isSafe = (v) => v !== "PHISHING";

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <span className={styles.pill}>Scan records</span>
          <h1 className={styles.title}>Scan History</h1>
          <p className={styles.subtitle}>{total.toLocaleString()} total scans in database</p>
        </div>
      </div>

      <div className={styles.filters}>
        <form onSubmit={handleSearch} className={styles.searchForm}>
          <input
            className={styles.searchInput}
            placeholder="Search by URL..."
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
          <button className={styles.searchBtn} type="submit">Search</button>
          {search && (
            <button className={styles.clearSearch} type="button"
              onClick={() => { setSearch(""); setSearchInput(""); setPage(1); }}>
              Clear
            </button>
          )}
        </form>

        <div className={styles.verdictBtns}>
          <button
            className={`${styles.filterBtn} ${verdict === "SAFE" ? styles.filterActive : ""}`}
            onClick={() => handleVerdictFilter("SAFE")}
          >Safe only</button>
          <button
            className={`${styles.filterBtn} ${verdict === "PHISHING" ? styles.filterActivePhish : ""}`}
            onClick={() => handleVerdictFilter("PHISHING")}
          >Phishing only</button>
        </div>
      </div>

      {loading ? (
        <div className={styles.loadingWrap}>
          <div className={styles.spinner} />
          Loading history…
        </div>
      ) : scans.length === 0 ? (
        <div className={styles.empty}>
          No scans found. Go check some URLs first!
        </div>
      ) : (
        <>
          <div className={styles.table}>
            <div className={`${styles.row} ${styles.rowHeader}`}>
              <span>URL</span>
              <span>Verdict</span>
              <span>P(Safe)</span>
              <span>P(Phish)</span>
              <span>Scanned</span>
              <span></span>
            </div>

            {scans.map((scan) => (
              <div key={scan._id} className={styles.row}>
                <span className={styles.urlCell} title={scan.url}>
                  {scan.url.length > 55 ? scan.url.slice(0, 52) + "…" : scan.url}
                </span>
                <span>
                  <span className={`${styles.badge} ${isSafe(scan.verdict) ? styles.badgeSafe : styles.badgePhish}`}>
                    {isSafe(scan.verdict) ? "SAFE" : "PHISHING"}
                  </span>
                </span>
                <span className={styles.prob}>{(scan.p_legitimate * 100).toFixed(1)}%</span>
                <span className={styles.prob}>{(scan.p_phishing   * 100).toFixed(1)}%</span>
                <span className={styles.date}>
                  {new Date(scan.scannedAt).toLocaleDateString()}{" "}
                  <span className={styles.time}>
                    {new Date(scan.scannedAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                  </span>
                </span>
                <span>
                  <button className={styles.deleteBtn} onClick={() => handleDelete(scan._id)} title="Delete">✕</button>
                </span>
              </div>
            ))}
          </div>

          {pages > 1 && (
            <div className={styles.pagination}>
              <button className={styles.pageBtn} disabled={page === 1}     onClick={() => setPage(page - 1)}>← Prev</button>
              <span className={styles.pageInfo}>Page {page} of {pages}</span>
              <button className={styles.pageBtn} disabled={page === pages} onClick={() => setPage(page + 1)}>Next →</button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
