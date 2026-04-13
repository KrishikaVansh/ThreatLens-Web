import { NavLink, Link } from "react-router-dom";
import styles from "./Navbar.module.css";

export default function Navbar() {
  return (
    <nav className={styles.nav}>
      <div className={styles.inner}>
        <Link to="/" className={styles.logo}>
          <span className={styles.logoIcon}>
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="#2563eb" opacity="0.15"/>
              <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" stroke="#2563eb" strokeWidth="1.5" fill="none"/>
              <path d="M9 12l2 2 4-4" stroke="#2563eb" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </span>
          <span className={styles.logoText}>ThreatLens</span>
        </Link>

        <div className={styles.links}>
          <NavLink to="/"          end className={({ isActive }) => isActive ? `${styles.link} ${styles.active}` : styles.link}>Home</NavLink>
          <NavLink to="/scan"      className={({ isActive }) => isActive ? `${styles.link} ${styles.active}` : styles.link}>Scan URL</NavLink>
          <NavLink to="/bulk"      className={({ isActive }) => isActive ? `${styles.link} ${styles.active}` : styles.link}>Bulk Scan</NavLink>
          <NavLink to="/history"   className={({ isActive }) => isActive ? `${styles.link} ${styles.active}` : styles.link}>History</NavLink>
          <NavLink to="/dashboard" className={({ isActive }) => isActive ? `${styles.link} ${styles.active}` : styles.link}>Dashboard</NavLink>
          <NavLink to="/about"     className={({ isActive }) => isActive ? `${styles.link} ${styles.active}` : styles.link}>About</NavLink>
        </div>

        <Link to="/scan" className={styles.ctaBtn}>
          Scan a URL
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
        </Link>
      </div>
    </nav>
  );
}
