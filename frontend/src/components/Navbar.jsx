import { NavLink } from "react-router-dom";
import styles from "./Navbar.module.css";

export default function Navbar() {
  return (
    <nav className={styles.nav}>
      <div className={styles.logo}>
        <span className={styles.icon}>🔍</span>
        ThreatLens
      </div>
      <div className={styles.links}>
        <NavLink to="/"          className={({ isActive }) => isActive ? styles.active : ""}>Check URL</NavLink>
        <NavLink to="/bulk"      className={({ isActive }) => isActive ? styles.active : ""}>Bulk Scan</NavLink>
        <NavLink to="/history"   className={({ isActive }) => isActive ? styles.active : ""}>History</NavLink>
        <NavLink to="/dashboard" className={({ isActive }) => isActive ? styles.active : ""}>Dashboard</NavLink>
      </div>
    </nav>
  );
}
