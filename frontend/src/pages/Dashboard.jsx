import { useState, useEffect } from "react";
import { getStats } from "../utils/api";
import {
  AreaChart, Area, BarChart, Bar,
  XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from "recharts";
import styles from "./Dashboard.module.css";

const SAFE_COLOR  = "#22c55e";
const PHISH_COLOR = "#ef4444";
const ACCENT      = "#6366f1";

function StatCard({ label, value, sub, color }) {
  return (
    <div className={styles.statCard} style={{ borderTopColor: color }}>
      <span className={styles.statValue} style={{ color }}>{value}</span>
      <span className={styles.statLabel}>{label}</span>
      {sub && <span className={styles.statSub}>{sub}</span>}
    </div>
  );
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className={styles.tooltip}>
      <p className={styles.tooltipLabel}>{label}</p>
      {payload.map((p) => (
        <p key={p.name} style={{ color: p.color, fontSize: "0.8rem" }}>
          {p.name}: {p.value}
        </p>
      ))}
    </div>
  );
};

export default function Dashboard() {
  const [stats, setStats]     = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getStats()
      .then((res) => setStats(res.data))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className={styles.loadingWrap}>
        <div className={styles.spinner} />
        <span>Loading dashboard…</span>
      </div>
    );
  }

  if (!stats) {
    return (
      <div className={styles.page}>
        <p className={styles.empty}>Could not load stats. Is the backend running?</p>
      </div>
    );
  }

  const pieData = [
    { name: "Safe",     value: stats.safe },
    { name: "Phishing", value: stats.phishing },
  ];

  // Fill missing days in the last 7 days
  const last7 = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    const found = stats.daily.find((r) => r._id === key);
    last7.push({
      date:     d.toLocaleDateString(undefined, { month: "short", day: "numeric" }),
      total:    found?.count    || 0,
      phishing: found?.phishing || 0,
      safe:     found?.safe     || 0,
    });
  }

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <h1 className={styles.title}>Dashboard</h1>
        <p className={styles.subtitle}>All-time scan statistics</p>
      </div>

      {/* Stat cards */}
      <div className={styles.cards}>
        <StatCard
          label="Total Scans"
          value={stats.total.toLocaleString()}
          color={ACCENT}
        />
        <StatCard
          label="Safe URLs"
          value={stats.safe.toLocaleString()}
          sub={`${(100 - parseFloat(stats.phishingRate)).toFixed(1)}% of total`}
          color={SAFE_COLOR}
        />
        <StatCard
          label="Phishing Detected"
          value={stats.phishing.toLocaleString()}
          sub={`${stats.phishingRate}% of total`}
          color={PHISH_COLOR}
        />
        <StatCard
          label="Detection Rate"
          value="97.0%"
          sub="Model accuracy"
          color="#f59e0b"
        />
      </div>

      {/* Charts row */}
      <div className={styles.chartsRow}>
        {/* Area chart — activity over 7 days */}
        <div className={styles.chartCard}>
          <h2 className={styles.chartTitle}>Scans — Last 7 Days</h2>
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={last7} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="gSafe" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor={SAFE_COLOR}  stopOpacity={0.25} />
                  <stop offset="95%" stopColor={SAFE_COLOR}  stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gPhish" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor={PHISH_COLOR} stopOpacity={0.25} />
                  <stop offset="95%" stopColor={PHISH_COLOR} stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="date" tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="safe"     stroke={SAFE_COLOR}  fill="url(#gSafe)"  strokeWidth={2} name="Safe" />
              <Area type="monotone" dataKey="phishing" stroke={PHISH_COLOR} fill="url(#gPhish)" strokeWidth={2} name="Phishing" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Pie chart */}
        <div className={`${styles.chartCard} ${styles.pieCard}`}>
          <h2 className={styles.chartTitle}>Overall Split</h2>
          {stats.total === 0 ? (
            <p className={styles.empty}>No data yet</p>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={3}
                  dataKey="value"
                >
                  <Cell fill={SAFE_COLOR} />
                  <Cell fill={PHISH_COLOR} />
                </Pie>
                <Tooltip formatter={(v) => v.toLocaleString()} />
                <Legend
                  formatter={(v) => (
                    <span style={{ color: "#94a3b8", fontSize: "0.8rem" }}>{v}</span>
                  )}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Bar chart — daily breakdown */}
      <div className={styles.chartCard}>
        <h2 className={styles.chartTitle}>Daily Breakdown — Safe vs Phishing</h2>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={last7} margin={{ top: 10, right: 10, left: -20, bottom: 0 }} barGap={2}>
            <XAxis dataKey="date" tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fill: "#64748b", fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
            <Tooltip content={<CustomTooltip />} />
            <Bar dataKey="safe"     name="Safe"     fill={SAFE_COLOR}  radius={[3,3,0,0]} maxBarSize={32} />
            <Bar dataKey="phishing" name="Phishing" fill={PHISH_COLOR} radius={[3,3,0,0]} maxBarSize={32} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
