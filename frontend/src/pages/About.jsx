import styles from "./About.module.css";

const TEAM = [
  {
    name: "Krishika Vansh",
    role: "ML Engineer & Full Stack Developer",
    desc: "Built the complete phishing detection pipeline — from raw dataset preprocessing to stacked ensemble training, Flask API, Node.js backend, and React frontend.",
    github: "https://github.com/KrishikaVansh/ThreatLens-Web",
  },
  {
    name: "Krisha Desai",
    role: "Full Stack Developer",
    desc: "Contributed to the full stack web application — React frontend design, Node.js backend integration, and MongoDB database architecture for scan history and analytics.",
    github: "https://github.com/KrishikaVansh/ThreatLens-Web",
  },
];

const MODELS = [
  ["Decision Tree",           "0.921", "0.964"],
  ["Random Forest",           "0.932", "0.981"],
  ["Naive Bayes (Gaussian)",  "0.667", "0.847"],
  ["Naive Bayes (Multinomial)","0.905","0.975"],
  ["Bagging",                 "0.916", "0.973"],
  ["AdaBoost",                "0.885", "0.954"],
  ["XGBoost",                 "0.922", "0.976"],
  ["MLP Neural Network",      "0.928", "0.979"],
  ["Logistic Reg (TF-IDF)",   "0.968", "0.995"],
  ["Final Stacked Ensemble",  "0.967", "0.995"],
];

export default function About() {
  return (
    <div className={styles.page}>

      <section className={styles.hero}>
        <div className={styles.heroInner}>
          <span className={styles.pill}>About ThreatLens</span>
          <h1 className={styles.title}>
            Built to make every<br /><span className={styles.blue}>click safer</span>
          </h1>
          <p className={styles.desc}>
            ThreatLens is a final-year B.Tech project combining classical machine learning,
            deep learning, and a full-stack web platform to detect phishing URLs in real time —
            with a special focus on India-specific cyber threats.
          </p>
        </div>
      </section>

      <section className={styles.section}>
        <div className={styles.sectionInner}>
          <h2 className={styles.secTitle}>The problem we solve</h2>
          <div className={styles.problemGrid}>
            {[
              { stat: "3.4B", label: "Phishing emails sent daily worldwide" },
              { stat: "36%",  label: "Of breaches involve phishing as the entry point" },
              { stat: "₹1.25T", label: "Lost to cyber fraud in India in 2023" },
              { stat: "97%",  label: "ThreatLens detection accuracy on test set" },
            ].map(p => (
              <div key={p.label} className={styles.problemCard}>
                <span className={styles.problemStat}>{p.stat}</span>
                <span className={styles.problemLabel}>{p.label}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className={styles.sectionAlt}>
        <div className={styles.sectionInner}>
          <h2 className={styles.secTitle}>Model performance</h2>
          <p className={styles.secDesc}>All models trained on 808,042 URLs (80/20 split, stratified, seed=42)</p>
          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>Model</th>
                  <th>Accuracy</th>
                  <th>AUC-ROC</th>
                </tr>
              </thead>
              <tbody>
                {MODELS.map(([name, acc, auc], i) => (
                  <tr key={name} className={i === MODELS.length - 1 ? styles.finalRow : ""}>
                    <td>{name}</td>
                    <td>{acc}</td>
                    <td>{auc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section className={styles.section}>
        <div className={styles.sectionInner}>
          <h2 className={styles.secTitle}>Technology stack</h2>
          <div className={styles.stackGrid}>
            {[
              { layer: "ML Pipeline",  items: ["Python 3.12", "scikit-learn", "XGBoost", "TF-IDF", "joblib"] },
              { layer: "Backend API",  items: ["Flask (ML service)", "Node.js + Express", "MongoDB + Mongoose", "Axios"] },
              { layer: "Frontend",     items: ["React 18", "Vite", "React Router v6", "Recharts", "CSS Modules"] },
              { layer: "Dev & Deploy", items: ["Git / GitHub", "nodemon", "openpyxl", "pandas", "matplotlib"] },
            ].map(s => (
              <div key={s.layer} className={styles.stackCard}>
                <h3 className={styles.stackLayer}>{s.layer}</h3>
                <div className={styles.stackItems}>
                  {s.items.map(item => (
                    <span key={item} className={styles.stackItem}>{item}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className={styles.sectionAlt}>
        <div className={styles.sectionInner}>
          <h2 className={styles.secTitle}>Meet the developer</h2>
          {TEAM.map(t => (
            <div key={t.name} className={styles.teamCard}>
              <div className={styles.teamAvatar}>
                {t.name.split(" ").map(n => n[0]).join("")}
              </div>
              <div>
                <h3 className={styles.teamName}>{t.name}</h3>
                <p className={styles.teamRole}>{t.role}</p>
                <p className={styles.teamDesc}>{t.desc}</p>
                <a href={t.github} target="_blank" rel="noreferrer" className={styles.ghLink}>
                  View on GitHub →
                </a>
              </div>
            </div>
          ))}
        </div>
      </section>

    </div>
  );
}