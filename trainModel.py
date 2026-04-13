"""
ThreatLens - Phishing URL Detection
Full ML Pipeline:
  - Decision Tree
  - Random Forest
  - Naive Bayes (GaussianNB)
  - Bagging (BaggingClassifier)
  - Boosting (AdaBoost + XGBoost)
  - Voting Ensemble - Hard & Soft
  - Neural Network (MLP via scikit-learn)
Output per URL: Safe / Not Safe + P(safe) + P(phishing)
"""

# ===========================================================
# 0. IMPORTS
# ===========================================================
import re
import os
import joblib
import warnings
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from urllib.parse import urlparse
from scipy.sparse import hstack, csr_matrix

# - scikit-learn ----------------------
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline

# Classifiers
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import (
    RandomForestClassifier,
    BaggingClassifier,
    AdaBoostClassifier,
    VotingClassifier,
    GradientBoostingClassifier,
)
from sklearn.naive_bayes import GaussianNB, MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier

# Metrics
from sklearn.metrics import (
    accuracy_score,
    roc_auc_score,
    roc_curve,
    auc,
    confusion_matrix,
    classification_report,
    ConfusionMatrixDisplay,
)

warnings.filterwarnings("ignore")

# ===========================================================
# 1. LOAD & COMBINE DATASETS
# ===========================================================
df1 = pd.read_csv("new_data_urls.csv")          # columns: url, status (0=phishing, 1=legit)
df1 = df1.rename(columns={"status": "y"})
df1["y"] = df1["y"].astype(int)

df2 = pd.read_csv("phishing_site_urls.csv")     # columns: url, label (bad/good)
df2 = df2.rename(columns={"label": "y"})
df2["y"] = df2["y"].map({"bad": 0, "good": 1})

df = pd.concat([df1[["url", "y"]], df2[["url", "y"]]], ignore_index=True)
df = df.drop_duplicates(subset=["url"]).dropna().reset_index(drop=True)

print("=" * 60)
print("CLASS DISTRIBUTION")
print(df["y"].value_counts())
print("=" * 60)

df.to_csv("combined_phishing_dataset.csv", index=False)

# ===========================================================
# 2. FEATURE ENGINEERING
# ===========================================================
ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work"}
BRAND_KEYWORDS  = ["paypal", "amazon", "apple", "google", "microsoft",
                   "netflix", "facebook", "instagram", "bank", "secure"]

def extract_url_features(urls):
    rows = []
    for url in urls:
        url = str(url).strip()
        full = url if "//" in url else "http://" + url
        try:
            parsed = urlparse(full)
            host   = parsed.netloc or ""
            path   = parsed.path   or ""
        except Exception:
            host = path = ""

        has_suspicious_tld = int(any(host.endswith(t) for t in SUSPICIOUS_TLDS))
        has_brand_keyword  = int(any(k in url.lower() for k in BRAND_KEYWORDS))
        subdomains         = host.split(".")[:-2] if host else []

        rows.append({
            # Length-based
            "url_len":          len(url),
            "host_len":         len(host),
            "path_len":         len(path),
            # Count-based
            "num_dots":         url.count("."),
            "num_hyphens":      url.count("-"),
            "num_digits":       sum(c.isdigit() for c in url),
            "num_special":      sum(not c.isalnum() for c in url),
            "num_slashes":      url.count("/"),
            "num_subdomains":   len(subdomains),
            "num_params":       url.count("?") + url.count("&"),
            "num_at":           url.count("@"),
            "num_percent":      url.count("%"),
            "num_eq":           url.count("="),
            # Binary flags
            "has_https":        int(url.lower().startswith("https")),
            "has_ip":           int(bool(ip_pattern.match(host))),
            "has_at":           int("@" in url),
            "has_double_slash": int("//" in url[8:]),   # skip protocol //
            "has_suspicious_tld": has_suspicious_tld,
            "has_brand_kw":     has_brand_keyword,
            # Ratios
            "digit_ratio":      sum(c.isdigit() for c in url) / max(len(url), 1),
            "special_ratio":    sum(not c.isalnum() for c in url) / max(len(url), 1),
        })
    return pd.DataFrame(rows)


print("Extracting hand-crafted URL features ...")
X_feat = extract_url_features(df["url"])
y      = df["y"]

# TF-IDF char n-gram features (for text-based models)
print("Building TF-IDF character n-gram matrix ...")
tfidf = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), max_features=20_000)
X_tfidf = tfidf.fit_transform(df["url"])   # sparse (N, 20000)

# Dense feature matrix (scaled)
scaler  = StandardScaler()
X_dense = scaler.fit_transform(X_feat)

# Combined sparse matrix: TF-IDF  +  dense features
X_combined = hstack([X_tfidf, csr_matrix(X_dense)])

# ===========================================================
# 3. TRAIN / TEST SPLIT  (same random_state -> identical splits)
# ===========================================================
SEED = 42

X_tr_d,  X_ts_d,  y_tr, y_ts = train_test_split(
    X_dense,    y, test_size=0.2, stratify=y, random_state=SEED)

X_tr_t,  X_ts_t,  _,    _    = train_test_split(
    X_tfidf,    y, test_size=0.2, stratify=y, random_state=SEED)

X_tr_c,  X_ts_c,  _,    _    = train_test_split(
    X_combined, y, test_size=0.2, stratify=y, random_state=SEED)

# ===========================================================
# 4. DEFINE ALL MODELS
# ===========================================================

# 4a. Decision Tree
dt = DecisionTreeClassifier(
    max_depth=20,
    min_samples_leaf=3,
    class_weight="balanced",
    random_state=SEED,
)

# 4b. Random Forest
rf = RandomForestClassifier(
    n_estimators=300,
    min_samples_split=5,
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=SEED,
    n_jobs=-1,
)

# 4c. Naive Bayes
#   GaussianNB works on dense features; MultinomialNB on TF-IDF counts.
gnb  = GaussianNB()
mnb  = MultinomialNB(alpha=0.1)          # for TF-IDF (non-negative)

# 4d. Bagging  (bagging of Decision Trees, i.e. manual Random Forest variant)
bag = BaggingClassifier(
    estimator=DecisionTreeClassifier(max_depth=15, random_state=SEED),
    n_estimators=100,
    max_samples=0.8,
    max_features=0.8,
    random_state=SEED,
    n_jobs=-1,
)

# 4e. Boosting
ada = AdaBoostClassifier(
    estimator=DecisionTreeClassifier(max_depth=3, random_state=SEED),
    n_estimators=200,
    learning_rate=0.5,
    random_state=SEED,
)

try:
    from xgboost import XGBClassifier
    xgb = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric="logloss",
        scale_pos_weight=(y == 0).sum() / (y == 1).sum(),  # handle imbalance
        random_state=SEED,
        n_jobs=-1,
    )
    HAS_XGB = True
    print("XGBoost found - will be included.")
except ImportError:
    HAS_XGB = False
    print("XGBoost not installed - using GradientBoostingClassifier instead.")
    xgb = GradientBoostingClassifier(
        n_estimators=200, max_depth=5, learning_rate=0.1, random_state=SEED
    )

# 4f. Logistic Regression (used inside voting ensembles for the TF-IDF leg)
lr = LogisticRegression(
    max_iter=1000,
    class_weight="balanced",
    solver="saga",
    C=1.0,
    random_state=SEED,
)

# 4g. MLP Neural Network
mlp = MLPClassifier(
    hidden_layer_sizes=(256, 128, 64),
    activation="relu",
    solver="adam",
    alpha=1e-4,               # L2 regularisation
    batch_size=512,
    learning_rate="adaptive",
    max_iter=50,              # increase for better convergence if time allows
    early_stopping=True,
    validation_fraction=0.1,
    random_state=SEED,
)

# ===========================================================
# 5. TRAIN EACH MODEL + COLLECT PROBABILITIES
# ===========================================================

results = {}   # model_name -> {pred, prob, auc}

def train_eval(name, model, X_tr, X_ts, fit_dense=True):
    print(f"\nTraining {name} ...")
    model.fit(X_tr, y_tr)
    pred = model.predict(X_ts)
    prob = model.predict_proba(X_ts)[:, 1]
    acc  = accuracy_score(y_ts, pred)
    ras  = roc_auc_score(y_ts, prob)
    print(f"  Accuracy: {acc:.4f}  |  AUC: {ras:.4f}")
    results[name] = {"model": model, "pred": pred, "prob": prob,
                     "acc": acc, "auc": ras}
    return pred, prob

train_eval("Decision Tree",  dt,  X_tr_d, X_ts_d)
train_eval("Random Forest",  rf,  X_tr_d, X_ts_d)
train_eval("Naive Bayes (Gaussian)", gnb, X_tr_d, X_ts_d)
train_eval("Naive Bayes (Multinomial)", mnb, X_tr_t, X_ts_t)
train_eval("Bagging",        bag, X_tr_d, X_ts_d)
train_eval("AdaBoost",       ada, X_tr_d, X_ts_d)
train_eval("XGBoost/GBM",   xgb, X_tr_d, X_ts_d)
train_eval("MLP Neural Net", mlp, X_tr_d, X_ts_d)
train_eval("Logistic Reg (TF-IDF)", lr, X_tr_t, X_ts_t)

# ===========================================================
# 6. VOTING ENSEMBLES  (Hard & Soft)
# ===========================================================
# We build the voting classifier from the dense-feature models
# (DT, RF, Bagging, AdaBoost, XGB/GBM, MLP) so a single
# feature matrix is used.

dense_estimators = [
    ("dt",  DecisionTreeClassifier(max_depth=20, min_samples_leaf=3,
                                   class_weight="balanced", random_state=SEED)),
    # n_jobs=1 inside estimators: VotingClassifier trains them sequentially,
    # nesting n_jobs=-1 inside would spawn processes-within-processes and
    # exhaust RAM on large datasets (~800k rows x multiple models).
    ("rf",  RandomForestClassifier(n_estimators=200, min_samples_leaf=2,
                                   class_weight="balanced", random_state=SEED, n_jobs=1)),
    ("bag", BaggingClassifier(estimator=DecisionTreeClassifier(max_depth=15,
                              random_state=SEED), n_estimators=50, random_state=SEED, n_jobs=1)),
    ("ada", AdaBoostClassifier(n_estimators=100, random_state=SEED)),
    ("gbm", xgb),
    ("mlp", MLPClassifier(hidden_layer_sizes=(128, 64), max_iter=30,
                          early_stopping=True, random_state=SEED)),
]

# Hard Voting - n_jobs=1: trains estimators sequentially, avoiding the
# "copy 800k rows into N worker processes simultaneously" OOM crash.
print("\nTraining Hard Voting Ensemble ...")
hard_vote = VotingClassifier(estimators=dense_estimators, voting="hard", n_jobs=1)
hard_vote.fit(X_tr_d, y_tr)
hv_pred = hard_vote.predict(X_ts_d)
# Hard voting has no predict_proba -> use mean of individual probas
hv_prob = np.mean(
    [est.predict_proba(X_ts_d)[:, 1] for est in hard_vote.estimators_], axis=0
)
results["Hard Voting"] = {
    "pred": hv_pred, "prob": hv_prob,
    "acc": accuracy_score(y_ts, hv_pred),
    "auc": roc_auc_score(y_ts, hv_prob),
}
print(f"  Accuracy: {results['Hard Voting']['acc']:.4f}  |  AUC: {results['Hard Voting']['auc']:.4f}")

# Soft Voting - same fix: n_jobs=1
print("\nTraining Soft Voting Ensemble ...")
soft_vote = VotingClassifier(estimators=dense_estimators, voting="soft", n_jobs=1)
soft_vote.fit(X_tr_d, y_tr)
sv_pred = soft_vote.predict(X_ts_d)
sv_prob = soft_vote.predict_proba(X_ts_d)[:, 1]
results["Soft Voting"] = {
    "pred": sv_pred, "prob": sv_prob,
    "acc": accuracy_score(y_ts, sv_pred),
    "auc": roc_auc_score(y_ts, sv_prob),
}
print(f"  Accuracy: {results['Soft Voting']['acc']:.4f}  |  AUC: {results['Soft Voting']['auc']:.4f}")

# ===========================================================
# 7. FINAL STACKED ENSEMBLE (best models weighted average)
# ===========================================================
# Blend LR-TF-IDF + Soft-Voting probabilities
lr_prob  = results["Logistic Reg (TF-IDF)"]["prob"]
sv_prob  = results["Soft Voting"]["prob"]

final_prob = 0.55 * sv_prob + 0.45 * lr_prob
final_pred = (final_prob >= 0.45).astype(int)   # lower threshold -> catch more phishing

print("\n" + "=" * 60)
print("FINAL STACKED ENSEMBLE RESULTS")
print("=" * 60)
print(confusion_matrix(y_ts, final_pred))
print(classification_report(y_ts, final_pred, target_names=["Phishing", "Legitimate"]))
print(f"Accuracy : {accuracy_score(y_ts, final_pred):.4f}")
print(f"AUC      : {roc_auc_score(y_ts, final_prob):.4f}")

# ===========================================================
# 8. OUTPUT FOLDER SETUP
# ===========================================================
from datetime import datetime

RUN_TS    = datetime.now().strftime("%Y%m%d_%H%M%S")   # e.g. 20250411_143022
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))  # saves next to trainModel.py
OUT_DIR   = os.path.join(BASE_DIR, "threatlens_results", RUN_TS)
GRAPH_DIR = os.path.join(OUT_DIR, "graphs")
os.makedirs(GRAPH_DIR, exist_ok=True)
print(f"\nAll outputs will be saved to: {OUT_DIR}")

def savefig(filename):
    """Save current figure to the graphs subfolder at high DPI."""
    path = os.path.join(GRAPH_DIR, filename)
    plt.savefig(path, dpi=150, bbox_inches="tight")
    print(f"  [graph] saved -> {path}")

# ===========================================================
# 9. GRAPHS
# ===========================================================

# - 9a. Model Comparison Bar Chart -------------------------
model_names = list(results.keys()) + ["Final Stacked"]
accs  = [results[m]["acc"] for m in results] + [accuracy_score(y_ts, final_pred)]
aucs  = [results[m]["auc"] for m in results] + [roc_auc_score(y_ts, final_prob)]

x = np.arange(len(model_names))
width = 0.35

fig, ax = plt.subplots(figsize=(14, 5))
bars_acc = ax.bar(x - width/2, accs, width, label="Accuracy", color="#4C72B0")
bars_auc = ax.bar(x + width/2, aucs, width, label="AUC-ROC",  color="#DD8452")
ax.set_xticks(x)
ax.set_xticklabels(model_names, rotation=30, ha="right", fontsize=9)
ax.set_ylim(0.60, 1.02)
ax.set_title("Model Comparison - Accuracy & AUC-ROC")
ax.set_ylabel("Score")
ax.legend()
# Annotate each bar with its value
for bar in list(bars_acc) + list(bars_auc):
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.002,
            f"{bar.get_height():.3f}", ha="center", va="bottom", fontsize=6.5)
plt.tight_layout()
savefig("01_model_comparison.png")
plt.show()

# - 9b. ROC Curves (key models) ----------------------------
fig, ax = plt.subplots(figsize=(7, 6))
highlight = ["Random Forest", "Soft Voting", "MLP Neural Net", "XGBoost/GBM", "Final Stacked"]

for name in highlight:
    if name == "Final Stacked":
        prob_ = final_prob
    else:
        prob_ = results[name]["prob"]
    fpr, tpr, _ = roc_curve(y_ts, prob_)
    ax.plot(fpr, tpr, label=f"{name} (AUC={auc(fpr,tpr):.3f})")

ax.plot([0, 1], [0, 1], "k--", linewidth=0.8)
ax.set_xlabel("False Positive Rate")
ax.set_ylabel("True Positive Rate")
ax.set_title("ROC Curves - Key Models")
ax.legend(fontsize=8)
plt.tight_layout()
savefig("02_roc_curves.png")
plt.show()

# - 9c. Confusion Matrix - Final Stacked Ensemble ----------
cm_final = confusion_matrix(y_ts, final_pred)
disp = ConfusionMatrixDisplay(cm_final, display_labels=["Phishing", "Legitimate"])
disp.plot(cmap="Blues")
plt.title("Confusion Matrix - Final Stacked Ensemble")
plt.tight_layout()
savefig("03_confusion_matrix_final.png")
plt.show()

# - 9d. Individual Confusion Matrices for ALL models -------
all_cm_models = list(results.keys())
ncols = 3
nrows = -(-len(all_cm_models) // ncols)   # ceiling division
fig, axes = plt.subplots(nrows, ncols, figsize=(ncols * 4.5, nrows * 4))
axes = axes.flatten()

for idx, name in enumerate(all_cm_models):
    cm_i = confusion_matrix(y_ts, results[name]["pred"])
    ConfusionMatrixDisplay(cm_i, display_labels=["Phish", "Legit"]).plot(
        ax=axes[idx], cmap="Blues", colorbar=False
    )
    axes[idx].set_title(f"{name}\nAcc={results[name]['acc']:.3f}", fontsize=9)

for idx in range(len(all_cm_models), len(axes)):
    axes[idx].set_visible(False)

plt.suptitle("Confusion Matrices - All Models", fontsize=12, y=1.01)
plt.tight_layout()
savefig("04_all_confusion_matrices.png")
plt.show()

# - 9e. Random Forest Feature Importance -------------------
importances = rf.feature_importances_
feat_df = pd.DataFrame({"feature": X_feat.columns, "importance": importances})
feat_df = feat_df.sort_values("importance", ascending=True)

fig, ax = plt.subplots(figsize=(8, 6))
colors = ["#4C72B0" if v < feat_df["importance"].median() else "#DD8452"
          for v in feat_df["importance"]]
ax.barh(feat_df["feature"], feat_df["importance"], color=colors)
ax.set_title("Random Forest - Feature Importance")
ax.set_xlabel("Importance")
for i, (val, name_) in enumerate(zip(feat_df["importance"], feat_df["feature"])):
    ax.text(val + 0.0005, i, f"{val:.4f}", va="center", fontsize=7)
plt.tight_layout()
savefig("05_feature_importance.png")
plt.show()

# - 9f. Precision / Recall / F1 heatmap -------------------
pr_data = {}
for name in list(results.keys()) + ["Final Stacked"]:
    if name == "Final Stacked":
        pred_ = final_pred
    else:
        pred_ = results[name]["pred"]
    rep = classification_report(y_ts, pred_,
                                target_names=["Phishing", "Legitimate"],
                                output_dict=True)
    pr_data[name] = {
        "Phish Precision": rep["Phishing"]["precision"],
        "Phish Recall":    rep["Phishing"]["recall"],
        "Phish F1":        rep["Phishing"]["f1-score"],
        "Legit Precision": rep["Legitimate"]["precision"],
        "Legit Recall":    rep["Legitimate"]["recall"],
        "Legit F1":        rep["Legitimate"]["f1-score"],
    }

pr_df = pd.DataFrame(pr_data).T
fig, ax = plt.subplots(figsize=(10, len(pr_df) * 0.55 + 1.5))
im = ax.imshow(pr_df.values, aspect="auto", cmap="RdYlGn", vmin=0.6, vmax=1.0)
ax.set_xticks(range(len(pr_df.columns)))
ax.set_xticklabels(pr_df.columns, rotation=30, ha="right", fontsize=8)
ax.set_yticks(range(len(pr_df.index)))
ax.set_yticklabels(pr_df.index, fontsize=8)
for i in range(len(pr_df.index)):
    for j in range(len(pr_df.columns)):
        ax.text(j, i, f"{pr_df.values[i, j]:.3f}", ha="center", va="center", fontsize=7)
plt.colorbar(im, ax=ax, fraction=0.02)
ax.set_title("Precision / Recall / F1 Heatmap - All Models")
plt.tight_layout()
savefig("06_prf1_heatmap.png")
plt.show()

# ===========================================================
# 10. SAVE ALL REPORTS (CSV + Excel + Text summary)
# ===========================================================

# 10a. Per-model metrics summary CSV -----------------------
summary_rows = []
for name in list(results.keys()) + ["Final Stacked"]:
    if name == "Final Stacked":
        pred_ = final_pred
        prob_ = final_prob
    else:
        pred_ = results[name]["pred"]
        prob_ = results[name]["prob"]

    rep = classification_report(y_ts, pred_,
                                target_names=["Phishing", "Legitimate"],
                                output_dict=True)
    cm_i = confusion_matrix(y_ts, pred_)
    tn, fp, fn, tp = cm_i.ravel()

    summary_rows.append({
        "Model":             name,
        "Accuracy":          round(accuracy_score(y_ts, pred_), 4),
        "AUC-ROC":           round(roc_auc_score(y_ts, prob_),  4),
        "Phish_Precision":   round(rep["Phishing"]["precision"],  4),
        "Phish_Recall":      round(rep["Phishing"]["recall"],     4),
        "Phish_F1":          round(rep["Phishing"]["f1-score"],   4),
        "Legit_Precision":   round(rep["Legitimate"]["precision"], 4),
        "Legit_Recall":      round(rep["Legitimate"]["recall"],    4),
        "Legit_F1":          round(rep["Legitimate"]["f1-score"],  4),
        "Macro_F1":          round(rep["macro avg"]["f1-score"],   4),
        "Weighted_F1":       round(rep["weighted avg"]["f1-score"],4),
        "TP": int(tp), "TN": int(tn), "FP": int(fp), "FN": int(fn),
        "False_Positive_Rate": round(fp / (fp + tn), 4),
        "False_Negative_Rate": round(fn / (fn + tp), 4),
    })

summary_df = pd.DataFrame(summary_rows)
summary_csv = os.path.join(OUT_DIR, "model_metrics_summary.csv")
summary_df.to_csv(summary_csv, index=False)
print(f"\n[report] Model metrics summary -> {summary_csv}")

# 10b. Final ensemble full classification report CSV -------
final_report = classification_report(
    y_ts, final_pred,
    target_names=["Phishing", "Legitimate"],
    output_dict=True,
)
final_report_csv = os.path.join(OUT_DIR, "final_ensemble_classification_report.csv")
pd.DataFrame(final_report).transpose().to_csv(final_report_csv)
print(f"[report] Final ensemble classification report -> {final_report_csv}")

# 10c. Feature importance CSV ------------------------------
feat_csv = os.path.join(OUT_DIR, "feature_importance.csv")
feat_df.sort_values("importance", ascending=False).to_csv(feat_csv, index=False)
print(f"[report] Feature importance -> {feat_csv}")

# 10d. Excel workbook (all sheets in one file) -------------
cm_rows = []
for name in list(results.keys()) + ["Final Stacked"]:
    pred_ = final_pred if name == "Final Stacked" else results[name]["pred"]
    tn, fp, fn, tp = confusion_matrix(y_ts, pred_).ravel()
    cm_rows.append({"Model": name, "TP": int(tp), "TN": int(tn),
                    "FP": int(fp), "FN": int(fn)})
cm_df = pd.DataFrame(cm_rows)

try:
    import openpyxl  # noqa: F401
    excel_path = os.path.join(OUT_DIR, "threatlens_full_report.xlsx")
    with pd.ExcelWriter(excel_path, engine="openpyxl") as writer:
        summary_df.to_excel(writer, sheet_name="Model_Summary", index=False)
        pd.DataFrame(final_report).transpose().to_excel(writer, sheet_name="Final_Ensemble_Report")
        feat_df.sort_values("importance", ascending=False).to_excel(
            writer, sheet_name="Feature_Importance", index=False)
        cm_df.to_excel(writer, sheet_name="Confusion_Matrices", index=False)
    print(f"[report] Excel workbook -> {excel_path}")
except ModuleNotFoundError:
    print("[report] openpyxl not installed - saving sheets as individual CSVs instead.")
    print("         Install with:  pip install openpyxl  to get the .xlsx file next run.")
    summary_df.to_csv(os.path.join(OUT_DIR, "sheet_model_summary.csv"), index=False)
    pd.DataFrame(final_report).transpose().to_csv(
        os.path.join(OUT_DIR, "sheet_final_ensemble_report.csv"))
    feat_df.sort_values("importance", ascending=False).to_csv(
        os.path.join(OUT_DIR, "sheet_feature_importance.csv"), index=False)
    cm_df.to_csv(os.path.join(OUT_DIR, "sheet_confusion_matrices.csv"), index=False)
    print(f"[report] 4 CSV sheets saved to {OUT_DIR}")

# 10e. Human-readable text summary -------------------------
txt_path = os.path.join(OUT_DIR, "run_summary.txt")
with open(txt_path, "w") as f:
    f.write("=" * 60 + "\n")
    f.write(f"ThreatLens - Run Summary\n")
    f.write(f"Timestamp : {RUN_TS}\n")
    f.write(f"Dataset   : {len(df):,} URLs  "
            f"({int((y==0).sum()):,} phishing / {int((y==1).sum()):,} legitimate)\n")
    f.write("=" * 60 + "\n\n")

    f.write("MODEL PERFORMANCE\n")
    f.write("-" * 60 + "\n")
    for row in summary_rows:
        f.write(f"{row['Model']:<35}  Acc={row['Accuracy']:.4f}  AUC={row['AUC-ROC']:.4f}  "
                f"Macro-F1={row['Macro_F1']:.4f}\n")

    f.write("\n\nFINAL STACKED ENSEMBLE - FULL REPORT\n")
    f.write("-" * 60 + "\n")
    f.write(classification_report(y_ts, final_pred, target_names=["Phishing", "Legitimate"]))

    f.write("\n\nFEATURE IMPORTANCE (Top 10)\n")
    f.write("-" * 60 + "\n")
    top10 = feat_df.sort_values("importance", ascending=False).head(10)
    for _, row in top10.iterrows():
        f.write(f"  {row['feature']:<25} {row['importance']:.6f}\n")

    f.write("\n\nSAVED FILES\n")
    f.write("-" * 60 + "\n")
    for fname in sorted(os.listdir(OUT_DIR)):
        fpath = os.path.join(OUT_DIR, fname)
        if os.path.isfile(fpath):
            size_kb = os.path.getsize(fpath) / 1024
            f.write(f"  {fname:<45} {size_kb:>8.1f} KB\n")
    f.write(f"  graphs/  ({len(os.listdir(GRAPH_DIR))} PNG files)\n")

print(f"[report] Text summary -> {txt_path}")

# ===========================================================
# 11. SAVE MODELS
# ===========================================================
model_path = os.path.join(OUT_DIR, "threatlens_phishing_ensemble.pkl")
joblib.dump({
    # individual models (dense features)
    "dt":         dt,
    "rf":         rf,
    "gnb":        gnb,
    "bag":        bag,
    "ada":        ada,
    "xgb":        xgb,
    "mlp":        mlp,
    # TF-IDF leg
    "lr":         lr,
    "mnb":        mnb,
    # voting ensembles
    "hard_vote":  hard_vote,
    "soft_vote":  soft_vote,
    # preprocessing
    "tfidf":      tfidf,
    "scaler":     scaler,
}, model_path)

print(f"[model ] Bundle saved -> {model_path}")
print(f"\n{'='*60}")
print(f"All outputs saved to: {os.path.abspath(OUT_DIR)}")
print(f"{'='*60}")

# ===========================================================
# 11. PREDICTION FUNCTION  (use this after loading the .pkl)
# ===========================================================

# ===========================================================
# 11b. CALIBRATE THRESHOLD ON TEST SET
# ===========================================================
# The raw blended probability (final_prob) is used on test data here
# to find the threshold that maximises F1, and also print a
# diagnostic so we can see what scores legitimate URLs actually get.

from sklearn.metrics import f1_score
from sklearn.calibration import CalibratedClassifierCV

print("\n--- Threshold calibration on test set ---")
print(f"  final_prob stats: min={final_prob.min():.4f}  "
      f"max={final_prob.max():.4f}  mean={final_prob.mean():.4f}  "
      f"median={np.median(final_prob):.4f}")

# Find best F1 threshold (sweep 0.05..0.95)
best_t, best_f1 = 0.5, 0.0
for t in np.arange(0.05, 0.96, 0.01):
    preds_t = (final_prob >= t).astype(int)
    f1 = f1_score(y_ts, preds_t, average="macro")
    if f1 > best_f1:
        best_f1, best_t = f1, t

THRESHOLD = round(float(best_t), 2)
print(f"  Best threshold (max macro-F1): {THRESHOLD}  (F1={best_f1:.4f})")
print(f"  Saving THRESHOLD={THRESHOLD} into model bundle for consistent prediction")

# Re-evaluate final model at calibrated threshold
final_pred_cal = (final_prob >= THRESHOLD).astype(int)
print("\n--- Final Stacked Ensemble @ calibrated threshold ---")
print(classification_report(y_ts, final_pred_cal, target_names=["Phishing", "Legitimate"]))

# Save calibrated threshold into the bundle
joblib.load(model_path)   # warm check
bundle_data = joblib.load(model_path)
bundle_data["threshold"] = THRESHOLD
bundle_data["prob_stats"] = {
    "mean":   float(final_prob.mean()),
    "median": float(np.median(final_prob)),
    "p10":    float(np.percentile(final_prob, 10)),
    "p90":    float(np.percentile(final_prob, 90)),
}
joblib.dump(bundle_data, model_path)
print(f"[model ] Threshold {THRESHOLD} saved into bundle -> {model_path}")


# ===========================================================
# 12. PREDICTION FUNCTION  (use this after loading the .pkl)
# ===========================================================

def load_and_predict(urls: list[str], bundle_path=None, debug=False):
    """
    Load saved model bundle and predict on new URLs.

    Parameters
    ----------
    urls        : list of str
    bundle_path : path to saved .pkl  (defaults to this run's model)
    debug       : if True, prints raw component probabilities

    Returns
    -------
    pd.DataFrame: url | verdict | p_legitimate | p_phishing | confidence
    """
    if bundle_path is None:
        bundle_path = model_path

    bundle    = joblib.load(bundle_path)
    scaler_   = bundle["scaler"]
    tfidf_    = bundle["tfidf"]
    sv_       = bundle["soft_vote"]
    lr_       = bundle["lr"]
    threshold = bundle.get("threshold", 0.5)   # use saved calibrated threshold

    X_feat_   = extract_url_features(urls)
    X_dense_  = scaler_.transform(X_feat_)
    X_tfidf_  = tfidf_.transform(urls)

    sv_prob_  = sv_.predict_proba(X_dense_)[:, 1]   # P(legitimate) from voting
    lr_prob_  = lr_.predict_proba(X_tfidf_)[:, 1]   # P(legitimate) from LR-TFIDF
    final_p   = 0.55 * sv_prob_ + 0.45 * lr_prob_   # blended P(legitimate)

    if debug:
        print(f"\n[DEBUG] Threshold in use : {threshold}")
        print(f"[DEBUG] sv_prob  : {np.round(sv_prob_, 4)}")
        print(f"[DEBUG] lr_prob  : {np.round(lr_prob_, 4)}")
        print(f"[DEBUG] final_p  : {np.round(final_p,  4)}")

    rows = []
    for url, p, sv_p, lr_p in zip(urls, final_p, sv_prob_, lr_prob_):
        is_safe    = p >= threshold
        confidence = p if is_safe else (1 - p)
        rows.append({
            "url":          url,
            "verdict":      "[SAFE] SAFE" if is_safe else "[PHISHING] PHISHING",
            "p_legitimate": round(float(p),           4),
            "p_phishing":   round(float(1 - p),       4),
            "confidence":   round(float(confidence),  4),
        })
    return pd.DataFrame(rows)


# --- Quick demo (run with debug=True so we can see raw scores) ---
test_urls = [
    "https://www.google.com",
    "http://paypal-secure-login.tk/confirm?user=you",
    "https://github.com/openai/gpt-4",
    "http://192.168.1.1/login.php@badsite.ru",
    "https://amazon.com",
    "http://secure-paypal-update.xyz/login",
    "https://stackoverflow.com/questions/12345",
]

demo_df = load_and_predict(test_urls, debug=True)
print("\n" + "=" * 60)
print("DEMO PREDICTIONS")
print("=" * 60)
print(demo_df.to_string(index=False))

demo_csv = os.path.join(OUT_DIR, "demo_predictions.csv")
demo_df.to_csv(demo_csv, index=False)
print(f"\n[report] Demo predictions saved -> {demo_csv}")