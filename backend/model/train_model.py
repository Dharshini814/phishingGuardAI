"""
PhishGuard AI – Model Training Pipeline
========================================

Trains three ML classifiers on URL structural features and saves the
best-performing model for use by the prediction API.

Models trained:
    1. Logistic Regression
    2. Decision Tree
    3. Random Forest (typically best performer)

Metric used for model selection:
    F1-score (phishing class) — prioritizes recall of phishing URLs.

Usage:
    cd backend
    python model/train_model.py

Outputs:
    model/phishing_model.pkl   – Trained best model + metadata
    model/model_metrics.json   – Metrics for all models (used by API)
"""

import os
import sys
import json
import warnings

warnings.filterwarnings("ignore")

# Allow importing config and services from the backend root
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND_DIR)

import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
from sklearn.preprocessing import StandardScaler

from services.feature_extraction import extract_features, FEATURE_NAMES
from config import (
    DATASET_PATH, MODEL_PATH, METRICS_PATH,
    RANDOM_STATE, TEST_SIZE, DATA_DIR,
)

# ── Step 1: Load / Generate Dataset ──────────────────────────────────────────

def load_or_generate_dataset() -> pd.DataFrame:
    """
    Load the CSV dataset. If it doesn't exist, run the generator script.
    """
    if not os.path.exists(DATASET_PATH):
        print("[INFO] Dataset not found. Generating from generate_dataset.py ...")
        gen_script = os.path.join(DATA_DIR, "generate_dataset.py")
        if os.path.exists(gen_script):
            import subprocess
            result = subprocess.run(
                [sys.executable, gen_script],
                capture_output=True, text=True
            )
            print(result.stdout)
            if result.returncode != 0:
                raise RuntimeError(f"Dataset generation failed:\n{result.stderr}")
        else:
            raise FileNotFoundError(
                f"Dataset not found at {DATASET_PATH} and no generator script found. "
                "Please provide phishing_dataset.csv in the data/ directory."
            )

    print(f"[INFO] Loading dataset from {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)
    return df


# ── Step 2: Validate and Clean ────────────────────────────────────────────────

def validate_and_clean(df: pd.DataFrame) -> pd.DataFrame:
    """
    Validate that required columns exist and clean the data.
    """
    required_cols = {"url", "label"}
    missing = required_cols - set(df.columns)
    if missing:
        raise ValueError(f"Dataset missing required columns: {missing}")

    original_count = len(df)
    df = df.dropna(subset=["url", "label"])
    df = df[df["url"].str.strip() != ""]
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)
    df = df[df["label"].isin([0, 1])]

    cleaned_count = len(df)
    removed = original_count - cleaned_count
    if removed > 0:
        print(f"[WARN] Removed {removed} invalid rows during cleaning.")

    print(f"[INFO] Dataset: {cleaned_count} valid rows | "
          f"Phishing: {df['label'].sum()} | "
          f"Legitimate: {(df['label']==0).sum()}")
    return df


# ── Step 3: Extract Features ──────────────────────────────────────────────────

def build_feature_matrix(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """
    Apply feature extraction to every URL and return X, y arrays.
    Uses the same extract_features() function as the prediction API.
    """
    print("[INFO] Extracting features ...")
    rows = []
    for url in df["url"]:
        feats = extract_features(str(url))
        row = [feats[name] for name in FEATURE_NAMES]
        rows.append(row)

    X = np.array(rows, dtype=float)
    y = df["label"].values
    print(f"[INFO] Feature matrix: {X.shape} | Labels: {y.shape}")
    return X, y


# ── Step 4: Train/Test Split ──────────────────────────────────────────────────

def split_data(X, y):
    """Stratified train/test split to preserve class ratios."""
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"[INFO] Train: {len(X_train)} | Test: {len(X_test)}")
    return X_train, X_test, y_train, y_test


# ── Step 5: Train and Evaluate Models ────────────────────────────────────────

def compute_metrics(y_true, y_pred, model_name: str) -> dict:
    """
    Compute classification metrics for a trained model.
    Returns a dict with numeric values only (JSON-serializable).
    """
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)

    tn, fp, fn, tp = cm.ravel()

    metrics = {
        "model_name": model_name,
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1_score": round(float(f1), 4),
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
    }

    print(f"\n" + "-"*50)
    print(f" {model_name}")
    print("-"*50)
    print(f"  Accuracy  : {acc:.4f}")
    print(f"  Precision : {prec:.4f}")
    print(f"  Recall    : {rec:.4f}")
    print(f"  F1-Score  : {f1:.4f}")
    print(f"  Confusion Matrix (TN={tn}, FP={fp}, FN={fn}, TP={tp})")

    return metrics


def train_all_models(X_train, X_test, y_train, y_test, scaler):
    """
    Train all three classifiers, evaluate them, and return results.
    """
    # Scale features for Logistic Regression (LR is sensitive to scale)
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    results = []

    # ── Logistic Regression ────────────────────────────────────────────────
    print("\n[TRAIN] Logistic Regression ...")
    lr = LogisticRegression(
        random_state=RANDOM_STATE,
        max_iter=1000,
        C=1.0,
        solver="lbfgs",
    )
    lr.fit(X_train_scaled, y_train)
    y_pred_lr = lr.predict(X_test_scaled)
    lr_metrics = compute_metrics(y_test, y_pred_lr, "Logistic Regression")
    results.append({
        "model": lr,
        "uses_scaler": True,
        "metrics": lr_metrics,
    })

    # ── Decision Tree ──────────────────────────────────────────────────────
    print("\n[TRAIN] Decision Tree ...")
    dt = DecisionTreeClassifier(
        random_state=RANDOM_STATE,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
    )
    dt.fit(X_train, y_train)
    y_pred_dt = dt.predict(X_test)
    dt_metrics = compute_metrics(y_test, y_pred_dt, "Decision Tree")
    results.append({
        "model": dt,
        "uses_scaler": False,
        "metrics": dt_metrics,
    })

    # ── Random Forest ──────────────────────────────────────────────────────
    print("\n[TRAIN] Random Forest ...")
    rf = RandomForestClassifier(
        n_estimators=200,
        random_state=RANDOM_STATE,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    y_pred_rf = rf.predict(X_test)
    rf_metrics = compute_metrics(y_test, y_pred_rf, "Random Forest")

    # Compute feature importances for Random Forest
    feature_importances = [
        {"feature": name, "importance": round(float(imp), 6)}
        for name, imp in zip(FEATURE_NAMES, rf.feature_importances_)
    ]
    feature_importances.sort(key=lambda x: x["importance"], reverse=True)
    rf_metrics["feature_importances"] = feature_importances

    results.append({
        "model": rf,
        "uses_scaler": False,
        "metrics": rf_metrics,
    })

    return results, X_train_scaled, X_test_scaled


# ── Step 6: Select Best Model ─────────────────────────────────────────────────

def select_best_model(results: list) -> dict:
    """
    Select the best model based on F1-score (phishing class recall priority).
    In case of tie, prefer the model with higher recall.
    """
    best = max(results, key=lambda r: (r["metrics"]["f1_score"], r["metrics"]["recall"]))
    print(f"\n[BEST] Selected: {best['metrics']['model_name']} "
          f"(F1={best['metrics']['f1_score']:.4f})")
    return best


# ── Step 7: Save Model ────────────────────────────────────────────────────────

def save_model(best_result: dict, scaler: StandardScaler, all_metrics: list,
               dataset_size: int, train_size: int, test_size: int) -> None:
    """
    Save the best model and all metadata using Joblib.
    """
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)

    model_data = {
        "model": best_result["model"],
        "scaler": scaler if best_result["uses_scaler"] else None,
        "uses_scaler": best_result["uses_scaler"],
        "feature_names": FEATURE_NAMES,
        "model_name": best_result["metrics"]["model_name"],
        "best_metrics": best_result["metrics"],
    }

    joblib.dump(model_data, MODEL_PATH)
    print(f"\n[SAVE] Model saved to: {MODEL_PATH}")

    # Save full metrics JSON for the API
    metrics_data = {
        "dataset_size": dataset_size,
        "train_size": train_size,
        "test_size": test_size,
        "feature_count": len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "best_model": best_result["metrics"]["model_name"],
        "models": [r["metrics"] for r in all_metrics],
    }

    with open(METRICS_PATH, "w") as f:
        json.dump(metrics_data, f, indent=2)
    print(f"[SAVE] Metrics saved to: {METRICS_PATH}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print(" PhishGuard AI - Model Training Pipeline")
    print("=" * 60)

    # 1. Load dataset
    df = load_or_generate_dataset()

    # 2. Clean
    df = validate_and_clean(df)

    # 3. Feature extraction
    X, y = build_feature_matrix(df)

    # 4. Split
    X_train, X_test, y_train, y_test = split_data(X, y)

    # 5. Train all models
    scaler = StandardScaler()
    results, X_train_scaled, X_test_scaled = train_all_models(
        X_train, X_test, y_train, y_test, scaler
    )

    # 6. Select best
    best = select_best_model(results)

    # 7. Save
    save_model(
        best_result=best,
        scaler=scaler,
        all_metrics=results,
        dataset_size=len(df),
        train_size=len(X_train),
        test_size=len(X_test),
    )

    print("\n" + "=" * 60)
    print(" Training complete!")
    print(" Run the API: uvicorn app:app --reload --port 8000")
    print("=" * 60)


if __name__ == "__main__":
    main()
