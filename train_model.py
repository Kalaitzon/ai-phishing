# ── Kalaitzidis Ioannis - MTE25012 ─────────────────────────────────────────────────────

from __future__ import annotations

import json
import os
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer

# ── Task 4 ─────────────────────────────────────────────────────
# Original classifier – Logistic Regression (baseline):
# from sklearn.linear_model import LogisticRegression
#
# Replaced with LinearSVC (Support Vector Machine) as the alternative model.
# LinearSVC is efficient in high-dimensional spaces (thousands of TF-IDF features).
# CalibratedClassifierCV wraps it to enable predict_proba(), which is required
# by app.py to compute the ML probability component of the risk score.
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV

from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer

# build_numeric_feature_frame feeds handcrafted features (Task 1) into the pipeline
from feature_extraction import build_numeric_feature_frame

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
DEFAULT_DATASET = DATA_DIR / "dataset_large.csv"
MODEL_DIR = ROOT / "model"


def build_pipeline() -> Pipeline:
    # Text branch: TF-IDF converts email text into a sparse matrix of n-gram weights.
    # ngram_range=(1,2) captures single words and two-word phrases.
    # min_df=2 ignores tokens that appear in fewer than 2 documents (noise reduction).
    text_features = TfidfVectorizer(ngram_range=(1, 2), min_df=2, stop_words="english")

    # Numeric branch: applies build_numeric_feature_frame to produce the
    # 19 handcrafted features defined in feature_extraction.py (including
    # the 4 new ones added in Task 1).
    numeric_features = FunctionTransformer(build_numeric_feature_frame, validate=False)

    # ColumnTransformer runs both branches on the "text" column in parallel
    # and concatenates their outputs into one feature matrix.
    preprocessor = ColumnTransformer(
        transformers=[
            ("text",    text_features,    "text"),
            ("numeric", numeric_features, "text"),
        ]
    )

    # ── Task 4 ─────────────────────────────────────────────────────
    # Original classifier (baseline – Logistic Regression):
    # model = LogisticRegression(max_iter=1200, class_weight="balanced")
    #
    # New classifier: LinearSVC wrapped in CalibratedClassifierCV (Task 4 – SVM).
    # class_weight="balanced" compensates for any class imbalance in the dataset.
    # cv=3 uses 3-fold cross-validation to fit the probability calibrator.
    model = CalibratedClassifierCV(
        LinearSVC(max_iter=2000, class_weight="balanced"),
        cv=3
    )

    # Assemble the full pipeline: preprocessing → classifier
    return Pipeline([
        ("preprocessor", preprocessor),
        ("classifier",   model),
    ])


def main() -> None:
    # Allow the dataset to be overridden via an environment variable,
    # defaulting to dataset_large.csv (2500 samples, balanced 50/50).
    dataset_name = os.environ.get("PHISHING_DATASET", "dataset_large.csv")
    data_path = DATA_DIR / dataset_name
    if not data_path.exists():
        raise FileNotFoundError(f"Dataset not found: {data_path}")

    df = pd.read_csv(data_path)
    X = df[["text"]]
    # Convert string labels to binary targets: phishing = 1, legitimate = 0
    y = (df["label"] == "phishing").astype(int)

    # Stratified 80/20 split ensures both classes are proportionally represented
    # in training and test sets (random_state=42 for reproducibility).
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Train the full pipeline (TF-IDF + numeric features + SVM)
    pipeline = build_pipeline()
    pipeline.fit(X_train, y_train)

    # Evaluate on the held-out test set
    preds  = pipeline.predict(X_test)
    report = classification_report(
        y_test, preds,
        target_names=["legitimate", "phishing"],
        output_dict=True
    )

    # Persist the trained pipeline so app.py can load it at runtime
    MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump(pipeline, MODEL_DIR / "phishing_pipeline.joblib")

    # ── Task 4 ─────────────────────────────────────────────────────
    # Original: saved to metrics.json (baseline Logistic Regression results).
    # with open(MODEL_DIR / "metrics.json", "w", encoding="utf-8") as f:
    #
    # Changed to metrics_svm.json so the SVM results are stored separately
    # and the baseline metrics.json is preserved for Task 3 comparison.
    with open(MODEL_DIR / "metrics_svm.json", "w", encoding="utf-8") as f:
        json.dump({"dataset": dataset_name, "rows": len(df), "report": report}, f, indent=2)

    print("Dataset:", data_path)
    print("Rows:",    len(df))
    print("Model saved to", MODEL_DIR / "phishing_pipeline.joblib")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()