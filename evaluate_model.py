# ── Kalaitzidis Ioannis - MTE25012 ─────────────────────────────────────────────────────

from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

ROOT = Path(__file__).resolve().parent

# Task 5 ─────────────────────────────────────────────────────
# Original dataset path (generic name, did not exist in the project):
# DATA_PATH = ROOT / "data" / "dataset.csv"
#
# Changed to challenge_dataset.csv for Task 5 Error Analysis.
# This dataset contains 10 adversarial / borderline samples (5 phishing, 5 legitimate)
# designed to stress-test the model on polite phishing that avoids obvious keywords.
DATA_PATH  = ROOT / "data" / "challenge_dataset.csv"
MODEL_PATH = ROOT / "model" / "phishing_pipeline.joblib"


def main() -> None:
    # Load the challenge dataset – labels are "phishing" or "legitimate"
    df = pd.read_csv(DATA_PATH)
    X = df[["text"]]
    # Convert string labels to binary: phishing = 1, legitimate = 0
    y = (df["label"] == "phishing").astype(int)

    # Load the trained pipeline (SVM after Task 4)
    pipeline = joblib.load(MODEL_PATH)

    # Generate hard predictions and phishing probabilities
    preds = pipeline.predict(X)
    probs = pipeline.predict_proba(X)[:, 1]   # probability of phishing class

    # Print overall accuracy
    print("Accuracy:", round(accuracy_score(y, preds), 4))

    # Confusion matrix layout:
    #   [[TN  FP]
    #    [FN  TP]]
    # FP = legitimate email flagged as phishing (false alarm)
    # FN = phishing email missed by the model   (dangerous)
    print("Confusion matrix:")
    print(confusion_matrix(y, preds))

    # Full per-class breakdown: precision, recall, f1-score
    print("\nClassification report:")
    print(classification_report(y, preds, target_names=["legitimate", "phishing"]))

    # Save detailed per-sample predictions for deeper error analysis (Task 5)
    out = pd.DataFrame({
        "text":                 df["text"],
        "true_label":           df["label"],
        "predicted_label":      ["phishing" if p == 1 else "legitimate" for p in preds],
        "phishing_probability": probs,
    })
    out_path = ROOT / "logs" / "evaluation_predictions.csv"
    out.to_csv(out_path, index=False)
    print(f"Saved detailed predictions to {out_path}")


if __name__ == "__main__":
    main()