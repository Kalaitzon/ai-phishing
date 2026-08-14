# AI Phishing Detection System

> MSc Assignment — Advanced Topics in Cybersecurity and Artificial Intelligence  
> University of Piraeus | Department of Digital Systems | 2026  
> **Author:** Ioannis Kalaitzidis

---

## Overview

A Flask-based web application that analyses email files (`.html`, `.eml`, `.docx`) and returns a hybrid risk score by combining:
- A **Support Vector Machine (SVM)** classifier trained on 2,500 samples
- A **weighted heuristic rule engine** with 12 severity-tagged detection rules

The system was extended from a baseline lab provided by the course instructors as part of a 6-task assignment covering feature engineering, model replacement, error analysis, and UI explainability.

---

## Project Structure

```
ai_phishing/
├── data/                  # Datasets (training, homework, challenge)
├── model/                 # Trained SVM pipeline (.joblib) + metrics
├── sample_inputs/         # Test files for manual evaluation
├── templates/             # Jinja2 HTML template (upload.html)
├── app.py                 # Flask web application
├── feature_extraction.py  # Feature engineering + detection rules
├── train_model.py         # Model training pipeline
├── evaluate_model.py      # Model evaluation on challenge dataset
├── requirements.txt       # Python dependencies
└── Report-AI Phishing.docx  # Full assignment report
```

---

## Implemented Tasks

| Task | Description |
|------|-------------|
| Task 1 | Feature Engineering — 4 new handcrafted features including Shannon Entropy for DGA detection |
| Task 2 | Enhanced detection logic — 4 new rules with weighted scoring (0–100) and severity tags |
| Task 3 | Model retraining and evaluation — baseline vs enhanced comparison |
| Task 4 | Model replacement — Logistic Regression → SVM (LinearSVC + CalibratedClassifierCV) |
| Task 5 | Error analysis — 3 FN + 1 FP scenario on adversarial challenge dataset |
| Task 6 | Application extension — Risk Score Breakdown panel + colour-coded cues |
| Optional | Generalization evaluation on `challenge_dataset.csv` (70% vs 100% accuracy) |

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/Kalaitzon/ai-phishing.git
cd ai-phishing

# 2. Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # Linux / macOS

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Train the model
```bash
python train_model.py
```
Trains on `data/dataset_large.csv` by default (2,500 samples, 80/20 split).

### Run the web application
```bash
python app.py
```
Open `http://127.0.0.1:5000/` and upload a `.html`, `.eml`, or `.docx` file.

### Evaluate on challenge dataset
```bash
python evaluate_model.py
```
Runs the trained SVM on `data/challenge_dataset.csv` and prints accuracy, confusion matrix, and per-class metrics.

---

## Results

| Model | Accuracy | Recall (Phishing) |
|-------|----------|-------------------|
| Baseline LR | 99.8% | 99.6% |
| Enhanced LR | 99.8% | 99.6% |
| **SVM (final)** | **100%** | **100%** |
| SVM on challenge set | 70% | 40% |

The gap between 100% (clean dataset) and 70% (adversarial dataset) demonstrates the limitation of static rule-based systems against polite phishing that avoids known keywords.

---

## Dependencies

```
flask
scikit-learn
pandas
joblib
python-docx
beautifulsoup4
lxml
```

---

## Report

The full assignment report (`Report-AI Phishing.docx`) covers all 6 tasks with code snippets, model comparison tables, error analysis, and UI screenshots.
