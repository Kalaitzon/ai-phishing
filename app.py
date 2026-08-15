from __future__ import annotations

from datetime import datetime
from pathlib import Path

import joblib
import pandas as pd
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename

# Import helper functions from our custom feature extraction module
from feature_extraction import (
    compute_handcrafted_features,   # builds the numeric feature dictionary
    extract_content,                 # parses HTML / DOCX / EML files
    get_header_anomalies,           # detects Reply-To / Return-Path mismatches
    log_result,                      # appends one row to the CSV analysis log
    phishing_cues,                   # Task 2: now returns (cues, weighted_score)
)

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = BASE_DIR / "uploads"
MODEL_PATH = BASE_DIR / "model" / "phishing_pipeline.joblib"
LOG_PATH = BASE_DIR / "logs" / "analysis_log.csv"
ALLOWED_EXTENSIONS = {"html", "docx", "eml"}

app = Flask(__name__)
UPLOAD_FOLDER.mkdir(exist_ok=True)

# Load the trained pipeline once at startup (Task 4: now uses LinearSVC via CalibratedClassifierCV)
pipeline = joblib.load(MODEL_PATH)

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def allowed_file(filename: str) -> bool:
    # Only accept the three file types supported by extract_content()
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
 
# ── Task 6 ─────────────────────────────────────────────────────
# Original version returned a single risk score (black-box output).
# New version returns a tuple so the UI can show ML probability and
# rule score separately (Explainability principle – Lecture 7).
 
# def calculate_risk(model_probability: float, cues: list[str], header_anomalies: list[str], feature_map: dict[str, float]) -> float:
#     heuristic_score = min(
#         1.0,
#         (len(cues) * 0.07)
#         + (len(header_anomalies) * 0.09)
#         + (feature_map.get("suspicious_domain_count", 0) * 0.12)
#         + (feature_map.get("ip_url_count", 0) * 0.15)
#         + (feature_map.get("urgency_count", 0) * 0.04)
#         + (feature_map.get("sensitive_count", 0) * 0.05)
#         + (feature_map.get("url_shortener_count", 0) * 0.08),
#     )
#     return round(min(1.0, 0.68 * float(model_probability) + 0.32 * heuristic_score), 4)
 
def calculate_risk(
    model_probability: float,
    cues: list[str],
    header_anomalies: list[str],
    feature_map: dict[str, float],
) -> tuple[float, float]:
    """Hybrid scoring: 68 % ML signal + 32 % heuristic signal.
    Returns (combined_risk, heuristic_score) both in [0, 1]."""
    heuristic_score = min(
        1.0,
        # Original baseline weights
        (len(cues) * 0.07)
        + (len(header_anomalies) * 0.09)
        + (feature_map.get("suspicious_domain_count", 0) * 0.12)
        + (feature_map.get("ip_url_count", 0) * 0.15)
        + (feature_map.get("urgency_count", 0) * 0.04)
        + (feature_map.get("sensitive_count", 0) * 0.05)
        + (feature_map.get("url_shortener_count", 0) * 0.08)
        # Task 1: new handcrafted features contribute to the heuristic score
        + (feature_map.get("reward_bait_count", 0) * 0.07)       # prize / lure language
        + (feature_map.get("at_symbol_url_count", 0) * 0.18)     # @ redirect trick in URLs
        + (feature_map.get("display_name_spoof", 0) * 0.22)      # sender identity spoofing
        # ── Task 6 ─────────────────────────────────────────────────────
        # Task 1 Feature 4: entropy > 3.5 flags algorithmically generated (DGA) domains
        + (1.0 if feature_map.get("max_url_entropy", 0) > 3.5 else 0.0) * 0.15
    )
    combined = round(
        min(1.0, 0.68 * float(model_probability) + 0.32 * heuristic_score), 4
    )
    return combined, round(heuristic_score, 4)
 
 
def label_from_risk(risk: float) -> str:
    # Map numeric risk to a human-readable verdict shown in the UI
    if risk >= 0.72:
        return "Likely phishing"
    if risk >= 0.45:
        return "Suspicious / needs review"
    return "Likely legitimate"
 
 
def risk_band(risk: float) -> str:
    # Used by Jinja2 to select the correct CSS colour class (high / medium / low)
    if risk >= 0.72:
        return "high"
    if risk >= 0.45:
        return "medium"
    return "low"
 
 
@app.route("/", methods=["GET", "POST"])
def index():
    # Default context for GET requests – all fields empty until a file is uploaded
    context = {
        "result": None,
        "risk_score": None,
        "model_probability": None,
        "cues": None,
        "header_anomalies": None,
        "features": None,
        "filename": None,
        "risk_percent": None,
        "risk_band": None,
    }
    if request.method == "POST":
        # 1. Validate the uploaded file
        file = request.files.get("file")
        if not file or not file.filename:
            context["result"] = "No file was selected."
            return render_template("upload.html", **context)
        if not allowed_file(file.filename):
            context["result"] = "Unsupported file type. Use .html, .docx, or .eml"
            return render_template("upload.html", **context)
 
        # 2. Save file and extract text, URLs, and email headers
        filename = secure_filename(file.filename)
        path = UPLOAD_FOLDER / filename
        file.save(path)
 
        parsed = extract_content(str(path))
        text = parsed["text"]
        urls = parsed["urls"]
        headers = parsed["headers"]
 
        # 3. ML model: predict_proba returns [P(legitimate), P(phishing)]; take index 1
        model_probability = float(pipeline.predict_proba(pd.DataFrame({"text": [text]}))[0][1])
 
        # 4. Compute all 19 handcrafted numeric features (includes 4 new ones from Task 1)
        feature_map = compute_handcrafted_features(text, urls, headers)
 
        # ── Task 6 ─────────────────────────────────────────────────────
        # Original: returned only a list of cue strings
        # cues = phishing_cues(text, urls, headers)
        #
        # Task 2 + Task 6: phishing_cues() now returns a tuple:
        #   cues              – list of severity-tagged explanation strings
        #   heuristic_score_raw – weighted integer 0-100 (capped at 100)
        cues, heuristic_score_raw = phishing_cues(text, urls, headers)
 
        # 5. Separate header anomaly check (Reply-To / Return-Path mismatches)
        header_anomalies = get_header_anomalies(headers)
 
        # ── Task 6 ─────────────────────────────────────────────────────
        # Original: risk_score = calculate_risk(model_probability, cues, header_anomalies, feature_map)
        #
        # New: unpack tuple; we use heuristic_score_raw (0-100) for the UI
        # and discard the internal [0,1] value from calculate_risk
        risk_score, heuristic_score = calculate_risk(
            model_probability, cues, header_anomalies, feature_map
        )
        # Use the weighted rule score (0-100) from phishing_cues for display
        heuristic_score = heuristic_score_raw
 
        result = label_from_risk(risk_score)
 
        # 6. Append this analysis to the CSV log for later review
        log_result(
            str(LOG_PATH),
            {
                "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                "filename": filename,
                "prediction": result,
                "risk_score": risk_score,
                "model_probability": round(model_probability, 4),
                "cue_count": len(cues),
                "header_anomaly_count": len(header_anomalies),
                "triggered_cues": "; ".join(cues),
            },
        )
 
        # 7. Pass all values to the Jinja2 template
        context.update(
            {
                "filename": filename,
                "result": result,
                "risk_score": risk_score,
                "risk_percent": int(round(risk_score * 100)),
                "risk_band": risk_band(risk_score),
                "model_probability": round(model_probability, 4),
                "cues": cues or ["No obvious phishing cues detected"],
                "header_anomalies": header_anomalies or ["No header anomalies detected"],
                "features": feature_map,
                # ── Task 6 ─────────────────────────────────────────────────────
                # New context variable: exposes the heuristic rule score (0-100)
                # to the UI so ML probability and rule score are shown separately
                "heuristic_score": heuristic_score_raw,
            }
        )
    return render_template("upload.html", **context)
 
 
if __name__ == "__main__":
    app.run(debug=True)
