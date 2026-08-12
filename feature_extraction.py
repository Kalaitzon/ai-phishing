# ── Kalaitzidis Ioannis - MTE25012 ─────────────────────────────────────────────────────

from __future__ import annotations

import csv
import email
import os
import re
import unicodedata
from dataclasses import dataclass
from email import policy
from pathlib import Path
from typing import Any

# ── Task 1 ─────────────────────────────────────────────────────
# math is required for the Shannon entropy calculation (Feature 4 / _domain_entropy)
import math

from urllib.parse import urlparse

from bs4 import BeautifulSoup   # HTML parsing
from docx import Document        # DOCX parsing


# ── NEW PATTERNS – Task 1 ─────────────────────────────────────────────────────

# Feature 1: Reward / incentive bait language — targets advance-fee fraud and
# credential phishing that avoids urgency/threat vocabulary entirely.
REWARD_BAIT_PATTERNS = [
    r"\bwon\b", r"\bwinner\b", r"\bprize\b", r"\breward\b",
    r"\bgift card\b", r"\bcongratulations?\b", r"\bselected\b",
    r"\bexclusive offer\b", r"\bclaim your\b", r"\bfree access\b",
    r"\byou have been chosen\b", r"\bspecial deal\b",
]

# Feature 3 / Rule B: Trusted organisation names used in display-name spoofing checks.
DISPLAY_NAME_ORGS = [
    "paypal", "microsoft", "google", "amazon", "apple", "netflix",
    "it support", "hr", "payroll", "helpdesk", "security team",
    "admin", "administrator", "noreply", "no-reply", "support",
]

# Rule C: URL path keywords that indicate credential-harvesting landing pages.
REDIRECT_PATH_KEYWORDS = [
    "/login", "/signin", "/sign-in", "/verify", "/auth",
    "/account-confirm", "/secure-access", "/update-credentials",
    "/credential", "/password-reset",
]

# ── Baseline pattern lists (original) ────────────────────────────────────────

# Free email domains — used to detect senders who should be using corporate addresses.
FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "live.com", "aol.com", "proton.me", "protonmail.com"
}

# Psychological pressure patterns — time-based and imperative language.
URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\basap\b", r"\baction required\b",
    r"\bfinal warning\b", r"\bwithin \d+ hours?\b", r"\bnow\b", r"\btoday\b"
]

# Direct credential / account data requests.
SENSITIVE_PATTERNS = [
    r"\bpassword\b", r"\bcredentials\b", r"\bcredit card\b",
    r"\bbank(ing)? information\b", r"\bssn\b", r"\blogin details\b",
    r"\bverification code\b", r"\baccount number\b"
]

# Call-to-action verbs typical in phishing landing-page redirects.
ACTION_PATTERNS = [
    r"\bclick here\b", r"\bverify\b", r"\bconfirm\b", r"\breset\b",
    r"\blog in\b", r"\bsign in\b", r"\bupdate\b", r"\bunlock\b", r"\benroll\b"
]

# Fear / punishment language designed to pressure immediate action.
THREAT_PATTERNS = [
    r"\bsuspended\b", r"\blocked\b", r"\bdeactivated\b", r"\bterminated\b",
    r"\bdisabled\b", r"\block(ed|out)\b", r"\bunauthorized\b", r"\bcompromised\b"
]

# Impersonal greetings — signal mass-mailing rather than targeted communication.
GENERIC_GREETING_PATTERNS = [
    r"\bdear customer\b", r"\bdear user\b", r"\bdear valued customer\b",
    r"\bhello\b", r"\battention\b"
]

# Safety/risk language used to lower the victim's guard through false authority.
EMOTIONAL_PATTERNS = [
    r"\bprotect your information\b", r"\bfor your safety\b",
    r"\bsecurity alert\b", r"\brisk\b", r"\bthreat\b",
    r"\bfraud\b", r"\bunauthorized\b"
]

# General URL extractor — matches http/https and bare www. links.
URL_REGEX = re.compile(r"https?://[^\s'\">)]+|www\.[^\s'\">)]+", re.I)

# Detects links that point directly to a raw IP address (e.g. http://192.168.1.1/login).
IP_URL_REGEX = re.compile(
    r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|\b)", re.I
)

# Detects known typosquatting patterns (character substitution in well-known brand names).
SUSPICIOUS_DOMAIN_REGEX = re.compile(
    r"(?:paypa1|micr0soft|secure-|verify-|account-|billing-|auth-update|transaction-review)",
    re.I
)


# ── Data class for email header fields ───────────────────────────────────────
@dataclass
class ParsedEmail:
    """Holds the five header fields we inspect for anomalies."""
    subject: str = ""
    from_addr: str = ""
    to_addr: str = ""
    reply_to: str = ""
    return_path: str = ""


def sanitize_text(text: str) -> str:
    """Normalise Unicode to remove homoglyph / encoding tricks."""
    return unicodedata.normalize("NFKD", text).encode("utf-8", "ignore").decode("utf-8", "ignore")


# ── Task 1 – Feature 4 ────────────────────────────────────────────────────────
def _domain_entropy(domain: str) -> float:
    """Compute Shannon entropy H = -Σ p(x) log₂ p(x) over the characters of a domain.

    Natural domains (e.g. 'google.com') have low entropy because characters
    are distributed in recognisable patterns.  DGA-generated domains
    (e.g. 'x9f2k-zqp.cc') have high entropy because characters are random.
    A threshold of 3.5 bits is used to flag suspicious domains.
    """
    if not domain or len(domain) < 3:
        return 0.0
    freq = {}
    for ch in domain:
        freq[ch] = freq.get(ch, 0) + 1
    return round(
        -sum((f / len(domain)) * math.log2(f / len(domain))
             for f in freq.values()), 4
    )


# ── File parsers ─────────────────────────────────────────────────────────────

def _read_html(path: str) -> tuple[str, list[str]]:
    """Extract visible text and all href links from an HTML file."""
    with open(path, encoding="utf-8", errors="ignore") as f:
        raw = f.read()
    soup = BeautifulSoup(raw, "html.parser")
    text = soup.get_text(" ", strip=True)
    urls = []
    for a in soup.find_all("a", href=True):
        urls.append(a["href"].strip())
    urls.extend(URL_REGEX.findall(raw))
    return text, sorted(set(urls))


def _read_docx(path: str) -> tuple[str, list[str]]:
    """Extract paragraph text and inline URLs from a Word document."""
    text = "\n".join(p.text for p in Document(path).paragraphs)
    return text, URL_REGEX.findall(text)


def _read_eml(path: str) -> tuple[str, list[str], ParsedEmail]:
    """Parse an RFC-2822 email: extract body text, URLs, and header fields.

    Walks all MIME parts; prefers plain-text but falls back to HTML.
    """
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    body_parts = []
    urls = []
    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type == "text/plain":
            try:
                body_parts.append(part.get_content())
            except Exception:
                pass
        elif content_type == "text/html":
            try:
                html = part.get_content()
                txt, found = _read_html_from_string(html)
                body_parts.append(txt)
                urls.extend(found)
            except Exception:
                pass

    # Fallback: some emails expose the body only via get_body()
    if not body_parts:
        try:
            payload = msg.get_body(preferencelist=("plain", "html"))
            if payload:
                content = payload.get_content()
                if payload.get_content_type() == "text/html":
                    txt, found = _read_html_from_string(content)
                    body_parts.append(txt)
                    urls.extend(found)
                else:
                    body_parts.append(content)
        except Exception:
            pass

    parsed = ParsedEmail(
        subject=str(msg.get("Subject", "") or ""),
        from_addr=str(msg.get("From", "") or ""),
        to_addr=str(msg.get("To", "") or ""),
        reply_to=str(msg.get("Reply-To", "") or ""),
        return_path=str(msg.get("Return-Path", "") or ""),
    )
    full_text = "\n".join(filter(None, [parsed.subject, *body_parts]))
    urls.extend(URL_REGEX.findall(full_text))
    return full_text, sorted(set(urls)), parsed


def _read_html_from_string(raw: str) -> tuple[str, list[str]]:
    """Same as _read_html but accepts a raw HTML string instead of a file path."""
    soup = BeautifulSoup(raw, "html.parser")
    text = soup.get_text(" ", strip=True)
    urls = [a["href"].strip() for a in soup.find_all("a", href=True)]
    urls.extend(URL_REGEX.findall(raw))
    return text, sorted(set(urls))


def extract_content(path: str) -> dict[str, Any]:
    """Route the file to the correct parser based on its extension.

    Returns a dict with keys: 'text', 'urls', 'headers'.
    HTML and DOCX files get an empty ParsedEmail() for headers.
    """
    ext = Path(path).suffix.lower()
    if ext == ".html":
        text, urls = _read_html(path)
        headers = ParsedEmail()
    elif ext == ".docx":
        text, urls = _read_docx(path)
        headers = ParsedEmail()
    elif ext == ".eml":
        text, urls, headers = _read_eml(path)
    else:
        raise ValueError(f"Unsupported file type: {ext}")

    text = sanitize_text(text)
    return {"text": text, "urls": urls, "headers": headers}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _count_matches(text: str, patterns: list[str]) -> int:
    """Return how many regex patterns match (case-insensitive) in text."""
    return sum(1 for p in patterns if re.search(p, text, re.I))


def get_header_anomalies(headers: ParsedEmail) -> list[str]:
    """Detect mismatches between From, Reply-To, and Return-Path domains.

    A legitimate email typically has matching domains across all three fields.
    Mismatches are a strong indicator of sender spoofing.
    """
    anomalies: list[str] = []
    from_domain   = extract_domain(headers.from_addr)
    reply_domain  = extract_domain(headers.reply_to)
    return_domain = extract_domain(headers.return_path)

    if from_domain and from_domain in FREE_EMAIL_DOMAINS:
        anomalies.append("From address uses a free email provider")
    if from_domain and reply_domain and from_domain != reply_domain:
        anomalies.append("Reply-To domain differs from From domain")
    if from_domain and return_domain and from_domain != return_domain:
        anomalies.append("Return-Path domain differs from From domain")
    return anomalies


def extract_domain(value: str) -> str:
    """Extract the domain part from an email address string (e.g. 'user@example.com' → 'example.com')."""
    if not value:
        return ""
    match = re.search(r"@([A-Za-z0-9.-]+)", value)
    return match.group(1).lower() if match else ""


# ── Feature computation ───────────────────────────────────────────────────────

def compute_handcrafted_features(
    text: str,
    urls: list[str] | None = None,
    headers: ParsedEmail | None = None,
) -> dict[str, float]:
    """Build a dictionary of 19 numeric features for a given email sample.

    15 features are from the original baseline; 4 new features were added in Task 1:
        - reward_bait_count   (Feature 1)
        - at_symbol_url_count (Feature 2)
        - display_name_spoof  (Feature 3)
        - max_url_entropy     (Feature 4)
    """
    urls    = urls or []
    headers = headers or ParsedEmail()
    lowered = text.lower()
    words   = re.findall(r"\b\w+\b", lowered)
    exclamations   = text.count("!")
    uppercase_ratio = (sum(1 for c in text if c.isupper()) / max(len(text), 1))

    # Counters initialised before the URL loop
    suspicious_domains = 0
    ip_urls            = 0
    shorteners         = 0
    at_symbol_urls     = 0      # Task 1 – Feature 2
    max_url_entropy    = 0.0    # Task 1 – Feature 4

    for url in urls:
        parsed = urlparse(url if url.startswith("http") else f"http://{url}")
        host   = (parsed.netloc or parsed.path).lower()

        if IP_URL_REGEX.search(url):
            ip_urls += 1
        if SUSPICIOUS_DOMAIN_REGEX.search(host):
            suspicious_domains += 1
        if any(short in host for short in ["bit.ly", "tinyurl.com", "t.co", "rb.gy"]):
            shorteners += 1

        # Feature 2: @ in URL body signals the credential-redirect trick
        # (everything before @ is treated as credentials by the browser)
        if "@" in url:
            at_symbol_urls += 1

        # Feature 4: track the highest Shannon entropy seen across all URLs
        parsed_host = (urlparse(url if url.startswith("http") else f"http://{url}").netloc or "").lower()
        if parsed_host:
            ent = _domain_entropy(parsed_host)
            if ent > max_url_entropy:
                max_url_entropy = ent

    # Feature 1: count reward / bait vocabulary matches
    reward_bait_count = float(_count_matches(lowered, REWARD_BAIT_PATTERNS))

    # Feature 3: binary flag — 1.0 if the From display name claims to be a
    # trusted organisation but the actual sending domain does not match.
    display_name_spoof = 0.0
    if headers and headers.from_addr:
        from_raw = headers.from_addr.lower()
        m = re.match(r'^(.+?)\s*<', from_raw)
        if m:
            display_name   = m.group(1).strip().strip('"\'')
            from_domain_val = extract_domain(headers.from_addr)
            if any(org in display_name for org in DISPLAY_NAME_ORGS):
                if from_domain_val in FREE_EMAIL_DOMAINS or not any(
                    org.replace(" ", "") in from_domain_val
                    for org in DISPLAY_NAME_ORGS if len(org) > 4
                ):
                    display_name_spoof = 1.0

    header_anomalies = len(get_header_anomalies(headers))

    return {
        # ── Baseline features ────────────────────────────────────────────────
        "char_count":              float(len(text)),
        "word_count":              float(len(words)),
        "url_count":               float(len(urls)),
        "ip_url_count":            float(ip_urls),
        "suspicious_domain_count": float(suspicious_domains),
        "url_shortener_count":     float(shorteners),
        "urgency_count":           float(_count_matches(lowered, URGENCY_PATTERNS)),
        "sensitive_count":         float(_count_matches(lowered, SENSITIVE_PATTERNS)),
        "action_count":            float(_count_matches(lowered, ACTION_PATTERNS)),
        "threat_count":            float(_count_matches(lowered, THREAT_PATTERNS)),
        "generic_greeting_count":  float(_count_matches(lowered, GENERIC_GREETING_PATTERNS)),
        "emotional_tone_count":    float(_count_matches(lowered, EMOTIONAL_PATTERNS)),
        "exclamation_count":       float(exclamations),
        "uppercase_ratio":         float(round(uppercase_ratio, 5)),
        "header_anomaly_count":    float(header_anomalies),
        # ── Task 1 new features ──────────────────────────────────────────────
        "reward_bait_count":       reward_bait_count,
        "at_symbol_url_count":     float(at_symbol_urls),
        "display_name_spoof":      display_name_spoof,
        "max_url_entropy":         round(max_url_entropy, 4),
    }


# ── Task 2: Enhanced phishing cues ───────────────────────────────────────────

# Original phishing_cues() returned a plain list[str] with one-word labels.
# Problems: no context, no severity, no scoring, no redundancy control.
#
# def phishing_cues(text, urls=None, headers=None) -> list[str]:
#     cues = []
#     if _count_matches(text, URGENCY_PATTERNS):
#         cues.append("Urgency language detected")
#     if _count_matches(text, ACTION_PATTERNS):
#         cues.append("Action-oriented request detected")
#     if _count_matches(text, SENSITIVE_PATTERNS):
#         cues.append("Sensitive information request detected")
#     if _count_matches(text, THREAT_PATTERNS):
#         cues.append("Threat or punishment language detected")
#     if _count_matches(text, GENERIC_GREETING_PATTERNS):
#         cues.append("Generic greeting detected")
#     if _count_matches(text, EMOTIONAL_PATTERNS):
#         cues.append("Fear or emotional manipulation language detected")
#     if any(IP_URL_REGEX.search(u) for u in urls):
#         cues.append("IP-based URL detected")
#     if any(SUSPICIOUS_DOMAIN_REGEX.search(u) for u in urls):
#         cues.append("Potential spoofed or suspicious domain detected")
#     cues.extend(get_header_anomalies(headers))
#     return cues

# ── Task 2 ──────────────────────────────────────────────

def phishing_cues(
    text: str,
    urls: list[str] | None = None,
    headers: ParsedEmail | None = None,
) -> tuple[list[str], int]:
    """Return (cues, heuristic_score 0-100) with weighted severity scoring.

    Each rule appends a severity-tagged explanation string and adds a weight
    to the running score.  The score is capped at 100 to avoid overflow.
    Returning a tuple (instead of a plain list) allows app.py to display
    the heuristic score separately from the ML probability (Task 6 / Explainability).
    """
    urls    = urls or []
    headers = headers or ParsedEmail()
    cues: list[str] = []
    lowered = text.lower()
    score   = 0

    # ── Improved baseline rules (Task 2: added severity tags + explanations) ─

    if _count_matches(text, URGENCY_PATTERNS):
        cues.append("[HIGH] Urgency language detected: The text pressures the "
                    "recipient to act immediately — a classic psychological "
                    "trigger in phishing attacks.")
        score += 25

    if _count_matches(text, ACTION_PATTERNS):
        cues.append("[MEDIUM] Action-oriented request detected: Contains explicit "
                    "instructions to click, verify or reset credentials — typical "
                    "of credential harvesting.")
        score += 15

    if _count_matches(text, SENSITIVE_PATTERNS):
        cues.append("[CRITICAL] Sensitive information request: Direct attempt to "
                    "collect passwords, banking details or account credentials.")
        score += 35

    if _count_matches(text, THREAT_PATTERNS):
        cues.append("[HIGH] Threat language detected: Attempts to frighten the "
                    "user by claiming their account is suspended or locked.")
        score += 25

    if _count_matches(text, GENERIC_GREETING_PATTERNS):
        cues.append("[LOW] Generic greeting detected: The message lacks "
                    "personalisation (e.g. 'Dear Customer'), typical of "
                    "mass phishing campaigns.")
        score += 10

    if _count_matches(text, EMOTIONAL_PATTERNS):
        cues.append("[MEDIUM] Emotional manipulation detected: Uses false security "
                    "alerts or safety promises to lower the recipient's guard.")
        score += 15

    if any(IP_URL_REGEX.search(u) for u in urls):
        cues.append("[CRITICAL] IP-based URL detected: A link points directly to "
                    "a raw IP address instead of a legitimate domain name.")
        score += 40

    if any(SUSPICIOUS_DOMAIN_REGEX.search(u) for u in urls):
        cues.append("[CRITICAL] Spoofed domain detected: A link mimics a "
                    "well-known platform using character substitution.")
        score += 40

    # ── NEW RULE A: Reward / Incentive Bait ──────────────────────────────────
    # Targets phishing that avoids urgency/threat vocabulary entirely.
    if _count_matches(lowered, REWARD_BAIT_PATTERNS):
        cues.append("[HIGH] Reward bait language detected: Words such as 'prize', "
                    "'winner' or 'exclusive offer' lure victims — common in "
                    "advance-fee fraud and credential phishing.")
        score += 28

    # ── NEW RULE B: Display-Name Spoofing ────────────────────────────────────
    # Checks whether the visible sender name claims a trusted org while the
    # actual sending domain is a free provider or an unrelated domain.
    if headers and headers.from_addr:
        from_raw = headers.from_addr.lower()
        m = re.match(r'^(.+?)\s*<', from_raw)
        if m:
            display_name    = m.group(1).strip().strip('"\'')
            from_domain_val = extract_domain(headers.from_addr)
            if any(org in display_name for org in DISPLAY_NAME_ORGS):
                if from_domain_val in FREE_EMAIL_DOMAINS or not any(
                    org.replace(" ", "") in from_domain_val
                    for org in DISPLAY_NAME_ORGS if len(org) > 4
                ):
                    cues.append(
                        f"[CRITICAL] Display-name spoofing detected: The sender "
                        f"claims to be a trusted organisation but the actual "
                        f"domain '{from_domain_val}' does not match."
                    )
                    score += 38

    # ── NEW RULE C: Credential Redirect Path ─────────────────────────────────
    # any() prevents duplicate alerts if multiple links share the same keyword.
    if any(kw in u.lower() for u in urls for kw in REDIRECT_PATH_KEYWORDS):
        cues.append("[HIGH] Credential redirect URL detected: At least one link "
                    "contains /login, /verify or /auth — used on spoofed landing "
                    "pages to harvest credentials.")
        score += 25

    # ── NEW RULE D: High-Entropy Domain (DGA Detection) ──────────────────────
    # Reuses _domain_entropy() from Task 1 Feature 4.
    # Threshold of 3.5 bits flags algorithmically generated domains.
    high_entropy_urls = []
    for u in urls:
        host = (urlparse(u if u.startswith("http") else f"http://{u}").netloc or "").lower()
        if host and _domain_entropy(host) > 3.5:
            high_entropy_urls.append(host)
    if high_entropy_urls:
        cues.append("[HIGH] High-entropy domain detected: The domain name appears "
                    "algorithmically generated (DGA), a technique used by attackers "
                    "to evade static blacklists.")
        score += 30

    # ── Header anomalies (one cue per anomaly detected) ──────────────────────
    for anomaly in get_header_anomalies(headers):
        cues.append(f"[CRITICAL] Email header anomaly: {anomaly}")
        score += 30

    # Cap the total score at 100 and return both the cue list and the score.
    return cues, min(score, 100)


# ── Training helper ───────────────────────────────────────────────────────────

def build_numeric_feature_frame(series):
    """Called by FunctionTransformer in train_model.py.

    Applies compute_handcrafted_features() to every row in the text column
    and returns a DataFrame that the ColumnTransformer concatenates with
    the TF-IDF matrix.
    """
    rows = []
    for text in series:
        rows.append(compute_handcrafted_features(str(text), urls=[], headers=None))
    return __import__("pandas").DataFrame(rows)


def log_result(log_path: str, row: dict[str, Any]) -> None:
    """Append one analysis result to the CSV log file.

    Creates the file with a header row on first call; appends on subsequent calls.
    """
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    file_exists = os.path.exists(log_path)
    with open(log_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "timestamp", "filename", "prediction", "risk_score",
                "model_probability", "cue_count", "header_anomaly_count",
                "triggered_cues"
            ],
        )
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)