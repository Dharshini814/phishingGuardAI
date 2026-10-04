"""
PhishGuard AI - Risk Analyzer
Converts raw model probability into a structured risk assessment.
"""

from config import RISK_LOW_MAX, RISK_MEDIUM_MAX


def compute_risk_score(phishing_probability: float) -> int:
    """
    Map a raw phishing probability [0, 1] to an integer risk score [0, 100].

    The score is application-generated and should be interpreted as an
    estimated risk indicator, not an official cybersecurity standard.

    Args:
        phishing_probability: Model's estimated probability of phishing.

    Returns:
        Integer risk score between 0 and 100.
    """
    score = int(round(phishing_probability * 100))
    return max(0, min(100, score))


def get_risk_level(risk_score: int) -> str:
    """
    Categorize a risk score into a risk level label.

    Categories:
        0–30   → LOW
        31–60  → MEDIUM
        61–100 → HIGH
    """
    if risk_score <= RISK_LOW_MAX:
        return "LOW"
    elif risk_score <= RISK_MEDIUM_MAX:
        return "MEDIUM"
    else:
        return "HIGH"


def build_explanation(
    prediction: str,
    confidence: float,
    risk_score: int,
    risk_level: str,
    indicators: list,
    positive_signals: list,
) -> str:
    """
    Generate a natural-language explanation of the prediction result.

    Args:
        prediction: "PHISHING" or "LEGITIMATE"
        confidence: Model confidence [0, 1]
        risk_score: Application risk score [0, 100]
        risk_level: "LOW" | "MEDIUM" | "HIGH"
        indicators: List of warning strings
        positive_signals: List of positive signal strings

    Returns:
        A concise explanation string.
    """
    conf_pct = round(confidence * 100, 1)

    if prediction == "PHISHING":
        base = (
            f"The ML model classified this URL as PHISHING with {conf_pct}% confidence. "
            f"The estimated application risk score is {risk_score}/100 ({risk_level})."
        )
        if indicators:
            base += (
                f" The following URL characteristics contributed to this assessment: "
                + "; ".join(indicators[:3]) + "."
            )
        base += (
            " This is an ML-based assessment. Always exercise caution and verify "
            "through additional security tools before trusting a website."
        )
    else:
        base = (
            f"The ML model classified this URL as LEGITIMATE with {conf_pct}% confidence. "
            f"The estimated application risk score is {risk_score}/100 ({risk_level})."
        )
        if positive_signals:
            base += (
                f" Positive URL characteristics include: "
                + "; ".join(positive_signals[:3]) + "."
            )
        base += (
            " Note: This model provides an estimated assessment only. "
            "It cannot guarantee that a website is safe."
        )

    return base
