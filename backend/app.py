"""
PhishGuard AI – FastAPI Backend
=================================

Endpoints:
    GET  /api/health           Health check
    POST /api/predict          Analyze a URL for phishing
    GET  /api/dashboard        Dashboard statistics
    GET  /api/history          Scan history
    DELETE /api/history        Clear scan history
    GET  /api/model/metrics    Model performance metrics
    GET  /api/model/features   Feature list with descriptions

Run:
    uvicorn app:app --reload --port 8000
"""

import os
import sys
import json
import traceback
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

# Ensure the backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (
    ALLOWED_ORIGINS, METRICS_PATH, MODEL_PATH,
    HOST, PORT, RELOAD,
)
from utils.validators import is_valid_url, sanitize_url
from services.feature_extraction import get_indicators, FEATURE_NAMES
from services.risk_analyzer import compute_risk_score, get_risk_level, build_explanation
from services.history_service import history_service
# Import enhanced predictor
try:
    from model.enhanced_predictor import get_enhanced_predictor
    USE_ENHANCED_PREDICTOR = True
    print("[PhishGuard AI] Enhanced predictor available")
except ImportError:
    from model.predictor import get_predictor
    USE_ENHANCED_PREDICTOR = False
    print("[PhishGuard AI] Using original predictor")

# ── App initialization ────────────────────────────────────────────────────────

app = FastAPI(
    title="PhishGuard AI",
    description="AI-Based Phishing Website Detection API",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ──────────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Accept"],
)

# ── Predictor Startup ─────────────────────────────────────────────────────────

_predictor = None


@app.on_event("startup")
async def startup_event():
    global _predictor
    print("[PhishGuard AI] Starting up ...")
    try:
        if USE_ENHANCED_PREDICTOR:
            _predictor = get_enhanced_predictor()
            print(f"[PhishGuard AI] Enhanced model loaded: {_predictor.model_name} v{_predictor.model_version}")
            print(f"[PhishGuard AI] Features: {_predictor.feature_count}, Enhanced: {_predictor.uses_enhanced_features}")
        else:
            _predictor = get_predictor()
            print(f"[PhishGuard AI] Original model loaded: {_predictor.model_name}")
    except FileNotFoundError as e:
        print(f"[PhishGuard AI] WARNING: {e}")
        print("[PhishGuard AI] Run 'python model/enhanced_train_model.py' or 'python model/train_model.py' to train the model.")
    except Exception as e:
        print(f"[PhishGuard AI] ERROR loading model: {e}")
        traceback.print_exc()


# ── Pydantic Schemas ──────────────────────────────────────────────────────────

class PredictRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def url_must_not_be_empty(cls, v):
        if not v or not v.strip():
            raise ValueError("URL cannot be empty.")
        return v.strip()


class PredictResponse(BaseModel):
    model_config = {"protected_namespaces": ()}

    prediction: str
    confidence: float
    risk_score: int
    risk_level: str
    indicators: list
    positive_signals: list
    explanation: str
    model_used: str
    url_analyzed: str


# ── Exception Handlers ────────────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Return a clean error without exposing Python stack traces."""
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error. Please try again.",
            "detail": str(exc) if not isinstance(exc, HTTPException) else exc.detail,
        },
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    model_ready = _predictor is not None and _predictor.is_loaded
    return {
        "status": "ok" if model_ready else "degraded",
        "model_ready": model_ready,
        "model_name": _predictor.model_name if model_ready else None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "PhishGuard AI",
        "version": "1.0.0",
    }


@app.post("/api/predict", response_model=PredictResponse)
async def predict_url(request: PredictRequest):
    """
    Analyze a URL for phishing indicators using the trained ML model.

    SECURITY NOTE: The URL is never visited, fetched, or executed.
    Only the URL string and its structural components are analyzed.
    """
    # Validate URL
    url = sanitize_url(request.url)
    is_valid, error_msg = is_valid_url(url)
    if not is_valid:
        raise HTTPException(status_code=422, detail=error_msg)

    # Check model availability
    if _predictor is None or not _predictor.is_loaded:
        raise HTTPException(
            status_code=503,
            detail=(
                "ML model is not available. "
                "Please run: python model/train_model.py to train the model first."
            ),
        )

    try:
        # Run prediction
        result = _predictor.predict(url)

        prediction = result["prediction"]
        confidence = result["confidence"]
        phishing_prob = result["phishing_probability"]
        feature_dict = result["feature_dict"]

        # Compute risk score and level
        risk_score = compute_risk_score(phishing_prob)
        risk_level = get_risk_level(risk_score)

        # Generate human-readable indicators
        indicators, positive_signals = get_indicators(url, feature_dict)

        # Build explanation
        explanation = build_explanation(
            prediction=prediction,
            confidence=confidence,
            risk_score=risk_score,
            risk_level=risk_level,
            indicators=indicators,
            positive_signals=positive_signals,
        )

        # Store in history (no sensitive data stored)
        history_service.add_record(
            url=url,
            prediction=prediction,
            confidence=confidence,
            risk_score=risk_score,
            risk_level=risk_level,
        )

        return PredictResponse(
            prediction=prediction,
            confidence=round(confidence, 4),
            risk_score=risk_score,
            risk_level=risk_level,
            indicators=indicators,
            positive_signals=positive_signals,
            explanation=explanation,
            model_used=_predictor.model_name,
            url_analyzed=url,
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Prediction failed: {str(e)}",
        )


@app.get("/api/dashboard")
async def get_dashboard():
    """
    Return aggregated statistics for the dashboard.
    Data is derived from in-session scan history and model metrics.
    """
    stats = history_service.get_statistics()

    # Load model accuracy from saved metrics if available
    model_accuracy = None
    best_model_name = None
    if os.path.exists(METRICS_PATH):
        try:
            with open(METRICS_PATH) as f:
                metrics_data = json.load(f)
            best_model = next(
                (m for m in metrics_data.get("models", [])
                 if m["model_name"] == metrics_data.get("best_model")),
                None,
            )
            if best_model:
                model_accuracy = best_model["accuracy"]
                best_model_name = best_model["model_name"]
        except Exception:
            pass

    return {
        "total_analyzed": stats["total"],
        "phishing_detected": stats["phishing_count"],
        "legitimate_detected": stats["legitimate_count"],
        "model_accuracy": model_accuracy,
        "best_model": best_model_name,
        "recent_activity": stats["recent_activity"],
    }


@app.get("/api/history")
async def get_history():
    """Return all scan history records (newest first)."""
    records = history_service.get_all()
    return {
        "history": records,
        "total": len(records),
    }


@app.delete("/api/history")
async def clear_history():
    """Clear all scan history for the current session."""
    count = history_service.clear()
    return {
        "message": f"History cleared. {count} records removed.",
        "cleared_count": count,
    }


@app.get("/api/model/metrics")
async def get_model_metrics():
    """
    Return model training metrics for the Model Performance page.
    All values are from actual training results.
    """
    if not os.path.exists(METRICS_PATH):
        raise HTTPException(
            status_code=404,
            detail=(
                "Model metrics not found. "
                "Please run: python model/train_model.py"
            ),
        )

    try:
        with open(METRICS_PATH) as f:
            metrics_data = json.load(f)
        return metrics_data
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500,
            detail="Model metrics file is corrupted. Please retrain the model.",
        )


@app.get("/api/model/features")
async def get_model_features():
    """Return the list of features used by the model with descriptions."""
    feature_descriptions = {
        "url_length": "Total character count of the URL",
        "domain_length": "Character count of the domain/hostname",
        "path_length": "Character count of the URL path",
        "num_dots": "Number of dot (.) characters in the URL",
        "num_hyphens": "Number of hyphen (-) characters in the URL",
        "num_underscores": "Number of underscore (_) characters in the URL",
        "num_slashes": "Number of forward slash (/) characters",
        "num_question_marks": "Number of question mark (?) characters",
        "num_equals": "Number of equals sign (=) characters",
        "num_ampersands": "Number of ampersand (&) characters",
        "num_special_chars": "Count of non-alphanumeric, non-dot characters",
        "num_digits": "Count of numeric digit characters",
        "has_at_symbol": "1 if @ symbol is present in URL",
        "has_ip_address": "1 if hostname is a raw IP address",
        "has_https": "1 if URL uses HTTPS scheme",
        "num_subdomains": "Number of subdomains before main domain",
        "num_query_params": "Number of key=value query parameters",
        "has_suspicious_keyword": "1 if URL contains known phishing keywords",
        "is_url_shortener": "1 if domain matches known URL shortener services",
    }

    features = [
        {
            "index": i,
            "name": name,
            "description": feature_descriptions.get(name, ""),
        }
        for i, name in enumerate(FEATURE_NAMES)
    ]

    return {
        "feature_count": len(FEATURE_NAMES),
        "features": features,
    }


# ── Run directly ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host=HOST, port=PORT, reload=RELOAD)
