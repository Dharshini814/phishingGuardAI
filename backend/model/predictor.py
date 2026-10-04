"""
PhishGuard AI – Predictor
Loads the saved ML model and runs predictions on new URLs.

This module is the single entry point for inference.
It uses the same feature extraction pipeline as train_model.py.
"""

import os
import sys
import joblib
import numpy as np

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND_DIR)

from services.feature_extraction import extract_features, features_to_list, FEATURE_NAMES
from config import MODEL_PATH


class PhishingPredictor:
    """
    Loads and wraps the trained phishing detection model.
    Provides a clean predict() interface for the FastAPI app.
    """

    def __init__(self):
        self._model = None
        self._scaler = None
        self._uses_scaler = False
        self._model_name = "Unknown"
        self._loaded = False
        self._load_model()

    def _load_model(self) -> None:
        """Load the persisted model from disk."""
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"Trained model not found at: {MODEL_PATH}\n"
                "Please run: python model/train_model.py"
            )

        model_data = joblib.load(MODEL_PATH)
        self._model = model_data["model"]
        self._scaler = model_data.get("scaler")
        self._uses_scaler = model_data.get("uses_scaler", False)
        self._model_name = model_data.get("model_name", "Unknown")
        self._loaded = True
        print(f"[Predictor] Loaded: {self._model_name}")

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def model_name(self) -> str:
        return self._model_name

    def predict(self, url: str) -> dict:
        """
        Run the full prediction pipeline on a URL string.

        Args:
            url: The URL to analyze (never fetched, only parsed as string).

        Returns:
            dict with keys: prediction, confidence, phishing_probability,
                            feature_dict
        """
        if not self._loaded:
            raise RuntimeError("Model is not loaded. Run train_model.py first.")

        # 1. Extract features (same pipeline as training)
        feature_dict = extract_features(url)

        # 2. Convert to ordered numpy array
        feature_vector = np.array(features_to_list(feature_dict), dtype=float).reshape(1, -1)

        # 3. Scale if required (Logistic Regression uses StandardScaler)
        if self._uses_scaler and self._scaler is not None:
            feature_vector = self._scaler.transform(feature_vector)

        # 4. Get prediction and probability
        raw_prediction = self._model.predict(feature_vector)[0]

        try:
            proba = self._model.predict_proba(feature_vector)[0]
            # proba[0] = P(legitimate), proba[1] = P(phishing)
            phishing_prob = float(proba[1])
            legit_prob = float(proba[0])
        except AttributeError:
            # Fallback: use hard prediction
            phishing_prob = 1.0 if raw_prediction == 1 else 0.0
            legit_prob = 1.0 - phishing_prob

        prediction_label = "PHISHING" if raw_prediction == 1 else "LEGITIMATE"

        # Confidence = probability of the predicted class
        confidence = phishing_prob if prediction_label == "PHISHING" else legit_prob

        return {
            "prediction": prediction_label,
            "confidence": confidence,
            "phishing_probability": phishing_prob,
            "feature_dict": feature_dict,
        }


# Module-level singleton – instantiated once when the FastAPI app starts
_predictor_instance = None


def get_predictor() -> PhishingPredictor:
    """Return (or create) the module-level predictor singleton."""
    global _predictor_instance
    # Force reload for development - clear cache if model file is newer
    if _predictor_instance is not None:
        import os
        try:
            model_time = os.path.getmtime(MODEL_PATH)
            # Force reload if model was retrained
            if not hasattr(get_predictor, '_last_model_time') or model_time > get_predictor._last_model_time:
                _predictor_instance = None
                get_predictor._last_model_time = model_time
        except:
            pass
    
    if _predictor_instance is None:
        _predictor_instance = PhishingPredictor()
    return _predictor_instance
