"""
PhishGuard AI – Enhanced Predictor
Loads the enhanced ML model and runs predictions with 31 features.

This module handles both original (20 features) and enhanced (31 features) models,
automatically detecting which one to use based on the saved model metadata.
"""

import os
import sys
import json
import joblib
import numpy as np

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND_DIR)

# Import both feature extraction methods
try:
    from services.enhanced_feature_extraction import (
        extract_enhanced_features, enhanced_features_to_list, 
        ENHANCED_FEATURE_NAMES, get_enhanced_indicators
    )
    ENHANCED_AVAILABLE = True
except ImportError:
    ENHANCED_AVAILABLE = False

from services.feature_extraction import extract_features, features_to_list, FEATURE_NAMES, get_indicators
from config import MODEL_PATH


class EnhancedPhishingPredictor:
    """
    Enhanced phishing detector that supports both original and enhanced models.
    Automatically detects model type and uses appropriate feature extraction.
    """

    def __init__(self):
        self._model = None
        self._scaler = None
        self._uses_scaler = False
        self._model_name = "Unknown"
        self._model_version = "1.0"
        self._feature_count = 20
        self._feature_names = FEATURE_NAMES
        self._uses_enhanced_features = False
        self._loaded = False
        self._load_model()

    def _load_model(self) -> None:
        """Load the persisted model from disk with auto-detection."""
        # Try enhanced model first
        enhanced_model_path = os.path.join(os.path.dirname(MODEL_PATH), "enhanced_phishing_model.pkl")
        enhanced_metadata_path = os.path.join(os.path.dirname(MODEL_PATH), "enhanced_model_metrics.json")
        
        if os.path.exists(enhanced_model_path) and os.path.exists(enhanced_metadata_path):
            self._load_enhanced_model(enhanced_model_path, enhanced_metadata_path)
        elif os.path.exists(MODEL_PATH):
            self._load_original_model()
        else:
            raise FileNotFoundError(
                f"No trained model found. Checked:\n"
                f"- Enhanced: {enhanced_model_path}\n"
                f"- Original: {MODEL_PATH}\n"
                "Please run: python model/enhanced_train_model.py or python model/train_model.py"
            )

    def _load_enhanced_model(self, model_path: str, metadata_path: str) -> None:
        """Load enhanced model with metadata."""
        if not ENHANCED_AVAILABLE:
            raise ImportError("Enhanced features not available. Using fallback to original model.")
        
        try:
            # Try to load the new proper model first
            proper_model_path = os.path.join(os.path.dirname(model_path), "proper_phishing_model.pkl")
            if os.path.exists(proper_model_path):
                model_data = joblib.load(proper_model_path)
                self._model = model_data['model']
                self._model_name = model_data.get('model_name', 'Proper Model')
                self._model_version = '4.0_proper_training'
                self._feature_count = model_data.get('feature_count', 31)
                self._feature_names = model_data.get('feature_names', ENHANCED_FEATURE_NAMES)
                self._uses_scaler = model_data.get('uses_scaler', False)
                self._uses_enhanced_features = True
                
                print(f"[Enhanced Predictor] Loaded proper model: {self._model_name} v{self._model_version}")
                print(f"[Enhanced Predictor] Features: {self._feature_count}, No hardcoded domains")
                
                self._loaded = True
                return
            
            # Fallback to enhanced model
            self._model = joblib.load(model_path)
            
            # Load metadata
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            self._model_name = metadata.get("model_name", "Enhanced Model")
            self._model_version = metadata.get("model_version", "3.0_enhanced")
            self._feature_count = metadata.get("feature_count", 31)
            self._feature_names = metadata.get("feature_names", ENHANCED_FEATURE_NAMES)
            self._uses_scaler = metadata.get("uses_scaler", False)
            self._uses_enhanced_features = True
            
            # Load scaler if it exists
            if self._uses_scaler:
                scaler_path = os.path.join(os.path.dirname(model_path), "enhanced_model_scaler.pkl")
                if os.path.exists(scaler_path):
                    self._scaler = joblib.load(scaler_path)
            
            self._loaded = True
            print(f"[Enhanced Predictor] Loaded: {self._model_name} v{self._model_version}")
            print(f"[Enhanced Predictor] Features: {self._feature_count}, Scaler: {self._uses_scaler}")
            
        except Exception as e:
            print(f"Failed to load enhanced model: {e}")
            # Fallback to original
            self._load_original_model()

    def _load_original_model(self) -> None:
        """Load original model format."""
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"Original model not found: {MODEL_PATH}")
        
        try:
            model_data = joblib.load(MODEL_PATH)
            
            if isinstance(model_data, dict):
                # New format with metadata
                self._model = model_data["model"]
                self._scaler = model_data.get("scaler")
                self._uses_scaler = model_data.get("uses_scaler", False)
                self._model_name = model_data.get("model_name", "Original Model")
            else:
                # Legacy format - just the model
                self._model = model_data
                self._scaler = None
                self._uses_scaler = False
                self._model_name = "Legacy Model"
            
            self._model_version = "2.0_original"
            self._feature_count = 20
            self._feature_names = FEATURE_NAMES
            self._uses_enhanced_features = False
            self._loaded = True
            
            print(f"[Enhanced Predictor] Loaded: {self._model_name} v{self._model_version}")
            print(f"[Enhanced Predictor] Features: {self._feature_count}, Scaler: {self._uses_scaler}")
            
        except Exception as e:
            raise RuntimeError(f"Failed to load original model: {e}")

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def model_version(self) -> str:
        return self._model_version

    @property
    def feature_count(self) -> int:
        return self._feature_count

    @property
    def uses_enhanced_features(self) -> bool:
        return self._uses_enhanced_features

    def extract_features(self, url: str) -> dict:
        """Extract features using appropriate method."""
        if self._uses_enhanced_features and ENHANCED_AVAILABLE:
            return extract_enhanced_features(url)
        else:
            return extract_features(url)

    def features_to_list(self, feature_dict: dict) -> list:
        """Convert features to list using appropriate method."""
        if self._uses_enhanced_features and ENHANCED_AVAILABLE:
            return enhanced_features_to_list(feature_dict)
        else:
            return features_to_list(feature_dict)

    def get_indicators(self, url: str, feature_dict: dict) -> tuple:
        """Get warning/positive indicators using appropriate method."""
        if self._uses_enhanced_features and ENHANCED_AVAILABLE:
            return get_enhanced_indicators(url, feature_dict)
        else:
            return get_indicators(url, feature_dict)

    def predict(self, url: str) -> dict:
        """
        Run the full prediction pipeline on a URL string.

        Args:
            url: The URL to analyze (never fetched, only parsed as string).

        Returns:
            dict with comprehensive prediction results
        """
        if not self._loaded:
            raise RuntimeError("Model is not loaded. Run enhanced_train_model.py first.")

        # 1. Extract features using appropriate method
        feature_dict = self.extract_features(url)

        # 2. Convert to ordered numpy array
        feature_vector = np.array(self.features_to_list(feature_dict), dtype=float).reshape(1, -1)

        # 3. Validate feature count
        if feature_vector.shape[1] != self._feature_count:
            raise ValueError(
                f"Feature count mismatch. Expected {self._feature_count}, got {feature_vector.shape[1]}"
            )

        # 4. Scale if required
        if self._uses_scaler and self._scaler is not None:
            feature_vector = self._scaler.transform(feature_vector)

        # 5. Get prediction and probability
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

        # 6. Generate human-readable indicators
        warnings, positives = self.get_indicators(url, feature_dict)

        # 7. Risk assessment
        if phishing_prob >= 0.8:
            risk_level = "HIGH"
        elif phishing_prob >= 0.5:
            risk_level = "MEDIUM"
        elif phishing_prob >= 0.2:
            risk_level = "LOW"
        else:
            risk_level = "MINIMAL"

        # 8. Enhanced response
        result = {
            "prediction": prediction_label,
            "confidence": round(confidence, 4),
            "phishing_probability": round(phishing_prob, 4),
            "legitimate_probability": round(legit_prob, 4),
            "risk_level": risk_level,
            "warnings": warnings,
            "positive_indicators": positives,
            "feature_dict": feature_dict,
            "model_info": {
                "name": self._model_name,
                "version": self._model_version,
                "feature_count": self._feature_count,
                "uses_enhanced_features": self._uses_enhanced_features,
                "uses_scaler": self._uses_scaler
            }
        }

        return result


# Module-level singleton
_enhanced_predictor_instance = None


def get_enhanced_predictor() -> EnhancedPhishingPredictor:
    """Return (or create) the module-level enhanced predictor singleton."""
    global _enhanced_predictor_instance
    
    # Force reload for development - clear cache if model file is newer
    if _enhanced_predictor_instance is not None:
        try:
            enhanced_model_path = os.path.join(os.path.dirname(MODEL_PATH), "enhanced_phishing_model.pkl")
            model_paths = [enhanced_model_path, MODEL_PATH]
            
            latest_time = 0
            for path in model_paths:
                if os.path.exists(path):
                    latest_time = max(latest_time, os.path.getmtime(path))
            
            # Force reload if any model was retrained
            if not hasattr(get_enhanced_predictor, '_last_model_time') or latest_time > get_enhanced_predictor._last_model_time:
                _enhanced_predictor_instance = None
                get_enhanced_predictor._last_model_time = latest_time
        except:
            pass
    
    if _enhanced_predictor_instance is None:
        _enhanced_predictor_instance = EnhancedPhishingPredictor()
    
    return _enhanced_predictor_instance


# Backward compatibility
def get_predictor() -> EnhancedPhishingPredictor:
    """Backward compatibility wrapper."""
    return get_enhanced_predictor()