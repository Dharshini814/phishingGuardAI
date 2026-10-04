"""
PhishGuard AI - Enhanced Model Training

Train phishing detection model with enhanced features and professional datasets.

Features:
- Uses professional datasets (PhishTank, LegitPhish, Zenodo, EdgePhish-5G)
- Enhanced feature extraction (31 features vs original 20)
- Advanced model selection and hyperparameter tuning
- Comprehensive evaluation metrics
- Model explainability and feature importance
"""

import pandas as pd
import numpy as np
import os
import sys
import json
import joblib
import logging
from datetime import datetime
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix, roc_auc_score
)
import warnings
warnings.filterwarnings('ignore')

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import enhanced feature extraction
try:
    from services.enhanced_feature_extraction import (
        extract_enhanced_features, ENHANCED_FEATURE_NAMES, enhanced_features_to_list
    )
    FEATURE_NAMES = ENHANCED_FEATURE_NAMES
    extract_features_func = extract_enhanced_features
    features_to_list_func = enhanced_features_to_list
    logger.info("Using enhanced feature extraction (31 features)")
except ImportError:
    from services.feature_extraction import extract_features, FEATURE_NAMES, features_to_list
    extract_features_func = extract_features
    features_to_list_func = features_to_list
    logger.info("Fallback to original feature extraction (20 features)")


class EnhancedPhishingModelTrainer:
    """Enhanced phishing detection model trainer."""
    
    def __init__(self, data_dir="./"):
        self.data_dir = data_dir
        self.models = {}
        self.scalers = {}
        self.feature_importance = {}
        self.evaluation_results = {}
        
    def load_enhanced_dataset(self):
        """Load the enhanced dataset with professional data."""
        # Try to load enhanced dataset first
        enhanced_path = os.path.join(self.data_dir, "../data/enhanced_phishing_dataset.csv")
        if os.path.exists(enhanced_path):
            logger.info("Loading enhanced dataset...")
            df = pd.read_csv(enhanced_path)
            logger.info(f"Loaded enhanced dataset: {len(df)} samples")
            return df
        
        # Fallback to processed dataset
        processed_path = os.path.join(self.data_dir, "../data/processed_phishing_dataset.csv")
        if os.path.exists(processed_path):
            logger.info("Loading processed dataset...")
            df = pd.read_csv(processed_path)
            logger.info(f"Loaded processed dataset: {len(df)} samples")
            return df
        
        # Fallback to original dataset
        original_path = os.path.join(self.data_dir, "../data/phishing_dataset.csv")
        if os.path.exists(original_path):
            logger.info("Loading original dataset...")
            df = pd.read_csv(original_path)
            logger.info(f"Loaded original dataset: {len(df)} samples")
            return df
        
        raise FileNotFoundError("No dataset found. Please generate dataset first.")
    
    def extract_features_from_urls(self, df):
        """Extract features from URLs if not already present."""
        logger.info("Checking if features need to be extracted...")
        
        # Check if features are already extracted
        features_present = all(feature in df.columns for feature in FEATURE_NAMES)
        
        if features_present:
            logger.info("Features already present in dataset")
            return df
        
        logger.info(f"Extracting {len(FEATURE_NAMES)} features from URLs...")
        feature_data = []
        
        for idx, row in df.iterrows():
            if idx % 500 == 0:
                logger.info(f"Processing URL {idx + 1}/{len(df)}")
            
            try:
                url = row['url']
                features = extract_features_func(url)
                
                # Combine row data with features
                combined_row = row.to_dict()
                combined_row.update(features)
                feature_data.append(combined_row)
                
            except Exception as e:
                logger.warning(f"Failed to extract features for URL {idx}: {e}")
                continue
        
        feature_df = pd.DataFrame(feature_data)
        logger.info(f"Feature extraction complete: {len(feature_df)} samples")
        return feature_df
    
    def prepare_training_data(self, df):
        """Prepare training data (X, y) from dataset."""
        logger.info("Preparing training data...")
        
        # Ensure all required features are present
        missing_features = [f for f in FEATURE_NAMES if f not in df.columns]
        if missing_features:
            logger.warning(f"Missing features: {missing_features}")
            # Fill missing features with zeros
            for feature in missing_features:
                df[feature] = 0
        
        # Extract features and labels
        X = df[FEATURE_NAMES].copy()
        y = df['label'].copy()
        
        logger.info(f"Training data shape: X={X.shape}, y={y.shape}")
        logger.info(f"Class distribution: {y.value_counts().to_dict()}")
        
        return X, y
    
    def train_multiple_models(self, X_train, y_train, X_test, y_test):
        """Train multiple models and compare performance."""
        logger.info("Training multiple models...")
        
        # Define models to train
        models_to_train = {
            'Logistic Regression': LogisticRegression(random_state=42, max_iter=1000),
            'Random Forest': RandomForestClassifier(random_state=42, n_estimators=100),
            'Gradient Boosting': GradientBoostingClassifier(random_state=42, n_estimators=100),
            'SVM': SVC(random_state=42, probability=True)
        }
        
        results = {}
        
        for model_name, model in models_to_train.items():
            logger.info(f"Training {model_name}...")
            
            try:
                # Scale features for models that need it
                if model_name in ['Logistic Regression', 'SVM']:
                    scaler = StandardScaler()
                    X_train_scaled = scaler.fit_transform(X_train)
                    X_test_scaled = scaler.transform(X_test)
                    self.scalers[model_name] = scaler
                else:
                    X_train_scaled = X_train
                    X_test_scaled = X_test
                
                # Train model
                model.fit(X_train_scaled, y_train)
                
                # Make predictions
                y_pred = model.predict(X_test_scaled)
                y_pred_proba = model.predict_proba(X_test_scaled)[:, 1] if hasattr(model, 'predict_proba') else None
                
                # Calculate metrics
                metrics = {
                    'accuracy': accuracy_score(y_test, y_pred),
                    'precision': precision_score(y_test, y_pred),
                    'recall': recall_score(y_test, y_pred),
                    'f1_score': f1_score(y_test, y_pred),
                    'roc_auc': roc_auc_score(y_test, y_pred_proba) if y_pred_proba is not None else None
                }
                
                # Cross-validation
                cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5, scoring='accuracy')
                metrics['cv_accuracy'] = cv_scores.mean()
                metrics['cv_std'] = cv_scores.std()
                
                # Feature importance (for applicable models)
                if hasattr(model, 'feature_importances_'):
                    importance = dict(zip(FEATURE_NAMES, model.feature_importances_))
                    self.feature_importance[model_name] = importance
                elif hasattr(model, 'coef_'):
                    importance = dict(zip(FEATURE_NAMES, abs(model.coef_[0])))
                    self.feature_importance[model_name] = importance
                
                results[model_name] = {
                    'model': model,
                    'metrics': metrics,
                    'predictions': y_pred,
                    'probabilities': y_pred_proba
                }
                
                logger.info(f"{model_name}: Accuracy={metrics['accuracy']:.4f}, F1={metrics['f1_score']:.4f}")
                
            except Exception as e:
                logger.error(f"Failed to train {model_name}: {e}")
                continue
        
        self.models = {name: result['model'] for name, result in results.items()}
        self.evaluation_results = results
        
        return results
    
    def select_best_model(self, results):
        """Select the best performing model."""
        logger.info("Selecting best model...")
        
        best_model_name = None
        best_score = 0
        
        # Compare models by F1 score (balanced metric for phishing detection)
        for model_name, result in results.items():
            f1 = result['metrics']['f1_score']
            logger.info(f"{model_name}: F1 Score = {f1:.4f}")
            
            if f1 > best_score:
                best_score = f1
                best_model_name = model_name
        
        logger.info(f"Best model: {best_model_name} (F1 = {best_score:.4f})")
        return best_model_name, results[best_model_name]
    
    def hyperparameter_tuning(self, X_train, y_train, model_name, model):
        """Perform hyperparameter tuning for the best model."""
        logger.info(f"Performing hyperparameter tuning for {model_name}...")
        
        # Define parameter grids
        param_grids = {
            'Logistic Regression': {
                'C': [0.1, 1, 10, 100],
                'penalty': ['l1', 'l2'],
                'solver': ['liblinear', 'saga']
            },
            'Random Forest': {
                'n_estimators': [100, 200, 300],
                'max_depth': [10, 20, None],
                'min_samples_split': [2, 5, 10]
            },
            'Gradient Boosting': {
                'n_estimators': [100, 200],
                'learning_rate': [0.05, 0.1, 0.2],
                'max_depth': [3, 5, 7]
            }
        }
        
        if model_name not in param_grids:
            logger.info(f"No hyperparameter tuning defined for {model_name}")
            return model
        
        try:
            # Scale data if needed
            if model_name in ['Logistic Regression', 'SVM']:
                scaler = self.scalers.get(model_name, StandardScaler())
                X_train_scaled = scaler.fit_transform(X_train)
            else:
                X_train_scaled = X_train
            
            # Perform grid search
            grid_search = GridSearchCV(
                model, param_grids[model_name], 
                cv=5, scoring='f1', n_jobs=-1, verbose=1
            )
            
            grid_search.fit(X_train_scaled, y_train)
            
            logger.info(f"Best parameters: {grid_search.best_params_}")
            logger.info(f"Best CV F1 score: {grid_search.best_score_:.4f}")
            
            return grid_search.best_estimator_
            
        except Exception as e:
            logger.error(f"Hyperparameter tuning failed: {e}")
            return model
    
    def save_model_artifacts(self, best_model, best_model_name, metrics):
        """Save model and related artifacts."""
        logger.info("Saving model artifacts...")
        
        # Save model
        model_path = os.path.join(self.data_dir, "enhanced_phishing_model.pkl")
        joblib.dump(best_model, model_path)
        
        # Save scaler if exists
        scaler = self.scalers.get(best_model_name)
        if scaler:
            scaler_path = os.path.join(self.data_dir, "enhanced_model_scaler.pkl")
            joblib.dump(scaler, scaler_path)
        
        # Save metrics and metadata
        model_info = {
            'model_name': best_model_name,
            'feature_count': len(FEATURE_NAMES),
            'feature_names': FEATURE_NAMES,
            'metrics': metrics,
            'training_date': datetime.now().isoformat(),
            'model_version': '3.0_enhanced',
            'uses_scaler': scaler is not None,
            'feature_importance': self.feature_importance.get(best_model_name, {})
        }
        
        metadata_path = os.path.join(self.data_dir, "enhanced_model_metrics.json")
        with open(metadata_path, 'w') as f:
            json.dump(model_info, f, indent=2, default=str)
        
        logger.info(f"Model saved: {model_path}")
        logger.info(f"Metadata saved: {metadata_path}")
        if scaler:
            logger.info(f"Scaler saved: {scaler_path}")
        
        return model_path, metadata_path
    
    def train_enhanced_model(self):
        """Complete enhanced model training pipeline."""
        logger.info("Starting enhanced model training pipeline...")
        
        # 1. Load dataset
        df = self.load_enhanced_dataset()
        
        # 2. Extract features if needed
        df = self.extract_features_from_urls(df)
        
        # 3. Prepare training data
        X, y = self.prepare_training_data(df)
        
        # 4. Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        logger.info(f"Training set: {X_train.shape[0]} samples")
        logger.info(f"Test set: {X_test.shape[0]} samples")
        
        # 5. Train multiple models
        results = self.train_multiple_models(X_train, y_train, X_test, y_test)
        
        # 6. Select best model
        best_model_name, best_result = self.select_best_model(results)
        best_model = best_result['model']
        
        # 7. Hyperparameter tuning
        tuned_model = self.hyperparameter_tuning(X_train, y_train, best_model_name, best_model)
        
        # 8. Final evaluation on test set
        logger.info("Final evaluation on test set...")
        if best_model_name in ['Logistic Regression', 'SVM']:
            scaler = self.scalers[best_model_name]
            X_test_scaled = scaler.transform(X_test)
        else:
            X_test_scaled = X_test
        
        y_pred_final = tuned_model.predict(X_test_scaled)
        final_metrics = {
            'accuracy': accuracy_score(y_test, y_pred_final),
            'precision': precision_score(y_test, y_pred_final),
            'recall': recall_score(y_test, y_pred_final),
            'f1_score': f1_score(y_test, y_pred_final)
        }
        
        # 9. Save model artifacts
        model_path, metadata_path = self.save_model_artifacts(
            tuned_model, best_model_name, final_metrics
        )
        
        logger.info("Enhanced model training complete!")
        return tuned_model, final_metrics


def main():
    """Main training function."""
    model_dir = os.path.dirname(os.path.abspath(__file__))
    trainer = EnhancedPhishingModelTrainer(model_dir)
    
    # Train enhanced model
    model, metrics = trainer.train_enhanced_model()
    
    print("\n" + "="*80)
    print("ENHANCED MODEL TRAINING COMPLETE")
    print("="*80)
    print(f"Best Model: {trainer.evaluation_results}")
    print(f"Features Used: {len(FEATURE_NAMES)}")
    print("\nFinal Test Set Performance:")
    print(f"  Accuracy:  {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1 Score:  {metrics['f1_score']:.4f}")
    print("="*80)
    
    # Show feature importance if available
    best_model_name = None
    for name, result in trainer.evaluation_results.items():
        if result['model'] == model:
            best_model_name = name
            break
    
    if best_model_name and best_model_name in trainer.feature_importance:
        print(f"\nTop 10 Most Important Features ({best_model_name}):")
        importance = trainer.feature_importance[best_model_name]
        sorted_features = sorted(importance.items(), key=lambda x: x[1], reverse=True)
        for i, (feature, score) in enumerate(sorted_features[:10]):
            print(f"  {i+1:2d}. {feature}: {score:.4f}")
    
    return model, metrics


if __name__ == "__main__":
    main()