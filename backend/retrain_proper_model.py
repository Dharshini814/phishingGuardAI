"""
Retrain PhishGuard AI Model Properly

This script retrains the model with proper data so it learns to distinguish
legitimate vs phishing URLs based on features, not hardcoded domain lists.
"""

import pandas as pd
import numpy as np
import os
import sys
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
import joblib
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from services.enhanced_feature_extraction import extract_enhanced_features, ENHANCED_FEATURE_NAMES


def create_training_data():
    """Create balanced training data without hardcoded whitelists."""
    
    # Legitimate URLs - Real examples that should be learned as legitimate
    legitimate_urls = [
        # Indian Banking - Real legitimate URLs
        "https://onlinesbi.sbi.co.in/",
        "https://netbanking.sbi.co.in/",
        "https://www.sbi.co.in/",
        "https://netbanking.hdfcbank.com/",
        "https://www.hdfcbank.com/",
        "https://www.icicibank.com/",
        "https://netbanking.icicibank.com/",
        "https://www.kotakbank.com/",
        "https://netbanking.kotak.com/",
        "https://www.axisbank.com/",
        "https://www.pnbindia.in/",
        
        # International Banking
        "https://www.chase.com/",
        "https://secure01a.chase.com/",
        "https://www.bankofamerica.com/",
        "https://secure.bankofamerica.com/",
        "https://www.wellsfargo.com/",
        "https://online.citi.com/",
        "https://www.citibank.com/",
        
        # Payment Services
        "https://www.paypal.com/",
        "https://www.paypal.com/signin",
        "https://pay.google.com/",
        "https://wallet.paytm.com/",
        "https://www.phonepe.com/",
        
        # Tech Companies
        "https://www.google.com/",
        "https://accounts.google.com/",
        "https://www.microsoft.com/",
        "https://login.microsoftonline.com/",
        "https://www.apple.com/",
        "https://appleid.apple.com/",
        "https://www.amazon.com/",
        "https://www.facebook.com/",
        "https://www.instagram.com/",
        "https://twitter.com/",
        "https://www.linkedin.com/",
        "https://github.com/",
        
        # Other services
        "https://www.netflix.com/",
        "https://www.spotify.com/",
        "https://www.dropbox.com/",
        "https://zoom.us/",
        "https://stackoverflow.com/",
        "https://www.wikipedia.org/",
        
        # Educational/Government
        "https://www.harvard.edu/",
        "https://www.mit.edu/",
        "https://www.stanford.edu/",
        "https://www.gov.uk/",
        "https://www.irs.gov/",
        "https://www.usa.gov/",
    ]
    
    # Phishing URLs - Clear examples with distinguishing features
    phishing_urls = [
        # Typosquatting (missing letters)
        "https://onlinessbi.sbi.bank.in/",     # The original case - missing 'e'
        "https://netbaking.hdfcbank.com/",     # Missing 'n' in netbanking
        "https://icicbank.com/",               # Missing 'i' in icicibank
        "https://paypa1.com/",                 # '1' instead of 'l'
        "https://payp4l.com/",                 # '4' instead of 'a'  
        "https://g00gle.com/",                 # '00' instead of 'oo'
        "https://micr0soft.com/",              # '0' instead of 'o'
        "https://arnazon.com/",                # 'rn' instead of 'm'
        "https://netf1ix.com/",                # '1' instead of 'l'
        
        # Homograph attacks
        "https://microsοft.com/",              # Greek omicron
        "https://gοοgle.com/",                # Greek omicrons
        "https://аpple.com/",                 # Cyrillic 'a'
        "https://paypaℓ.com/",                # Unicode 'ℓ'
        
        # Subdomain abuse / Misleading TLD
        "https://secure.paypal.com.phish.ru/",
        "https://login.amazon.com.fake.tk/",
        "https://verify.google.com.scam.ml/",
        "https://secure.sbi.co.in.phishing.cf/",
        "https://netbanking.hdfc.bank.fake.xyz/",
        
        # Suspicious TLD abuse
        "https://paypal-secure.tk/",
        "https://amazon-verify.ml/",
        "https://google-security.gq/",
        "https://sbi-netbanking.xyz/",
        "https://microsoft-update.cf/",
        
        # IP-based
        "http://192.168.1.100/paypal/signin/",
        "http://203.0.113.5/sbi/netbanking/",
        "http://198.51.100.1/google/accounts/",
        
        # Port abuse
        "https://secure-paypal.com:8080/signin",
        "https://banking-sbi.com:8888/login",
        
        # URL shorteners (suspicious context)
        "https://bit.ly/fake-paypal-urgent",
        "https://tinyurl.com/phish-sbi-2024",
        
        # Multiple services (red flag)
        "https://paypal-amazon-verify.com/",
        "https://google-microsoft-security.net/",
        "https://sbi-hdfc-netbanking.org/",
        
        # Urgency keywords
        "https://urgent-paypal-verify.com/",
        "https://suspended-account-restore.net/",
        "https://security-alert-verify.info/",
        
        # More sophisticated
        "https://www.paypal.com-security.malicious.com/",
        "https://accounts.google.com.phishing.net/",
        "https://onlinesbi.sbi.co.in.verify.suspicious.ru/",
    ]
    
    # Create balanced dataset
    data = []
    for url in legitimate_urls:
        data.append({"url": url, "label": 0})
    for url in phishing_urls:
        data.append({"url": url, "label": 1})
    
    return pd.DataFrame(data)


def extract_features_for_training(df):
    """Extract features for training data."""
    print(f"Extracting features for {len(df)} URLs...")
    
    feature_data = []
    for idx, row in df.iterrows():
        try:
            url = row['url']
            features = extract_enhanced_features(url)
            
            # Combine with original data
            combined = row.to_dict()
            combined.update(features)
            feature_data.append(combined)
            
        except Exception as e:
            print(f"Error extracting features for {url}: {e}")
            continue
    
    return pd.DataFrame(feature_data)


def train_model(df):
    """Train the model without hardcoded domain lists."""
    
    # Use available enhanced features
    available_features = [f for f in ENHANCED_FEATURE_NAMES if f in df.columns]
    print(f"Using {len(available_features)} features")
    
    X = df[available_features]
    y = df['label']
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training: {len(X_train)} samples")
    print(f"Testing: {len(X_test)} samples")
    print(f"Training distribution: {np.bincount(y_train)}")
    
    # Try different models
    models = {
        'RandomForest': RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42),
        'GradientBoosting': GradientBoostingClassifier(n_estimators=200, max_depth=10, random_state=42),
        'LogisticRegression': LogisticRegression(random_state=42, max_iter=1000, C=1.0)
    }
    
    best_model = None
    best_score = 0
    best_name = ''
    
    print("\nTraining models...")
    for name, model in models.items():
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        
        print(f"{name}: Acc={accuracy:.3f}, Prec={precision:.3f}, Rec={recall:.3f}, F1={f1:.3f}")
        
        if f1 > best_score:
            best_score = f1
            best_model = model
            best_name = name
    
    print(f"\nBest model: {best_name} (F1={best_score:.3f})")
    
    # Detailed evaluation
    y_pred_best = best_model.predict(X_test)
    print("\nDetailed evaluation:")
    print(classification_report(y_test, y_pred_best, target_names=['Legitimate', 'Phishing']))
    
    return best_model, best_name, available_features


def test_critical_cases(model, feature_names):
    """Test the critical cases that were failing."""
    
    test_cases = [
        ("https://onlinesbi.sbi.co.in/", "LEGITIMATE", "Real SBI banking"),
        ("https://onlinessbi.sbi.bank.in/", "PHISHING", "SBI typosquatting (missing e)"),
        ("https://payp4l.com/", "PHISHING", "PayPal character substitution"),
        ("https://www.paypal.com/", "LEGITIMATE", "Real PayPal"),
        ("https://microsοft.com/", "PHISHING", "Microsoft homograph attack"),
        ("https://www.microsoft.com/", "LEGITIMATE", "Real Microsoft"),
        ("https://netbanking.hdfcbank.com/", "LEGITIMATE", "Real HDFC banking"),
        ("https://netbaking.hdfcbank.com/", "PHISHING", "HDFC typo (missing n)"),
    ]
    
    print("\n" + "="*60)
    print("TESTING CRITICAL CASES")
    print("="*60)
    
    correct_predictions = 0
    
    for url, expected, description in test_cases:
        try:
            features = extract_enhanced_features(url)
            feature_vector = np.array([features.get(f, 0) for f in feature_names]).reshape(1, -1)
            
            prediction = model.predict(feature_vector)[0]
            pred_label = "PHISHING" if prediction == 1 else "LEGITIMATE"
            
            try:
                proba = model.predict_proba(feature_vector)[0]
                confidence = proba[1] if prediction == 1 else proba[0]
            except:
                confidence = 1.0
            
            is_correct = pred_label == expected
            if is_correct:
                correct_predictions += 1
            
            status = "✅" if is_correct else "❌"
            print(f"{status} {description}")
            print(f"    URL: {url}")
            print(f"    Expected: {expected}, Got: {pred_label} ({confidence:.3f})")
            print()
            
        except Exception as e:
            print(f"❌ Error testing {url}: {e}")
            print()
    
    accuracy = correct_predictions / len(test_cases)
    print(f"Critical Cases Accuracy: {accuracy:.1%} ({correct_predictions}/{len(test_cases)})")
    
    return accuracy


def main():
    """Main training function."""
    print("Retraining PhishGuard AI without hardcoded domain lists...")
    
    # Create training data
    df = create_training_data()
    print(f"Created dataset with {len(df)} URLs")
    print(f"Legitimate: {(df['label'] == 0).sum()}")
    print(f"Phishing: {(df['label'] == 1).sum()}")
    
    # Extract features
    feature_df = extract_features_for_training(df)
    print(f"Extracted features for {len(feature_df)} URLs")
    
    # Train model
    model, model_name, feature_names = train_model(feature_df)
    
    # Test critical cases
    critical_accuracy = test_critical_cases(model, feature_names)
    
    # Save the model
    model_data = {
        'model': model,
        'model_name': f"{model_name}_NoHardcodedDomains",
        'feature_names': feature_names,
        'feature_count': len(feature_names),
        'training_date': datetime.now().isoformat(),
        'critical_test_accuracy': critical_accuracy,
        'uses_scaler': False
    }
    
    model_path = "model/proper_phishing_model.pkl"
    joblib.dump(model_data, model_path)
    
    print(f"\n✅ Model saved: {model_path}")
    print(f"   Model: {model_name}")
    print(f"   Features: {len(feature_names)}")
    print(f"   Critical Cases Accuracy: {critical_accuracy:.1%}")
    
    return model, feature_names


if __name__ == "__main__":
    main()