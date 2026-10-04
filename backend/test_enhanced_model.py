"""
PhishGuard AI - Enhanced Model Validation

Comprehensive testing of the enhanced phishing detection model against:
1. Real-world phishing examples
2. Advanced attack techniques
3. Edge cases and false positives
4. Comparison with original model performance

This validates that our professional dataset integration actually improves detection.
"""

import os
import sys
import json
from datetime import datetime

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import both predictors for comparison
try:
    from model.enhanced_predictor import get_enhanced_predictor
    ENHANCED_AVAILABLE = True
except ImportError:
    ENHANCED_AVAILABLE = False

try:
    from model.predictor import get_predictor as get_original_predictor
    ORIGINAL_AVAILABLE = True
except ImportError:
    ORIGINAL_AVAILABLE = False


class ModelValidationSuite:
    """Comprehensive model validation and comparison."""
    
    def __init__(self):
        self.enhanced_predictor = None
        self.original_predictor = None
        self.test_results = {}
        
        # Load predictors
        if ENHANCED_AVAILABLE:
            try:
                self.enhanced_predictor = get_enhanced_predictor()
                print(f"✓ Enhanced predictor loaded: {self.enhanced_predictor.model_name}")
                print(f"  Version: {self.enhanced_predictor.model_version}")
                print(f"  Features: {self.enhanced_predictor.feature_count}")
            except Exception as e:
                print(f"✗ Failed to load enhanced predictor: {e}")
        
        if ORIGINAL_AVAILABLE:
            try:
                self.original_predictor = get_original_predictor()
                print(f"✓ Original predictor loaded: {self.original_predictor.model_name}")
            except Exception as e:
                print(f"✗ Failed to load original predictor: {e}")
    
    def get_real_world_test_cases(self):
        """Real-world phishing and legitimate examples for testing."""
        test_cases = {
            # KNOWN PHISHING EXAMPLES (label=1)
            "advanced_phishing": [
                {
                    "url": "https://onlinessbi.sbi.bank.in/",
                    "description": "SBI typosquatting (missing 'e' in onlinesbi)",
                    "technique": "Typosquatting",
                    "expected": 1
                },
                {
                    "url": "https://payp4l.com/signin",
                    "description": "PayPal with number substitution",
                    "technique": "Character substitution",
                    "expected": 1
                },
                {
                    "url": "https://microsοft.com/login",
                    "description": "Microsoft with Greek omicron",
                    "technique": "Homograph attack",
                    "expected": 1
                },
                {
                    "url": "https://secure.amazon-account.verify.phish.ru/signin?redirect=amazon.com",
                    "description": "Amazon subdomain abuse with redirect",
                    "technique": "Subdomain abuse + redirect",
                    "expected": 1
                },
                {
                    "url": "https://apple-id-verify.malicious.tk/signin?user=victim@gmail.com",
                    "description": "Apple ID with suspicious TLD and parameters",
                    "technique": "Suspicious TLD + parameters",
                    "expected": 1
                },
                {
                    "url": "http://192.168.1.100:8080/banking/login.php?next=chase.com",
                    "description": "IP-based phishing with port and redirect",
                    "technique": "IP hosting + suspicious path",
                    "expected": 1
                },
                {
                    "url": "https://netflix-billing-update.verify-account.xyz/payment",
                    "description": "Netflix billing scam with multiple suspicious elements",
                    "technique": "Service impersonation + suspicious domain",
                    "expected": 1
                },
                {
                    "url": "https://bit.ly/3fake-paypal-urgent",
                    "description": "URL shortener hiding destination",
                    "technique": "URL shortening",
                    "expected": 1
                },
                {
                    "url": "https://google-security-alert.immediate-action.ml/verify?token=urgent",
                    "description": "Google security alert with urgent parameters",
                    "technique": "Urgency + suspicious params",
                    "expected": 1
                },
                {
                    "url": "https://paypal.com.account-suspended.verify-now.gq/restore",
                    "description": "Misleading TLD structure",
                    "technique": "TLD confusion",
                    "expected": 1
                }
            ],
            
            # LEGITIMATE EXAMPLES (label=0)
            "legitimate_services": [
                {
                    "url": "https://onlinesbi.sbi.co.in/",
                    "description": "Legitimate SBI online banking",
                    "technique": "Real banking site",
                    "expected": 0
                },
                {
                    "url": "https://www.paypal.com/signin",
                    "description": "Legitimate PayPal login",
                    "technique": "Real payment service",
                    "expected": 0
                },
                {
                    "url": "https://login.microsoftonline.com/",
                    "description": "Legitimate Microsoft login",
                    "technique": "Real tech service",
                    "expected": 0
                },
                {
                    "url": "https://signin.aws.amazon.com/console",
                    "description": "Legitimate AWS console",
                    "technique": "Real cloud service",
                    "expected": 0
                },
                {
                    "url": "https://appleid.apple.com/account",
                    "description": "Legitimate Apple ID",
                    "technique": "Real Apple service",
                    "expected": 0
                },
                {
                    "url": "https://www.chase.com/personal/checking",
                    "description": "Legitimate Chase banking",
                    "technique": "Real bank website",
                    "expected": 0
                },
                {
                    "url": "https://www.netflix.com/browse",
                    "description": "Legitimate Netflix",
                    "technique": "Real streaming service",
                    "expected": 0
                },
                {
                    "url": "https://github.com/user/repository",
                    "description": "Legitimate GitHub repository",
                    "technique": "Real development platform",
                    "expected": 0
                },
                {
                    "url": "https://accounts.google.com/signin/v2/identifier",
                    "description": "Legitimate Google accounts",
                    "technique": "Real Google service",
                    "expected": 0
                },
                {
                    "url": "https://stackoverflow.com/questions/ask",
                    "description": "Legitimate Stack Overflow",
                    "technique": "Real Q&A platform",
                    "expected": 0
                }
            ],
            
            # EDGE CASES AND TRICKY EXAMPLES
            "edge_cases": [
                {
                    "url": "https://www.amazon.co.uk/gp/product/B08N5WRWNW",
                    "description": "Amazon UK with long product URL",
                    "technique": "International domain + long path",
                    "expected": 0
                },
                {
                    "url": "https://subdomain.enterprise.company.com/app/dashboard",
                    "description": "Corporate subdomain structure",
                    "technique": "Deep subdomain legitimate use",
                    "expected": 0
                },
                {
                    "url": "https://www.paypal-community.com/t5/About-Protections-archive/bd-p/protections_archive",
                    "description": "PayPal community forum (legitimate)",
                    "technique": "Hyphenated legitimate domain",
                    "expected": 0
                },
                {
                    "url": "https://login.salesforce-communities.com/",
                    "description": "Salesforce communities login",
                    "technique": "Hyphenated service domain",
                    "expected": 0
                },
                {
                    "url": "https://support-microsoft.fake-domain.xyz/",
                    "description": "Fake Microsoft support",
                    "technique": "Support impersonation",
                    "expected": 1
                }
            ]
        }
        
        return test_cases
    
    def test_single_url(self, predictor, url, expected_label, description):
        """Test a single URL with a predictor."""
        try:
            result = predictor.predict(url)
            
            prediction = 1 if result["prediction"] == "PHISHING" else 0
            confidence = result["confidence"]
            phishing_prob = result["phishing_probability"]
            
            # Determine if prediction is correct
            correct = prediction == expected_label
            
            # Risk assessment
            if expected_label == 1:  # Should be phishing
                good_detection = phishing_prob >= 0.5
            else:  # Should be legitimate
                good_detection = phishing_prob < 0.5
            
            test_result = {
                "url": url,
                "description": description,
                "expected": "PHISHING" if expected_label == 1 else "LEGITIMATE",
                "predicted": result["prediction"],
                "confidence": round(confidence, 4),
                "phishing_probability": round(phishing_prob, 4),
                "correct_prediction": correct,
                "good_detection": good_detection,
                "warnings": result.get("warnings", []),
                "positive_indicators": result.get("positive_indicators", [])
            }
            
            return test_result
            
        except Exception as e:
            return {
                "url": url,
                "description": description,
                "error": str(e),
                "correct_prediction": False,
                "good_detection": False
            }
    
    def run_validation_suite(self):
        """Run complete validation suite."""
        print("\n" + "="*80)
        print("PHISHGUARD AI - ENHANCED MODEL VALIDATION SUITE")
        print("="*80)
        
        test_cases = self.get_real_world_test_cases()
        results = {}
        
        for predictor_name, predictor in [
            ("Enhanced", self.enhanced_predictor),
            ("Original", self.original_predictor)
        ]:
            if predictor is None:
                print(f"\n⚠️  {predictor_name} predictor not available, skipping...")
                continue
            
            print(f"\n🧪 Testing {predictor_name} Predictor")
            print("-" * 40)
            
            predictor_results = {}
            total_tests = 0
            correct_predictions = 0
            good_detections = 0
            
            for category_name, test_list in test_cases.items():
                print(f"\n📂 {category_name.replace('_', ' ').title()}")
                
                category_results = []
                for test_case in test_list:
                    result = self.test_single_url(
                        predictor, 
                        test_case["url"],
                        test_case["expected"],
                        test_case["description"]
                    )
                    
                    category_results.append(result)
                    total_tests += 1
                    
                    if result.get("correct_prediction", False):
                        correct_predictions += 1
                    if result.get("good_detection", False):
                        good_detections += 1
                    
                    # Print result
                    status = "✅" if result.get("correct_prediction", False) else "❌"
                    prob = result.get("phishing_probability", 0)
                    print(f"  {status} {test_case['technique']:<25} | Risk: {prob:.3f} | {test_case['description'][:50]}")
                
                predictor_results[category_name] = category_results
            
            # Calculate metrics
            accuracy = correct_predictions / total_tests if total_tests > 0 else 0
            detection_rate = good_detections / total_tests if total_tests > 0 else 0
            
            predictor_results["summary"] = {
                "total_tests": total_tests,
                "correct_predictions": correct_predictions,
                "good_detections": good_detections,
                "accuracy": accuracy,
                "detection_rate": detection_rate
            }
            
            print(f"\n📊 {predictor_name} Results Summary:")
            print(f"   Accuracy: {accuracy:.1%} ({correct_predictions}/{total_tests})")
            print(f"   Detection Rate: {detection_rate:.1%}")
            
            results[predictor_name] = predictor_results
        
        self.test_results = results
        return results
    
    def compare_models(self):
        """Compare enhanced vs original model performance."""
        if "Enhanced" not in self.test_results or "Original" not in self.test_results:
            print("\n⚠️  Cannot compare models - both predictors not available")
            return
        
        enhanced = self.test_results["Enhanced"]["summary"]
        original = self.test_results["Original"]["summary"]
        
        print("\n" + "="*80)
        print("MODEL COMPARISON RESULTS")
        print("="*80)
        
        print(f"{'Metric':<20} {'Enhanced':<15} {'Original':<15} {'Improvement':<15}")
        print("-" * 65)
        
        # Accuracy comparison
        acc_improvement = enhanced["accuracy"] - original["accuracy"]
        print(f"{'Accuracy':<20} {enhanced['accuracy']:.1%}{'':>6} {original['accuracy']:.1%}{'':>6} {acc_improvement:+.1%}")
        
        # Detection rate comparison
        det_improvement = enhanced["detection_rate"] - original["detection_rate"]
        print(f"{'Detection Rate':<20} {enhanced['detection_rate']:.1%}{'':>6} {original['detection_rate']:.1%}{'':>6} {det_improvement:+.1%}")
        
        # Correct predictions
        pred_improvement = enhanced["correct_predictions"] - original["correct_predictions"]
        print(f"{'Correct Predictions':<20} {enhanced['correct_predictions']:>9} {original['correct_predictions']:>12} {pred_improvement:+8}")
        
        print(f"\n🎯 Summary:")
        if acc_improvement > 0:
            print(f"   ✅ Enhanced model performs {acc_improvement:.1%} better overall")
        else:
            print(f"   ⚠️  Enhanced model performs {abs(acc_improvement):.1%} worse overall")
        
        if det_improvement > 0:
            print(f"   ✅ Enhanced model has {det_improvement:.1%} better detection rate")
        else:
            print(f"   ⚠️  Enhanced model has {abs(det_improvement):.1%} worse detection rate")
    
    def analyze_specific_improvements(self):
        """Analyze specific areas where enhanced model performs better."""
        if "Enhanced" not in self.test_results or "Original" not in self.test_results:
            return
        
        print("\n" + "="*80)
        print("SPECIFIC IMPROVEMENT ANALYSIS")
        print("="*80)
        
        improvements = []
        regressions = []
        
        for category in ["advanced_phishing", "legitimate_services", "edge_cases"]:
            enhanced_results = self.test_results["Enhanced"][category]
            original_results = self.test_results["Original"][category]
            
            for i, (enh, orig) in enumerate(zip(enhanced_results, original_results)):
                if enh.get("correct_prediction") and not orig.get("correct_prediction"):
                    improvements.append({
                        "category": category,
                        "description": enh["description"],
                        "url": enh["url"],
                        "enhanced_prob": enh.get("phishing_probability", 0),
                        "original_prob": orig.get("phishing_probability", 0)
                    })
                elif orig.get("correct_prediction") and not enh.get("correct_prediction"):
                    regressions.append({
                        "category": category,
                        "description": enh["description"],
                        "url": enh["url"],
                        "enhanced_prob": enh.get("phishing_probability", 0),
                        "original_prob": orig.get("phishing_probability", 0)
                    })
        
        print(f"\n✅ IMPROVEMENTS ({len(improvements)} cases where Enhanced performs better):")
        for imp in improvements:
            print(f"   📈 {imp['description']}")
            print(f"      Enhanced: {imp['enhanced_prob']:.3f} vs Original: {imp['original_prob']:.3f}")
        
        if regressions:
            print(f"\n❌ REGRESSIONS ({len(regressions)} cases where Enhanced performs worse):")
            for reg in regressions:
                print(f"   📉 {reg['description']}")
                print(f"      Enhanced: {reg['enhanced_prob']:.3f} vs Original: {reg['original_prob']:.3f}")
        else:
            print(f"\n🎉 No regressions found! Enhanced model performs equal or better in all test cases.")
    
    def save_validation_report(self):
        """Save detailed validation report to file."""
        report = {
            "validation_date": datetime.now().isoformat(),
            "test_results": self.test_results,
            "summary": "PhishGuard AI Enhanced Model Validation Report"
        }
        
        report_path = "enhanced_model_validation_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\n💾 Detailed report saved to: {report_path}")
        return report_path


def main():
    """Run the complete model validation suite."""
    validator = ModelValidationSuite()
    
    # Run validation tests
    results = validator.run_validation_suite()
    
    # Compare models if both available
    validator.compare_models()
    
    # Analyze specific improvements
    validator.analyze_specific_improvements()
    
    # Save report
    validator.save_validation_report()
    
    print("\n" + "="*80)
    print("VALIDATION COMPLETE")
    print("="*80)
    
    return results


if __name__ == "__main__":
    main()