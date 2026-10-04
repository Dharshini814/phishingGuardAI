"""
PhishGuard AI - False Positive Fix

Quick fix for false positives on legitimate banking websites.
This creates a post-processing filter to reduce false positives.
"""

import os
import sys
import json
import joblib
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.enhanced_feature_extraction import extract_enhanced_features, ENHANCED_FEATURE_NAMES
from model.enhanced_predictor import get_enhanced_predictor


class FalsePositiveFilter:
    """Filter to reduce false positives on legitimate websites."""
    
    def __init__(self):
        self.legitimate_domains = [
            # Indian Banking - Legitimate
            'sbi.co.in', 'onlinesbi.sbi.co.in', 'netbanking.sbi.co.in',
            'hdfcbank.com', 'netbanking.hdfcbank.com', 'hdfcbank.net',
            'icicibank.com', 'netbanking.icicibank.com', 'icicibank.co.in',
            'kotakbank.com', 'netbanking.kotak.com', 'kotak.com',
            'axisbank.com', 'axisbank.co.in', 'axisbank.net',
            'pnbindia.in', 'pnb.co.in', 'netbanking.pnb.co.in',
            'canarabank.com', 'canarabank.in', 'canbank.co.in',
            'bankofbaroda.in', 'bankofbaroda.com', 'bobibanking.com',
            'unionbankofindia.co.in', 'ubibanking.com', 'ubi.co.in',
            'indianbank.in', 'indianbank.net.in', 'indianbank-net.com',
            'centralbankofindia.co.in', 'centralbankofindia.co.in',
            
            # Payment Services - Legitimate
            'paytm.com', 'paytm.in', 'paytmbank.com',
            'phonepe.com', 'phonepe.app',
            'googlepay.com', 'pay.google.com',
            'bharatpe.com', 'bharatpe.in',
            'mobikwik.com', 'zaakpay.com',
            
            # International Banking - Legitimate
            'chase.com', 'jpmorgan.com', 'jpmorganchase.com',
            'bankofamerica.com', 'bofa.com', 'merrilledge.com',
            'wellsfargo.com', 'wf.com', 'wellsfargobank.com',
            'citibank.com', 'citi.com', 'citigroup.com',
            'hsbc.com', 'hsbc.co.uk', 'us.hsbc.com',
            
            # Tech Companies - Legitimate
            'google.com', 'gmail.com', 'youtube.com', 'blogger.com',
            'microsoft.com', 'outlook.com', 'hotmail.com', 'live.com',
            'apple.com', 'icloud.com', 'me.com', 'mac.com',
            'amazon.com', 'amazon.in', 'aws.amazon.com', 'amazonpay.com',
            'facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com',
            'twitter.com', 'x.com', 't.co',
            'linkedin.com', 'github.com', 'stackoverflow.com',
            'paypal.com', 'paypal.me', 'paypal-community.com',
            
            # Other Legitimate Services
            'netflix.com', 'spotify.com', 'dropbox.com', 'zoom.us',
            'salesforce.com', 'salesforce-communities.com',
            'office.com', 'office365.com', 'microsoftonline.com',
            'adobe.com', 'adobelogin.com'
        ]
    
    def is_legitimate_domain(self, hostname):
        """Check if hostname belongs to a legitimate service."""
        hostname_lower = hostname.lower()
        
        # Direct match or subdomain of legitimate domains
        for legit_domain in self.legitimate_domains:
            if hostname_lower == legit_domain or hostname_lower.endswith('.' + legit_domain):
                return True
        
        # Educational, government, non-profit
        if hostname_lower.endswith(('.edu', '.gov', '.org')):
            return True
        
        return False
    
    def apply_filter(self, prediction_result, url):
        """Apply false positive filter to prediction result."""
        from urllib.parse import urlparse
        
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            
            # If it's a legitimate domain and predicted as phishing
            if (prediction_result["prediction"] == "PHISHING" and 
                self.is_legitimate_domain(hostname)):
                
                # Check if it's a borderline case (not very high confidence)
                phishing_prob = prediction_result.get("phishing_probability", 1.0)
                
                if phishing_prob < 0.95:  # Less than 95% confidence
                    # Reduce the phishing probability and change prediction
                    adjusted_prob = min(phishing_prob * 0.3, 0.4)  # Reduce significantly
                    
                    new_result = prediction_result.copy()
                    new_result["phishing_probability"] = adjusted_prob
                    new_result["legitimate_probability"] = 1.0 - adjusted_prob
                    new_result["prediction"] = "LEGITIMATE" if adjusted_prob < 0.5 else "PHISHING"
                    new_result["confidence"] = 1.0 - adjusted_prob if adjusted_prob < 0.5 else adjusted_prob
                    new_result["risk_level"] = "MINIMAL" if adjusted_prob < 0.2 else "LOW"
                    
                    # Add note about filter
                    if "positive_indicators" not in new_result:
                        new_result["positive_indicators"] = []
                    new_result["positive_indicators"].append("Recognized as legitimate service domain")
                    
                    return new_result
            
            return prediction_result
            
        except Exception as e:
            # If filtering fails, return original result
            return prediction_result


def test_filter():
    """Test the false positive filter."""
    filter_obj = FalsePositiveFilter()
    
    try:
        predictor = get_enhanced_predictor()
    except Exception as e:
        print(f"Could not load predictor: {e}")
        return
    
    # Test cases that were showing false positives
    test_urls = [
        "https://onlinesbi.sbi.co.in/",  # Should be LEGITIMATE
        "https://netbanking.hdfcbank.com/",  # Should be LEGITIMATE
        "https://www.paypal.com/signin",  # Should be LEGITIMATE
        "https://onlinessbi.sbi.bank.in/",  # Should still be PHISHING (typosquatting)
        "https://accounts.google.com/signin",  # Should be LEGITIMATE
    ]
    
    print("="*80)
    print("FALSE POSITIVE FILTER TEST")
    print("="*80)
    
    for url in test_urls:
        print(f"\nTesting: {url}")
        
        try:
            # Get original prediction
            original = predictor.predict(url)
            
            # Apply filter
            filtered = filter_obj.apply_filter(original, url)
            
            print(f"  Original : {original['prediction']} ({original['phishing_probability']:.3f})")
            print(f"  Filtered : {filtered['prediction']} ({filtered['phishing_probability']:.3f})")
            
            if original != filtered:
                print(f"  ✅ Filter applied - reduced false positive!")
            else:
                print(f"  ➡️  No change needed")
                
        except Exception as e:
            print(f"  ❌ Error: {e}")
    
    return filter_obj


def create_enhanced_predictor_with_filter():
    """Create an enhanced predictor class with built-in filter."""
    
    code = '''"""
Enhanced Predictor with False Positive Filter
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from model.enhanced_predictor import EnhancedPhishingPredictor
from urllib.parse import urlparse


class FilteredEnhancedPredictor(EnhancedPhishingPredictor):
    """Enhanced predictor with built-in false positive filtering."""
    
    def __init__(self):
        super().__init__()
        self.legitimate_domains = [
            # Indian Banking
            'sbi.co.in', 'onlinesbi.sbi.co.in', 'netbanking.sbi.co.in',
            'hdfcbank.com', 'netbanking.hdfcbank.com',
            'icicibank.com', 'netbanking.icicibank.com',
            'kotakbank.com', 'netbanking.kotak.com',
            'axisbank.com', 'axisbank.co.in',
            'pnbindia.in', 'pnb.co.in',
            
            # International
            'chase.com', 'bankofamerica.com', 'wellsfargo.com',
            'citibank.com', 'hsbc.com', 'paypal.com',
            
            # Tech
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'twitter.com', 'linkedin.com', 'github.com'
        ]
    
    def is_legitimate_domain(self, hostname):
        """Check if hostname is legitimate."""
        hostname_lower = hostname.lower()
        for domain in self.legitimate_domains:
            if hostname_lower == domain or hostname_lower.endswith('.' + domain):
                return True
        return hostname_lower.endswith(('.edu', '.gov', '.org'))
    
    def predict(self, url: str) -> dict:
        """Predict with false positive filtering."""
        # Get base prediction
        result = super().predict(url)
        
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            
            # Apply filter for legitimate domains
            if (result["prediction"] == "PHISHING" and 
                self.is_legitimate_domain(hostname) and
                result.get("phishing_probability", 1.0) < 0.95):
                
                # Adjust probabilities
                original_prob = result.get("phishing_probability", 1.0)
                adjusted_prob = min(original_prob * 0.3, 0.4)
                
                result["phishing_probability"] = adjusted_prob
                result["legitimate_probability"] = 1.0 - adjusted_prob
                result["prediction"] = "LEGITIMATE" if adjusted_prob < 0.5 else "PHISHING"
                result["confidence"] = 1.0 - adjusted_prob if adjusted_prob < 0.5 else adjusted_prob
                result["risk_level"] = "MINIMAL" if adjusted_prob < 0.2 else "LOW"
                
                if "positive_indicators" not in result:
                    result["positive_indicators"] = []
                result["positive_indicators"].append("Recognized as legitimate service domain")
        
        except:
            pass  # Return original result if filtering fails
        
        return result


def get_filtered_predictor():
    """Get the filtered enhanced predictor."""
    global _filtered_predictor_instance
    if '_filtered_predictor_instance' not in globals():
        globals()['_filtered_predictor_instance'] = FilteredEnhancedPredictor()
    return globals()['_filtered_predictor_instance']
'''
    
    # Save the filtered predictor
    with open("model/filtered_enhanced_predictor.py", "w") as f:
        f.write(code)
    
    print("✅ Created filtered enhanced predictor at model/filtered_enhanced_predictor.py")


if __name__ == "__main__":
    # Test the filter
    filter_obj = test_filter()
    
    # Create the filtered predictor file
    create_enhanced_predictor_with_filter()
    
    print(f"\n💡 To use the filtered predictor, update your app.py imports:")
    print(f"   from model.filtered_enhanced_predictor import get_filtered_predictor")
    print(f"   predictor = get_filtered_predictor()")