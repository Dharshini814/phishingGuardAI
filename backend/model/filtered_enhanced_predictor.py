"""
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
