"""
Create a Proper Training Dataset for PhishGuard AI

This creates a balanced, realistic dataset that will teach the model to:
1. Recognize legitimate banking/service URLs correctly
2. Detect typosquatting, homograph attacks, and other phishing techniques
3. Not rely on hardcoded domain lists but learn patterns

The key is to have enough legitimate examples of real banking URLs
and enough phishing examples with clear distinguishing features.
"""

import pandas as pd
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from services.enhanced_feature_extraction import extract_enhanced_features, ENHANCED_FEATURE_NAMES


def create_realistic_training_data():
    """Create realistic training data with proper balance."""
    
    # Legitimate URLs - Real banking and service URLs
    legitimate_urls = [
        # Indian Banking (Legitimate)
        "https://onlinesbi.sbi.co.in/",
        "https://onlinesbi.sbi.co.in/sbijava/",
        "https://netbanking.sbi.co.in/",
        "https://retail.onlinesbi.com/",
        "https://netbanking.hdfcbank.com/",
        "https://netbanking.hdfcbank.com/netbanking/",
        "https://www.hdfcbank.com/",
        "https://www.icicibank.com/",
        "https://www.icicibank.com/personal-banking/",
        "https://netbanking.icicibank.com/",
        "https://www.kotakbank.com/",
        "https://netbanking.kotak.com/",
        "https://www.axisbank.com/",
        "https://retail.axisbank.co.in/",
        "https://www.pnbindia.in/",
        "https://netbanking.pnb.co.in/",
        
        # International Banking (Legitimate)
        "https://www.chase.com/",
        "https://www.chase.com/personal/checking",
        "https://secure01a.chase.com/web/auth/",
        "https://www.bankofamerica.com/",
        "https://secure.bankofamerica.com/",
        "https://www.wellsfargo.com/",
        "https://connect.secure.wellsfargo.com/",
        "https://online.citi.com/",
        "https://www.citibank.com/",
        "https://www.hsbc.com/",
        "https://www.hsbc.co.uk/",
        
        # Payment Services (Legitimate)
        "https://www.paypal.com/",
        "https://www.paypal.com/signin",
        "https://www.paypal.com/us/webapps/mpp/",
        "https://www.paypal-community.com/",
        "https://developer.paypal.com/",
        "https://pay.google.com/",
        "https://payments.google.com/",
        "https://wallet.paytm.com/",
        "https://www.paytm.com/",
        "https://www.phonepe.com/",
        "https://razorpay.com/",
        "https://stripe.com/",
        
        # Tech Companies (Legitimate)
        "https://www.google.com/",
        "https://accounts.google.com/signin/v2/",
        "https://www.microsoft.com/",
        "https://login.microsoftonline.com/",
        "https://portal.azure.com/",
        "https://www.apple.com/",
        "https://appleid.apple.com/",
        "https://www.amazon.com/",
        "https://signin.aws.amazon.com/",
        "https://www.facebook.com/",
        "https://www.instagram.com/",
        "https://twitter.com/",
        "https://www.linkedin.com/",
        "https://github.com/",
        
        # Other Services (Legitimate)
        "https://www.netflix.com/",
        "https://www.spotify.com/",
        "https://www.dropbox.com/",
        "https://zoom.us/",
        "https://slack.com/",
        "https://www.salesforce.com/",
        "https://login.salesforce.com/",
        "https://www.adobe.com/",
        "https://stackoverflow.com/",
        "https://www.wikipedia.org/",
        
        # More legitimate variations
        "https://www.sbi.co.in/web/personal-banking",
        "https://www.sbi.co.in/web/corporate-banking", 
        "https://netbanking.hdfcbank.com/netbanking/IpinResetUsingOTP.htm",
        "https://www.icicibank.com/Personal-Banking/account-deposit/savings-account",
        "https://www.paypal.com/us/smarthelp/home",
        "https://support.google.com/accounts/",
        "https://support.microsoft.com/",
        "https://help.apple.com/",
        "https://www.amazon.com/gp/help/customer/",
        "https://help.netflix.com/",
    ]
    
    # Phishing URLs - Clear phishing examples with distinguishing features
    phishing_urls = [
        # Typosquatting - Missing letters
        "https://onlinessbi.sbi.bank.in/",  # Missing 'e' in onlinesbi
        "https://onlinesbi.sb.co.in/",      # Missing 'i' in sbi
        "https://onlinesbi.sbi.co.n/",      # Missing 'i' in .in
        "https://netbaking.hdfcbank.com/",  # Missing 'n' in netbanking
        "https://netbankin.hdfcbank.com/",  # Missing 'g' in netbanking
        "https://hdfcbnk.com/",             # Missing letters in hdfcbank
        "https://icicbank.com/",            # Missing 'i' in icicibank
        "https://kotakbnk.com/",            # Missing letters in kotakbank
        "https://axisbnk.com/",             # Missing letters in axisbank
        
        # Typosquatting - Character substitution
        "https://payp4l.com/",              # '4' instead of 'a'
        "https://paypa1.com/",              # '1' instead of 'l'
        "https://g00gle.com/",              # '00' instead of 'oo'
        "https://micr0soft.com/",           # '0' instead of 'o'
        "https://arnazon.com/",             # 'rn' instead of 'm'
        "https://netf1ix.com/",             # '1' instead of 'l'
        "https://spotify.corn/",            # 'corn' instead of 'com'
        
        # Homograph attacks (Unicode)
        "https://microsοft.com/",           # Greek omicron
        "https://gοοgle.com/",             # Greek omicrons
        "https://аpple.com/",              # Cyrillic 'a'
        "https://paypaℓ.com/",             # Unicode 'ℓ'
        
        # Subdomain abuse
        "https://secure.paypal.com.phish.ru/",
        "https://login.amazon.com.fake.tk/",
        "https://verify.google.com.scam.ml/",
        "https://update.microsoft.com.malicious.gq/",
        "https://secure.sbi.co.in.phishing.cf/",
        "https://netbanking.hdfc.bank.fake.xyz/",
        
        # Suspicious TLD abuse
        "https://paypal-secure.tk/",
        "https://amazon-verify.ml/",
        "https://google-security.gq/",
        "https://microsoft-update.cf/",
        "https://sbi-netbanking.xyz/",
        "https://hdfc-secure.info/",
        
        # IP-based phishing
        "http://192.168.1.100/banking/sbi/",
        "http://203.0.113.5/paypal/signin/",
        "http://198.51.100.1/google/accounts/",
        "http://172.16.0.1/microsoft/login/",
        
        # Port-based suspicious
        "https://secure-paypal.com:8080/",
        "https://banking-sbi.com:8888/",
        "https://google-verify.com:9090/",
        
        # Misleading paths
        "https://phishing.com/paypal.com/signin",
        "https://scam.ru/google.com/accounts",
        "https://fake.tk/microsoft.com/login",
        "https://malicious.ml/sbi.co.in/banking",
        
        # URL shorteners (suspicious usage)
        "https://bit.ly/fake-paypal-login",
        "https://tinyurl.com/phish-sbi-bank",
        "https://t.co/suspicious-google-auth",
        
        # Multiple service names (red flag)
        "https://paypal-amazon-verify.com/",
        "https://google-microsoft-update.net/",
        "https://sbi-hdfc-netbanking.org/",
        
        # Urgency/scam keywords in domain
        "https://urgent-paypal-verify.com/",
        "https://suspended-account-restore.net/",
        "https://immediate-action-required.org/",
        "https://security-alert-verify.info/",
        
        # Mixed legitimate + suspicious
        "https://secure-login-paypal.phishing.ru/",
        "https://verify-account-sbi.fake.tk/",
        "https://update-security-google.scam.ml/",
        
        # More sophisticated examples
        "https://www.paypal.com-security-verify.malicious.com/",
        "https://accounts.google.com.phishing.net/",
        "https://login.microsoft.com.fake.org/",
        "https://onlinesbi.sbi.co.in.verify.suspicious.ru/",
    ]
    
    # Create dataset
    data = []
    
    # Add legitimate URLs
    for url in legitimate_urls:
        data.append({"url": url, "label": 0, "type": "legitimate"})
    
    # Add phishing URLs  
    for url in phishing_urls:
        data.append({"url": url, "label": 1, "type": "phishing"})
    
    # Balance the dataset by adding more legitimate examples if needed
    while len([d for d in data if d["label"] == 0]) < len([d for d in data if d["label"] == 1]):
        # Add more legitimate variations
        base_legit = [
            "https://www.example-bank.com/",
            "https://secure.legitimate-service.org/",
            "https://portal.real-company.net/",
            "https://www.trusted-site.edu/",
            "https://official.government.gov/",
        ]
        for url in base_legit[:5]:  # Add a few at a time
            data.append({"url": url, "label": 0, "type": "legitimate_synthetic"})
            if len([d for d in data if d["label"] == 0]) >= len([d for d in data if d["label"] == 1]):
                break
    
    return pd.DataFrame(data)


def extract_features_for_dataset(df):
    """Extract features for all URLs in the dataset."""
    print(f"Extracting features for {len(df)} URLs...")
    
    feature_data = []
    for idx, row in df.iterrows():
        if idx % 20 == 0:
            print(f"  Processing {idx+1}/{len(df)}")
        
        try:
            url = row['url']
            features = extract_enhanced_features(url)
            
            # Combine row data with features
            combined = row.to_dict()
            combined.update(features)
            feature_data.append(combined)
            
        except Exception as e:
            print(f"  Error processing {url}: {e}")
            continue
    
    return pd.DataFrame(feature_data)


def main():
    """Create proper training dataset."""
    print("Creating realistic phishing detection dataset...")
    
    # Generate URLs
    df = create_realistic_training_data()
    print(f"Generated {len(df)} URLs:")
    print(f"  Legitimate: {(df['label'] == 0).sum()}")
    print(f"  Phishing: {(df['label'] == 1).sum()}")
    
    # Extract features
    feature_df = extract_features_for_dataset(df)
    print(f"Extracted features for {len(feature_df)} URLs")
    
    # Save dataset
    output_path = "data/proper_training_dataset.csv"
    feature_df.to_csv(output_path, index=False)
    print(f"Saved dataset: {output_path}")
    
    # Show sample
    print("\nSample legitimate URLs:")
    legit_samples = feature_df[feature_df['label'] == 0]['url'].head(5)
    for url in legit_samples:
        print(f"  ✅ {url}")
    
    print("\nSample phishing URLs:")
    phish_samples = feature_df[feature_df['label'] == 1]['url'].head(5)
    for url in phish_samples:
        print(f"  ⚠️  {url}")
    
    # Show key features
    print(f"\nDataset features: {len(ENHANCED_FEATURE_NAMES)} total")
    print("Key distinguishing features:")
    for feature in ['has_typosquatting', 'has_homograph_chars', 'has_misleading_tld', 'has_suspicious_tld']:
        if feature in feature_df.columns:
            count = feature_df[feature].sum()
            print(f"  {feature}: {count} URLs ({count/len(feature_df)*100:.1f}%)")
    
    return feature_df


if __name__ == "__main__":
    main()