"""
PhishGuard AI - Dataset Preprocessing Pipeline

This module processes and combines multiple phishing datasets:
1. Professional datasets (PhishTank, LegitPhish, Zenodo, EdgePhish-5G)
2. Synthetic datasets with enhanced patterns
3. Data quality validation and cleaning
4. Balanced dataset generation for optimal training

Ensures high-quality training data for improved phishing detection.
"""

import pandas as pd
import numpy as np
import os
import sys
import re
import logging
from urllib.parse import urlparse, parse_qs
from collections import Counter
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from config import TYPOSQUATTING_PATTERNS, LEGITIMATE_DOMAINS
except ImportError:
    logger.warning("Could not import config. Using fallback patterns.")
    TYPOSQUATTING_PATTERNS = ['onlinessbi', 'microsοft', 'payp4l', 'arnazon', 'gοοgle']
    LEGITIMATE_DOMAINS = ['sbi.co.in', 'microsoft.com', 'paypal.com', 'amazon.com', 'google.com']


class DatasetPreprocessor:
    """Comprehensive dataset preprocessing for phishing detection."""
    
    def __init__(self, data_dir="./"):
        self.data_dir = data_dir
        self.quality_stats = {}
        
    def load_professional_dataset(self, filename="professional_phishing_dataset.csv"):
        """Load professional dataset if exists."""
        filepath = os.path.join(self.data_dir, filename)
        if os.path.exists(filepath):
            logger.info(f"Loading professional dataset: {filename}")
            df = pd.read_csv(filepath)
            logger.info(f"Loaded {len(df)} samples from professional sources")
            return df
        else:
            logger.warning(f"Professional dataset not found: {filepath}")
            return pd.DataFrame()
    
    def load_synthetic_dataset(self, filename="phishing_dataset.csv"):
        """Load existing synthetic dataset."""
        filepath = os.path.join(self.data_dir, filename)
        if os.path.exists(filepath):
            logger.info(f"Loading synthetic dataset: {filename}")
            df = pd.read_csv(filepath)
            # Add source column if missing
            if 'source' not in df.columns:
                df['source'] = 'Synthetic'
            logger.info(f"Loaded {len(df)} samples from synthetic sources")
            return df
        else:
            logger.warning(f"Synthetic dataset not found: {filepath}")
            return pd.DataFrame()
    
    def validate_url_quality(self, df):
        """Validate and clean URL data quality."""
        logger.info("Validating URL data quality...")
        
        original_count = len(df)
        quality_issues = []
        
        # Remove empty URLs
        empty_urls = df['url'].isna() | (df['url'].str.strip() == '')
        if empty_urls.sum() > 0:
            quality_issues.append(f"Removed {empty_urls.sum()} empty URLs")
            df = df[~empty_urls]
        
        # Remove malformed URLs
        def is_valid_url(url):
            try:
                parsed = urlparse(str(url))
                return bool(parsed.scheme and parsed.netloc)
            except:
                return False
        
        valid_urls = df['url'].apply(is_valid_url)
        if (~valid_urls).sum() > 0:
            quality_issues.append(f"Removed {(~valid_urls).sum()} malformed URLs")
            df = df[valid_urls]
        
        # Remove extremely long URLs (likely corrupted)
        max_url_length = 2000
        long_urls = df['url'].str.len() > max_url_length
        if long_urls.sum() > 0:
            quality_issues.append(f"Removed {long_urls.sum()} extremely long URLs (>{max_url_length} chars)")
            df = df[~long_urls]
        
        # Remove duplicate URLs
        duplicates = df.duplicated(subset=['url'], keep='first')
        if duplicates.sum() > 0:
            quality_issues.append(f"Removed {duplicates.sum()} duplicate URLs")
            df = df[~duplicates]
        
        # Validate labels
        invalid_labels = ~df['label'].isin([0, 1])
        if invalid_labels.sum() > 0:
            quality_issues.append(f"Removed {invalid_labels.sum()} samples with invalid labels")
            df = df[~invalid_labels]
        
        cleaned_count = len(df)
        logger.info(f"Data quality validation complete:")
        logger.info(f"  Original samples: {original_count:,}")
        logger.info(f"  Cleaned samples: {cleaned_count:,}")
        logger.info(f"  Removed samples: {original_count - cleaned_count:,}")
        
        for issue in quality_issues:
            logger.info(f"  - {issue}")
        
        self.quality_stats = {
            'original_count': original_count,
            'cleaned_count': cleaned_count,
            'removed_count': original_count - cleaned_count,
            'quality_issues': quality_issues
        }
        
        return df
    
    def enhance_url_features(self, df):
        """Add enhanced URL features for better detection."""
        logger.info("Enhancing URL features...")
        
        # Basic URL parsing
        df['parsed_url'] = df['url'].apply(lambda x: urlparse(str(x)))
        df['domain'] = df['parsed_url'].apply(lambda x: x.netloc.lower())
        df['path'] = df['parsed_url'].apply(lambda x: x.path)
        df['query'] = df['parsed_url'].apply(lambda x: x.query)
        df['scheme'] = df['parsed_url'].apply(lambda x: x.scheme.lower())
        
        # Domain analysis
        df['domain_length'] = df['domain'].str.len()
        df['subdomain_count'] = df['domain'].str.count('\.') 
        df['has_ip_domain'] = df['domain'].apply(self._is_ip_address)
        
        # Path analysis
        df['path_length'] = df['path'].str.len()
        df['path_depth'] = df['path'].str.count('/')
        df['has_suspicious_path'] = df['path'].str.contains(
            r'(login|signin|verify|update|confirm|secure|account|banking|paypal|amazon|google|apple|microsoft)',
            case=False, na=False
        )
        
        # Query analysis
        df['query_length'] = df['query'].str.len()
        df['query_params_count'] = df['query'].apply(lambda x: len(parse_qs(str(x))) if x else 0)
        df['has_suspicious_params'] = df['query'].str.contains(
            r'(redirect|next|return|user|email|password|token|session|ssn|credit|cvv)',
            case=False, na=False
        )
        
        # Protocol analysis
        df['is_https'] = df['scheme'] == 'https'
        df['has_port'] = df['domain'].str.contains(':', na=False)
        
        # Suspicious character analysis
        df['has_suspicious_chars'] = df['url'].str.contains(r'[^\x00-\x7F]', na=False)  # Non-ASCII
        df['hyphen_count'] = df['domain'].str.count('-')
        df['digit_count'] = df['domain'].str.count(r'\d')
        
        # Typosquatting detection
        df['has_typosquatting'] = df['domain'].apply(self._detect_typosquatting)
        
        # URL shortening detection
        shortening_services = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.link',
            'is.gd', 'buff.ly', 'adf.ly', 'bc.vc', 'smarturl.it'
        ]
        df['is_shortened'] = df['domain'].apply(
            lambda x: any(service in str(x).lower() for service in shortening_services)
        )
        
        # Reputation analysis (basic)
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.ru', '.cn', '.cc']
        df['has_suspicious_tld'] = df['domain'].apply(
            lambda x: any(str(x).lower().endswith(tld) for tld in suspicious_tlds)
        )
        
        # Advanced pattern detection
        df['looks_like_legitimate'] = df['domain'].apply(self._looks_like_legitimate_service)
        df['has_misleading_tld'] = df.apply(self._has_misleading_tld, axis=1)
        
        # Clean up temporary columns
        df = df.drop(['parsed_url'], axis=1)
        
        logger.info(f"Enhanced {len(df)} URLs with {df.select_dtypes(include=['bool']).shape[1]} boolean features")
        return df
    
    def _is_ip_address(self, domain):
        """Check if domain is an IP address."""
        try:
            parts = str(domain).split(':')[0].split('.')  # Remove port if present
            if len(parts) == 4:
                return all(0 <= int(part) <= 255 for part in parts)
        except:
            pass
        return False
    
    def _detect_suspicious_keywords_smart(self, url, domain):
        """Smart suspicious keyword detection that considers legitimate domains."""
        url_lower = url.lower()
        domain_lower = domain.lower()
        
        # If the domain is legitimate, don't flag keywords as suspicious
        if self._is_legitimate_domain(domain_lower):
            return False
        
        # Check for suspicious keywords in URL
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in url_lower:
                return True
        
        return False
    
    def _is_legitimate_domain(self, domain):
        """Check if domain is a known legitimate service."""
        # Known legitimate domains (including banking)
        legitimate_domains = [
            # Indian Banking
            'sbi.co.in', 'onlinesbi.sbi.co.in', 'sbi.co.in', 
            'hdfcbank.com', 'netbanking.hdfcbank.com',
            'icicibank.com', 'netbanking.icicibank.com',
            'kotakbank.com', 'netbanking.kotak.com',
            'axisbank.com', 'axisbank.co.in',
            'pnbindia.in', 'netbanking.pnb.co.in',
            
            # International Banking
            'chase.com', 'bankofamerica.com', 'wellsfargo.com',
            'citibank.com', 'hsbc.com', 'jpmorgan.com',
            
            # Tech Companies
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'twitter.com', 'linkedin.com', 'github.com',
            
            # Payment Services
            'paypal.com', 'paytm.com', 'phonepe.com', 'googlepay.com',
            
            # Other Services
            'netflix.com', 'spotify.com', 'dropbox.com', 'zoom.us'
        ]
        
        # Check if domain ends with any legitimate domain
        for legit_domain in legitimate_domains:
            if domain.endswith(legit_domain):
                return True
        
        # Check for common legitimate TLD patterns
        legitimate_patterns = [
            '.edu', '.gov', '.org'  # Educational, government, non-profit
        ]
        
        for pattern in legitimate_patterns:
            if domain.endswith(pattern):
                return True
        
        return False
    
    def _is_similar_domain(self, domain1, domain2, threshold=0.8):
        """Check if domains are similar (potential typosquatting)."""
        try:
            # Simple similarity check based on common characters
            set1, set2 = set(domain1), set(domain2)
            intersection = len(set1 & set2)
            union = len(set1 | set2)
            similarity = intersection / union if union > 0 else 0
            return similarity > threshold and abs(len(domain1) - len(domain2)) <= 2
        except:
            return False
    
    def _looks_like_legitimate_service(self, domain):
        """Check if domain looks like a legitimate service."""
        domain_str = str(domain).lower()
        
        # Known legitimate patterns
        legitimate_patterns = [
            r'\.edu$', r'\.gov$', r'\.org$',  # Educational/Government
            r'\.com$', r'\.net$', r'\.co\.', # Commercial
            r'(google|microsoft|amazon|apple|facebook|twitter|linkedin|github)\.com',
            r'(paypal|visa|mastercard|amex)\.com',
            r'(chase|bankofamerica|wellsfargo|citibank)\.com'
        ]
        
        return any(re.search(pattern, domain_str) for pattern in legitimate_patterns)
    
    def _has_misleading_tld(self, row):
        """Check if URL has misleading TLD (e.g., paypal.com.phishing.xyz)."""
        url = str(row['url']).lower()
        domain = str(row['domain']).lower()
        
        # Check for legitimate domain followed by suspicious domain
        legitimate_services = ['paypal.com', 'amazon.com', 'google.com', 'apple.com', 'microsoft.com']
        
        for service in legitimate_services:
            if service in url and not domain.endswith(service):
                return True
        
        return False
    
    def balance_dataset(self, df, target_ratio=0.5, max_samples_per_class=25000):
        """Balance the dataset for optimal training."""
        logger.info("Balancing dataset...")
        
        phishing_samples = df[df['label'] == 1]
        legitimate_samples = df[df['label'] == 0]
        
        logger.info(f"Before balancing:")
        logger.info(f"  Phishing samples: {len(phishing_samples):,}")
        logger.info(f"  Legitimate samples: {len(legitimate_samples):,}")
        
        # Calculate target counts
        total_samples = min(len(phishing_samples) + len(legitimate_samples), max_samples_per_class * 2)
        target_phishing = min(int(total_samples * target_ratio), max_samples_per_class)
        target_legitimate = min(total_samples - target_phishing, max_samples_per_class)
        
        # Sample from each class
        if len(phishing_samples) > target_phishing:
            phishing_samples = phishing_samples.sample(n=target_phishing, random_state=42)
        
        if len(legitimate_samples) > target_legitimate:
            legitimate_samples = legitimate_samples.sample(n=target_legitimate, random_state=42)
        
        # Combine and shuffle
        balanced_df = pd.concat([phishing_samples, legitimate_samples], ignore_index=True)
        balanced_df = balanced_df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        logger.info(f"After balancing:")
        logger.info(f"  Phishing samples: {(balanced_df['label'] == 1).sum():,}")
        logger.info(f"  Legitimate samples: {(balanced_df['label'] == 0).sum():,}")
        logger.info(f"  Total samples: {len(balanced_df):,}")
        logger.info(f"  Balance ratio: {(balanced_df['label'] == 1).mean():.3f}")
        
        return balanced_df
    
    def add_dataset_metadata(self, df):
        """Add metadata to the dataset."""
        df['processing_date'] = datetime.now().isoformat()
        df['dataset_version'] = '3.0_professional'
        
        # Add feature counts
        boolean_features = df.select_dtypes(include=['bool']).columns
        df['feature_count'] = len(boolean_features)
        
        return df
    
    def generate_dataset_report(self, df):
        """Generate comprehensive dataset report."""
        report = {
            'total_samples': len(df),
            'phishing_samples': (df['label'] == 1).sum(),
            'legitimate_samples': (df['label'] == 0).sum(),
            'balance_ratio': (df['label'] == 1).mean(),
            'sources': df['source'].value_counts().to_dict() if 'source' in df.columns else {},
            'url_length_stats': df['url'].str.len().describe().to_dict(),
            'domain_length_stats': df['domain'].str.len().describe().to_dict(),
            'feature_counts': {}
        }
        
        # Feature analysis
        boolean_features = df.select_dtypes(include=['bool']).columns
        for feature in boolean_features:
            report['feature_counts'][feature] = {
                'total_true': df[feature].sum(),
                'percentage': (df[feature].sum() / len(df)) * 100
            }
        
        # Quality statistics
        if hasattr(self, 'quality_stats'):
            report['quality_stats'] = self.quality_stats
        
        return report
    
    def process_complete_dataset(self):
        """Complete dataset processing pipeline."""
        logger.info("Starting complete dataset processing pipeline...")
        
        # Load datasets
        professional_df = self.load_professional_dataset()
        synthetic_df = self.load_synthetic_dataset()
        
        # Combine datasets
        all_dfs = []
        if len(professional_df) > 0:
            all_dfs.append(professional_df)
        if len(synthetic_df) > 0:
            all_dfs.append(synthetic_df)
        
        if not all_dfs:
            logger.error("No datasets found to process")
            return None
        
        combined_df = pd.concat(all_dfs, ignore_index=True, sort=False)
        logger.info(f"Combined {len(combined_df)} samples from {len(all_dfs)} sources")
        
        # Process pipeline
        validated_df = self.validate_url_quality(combined_df)
        enhanced_df = self.enhance_url_features(validated_df)
        balanced_df = self.balance_dataset(enhanced_df)
        final_df = self.add_dataset_metadata(balanced_df)
        
        # Generate report
        report = self.generate_dataset_report(final_df)
        
        logger.info("Dataset processing pipeline complete!")
        return final_df, report
    
    def save_processed_dataset(self, df, report, filename="processed_phishing_dataset.csv"):
        """Save the processed dataset and report."""
        # Save dataset
        dataset_path = os.path.join(self.data_dir, filename)
        df.to_csv(dataset_path, index=False)
        logger.info(f"Processed dataset saved: {dataset_path}")
        
        # Save report
        report_path = os.path.join(self.data_dir, filename.replace('.csv', '_report.json'))
        import json
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        logger.info(f"Dataset report saved: {report_path}")
        
        return dataset_path, report_path


def main():
    """Main function to process datasets."""
    data_dir = os.path.dirname(os.path.abspath(__file__))
    preprocessor = DatasetPreprocessor(data_dir)
    
    # Process complete dataset
    result = preprocessor.process_complete_dataset()
    
    if result:
        processed_df, report = result
        
        # Save processed dataset
        dataset_path, report_path = preprocessor.save_processed_dataset(
            processed_df, report, "enhanced_phishing_dataset.csv"
        )
        
        print("\n" + "="*80)
        print("DATASET PREPROCESSING COMPLETE")
        print("="*80)
        print(f"Processed dataset: {dataset_path}")
        print(f"Dataset report: {report_path}")
        print(f"Total samples: {report['total_samples']:,}")
        print(f"Phishing samples: {report['phishing_samples']:,}")
        print(f"Legitimate samples: {report['legitimate_samples']:,}")
        print(f"Balance ratio: {report['balance_ratio']:.3f}")
        if 'sources' in report and report['sources']:
            print(f"Data sources: {', '.join(report['sources'].keys())}")
        print("="*80)
        
        # Show feature summary
        print("\nEnhanced Features:")
        feature_counts = report.get('feature_counts', {})
        for feature, stats in list(feature_counts.items())[:10]:  # Show top 10
            print(f"  {feature}: {stats['percentage']:.1f}% positive")
        
        if len(feature_counts) > 10:
            print(f"  ... and {len(feature_counts) - 10} more features")
        
        return processed_df, report
    else:
        print("Failed to process datasets")
        return None, None


if __name__ == "__main__":
    main()