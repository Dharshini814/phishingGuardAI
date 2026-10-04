"""
PhishGuard AI – Enhanced Training Dataset Generator (v3.0)

This version integrates professional datasets with synthetic patterns:
1. PhishTank verified phishing URLs
2. LegitPhish dataset (101,219 labeled URLs)
3. Zenodo Phishing dataset (60,000+ URLs)
4. EdgePhish-5G dataset (340,000+ URLs)
5. Enhanced synthetic patterns based on research

Features:
- Balanced dataset generation
- Quality validation and deduplication
- Enhanced feature extraction (31 features)
- Professional dataset integration
- Comprehensive data preprocessing
"""

import pandas as pd
import os
import sys
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add parent dir to path so modules are importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import our modules
from data.professional_datasets import ProfessionalDatasetDownloader
from data.dataset_preprocessing import DatasetPreprocessor
from services.enhanced_feature_extraction import extract_enhanced_features, ENHANCED_FEATURE_NAMES


class EnhancedDatasetGenerator:
    """Generate enhanced phishing detection dataset with professional data integration."""
    
    def __init__(self, data_dir="./", use_professional_data=True):
        self.data_dir = data_dir
        self.use_professional_data = use_professional_data
        self.downloader = ProfessionalDatasetDownloader(data_dir)
        self.preprocessor = DatasetPreprocessor(data_dir)
        
    def generate_complete_dataset(self, max_samples=50000, target_balance=0.5):
        """
        Generate complete enhanced dataset combining professional and synthetic sources.
        
        Args:
            max_samples: Maximum total samples to include
            target_balance: Target ratio of phishing samples (0.5 = 50/50 split)
        
        Returns:
            pd.DataFrame: Enhanced dataset with extracted features
        """
        logger.info("Starting enhanced dataset generation...")
        logger.info(f"Target samples: {max_samples:,}, Target balance: {target_balance}")
        
        all_samples = []
        
        # 1. Download professional datasets
        if self.use_professional_data:
            logger.info("Downloading professional datasets...")
            try:
                professional_df = self.downloader.download_all_datasets()
                if len(professional_df) > 0:
                    all_samples.append(professional_df)
                    logger.info(f"Added {len(professional_df):,} professional samples")
                else:
                    logger.warning("No professional data downloaded, using synthetic only")
            except Exception as e:
                logger.error(f"Failed to download professional data: {e}")
                logger.info("Continuing with synthetic data only")
        
        # 2. Load existing synthetic dataset if available
        try:
            synthetic_df = self.preprocessor.load_synthetic_dataset()
            if len(synthetic_df) > 0:
                all_samples.append(synthetic_df)
                logger.info(f"Added {len(synthetic_df):,} synthetic samples")
        except Exception as e:
            logger.warning(f"Could not load synthetic dataset: {e}")
        
        # 3. Generate additional synthetic samples if needed
        if not all_samples:
            logger.info("No existing datasets found, generating synthetic samples...")
            synthetic_df = self._generate_synthetic_samples(max_samples // 2)
            all_samples.append(synthetic_df)
        
        # 4. Combine all datasets
        if all_samples:
            combined_df = pd.concat(all_samples, ignore_index=True, sort=False)
            logger.info(f"Combined {len(combined_df):,} total samples")
        else:
            logger.error("No data sources available")
            return pd.DataFrame()
        
        # 5. Preprocess and clean data
        logger.info("Preprocessing combined dataset...")
        validated_df = self.preprocessor.validate_url_quality(combined_df)
        
        # 6. Balance the dataset
        balanced_df = self.preprocessor.balance_dataset(
            validated_df, target_ratio=target_balance, max_samples_per_class=max_samples//2
        )
        
        # 7. Extract enhanced features for all URLs
        logger.info("Extracting enhanced features...")
        enhanced_df = self._extract_features_for_dataset(balanced_df)
        
        # 8. Add metadata
        enhanced_df['generation_date'] = datetime.now().isoformat()
        enhanced_df['dataset_version'] = '3.0_enhanced'
        enhanced_df['feature_count'] = len(ENHANCED_FEATURE_NAMES)
        
        logger.info("Enhanced dataset generation complete!")
        logger.info(f"Final dataset: {len(enhanced_df):,} samples with {len(ENHANCED_FEATURE_NAMES)} features")
        
        return enhanced_df
    
    def _generate_synthetic_samples(self, target_count):
        """Generate synthetic samples as fallback."""
        logger.info(f"Generating {target_count:,} synthetic samples...")
        
        # Enhanced synthetic legitimate URLs
        legitimate_urls = self._generate_legitimate_urls(target_count // 2)
        
        # Enhanced synthetic phishing URLs  
        phishing_urls = self._generate_phishing_urls(target_count // 2)
        
        # Combine
        all_urls = legitimate_urls + phishing_urls
        
        df = pd.DataFrame(all_urls)
        df['source'] = 'Synthetic_Enhanced'
        
        logger.info(f"Generated {len(df):,} synthetic samples")
        return df
    
    def _generate_legitimate_urls(self, count):
        """Generate enhanced legitimate URL samples."""
        import random
        
        legitimate_samples = []
        
        # Enterprise and professional services
        enterprise_domains = [
            'portal.enterprise.com', 'workspace.company.org', 'dashboard.business.net',
            'intranet.corporation.com', 'app.platform.io', 'console.service.net',
            'admin.system.org', 'management.solution.com', 'hub.technology.net'
        ]
        
        # Educational institutions
        edu_domains = [
            'portal.university.edu', 'canvas.college.edu', 'blackboard.institute.edu',
            'library.academy.edu', 'research.school.edu', 'online.education.org'
        ]
        
        # Government and public services
        gov_domains = [
            'services.gov.us', 'portal.state.gov', 'benefits.federal.gov',
            'taxes.revenue.gov', 'permits.city.gov', 'records.county.gov'
        ]
        
        # Healthcare and medical
        health_domains = [
            'patient.hospital.org', 'portal.clinic.com', 'records.medical.net',
            'appointment.healthcare.org', 'billing.medicine.com'
        ]
        
        all_legit_domains = enterprise_domains + edu_domains + gov_domains + health_domains
        
        paths = [
            '/dashboard', '/login', '/portal', '/app', '/console', '/admin',
            '/profile', '/settings', '/account', '/home', '/workspace'
        ]
        
        for i in range(count):
            domain = random.choice(all_legit_domains)
            path = random.choice(paths)
            url = f"https://{domain}{path}"
            
            legitimate_samples.append({
                'url': url,
                'label': 0,  # Legitimate
                'category': 'Enhanced_Synthetic_Legitimate'
            })
        
        return legitimate_samples
    
    def _generate_phishing_urls(self, count):
        """Generate enhanced phishing URL samples based on professional patterns."""
        import random
        
        phishing_samples = []
        
        # Advanced phishing domain patterns
        phishing_patterns = [
            # Subdomain abuse
            'secure.{service}.verify.{malicious_tld}',
            'login.{service}.account.{malicious_tld}',
            'update.{service}.security.{malicious_tld}',
            
            # Service impersonation
            '{service}-security.{malicious_tld}',
            '{service}-verify.{malicious_tld}',
            '{service}-account.{malicious_tld}',
            
            # Typosquatting with missing/changed characters
            '{typo_service}.com',
            '{service}.{fake_tld}',
        ]
        
        services = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'netflix', 'dropbox']
        malicious_tlds = ['phish.ru', 'scam.tk', 'fake.ml', 'suspicious.gq', 'malware.cf']
        fake_tlds = ['corn', 'net.phish.xyz', 'co.fake.ru']
        
        # Typosquatting variants
        typo_services = {
            'paypal': ['payp4l', 'paypaI', 'paypaℓ'],  # Number/letter/unicode substitution
            'amazon': ['arnazon', 'amazon', 'amazοn'],  # Missing/changed/unicode chars
            'google': ['gοοgle', 'googIe', 'g00gle'],   # Unicode/number/letter substitution
            'microsoft': ['microsοft', 'microsooft', 'micr0soft'],
            'apple': ['appIe', 'apple', 'аpple']  # Cyrillic/unicode substitution
        }
        
        phishing_paths = [
            '/login.php?redirect={service}.com&session=abc123',
            '/verify.html?user=victim&token=xyz456',
            '/update-account.asp?service={service}&auth=required',
            '/security-check.jsp?account=suspended&verify=now',
            '/signin?email=victim@gmail.com&next=dashboard'
        ]
        
        for i in range(count):
            service = random.choice(services)
            pattern = random.choice(phishing_patterns)
            
            # Generate domain
            if '{typo_service}' in pattern:
                typo_service = random.choice(typo_services.get(service, [service + '1']))
                domain = pattern.format(typo_service=typo_service, service=service)
            else:
                malicious_tld = random.choice(malicious_tlds)
                fake_tld = random.choice(fake_tlds)
                domain = pattern.format(
                    service=service, 
                    malicious_tld=malicious_tld,
                    fake_tld=fake_tld
                )
            
            # Add path
            path = random.choice(phishing_paths).format(service=service)
            
            # Construct URL
            scheme = random.choice(['http', 'https'])  # Phishing often uses http
            url = f"{scheme}://{domain}{path}"
            
            phishing_samples.append({
                'url': url,
                'label': 1,  # Phishing
                'category': 'Enhanced_Synthetic_Phishing'
            })
        
        return phishing_samples
    
    def _extract_features_for_dataset(self, df):
        """Extract enhanced features for all URLs in dataset."""
        logger.info(f"Extracting enhanced features for {len(df):,} URLs...")
        
        # Extract features for each URL
        feature_data = []
        for idx, row in df.iterrows():
            if idx % 1000 == 0:
                logger.info(f"Processing URL {idx + 1:,}/{len(df):,}")
            
            try:
                url = row['url']
                features = extract_enhanced_features(url)
                
                # Combine original row data with features
                combined_row = row.to_dict()
                combined_row.update(features)
                feature_data.append(combined_row)
                
            except Exception as e:
                logger.warning(f"Failed to extract features for URL {idx}: {e}")
                continue
        
        feature_df = pd.DataFrame(feature_data)
        logger.info(f"Successfully extracted features for {len(feature_df):,} URLs")
        
        return feature_df
    
    def save_enhanced_dataset(self, df, filename="enhanced_training_dataset.csv"):
        """Save the enhanced dataset."""
        output_path = os.path.join(self.data_dir, filename)
        df.to_csv(output_path, index=False)
        logger.info(f"Enhanced dataset saved: {output_path}")
        
        # Save feature-only dataset for ML training
        feature_columns = ['url', 'label'] + ENHANCED_FEATURE_NAMES
        available_columns = [col for col in feature_columns if col in df.columns]
        
        ml_df = df[available_columns].copy()
        ml_output_path = os.path.join(self.data_dir, filename.replace('.csv', '_ml_ready.csv'))
        ml_df.to_csv(ml_output_path, index=False)
        logger.info(f"ML-ready dataset saved: {ml_output_path}")
        
        return output_path, ml_output_path


def main():
    """Main function to generate enhanced dataset."""
    data_dir = os.path.dirname(os.path.abspath(__file__))
    generator = EnhancedDatasetGenerator(data_dir, use_professional_data=True)
    
    # Generate enhanced dataset
    enhanced_df = generator.generate_complete_dataset(max_samples=50000, target_balance=0.5)
    
    if len(enhanced_df) > 0:
        # Save enhanced dataset
        dataset_path, ml_path = generator.save_enhanced_dataset(enhanced_df)
        
        print("\n" + "="*80)
        print("ENHANCED DATASET GENERATION COMPLETE")
        print("="*80)
        print(f"Enhanced dataset: {dataset_path}")
        print(f"ML-ready dataset: {ml_path}")
        print(f"Total samples: {len(enhanced_df):,}")
        print(f"Phishing samples: {(enhanced_df['label'] == 1).sum():,}")
        print(f"Legitimate samples: {(enhanced_df['label'] == 0).sum():,}")
        print(f"Balance ratio: {(enhanced_df['label'] == 1).mean():.3f}")
        print(f"Features extracted: {len(ENHANCED_FEATURE_NAMES)}")
        
        # Show data sources
        if 'source' in enhanced_df.columns:
            print(f"Data sources: {', '.join(enhanced_df['source'].unique())}")
        
        print("="*80)
        
        # Show sample features
        print("\nEnhanced Features (first 10):")
        for i, feature in enumerate(ENHANCED_FEATURE_NAMES[:10]):
            if feature in enhanced_df.columns:
                avg_val = enhanced_df[feature].mean()
                print(f"  {i+1:2d}. {feature}: avg={avg_val:.3f}")
        
        if len(ENHANCED_FEATURE_NAMES) > 10:
            print(f"     ... and {len(ENHANCED_FEATURE_NAMES) - 10} more features")
        
        return enhanced_df
    else:
        print("Failed to generate enhanced dataset")
        return None


if __name__ == "__main__":
    main()