#!/usr/bin/env python3

import requests
import json

def test_api():
    """Test the PhishGuard AI API with our fixed model."""
    
    base_url = "http://localhost:8000"
    
    # Test cases
    test_cases = [
        {
            "url": "https://onlinesbi.sbi.co.in/", 
            "description": "Legitimate SBI banking",
            "expected": "LEGITIMATE"
        },
        {
            "url": "https://onlinessbi.sbi.bank.in/", 
            "description": "SBI typosquatting (missing 'e')",
            "expected": "PHISHING"
        },
        {
            "url": "https://www.paypal.com/", 
            "description": "Legitimate PayPal",
            "expected": "LEGITIMATE"
        },
        {
            "url": "https://payp4l.com/", 
            "description": "PayPal character substitution",
            "expected": "PHISHING"
        }
    ]
    
    print("="*60)
    print("PHISHGUARD AI API TEST")
    print("="*60)
    
    # Test health endpoint
    try:
        health_response = requests.get(f"{base_url}/api/health")
        if health_response.status_code == 200:
            print("✅ Server health: OK")
        else:
            print(f"❌ Server health failed: {health_response.status_code}")
            return
    except Exception as e:
        print(f"❌ Cannot connect to server: {e}")
        return
    
    print()
    
    # Test prediction endpoint
    correct_predictions = 0
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"{i}. Testing: {test_case['description']}")
        print(f"   URL: {test_case['url']}")
        
        try:
            payload = {"url": test_case['url']}
            response = requests.post(
                f"{base_url}/api/predict", 
                headers={"Content-Type": "application/json"},
                json=payload
            )
            
            if response.status_code == 200:
                result = response.json()
                prediction = result.get('prediction', 'UNKNOWN')
                confidence = result.get('confidence', 0)
                risk_level = result.get('risk_level', 'UNKNOWN')
                
                is_correct = prediction == test_case['expected']
                if is_correct:
                    correct_predictions += 1
                
                status = "✅" if is_correct else "❌"
                print(f"   {status} Result: {prediction} ({confidence:.3f} confidence, {risk_level} risk)")
                
                # Show warnings if any
                warnings = result.get('warnings', [])
                if warnings:
                    print(f"   Warnings: {len(warnings)} detected")
                
            else:
                print(f"   ❌ API Error: {response.status_code}")
                print(f"   Response: {response.text}")
        
        except Exception as e:
            print(f"   ❌ Request failed: {e}")
        
        print()
    
    accuracy = correct_predictions / len(test_cases)
    print(f"Overall API Test Accuracy: {accuracy:.1%} ({correct_predictions}/{len(test_cases)})")
    
    if accuracy >= 0.75:
        print("🎉 API is working correctly with the enhanced model!")
    else:
        print("⚠️  API may need further adjustments")


if __name__ == "__main__":
    test_api()