"""
PhishGuard AI – One-Click Setup Script
Run this script to:
  1. Generate the dataset
  2. Train the ML models
  3. Verify the model was saved

Usage:
    cd phishguard-ai/backend
    python setup.py
"""

import os
import sys

print("=" * 60)
print(" PhishGuard AI – Setup & Training")
print("=" * 60)

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BACKEND_DIR)

# Step 1: Generate dataset
print("\n[Step 1/2] Generating dataset...")
data_dir = os.path.join(BACKEND_DIR, "data")
dataset_path = os.path.join(data_dir, "phishing_dataset.csv")
gen_script = os.path.join(data_dir, "generate_dataset.py")

if not os.path.exists(dataset_path):
    exec(open(gen_script).read())
    print(f"  ✓ Dataset generated: {dataset_path}")
else:
    import pandas as pd
    df = pd.read_csv(dataset_path)
    print(f"  ✓ Dataset already exists ({len(df)} rows). Skipping generation.")

# Step 2: Train models
print("\n[Step 2/2] Training ML models...")
train_script = os.path.join(BACKEND_DIR, "model", "train_model.py")
exec(open(train_script).read())

# Step 3: Verify
model_path = os.path.join(BACKEND_DIR, "model", "phishing_model.pkl")
metrics_path = os.path.join(BACKEND_DIR, "model", "model_metrics.json")

print("\n" + "=" * 60)
print(" Setup Complete!")
print("=" * 60)

if os.path.exists(model_path):
    print(f"  ✓ Model saved    : {model_path}")
else:
    print(f"  ✗ Model NOT found: {model_path}")

if os.path.exists(metrics_path):
    import json
    with open(metrics_path) as f:
        m = json.load(f)
    print(f"  ✓ Metrics saved  : {metrics_path}")
    print(f"  ✓ Best model     : {m.get('best_model', 'Unknown')}")
else:
    print(f"  ✗ Metrics NOT found: {metrics_path}")

print("\n Next steps:")
print("  1. Start backend : uvicorn app:app --reload --port 8000")
print("  2. cd ../frontend")
print("  3. npm install")
print("  4. npm run dev")
print("  5. Open          : http://localhost:5173")
