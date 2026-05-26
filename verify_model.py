import sys
import os
import joblib
import pandas as pd
from libs.NetIDSFeatureNBased import NetIDSFeatureNBased

print("Starting model verification...")

try:
    netids_model = NetIDSFeatureNBased(preprocessed_dataset_location="")
    print("NetIDSFeatureNBased initialized successfully.")
    
    # Try loading the model file directly to see if it's valid
    model_path = "models/netids_model.pkl"
    if os.path.exists(model_path):
        print(f"Loading {model_path}...")
        data = joblib.load(model_path)
        print("Model loaded successfully.")
    else:
        print(f"Model file {model_path} not found.")

except Exception as e:
    print(f"Error during verification: {e}")
    import traceback
    traceback.print_exc()

print("Verification complete.")
