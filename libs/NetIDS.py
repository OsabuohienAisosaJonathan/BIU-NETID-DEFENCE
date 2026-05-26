import os
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
from sklearn.ensemble import RandomForestClassifier
from sklearn.multioutput import MultiOutputClassifier
from sklearn.decomposition import PCA
from sklearn.preprocessing import LabelEncoder
from sklearn.utils import resample

class NetIDS:
    def __init__(self, model_path="models/netids_model.pkl"): 
        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.pca = None

    def load_datasets(self, dataset_dir):        
        # Load datasets
        df_ransomware = pd.read_csv(os.path.join(dataset_dir, 'Ransomware_attack.csv'), low_memory=False)
        df_ddos = pd.read_csv(os.path.join(dataset_dir, 'DDoS_HTTP_Flood_attack.csv'), low_memory=False)
        df_mitm = pd.read_csv(os.path.join(dataset_dir, 'MITM_attack.csv'), low_memory=False)
        df_normal = pd.read_csv(os.path.join(dataset_dir, 'Normal.csv'), low_memory=False)
        
        # Determine the target size (for simplicity, choose the size of the smallest class)
        target_size = min(len(df_ddos), len(df_mitm), len(df_ransomware), len(df_normal))

        # Downsample the majority class (DDoS) to match the target size
        ddos_balanced = resample(df_ddos, replace=False, n_samples=target_size, random_state=42)

        # Upsample the minority classes (MITM, Ransomware, Normal)
        mitm_balanced = resample(df_mitm, replace=True, n_samples=target_size, random_state=42)
        ransomware_balanced = resample(df_ransomware, replace=True, n_samples=target_size, random_state=42)
        normal_balanced = resample(df_normal, replace=True, n_samples=target_size, random_state=42)
        
        print('[INFO] ddos_balanced size:', len(ddos_balanced))
        print('[INFO] mitm_balanced size:', len(mitm_balanced))
        print('[INFO] ransomware_balanced size:', len(ransomware_balanced))
        print('[INFO] normal_balanced size:', len(normal_balanced)) 

        # Combine all balanced datasets
        data = pd.concat([ddos_balanced, mitm_balanced, ransomware_balanced, normal_balanced])

        # Shuffle the dataset
        data = data.sample(frac=1, random_state=42).reset_index(drop=True)
        data = data.reset_index(drop=True)  
        data = self.clean_dataset(data)
        return data
           
            
    def clean_dataset(self, data):        
        # 1. Strip spaces from column names
        data.columns = data.columns.str.strip()

        # 2. Strip spaces from string values
        for col in data.select_dtypes(include=["object"]):
            data[col] = data[col].astype(str).str.strip()

        # 3. Replace hex strings like "0x00009184" with integers
        def hex_to_int(val):
            try:
                if isinstance(val, str) and val.startswith("0x"):
                    return int(val, 16)
                return float(val) if val not in ["", "nan", "None"] else np.nan
            except:
                return np.nan

        for col in data.columns:
            # Only try conversion if column is not label
            if col not in ["Attack_label", "Attack_type"]:
                data[col] = data[col].apply(hex_to_int)

        if all(col in data.columns for col in ["Attack_label", "Attack_type"]):
            # 4. Convert label column to int
            data["Attack_label"] = pd.to_numeric(data["Attack_label"], errors="coerce").astype("Int64")

            # 5. Drop rows with missing labels
            data = data.dropna(subset=["Attack_label", "Attack_type"])

            # 6. Fill remaining NaN in features with 0
            feature_cols = [c for c in data.columns if c not in ["Attack_label", "Attack_type"]]
            data[feature_cols] = data[feature_cols].fillna(0)

        print(f"[INFO] Cleaned dataset: {data.shape[0]} rows, {data.shape[1]} columns")
        
        # Create label encoders for each column
        le_attack_type = LabelEncoder()
        data["Attack_type"] = le_attack_type.fit_transform(data["Attack_type"])
        joblib.dump(le_attack_type, "models/attack_type_encoder.pkl")
        
        le_attack_label = LabelEncoder()
        data["Attack_label"] = le_attack_label.fit_transform(data["Attack_label"]) 
        joblib.dump(le_attack_label, "models/attack_label_encoder.pkl")
        
        data.to_csv("datasets/processed.csv", index=False)

        return data


    def preprocess(self, data, fit=True):
        """
        Preprocess dataset: handle missing values, scale, PCA.
        """
        data = data.dropna()

        # Separate features and targets
        X = data.drop(columns=["Attack_label", "Attack_type"])
        y = data[["Attack_label", "Attack_type"]]

        # Scale
        if fit:
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
        else:
            X_scaled = self.scaler.transform(X)

        # PCA for feature-based transfer learning
        if fit:
            self.pca = PCA(n_components=0.95)  # keep 95% variance
            X_pca = self.pca.fit_transform(X_scaled)
        else:
            X_pca = self.pca.transform(X_scaled)

        return X_pca, y
 

    def train(self, dataset_dir='datasets'):
        """
        Train model on combined datasets.
        """
        data = self.load_datasets(dataset_dir)
        print('data:',data)
        X, y = self.preprocess(data, fit=True)

        # Train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )

        # Multioutput classifier (Attack_label + Attack_type)
        base_model = RandomForestClassifier(n_estimators=200, random_state=42)
        model = MultiOutputClassifier(base_model)
        model.fit(X_train, y_train)

        self.model = model

        # Save artifacts
        self.save_model()

        # Evaluation
        y_pred = model.predict(X_test)
        print("=== Attack_label classification ===")
        print(classification_report(y_test.iloc[:, 0], y_pred[:, 0]))
        print("=== Attack_type classification ===")
        print(classification_report(y_test.iloc[:, 1], y_pred[:, 1]))

    def predict(self, X_new):
        """
        Predict Attack_label and Attack_type for new samples.
        """
        if self.model is None:
            self.load_model()

        X_scaled = self.scaler.transform(X_new)
        X_pca = self.pca.transform(X_scaled)

        preds = self.model.predict(X_pca)
        return preds

    def save_model(self):
        """Save model, scaler, and PCA."""
        joblib.dump({
            "model": self.model,
            "scaler": self.scaler,
            "pca": self.pca
        }, self.model_path)
        print(f"[INFO] Model saved to {self.model_path}")

    def load_model(self):
        """Load model, scaler, and PCA."""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Model file not found: {self.model_path}")
        data = joblib.load(self.model_path)
        self.model = data["model"]
        self.scaler = data["scaler"]
        self.pca = data["pca"]
        print(f"[INFO] Model loaded from {self.model_path}")


if __name__ == "__main__":
    # Example usage 
    netIds = NetIDS()
    netIds.train(dataset_dir='../datasets')
