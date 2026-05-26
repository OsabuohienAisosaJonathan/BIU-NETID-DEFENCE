import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler 
from sklearn.preprocessing import LabelEncoder
import os
from libs.NetIDS import NetIDS
import seaborn as sns

import matplotlib
matplotlib.use("Agg")  # Use non-GUI backend
import matplotlib.pyplot as plt

class NetIDSFeatureNBased:
    
    def __init__(self, pretrained_model_path=None, preprocessed_dataset_location="datasets/processed.csv"):
        self.preprocessed_dataset_location = preprocessed_dataset_location
        self.feature_columns = None
        if pretrained_model_path and os.path.exists(pretrained_model_path):
            self.load_model(pretrained_model_path)
        else:
            self.rf_pretrained = RandomForestClassifier(n_estimators=100, random_state=42)
            # Classifiers for transfer learning
            self.label_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
            self.type_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
            
            
    def load_datasets(self):
        """
        Load one or more CSV datasets, combine them, shuffle, and save to processed.csv.
        """
        if os.path.exists(self.preprocessed_dataset_location): 
            data = pd.read_csv(self.preprocessed_dataset_location, low_memory=False)
        else: 
            netids = NetIDS() 
            data = netids.load_datasets(dataset_dir='datasets')  
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
        # Create and fit LabelEncoder
        le = LabelEncoder()
        data["Attack_type"] = le.fit_transform(data["Attack_type"])
        
        # Save the label encoder
        joblib.dump(le, "models/attack_type_label_encoder.pkl")
        
        data.to_csv(self.preprocessed_dataset_location, index=False)

        return data

 
    def extract_features(self, X):
        """
        Extracts high-level features from the pretrained RandomForest
        using the leaf indices as transformed features.
        """
        return self.rf_pretrained.apply(X)


    def train(self, df, feature_cols, label_col, type_col):
        try:
            # Prepare features
            self.feature_columns = feature_cols
            X = df[feature_cols].apply(pd.to_numeric, errors='coerce').fillna(0)
            y_label = pd.to_numeric(df[label_col], errors='coerce')
            y_type = df[type_col].astype(str).fillna("Unknown")
             
            self.rf_pretrained.fit(X, y_label) 
            
            # Extract features 
            X_transformed = self.extract_features(X)  

            # Remove rows with NaNs in labels/types
            mask = (~y_label.isna()) & (~y_type.isna())             
            
            # Train transfer classifiers
            print("[INFO] Training transfer classifiers...")
            self.label_classifier.fit(X_transformed[mask], y_label[mask]) 
            self.type_classifier.fit(X_transformed[mask], y_type[mask])  
             
            print("[INFO] Training complete.")
            return True
        except Exception as ex:
            print("[ERROR] Training error:", str(ex))
            return False

    def predict(self, df, feature_cols):
        try:
            """
            Predict Attack_label and Attack_type using transfer learning.
            """
            print('predict(self, df, feature_cols)->feature_cols:', feature_cols)
            print('1')
            
            X = df[feature_cols] 
            print('2')
            X_transformed = self.extract_features(X)
            
            print('predict(self, df, feature_cols)->X:', X)

            # Predict label
            pred_label = self.label_classifier.predict(X_transformed)
            print('pred_label:', pred_label)
            attack_label_encoder = joblib.load("models/attack_label_encoder.pkl")
            decoded_pred_label = attack_label_encoder.inverse_transform(pred_label)

            # Predict attack type
            pred_type = self.type_classifier.predict(X_transformed)
            pred_type = pred_type.astype(int)
            print('pred_type:', pred_type)
            attack_type_encoder = joblib.load("models/attack_type_encoder.pkl")
            decoded_pred_type = attack_type_encoder.inverse_transform(pred_type) 
            
            return decoded_pred_label, decoded_pred_type
        except Exception as ex:
            print('[ERROR] NetIDSFeatureNBased predict: ', str(ex))
            return [0], ['']

    def predict0(self, df, feature_cols):
        result = self.predict(df, feature_cols)
        decoded_pred_label, decoded_pred_type = result
        return decoded_pred_label[0], decoded_pred_type[0]
        
        
        
    def evaluate(self, df, feature_cols, label_col, type_col):
        try:
            """
            Evaluate both label and type prediction performance.
            """
            y_label_true = df[label_col]
            y_type_true = df[type_col]
            pred_label, pred_type = self.predict(df, feature_cols)
            
            attack_type_encoder = joblib.load("models/attack_type_encoder.pkl") 
            pred_type_int = attack_type_encoder.transform(np.array(pred_type).reshape(-1))
            
            print('y_type_true: ', y_type_true)
            print('pred_type_int: ', pred_type_int)
            
            report_dict = classification_report(y_type_true, pred_type_int, output_dict=True)
            accuracy = report_dict["accuracy"]  # float value
            accuracy_percent = f"{accuracy*100:.2f}%"       
            
            self.plot_classification(report_dict)
            self.plot_report(y_type_true, pred_type_int)
            
            print("[INFO] Attack Type Prediction Report")
            class_report = classification_report(y_type_true, pred_type_int) 
            
            
            print("y_type_true:", y_type_true)
            print("pred_type:", pred_type)
            print("pred_type_int:", pred_type_int)
            print("Accuracy:", accuracy_percent)
            print("Class report:", class_report)
            
            return class_report, accuracy_percent
        except Exception as ex:
            print('[ERROR] NetIDSFeatureNBased evalution: ', str(ex))
            return "", "0%"
            
            
    def plot_classification(self, classification_report_dict):
        try:
            # Convert dict to DataFrame
            df_report = pd.DataFrame(classification_report_dict).transpose().reset_index()
            df_report = df_report.rename(columns={'index': 'class'})

            # Keep only numeric metric rows (drop averages & accuracy row)
            df_report = df_report[df_report['class'].isin(['0', '1', '2', '3'])]

            # Plot
            fig, ax = plt.subplots(figsize=(8, 6))
            df_report.plot(x="class", y=["precision", "recall", "f1-score"], kind="bar", ax=ax)

            plt.title("Classification Report Metrics by Class")
            plt.ylabel("Score")
            plt.ylim(0, 1.1)
            plt.grid(axis="y", linestyle="--", alpha=0.7)
            plt.xticks(rotation=0)
            plt.legend(title="Metrics")
            plt.tight_layout()
            plt.savefig('plots/classification_report.png')
            plt.close()
            print("[INFO] Classification report plot saved.")
        except Exception as ex:
            print('[DEBUG] plot_classification:', str(ex))
            

    def plot_report(self, y_true, y_pred, encoder_path="models/attack_type_encoder.pkl"):
        try:
            # Load the encoder
            attack_type_encoder = joblib.load(encoder_path)
            
            # Get original class names from encoder
            class_labels = attack_type_encoder.classes_  # This will be in the same order as the encoded values
            
            # Classification report as dict
            report_dict = classification_report(y_true, y_pred, target_names=class_labels, output_dict=True)
            
            # Accuracy
            accuracy = report_dict['accuracy']
            print(f"\nModel Accuracy: {accuracy:.4f}")
            
            # Pretty printed classification report
            print("\nClassification Report:")
            print(classification_report(y_true, y_pred, target_names=class_labels))
            
            # Confusion matrix
            cm = confusion_matrix(y_true, y_pred)
            
            # Plot confusion matrix
            plt.figure(figsize=(6, 5))
            sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
                        xticklabels=class_labels,
                        yticklabels=class_labels)
            plt.xlabel("Predicted Label")
            plt.ylabel("True Label")
            plt.title(f"Confusion Matrix\nAccuracy: {accuracy:.2%}")
            plt.tight_layout()
            plt.savefig('plots/confusion.png')
            plt.close()
        except Exception as ex:
            print('[DEBUG] plot_report:', str(ex))
            
        
    def save_model(self, path, feature_columns):
        joblib.dump({
            'rf_pretrained': self.rf_pretrained,
            'label_classifier': self.label_classifier,
            'type_classifier': self.type_classifier,
            'feature_columns': feature_columns  # Save order!
        }, path)

    def load_model(self, path):
        """
        Load pretrained RF and transfer classifiers (compatible with old/new saves).
        """
        data = joblib.load(path)

        print('[INFO] load_model ,data :', data)
         
        self.rf_pretrained = data['rf_pretrained']
        self.label_classifier = data['label_classifier']
        self.type_classifier = data['type_classifier']
        self.feature_columns = data['feature_columns']
            
        print('[M O D E L S]')
        print('[INFO] self.rf_pretrained:', self.rf_pretrained)
        print('[INFO] self.type_classifier:', self.type_classifier)
        print('[INFO] self.type_classifier:', self.type_classifier) 
        print('[INFO] self.feature_columns:', self.feature_columns) 
        
        print(f"[INFO] Model loaded from {path}")
        
        

if __name__ == "__main__":
    
    # Initialize (train RF from scratch)
    netids = NetIDSFeatureNBased(preprocessed_dataset_location="datasets/processed.csv")
     
    df = netids.load_datasets()
    
    feature_cols = [col for col in df.columns if col not in ["Attack_label", "Attack_type"]]
    label_col = "Attack_label"
    type_col = "Attack_type"


    # Train
    netids.train(df, feature_cols, label_col, type_col)

    # Evaluate
    netids.evaluate(df, feature_cols, label_col, type_col)
