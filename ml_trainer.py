import numpy as np
import json
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import proteus
from typing import List, Dict, Tuple

class ProteusMLTrainer:
    def __init__(self):
        self.rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        self.isolation_model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_jobs=-1
        )
        
    def extract_features(self, file_path: str) -> np.ndarray:
        try:
            analysis = proteus.analyze_file(file_path)
            strings = proteus.extract_strings_from_file(file_path)
            
            features = [
                analysis.entropy,
                analysis.threat_score,
                len(analysis.suspicious_indicators),
                analysis.import_count,
                analysis.export_count,
                analysis.section_count,
                analysis.max_section_entropy,
                strings.total_strings,
                len(strings.urls),
                len(strings.ips),
                len(strings.registry_keys),
                len(strings.suspicious_strings),
                len(strings.file_paths),
                strings.encoded_strings,
                strings.encoded_strings / max(strings.total_strings, 1),
                len(strings.suspicious_strings) / max(strings.total_strings, 1),
            ]
            
            return np.array(features)
        except Exception as e:
            print(f"[!] Error extracting features from {file_path}: {e}")
            return None
    
    def prepare_dataset(self, malicious_dir: str, clean_dir: str) -> Tuple[np.ndarray, np.ndarray]:
        X = []
        y = []
        
        print("[*] Processing malicious samples...")
        mal_path = Path(malicious_dir)
        for file in mal_path.glob("**/*.exe"):
            features = self.extract_features(str(file))
            if features is not None:
                X.append(features)
                y.append(1)
                print(f"    [+] {file.name}")
        
        print(f"\n[*] Processing clean samples...")
        clean_path = Path(clean_dir)
        for file in clean_path.glob("**/*.exe"):
            features = self.extract_features(str(file))
            if features is not None:
                X.append(features)
                y.append(0)
                print(f"    [+] {file.name}")
        
        return np.array(X), np.array(y)
    
    def train_random_forest(self, X: np.ndarray, y: np.ndarray):
        print("\n[*] Training Random Forest Classifier...")
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        self.rf_model.fit(X_train, y_train)
        
        train_score = self.rf_model.score(X_train, y_train)
        test_score = self.rf_model.score(X_test, y_test)
        
        print(f"[+] Training accuracy: {train_score:.4f}")
        print(f"[+] Test accuracy: {test_score:.4f}")
        
        cv_scores = cross_val_score(self.rf_model, X, y, cv=5)
        print(f"[+] Cross-validation scores: {cv_scores}")
        print(f"[+] Mean CV score: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
        
        y_pred = self.rf_model.predict(X_test)
        
        print("\n[*] Classification Report:")
        print(classification_report(y_test, y_pred, target_names=['Clean', 'Malicious']))
        
        print("\n[*] Confusion Matrix:")
        cm = confusion_matrix(y_test, y_pred)
        print(f"    TN: {cm[0][0]}, FP: {cm[0][1]}")
        print(f"    FN: {cm[1][0]}, TP: {cm[1][1]}")
        
        feature_names = [
            'entropy', 'threat_score', 'suspicious_indicators',
            'import_count', 'export_count', 'section_count',
            'max_section_entropy', 'total_strings', 'urls',
            'ips', 'registry_keys', 'suspicious_strings',
            'file_paths', 'encoded_strings', 'encoded_ratio',
            'suspicious_ratio'
        ]
        
        importances = self.rf_model.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        print("\n[*] Feature Importances:")
        for i in range(min(10, len(indices))):
            print(f"    {feature_names[indices[i]]}: {importances[indices[i]]:.4f}")
        
        return X_test, y_test, y_pred
    
    def train_isolation_forest(self, X: np.ndarray):
        print("\n[*] Training Isolation Forest (Anomaly Detection)...")
        self.isolation_model.fit(X)
        print("[+] Isolation Forest trained successfully")
    
    def save_models(self, rf_path: str = "models/rf_model.pkl", 
                    iso_path: str = "models/iso_model.pkl"):
        Path("models").mkdir(exist_ok=True)
        
        with open(rf_path, 'wb') as f:
            pickle.dump(self.rf_model, f)
        print(f"[+] Random Forest saved to {rf_path}")
        
        with open(iso_path, 'wb') as f:
            pickle.dump(self.isolation_model, f)
        print(f"[+] Isolation Forest saved to {iso_path}")
    
    def load_models(self, rf_path: str = "models/rf_model.pkl",
                    iso_path: str = "models/iso_model.pkl"):
        with open(rf_path, 'rb') as f:
            self.rf_model = pickle.load(f)
        print(f"[+] Random Forest loaded from {rf_path}")
        
        with open(iso_path, 'rb') as f:
            self.isolation_model = pickle.load(f)
        print(f"[+] Isolation Forest loaded from {iso_path}")

def main():
    print("╔═══════════════════════════════════════╗")
    print("║   PROTEUS ML Training Pipeline        ║")
    print("╚═══════════════════════════════════════╝\n")
    
    trainer = ProteusMLTrainer()
    
    malicious_dir = "test_dataset/malicious"
    clean_dir = "test_dataset/clean"
    
    X, y = trainer.prepare_dataset(malicious_dir, clean_dir)
    
    print(f"\n[*] Dataset Summary:")
    print(f"    Total samples: {len(X)}")
    print(f"    Malicious: {np.sum(y == 1)}")
    print(f"    Clean: {np.sum(y == 0)}")
    print(f"    Features: {X.shape[1]}")
    
    if len(X) < 10:
        print("\n[!] Warning: Dataset too small for reliable training")
        print("[!] Recommendation: Add more samples (50+ each class)")
        return
    
    trainer.train_random_forest(X, y)
    trainer.train_isolation_forest(X)
    trainer.save_models()
    
    print("\n[+] Training complete!")

if __name__ == "__main__":
    main()