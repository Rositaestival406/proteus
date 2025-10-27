import numpy as np
from sklearn.ensemble import IsolationForest
import pickle


class ProteusMLDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.is_trained = False

    def extract_features(self, analysis_result: dict) -> np.ndarray:
        features = [
            analysis_result["entropy"],
            analysis_result["score"],
            len(analysis_result["indicators"]),
        ]
        return np.array(features).reshape(1, -1)

    def train(self, training_data: list):
        X = np.vstack([self.extract_features(d) for d in training_data])
        self.model.fit(X)
        self.is_trained = True

    def predict(self, analysis_result: dict) -> int:
        if not self.is_trained:
            raise ValueError("Model not trained")

        features = self.extract_features(analysis_result)
        prediction = self.model.predict(features)
        return -1 if prediction[0] == -1 else 1

    def save_model(self, path: str):
        with open(path, "wb") as f:
            pickle.dump(self.model, f)

    def load_model(self, path: str):
        with open(path, "rb") as f:
            self.model = pickle.load(f)
        self.is_trained = True
