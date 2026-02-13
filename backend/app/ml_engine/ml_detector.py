import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import pickle
import os
from urllib.parse import urlparse
import re


class MLDetector:
    MODEL_PATH = os.path.join(os.path.dirname(__file__), "trained_model.pkl")
    SCALER_PATH = os.path.join(os.path.dirname(__file__), "scaler.pkl")

    def __init__(self):
        self.model = None
        self.scaler = None
        self.load_model()

    def load_model(self):
        if os.path.exists(self.MODEL_PATH):
            try:
                with open(self.MODEL_PATH, "rb") as f:
                    self.model = pickle.load(f)
                with open(self.SCALER_PATH, "rb") as f:
                    self.scaler = pickle.load(f)
                return
            except Exception as e:
                print(f"Error loading model: {e}")

        self._initialize_default_model()

    def _initialize_default_model(self):
        X_train = self._generate_training_data(200)
        y_train = np.array([1] * 100 + [0] * 100)

        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)

        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X_train_scaled, y_train)
        self.save_model()

    def _generate_training_data(self, n_samples):
        features = []
        for _ in range(n_samples):
            feature_vector = np.random.rand(10)
            features.append(feature_vector)
        return np.array(features)

    def extract_features(self, url):
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path

            features = []
            features.append(len(url))
            features.append(len(domain))
            features.append(domain.count("."))
            features.append(url.count("-"))
            features.append(url.count("_"))

            special_chars = len(re.findall(r'[@!#$%^&*()_+=\[\]{};\':",.<>?/\\|`~]', url))
            features.append(special_chars)
            features.append(1 if parsed.scheme == "https" else 0)
            features.append(url.count("/"))

            has_ip = 1 if re.match(r"\d+\.\d+\.\d+\.\d+", domain) else 0
            features.append(has_ip)

            domain_entropy = self._calculate_entropy(domain)
            features.append(domain_entropy)

            return np.array(features).reshape(1, -1)

        except Exception as e:
            print(f"Error extracting features: {e}")
            return np.zeros((1, 10))

    @staticmethod
    def _calculate_entropy(s):
        if len(s) == 0:
            return 0

        entropy = 0
        for char in set(s):
            prob = s.count(char) / len(s)
            entropy -= prob * np.log2(prob)

        return entropy / 8.0

    def predict(self, url):
        try:
            features = self.extract_features(url)
            features_scaled = self.scaler.transform(features)

            prediction = self.model.predict(features_scaled)[0]
            probability = self.model.predict_proba(features_scaled)[0]

            phishing_score = probability[1] * 100

            return {
                "is_phishing": bool(prediction),
                "score": phishing_score,
                "confidence": (max(probability) * 100),
                "probability_legitimate": probability[0] * 100,
                "probability_phishing": probability[1] * 100,
                "detection_method": "ml_based"
            }

        except Exception as e:
            print(f"Prediction error: {e}")
            return {
                "is_phishing": False,
                "score": 0,
                "confidence": 0,
                "error": str(e),
                "detection_method": "ml_based"
            }

    def save_model(self):
        try:
            with open(self.MODEL_PATH, "wb") as f:
                pickle.dump(self.model, f)
            with open(self.SCALER_PATH, "wb") as f:
                pickle.dump(self.scaler, f)
        except Exception as e:
            print(f"Error saving model: {e}")
