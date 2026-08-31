"""
Inference Module for VPN Traffic Classifier.
Loads models/traffic_rf_model.joblib and predicts traffic class and confidence score.
"""

import os
import sys
from typing import List, Tuple, Union
import numpy as np
import joblib

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def predict_traffic(
    feature_vector: List[float],
    model_path: str = "models/traffic_rf_model.joblib"
) -> Tuple[str, float]:
    """
    Predict traffic class and confidence score from an 8-feature statistical array.

    Args:
        feature_vector (list): 8-element list of floats computed by feature_extractor:
            [mean_size, std_size, mean_iat, std_iat, pkt_count, bidirectional_ratio, min_size, max_size]
        model_path (str): Path to saved Random Forest joblib model.

    Returns:
        tuple: (predicted_label, confidence_score)
            - predicted_label (str): Predicted traffic type (e.g., 'web', 'voip', 'video')
            - confidence_score (float): Maximum class probability score (0.0 to 1.0)
    """
    # Ensure feature vector is a 2D float array [1, 8]
    vec = np.array(feature_vector, dtype=float).reshape(1, -1)

    # Resolve model path relative to project root if needed
    resolved_model_path = model_path
    if not os.path.isabs(resolved_model_path):
        if not os.path.exists(resolved_model_path):
            alt_path = os.path.join(PROJECT_ROOT, resolved_model_path)
            if os.path.exists(alt_path):
                resolved_model_path = alt_path

    # Fallback handling if model file does not exist
    if not os.path.exists(resolved_model_path):
        try:
            from src.ml.train_traffic_classifier import train_classifier
            print(f"[*] Model file '{resolved_model_path}' not found. Training model automatically...")
            train_classifier()
            if not os.path.exists(resolved_model_path):
                alt_path = os.path.join(PROJECT_ROOT, "models", "traffic_rf_model.joblib")
                if os.path.exists(alt_path):
                    resolved_model_path = alt_path
        except Exception as e:
            print(f"[!] Warning: Could not auto-train model: {e}")

    # Load model and run prediction
    if os.path.exists(resolved_model_path):
        try:
            clf = joblib.load(resolved_model_path)
            prediction = clf.predict(vec)[0]

            if hasattr(clf, "predict_proba"):
                probabilities = clf.predict_proba(vec)[0]
                confidence = float(np.max(probabilities))
            else:
                confidence = 1.0

            return (str(prediction), round(confidence, 4))
        except Exception as e:
            print(f"[!] Error loading model from {resolved_model_path}: {e}")

    # Return safe fallback if model is unavailable
    return ("unknown", 0.0)


if __name__ == "__main__":
    # Quick test inference with sample feature vector
    sample_features = [500.0, 150.0, 0.05, 0.01, 50.0, 0.5, 64.0, 1400.0]
    label, score = predict_traffic(sample_features)
    print(f"[Test Predict] Label: {label}, Confidence: {score}")
