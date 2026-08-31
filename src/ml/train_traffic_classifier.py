"""
Training script for Random Forest VPN Traffic Classifier.
Loads real PCAP captures from data/pcaps/ using data/labels.csv ground truth,
extracts 8 statistical features per flow using the ESP parser and feature extractor,
trains a RandomForestClassifier(n_estimators=200, max_depth=8), prints a classification report,
and saves the trained model to models/traffic_rf_model.joblib.
"""

import os
import sys
from typing import Optional
import numpy as np
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.parser.esp_parser import parse_esp
from src.parser.feature_extractor import extract_features


def train_classifier(
    data_dir: str = "data",
    labels_csv_path: Optional[str] = None,
    model_dir: str = "models"
) -> RandomForestClassifier:
    """
    Main training function:
    - Reads ground-truth metadata from data/labels.csv
    - Locates each PCAP using 'pcap_path'
    - Uses 'traffic_type' as the ML target label
    - Extracts 8 statistical features from ESP flows
    - Trains RandomForestClassifier(n_estimators=200, max_depth=8)
    - Evaluates model performance and prints classification report
    - Saves trained model to models/traffic_rf_model.joblib
    """
    # Resolve paths relative to project root or cwd
    if not os.path.isabs(data_dir) and not os.path.exists(data_dir):
        alt_data_dir = os.path.join(PROJECT_ROOT, data_dir)
        if os.path.exists(alt_data_dir):
            data_dir = alt_data_dir

    if labels_csv_path is None:
        labels_csv = os.path.join(data_dir, "labels.csv")
    else:
        labels_csv = labels_csv_path

    if not os.path.isabs(labels_csv) and not os.path.exists(labels_csv):
        alt_labels_csv = os.path.join(PROJECT_ROOT, labels_csv)
        if os.path.exists(alt_labels_csv):
            labels_csv = alt_labels_csv

    # Strictly require real ground-truth dataset; do NOT generate synthetic data
    if not os.path.exists(labels_csv):
        raise FileNotFoundError(
            f"Authoritative ground-truth labels file not found at: '{labels_csv}'. "
            "Please ensure Workstream A dataset (data/labels.csv and data/pcaps/) exists."
        )

    df_labels = pd.read_csv(labels_csv)

    # Validate required columns from Workstream A schema
    if "traffic_type" not in df_labels.columns:
        if "label" in df_labels.columns:
            target_col = "label"
        else:
            raise KeyError(
                f"Missing 'traffic_type' column in '{labels_csv}'. Available columns: {list(df_labels.columns)}"
            )
    else:
        target_col = "traffic_type"

    if "pcap_path" not in df_labels.columns:
        if "filename" in df_labels.columns:
            pcap_col = "filename"
        else:
            raise KeyError(
                f"Missing 'pcap_path' column in '{labels_csv}'. Available columns: {list(df_labels.columns)}"
            )
    else:
        pcap_col = "pcap_path"

    X = []
    y = []
    skipped_count = 0

    print(f"[*] Loading ground-truth metadata from: {labels_csv}")
    print(f"[*] Processing {len(df_labels)} scenario entries (Target: '{target_col}', Path: '{pcap_col}')...")

    for idx, row in df_labels.iterrows():
        raw_pcap_path = str(row[pcap_col]).strip()
        label = str(row[target_col]).strip()
        scenario_id = row.get("scenario_id", f"Row-{idx}")

        # Resolve PCAP path
        pcap_path = raw_pcap_path
        if not os.path.isabs(pcap_path):
            if not os.path.exists(pcap_path):
                # Try relative to project root
                cand1 = os.path.join(PROJECT_ROOT, pcap_path)
                # Try relative to data_dir parent
                cand2 = os.path.join(os.path.dirname(labels_csv), os.path.basename(pcap_path))
                # Try in data_dir/pcaps
                cand3 = os.path.join(data_dir, "pcaps", os.path.basename(pcap_path))

                if os.path.exists(cand1):
                    pcap_path = cand1
                elif os.path.exists(cand2):
                    pcap_path = cand2
                elif os.path.exists(cand3):
                    pcap_path = cand3

        if not os.path.exists(pcap_path):
            print(f"[!] Warning: PCAP file not found for {scenario_id} at '{raw_pcap_path}', skipping.")
            skipped_count += 1
            continue

        # Parse ESP flows and extract 8 statistical features
        esp_flows = parse_esp(pcap_path)
        features = extract_features(esp_flows)

        X.append(features)
        y.append(label)
        print(f"    [+] {scenario_id} | {label:8s} | ESP pkts: {len(esp_flows):4d} | Mean Size: {features[0]:6.1f}B | PCAP: {os.path.basename(pcap_path)}")

    if len(X) == 0:
        raise ValueError(
            f"No feature vectors could be extracted from PCAPs listed in '{labels_csv}'. "
            "Please check that PCAP files exist and contain valid network flows."
        )

    X = np.array(X, dtype=float)
    y = np.array(y)

    unique_classes = sorted(list(set(y)))
    print(f"\n[+] Successfully extracted features for {len(X)} samples across {len(unique_classes)} classes: {unique_classes}")

    # 80/20 Train/Test split
    if len(X) >= 5:
        # Check if stratified split is possible (every class has >= 2 samples)
        class_counts = pd.Series(y).value_counts()
        can_stratify = (class_counts.min() >= 2) and (int(len(X) * 0.2) >= len(unique_classes))

        try:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y if can_stratify else None
            )
        except ValueError:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=None
            )
    else:
        X_train, X_test, y_train, y_test = X, X, y, y

    print(f"[*] Training RandomForestClassifier(n_estimators=200, max_depth=8) on {len(X_train)} training samples...")
    clf = RandomForestClassifier(n_estimators=200, max_depth=8, random_state=42)
    clf.fit(X_train, y_train)

    # Evaluate on test split
    y_pred = clf.predict(X_test)
    print("\n" + "=" * 60)
    print("RANDOM FOREST TRAFFIC CLASSIFICATION REPORT (Test Split)")
    print("=" * 60)
    print(classification_report(y_test, y_pred, zero_division=0))

    # Refit classifier on all available real data so all classes are learned
    clf.fit(X, y)

    # Save model
    if not os.path.isabs(model_dir):
        target_model_dir = os.path.join(PROJECT_ROOT, model_dir)
    else:
        target_model_dir = model_dir

    os.makedirs(target_model_dir, exist_ok=True)
    model_path = os.path.join(target_model_dir, "traffic_rf_model.joblib")
    joblib.dump(clf, model_path)
    print(f"[+] Trained Random Forest model successfully saved to: {model_path}\n")

    return clf


if __name__ == "__main__":
    train_classifier()
