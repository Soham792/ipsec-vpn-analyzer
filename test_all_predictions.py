import pandas as pd

from src.parser.esp_parser import parse_esp
from src.parser.feature_extractor import extract_features
from src.ml.predict import predict_traffic

df = pd.read_csv("data/labels.csv")

passed = 0

print("=" * 70)
print("{:<10}{:<15}{:<15}{:<12}{}".format(
    "SCENARIO", "GROUND TRUTH", "PREDICTION", "CONFIDENCE", "RESULT"
))
print("=" * 70)

for _, row in df.iterrows():
    packets = parse_esp(row["pcap_path"])
    features = extract_features(packets)
    prediction, confidence = predict_traffic(features)

    result = "PASS" if prediction == row["traffic_type"] else "FAIL"

    if result == "PASS":
        passed += 1

    print("{:<10}{:<15}{:<15}{:<12.1%}{}".format(
        row["scenario_id"],
        row["traffic_type"],
        prediction,
        confidence,
        result
    ))

print("=" * 70)
print("TOTAL: {}/{} PASS".format(passed, len(df)))