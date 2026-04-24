import os
from pathlib import Path

import joblib
import pandas as pd

from network.feature_extractor import FeatureExtractor


FEATURE_COLUMNS = [
    "Protocol",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packets Length Total",
    "Bwd Packets Length Total",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Packet Length Min",
    "Packet Length Max",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Avg Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init Fwd Win Bytes",
    "Init Bwd Win Bytes",
    "Fwd Act Data Packets",
    "Fwd Seg Size Min",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]


class MLAnalyzer:
    def __init__(self):
        self.extractor = FeatureExtractor()

        # Resolve project root no matter where the app is launched from
        current_file = Path(__file__).resolve()
        project_root = current_file.parent.parent

        self.supervised_model_path = project_root / "models" / "supervised_alert_model.pkl"
        self.label_encoder_path = project_root / "models" / "supervised_label_encoder.pkl"
        self.anomaly_model_path = project_root / "models" / "anomaly_model.pkl"

        print("\n[MLAnalyzer] Checking model files...")
        print("[MLAnalyzer] Supervised model:", self.supervised_model_path, self.supervised_model_path.exists())
        print("[MLAnalyzer] Label encoder   :", self.label_encoder_path, self.label_encoder_path.exists())
        print("[MLAnalyzer] Anomaly model   :", self.anomaly_model_path, self.anomaly_model_path.exists())

        self.supervised_model = None
        self.label_encoder = None
        self.anomaly_model = None

        if self.supervised_model_path.exists():
            self.supervised_model = joblib.load(self.supervised_model_path)

        if self.label_encoder_path.exists():
            self.label_encoder = joblib.load(self.label_encoder_path)

        if self.anomaly_model_path.exists():
            self.anomaly_model = joblib.load(self.anomaly_model_path)

    def analyze_alert(self, alert, packets):
        features = self.extractor.extract_from_packets(packets)

        X = pd.DataFrame([[features.get(col, 0) for col in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS)

        supervised_result = "Not loaded"
        supervised_confidence = None
        anomaly_result = "Not loaded"

        if self.supervised_model is not None and self.label_encoder is not None:
            try:
                pred_encoded = self.supervised_model.predict(X)[0]
                supervised_result = self.label_encoder.inverse_transform([pred_encoded])[0]

                if hasattr(self.supervised_model, "predict_proba"):
                    supervised_confidence = max(self.supervised_model.predict_proba(X)[0])
            except Exception as exc:
                supervised_result = f"Model error: {exc}"

        if self.anomaly_model is not None:
            try:
                anomaly_pred = self.anomaly_model.predict(X)[0]
                anomaly_result = "Anomalous" if anomaly_pred == -1 else "Normal-like"
            except Exception as exc:
                anomaly_result = f"Model error: {exc}"

        supervised_lower = str(supervised_result).strip().lower()
        benign_like_labels = {
            "benign",
            "normal",
            "false_positive",
            "false positive",
            "not loaded",
        }

        if supervised_lower not in benign_like_labels and not supervised_lower.startswith("model error"):
            verdict = f"Legitimate / Likely {supervised_result}"
        elif anomaly_result == "Anomalous":
            verdict = "Suspicious / Needs Review"
        elif anomaly_result == "Normal-like":
            verdict = "Likely False Positive"
        else:
            verdict = "Unable to determine"

        reasons = []

        if features.get("SYN Flag Count", 0) >= 10:
            reasons.append("High SYN activity suggests probing or incomplete TCP handshakes.")

        if features.get("RST Flag Count", 0) >= 5:
            reasons.append("Elevated RST activity suggests failed or rejected connections.")

        if features.get("Flow Packets/s", 0) >= 20:
            reasons.append("High packet rate suggests automated or aggressive traffic.")

        if features.get("Flow Duration", 0) > 0 and features.get("Flow IAT Std", 0) < 0.5:
            reasons.append("Low inter-arrival variation can indicate periodic callback behavior.")

        if features.get("Down/Up Ratio", 0) >= 1.5:
            reasons.append("Unusual direction ratio may indicate asymmetric attack traffic.")

        if not reasons:
            reasons.append("Decision was based mainly on learned feature patterns.")

        return {
            "verdict": verdict,
            "supervised_prediction": supervised_result,
            "supervised_confidence": (
                f"{supervised_confidence:.2%}" if supervised_confidence is not None else "N/A"
            ),
            "anomaly_result": anomaly_result,
            "features": features,
            "reasons": reasons,
        }
