import os
from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


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

LABEL_COLUMN = "Label"


def normalize_labels(series: pd.Series) -> pd.Series:
    s = series.astype(str).str.strip()

    s = s.str.replace("�", "-", regex=False)
    s = s.str.replace("–", "-", regex=False)
    s = s.str.replace("—", "-", regex=False)

    mapping = {
        "BENIGN": "benign",
        "Benign": "benign",
        "benign": "benign",
        "normal": "benign",
        "Normal": "benign",
    }

    return s.replace(mapping)


def main():
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent

    input_file = project_root / "datasets" / "benign_dataset.csv"
    models_dir = project_root / "models"
    model_path = models_dir / "anomaly_model.pkl"

    print("Project root:", project_root)
    print("Input file:", input_file)
    print("Models dir:", models_dir)

    if not input_file.exists():
        raise FileNotFoundError(f"Dataset not found: {input_file}")

    df = pd.read_csv(input_file)

    print("\nColumns loaded:")
    print(df.columns.tolist())

    missing = [col for col in FEATURE_COLUMNS + [LABEL_COLUMN] if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    df = df[FEATURE_COLUMNS + [LABEL_COLUMN]].copy()
    df = df.replace([float("inf"), -float("inf")], pd.NA)

    for col in FEATURE_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df = df.dropna(subset=[LABEL_COLUMN])
    df = df.fillna(0)

    df[LABEL_COLUMN] = normalize_labels(df[LABEL_COLUMN])

    print("\nLabel counts before benign filtering:")
    print(df[LABEL_COLUMN].value_counts())

    benign_labels = {"benign"}
    df_benign = df[df[LABEL_COLUMN].isin(benign_labels)].copy()

    if df_benign.empty:
        raise ValueError("No benign rows found for anomaly training.")

    print("\nBenign rows selected for anomaly training:")
    print(df_benign[LABEL_COLUMN].value_counts())

    # Sample for faster training if very large
    max_rows = 200000
    if len(df_benign) > max_rows:
        df_benign = df_benign.sample(n=max_rows, random_state=42)
        print(f"\nSampled benign dataset down to {len(df_benign)} rows for faster training.")

    X = df_benign[FEATURE_COLUMNS]

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("iso", IsolationForest(
            n_estimators=200,
            contamination=0.05,
            random_state=42,
            n_jobs=-1
        ))
    ])

    print("\nTraining anomaly model...")
    model.fit(X)

    models_dir.mkdir(parents=True, exist_ok=True)

    print("\nSaving anomaly model...")
    joblib.dump(model, model_path)

    print("Saved anomaly model to:", model_path)
    print("Model exists after save:", model_path.exists())


if __name__ == "__main__":
    main()