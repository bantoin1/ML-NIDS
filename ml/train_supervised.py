import os
from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler


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


def normalize_labels(series: pd.Series) -> pd.Series:
    s = series.astype(str).str.strip()

    s = s.str.replace("�", "-", regex=False)
    s = s.str.replace("–", "-", regex=False)
    s = s.str.replace("—", "-", regex=False)

    mapping = {
        "BENIGN": "benign",
        "Benign": "benign",
        "benign": "benign",
        "DoS Hulk": "dos",
        "DoS GoldenEye": "dos",
        "DoS slowloris": "dos",
        "DoS Slowhttptest": "dos",
        "DDoS": "ddos",
        "PortScan": "port_scan",
        "FTP-Patator": "brute_force",
        "SSH-Patator": "brute_force",
        "Web Attack - Brute Force": "web_attack",
        "Web Attack - XSS": "web_attack",
        "Web Attack - Sql Injection": "web_attack",
        "Bot": "botnet",
        "Infiltration": "malware",
        "Heartbleed": "heartbleed",
    }

    return s.replace(mapping)


def find_label_column(df: pd.DataFrame) -> str:
    candidates = ["Label", "label", "Flow Label", "flow label", "Class", "class"]

    for candidate in candidates:
        if candidate in df.columns:
            return candidate

    normalized = {col.strip().lower(): col for col in df.columns}
    for candidate in ["label", "flow label", "class"]:
        if candidate in normalized:
            return normalized[candidate]

    raise ValueError(f"No label column found. Columns are: {df.columns.tolist()}")


def balance_dataset(df: pd.DataFrame, label_col: str, max_per_class: int = 50000) -> pd.DataFrame:
    parts = []

    for label_value, group in df.groupby(label_col):
        n = min(len(group), max_per_class)
        sampled = group.sample(n=n, random_state=42)
        parts.append(sampled)

    balanced = pd.concat(parts, ignore_index=True)
    return balanced


def load_dataset(input_file: Path):
    if not input_file.exists():
        raise FileNotFoundError(f"Dataset not found: {input_file}")

    df = pd.read_csv(input_file, low_memory=False)
    df.columns = df.columns.str.strip()

    print("\nColumns loaded:")
    print(df.columns.tolist())

    label_column = find_label_column(df)
    print(f"\nDetected label column: {label_column}")

    missing = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required feature columns: {missing}")

    df = df[FEATURE_COLUMNS + [label_column]].copy()
    df = df.replace([float("inf"), -float("inf")], pd.NA)

    for col in FEATURE_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df = df.dropna(subset=[label_column])
    df = df.fillna(0)
    df[label_column] = normalize_labels(df[label_column])

    return df, label_column


def evaluate_model(name, model, X_train, X_test, y_train, y_test, label_encoder):
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, average="macro")

    print(f"\n===== {name} =====")
    print("Accuracy:", round(acc, 4))
    print("F1 Macro:", round(f1, 4))
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("Classification Report:")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_, zero_division=0))

    return model, f1


def main():
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent

    input_file = project_root / "datasets" / "parquet" / "combined_dataset.csv"
    models_dir = project_root / "models"
    model_path = models_dir / "supervised_alert_model.pkl"
    encoder_path = models_dir / "supervised_label_encoder.pkl"

    print("Project root:", project_root)
    print("Input file:", input_file)

    df, label_column = load_dataset(input_file)

    print("\nLabel counts before filtering:")
    print(df[label_column].value_counts())

    min_samples = 50
    label_counts = df[label_column].value_counts()
    valid_labels = label_counts[label_counts >= min_samples].index
    df = df[df[label_column].isin(valid_labels)].copy()

    print("\nLabel counts after dropping tiny classes:")
    print(df[label_column].value_counts())

    if df[label_column].nunique() < 2:
        raise ValueError("Need at least 2 classes for supervised training.")

    df = balance_dataset(df, label_column, max_per_class=50000)

    print("\nFinal balanced label counts:")
    print(df[label_column].value_counts())
    print("\nFinal dataset size used for training:", len(df))

    X = df[FEATURE_COLUMNS]
    y = df[label_column]

    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_encoded,
        test_size=0.2,
        random_state=42,
        stratify=y_encoded
    )

    models = {
        "RandomForest": RandomForestClassifier(
            n_estimators=200,
            max_depth=14,
            min_samples_split=4,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced"
        ),
        "LogisticRegression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(
                max_iter=2000,
                class_weight="balanced"
            ))
        ]),
    }

    best_name = None
    best_model = None
    best_score = -1

    for name, model in models.items():
        trained_model, score = evaluate_model(
            name, model, X_train, X_test, y_train, y_test, label_encoder
        )
        if score > best_score:
            best_score = score
            best_name = name
            best_model = trained_model

    if best_model is None:
        raise RuntimeError("No model trained successfully.")

    models_dir.mkdir(parents=True, exist_ok=True)

    print("\nSaving files...")
    joblib.dump(best_model, model_path)
    joblib.dump(label_encoder, encoder_path)

    print("Best model:", best_name)
    print("Saved model to:", model_path)
    print("Saved encoder to:", encoder_path)
    print("Model exists after save:", model_path.exists())
    print("Encoder exists after save:", encoder_path.exists())


if __name__ == "__main__":
    main()