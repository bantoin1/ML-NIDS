import joblib
import pandas as pd

from sklearn.metrics import classification_report, confusion_matrix


FEATURE_COLUMNS = [
    "packet_count",
    "unique_src_ips",
    "unique_dst_ips",
    "unique_src_ports",
    "unique_dst_ports",
    "avg_packet_size",
    "min_packet_size",
    "max_packet_size",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "dns_ratio",
    "syn_ratio",
    "ack_ratio",
    "rst_ratio",
    "fin_ratio",
    "same_target_ratio",
    "timespan_seconds",
    "packets_per_second",
    "bytes_per_second",
    "mean_interarrival",
    "std_interarrival",
    "beacon_score",
]


def main():
    df = pd.read_csv("datasets/processed/final_combined_dataset.csv")

    X = df[FEATURE_COLUMNS]
    y_true = df["label"].apply(lambda x: "benign" if x == "benign" else "attack")

    model = joblib.load("../models/anomaly_model.pkl")

    preds = model.predict(X)
    y_pred = ["attack" if p == -1 else "benign" for p in preds]

    print(confusion_matrix(y_true, y_pred, labels=["benign", "attack"]))
    print(classification_report(y_true, y_pred, labels=["benign", "attack"]))


if __name__ == "__main__":
    main()