import csv
import json
from pathlib import Path

from network.feature_extractor import FeatureExtractor


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


def build_dataset_from_json(input_folder, output_csv):
    extractor = FeatureExtractor()
    input_folder = Path(input_folder)

    rows = []

    for json_file in input_folder.glob("*.json"):
        with open(json_file, "r", encoding="utf-8") as f:
            record = json.load(f)

        label = record["label"]
        packets = record["packets"]

        features = extractor.extract_from_packets(packets)
        row = {**features, "label": label}
        rows.append(row)

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FEATURE_COLUMNS + ["label"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved {len(rows)} rows to {output_csv}")


if __name__ == "__main__":
    build_dataset_from_json(
        input_folder="datasets/project_attacks/json_groups",
        output_csv="datasets/processed/project_alert_features.csv"
    )