from collections import Counter
import statistics


class FeatureExtractor:
    def extract_from_packets(self, packets):
        if not packets:
            return self._empty_features()

        packet_count = len(packets)

        src_ips = [p.get("src_ip", "-") for p in packets]
        dst_ips = [p.get("dst_ip", "-") for p in packets]

        src_ports = [p.get("src_port") for p in packets if p.get("src_port") not in ("-", None)]
        dst_ports = [p.get("dst_port") for p in packets if p.get("dst_port") not in ("-", None)]

        lengths = [float(p.get("length", 0) or 0) for p in packets]
        protocols = [str(p.get("protocol", "")).upper() for p in packets]
        flags = [str(p.get("flags", "") or "") for p in packets]

        timestamps = []
        for p in packets:
            try:
                ts = p.get("timestamp")
                if ts is not None:
                    timestamps.append(float(ts))
            except Exception:
                pass

        total_fwd_packets = packet_count // 2
        total_bwd_packets = packet_count - total_fwd_packets

        fwd_lengths = lengths[:total_fwd_packets]
        bwd_lengths = lengths[total_fwd_packets:]

        def safe_stats(arr):
            if not arr:
                return 0.0, 0.0, 0.0, 0.0
            return (
                max(arr),
                min(arr),
                sum(arr) / len(arr),
                statistics.pstdev(arr) if len(arr) > 1 else 0.0,
            )

        fwd_max, fwd_min, fwd_mean, fwd_std = safe_stats(fwd_lengths)
        bwd_max, bwd_min, bwd_mean, bwd_std = safe_stats(bwd_lengths)

        if len(timestamps) > 1:
            timestamps = sorted(timestamps)
            flow_duration_seconds = max(timestamps) - min(timestamps)
            flow_duration = flow_duration_seconds * 1_000_000  # microseconds

            iats = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
            flow_iat_mean = sum(iats) / len(iats)
            flow_iat_std = statistics.pstdev(iats) if len(iats) > 1 else 0.0
            flow_iat_max = max(iats)
            flow_iat_min = min(iats)
        else:
            flow_duration_seconds = 0.0
            flow_duration = 0.0
            flow_iat_mean = 0.0
            flow_iat_std = 0.0
            flow_iat_max = 0.0
            flow_iat_min = 0.0

        flow_bytes = sum(lengths)
        flow_packets_per_sec = packet_count / flow_duration_seconds if flow_duration_seconds > 0 else 0.0
        flow_bytes_per_sec = flow_bytes / flow_duration_seconds if flow_duration_seconds > 0 else 0.0

        syn_count = sum(1 for f in flags if "S" in f)
        ack_count = sum(1 for f in flags if "A" in f)
        rst_count = sum(1 for f in flags if "R" in f)
        fin_count = sum(1 for f in flags if "F" in f)
        psh_count = sum(1 for f in flags if "P" in f)
        urg_count = sum(1 for f in flags if "U" in f)

        protocol_counts = Counter(protocols)
        proto = protocol_counts.most_common(1)[0][0] if protocol_counts else "OTHER"
        protocol_map = {
            "TCP": 6,
            "UDP": 17,
            "ICMP": 1,
            "DNS": 17,
        }
        protocol_value = protocol_map.get(proto, 0)

        packet_length_min = min(lengths) if lengths else 0.0
        packet_length_max = max(lengths) if lengths else 0.0
        avg_packet_size = sum(lengths) / packet_count if packet_count else 0.0
        packet_length_std = statistics.pstdev(lengths) if len(lengths) > 1 else 0.0
        packet_length_variance = statistics.pvariance(lengths) if len(lengths) > 1 else 0.0

        down_up_ratio = (total_bwd_packets / total_fwd_packets) if total_fwd_packets else 0.0

        return {
            "Protocol": protocol_value,
            "Flow Duration": flow_duration,

            "Total Fwd Packets": total_fwd_packets,
            "Total Backward Packets": total_bwd_packets,

            "Fwd Packets Length Total": sum(fwd_lengths),
            "Bwd Packets Length Total": sum(bwd_lengths),

            "Fwd Packet Length Max": fwd_max,
            "Fwd Packet Length Min": fwd_min,
            "Fwd Packet Length Mean": fwd_mean,
            "Fwd Packet Length Std": fwd_std,

            "Bwd Packet Length Max": bwd_max,
            "Bwd Packet Length Min": bwd_min,
            "Bwd Packet Length Mean": bwd_mean,
            "Bwd Packet Length Std": bwd_std,

            "Flow Bytes/s": flow_bytes_per_sec,
            "Flow Packets/s": flow_packets_per_sec,

            "Flow IAT Mean": flow_iat_mean,
            "Flow IAT Std": flow_iat_std,
            "Flow IAT Max": flow_iat_max,
            "Flow IAT Min": flow_iat_min,

            "Fwd IAT Total": flow_iat_mean * total_fwd_packets if total_fwd_packets else 0.0,
            "Fwd IAT Mean": flow_iat_mean,
            "Fwd IAT Std": flow_iat_std,
            "Fwd IAT Max": flow_iat_max,
            "Fwd IAT Min": flow_iat_min,

            "Bwd IAT Total": flow_iat_mean * total_bwd_packets if total_bwd_packets else 0.0,
            "Bwd IAT Mean": flow_iat_mean,
            "Bwd IAT Std": flow_iat_std,
            "Bwd IAT Max": flow_iat_max,
            "Bwd IAT Min": flow_iat_min,

            "Fwd PSH Flags": psh_count if total_fwd_packets else 0,
            "Bwd PSH Flags": 0,
            "Fwd URG Flags": urg_count if total_fwd_packets else 0,
            "Bwd URG Flags": 0,

            "Fwd Header Length": 0,
            "Bwd Header Length": 0,

            "Fwd Packets/s": flow_packets_per_sec,
            "Bwd Packets/s": flow_packets_per_sec,

            "Packet Length Min": packet_length_min,
            "Packet Length Max": packet_length_max,
            "Packet Length Mean": avg_packet_size,
            "Packet Length Std": packet_length_std,
            "Packet Length Variance": packet_length_variance,

            "FIN Flag Count": fin_count,
            "SYN Flag Count": syn_count,
            "RST Flag Count": rst_count,
            "PSH Flag Count": psh_count,
            "ACK Flag Count": ack_count,
            "URG Flag Count": urg_count,
            "CWE Flag Count": 0,
            "ECE Flag Count": 0,

            "Down/Up Ratio": down_up_ratio,

            "Avg Packet Size": avg_packet_size,
            "Avg Fwd Segment Size": fwd_mean,
            "Avg Bwd Segment Size": bwd_mean,

            "Fwd Avg Bytes/Bulk": 0.0,
            "Fwd Avg Packets/Bulk": 0.0,
            "Fwd Avg Bulk Rate": 0.0,
            "Bwd Avg Bytes/Bulk": 0.0,
            "Bwd Avg Packets/Bulk": 0.0,
            "Bwd Avg Bulk Rate": 0.0,

            "Subflow Fwd Packets": total_fwd_packets,
            "Subflow Fwd Bytes": sum(fwd_lengths),
            "Subflow Bwd Packets": total_bwd_packets,
            "Subflow Bwd Bytes": sum(bwd_lengths),

            "Init Fwd Win Bytes": 0,
            "Init Bwd Win Bytes": 0,

            "Fwd Act Data Packets": total_fwd_packets,
            "Fwd Seg Size Min": fwd_min,

            "Active Mean": flow_iat_mean,
            "Active Std": flow_iat_std,
            "Active Max": flow_iat_max,
            "Active Min": flow_iat_min,

            "Idle Mean": 0.0,
            "Idle Std": 0.0,
            "Idle Max": 0.0,
            "Idle Min": 0.0,
        }

    def _empty_features(self):
        return {
            "Protocol": 0,
            "Flow Duration": 0.0,

            "Total Fwd Packets": 0,
            "Total Backward Packets": 0,

            "Fwd Packets Length Total": 0.0,
            "Bwd Packets Length Total": 0.0,

            "Fwd Packet Length Max": 0.0,
            "Fwd Packet Length Min": 0.0,
            "Fwd Packet Length Mean": 0.0,
            "Fwd Packet Length Std": 0.0,

            "Bwd Packet Length Max": 0.0,
            "Bwd Packet Length Min": 0.0,
            "Bwd Packet Length Mean": 0.0,
            "Bwd Packet Length Std": 0.0,

            "Flow Bytes/s": 0.0,
            "Flow Packets/s": 0.0,

            "Flow IAT Mean": 0.0,
            "Flow IAT Std": 0.0,
            "Flow IAT Max": 0.0,
            "Flow IAT Min": 0.0,

            "Fwd IAT Total": 0.0,
            "Fwd IAT Mean": 0.0,
            "Fwd IAT Std": 0.0,
            "Fwd IAT Max": 0.0,
            "Fwd IAT Min": 0.0,

            "Bwd IAT Total": 0.0,
            "Bwd IAT Mean": 0.0,
            "Bwd IAT Std": 0.0,
            "Bwd IAT Max": 0.0,
            "Bwd IAT Min": 0.0,

            "Fwd PSH Flags": 0,
            "Bwd PSH Flags": 0,
            "Fwd URG Flags": 0,
            "Bwd URG Flags": 0,

            "Fwd Header Length": 0,
            "Bwd Header Length": 0,

            "Fwd Packets/s": 0.0,
            "Bwd Packets/s": 0.0,

            "Packet Length Min": 0.0,
            "Packet Length Max": 0.0,
            "Packet Length Mean": 0.0,
            "Packet Length Std": 0.0,
            "Packet Length Variance": 0.0,

            "FIN Flag Count": 0,
            "SYN Flag Count": 0,
            "RST Flag Count": 0,
            "PSH Flag Count": 0,
            "ACK Flag Count": 0,
            "URG Flag Count": 0,
            "CWE Flag Count": 0,
            "ECE Flag Count": 0,

            "Down/Up Ratio": 0.0,

            "Avg Packet Size": 0.0,
            "Avg Fwd Segment Size": 0.0,
            "Avg Bwd Segment Size": 0.0,

            "Fwd Avg Bytes/Bulk": 0.0,
            "Fwd Avg Packets/Bulk": 0.0,
            "Fwd Avg Bulk Rate": 0.0,
            "Bwd Avg Bytes/Bulk": 0.0,
            "Bwd Avg Packets/Bulk": 0.0,
            "Bwd Avg Bulk Rate": 0.0,

            "Subflow Fwd Packets": 0,
            "Subflow Fwd Bytes": 0.0,
            "Subflow Bwd Packets": 0,
            "Subflow Bwd Bytes": 0.0,

            "Init Fwd Win Bytes": 0,
            "Init Bwd Win Bytes": 0,

            "Fwd Act Data Packets": 0,
            "Fwd Seg Size Min": 0.0,

            "Active Mean": 0.0,
            "Active Std": 0.0,
            "Active Max": 0.0,
            "Active Min": 0.0,

            "Idle Mean": 0.0,
            "Idle Std": 0.0,
            "Idle Max": 0.0,
            "Idle Min": 0.0,
        }
