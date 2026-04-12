from collections import Counter, deque
from datetime import datetime

from scapy.all import PcapReader, IP, TCP, UDP, ICMP, DNS, DNSQR

from network.attack_detector import AttackDetector


class PcapAnalyzer:
    def __init__(self, max_packets=200, max_alerts=100):
        self.max_packets = max_packets
        self.max_alerts = max_alerts

    def analyze(self, file_path):
        detector = AttackDetector()

        packet_rows = deque(maxlen=self.max_packets)
        alert_rows = deque(maxlen=self.max_alerts)

        total_packets = 0
        total_bytes = 0
        protocol_counter = Counter()
        flows = set()

        with PcapReader(file_path) as pcap_reader:
            for packet in pcap_reader:
                normalized = self._normalize_packet(packet)
                if not normalized:
                    continue

                total_packets += 1
                total_bytes += normalized["length"]
                protocol_counter[normalized["protocol"]] += 1

                flow_key = self._build_flow_key(normalized)
                if flow_key:
                    flows.add(flow_key)

                packet_row = (
                    normalized["time"],
                    normalized["src_ip"],
                    normalized["src_port"],
                    normalized["dst_ip"],
                    normalized["dst_port"],
                    normalized["protocol"],
                    normalized["length"],
                    normalized["flags"]
                )
                packet_rows.appendleft(packet_row)

                alerts = detector.process_packet(normalized)
                for alert in alerts:
                    alert_row = (
                        alert["time"],
                        alert["type"],
                        alert["source"],
                        alert["details"]
                    )
                    alert_rows.appendleft(alert_row)

        return {
            "packets": list(packet_rows),
            "alerts": list(alert_rows),
            "stats": {
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "total_alerts": len(alert_rows),
                "tracked_flows": len(flows),
                "protocol_counter": dict(protocol_counter)
            }
        }

    def _normalize_packet(self, packet):
        if IP not in packet:
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_time = self._format_time(getattr(packet, "time", None))
        length = len(packet)

        normalized = {
            "time": packet_time,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": "-",
            "dst_port": "-",
            "protocol": "OTHER",
            "length": length,
            "flags": "-",
            "dns_query": None
        }

        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            normalized["protocol"] = "DNS"
            if UDP in packet:
                normalized["src_port"] = packet[UDP].sport
                normalized["dst_port"] = packet[UDP].dport
            elif TCP in packet:
                normalized["src_port"] = packet[TCP].sport
                normalized["dst_port"] = packet[TCP].dport
                normalized["flags"] = packet.sprintf("%TCP.flags%") or "-"
            try:
                normalized["dns_query"] = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
            except Exception:
                normalized["dns_query"] = str(packet[DNSQR].qname)
            return normalized

        if TCP in packet:
            normalized["protocol"] = "TCP"
            normalized["src_port"] = packet[TCP].sport
            normalized["dst_port"] = packet[TCP].dport
            normalized["flags"] = packet.sprintf("%TCP.flags%") or "-"
            return normalized

        if UDP in packet:
            normalized["protocol"] = "UDP"
            normalized["src_port"] = packet[UDP].sport
            normalized["dst_port"] = packet[UDP].dport
            return normalized

        if ICMP in packet:
            normalized["protocol"] = "ICMP"
            return normalized

        return normalized

    def _build_flow_key(self, packet_data):
        proto = packet_data["protocol"]

        if proto in {"TCP", "UDP", "DNS"}:
            return (
                packet_data["src_ip"],
                packet_data["src_port"],
                packet_data["dst_ip"],
                packet_data["dst_port"],
                proto
            )

        if proto == "ICMP":
            return (
                packet_data["src_ip"],
                packet_data["dst_ip"],
                proto
            )

        return None

    def _format_time(self, packet_time):
        try:
            if packet_time is None:
                return "-"
            return datetime.fromtimestamp(float(packet_time)).strftime("%H:%M:%S")
        except Exception:
            return "-"