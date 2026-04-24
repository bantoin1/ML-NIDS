from collections import Counter, deque, defaultdict
from datetime import datetime
import uuid

from scapy.all import PcapReader, IP, TCP, UDP, ICMP, DNS, DNSQR, ARP

from network.attack_detector import AttackDetector


class PcapAnalyzer:
    def __init__(self, max_packets=200, max_alerts=100, packets_per_alert_limit=250):
        self.max_packets = max_packets
        self.max_alerts = max_alerts
        self.packets_per_alert_limit = packets_per_alert_limit

        self.alert_store = {}
        self.alert_packets = defaultdict(list)

    def analyze(self, file_path):
        detector = AttackDetector()

        packet_rows = deque(maxlen=self.max_packets)
        alert_rows = deque(maxlen=self.max_alerts)

        total_packets = 0
        total_bytes = 0
        protocol_counter = Counter()
        flows = set()
        recent_packets = deque(maxlen=3000)

        self.alert_store = {}
        self.alert_packets = defaultdict(list)

        with PcapReader(file_path) as pcap_reader:
            for packet in pcap_reader:
                normalized = self._normalize_packet(packet)
                if not normalized:
                    continue

                recent_packets.append(normalized)

                total_packets += 1
                total_bytes += normalized["length"]
                protocol_counter[normalized["protocol"]] += 1

                flow_key = self._build_flow_key(normalized)
                if flow_key:
                    flows.add(flow_key)

                packet_row = (
                    normalized["time"],
                    normalized["src_ip"] if normalized["protocol"] != "ARP" else normalized.get("src_mac", "-"),
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
                    alert_id = str(uuid.uuid4())[:8]
                    enriched_alert = {
                        "alert_id": alert_id,
                        "time": alert["time"],
                        "type": alert["type"],
                        "source": alert["source"],
                        "target": alert.get("target", "-"),
                        "details": alert["details"],
                        "flow_snapshot": {}
                    }

                    related_packets = self._match_packets_for_alert(enriched_alert, recent_packets)
                    self.alert_store[alert_id] = enriched_alert
                    self.alert_packets[alert_id] = related_packets

                    alert_row = (
                        enriched_alert["alert_id"],
                        enriched_alert["time"],
                        enriched_alert["type"],
                        enriched_alert["source"],
                        enriched_alert["target"],
                        enriched_alert["details"]
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

    def get_alert(self, alert_id):
        return self.alert_store.get(alert_id)

    def get_alert_packets(self, alert_id):
        return self.alert_packets.get(alert_id, [])

    def _match_packets_for_alert(self, alert, recent_packets):
        source = alert.get("source")
        target = alert.get("target", "-")
        alert_type = alert.get("type", "")

        matched = []

        for packet in reversed(recent_packets):
            if "ARP Spoofing" in alert_type:
                if packet.get("src_mac") != source:
                    continue
            else:
                if packet["src_ip"] != source:
                    continue

            if target not in ("-", "Multiple"):
                if ":" in str(target):
                    try:
                        target_ip, target_port = str(target).split(":", 1)
                        if packet["dst_ip"] != target_ip:
                            continue
                        if str(packet["dst_port"]) != str(target_port):
                            continue
                    except ValueError:
                        pass
                else:
                    if packet["dst_ip"] != target:
                        continue

            matched.append(packet)
            if len(matched) >= self.packets_per_alert_limit:
                break

        if "Dynamic Malware" in alert_type or "Beaconing" in alert_type:
            broader = [p for p in list(recent_packets) if p["src_ip"] == source]
            matched = broader[-self.packets_per_alert_limit:] if broader else matched

        if "ARP Spoofing" in alert_type and not matched:
            matched = [p for p in list(recent_packets) if p.get("protocol") == "ARP"][-self.packets_per_alert_limit:]

        return matched

    def _normalize_packet(self, packet):
        if ARP in packet:
            try:
                arp_op = packet[ARP].sprintf("%ARP.op%")
            except Exception:
                arp_op = str(getattr(packet[ARP], "op", "-"))

            return {
                "time": self._format_time(getattr(packet, "time", None)),
                "timestamp": self._timestamp_float(getattr(packet, "time", None)),
                "src_ip": getattr(packet[ARP], "psrc", "-"),
                "dst_ip": getattr(packet[ARP], "pdst", "-"),
                "src_port": "-",
                "dst_port": "-",
                "protocol": "ARP",
                "length": len(packet),
                "flags": "-",
                "dns_query": None,
                "src_mac": getattr(packet[ARP], "hwsrc", "-"),
                "dst_mac": getattr(packet[ARP], "hwdst", "-"),
                "arp_op": arp_op
            }

        if IP not in packet:
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_time = self._format_time(getattr(packet, "time", None))
        packet_timestamp = self._timestamp_float(getattr(packet, "time", None))
        length = len(packet)

        normalized = {
            "time": packet_time,
            "timestamp": packet_timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": "-",
            "dst_port": "-",
            "protocol": "OTHER",
            "length": length,
            "flags": "-",
            "dns_query": None,
            "src_mac": "-",
            "dst_mac": "-",
            "arp_op": "-"
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

    def _timestamp_float(self, packet_time):
        try:
            if packet_time is None:
                return 0.0
            return float(packet_time)
        except Exception:
            return 0.0
