from collections import Counter
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR

from network.attack_detector import AttackDetector


class NetworkMonitor:
    def __init__(
        self,
        packet_callback=None,
        alert_callback=None,
        interface=None,
    ):
        self.packet_callback = packet_callback
        self.alert_callback = alert_callback
        self.interface = interface

        self.detector = AttackDetector()

        self.capture_running = False
        self.flows = {}
        self.protocol_counter = Counter()
        self.source_counter = Counter()

        self.total_packets = 0
        self.total_bytes = 0
        self.total_alerts = 0
        self.start_time = None

    # -------------------------
    # Public methods
    # -------------------------
    def start(self):
        self.capture_running = True
        self.start_time = time.time()

        sniff(
            prn=self.process_packet,
            store=False,
            iface=self.interface,
            stop_filter=lambda pkt: not self.capture_running
        )

    def stop(self):
        self.capture_running = False

    def get_stats(self):
        uptime = 0
        if self.capture_running and self.start_time:
            uptime = int(time.time() - self.start_time)

        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "total_alerts": self.total_alerts,
            "tracked_flows": len(self.flows),
            "uptime": uptime,
            "protocol_counter": dict(self.protocol_counter),
            "source_counter": dict(self.source_counter)
        }

    def get_flows(self):
        return self.flows

    # -------------------------
    # Packet parsing helpers
    # -------------------------
    def get_protocol_name(self, pkt):
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            return "DNS"
        if TCP in pkt:
            return "TCP"
        if UDP in pkt:
            return "UDP"
        if ICMP in pkt:
            return "ICMP"
        return "OTHER"

    def get_ports(self, pkt):
        src_port = "-"
        dst_port = "-"

        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        return src_port, dst_port

    def normalize_packet(self, pkt):
        if IP not in pkt:
            return None

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = self.get_protocol_name(pkt)
        src_port, dst_port = self.get_ports(pkt)
        pkt_len = len(pkt)

        flags_text = "-"
        if TCP in pkt:
            flags_text = pkt.sprintf("%TCP.flags%") or "-"

        dns_query = None
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                dns_query = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            except Exception:
                dns_query = str(pkt[DNSQR].qname)

        packet_data = {
            "time": time.strftime("%H:%M:%S"),
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "length": pkt_len,
            "flags": flags_text,
            "dns_query": dns_query
        }

        return packet_data

    # -------------------------
    # Flow tracking
    # -------------------------
    def create_new_flow(self, packet_data, pkt_time):
        return {
            "src_ip": packet_data["src_ip"],
            "dst_ip": packet_data["dst_ip"],
            "src_port": packet_data["src_port"],
            "dst_port": packet_data["dst_port"],
            "protocol": packet_data["protocol"],
            "packet_count": 1,
            "byte_count": packet_data["length"],
            "start_time": pkt_time,
            "end_time": pkt_time,
            "syn_count": 0,
            "ack_count": 0,
            "rst_count": 0,
            "fin_count": 0,
        }

    def update_tcp_flags(self, flow, packet_data):
        if packet_data["protocol"] != "TCP":
            return

        flags = str(packet_data.get("flags", "") or "")

        if "S" in flags:
            flow["syn_count"] += 1
        if "A" in flags:
            flow["ack_count"] += 1
        if "R" in flags:
            flow["rst_count"] += 1
        if "F" in flags:
            flow["fin_count"] += 1

    def track_flow(self, packet_data):
        protocol = packet_data["protocol"]

        if protocol not in {"TCP", "UDP", "DNS"}:
            return None

        pkt_time = time.time()

        flow_key = (
            packet_data["src_ip"],
            packet_data["dst_ip"],
            packet_data["src_port"],
            packet_data["dst_port"],
            protocol
        )

        if flow_key not in self.flows:
            self.flows[flow_key] = self.create_new_flow(packet_data, pkt_time)
        else:
            self.flows[flow_key]["packet_count"] += 1
            self.flows[flow_key]["byte_count"] += packet_data["length"]
            self.flows[flow_key]["end_time"] = pkt_time

        self.update_tcp_flags(self.flows[flow_key], packet_data)
        return flow_key

    # -------------------------
    # Alerts
    # -------------------------
    def raise_alert(self, alert_data):
        self.total_alerts += 1

        if self.alert_callback:
            self.alert_callback(alert_data)

    # -------------------------
    # Main packet processing
    # -------------------------
    def process_packet(self, pkt):
        if not self.capture_running:
            return

        packet_data = self.normalize_packet(pkt)
        if not packet_data:
            return

        self.total_packets += 1
        self.total_bytes += packet_data["length"]
        self.protocol_counter[packet_data["protocol"]] += 1
        self.source_counter[packet_data["src_ip"]] += 1

        if self.packet_callback:
            self.packet_callback(packet_data)

        self.track_flow(packet_data)

        alerts = self.detector.process_packet(packet_data)
        for alert in alerts:
            self.raise_alert(alert)