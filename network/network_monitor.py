from collections import defaultdict, deque, Counter
import time

from scapy.all import sniff, IP, TCP, UDP, ICMP


class NetworkMonitor:
    def __init__(
        self,
        port_scan_window=10,
        port_scan_port_threshold=20,
        syn_flood_syn_threshold=30,
        syn_flood_ack_threshold=5,
        packet_callback=None,
        alert_callback=None,
        interface=None
    ):
        self.port_scan_window = port_scan_window
        self.port_scan_port_threshold = port_scan_port_threshold
        self.syn_flood_syn_threshold = syn_flood_syn_threshold
        self.syn_flood_ack_threshold = syn_flood_ack_threshold
        self.packet_callback = packet_callback
        self.alert_callback = alert_callback
        self.interface = interface

        self.capture_running = False
        self.flows = {}
        self.port_scan_tracker = defaultdict(lambda: deque())
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
        if TCP in pkt:
            return "TCP"
        if UDP in pkt:
            return "UDP"
        if ICMP in pkt:
            return "ICMP"
        return "OTHER"

    def get_ports(self, pkt):
        src_port = 0
        dst_port = 0

        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        return src_port, dst_port

    # -------------------------
    # Flow tracking
    # -------------------------
    def create_new_flow(self, src_ip, dst_ip, src_port, dst_port, protocol, pkt_len, pkt_time):
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "packet_count": 1,
            "byte_count": pkt_len,
            "start_time": pkt_time,
            "end_time": pkt_time,
            "syn_count": 0,
            "ack_count": 0,
            "rst_count": 0,
            "fin_count": 0,
        }

    def update_tcp_flags(self, flow, pkt):
        if TCP not in pkt:
            return

        flags = pkt[TCP].flags

        if flags & 0x02:
            flow["syn_count"] += 1
        if flags & 0x10:
            flow["ack_count"] += 1
        if flags & 0x04:
            flow["rst_count"] += 1
        if flags & 0x01:
            flow["fin_count"] += 1

    def track_flow(self, pkt):
        if IP not in pkt:
            return None

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = self.get_protocol_name(pkt)
        src_port, dst_port = self.get_ports(pkt)
        pkt_len = len(pkt)
        pkt_time = time.time()

        flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)

        if flow_key not in self.flows:
            self.flows[flow_key] = self.create_new_flow(
                src_ip, dst_ip, src_port, dst_port, protocol, pkt_len, pkt_time
            )
        else:
            self.flows[flow_key]["packet_count"] += 1
            self.flows[flow_key]["byte_count"] += pkt_len
            self.flows[flow_key]["end_time"] = pkt_time

        self.update_tcp_flags(self.flows[flow_key], pkt)
        return flow_key

    # -------------------------
    # Detection
    # -------------------------
    def detect_port_scan(self, src_ip, dst_port):
        current_time = time.time()
        self.port_scan_tracker[src_ip].append((current_time, dst_port))

        while (
            self.port_scan_tracker[src_ip]
            and current_time - self.port_scan_tracker[src_ip][0][0] > self.port_scan_window
        ):
            self.port_scan_tracker[src_ip].popleft()

        unique_ports = {port for _, port in self.port_scan_tracker[src_ip]}

        if len(unique_ports) >= self.port_scan_port_threshold:
            self.raise_alert(
                alert_type="Port Scan",
                source=src_ip,
                details=f"Hit {len(unique_ports)} unique ports in {self.port_scan_window}s"
            )

    def detect_syn_flood(self, flow):
        if flow["protocol"] != "TCP":
            return

        if (
            flow["syn_count"] >= self.syn_flood_syn_threshold
            and flow["ack_count"] <= self.syn_flood_ack_threshold
        ):
            self.raise_alert(
                alert_type="Possible SYN Flood",
                source=flow["src_ip"],
                details=f"SYN={flow['syn_count']} ACK={flow['ack_count']} to {flow['dst_ip']}:{flow['dst_port']}"
            )

    def raise_alert(self, alert_type, source, details):
        self.total_alerts += 1

        alert_data = {
            "time": time.strftime("%H:%M:%S"),
            "type": alert_type,
            "source": source,
            "details": details
        }

        if self.alert_callback:
            self.alert_callback(alert_data)

    # -------------------------
    # Main packet processing
    # -------------------------
    def process_packet(self, pkt):
        if not self.capture_running:
            return

        if IP not in pkt:
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = self.get_protocol_name(pkt)
        src_port, dst_port = self.get_ports(pkt)
        pkt_len = len(pkt)

        flags_text = "-"
        if TCP in pkt:
            flags_text = str(pkt[TCP].flags)

        packet_data = {
            "time": time.strftime("%H:%M:%S"),
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "length": pkt_len,
            "flags": flags_text
        }

        self.total_packets += 1
        self.total_bytes += pkt_len
        self.protocol_counter[protocol] += 1
        self.source_counter[src_ip] += 1

        if self.packet_callback:
            self.packet_callback(packet_data)

        flow_key = self.track_flow(pkt)
        if flow_key:
            flow = self.flows[flow_key]

            if flow["protocol"] == "TCP":
                self.detect_port_scan(flow["src_ip"], flow["dst_port"])
                self.detect_syn_flood(flow)