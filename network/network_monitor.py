from collections import Counter, deque, defaultdict
import time
import uuid

from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR, ARP

from network.attack_detector import AttackDetector


class NetworkMonitor:
    def __init__(
        self,
        packet_callback=None,
        alert_callback=None,
        interface=None,
        max_recent_packets=3000,
        packets_per_alert_limit=250,
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

        self.recent_packets = deque(maxlen=max_recent_packets)
        self.packets_per_alert_limit = packets_per_alert_limit

        self.alert_store = {}
        self.alert_packets = defaultdict(list)

    # Function to start capturing and sniffing the network
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

    def get_alert(self, alert_id):
        return self.alert_store.get(alert_id)

    def get_alert_packets(self, alert_id):
        return self.alert_packets.get(alert_id, [])

    def get_protocol_name(self, pkt):
        if ARP in pkt:
            return "ARP"
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
        protocol = self.get_protocol_name(pkt)

        # ARP packet normalization
        if protocol == "ARP":
            try:
                arp_op = pkt[ARP].sprintf("%ARP.op%")
            except Exception:
                arp_op = str(getattr(pkt[ARP], "op", "-"))

            packet_data = {
                "time": time.strftime("%H:%M:%S"),
                "timestamp": time.time(),
                "src_ip": getattr(pkt[ARP], "psrc", "-"),
                "src_port": "-",
                "dst_ip": getattr(pkt[ARP], "pdst", "-"),
                "dst_port": "-",
                "protocol": "ARP",
                "length": len(pkt),
                "flags": "-",
                "dns_query": None,
                "src_mac": getattr(pkt[ARP], "hwsrc", "-"),
                "dst_mac": getattr(pkt[ARP], "hwdst", "-"),
                "arp_op": arp_op
            }
            return packet_data

        if IP not in pkt:
            return None

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
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
            "timestamp": time.time(),
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "length": pkt_len,
            "flags": flags_text,
            "dns_query": dns_query,
            "src_mac": "-",
            "dst_mac": "-",
            "arp_op": "-"
        }

        return packet_data

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

        pkt_time = packet_data["timestamp"]

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

    def get_flow_snapshot_for_packet(self, packet_data):
        flow_key = (
            packet_data["src_ip"],
            packet_data["dst_ip"],
            packet_data["src_port"],
            packet_data["dst_port"],
            packet_data["protocol"]
        )
        flow = self.flows.get(flow_key)
        return flow.copy() if flow else {}

    def _match_packets_for_alert(self, alert_data):
        source = alert_data.get("source")
        target = alert_data.get("target", "-")
        alert_type = alert_data.get("type", "")

        matched = []

        for packet in reversed(self.recent_packets):
            # ARP spoofing source is MAC in alerts
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

        if not matched:
            if "ARP Spoofing" in alert_type:
                matched = [p for p in list(self.recent_packets)[-50:] if p.get("protocol") == "ARP"]
            else:
                matched = [p for p in list(self.recent_packets)[-30:] if p["src_ip"] == source]

        if "Dynamic Malware" in alert_type or "Beaconing" in alert_type:
            broader = [p for p in list(self.recent_packets) if p["src_ip"] == source]
            matched = broader[-self.packets_per_alert_limit:] if broader else matched

        return matched

    def raise_alert(self, alert_data, triggering_packet=None):
        self.total_alerts += 1

        alert_id = str(uuid.uuid4())[:8]

        enriched_alert = {
            "alert_id": alert_id,
            "time": alert_data.get("time", time.strftime("%H:%M:%S")),
            "type": alert_data.get("type", "Unknown Alert"),
            "source": alert_data.get("source", "-"),
            "target": alert_data.get("target", "-"),
            "details": alert_data.get("details", ""),
            "flow_snapshot": self.get_flow_snapshot_for_packet(triggering_packet) if triggering_packet else {},
        }

        related_packets = self._match_packets_for_alert(enriched_alert)

        if triggering_packet and triggering_packet not in related_packets:
            related_packets.append(triggering_packet)

        self.alert_store[alert_id] = enriched_alert
        self.alert_packets[alert_id] = related_packets

        if self.alert_callback:
            self.alert_callback(enriched_alert)

    #Method Used for processing the packets.
    def process_packet(self, pkt):
        if not self.capture_running:
            return
        #Method to get the fields i need from the network traffic
        packet_data = self.normalize_packet(pkt)
        if not packet_data:
            return

        self.recent_packets.append(packet_data)

        self.total_packets += 1
        self.total_bytes += packet_data["length"]
        self.protocol_counter[packet_data["protocol"]] += 1

        source_key = packet_data["src_mac"] if packet_data["protocol"] == "ARP" else packet_data["src_ip"]
        self.source_counter[source_key] += 1

        if self.packet_callback:
            self.packet_callback(packet_data)

        self.track_flow(packet_data)

        alerts = self.detector.process_packet(packet_data)
        for alert in alerts:
            self.raise_alert(alert, triggering_packet=packet_data)
