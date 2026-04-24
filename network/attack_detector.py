from collections import defaultdict, deque
from datetime import datetime
import socket
import statistics
import time


class AttackDetector:
    def __init__(
        self,
        syn_threshold=20,
        icmp_threshold=20,
        portscan_threshold=10,
        bruteforce_threshold=12,
        dns_length_threshold=45,
        dns_subdomain_threshold=5,
        dns_query_rate_threshold=25,
        rst_threshold=15,
        malware_conn_threshold=20,
        malware_port_threshold=12,
        malware_dest_threshold=6,
        beacon_min_hits=6,
        arp_spoof_threshold=2,
        trusted_ips=None
    ):
        self.syn_threshold = syn_threshold
        self.icmp_threshold = icmp_threshold
        self.portscan_threshold = portscan_threshold
        self.bruteforce_threshold = bruteforce_threshold
        self.dns_length_threshold = dns_length_threshold
        self.dns_subdomain_threshold = dns_subdomain_threshold
        self.dns_query_rate_threshold = dns_query_rate_threshold
        self.rst_threshold = rst_threshold

        self.malware_conn_threshold = malware_conn_threshold
        self.malware_port_threshold = malware_port_threshold
        self.malware_dest_threshold = malware_dest_threshold
        self.beacon_min_hits = beacon_min_hits

        self.arp_spoof_threshold = arp_spoof_threshold

        # Basic counters
        self.syn_counter = defaultdict(int)
        self.ack_counter = defaultdict(int)
        self.icmp_counter = defaultdict(int)
        self.port_scan_tracker = defaultdict(set)
        self.bruteforce_tracker = defaultdict(int)
        self.rst_counter = defaultdict(int)

        # Time-based SYN tracking
        self.syn_time_tracker = defaultdict(lambda: deque())

        # Distributed SYN flood tracking
        self.target_syn_tracker = defaultdict(lambda: deque())
        self.target_ack_counter = defaultdict(int)

        # Alert suppression
        self.alerted_syn = set()
        self.alerted_distributed_syn = set()
        self.alerted_icmp = set()
        self.alerted_portscan = set()
        self.alerted_bruteforce = set()
        self.alerted_dns = set()
        self.alerted_dns_rate = set()
        self.alerted_rst = set()

        # Dynamic / malware-style tracking
        self.activity_window_seconds = 20
        self.src_activity_tracker = defaultdict(lambda: deque())
        self.src_dest_times = defaultdict(lambda: deque())
        self.alerted_dynamic_malware = set()
        self.alerted_beaconing = set()

        # ARP spoofing tracking
        self.ip_mac_map = defaultdict(set)
        self.mac_ip_map = defaultdict(set)
        self.alerted_arp_pairs = set()

        self.trusted_ips = set(trusted_ips or [])
        self.trusted_ips.update(self._get_local_ips())

    def process_packet(self, packet_data):
        alerts = []

        src_ip = packet_data.get("src_ip", "-")
        dst_ip = packet_data.get("dst_ip", "-")
        dst_port = packet_data.get("dst_port")
        protocol = packet_data.get("protocol", "OTHER")
        flags = str(packet_data.get("flags", "") or "")
        dns_query = packet_data.get("dns_query")
        packet_timestamp = packet_data.get("timestamp", time.time())

        # -------------------------
        # ARP spoofing detection
        # -------------------------
        if protocol == "ARP":
            alerts.extend(self._detect_arp_spoofing(packet_data))
            return alerts

        # -------------------------
        # Dynamic behavior tracking
        # -------------------------
        self._track_dynamic_behavior(src_ip, dst_ip, dst_port, packet_timestamp, protocol)

        # -------------------------
        # TCP-based detections
        # -------------------------
        if protocol == "TCP":
            now = packet_timestamp
            syn_window = 10

            # 1. SINGLE-SOURCE MODERN SYN FLOOD
            if "S" in flags and "A" not in flags:
                self.syn_counter[src_ip] += 1
                self.syn_time_tracker[src_ip].append(now)

            if "A" in flags:
                self.ack_counter[src_ip] += 1

            while (
                self.syn_time_tracker[src_ip]
                and now - self.syn_time_tracker[src_ip][0] > syn_window
            ):
                self.syn_time_tracker[src_ip].popleft()

            syn_count = self.syn_counter[src_ip]
            ack_count = self.ack_counter[src_ip]
            syn_rate = len(self.syn_time_tracker[src_ip]) / syn_window if syn_window > 0 else 0
            ack_ratio = (ack_count / syn_count) if syn_count > 0 else 0

            if (
                syn_count >= self.syn_threshold
                and syn_rate >= 5
                and ack_ratio < 0.3
                and src_ip not in self.alerted_syn
            ):
                alerts.append(self._build_alert(
                    "Modern SYN Flood Suspicion",
                    src_ip,
                    f"SYN={syn_count}, ACK={ack_count}, Rate={syn_rate:.2f}/s, AckRatio={ack_ratio:.2f}",
                    target=f"{dst_ip}:{dst_port}"
                ))
                self.alerted_syn.add(src_ip)

            # 2. DISTRIBUTED / MODERN SYN FLOOD
            if "S" in flags and "A" not in flags:
                self.target_syn_tracker[dst_ip].append((now, src_ip))

            if "A" in flags:
                self.target_ack_counter[dst_ip] += 1

            while (
                self.target_syn_tracker[dst_ip]
                and now - self.target_syn_tracker[dst_ip][0][0] > syn_window
            ):
                self.target_syn_tracker[dst_ip].popleft()

            target_syn_count = len(self.target_syn_tracker[dst_ip])
            unique_sources = len({entry[1] for entry in self.target_syn_tracker[dst_ip]})
            target_ack_count = self.target_ack_counter[dst_ip]
            target_syn_rate = target_syn_count / syn_window if syn_window > 0 else 0
            target_ack_ratio = (target_ack_count / target_syn_count) if target_syn_count > 0 else 0

            if (
                target_syn_count >= 50
                and unique_sources >= 10
                and target_syn_rate >= 10
                and target_ack_ratio < 0.3
                and dst_ip not in self.alerted_distributed_syn
            ):
                alerts.append(self._build_alert(
                    "Distributed SYN Flood Suspicion",
                    "Multiple Sources",
                    f"Target {dst_ip} receiving SYN flood from {unique_sources} IPs. SYN={target_syn_count}, Rate={target_syn_rate:.2f}/s, AckRatio={target_ack_ratio:.2f}",
                    target=dst_ip
                ))
                self.alerted_distributed_syn.add(dst_ip)

            # 3. PORT SCAN SUSPICION
            if dst_port not in (None, "-", ""):
                self.port_scan_tracker[src_ip].add(dst_port)

                if (
                    len(self.port_scan_tracker[src_ip]) >= self.portscan_threshold
                    and src_ip not in self.alerted_portscan
                ):
                    alerts.append(self._build_alert(
                        "Port Scan Suspicion",
                        src_ip,
                        f"Contacted {len(self.port_scan_tracker[src_ip])} unique destination ports",
                        target=dst_ip
                    ))
                    self.alerted_portscan.add(src_ip)

            # 4. BRUTE FORCE SUSPICION
            if src_ip not in self.trusted_ips and dst_port in {21, 22, 23, 25, 80, 110, 143, 443, 3389}:
                brute_key = (src_ip, dst_ip, dst_port)
                self.bruteforce_tracker[brute_key] += 1

                if (
                    self.bruteforce_tracker[brute_key] >= self.bruteforce_threshold
                    and brute_key not in self.alerted_bruteforce
                ):
                    alerts.append(self._build_alert(
                        "Brute Force Suspicion",
                        src_ip,
                        f"Repeated connection attempts to {dst_ip}:{dst_port}",
                        target=f"{dst_ip}:{dst_port}"
                    ))
                    self.alerted_bruteforce.add(brute_key)

            # 5. TCP RESET SUSPICION
            if "R" in flags:
                self.rst_counter[src_ip] += 1

                if (
                    self.rst_counter[src_ip] >= self.rst_threshold
                    and src_ip not in self.alerted_rst
                ):
                    alerts.append(self._build_alert(
                        "TCP Reset Suspicion",
                        src_ip,
                        f"Detected {self.rst_counter[src_ip]} TCP RST packets",
                        target=dst_ip
                    ))
                    self.alerted_rst.add(src_ip)

        # -------------------------
        # ICMP detections
        # -------------------------
        elif protocol == "ICMP":
            self.icmp_counter[src_ip] += 1
            if (
                self.icmp_counter[src_ip] >= self.icmp_threshold
                and src_ip not in self.alerted_icmp
            ):
                alerts.append(self._build_alert(
                    "ICMP Flood Suspicion",
                    src_ip,
                    f"Detected {self.icmp_counter[src_ip]} ICMP packets",
                    target=dst_ip
                ))
                self.alerted_icmp.add(src_ip)

        # -------------------------
        # DNS tunneling detections
        # -------------------------
        elif protocol == "DNS":
            alerts.extend(self._detect_dns_tunneling(packet_data))

        # -------------------------
        # Dynamic malware-like detections
        # -------------------------
        alerts.extend(self._detect_dynamic_malware(src_ip))
        alerts.extend(self._detect_beaconing(src_ip, dst_ip))

        return alerts

    def _track_dynamic_behavior(self, src_ip, dst_ip, dst_port, packet_timestamp, protocol):
        activity = self.src_activity_tracker[src_ip]
        activity.append((packet_timestamp, dst_ip, dst_port, protocol))

        while activity and packet_timestamp - activity[0][0] > self.activity_window_seconds:
            activity.popleft()

        if dst_ip not in ("-", None):
            dest_key = (src_ip, dst_ip)
            self.src_dest_times[dest_key].append(packet_timestamp)

            while (
                self.src_dest_times[dest_key]
                and packet_timestamp - self.src_dest_times[dest_key][0] > self.activity_window_seconds
            ):
                self.src_dest_times[dest_key].popleft()

    def _detect_dynamic_malware(self, src_ip):
        alerts = []
        activity = list(self.src_activity_tracker[src_ip])
        if not activity:
            return alerts

        unique_dests = {item[1] for item in activity if item[1] not in (None, "-")}
        unique_ports = {item[2] for item in activity if item[2] not in (None, "-", "")}

        if (
            len(activity) >= self.malware_conn_threshold
            and len(unique_ports) >= self.malware_port_threshold
            and len(unique_dests) >= self.malware_dest_threshold
            and src_ip not in self.alerted_dynamic_malware
        ):
            alerts.append(self._build_alert(
                "Dynamic Malware Suspicion",
                src_ip,
                f"High connection churn: {len(activity)} packets across {len(unique_ports)} ports and {len(unique_dests)} destinations in {self.activity_window_seconds}s",
                target="Multiple"
            ))
            self.alerted_dynamic_malware.add(src_ip)

        return alerts

    def _detect_beaconing(self, src_ip, dst_ip):
        alerts = []
        dest_key = (src_ip, dst_ip)
        timestamps = list(self.src_dest_times[dest_key])

        if len(timestamps) < self.beacon_min_hits:
            return alerts

        intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
        if not intervals:
            return alerts

        avg_interval = sum(intervals) / len(intervals)
        variance = statistics.pvariance(intervals) if len(intervals) > 1 else 0.0

        beacon_key = (src_ip, dst_ip)
        if (
            0.5 <= avg_interval <= 5
            and variance < 0.8
            and beacon_key not in self.alerted_beaconing
        ):
            alerts.append(self._build_alert(
                "Beaconing Suspicion",
                src_ip,
                f"Regular repeated callbacks to {dst_ip}. Avg interval={avg_interval:.2f}s variance={variance:.2f}",
                target=dst_ip
            ))
            self.alerted_beaconing.add(beacon_key)

        return alerts

    def _detect_dns_tunneling(self, packet_data):
        alerts = []

        src_ip = packet_data.get("src_ip", "-")
        dst_ip = packet_data.get("dst_ip", "-")
        dns_query = packet_data.get("dns_query")
        packet_timestamp = packet_data.get("timestamp", time.time())

        if not dns_query:
            return alerts

        dns_query = str(dns_query).strip().lower()
        labels = [x for x in dns_query.split(".") if x]
        subdomain_count = max(len(labels) - 2, 0) if len(labels) >= 2 else len(labels)

        # 1. Long query detection
        dns_key = (src_ip, dns_query)
        if (
            len(dns_query) >= self.dns_length_threshold
            and dns_key not in self.alerted_dns
        ):
            alerts.append(self._build_alert(
                "DNS Tunneling Suspicion",
                src_ip,
                f"Long DNS query detected: {dns_query[:100]}",
                target=dst_ip
            ))
            self.alerted_dns.add(dns_key)

        # 2. Excessive subdomains
        dns_sub_key = (src_ip, "subdomain_count")
        if (
            subdomain_count >= self.dns_subdomain_threshold
            and dns_sub_key not in self.alerted_dns
        ):
            alerts.append(self._build_alert(
                "DNS Tunneling Suspicion",
                src_ip,
                f"Excessive DNS subdomains detected ({subdomain_count}): {dns_query[:100]}",
                target=dst_ip
            ))
            self.alerted_dns.add(dns_sub_key)

        # 3. High-rate DNS querying
        q = self.dns_query_tracker[src_ip]
        q.append((packet_timestamp, dns_query))

        while q and packet_timestamp - q[0][0] > 10:
            q.popleft()

        if (
            len(q) >= self.dns_query_rate_threshold
            and src_ip not in self.alerted_dns_rate
        ):
            alerts.append(self._build_alert(
                "DNS Tunneling Suspicion",
                src_ip,
                f"High DNS query rate detected: {len(q)} queries in 10 seconds",
                target=dst_ip
            ))
            self.alerted_dns_rate.add(src_ip)

        return alerts

    def _detect_arp_spoofing(self, packet_data):
        alerts = []

        src_ip = packet_data.get("src_ip", "-")
        src_mac = packet_data.get("src_mac", "-")
        dst_ip = packet_data.get("dst_ip", "-")
        arp_op = packet_data.get("arp_op", "-")

        if src_ip in ("-", None) or src_mac in ("-", None):
            return alerts

        self.ip_mac_map[src_ip].add(src_mac)
        self.mac_ip_map[src_mac].add(src_ip)

        # Same IP claimed by multiple MACs
        if len(self.ip_mac_map[src_ip]) >= self.arp_spoof_threshold:
            key = ("ip_to_many_macs", src_ip)
            if key not in self.alerted_arp_pairs:
                alerts.append(self._build_alert(
                    "ARP Spoofing Suspicion",
                    src_mac,
                    f"IP {src_ip} is being advertised by multiple MAC addresses: {sorted(self.ip_mac_map[src_ip])}",
                    target=dst_ip
                ))
                self.alerted_arp_pairs.add(key)

        # Same MAC claiming multiple IPs
        if len(self.mac_ip_map[src_mac]) >= self.arp_spoof_threshold:
            key = ("mac_to_many_ips", src_mac)
            if key not in self.alerted_arp_pairs:
                alerts.append(self._build_alert(
                    "ARP Spoofing Suspicion",
                    src_mac,
                    f"MAC {src_mac} is claiming multiple IP addresses: {sorted(self.mac_ip_map[src_mac])}",
                    target=dst_ip
                ))
                self.alerted_arp_pairs.add(key)

        # Conflicting ARP replies
        if arp_op == "is-at" and len(self.ip_mac_map[src_ip]) >= self.arp_spoof_threshold:
            key = ("arp_reply_conflict", src_ip)
            if key not in self.alerted_arp_pairs:
                alerts.append(self._build_alert(
                    "ARP Spoofing Suspicion",
                    src_mac,
                    f"Conflicting ARP reply detected for IP {src_ip}",
                    target=dst_ip
                ))
                self.alerted_arp_pairs.add(key)

        return alerts

    def _build_alert(self, alert_type, source, details, target="-"):
        return {
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": alert_type,
            "source": source,
            "target": target,
            "details": details
        }

    def _get_local_ips(self):
        local_ips = {"127.0.0.1"}

        try:
            hostname = socket.gethostname()
            local_ips.update(socket.gethostbyname_ex(hostname)[2])
        except Exception:
            pass

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ips.add(s.getsockname()[0])
            s.close()
        except Exception:
            pass

        return local_ips
