from collections import defaultdict
from datetime import datetime
import socket


class AttackDetector:
    def __init__(
        self,
        syn_threshold=20,
        icmp_threshold=20,
        portscan_threshold=10,
        bruteforce_threshold=12,
        dns_length_threshold=45,
        rst_threshold=15,
        trusted_ips=None
    ):
        self.syn_threshold = syn_threshold
        self.icmp_threshold = icmp_threshold
        self.portscan_threshold = portscan_threshold
        self.bruteforce_threshold = bruteforce_threshold
        self.dns_length_threshold = dns_length_threshold
        self.rst_threshold = rst_threshold

        self.syn_counter = defaultdict(int)
        self.icmp_counter = defaultdict(int)
        self.port_scan_tracker = defaultdict(set)
        self.bruteforce_tracker = defaultdict(int)
        self.rst_counter = defaultdict(int)

        self.alerted_syn = set()
        self.alerted_icmp = set()
        self.alerted_portscan = set()
        self.alerted_bruteforce = set()
        self.alerted_dns = set()
        self.alerted_rst = set()

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

        # TCP-based detections
        if protocol == "TCP":
            # SYN flood suspicion
            if "S" in flags and "A" not in flags:
                self.syn_counter[src_ip] += 1
                if (
                    self.syn_counter[src_ip] >= self.syn_threshold
                    and src_ip not in self.alerted_syn
                ):
                    alerts.append(self._build_alert(
                        "SYN Flood Suspicion",
                        src_ip,
                        f"Detected {self.syn_counter[src_ip]} SYN packets"
                    ))
                    self.alerted_syn.add(src_ip)

            # Port scan suspicion
            if dst_port not in (None, "-", ""):
                self.port_scan_tracker[src_ip].add(dst_port)
                if (
                    len(self.port_scan_tracker[src_ip]) >= self.portscan_threshold
                    and src_ip not in self.alerted_portscan
                ):
                    alerts.append(self._build_alert(
                        "Port Scan Suspicion",
                        src_ip,
                        f"Contacted {len(self.port_scan_tracker[src_ip])} unique destination ports"
                    ))
                    self.alerted_portscan.add(src_ip)

            # Brute force suspicion
            # Skip if the source IP is one of your own trusted/local IPs
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
                        f"Repeated connection attempts to {dst_ip}:{dst_port}"
                    ))
                    self.alerted_bruteforce.add(brute_key)

            # TCP Reset suspicion
            if "R" in flags:
                self.rst_counter[src_ip] += 1
                if (
                    self.rst_counter[src_ip] >= self.rst_threshold
                    and src_ip not in self.alerted_rst
                ):
                    alerts.append(self._build_alert(
                        "TCP Reset Suspicion",
                        src_ip,
                        f"Detected {self.rst_counter[src_ip]} TCP RST packets"
                    ))
                    self.alerted_rst.add(src_ip)

        elif protocol == "ICMP":
            self.icmp_counter[src_ip] += 1
            if (
                self.icmp_counter[src_ip] >= self.icmp_threshold
                and src_ip not in self.alerted_icmp
            ):
                alerts.append(self._build_alert(
                    "ICMP Flood Suspicion",
                    src_ip,
                    f"Detected {self.icmp_counter[src_ip]} ICMP packets"
                ))
                self.alerted_icmp.add(src_ip)

        elif protocol == "DNS":
            if dns_query:
                dns_key = (src_ip, dns_query)
                if (
                    len(dns_query) >= self.dns_length_threshold
                    and dns_key not in self.alerted_dns
                ):
                    alerts.append(self._build_alert(
                        "DNS Tunneling Suspicion",
                        src_ip,
                        f"Long DNS query detected: {dns_query[:80]}"
                    ))
                    self.alerted_dns.add(dns_key)

        return alerts

    def _build_alert(self, alert_type, source, details):
        return {
            "time": datetime.now().strftime("%H:%M:%S"),
            "type": alert_type,
            "source": source,
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