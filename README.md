# ML-Based Network Intrusion Detection System (ML-NIDS)

A Python-based Network Intrusion Detection System (NIDS) that combines:
- Real-time packet monitoring
- PCAP file analysis
- Rule-based attack detection
- Machine Learning for alert analysis
- Interactive GUI dashboard

--------------------------------------------------

FEATURES

- Live packet capture using Scapy
- Offline PCAP analysis
- Flow-based tracking using tuple keys
- Detection of multiple attack types:
  * SYN Flood
  * ICMP Flood
  * Port Scan
  * Brute Force
  * TCP Reset Abuse
  * DNS Tunneling
  * ARP Spoofing
  * Beaconing (malware-like behavior)
- Packet-to-alert correlation
- GUI dashboard with packet and alert tables
- Machine Learning:
  * Random Forest (classification)
  * Isolation Forest (anomaly detection)

--------------------------------------------------

PROJECT STRUCTURE

ml-nids-project/

gui/
  gui_dashboard.py
  alert_details_window.py

network/
  network_monitor.py
  attack_detector.py
  pcap_reader.py
  feature_extractor.py
  ml_analyzer.py

ml/
  train_supervised.py
  train_anomaly.py

models/
  supervised_alert_model.pkl
  supervised_label_encoder.pkl
  anomaly_model.pkl

scripts/
  combine_parquet_files.py

--------------------------------------------------

PREREQUISITES

- Python 3.9+
- Administrator privileges (for packet sniffing)

--------------------------------------------------

INSTALL REQUIRED LIBRARIES

pip install scapy pandas numpy scikit-learn matplotlib joblib customtkinter

--------------------------------------------------

HOW TO RUN

Run the GUI:

python gui/gui_dashboard.py

Steps:
1. Click Start Capture
2. Monitor packets in real time
3. Click alerts to view details

--------------------------------------------------

PCAP MODE

1. Open GUI
2. Click Upload PCAP
3. Select a .pcap file
4. System analyzes traffic

--------------------------------------------------

MACHINE LEARNING SETUP

Train supervised model:

python ml/train_supervised.py

Train anomaly model:

python ml/train_anomaly.py

Models will be saved in:

models/

--------------------------------------------------

HOW IT WORKS

1. Packet Capture using Scapy
2. Packet Normalization into dictionaries
3. Flow Tracking using tuple keys:
   (src_ip, dst_ip, src_port, dst_port, protocol)
4. Detection Engine using thresholds
5. Alert Generation and packet linking
6. Machine Learning analysis for final verdict

--------------------------------------------------

NOTES

- Run as Administrator for packet capture
- Ensure models exist before ML analysis
- Large PCAP files may take time

--------------------------------------------------

AUTHORS

Brandon Antoine
Pooja Badiwale

--------------------------------------------------

SUMMARY

This project combines networking, data structures, rule-based detection, and machine learning to build a real-world intrusion detection system.
