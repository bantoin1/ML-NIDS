import customtkinter as ctk
from tkinter import ttk

from network.ml_analyzer import MLAnalyzer


class AlertDetailsWindow(ctk.CTkToplevel):
    def __init__(self, parent, alert, packets):
        super().__init__(parent)

        self.alert = alert
        self.packets = packets
        self.analyzer = MLAnalyzer()

        self.title(f"Alert Investigation - {alert.get('alert_id', 'N/A')}")
        self.geometry("1280x820")
        self.minsize(1080, 720)

        self._build_ui()
        self._load_data()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        header = ctk.CTkFrame(self, corner_radius=18)
        header.grid(row=0, column=0, sticky="ew", padx=14, pady=(14, 10))
        header.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            header,
            text="Alert Investigation & ML Review",
            font=ctk.CTkFont(size=24, weight="bold")
        ).grid(row=0, column=0, sticky="w", padx=16, pady=16)

        self.alert_summary_label = ctk.CTkLabel(
            header,
            text="",
            font=ctk.CTkFont(size=14)
        )
        self.alert_summary_label.grid(row=0, column=1, sticky="e", padx=16, pady=16)

        top = ctk.CTkFrame(self, corner_radius=18)
        top.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 10))
        top.grid_columnconfigure(0, weight=1)
        top.grid_columnconfigure(1, weight=1)

        self.alert_box = ctk.CTkTextbox(top, height=220)
        self.alert_box.grid(row=0, column=0, sticky="nsew", padx=(14, 7), pady=14)

        self.analysis_box = ctk.CTkTextbox(top, height=220)
        self.analysis_box.grid(row=0, column=1, sticky="nsew", padx=(7, 14), pady=14)

        bottom = ctk.CTkFrame(self, corner_radius=18)
        bottom.grid(row=2, column=0, sticky="nsew", padx=14, pady=(0, 14))
        bottom.grid_columnconfigure(0, weight=1)
        bottom.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            bottom,
            text="Packets Related to This Alert",
            font=ctk.CTkFont(size=18, weight="bold")
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 8))

        self.packet_table = self._create_table(
            bottom,
            columns=("time", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "length", "flags"),
            headings=("Time", "Source IP", "Src Port", "Dest IP", "Dst Port", "Protocol", "Length", "Flags")
        )
        self.packet_table.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))

    def _create_table(self, parent, columns, headings):
        container = ctk.CTkFrame(parent, fg_color="transparent")
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Treeview",
            background="#1f1f1f",
            foreground="white",
            fieldbackground="#1f1f1f",
            rowheight=28,
            borderwidth=0
        )
        style.configure(
            "Treeview.Heading",
            background="#2b2b2b",
            foreground="white",
            relief="flat"
        )

        tree = ttk.Treeview(container, columns=columns, show="headings")
        y_scroll = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
        x_scroll = ttk.Scrollbar(container, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        for col, heading in zip(columns, headings):
            tree.heading(col, text=heading)
            tree.column(col, width=130, anchor="center")

        tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")

        container.tree = tree
        return container

    def _load_data(self):
        self.alert_summary_label.configure(
            text=f"{self.alert.get('type', 'Unknown')} | Source: {self.alert.get('source', '-')} | Target: {self.alert.get('target', '-')}"
        )

        alert_lines = [
            f"Alert ID: {self.alert.get('alert_id', '-')}",
            f"Time: {self.alert.get('time', '-')}",
            f"Type: {self.alert.get('type', '-')}",
            f"Source: {self.alert.get('source', '-')}",
            f"Target: {self.alert.get('target', '-')}",
            f"Details: {self.alert.get('details', '-')}",
            ""
        ]

        flow_snapshot = self.alert.get("flow_snapshot", {})
        if flow_snapshot:
            alert_lines.extend([
                "Flow Snapshot",
                f"Protocol: {flow_snapshot.get('protocol', '-')}",
                f"Packets: {flow_snapshot.get('packet_count', '-')}",
                f"Bytes: {flow_snapshot.get('byte_count', '-')}",
                f"SYN: {flow_snapshot.get('syn_count', '-')}",
                f"ACK: {flow_snapshot.get('ack_count', '-')}",
                f"RST: {flow_snapshot.get('rst_count', '-')}",
                f"FIN: {flow_snapshot.get('fin_count', '-')}",
            ])

        self.alert_box.delete("1.0", "end")
        self.alert_box.insert("1.0", "\n".join(alert_lines))

        result = self.analyzer.analyze_alert(self.alert, self.packets)

        analysis_lines = [
            f"Verdict: {result.get('verdict', 'N/A')}",
            f"Supervised Prediction: {result.get('supervised_prediction', 'N/A')}",
            f"Supervised Confidence: {result.get('supervised_confidence', 'N/A')}",
            f"Anomaly Result: {result.get('anomaly_result', 'N/A')}",
            "",
            "Extracted Features"
        ]

        for key, value in result["features"].items():
            analysis_lines.append(f"- {key}: {value}")

        analysis_lines.append("")
        analysis_lines.append("Why the analyzer says this")

        if result["reasons"]:
            for reason in result["reasons"]:
                analysis_lines.append(f"- {reason}")
        else:
            analysis_lines.append("- Very little evidence of malicious behavior in this packet set.")

        self.analysis_box.delete("1.0", "end")
        self.analysis_box.insert("1.0", "\n".join(analysis_lines))

        tree = self.packet_table.tree
        for item in tree.get_children():
            tree.delete(item)

        for packet in self.packets:
            row = (
                packet["time"],
                packet["src_ip"],
                packet["src_port"],
                packet["dst_ip"],
                packet["dst_port"],
                packet["protocol"],
                packet["length"],
                packet["flags"]
            )
            tree.insert("", "end", values=row)
