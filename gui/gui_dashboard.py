import threading
import time
from collections import deque

import customtkinter as ctk
from tkinter import ttk, filedialog, messagebox

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from network.network_monitor import NetworkMonitor
from network.pcap_reader import PcapAnalyzer


MAX_PACKET_ROWS = 200
MAX_ALERT_ROWS = 100


class NIDSGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("Network Intrusion Detection Dashboard")
        self.geometry("1450x900")
        self.minsize(1250, 780)

        self.packet_log = deque(maxlen=MAX_PACKET_ROWS)
        self.alert_log = deque(maxlen=MAX_ALERT_ROWS)

        self.monitor = NetworkMonitor(
            packet_callback=self.on_packet,
            alert_callback=self.on_alert
        )

        self.pcap_analyzer = PcapAnalyzer()

        self.capture_thread = None
        self.analysis_thread = None

        # Live capture uptime
        self.gui_capture_running = False
        self.capture_start_time = None
        self.frozen_uptime = 0

        # Mode: "live" or "pcap"
        self.current_mode = "live"

        # PCAP stats
        self.pcap_stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "total_alerts": 0,
            "tracked_flows": 0,
            "protocol_counter": {}
        }

        self._build_ui()
        self._update_dashboard()

    # -------------------------
    # Callbacks from live monitor
    # -------------------------
    def on_packet(self, packet_data):
        if self.current_mode != "live":
            return

        row = (
            packet_data["time"],
            packet_data["src_ip"],
            packet_data["src_port"],
            packet_data["dst_ip"],
            packet_data["dst_port"],
            packet_data["protocol"],
            packet_data["length"],
            packet_data["flags"]
        )
        self.packet_log.appendleft(row)

    def on_alert(self, alert_data):
        if self.current_mode != "live":
            return

        row = (
            alert_data["time"],
            alert_data["type"],
            alert_data["source"],
            alert_data["details"]
        )

        if self.alert_log and self.alert_log[0] == row:
            return

        self.alert_log.appendleft(row)

    # -------------------------
    # UI
    # -------------------------
    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, corner_radius=18)
        header.grid(row=0, column=0, sticky="ew", padx=16, pady=(16, 10))
        header.grid_columnconfigure(1, weight=1)

        title = ctk.CTkLabel(
            header,
            text="Network Intrusion Detection Dashboard",
            font=ctk.CTkFont(size=26, weight="bold")
        )
        title.grid(row=0, column=0, padx=18, pady=16, sticky="w")

        self.status_label = ctk.CTkLabel(
            header,
            text="Status: Stopped",
            font=ctk.CTkFont(size=15, weight="bold")
        )
        self.status_label.grid(row=0, column=1, padx=10, sticky="e")

        self.upload_button = ctk.CTkButton(
            header,
            text="Upload PCAP",
            command=self.upload_pcap,
            width=130,
            height=38,
            corner_radius=12
        )
        self.upload_button.grid(row=0, column=2, padx=(10, 8), pady=14)

        self.start_button = ctk.CTkButton(
            header,
            text="Start Capture",
            command=self.start_capture,
            width=130,
            height=38,
            corner_radius=12
        )
        self.start_button.grid(row=0, column=3, padx=(0, 8), pady=14)

        self.stop_button = ctk.CTkButton(
            header,
            text="Stop Capture",
            command=self.stop_capture,
            width=130,
            height=38,
            corner_radius=12,
            state="disabled"
        )
        self.stop_button.grid(row=0, column=4, padx=(0, 16), pady=14)

        body = ctk.CTkFrame(self, corner_radius=18)
        body.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 16))
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(1, weight=1)

        stats_frame = ctk.CTkFrame(body, fg_color="transparent")
        stats_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=14, pady=14)
        for i in range(5):
            stats_frame.grid_columnconfigure(i, weight=1)

        self.card_packets = self._create_stat_card(stats_frame, 0, "Total Packets", "0")
        self.card_bytes = self._create_stat_card(stats_frame, 1, "Total Bytes", "0")
        self.card_alerts = self._create_stat_card(stats_frame, 2, "Alerts", "0")
        self.card_flows = self._create_stat_card(stats_frame, 3, "Tracked Flows", "0")
        self.card_uptime = self._create_stat_card(stats_frame, 4, "Uptime", "0s")

        packet_frame = ctk.CTkFrame(body, corner_radius=18)
        packet_frame.grid(row=1, column=0, sticky="nsew", padx=(14, 8), pady=(0, 14))
        packet_frame.grid_rowconfigure(1, weight=1)
        packet_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            packet_frame,
            text="Live Packet Feed / PCAP Analysis",
            font=ctk.CTkFont(size=18, weight="bold")
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 8))

        self.packet_table = self._create_table(
            packet_frame,
            columns=("time", "src", "sport", "dst", "dport", "proto", "length", "flags"),
            headings=("Time", "Source IP", "Src Port", "Dest IP", "Dst Port", "Proto", "Len", "Flags")
        )
        self.packet_table.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))

        right_top = ctk.CTkFrame(body, corner_radius=18)
        right_top.grid(row=1, column=1, sticky="nsew", padx=(8, 14), pady=(0, 14))
        right_top.grid_rowconfigure(1, weight=1)
        right_top.grid_rowconfigure(3, weight=1)
        right_top.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            right_top,
            text="Protocol Distribution",
            font=ctk.CTkFont(size=18, weight="bold")
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 8))

        self.figure = Figure(figsize=(5, 2.8), dpi=100)
        self.ax = self.figure.add_subplot(111)
        self.ax.set_facecolor("#1f1f1f")
        self.figure.patch.set_facecolor("#1f1f1f")

        self.chart_canvas = FigureCanvasTkAgg(self.figure, master=right_top)
        self.chart_canvas.get_tk_widget().grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 10))

        ctk.CTkLabel(
            right_top,
            text="Alerts",
            font=ctk.CTkFont(size=18, weight="bold")
        ).grid(row=2, column=0, sticky="w", padx=16, pady=(8, 8))

        self.alert_table = self._create_table(
            right_top,
            columns=("time", "type", "source", "details"),
            headings=("Time", "Type", "Source", "Details")
        )
        self.alert_table.grid(row=3, column=0, sticky="nsew", padx=14, pady=(0, 14))

    def _create_stat_card(self, parent, column, title, value):
        card = ctk.CTkFrame(parent, corner_radius=18)
        card.grid(row=0, column=column, sticky="ew", padx=8)

        ctk.CTkLabel(
            card,
            text=title,
            font=ctk.CTkFont(size=14)
        ).pack(anchor="w", padx=16, pady=(14, 4))

        value_label = ctk.CTkLabel(
            card,
            text=value,
            font=ctk.CTkFont(size=28, weight="bold")
        )
        value_label.pack(anchor="w", padx=16, pady=(0, 14))
        return value_label

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
        style.map("Treeview", background=[("selected", "#1f538d")])

        tree = ttk.Treeview(container, columns=columns, show="headings")
        y_scroll = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
        x_scroll = ttk.Scrollbar(container, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        for col, heading in zip(columns, headings):
            tree.heading(col, text=heading)
            tree.column(col, width=115, anchor="center")

        tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")

        container.tree = tree
        return container

    # -------------------------
    # Capture control
    # -------------------------
    def start_capture(self):
        if self.gui_capture_running or self.monitor.capture_running:
            return

        self.current_mode = "live"
        self.packet_log.clear()
        self.alert_log.clear()

        self.gui_capture_running = True
        self.capture_start_time = time.time()
        self.frozen_uptime = 0

        self.status_label.configure(text="Status: Running")
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.upload_button.configure(state="disabled")

        self.capture_thread = threading.Thread(target=self.monitor.start, daemon=True)
        self.capture_thread.start()

    def stop_capture(self):
        if not self.gui_capture_running and not self.monitor.capture_running:
            return

        if self.gui_capture_running and self.capture_start_time is not None:
            self.frozen_uptime = int(time.time() - self.capture_start_time)

        self.gui_capture_running = False
        self.monitor.stop()

        self.status_label.configure(text="Status: Stopped")
        self.card_uptime.configure(text=f"{self.frozen_uptime}s")
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.upload_button.configure(state="normal")

    def upload_pcap(self):
        if self.gui_capture_running or self.monitor.capture_running:
            messagebox.showwarning("Capture Running", "Stop live capture before uploading a PCAP file.")
            return

        file_path = filedialog.askopenfilename(
            title="Select PCAP File",
            filetypes=[
                ("PCAP files", "*.pcap *.pcapng"),
                ("All files", "*.*")
            ]
        )

        if not file_path:
            return

        self.current_mode = "pcap"
        self.packet_log.clear()
        self.alert_log.clear()
        self.pcap_stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "total_alerts": 0,
            "tracked_flows": 0,
            "protocol_counter": {}
        }

        self.status_label.configure(text="Status: Analyzing PCAP...")
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="disabled")
        self.upload_button.configure(state="disabled")
        self.card_uptime.configure(text="Offline")

        self.analysis_thread = threading.Thread(
            target=self._run_pcap_analysis,
            args=(file_path,),
            daemon=True
        )
        self.analysis_thread.start()

    def _run_pcap_analysis(self, file_path):
        try:
            result = self.pcap_analyzer.analyze(file_path)

            self.after(0, lambda: self._apply_pcap_results(result))
        except Exception as exc:
            self.after(0, lambda: self._handle_pcap_error(str(exc)))

    def _apply_pcap_results(self, result):
        self.packet_log.clear()
        self.alert_log.clear()

        for row in result["packets"]:
            self.packet_log.append(row)

        for row in result["alerts"]:
            self.alert_log.append(row)

        self.pcap_stats = result["stats"]

        self.status_label.configure(text="Status: PCAP Loaded")
        self.start_button.configure(state="normal")
        self.upload_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.card_uptime.configure(text="Offline")

    def _handle_pcap_error(self, error_message):
        self.status_label.configure(text="Status: PCAP Error")
        self.start_button.configure(state="normal")
        self.upload_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        messagebox.showerror("PCAP Analysis Error", error_message)

    # -------------------------
    # Dashboard refresh
    # -------------------------
    def _update_dashboard(self):
        if self.current_mode == "live":
            stats = self.monitor.get_stats()

            self.card_packets.configure(text=str(stats["total_packets"]))
            self.card_bytes.configure(text=str(stats["total_bytes"]))
            self.card_alerts.configure(text=str(stats["total_alerts"]))
            self.card_flows.configure(text=str(stats["tracked_flows"]))

            if self.gui_capture_running and self.capture_start_time is not None:
                elapsed = int(time.time() - self.capture_start_time)
                self.card_uptime.configure(text=f"{elapsed}s")
            else:
                self.card_uptime.configure(text=f"{self.frozen_uptime}s")

            self._refresh_protocol_chart(stats["protocol_counter"])

        else:
            self.card_packets.configure(text=str(self.pcap_stats["total_packets"]))
            self.card_bytes.configure(text=str(self.pcap_stats["total_bytes"]))
            self.card_alerts.configure(text=str(self.pcap_stats["total_alerts"]))
            self.card_flows.configure(text=str(self.pcap_stats["tracked_flows"]))
            self.card_uptime.configure(text="Offline")

            self._refresh_protocol_chart(self.pcap_stats["protocol_counter"])

        self._refresh_packet_table()
        self._refresh_alert_table()

        self.after(1000, self._update_dashboard)

    def _refresh_packet_table(self):
        tree = self.packet_table.tree
        for item in tree.get_children():
            tree.delete(item)

        for row in list(self.packet_log):
            tree.insert("", "end", values=row)

    def _refresh_alert_table(self):
        tree = self.alert_table.tree
        for item in tree.get_children():
            tree.delete(item)

        for row in list(self.alert_log):
            tree.insert("", "end", values=row)

    def _refresh_protocol_chart(self, protocol_counter):
        self.ax.clear()
        self.ax.set_facecolor("#1f1f1f")

        labels = list(protocol_counter.keys()) or ["No Data"]
        values = list(protocol_counter.values()) or [0]

        self.ax.bar(labels, values)
        self.ax.set_title("Packets by Protocol", color="white", fontsize=11)
        self.ax.tick_params(axis="x", colors="white")
        self.ax.tick_params(axis="y", colors="white")

        for spine in self.ax.spines.values():
            spine.set_color("white")

        self.figure.tight_layout()
        self.chart_canvas.draw()


if __name__ == "__main__":
    app = NIDSGUI()
    app.mainloop()