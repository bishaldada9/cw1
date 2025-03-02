import ttkbootstrap as ttk
import tkinter as tk
from tkinter import scrolledtext, messagebox
import scapy.all as scapy
from scapy.all import AsyncSniffer
from datetime import datetime

class IDSApp(ttk.Window):
    def __init__(self):
        # Using a modern flat theme, e.g. "litera"
        super().__init__(themename="litera")
        self.title("IDS system")
        self.geometry("1100x700")
        
        # IDS state and detection thresholds.
        self.sniffing = False
        self.paused = False
        self.sniffer = None
        self.packet_count = {}  # {src_ip: [timestamps]}
        self.ip_ports = {}      # {src_ip: [(timestamp, port)]}
        self.total_packets = 0
        self.total_anomalies = 0
        self.log_messages = []  # List for log entries

        self.time_threshold = 60   # seconds window
        self.count_threshold = 10  # packets within time window
        self.scan_threshold = 5    # unique ports within time window

        self.create_widgets()
        self.update_logs()
        self.update_status_bar()

    def create_widgets(self):
        # --- Control Frame ---
        control_frame = ttk.Frame(self, padding=10)
        control_frame.pack(side=tk.TOP, fill=tk.X)
        
        ttk.Label(control_frame, text="Interface:").pack(side=tk.LEFT, padx=(0,5))
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(control_frame, textvariable=self.interface_var, width=20)
        self.interface_combo.pack(side=tk.LEFT, padx=(0,15))
        self.load_interfaces()
        
        ttk.Label(control_frame, text="Protocol:").pack(side=tk.LEFT, padx=(0,5))
        self.filter_var = tk.StringVar(value="All")
        self.filter_combo = ttk.Combobox(control_frame, textvariable=self.filter_var, width=10,
                                          values=["All", "TCP", "UDP", "ICMP"])
        self.filter_combo.pack(side=tk.LEFT, padx=(0,15))
        
        self.start_button = ttk.Button(control_frame, text="Start IDS", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=5)
        self.stop_button = ttk.Button(control_frame, text="Stop IDS", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.pause_button = ttk.Button(control_frame, text="Pause IDS", command=self.toggle_pause, state=tk.DISABLED)
        self.pause_button.pack(side=tk.LEFT, padx=5)

        # --- Notebook ---
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tab 1: Packets
        self.tab_packets = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_packets, text="Packets")
        self.create_packets_tab(self.tab_packets)
        
        # Tab 2: Logs
        self.tab_logs = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab_logs, text="Logs")
        self.create_logs_tab(self.tab_logs)

        # --- Status Bar ---
        self.status_var = tk.StringVar(value="Status: Idle | Packets: 0 | Anomalies: 0")
        self.status_bar = ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w", padding=5)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def create_packets_tab(self, parent):
        columns = ("Source", "Destination", "Protocol", "Port", "Threat", "Details")
        self.tree = ttk.Treeview(parent, columns=columns, show="headings", height=20)
        for col in columns:
            self.tree.heading(col, text=col)
        self.tree.column("Source", width=150, anchor="center")
        self.tree.column("Destination", width=150, anchor="center")
        self.tree.column("Protocol", width=80, anchor="center")
        self.tree.column("Port", width=80, anchor="center")
        self.tree.column("Threat", width=120, anchor="center")
        self.tree.column("Details", width=300, anchor="w")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def create_logs_tab(self, parent):
        self.log_text = scrolledtext.ScrolledText(parent, wrap=tk.WORD, font=("Consolas", 10))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.configure(state="disabled")

    def load_interfaces(self):
        try:
            interfaces = scapy.get_if_list()
            self.interface_combo['values'] = interfaces
            if interfaces:
                self.interface_var.set(interfaces[0])
            else:
                messagebox.showerror("Error", "No network interfaces found!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load interfaces: {e}")

    def start_sniffing(self):
        interface = self.interface_var.get().strip()
        if not interface:
            messagebox.showerror("Error", "No network interface selected!")
            return
        self.sniffing = True
        self.paused = False
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.pause_button.config(state=tk.NORMAL, text="Pause IDS")
        self.sniffer = AsyncSniffer(iface=interface, prn=self.packet_callback, store=False)
        self.sniffer.start()
        self.update_status("Sniffing...")

    def stop_sniffing(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
        self.sniffing = False
        self.paused = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.pause_button.config(state=tk.DISABLED)
        self.update_status("Stopped")

    def toggle_pause(self):
        if not self.paused:
            if self.sniffer:
                self.sniffer.stop()
                self.sniffer = None
            self.paused = True
            self.pause_button.config(text="Resume IDS")
            self.update_status("Paused")
        else:
            interface = self.interface_var.get().strip()
            if interface:
                self.sniffer = AsyncSniffer(iface=interface, prn=self.packet_callback, store=False)
                self.sniffer.start()
                self.paused = False
                self.pause_button.config(text="Pause IDS")
                self.update_status("Sniffing...")

    def update_status(self, status_text):
        self.status_var.set(f"Status: {status_text} | Packets: {self.total_packets} | Anomalies: {self.total_anomalies}")

    def update_status_bar(self):
        self.update_status("")
        self.after(2000, self.update_status_bar)

    def update_logs(self):
        if self.log_messages:
            self.log_text.configure(state="normal")
            for msg in self.log_messages:
                self.log_text.insert(tk.END, msg + "\n")
            self.log_text.configure(state="disabled")
            self.log_text.yview_moveto(1)
            self.log_messages.clear()
        self.after(2000, self.update_logs)

    def packet_callback(self, packet):
        try:
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                proto_num = packet[scapy.IP].proto
                protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_num, "Other")
                port = "N/A"
                if protocol == "TCP" and packet.haslayer(scapy.TCP):
                    port = packet[scapy.TCP].dport
                elif protocol == "UDP" and packet.haslayer(scapy.UDP):
                    port = packet[scapy.UDP].dport
                if self.filter_var.get() != "All" and self.filter_var.get() != protocol:
                    return
                threat_level, details = self.detect_anomaly(src_ip, protocol, port)
                self.after(0, lambda: self.process_packet(src_ip, dst_ip, protocol, port, threat_level, details))
        except Exception as e:
            print(f"Error in packet_callback: {e}")

    def process_packet(self, src_ip, dst_ip, protocol, port, threat, details):
        self.total_packets += 1
        if threat in ["Suspicious", "High Threat"]:
            self.total_anomalies += 1
        self.tree.insert("", "end", values=(src_ip, dst_ip, protocol, port, threat, details))
        log_entry = f"[{datetime.now().strftime('%H:%M:%S')}] {protocol} packet from {src_ip} to {dst_ip} | Port: {port} | Threat: {threat} | {details}"
        self.log_messages.append(log_entry)
        self.update_status("Sniffing...")

    def detect_anomaly(self, src_ip, protocol, port):
        anomalies = 0
        triggers = []
        now = datetime.now()
        # Rule 1: Connection frequency.
        self.packet_count.setdefault(src_ip, [])
        self.packet_count[src_ip].append(now)
        recent = [t for t in self.packet_count[src_ip] if (now - t).total_seconds() < self.time_threshold]
        self.packet_count[src_ip] = recent
        if len(recent) > self.count_threshold:
            anomalies += 1
            triggers.append(f"High frequency ({len(recent)}/{self.count_threshold})")
        # Rule 2: Suspicious ports.
        suspicious_ports = {23: "Telnet", 3389: "RDP", 5900: "VNC"}
        if protocol in ["TCP", "UDP"] and port != "N/A":
            try:
                p = int(port)
                if p in suspicious_ports:
                    anomalies += 1
                    triggers.append(f"Suspicious port {p} ({suspicious_ports[p]})")
            except Exception:
                pass
        # Rule 3: Port scanning (many unique ports).
        self.ip_ports.setdefault(src_ip, [])
        self.ip_ports[src_ip].append((now, port))
        self.ip_ports[src_ip] = [(t, p) for (t, p) in self.ip_ports[src_ip] if (now - t).total_seconds() < self.time_threshold]
        unique_ports = {p for (t, p) in self.ip_ports[src_ip] if p != "N/A"}
        if len(unique_ports) > self.scan_threshold:
            anomalies += 1
            triggers.append(f"Port scanning ({len(unique_ports)} unique ports)")
        
        if anomalies >= 2:
            threat = "High Threat"
        elif anomalies == 1:            
            threat = "Suspicious"
        else:
            threat = "Normal"
        details = "; ".join(triggers) if triggers else "None"
        return threat, details

if __name__ == "__main__":
    app = IDSApp()
    app.mainloop()
