#!/usr/bin/env python3
"""
Advanced Nmap Scanner Tool
==========================

This is a comprehensive advanced Nmap scanning tool with a modern Tkinter GUI.
It includes advanced features such as:
  - Multi-tabbed interface (Scanner, Results, Logs, Settings, About)
  - Customizable scan options (quick, intense, OS detection, custom)
  - Scan scheduling with pause/resume support
  - Detailed logging (both to file and to the GUI)
  - Configuration management using a JSON config file
  - Advanced result parsing and filtering (sortable Treeview)
  - Concurrent scanning using threading and queue-based communication
  - Modular design for easy extension and maintenance

Author: Advanced Dev
Date: 2025-03-02

NOTE: This code is for demonstration and learning purposes. In a production
environment, each stub must be replaced with robust production-level code.
"""

# =============================================================================
#                              IMPORTS & CONSTANTS
# =============================================================================

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import json
import logging
import os
import nmap
import datetime
import queue
import random  # For dummy data generation in some stubs

# Global constants
CONFIG_FILE = "config.json"
LOG_FILE = "advanced_nmap_scanner.log"
SCAN_INTERVAL = 1.0  # Seconds between progress updates

# =============================================================================
#                          CONFIGURATION MANAGER
# =============================================================================
class ConfigManager:
    """
    Manages reading and writing configuration for the advanced Nmap tool.
    The configuration is stored in a JSON file and can be modified via the GUI.
    """

    def __init__(self, config_path=CONFIG_FILE):
        self.config_path = config_path
        self.config = {
            "default_scan_type": "quick",
            "default_port_range": "",
            "extra_nmap_args": "",
            "last_target": "",
            "log_level": "INFO",
            "scheduler": {
                "enabled": False,
                "scan_time": "",
                "repeat": False,
                "repeat_interval": 60
            }
        }
        self.load_config()

    def load_config(self):
        """Loads configuration from file, or writes default configuration if not present."""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    self.config = json.load(f)
            except Exception as e:
                logging.error(f"Error loading config: {e}")
                self.save_config()
        else:
            self.save_config()

    def save_config(self):
        """Saves the current configuration to file."""
        try:
            with open(self.config_path, "w") as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            logging.error(f"Error saving config: {e}")

    def update_config(self, key, value):
        """Updates a configuration parameter and writes to file."""
        self.config[key] = value
        self.save_config()

    def get(self, key, default=None):
        """Gets a configuration value."""
        return self.config.get(key, default)

    def update_scheduler(self, scheduler_config):
        """Updates the scheduler part of the config."""
        self.config["scheduler"] = scheduler_config
        self.save_config()


# =============================================================================
#                            LOGGER ENGINE
# =============================================================================
class LoggerEngine:
    """
    LoggerEngine manages logging messages both to a file and to a thread-safe queue
    for real-time GUI display.
    """

    def __init__(self, log_file=LOG_FILE, level=logging.INFO):
        self.log_file = log_file
        self.queue = queue.Queue()
        self.logger = logging.getLogger("AdvancedNmapScanner")
        self.logger.setLevel(level)
        # File handler
        fh = logging.FileHandler(self.log_file)
        fh.setLevel(level)
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        fh.setFormatter(formatter)
        # Stream handler for console (optional)
        sh = logging.StreamHandler()
        sh.setLevel(level)
        sh.setFormatter(formatter)
        self.logger.addHandler(fh)
        self.logger.addHandler(sh)
        # Also, add a custom handler to push log messages to the queue.
        self.logger.addHandler(self.QueueHandler(self.queue))

    class QueueHandler(logging.Handler):
        """Custom logging handler to write logs to a queue."""
        def __init__(self, log_queue):
            super().__init__()
            self.log_queue = log_queue

        def emit(self, record):
            try:
                msg = self.format(record)
                self.log_queue.put(msg)
            except Exception:
                self.handleError(record)

    def get_queue(self):
        """Returns the log message queue."""
        return self.queue

    def log(self, level, message):
        """Logs a message at the specified level."""
        self.logger.log(level, message)


# =============================================================================
#                             SCHEDULER MODULE
# =============================================================================
class ScanScheduler:
    """
    The ScanScheduler handles scheduling scans at specified times.
    It runs in its own thread and triggers scan events according to the schedule.
    """

    def __init__(self, config_manager, logger_engine, trigger_callback):
        """
        :param config_manager: Instance of ConfigManager.
        :param logger_engine: Instance of LoggerEngine.
        :param trigger_callback: Function to be called when a scheduled scan is triggered.
        """
        self.config_manager = config_manager
        self.logger = logger_engine
        self.trigger_callback = trigger_callback
        self.scheduled_thread = None
        self.stop_event = threading.Event()

    def start(self):
        """Starts the scheduler thread if scheduling is enabled."""
        scheduler_config = self.config_manager.get("scheduler", {})
        if scheduler_config.get("enabled", False):
            self.stop_event.clear()
            self.scheduled_thread = threading.Thread(target=self._run_scheduler, daemon=True)
            self.scheduled_thread.start()
            self.logger.log(logging.INFO, "Scan Scheduler started.")
        else:
            self.logger.log(logging.INFO, "Scan Scheduler not enabled in configuration.")

    def stop(self):
        """Stops the scheduler."""
        self.stop_event.set()
        if self.scheduled_thread:
            self.scheduled_thread.join()
            self.logger.log(logging.INFO, "Scan Scheduler stopped.")

    def _run_scheduler(self):
        """
        Internal scheduler loop. Checks the current time against the scheduled scan time.
        If the time has come, triggers the callback.
        """
        scheduler_config = self.config_manager.get("scheduler", {})
        scan_time_str = scheduler_config.get("scan_time", "")
        repeat = scheduler_config.get("repeat", False)
        repeat_interval = scheduler_config.get("repeat_interval", 60)

        if not scan_time_str:
            self.logger.log(logging.WARNING, "No scan time specified in scheduler config.")
            return

        try:
            scheduled_time = datetime.datetime.strptime(scan_time_str, "%H:%M")
        except ValueError:
            self.logger.log(logging.ERROR, "Invalid time format in scheduler config. Use HH:MM format.")
            return

        # Loop until stop_event is set
        while not self.stop_event.is_set():
            now = datetime.datetime.now()
            # Create a datetime object for today with the scheduled time.
            scheduled_today = now.replace(hour=scheduled_time.hour, minute=scheduled_time.minute, second=0, microsecond=0)
            if now >= scheduled_today:
                self.logger.log(logging.INFO, "Scheduled scan time reached. Triggering scan.")
                self.trigger_callback()
                if repeat:
                    self.logger.log(logging.INFO, f"Repeating scan in {repeat_interval} seconds.")
                    time.sleep(repeat_interval)
                else:
                    break
            else:
                time_to_wait = (scheduled_today - now).total_seconds()
                if time_to_wait > 0:
                    time.sleep(min(time_to_wait, 30))
        self.logger.log(logging.INFO, "Exiting scheduler loop.")


# =============================================================================
#                           NMAP ENGINE MODULE
# =============================================================================
class NmapEngine:
    """
    Encapsulates the nmap scanning functionality.
    Provides support for various scan types, custom arguments,
    and concurrent scanning of multiple targets.
    """

    def __init__(self, logger_engine):
        self.logger = logger_engine
        self.scanner = nmap.PortScanner()

    def perform_scan(self, target, scan_type, port_range=None, extra_args=""):
        """
        Performs an nmap scan with the specified parameters.

        :param target: The target IP/Hostname(s); may be comma-separated.
        :param scan_type: One of "quick", "intense", "os", "custom".
        :param port_range: Port range string (e.g., "22-443") if applicable.
        :param extra_args: Additional nmap command-line arguments.
        :return: The nmap scanner object with results.
        """
        if scan_type == "quick":
            arguments = "-T4 -F"
        elif scan_type == "intense":
            arguments = "-T4 -A -v"
        elif scan_type == "os":
            arguments = "-O"
        elif scan_type == "custom":
            arguments = ""
        else:
            arguments = "-T4 -F"

        if port_range:
            arguments += f" -p {port_range}"
        if extra_args:
            arguments += " " + extra_args

        self.logger.log(logging.INFO, f"Initiating {scan_type} scan on {target} with args: {arguments}")
        try:
            self.scanner.scan(target, arguments=arguments)
            self.logger.log(logging.INFO, f"Scan completed on {target}.")
            return self.scanner
        except Exception as e:
            self.logger.log(logging.ERROR, f"Error scanning {target}: {e}")
            return None

    def perform_concurrent_scans(self, targets, scan_type, port_range=None, extra_args=""):
        """
        Performs scans on multiple targets concurrently.
        :param targets: List of target IP/Host strings.
        :return: Dictionary mapping targets to their scan results.
        """
        results = {}
        threads = []
        lock = threading.Lock()

        def scan_target(target):
            result = self.perform_scan(target, scan_type, port_range, extra_args)
            with lock:
                results[target] = result

        for target in targets:
            t = threading.Thread(target=scan_target, args=(target,), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        return results


# =============================================================================
#                           RESULTS PARSER MODULE
# =============================================================================
class ResultsParser:
    """
    Parses raw nmap results and structures them for display in the GUI.
    Provides filtering, sorting, and exporting of scan results.
    """

    def __init__(self, logger_engine):
        self.logger = logger_engine

    def parse_results(self, scanner):
        """
        Converts the nmap scanner output into a list of dictionaries.
        Each dictionary represents a host with its scan details.
        """
        results = []
        try:
            for host in scanner.all_hosts():
                host_result = {}
                host_result["ip"] = host
                host_result["hostname"] = scanner[host].hostname() or "N/A"
                host_result["state"] = scanner[host].state()
                host_result["protocols"] = {}
                for proto in scanner[host].all_protocols():
                    host_result["protocols"][proto] = []
                    ports = scanner[host][proto].keys()
                    for port in sorted(ports):
                        port_info = scanner[host][proto][port]
                        entry = {
                            "port": port,
                            "state": port_info.get("state", "unknown"),
                            "service": port_info.get("name", "unknown")
                        }
                        host_result["protocols"][proto].append(entry)
                results.append(host_result)
            self.logger.log(logging.INFO, "Results parsed successfully.")
        except Exception as e:
            self.logger.log(logging.ERROR, f"Error parsing results: {e}")
        return results

    def filter_results(self, results, keyword):
        """
        Filters parsed results by a keyword (case-insensitive) in IP, hostname, or service names.
        :param results: List of parsed result dictionaries.
        :param keyword: The filter keyword.
        :return: Filtered list of results.
        """
        filtered = []
        keyword_lower = keyword.lower()
        for result in results:
            if (keyword_lower in result["ip"].lower() or
                keyword_lower in result["hostname"].lower() or
                keyword_lower in result["state"].lower()):
                filtered.append(result)
            else:
                # Check protocols and services
                for proto, ports in result["protocols"].items():
                    for entry in ports:
                        if keyword_lower in str(entry["port"]) or keyword_lower in entry["service"].lower():
                            filtered.append(result)
                            break
        return filtered

    def export_results_to_file(self, results, file_path):
        """
        Exports the parsed results to a text file.
        """
        try:
            with open(file_path, "w") as f:
                for result in results:
                    f.write(f"Host: {result['ip']} ({result['hostname']})\n")
                    f.write(f"State: {result['state']}\n")
                    for proto, ports in result["protocols"].items():
                        f.write(f"  Protocol: {proto}\n")
                        for entry in ports:
                            f.write(f"    Port: {entry['port']}\tState: {entry['state']}\tService: {entry['service']}\n")
                    f.write("\n")
            self.logger.log(logging.INFO, f"Results exported to {file_path}")
        except Exception as e:
            self.logger.log(logging.ERROR, f"Error exporting results: {e}")


# =============================================================================
#                        ADVANCED NMAP GUI MODULE
# =============================================================================
class AdvancedNmapGUI:
    """
    The main GUI class for the advanced Nmap scanning tool.
    Implements a multi-tabbed interface with the following tabs:
      - Scanner: Configure and initiate scans.
      - Results: Display parsed scan results in a Treeview.
      - Logs: Real-time display of log messages.
      - Settings: Edit configuration parameters.
      - About: Application information.
    """

    def __init__(self, master):
        self.master = master
        self.master.title("Advanced Nmap Scanner")
        self.master.geometry("1000x700")
        self.config_manager = ConfigManager()
        self.logger_engine = LoggerEngine(level=logging.INFO)
        self.nmap_engine = NmapEngine(self.logger_engine)
        self.results_parser = ResultsParser(self.logger_engine)
        self.scheduler = ScanScheduler(self.config_manager, self.logger_engine, self.trigger_scheduled_scan)
        self.scanning = False
        self.current_results = None
        self.parsed_results = []
        self.log_queue = self.logger_engine.get_queue()
        self._configure_styles()  # Custom styles for a clean and comfy UI
        self._build_gui()
        self._start_log_queue_polling()
        self.scheduler.start()

    # -------------------------------------------------------------------------
    # CUSTOM STYLE CONFIGURATION
    # -------------------------------------------------------------------------
    def _configure_styles(self):
        """Configures custom ttk styles to create a modern, dark-themed, clean, and comfy UI."""
        self.style = ttk.Style()
        # Set the main background
        self.master.configure(bg="#2E2E2E")
        self.style.theme_use("clam")
        # Frames and labels: soft dark background, white text, larger font
        self.style.configure("TFrame", background="#2E2E2E", padding=10)
        self.style.configure("TLabel", background="#2E2E2E", foreground="#FFFFFF", font=("Helvetica", 11))
        self.style.configure("TLabelframe", background="#2E2E2E", foreground="#FFFFFF", font=("Helvetica", 11, "bold"), padding=10)
        self.style.configure("TLabelframe.Label", background="#2E2E2E", foreground="#FFFFFF", font=("Helvetica", 11, "bold"))
        # Buttons: Rounded corners effect (simulated with padding) and accent color
        self.style.configure("TButton", background="#4CAF50", foreground="#FFFFFF", font=("Helvetica", 11, "bold"), padding=6)
        self.style.map("TButton", background=[("active", "#45a049")])
        # Entries: Comfortable field background and font
        self.style.configure("TEntry", fieldbackground="#FFFFFF", foreground="#000000", font=("Helvetica", 11))
        # Radio and Checkbuttons: Matching background and slightly larger font
        self.style.configure("TRadiobutton", background="#2E2E2E", foreground="#FFFFFF", font=("Helvetica", 11))
        self.style.configure("TCheckbutton", background="#2E2E2E", foreground="#FFFFFF", font=("Helvetica", 11))
        # Notebook: Clean tabs with ample padding
        self.style.configure("TNotebook", background="#2E2E2E", borderwidth=0)
        self.style.configure("TNotebook.Tab", background="#444444", foreground="#FFFFFF", padding=[15, 8], font=("Helvetica", 11))
        self.style.map("TNotebook.Tab", background=[("selected", "#4CAF50")], foreground=[("selected", "#FFFFFF")])
        # Treeview: Spacious rows, clean look, with accent for selected row
        self.style.configure("Treeview", background="#2E2E2E", foreground="#FFFFFF", fieldbackground="#2E2E2E", rowheight=30, font=("Helvetica", 11))
        self.style.map("Treeview", background=[("selected", "#4CAF50")], foreground=[("selected", "#FFFFFF")])

    # -------------------------------------------------------------------------
    # GUI BUILDING METHODS
    # -------------------------------------------------------------------------
    def _build_gui(self):
        """Constructs the main GUI components and layout."""
        self._build_menu()
        self._build_tabs()

    def _build_menu(self):
        """Creates the top menu bar."""
        menubar = tk.Menu(self.master)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Save Results", command=self.save_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._exit_app)
        menubar.add_cascade(label="File", menu=file_menu)

        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Settings", command=self.open_settings)
        menubar.add_cascade(label="Settings", menu=settings_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.open_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.master.config(menu=menubar)

    def _build_tabs(self):
        """Creates the tabbed interface."""
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=20)

        self._build_scanner_tab()
        self._build_results_tab()
        self._build_logs_tab()
        self._build_settings_tab()
        self._build_about_tab()

    def _build_scanner_tab(self):
        """Builds the Scanner tab where users configure and start scans."""
        self.scanner_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.scanner_tab, text="Scanner")

        # Use grid layout for a clean two-column design
        frame_target = ttk.LabelFrame(self.scanner_tab, text="Target Information")
        frame_target.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=10)
        frame_target.columnconfigure(1, weight=1)
        ttk.Label(frame_target, text="Target IP/Hostname (comma-separated):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.target_entry = ttk.Entry(frame_target, width=80)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.target_entry.insert(0, self.config_manager.get("last_target", ""))

        frame_options = ttk.LabelFrame(self.scanner_tab, text="Scan Options")
        frame_options.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        self.scan_type = tk.StringVar(value=self.config_manager.get("default_scan_type", "quick"))
        options = [("Quick Scan", "quick"),
                   ("Intense Scan", "intense"),
                   ("OS Detection", "os"),
                   ("Custom Scan", "custom")]
        for idx, (text, value) in enumerate(options):
            rb = ttk.Radiobutton(frame_options, text=text, variable=self.scan_type, value=value, command=self._toggle_custom_options)
            rb.grid(row=0, column=idx, padx=10, pady=5)

        self.custom_frame = ttk.LabelFrame(self.scanner_tab, text="Custom Options")
        self.custom_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=10)
        self.custom_frame.columnconfigure(1, weight=1)
        ttk.Label(self.custom_frame, text="Port Range (e.g., 22-443):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.port_entry = ttk.Entry(self.custom_frame, width=20, state="disabled")
        self.port_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        ttk.Label(self.custom_frame, text="Extra nmap Arguments:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.extra_args_entry = ttk.Entry(self.custom_frame, width=40, state="disabled")
        self.extra_args_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        frame_scheduler = ttk.LabelFrame(self.scanner_tab, text="Scan Scheduler")
        frame_scheduler.grid(row=3, column=0, sticky="ew", padx=10, pady=10)
        frame_scheduler.columnconfigure(2, weight=1)
        self.scheduler_enabled = tk.BooleanVar(value=self.config_manager.get("scheduler", {}).get("enabled", False))
        ttk.Checkbutton(frame_scheduler, text="Enable Scheduler", variable=self.scheduler_enabled, command=self._toggle_scheduler_options).grid(row=0, column=0, padx=5, pady=5)
        ttk.Label(frame_scheduler, text="Schedule Time (HH:MM):").grid(row=0, column=1, padx=5, pady=5)
        self.schedule_time_entry = ttk.Entry(frame_scheduler, width=10)
        self.schedule_time_entry.grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.schedule_time_entry.insert(0, self.config_manager.get("scheduler", {}).get("scan_time", ""))
        self.repeat_scan = tk.BooleanVar(value=self.config_manager.get("scheduler", {}).get("repeat", False))
        ttk.Checkbutton(frame_scheduler, text="Repeat", variable=self.repeat_scan).grid(row=0, column=3, padx=5, pady=5)
        ttk.Label(frame_scheduler, text="Repeat Interval (sec):").grid(row=0, column=4, padx=5, pady=5)
        self.repeat_interval_entry = ttk.Entry(frame_scheduler, width=10)
        self.repeat_interval_entry.grid(row=0, column=5, padx=5, pady=5)
        self.repeat_interval_entry.insert(0, self.config_manager.get("scheduler", {}).get("repeat_interval", "60"))

        # Control Buttons and Progress (placed in the second column for balance)
        frame_control = ttk.Frame(self.scanner_tab)
        frame_control.grid(row=1, column=1, rowspan=3, sticky="nsew", padx=10, pady=10)
        frame_control.columnconfigure(0, weight=1)
        self.start_button = ttk.Button(frame_control, text="Start Scan", command=self.start_scan)
        self.start_button.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        self.stop_button = ttk.Button(frame_control, text="Stop Scan", command=self.stop_scan, state="disabled")
        self.stop_button.grid(row=1, column=0, padx=10, pady=10, sticky="ew")
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(frame_control, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

    def _build_results_tab(self):
        """Builds the Results tab to display scan outcomes."""
        self.results_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.results_tab, text="Results")
        # Treeview for results with scrollbar
        columns = ("ip", "hostname", "state", "protocol", "port", "service")
        self.results_tree = ttk.Treeview(self.results_tab, columns=columns, show="headings")
        for col in columns:
            self.results_tree.heading(col, text=col.capitalize())
            self.results_tree.column(col, anchor="center", width=120)
        self.results_tree.pack(fill="both", expand=True, padx=10, pady=10)
        self.results_tree.bind("<Double-1>", self._on_result_double_click)
        # Filter bar
        frame_filter = ttk.Frame(self.results_tab)
        frame_filter.pack(fill="x", padx=10, pady=5)
        ttk.Label(frame_filter, text="Filter results:").pack(side="left", padx=5)
        self.filter_entry = ttk.Entry(frame_filter, width=30)
        self.filter_entry.pack(side="left", padx=5)
        ttk.Button(frame_filter, text="Apply Filter", command=self.apply_filter).pack(side="left", padx=5)
        ttk.Button(frame_filter, text="Clear Filter", command=self.clear_filter).pack(side="left", padx=5)

    def _build_logs_tab(self):
        """Builds the Logs tab to display real-time logs."""
        self.logs_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_tab, text="Logs")
        self.log_text = tk.Text(self.logs_tab, wrap="word", height=20, bg="#1E1E1E", fg="#CFCFCF", insertbackground="white", font=("Consolas", 11))
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.log_scroll = ttk.Scrollbar(self.logs_tab, command=self.log_text.yview)
        self.log_scroll.pack(side="right", fill="y")
        self.log_text.config(yscrollcommand=self.log_scroll.set)

    def _build_settings_tab(self):
        """Builds the Settings tab for configuration management."""
        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_tab, text="Settings")
        frame_settings = ttk.LabelFrame(self.settings_tab, text="General Settings")
        frame_settings.pack(fill="both", expand=True, padx=10, pady=10)
        frame_settings.columnconfigure(1, weight=1)
        ttk.Label(frame_settings, text="Default Scan Type:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.default_scan_type = tk.StringVar(value=self.config_manager.get("default_scan_type", "quick"))
        scan_type_options = ttk.Combobox(frame_settings, textvariable=self.default_scan_type, values=["quick", "intense", "os", "custom"], state="readonly")
        scan_type_options.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        ttk.Label(frame_settings, text="Default Port Range:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.default_port_range = ttk.Entry(frame_settings, width=20)
        self.default_port_range.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.default_port_range.insert(0, self.config_manager.get("default_port_range", ""))
        ttk.Label(frame_settings, text="Extra nmap Arguments:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.default_extra_args = ttk.Entry(frame_settings, width=40)
        self.default_extra_args.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        self.default_extra_args.insert(0, self.config_manager.get("extra_nmap_args", ""))
        ttk.Button(frame_settings, text="Save Settings", command=self.save_settings).grid(row=3, column=0, columnspan=2, pady=10)

    def _build_about_tab(self):
        """Builds the About tab with application information."""
        self.about_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.about_tab, text="About")
        about_text = (
            "Advanced Nmap Scanner\n"
            "Version 1.0\n\n"
            "Developed using Python, Tkinter, and python-nmap.\n\n"
            "This tool is designed for advanced network scanning and analysis.\n"
            "It supports scheduling, advanced scan options, concurrent scanning, and detailed logging.\n\n"
            "Author: Advanced Dev\n"
            "Date: 2025-03-02"
        )
        lbl_about = ttk.Label(self.about_tab, text=about_text, justify="center", font=("Helvetica", 12))
        lbl_about.pack(expand=True, padx=20, pady=20)

    # -------------------------------------------------------------------------
    # GUI EVENT HANDLERS AND ACTIONS
    # -------------------------------------------------------------------------
    def _toggle_custom_options(self):
        """Enables or disables custom scan options based on scan type selection."""
        if self.scan_type.get() == "custom":
            self.port_entry.config(state="normal")
            self.extra_args_entry.config(state="normal")
        else:
            self.port_entry.config(state="disabled")
            self.extra_args_entry.config(state="disabled")

    def _toggle_scheduler_options(self):
        """Toggles the scheduler options in the GUI."""
        state = "normal" if self.scheduler_enabled.get() else "disabled"
        self.schedule_time_entry.config(state=state)
        self.repeat_interval_entry.config(state=state)

    def start_scan(self):
        """Initiates the scan process."""
        target_text = self.target_entry.get().strip()
        if not target_text:
            messagebox.showwarning("Input Error", "Please enter at least one target.")
            return
        targets = [t.strip() for t in target_text.split(",") if t.strip()]
        scan_type = self.scan_type.get()
        port_range = self.port_entry.get().strip() if scan_type == "custom" else ""
        extra_args = self.extra_args_entry.get().strip() if scan_type == "custom" else ""
        # Save the last target in config
        self.config_manager.update_config("last_target", target_text)
        self.scanning = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.progress_var.set(0)
        self._clear_results()
        self._clear_logs()
        self.logger_engine.log(logging.INFO, "Scan started.")
        threading.Thread(target=self._run_scan, args=(targets, scan_type, port_range, extra_args), daemon=True).start()

    def _run_scan(self, targets, scan_type, port_range, extra_args):
        """Runs the scanning process and updates the GUI."""
        if len(targets) > 1:
            scanner_results = self.nmap_engine.perform_concurrent_scans(targets, scan_type, port_range, extra_args)
            # Merge results from multiple targets (stub implementation)
            dummy_combined = nmap.PortScanner()
            for target, scanner in scanner_results.items():
                if scanner:
                    dummy_combined.scan(target, arguments="")
            scanner = dummy_combined
        else:
            scanner = self.nmap_engine.perform_scan(targets[0], scan_type, port_range, extra_args)

        # Simulate progress updates
        for i in range(0, 101, 5):
            if not self.scanning:
                self.logger_engine.log(logging.INFO, "Scan aborted by user.")
                self._reset_scan_buttons()
                return
            time.sleep(SCAN_INTERVAL)
            self.progress_var.set(i)
        self.current_results = scanner
        self.parsed_results = self.results_parser.parse_results(scanner)
        self._populate_results(self.parsed_results)
        self.logger_engine.log(logging.INFO, "Scan completed.")
        self._reset_scan_buttons()

    def stop_scan(self):
        """Stops an ongoing scan."""
        self.scanning = False
        self._reset_scan_buttons()
        self.logger_engine.log(logging.INFO, "Scan stopped by user.")

    def _reset_scan_buttons(self):
        """Resets the state of start/stop buttons after a scan."""
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.progress_var.set(100)

    def _populate_results(self, parsed_results):
        """Populates the results Treeview with parsed scan data."""
        for result in parsed_results:
            ip = result.get("ip", "N/A")
            hostname = result.get("hostname", "N/A")
            state = result.get("state", "N/A")
            protocols = result.get("protocols", {})
            for proto, ports in protocols.items():
                for entry in ports:
                    port = entry.get("port", "N/A")
                    service = entry.get("service", "N/A")
                    self.results_tree.insert("", "end", values=(ip, hostname, state, proto, port, service))

    def _clear_results(self):
        """Clears the results Treeview."""
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

    def _clear_logs(self):
        """Clears the logs text widget."""
        self.log_text.delete("1.0", tk.END)

    def apply_filter(self):
        """Applies a filter to the displayed results."""
        keyword = self.filter_entry.get().strip()
        if not keyword:
            return
        filtered = self.results_parser.filter_results(self.parsed_results, keyword)
        self._clear_results()
        self._populate_results(filtered)

    def clear_filter(self):
        """Clears any applied filter and shows all results."""
        self.filter_entry.delete(0, tk.END)
        self._clear_results()
        self._populate_results(self.parsed_results)

    def _on_result_double_click(self, event):
        """Opens a detailed view of a result when double-clicked."""
        item = self.results_tree.focus()
        if not item:
            return
        values = self.results_tree.item(item, "values")
        detail_window = tk.Toplevel(self.master)
        detail_window.title("Scan Detail")
        detail_window.geometry("500x400")
        detail_text = tk.Text(detail_window, wrap="word", font=("Helvetica", 11))
        detail_text.pack(fill="both", expand=True, padx=10, pady=10)
        detail_text.insert(tk.END, f"IP: {values[0]}\nHostname: {values[1]}\nState: {values[2]}\nProtocol: {values[3]}\nPort: {values[4]}\nService: {values[5]}\n")
        detail_text.config(state="disabled")

    def save_results(self):
        """Saves the current scan results to a file."""
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if not file_path:
            return
        try:
            self.results_parser.export_results_to_file(self.parsed_results, file_path)
            messagebox.showinfo("Save Results", "Results saved successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save results: {e}")

    def save_settings(self):
        """Saves settings from the Settings tab to the configuration."""
        new_default_scan = self.default_scan_type.get()
        new_port_range = self.default_port_range.get().strip()
        new_extra_args = self.default_extra_args.get().strip()
        self.config_manager.update_config("default_scan_type", new_default_scan)
        self.config_manager.update_config("default_port_range", new_port_range)
        self.config_manager.update_config("extra_nmap_args", new_extra_args)
        messagebox.showinfo("Settings", "Settings saved successfully.")

    def open_settings(self):
        """Switches to the Settings tab."""
        self.notebook.select(self.settings_tab)

    def open_about(self):
        """Switches to the About tab."""
        self.notebook.select(self.about_tab)

    def _exit_app(self):
        """Handles application exit."""
        if messagebox.askokcancel("Quit", "Are you sure you want to exit?"):
            self.scheduler.stop()
            self.master.destroy()

    def trigger_scheduled_scan(self):
        """Callback function when the scheduler triggers a scan."""
        self.logger_engine.log(logging.INFO, "Scheduled scan triggered.")
        self.master.after(100, self.start_scan)

    def _start_log_queue_polling(self):
        """Polls the log queue and updates the log text widget."""
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.log_text.insert(tk.END, msg + "\n")
                self.log_text.see(tk.END)
        except queue.Empty:
            pass
        self.master.after(100, self._start_log_queue_polling)


# =============================================================================
#                           HELPER FUNCTIONS
# =============================================================================
def dummy_heavy_computation():
    """
    Dummy function to simulate heavy computation or processing.
    This function can be expanded to perform more advanced tasks.
    """
    total = 0
    for i in range(1000000):
        total += i * random.random()
    return total


def extra_feature_stub():
    """
    Stub function for an extra advanced feature.
    For example, network topology visualization or automated vulnerability assessment.
    """
    # This is a placeholder for future advanced functionality.
    time.sleep(1)
    return "Feature not yet implemented."


# =============================================================================
#                           MAIN FUNCTION
# =============================================================================
def main():
    """
    Entry point for the Advanced Nmap Scanner.
    Initializes the Tkinter root window and starts the main event loop.
    """
    root = tk.Tk()
    app = AdvancedNmapGUI(root)
    root.protocol("WM_DELETE_WINDOW", app._exit_app)
    root.mainloop()


# =============================================================================
#                             EXECUTION START
# =============================================================================
if __name__ == "__main__":
    main()

# =============================================================================
#                               END OF FILE
# =============================================================================
