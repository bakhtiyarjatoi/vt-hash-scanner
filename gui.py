import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from datetime import datetime
import csv
import time
import queue
import threading
import os
import configparser
from scanning import scan_file  # Import scan_file from scanning.py


class HashReputationTool:
    def __init__(self, root):
        self.root = root
        self.api_key = None  # API Key for VirusTotal
        self.hash_list = []  # Store list of hashes to be scanned
        self.scan_results = []
        self.scan_in_progress = False
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.log_queue = queue.Queue()
        self.is_full_screen = False  # Track full-screen state
        self.setup_ui()

        # Load the API key from config.ini
        self.set_api_key()

    def setup_ui(self):
        """Set up the user interface."""
        self.root.title("Hash Reputation Tool")
        self.root.geometry("750x550")
        self.root.resizable(True, True)

        # Set the icon for the window
        if os.path.exists("assets/scan_logo.ico"):
            self.root.iconbitmap("assets/scan_logo.ico")

        # Custom Styles
        style = ttk.Style()
        style.theme_use("clam")

        # Define Button Styles
        self._set_button_styles(style)

        # UI Layout
        self._create_ui_layout()

        # Start updating logs
        self.update_logs()

    def _set_button_styles(self, style):
        """Define styles for buttons."""
        # Insert API Button (Sky Blue)
        style.configure("InsertAPI.TButton", foreground="black", background="skyblue", padding=6, relief="flat")
        style.map("InsertAPI.TButton", background=[("active", "deepskyblue")])

        # File Buttons (Light Purple)
        style.configure("FileControl.TButton", foreground="black", background="lightblue", padding=6, relief="flat")
        style.map("FileControl.TButton", background=[("active", "lightskyblue")])

        # Start Button (Light Green)
        style.configure("StartScan.TButton", foreground="black", background="lightgreen", padding=6, relief="flat")
        style.map("StartScan.TButton", background=[("active", "mediumseagreen")])

        # Stop Button (Light Red)
        style.configure("StopScan.TButton", foreground="black", background="lightcoral", padding=6, relief="flat")
        style.map("StopScan.TButton", background=[("active", "indianred")])

        # Pause/Resume Button (Light Yellow)
        style.configure("PauseResume.TButton", foreground="black", background="lightyellow", padding=6, relief="flat")
        style.map("PauseResume.TButton", background=[("active", "goldenrod")])

    def _create_ui_layout(self):
        """Create the layout of the UI."""
        # API Key Frame
        api_frame = ttk.LabelFrame(self.root, text="API Key", padding=(10, 5))
        api_frame.pack(fill="x", padx=10, pady=5)
        ttk.Button(api_frame, text="Insert API Key", command=self.set_api_key, style="InsertAPI.TButton").pack(side="left", padx=5, pady=5)

        # File Operations Frame
        file_frame = ttk.LabelFrame(self.root, text="File Operations", padding=(10, 5))
        file_frame.pack(fill="x", padx=10, pady=5)
        ttk.Button(file_frame, text="Load File", command=self.load_file, style="FileControl.TButton").pack(side="left", padx=5, pady=5)
        ttk.Button(file_frame, text="Export Results", command=self.export_results, style="FileControl.TButton").pack(side="left", padx=5, pady=5)

        # Scan Control Frame
        scan_frame = ttk.LabelFrame(self.root, text="Scan Control", padding=(10, 5))
        scan_frame.pack(fill="x", padx=10, pady=5)
        ttk.Button(scan_frame, text="Start Scan", command=self.start_scan, style="StartScan.TButton").pack(side="left", padx=5, pady=5)
        self.pause_button = ttk.Button(scan_frame, text="Pause Scan", command=self.toggle_pause, style="PauseResume.TButton")
        self.pause_button.pack(side="left", padx=5, pady=5)
        self.stop_button = ttk.Button(scan_frame, text="Stop Scan", command=self.stop_scan, style="StopScan.TButton")
        self.stop_button.pack(side="left", padx=5, pady=5)
        ttk.Button(scan_frame, text="Toggle Full Screen", command=self.toggle_full_screen, style="FileControl.TButton").pack(side="left", padx=5, pady=5)

        # Progress Frame
        progress_frame = ttk.LabelFrame(self.root, text="Progress", padding=(10, 5))
        progress_frame.pack(fill="x", padx=10, pady=5)
        self.progress_label = ttk.Label(progress_frame, text="Imported Hashes: 0 | Scanned: 0 | Remaining: 0 | 0%", anchor="w")
        self.progress_label.pack(fill="x", padx=5, pady=5)
        self.progress_var = tk.DoubleVar()
        ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100).pack(fill="x", padx=5, pady=5)

        # Logs Frame
        log_frame = ttk.LabelFrame(self.root, text="Logs", padding=(10, 5))
        log_frame.pack(fill="both", expand=True, padx=10, pady=5)
        self.log_text = tk.Text(log_frame, wrap="word", height=10, state="disabled")
        self.log_text.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        log_scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        log_scrollbar.pack(side="right", fill="y")
        self.log_text["yscrollcommand"] = log_scrollbar.set

        # Status Label
        self.status_label = ttk.Label(self.root, text="Status: Ready", anchor="w", foreground="green")
        self.status_label.pack(fill="x", padx=10, pady=5)

        # Footer Label
        footer_label = ttk.Label(self.root, text="Tool made with ❤️ by Bakhtiyar Ahmad. All rights reserved", anchor="center", font=("Arial", 8), foreground="black")
        footer_label.pack(side="bottom", fill="x", padx=10, pady=5)

    def set_api_key(self):
        """Set or load the API key for VirusTotal."""
        config = configparser.ConfigParser()
        try:
            # Check if the config file exists
            if os.path.exists("config.ini"):
                config.read("config.ini")
                
                # Check if the API key exists in the file
                if config.has_section("virustotal") and config.has_option("virustotal", "key"):
                    existing_api_key = config.get("virustotal", "key")
                    if existing_api_key and existing_api_key.strip() and existing_api_key != "YOUR_API_KEY_HERE":
                        self.api_key = existing_api_key
                        messagebox.showinfo("API Key", "API Key loaded successfully from config.ini!")
                        return
                    else:
                        self.log_error("Invalid API key found in config.ini.")
            
            # If no valid API key is found, ask the user for a new key
            new_api_key = simpledialog.askstring("Enter API Key", "Please enter your VirusTotal API key:")
            if new_api_key:
                if not config.has_section("virustotal"):
                    config.add_section("virustotal")
                config.set("virustotal", "key", new_api_key)
                with open("config.ini", "w") as configfile:
                    config.write(configfile)
                self.api_key = new_api_key
                messagebox.showinfo("API Key", "API Key set successfully and saved to config.ini!")
            else:
                messagebox.showerror("Error", "API Key was not set. Please provide a valid key.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while processing the API key: {e}")
            self.log_error(f"Error processing API Key: {e}")

    def load_file(self):
        """Load the hash file into the hash list.""" 
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("CSV Files", "*.csv")]) 
        if file_path: 
            with open(file_path, "r") as file: 
                if file_path.endswith(".txt"): 
                    self.hash_list = [line for line in file.read().splitlines() if line.strip()] 
                elif file_path.endswith(".csv"): 
                    reader = csv.reader(file) 
                    self.hash_list = [row[0] for row in reader if row]  # Avoid empty rows
            self.log_info(f"{len(self.hash_list)} hashes loaded.") 
            self.update_progress(0, len(self.hash_list))

    def update_progress(self, scanned, total):
        """Update the progress bar and remaining hashes label."""
        progress_percent = (scanned / total) * 100
        remaining = total - scanned
        self.progress_var.set(progress_percent)
        self.progress_label.config(
            text=f"Imported Hashes: {scanned} | Scanned: {scanned} | Remaining: {remaining} | {int(progress_percent)}%"
        )

    def start_scan(self):
        """Start scanning the hash list."""
        if not self.api_key:
            messagebox.showerror("Error", "API Key not set. Please set an API key before starting the scan.")
            return

        if not self.hash_list:
            messagebox.showerror("Error", "No hashes loaded. Please load a hash file before scanning.")
            return

        self.scan_in_progress = True
        self.stop_event.clear()
        self.pause_event.clear()
        self.scan_results = []

        self.scan_thread = threading.Thread(target=self._run_scan)
        self.scan_thread.start()

    def _run_scan(self):
        """Scan hashes in the background."""
        scanned = 0
        total = len(self.hash_list)
        self.update_progress(scanned, total)

        for hash_value in self.hash_list:
            if self.stop_event.is_set():
                break
            if self.pause_event.is_set():
                while self.pause_event.is_set():
                    time.sleep(0.5)
            try:
                result = scan_file(self.api_key, hash_value)
                self.scan_results.append(result)
                self.log_info(f"Hash: {hash_value} | {result}")
                scanned += 1
                self.update_progress(scanned, total)
            except Exception as e:
                self.log_error(f"Error scanning hash {hash_value}: {e}")
            time.sleep(0.1)

        self.scan_in_progress = False
        self.log_info("Scan completed.")

    def stop_scan(self):
        """Stop the scan."""
        if self.scan_in_progress:
            self.stop_event.set()
            self.log_info("Scan stopped.")
        else:
            messagebox.showwarning("No Scan", "No scan is currently in progress.")

    def toggle_pause(self):
        """Pause or resume the scan."""
        if self.scan_in_progress:
            if self.pause_event.is_set():
                self.pause_event.clear()
                self.pause_button.config(text="Pause Scan")
                self.log_info("Scan resumed.")
            else:
                self.pause_event.set()
                self.pause_button.config(text="Resume Scan")
                self.log_info("Scan paused.")
        else:
            messagebox.showwarning("No Scan", "No scan is currently in progress.")

    def toggle_full_screen(self):
        """Toggle full screen mode."""
        if self.is_full_screen:
            self.root.attributes("-fullscreen", False)
        else:
            self.root.attributes("-fullscreen", True)
        self.is_full_screen = not self.is_full_screen

    def log_info(self, message):
        """Log an info message with timestamp and color-coded text."""
        self.log_queue.put(self.format_log_message("INFO", message, "green"))
        self.update_logs()

    def log_error(self, message):
        """Log an error message with timestamp and color-coded text."""
        self.log_queue.put(self.format_log_message("ERROR", message, "red"))
        self.update_logs()

    def format_log_message(self, log_level, message, color):
        """Format the log message with timestamp and color."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return {"level": log_level, "message": message, "color": color, "timestamp": timestamp}

    def update_logs(self):
        """Update the log display asynchronously with the log queue."""
        while not self.log_queue.empty():
            log_entry = self.log_queue.get()
            log_message = f"[{log_entry['timestamp']}] [{log_entry['level']}] {log_entry['message']}"
            
            # Insert the log message with appropriate color
            self.log_text.config(state="normal")
            self.log_text.insert(tk.END, log_message + "\n", log_entry["level"])
            self.log_text.config(state="disabled")
            
            # Apply color formatting based on log level
            if log_entry["level"] == "INFO":
                self.log_text.tag_add("info", "1.0", "end")
                self.log_text.tag_config("info", foreground="green")
            elif log_entry["level"] == "ERROR":
                self.log_text.tag_add("error", "1.0", "end")
                self.log_text.tag_config("error", foreground="red")
        
        # Schedule the next update (non-blocking)
        self.root.after(100, self.update_logs)

    def export_results(self):
        """Export the scan results to a CSV file, including VT attributes."""
        if not self.scan_results:
            messagebox.showwarning("No Results", "No scan results to export.")
            return

        # Ask for the save location
        save_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if not save_path:
            return

        try:
            with open(save_path, mode="w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                # Write the header row
                writer.writerow([
                    "Hash", "Magic", "TLSH", "Type Tag", "MD5", "SHA256", "Authentihash",
                    ".NET GUIDs", "File Type", "Probability", "Scan Results", "VT Link"
                ])
                
                for result in self.scan_results:
                    # Ensure result is a dictionary before accessing attributes
                    if isinstance(result, dict):
                        hash_value = result.get("scan_id", "N/A")
                        magic = result.get("magic", "N/A")
                        tlsh = result.get("tlsh", "N/A")
                        type_tag = result.get("type_tag", "N/A")
                        md5 = result.get("md5", "N/A")
                        sha256 = result.get("sha256", "N/A")
                        authentihash = result.get("authentihash", "N/A")
                        dot_net_guids = result.get("dot_net_guids", "N/A")
                        file_type = result.get("file_type", "N/A")
                        probability = result.get("probability", "N/A")

                        # Safely process scan results if it's a dictionary
                        scan_results = "N/A"
                        if isinstance(result.get("scan_results"), dict):
                            scan_results = "; ".join([f"{r.get('engine_name', 'N/A')}: {r.get('result', 'N/A')}" 
                                                    for r in result["scan_results"].values()])

                        vt_link = result.get("permalink", "N/A")

                        # Write the row to CSV
                        writer.writerow([
                            hash_value, magic, tlsh, type_tag, md5, sha256, authentihash,
                            dot_net_guids, file_type, probability, scan_results, vt_link
                        ])
                    else:
                        # Log or handle unexpected data types
                        self.log_info(f"Unexpected result type: {type(result)} - {result}")
                        messagebox.showerror("Export Error", f"Unexpected result type: {type(result)} - {result}")
                        continue

            messagebox.showinfo("Export Successful", f"Scan results successfully exported to {save_path}")
            self.log_info(f"Scan results successfully exported to {save_path}")

        except Exception as e:
            messagebox.showerror("Export Error", f"An error occurred while exporting the results: {e}")
            self.log_info(f"Export Error: {e}")

    def save_logs(self):
        """Save all logs to a text file in the current working directory."""
        try:
            log_file_path = os.path.join(os.getcwd(), "scan_logs.txt")

            # Open the file in append mode to keep existing logs intact
            with open(log_file_path, "a", encoding="utf-8") as log_file:
                while not self.log_queue.empty():
                    log_entry = self.log_queue.get()
                    log_message = f"[{log_entry['timestamp']}] [{log_entry['level']}] {log_entry['message']}\n"
                    log_file.write(log_message)

            messagebox.showinfo("Logs Saved", f"Logs have been saved to {log_file_path}")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while saving logs: {e}")


