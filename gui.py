import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from datetime import datetime
import csv
import time
import queue
import threading
import logging
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
        ttk.Button(scan_frame, text="View History", command=self.view_history, style="FileControl.TButton").pack(side="left", padx=5, pady=5)
        
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

        def is_valid_api_key(api_key):
            """Validate the format of the API key."""
            return len(api_key) == 64

        try:
            # Check if the config file exists
            if os.path.exists("config.ini"):
                config.read("config.ini")
                
                # Check if the API key exists in the file
                if config.has_section("virustotal") and config.has_option("virustotal", "key"):
                    existing_api_key = config.get("virustotal", "key")
                    if existing_api_key and existing_api_key.strip() and existing_api_key != "YOUR_API_KEY_HERE":
                        if is_valid_api_key(existing_api_key.strip()):
                            self.api_key = existing_api_key.strip()
                            messagebox.showinfo("API Key", "API Key loaded successfully from config.ini!")
                            return
                        else:
                            self.log_error("Invalid API key format found in config.ini.")
                            messagebox.showerror("Error", "Invalid API key format found in config.ini.")
                    else:
                        self.log_error("Invalid or missing API key in config.ini.")
                        messagebox.showerror("Error", "Invalid or missing API key in config.ini.")
            
            # Ensure the root window is created and icon is set
            if not hasattr(self, 'root') or self.root is None:
                self.root = tk.Tk()  # Create root window if not created already
                self.root.iconbitmap("assets/config.ico")  # Set the icon for the root window

            # If no valid API key is found, ask the user for a new key
            new_api_key = simpledialog.askstring("Enter API Key", "Please enter your VirusTotal API key:", parent=self.root)

            if new_api_key:
                if is_valid_api_key(new_api_key):
                    if not config.has_section("virustotal"):
                        config.add_section("virustotal")
                    config.set("virustotal", "key", new_api_key)

                    try:
                        with open("config.ini", "w") as configfile:
                            config.write(configfile)
                        self.api_key = new_api_key
                        messagebox.showinfo("API Key", "API Key set successfully and saved to config.ini!")
                    except Exception as e:
                        messagebox.showerror("Error", f"Error writing to config file: {e}")
                        self.log_error(f"Error writing to config file: {e}")
                else:
                    messagebox.showerror("Error", "Invalid API key format. Please provide a valid key.")
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
        # Check if the message contains HTTP error codes like 404, 500, etc.
        error_codes = ["404", "403", "500", "502", "503"]  # Add more error codes as needed
        if any(code in message for code in error_codes):
            # If error code is found in the message, color it red
            self.log_queue.put(self.format_log_message("ERROR", message, "red"))
        else:
            # Default error message formatting (red)
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

        # Check if the user is currently scrolling
        log_text_pos = self.log_text.yview()
        if log_text_pos[1] == 1.0:  # If the user is at the bottom
            self.log_text.see(tk.END)  # Automatically scroll to the bottom
        else:
            # If the user is not at the bottom, don't scroll automatically
            self.root.after(50, self.update_logs)  # Keep trying to update logs in the background

    def export_results(self):
        """Export the scan results to a CSV file, including error responses."""
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

                for idx, result in enumerate(self.scan_results):
                    if not isinstance(result, dict):
                        logging.error(f"Invalid entry at index {idx}: {type(result)} - {result}")
                        continue

                    # Safely extract fields from the result
                    try:
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

                        # Safely handle scan results
                        scan_results = "N/A"
                        if isinstance(result.get("scan_results"), dict):
                            scan_results = "; ".join([
                                f"{r.get('engine_name', 'N/A')}: {r.get('result', 'N/A')}"
                                for r in result["scan_results"].values()
                            ])

                        vt_link = result.get("permalink", "N/A")

                        # Write to CSV
                        writer.writerow([
                            hash_value, magic, tlsh, type_tag, md5, sha256, authentihash,
                            dot_net_guids, file_type, probability, scan_results, vt_link
                        ])
                    except Exception as e:
                        logging.error(f"Error processing result at index {idx}: {e}")
                        continue

            messagebox.showinfo("Export Successful", f"Scan results successfully exported to {save_path}")
            logging.info(f"Scan results successfully exported to {save_path}")

        except PermissionError:
            messagebox.showerror(
                "Export Error", f"Permission denied: {save_path}. Please close the file or choose a different location."
            )
            logging.error(f"Permission denied: {save_path}. File may be open or write access restricted.")
        except Exception as e:
            messagebox.showerror("Export Error", f"An unexpected error occurred: {e}")
            logging.error(f"Unexpected error during export: {e}")

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

    def view_history(self):
        """Open and display the scan results log in a pop-up window with an icon."""
        log_file_path = os.path.join(os.getcwd(), "scan_results.log")
        
        if not os.path.exists(log_file_path):
            messagebox.showerror("Error", "Log file not found.")
            return
        
        try:
            with open(log_file_path, "r", encoding="utf-8") as log_file:
                log_content = log_file.read()
            
            # Create a new top-level window to display the logs
            history_window = tk.Toplevel(self.root)
            history_window.title("Scan History")
            history_window.geometry("800x600")
            
            # Set the window icon from the 'assets' folder
            icon_path = os.path.join(os.getcwd(), "assets", "history_icon.ico")  # Adjusted to assets folder
            if os.path.exists(icon_path):
                history_window.iconbitmap(icon_path)
            else:
                print("Icon file not found in the assets folder, using default window icon.")
            
            # Create a Text widget to display the logs
            log_text = tk.Text(history_window, wrap="word", height=30, width=100)
            log_text.insert(tk.END, log_content)
            log_text.config(state="disabled")  # Make it read-only
            log_text.pack(padx=10, pady=10, expand=True, fill=tk.BOTH)
            
            # Add a scrollbar for better navigation
            scrollbar = ttk.Scrollbar(history_window, orient="vertical", command=log_text.yview)
            scrollbar.pack(side="right", fill="y")
            log_text.config(yscrollcommand=scrollbar.set)

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while reading the log file: {e}")

    def on_closing(self):
        """Handle the window closing event."""
        if self.scan_in_progress:
            confirm = messagebox.askyesno("Confirm Exit", "Scan is still in progress. Do you want to exit?")
            if confirm:
                self.stop_event.set()
                self.root.quit()
        else:
            self.root.quit()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
