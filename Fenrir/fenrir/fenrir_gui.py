# fenrir/fenrir_gui.py
import asyncio
import queue
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, PhotoImage, filedialog
import logging
import os
from PIL import Image, ImageTk

from .logging_config import setup_logging
from .report_manager import ReportManager
# Import all scanner modules
from .modules import *

class FenrirGUI(tk.Tk):
    """Main class for the Fenrir GUI application."""
    def __init__(self):
        super().__init__()
        self.title("Fenrir Security Scanner")
        self.geometry("900x700")
        self.minsize(800, 600)

        self.asset_paths = {
            "icon": "assets/logo.png",
            "logo": "assets/logo.png",
            "background": "assets/background.png"
        }
        
        self.apply_styles()
        self.set_icon()

        self.log_queue = queue.Queue()
        self.logger = setup_logging(log_level=logging.INFO, log_queue=self.log_queue)
        
        self.scan_thread = None
        self.create_widgets()
        self.process_log_queue()
        self.bind("<Configure>", self.on_resize)

    def apply_styles(self):
        """Configures the dark theme for the application."""
        self.style = ttk.Style(self)
        self.style.theme_use('clam')
        dark_bg, light_bg, text_color = "#2e2e2e", "#3c3c3c", "#e0e0e0"
        self.configure(background=dark_bg)
        self.style.configure('.', background=dark_bg, foreground=text_color, fieldbackground=light_bg)
        self.style.configure('TLabel', background=dark_bg, foreground=text_color)
        self.style.configure('TButton', padding=5)
        self.style.configure('TCheckbutton', background=dark_bg, foreground=text_color)
        self.style.map('TCheckbutton', indicatorbackground=[('selected', light_bg)], background=[('active', light_bg)])
        self.style.configure('TLabelframe', background=dark_bg, bordercolor=text_color)
        self.style.configure('TLabelframe.Label', background=dark_bg, foreground=text_color)
        self.style.configure('Transparent.TFrame', background=dark_bg)

    def set_icon(self):
        """Sets the window icon from a PNG file."""
        try:
            if os.path.exists(self.asset_paths["icon"]):
                self.icon_image = ImageTk.PhotoImage(file=self.asset_paths["icon"])
                self.tk.call('wm', 'iconphoto', self._w, self.icon_image)
        except Exception as e:
            print(f"Warning: Could not load icon. Error: {e}")

    def create_widgets(self):
        """Create and layout all the GUI widgets."""
        self.bg_label = tk.Label(self)
        self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        self.on_resize(None)

        main_frame = ttk.Frame(self, padding="10", style='Transparent.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Logo
        try:
            if os.path.exists(self.asset_paths["logo"]):
                logo_img = Image.open(self.asset_paths["logo"]).resize((120, 120), Image.Resampling.LANCZOS)
                self.logo_image = ImageTk.PhotoImage(logo_img)
                logo_label = tk.Label(main_frame, image=self.logo_image, bg=self.style.lookup('Transparent.TFrame', 'background'))
                logo_label.pack(pady=(0, 10))
        except Exception as e:
            print(f"Warning: Could not load logo. Error: {e}")

        # --- Main Paned Window (for resizable sections) ---
        paned_window = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True)

        # --- Left Pane: Options ---
        options_pane = ttk.Frame(paned_window, padding="10")
        paned_window.add(options_pane, weight=1)

        # Target Inputs
        target_frame = ttk.LabelFrame(options_pane, text="Target", padding="10")
        target_frame.pack(fill=tk.X, pady=5)
        target_frame.columnconfigure(1, weight=1)
        ttk.Label(target_frame, text="Target:").grid(row=0, column=0, sticky="w", padx=5)
        self.target_var = tk.StringVar(value="192.168.56.103")
        ttk.Entry(target_frame, textvariable=self.target_var).grid(row=0, column=1, sticky="ew")

        # Module Selection
        module_frame = ttk.LabelFrame(options_pane, text="Modules", padding="10")
        module_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.module_vars = {
            "Port Scan": tk.BooleanVar(value=True),
            "Vulnerability Scan": tk.BooleanVar(value=True),
            "Web Recon": tk.BooleanVar(),
            "Directory Brute-force": tk.BooleanVar(),
            "Tech Detection": tk.BooleanVar(),
            "Subdomain Scan": tk.BooleanVar(),
            "DNS Scan": tk.BooleanVar(),
            "WHOIS Lookup": tk.BooleanVar(),
            "Threat Intel": tk.BooleanVar(),
            "OSINT Scan": tk.BooleanVar(),
            "IoT Scan": tk.BooleanVar(),
        }
        for i, (name, var) in enumerate(self.module_vars.items()):
            ttk.Checkbutton(module_frame, text=name, variable=var).grid(row=i, column=0, sticky="w")

        # Output Folder
        output_frame = ttk.LabelFrame(options_pane, text="Output", padding="10")
        output_frame.pack(fill=tk.X, pady=5)
        output_frame.columnconfigure(0, weight=1)
        self.output_dir_var = tk.StringVar(value=os.getcwd())
        ttk.Entry(output_frame, textvariable=self.output_dir_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(output_frame, text="Browse...", command=self.browse_folder).pack(side=tk.RIGHT)

        # Start Button
        self.start_button = ttk.Button(options_pane, text="Start Scan", command=self.start_scan)
        self.start_button.pack(pady=10, fill=tk.X)

        # --- Right Pane: Output ---
        output_pane = ttk.Frame(paned_window, padding="10")
        paned_window.add(output_pane, weight=3)
        
        output_log_frame = ttk.LabelFrame(output_pane, text="Live Output", padding="10")
        output_log_frame.pack(fill=tk.BOTH, expand=True)
        self.output_text = scrolledtext.ScrolledText(output_log_frame, wrap=tk.WORD, state="disabled", bg="#1e1e1e", fg="#d4d4d4")
        self.output_text.pack(fill=tk.BOTH, expand=True)

    def on_resize(self, event):
        """Handles window resize event to update the background image."""
        if not os.path.exists(self.asset_paths["background"]): return
        try:
            width, height = self.winfo_width(), self.winfo_height()
            if width < 1 or height < 1: return
            bg_img = Image.open(self.asset_paths["background"]).resize((width, height), Image.Resampling.LANCZOS)
            bg_img.putalpha(70)
            self.bg_image_tk = ImageTk.PhotoImage(bg_img)
            self.bg_label.config(image=self.bg_image_tk)
        except Exception as e:
            print(f"Error resizing background: {e}")

    def browse_folder(self):
        """Opens a dialog to select an output folder."""
        folder = filedialog.askdirectory()
        if folder:
            self.output_dir_var.set(folder)

    def start_scan(self):
        """Validates inputs and starts the scanner thread."""
        if self.scan_thread and self.scan_thread.is_alive():
            self.logger.warning("A scan is already in progress.")
            return

        target = self.target_var.get()
        output_dir = self.output_dir_var.get()
        if not target:
            self.logger.error("Target cannot be empty.")
            return
        if not os.path.isdir(output_dir):
            self.logger.error("Output directory is not valid.")
            return

        self.output_text.config(state="normal")
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state="disabled")
        self.start_button.config(state="disabled")

        self.scan_thread = threading.Thread(
            target=self.run_scan_in_thread,
            args=(target, output_dir),
            daemon=True
        )
        self.scan_thread.start()

    def run_scan_in_thread(self, target, output_dir):
        """Target function for the scanner thread."""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.run_scan_async(target, output_dir))
        except Exception as e:
            self.logger.error(f"An error occurred in the scan thread: {e}")
        finally:
            self.after(0, lambda: self.start_button.config(state="normal"))
            
    async def run_scan_async(self, target, output_dir):
        """Orchestrates the execution of selected scanner modules."""
        self.logger.info(f"--- Starting new scan on {target} ---")
        report_manager = ReportManager(output_dir, target)
        
        # Run selected scans
        if self.module_vars["Port Scan"].get() or self.module_vars["Vulnerability Scan"].get():
            ports = await PortScanner().run(target, []) # Let it use default list
            report_manager.add_section("Open Ports", [f"- Port {p}" for p in ports])
            if self.module_vars["Vulnerability Scan"].get():
                # In a real app, the vuln scanner would return data to be reported.
                await VulnerabilityScanner().run(target, ports)
        
        if self.module_vars["Web Recon"].get(): await WebScanner().run(target, [80, 443, 3000, 8080])
        # ... and so on for all other modules ...
        
        self.logger.info("--- All selected scans complete ---")

    def process_log_queue(self):
        """Periodically checks the log queue and updates the text widget."""
        try:
            while True:
                record = self.log_queue.get_nowait()
                self.output_text.config(state="normal")
                self.output_text.insert(tk.END, record + "\n")
                self.output_text.yview(tk.END)
                self.output_text.config(state="disabled")
        except queue.Empty:
            pass
        finally:
            self.after(100, self.process_log_queue)
            
    def on_closing(self):
        """Handles window closing event."""
        if self.scan_thread and self.scan_thread.is_alive():
            self.logger.warning("Closing application with a scan running.")
        self.destroy()

def launch_gui():
    """Function to create and run the GUI application."""
    app = FenrirGUI()
    app.mainloop()
