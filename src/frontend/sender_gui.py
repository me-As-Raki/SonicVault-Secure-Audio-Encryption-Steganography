
# src/frontend/sender_gui.py
"""
Sender GUI (polished / pro)

Responsibilities:
- Provide a user-friendly interface for the sender's workflow.
- Allow easy selection of infile, cover audio, and recipient public key.
- Display the public key fingerprint for security verification.
- Run the complex backend tasks (audio conversion, encryption, embedding)
  in a background thread to keep the UI responsive.
- Provide real-time feedback via a progress bar and a live log.
- Offer simple controls for advanced options like LSB count and padding.
"""

from __future__ import annotations
import sys
import threading
import queue
import time
import hashlib
from pathlib import Path
from typing import Optional, List, Tuple

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

# Ensure project root is importable (src package)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Backend imports using relative paths
from src.sender import run as run_sender_workflow

# --- Global Queue for Thread-Safe Logging ---
LOG_Q: queue.Queue[str] = queue.Queue()

def sha256_fingerprint(data: bytes) -> str:
    """Calculates and formats a SHA-256 fingerprint."""
    h = hashlib.sha256(data).hexdigest().upper()
    return ":".join(h[i : i + 2] for i in range(0, len(h), 2))

class SenderGUI(ttk.Frame):
    def __init__(self, master: Optional[tk.Tk] = None):
        self.root = master or tk.Tk()
        super().__init__(self.root)
        self.root.title("Secure Audio — Sender")
        self.root.geometry("820x600")
        
        # Attempt to apply a modern theme
        try:
            import sv_ttk
            sv_ttk.set_theme("light")
        except ImportError:
            pass # Use default theme if sv_ttk is not available

        self._build_vars()
        self._build_ui()
        self._poll_logs()

        self.worker_thread: Optional[threading.Thread] = None

    def _build_vars(self):
        """Initialize Tkinter control variables."""
        self.infile_path = tk.StringVar(value="")
        self.cover_path = tk.StringVar(value="")
        self.pubkey_path = tk.StringVar(value="")
        self.fingerprint = tk.StringVar(value="No public key loaded")
        self.lsb_count = tk.IntVar(value=1)
        self.pad_audio = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="Ready")
        self.progress = tk.DoubleVar(value=0.0)

    def _build_ui(self):
        """Construct the main user interface."""
        pad = 10
        container = ttk.Frame(self.root, padding=pad)
        container.pack(fill=tk.BOTH, expand=True)

        header = ttk.Label(container, text="Sender — Encrypt & Hide File", font=("Segoe UI", 14, "bold"))
        header.pack(anchor=tk.W, pady=(0, 6))

        # --- Input Files Frame ---
        files_frame = ttk.LabelFrame(container, text="1. Select Files", padding=8)
        files_frame.pack(fill=tk.X, pady=(0, pad))

        # Secret File
        row1 = ttk.Frame(files_frame)
        row1.pack(fill=tk.X, pady=4)
        ttk.Label(row1, text="Secret File:", width=15).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Entry(row1, textvariable=self.infile_path).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 6))
        ttk.Button(row1, text="Browse...", command=lambda: self._browse_file(self.infile_path, "Select Secret File")).pack(side=tk.LEFT)

        # Cover Audio
        row2 = ttk.Frame(files_frame)
        row2.pack(fill=tk.X, pady=4)
        ttk.Label(row2, text="Cover Audio:", width=15).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Entry(row2, textvariable=self.cover_path).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 6))
        ttk.Button(row2, text="Browse...", command=lambda: self._browse_file(self.cover_path, "Select Cover Audio", [("Audio Files", "*.wav *.mp3 *.flac"), ("All files", "*.*")])).pack(side=tk.LEFT)

        # Recipient Public Key
        row3 = ttk.Frame(files_frame)
        row3.pack(fill=tk.X, pady=4)
        ttk.Label(row3, text="Recipient's Key:", width=15).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Entry(row3, textvariable=self.pubkey_path).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 6))
        ttk.Button(row3, text="Browse...", command=self._on_load_public_key).pack(side=tk.LEFT)
        
        # --- Verification Frame ---
        verify_frame = ttk.LabelFrame(container, text="2. Verify Recipient", padding=8)
        verify_frame.pack(fill=tk.X, pady=(0, pad))
        ttk.Label(verify_frame, text="Public Key Fingerprint (SHA-256):").pack(anchor=tk.W)
        ttk.Label(verify_frame, textvariable=self.fingerprint, font=("Courier New", 10), foreground="#003366").pack(anchor=tk.W, pady=(4,0))
        ttk.Label(verify_frame, text="Confirm this fingerprint with the recipient (e.g., via phone call).", font=("Segoe UI", 8, "italic")).pack(anchor=tk.W)

        # --- Options and Action Frame ---
        action_frame = ttk.LabelFrame(container, text="3. Configure and Run", padding=8)
        action_frame.pack(fill=tk.X, pady=(0, pad))
        
        opts_row = ttk.Frame(action_frame)
        opts_row.pack(fill=tk.X, pady=4)
        ttk.Label(opts_row, text="LSB Used:").pack(side=tk.LEFT, padx=(0, 6))
        ttk.OptionMenu(opts_row, self.lsb_count, self.lsb_count.get(), 1, 2).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(opts_row, text="Pad audio with silence if it's too small", variable=self.pad_audio).pack(side=tk.LEFT, padx=12)
        
        self.btn_start = ttk.Button(opts_row, text="Encrypt and Hide File", command=self._start_workflow)
        self.btn_start.pack(side=tk.RIGHT, padx=4)

        # --- Progress and Status ---
        prog = ttk.Frame(container)
        prog.pack(fill=tk.X, pady=(0, pad))
        ttk.Label(prog, textvariable=self.status).pack(anchor=tk.W)
        self.progress_bar = ttk.Progressbar(prog, variable=self.progress, maximum=100, mode='indeterminate')
        self.progress_bar.pack(fill=tk.X, pady=(6, 0))

        # --- Log Area ---
        log_frame = ttk.LabelFrame(container, text="Activity Log", padding=6)
        log_frame.pack(fill=tk.BOTH, expand=True)
        self.logbox = ScrolledText(log_frame, height=10, state="disabled", font=("Courier New", 9))
        self.logbox.pack(fill=tk.BOTH, expand=True)

    def _log(self, msg: str):
        """Thread-safe logging to the GUI."""
        timestamp = time.strftime("%H:%M:%S")
        LOG_Q.put(f"{timestamp}  {msg}")

    def _poll_logs(self):
        """Periodically check the log queue and update the GUI."""
        try:
            while True:
                line = LOG_Q.get_nowait()
                self.logbox.configure(state="normal")
                self.logbox.insert("end", line + "\n")
                self.logbox.configure(state="disabled")
                self.logbox.see("end")
        except queue.Empty:
            pass
        self.root.after(150, self._poll_logs)

    def _browse_file(self, var: tk.StringVar, title: str, filetypes: Optional[List[Tuple[str, str]]] = None):
        """Open a file dialog and set the result to a StringVar."""
        p = filedialog.askopenfilename(title=title, filetypes=filetypes or [])
        if p:
            var.set(p)

    def _on_load_public_key(self):
        """Handle public key selection and fingerprint display."""
        p_str = filedialog.askopenfilename(title="Select Recipient's Public Key", filetypes=[("PEM files", "*.pem")])
        if not p_str:
            return
        
        p = Path(p_str)
        self.pubkey_path.set(str(p))
        try:
            data = p.read_bytes()
            fp = sha256_fingerprint(data)
            self.fingerprint.set(fp)
            self._log(f"Loaded recipient public key: {p.name}")
            self._log(f"Fingerprint: {fp}")
        except Exception as e:
            self.fingerprint.set(f"Error reading key: {e}")
            messagebox.showerror("Key Error", f"Could not read or process the public key file:\n{e}")

    def _set_busy(self, busy: bool, status_text: Optional[str] = None):
        """Disable/enable UI controls and update status."""
        state = "disabled" if busy else "normal"
        self.btn_start.config(state=state)
        
        if busy:
            self.status.set(status_text or "Working...")
            self.progress_bar.start(10)
        else:
            self.status.set("Ready")
            self.progress_bar.stop()
            self.progress.set(0.0)

    def _start_workflow(self):
        """Validate inputs and start the backend workflow in a new thread."""
        infile = self.infile_path.get().strip()
        cover = self.cover_path.get().strip()
        pubkey = self.pubkey_path.get().strip()

        if not all([infile, cover, pubkey]):
            messagebox.showerror("Missing Information", "Please select the secret file, cover audio, and recipient's key.")
            return

        self._set_busy(True, "Starting...")

        def work():
            try:
                self._log("--- Starting Sender Workflow ---")
                # The `run_sender_workflow` already logs its progress,
                # so we just need to capture its success/failure.
                final_path = run_sender_workflow(
                    infile=Path(infile),
                    cover=Path(cover),
                    recipient_pub=Path(pubkey),
                    lsb=self.lsb_count.get(),
                    pad=self.pad_audio.get(),
                )
                self._log(f"--- Workflow Complete ---")
                messagebox.showinfo("Success", f"Stego file created successfully:\n{final_path}")
            except Exception as e:
                self._log(f"❌ ERROR: {e}")
                messagebox.showerror("Workflow Failed", f"An error occurred:\n{e}")
            finally:
                self._set_busy(False)

        self.worker_thread = threading.Thread(target=work, daemon=True)
        self.worker_thread.start()

    def run(self):
        """Start the Tkinter main loop."""
        self.root.mainloop()

if __name__ == "__main__":
    app = SenderGUI()
    app.run()