# src/frontend/receiver_gui.py
"""
Receiver GUI - polished, compact, backward-compatible.

Drop-in file: src/frontend/receiver_gui.py
Run: python -m src.frontend.receiver_gui
"""

from __future__ import annotations
import sys
import threading
import queue
import time
import hashlib
from pathlib import Path
from typing import Optional, Any
import inspect

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText

# Ensure 'src' package is importable (project root)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Backend imports
from src.key_management import generate_and_save_keys
from src import receiver as receiver_module  # module object to inspect receive_file
from src.receiver import receive_file  # expected function to call

LOG_Q: "queue.Queue[str]" = queue.Queue()


def _sha256_fingerprint(data: bytes) -> str:
    h = hashlib.sha256(data).hexdigest().upper()
    return ":".join(h[i : i + 2] for i in range(0, len(h), 2))


class ReceiverGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure Audio — Receiver")
        self.root.geometry("860x640")
        try:
            import sv_ttk

            sv_ttk.set_theme("light")
        except Exception:
            pass

        self._vars()
        self._build_ui()
        self._poll_log_queue()

        self.worker: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def _vars(self):
        self.priv_path = tk.StringVar(value="")
        self.pub_path = tk.StringVar(value="")
        self.fingerprint = tk.StringVar(value="No public key loaded")
        self.stego_path = tk.StringVar(value="")
        self.out_dir = tk.StringVar(value=str(Path.cwd() / "recovered"))
        self.lsb = tk.IntVar(value=1)
        self.status = tk.StringVar(value="Ready")
        self._log_q = LOG_Q

    def _build_ui(self):
        pad = 10
        frm = ttk.Frame(self.root, padding=pad)
        frm.pack(fill=tk.BOTH, expand=True)

        title = ttk.Label(frm, text="Receiver — Key Management & File Recovery", font=("Segoe UI", 14, "bold"))
        title.pack(anchor=tk.W, pady=(0, 8))

        # Key management
        keys = ttk.LabelFrame(frm, text="Key Management", padding=8)
        keys.pack(fill=tk.X, pady=(0, pad))

        row1 = ttk.Frame(keys)
        row1.pack(fill=tk.X, pady=4)
        ttk.Label(row1, text="Private key:", width=14).pack(side=tk.LEFT)
        ttk.Entry(row1, textvariable=self.priv_path, width=62).pack(side=tk.LEFT, padx=(6, 6))
        ttk.Button(row1, text="Load", command=self._load_private).pack(side=tk.LEFT)
        ttk.Button(row1, text="Generate", command=self._generate_keys).pack(side=tk.LEFT, padx=(6, 0))

        row2 = ttk.Frame(keys)
        row2.pack(fill=tk.X, pady=4)
        ttk.Label(row2, text="Public key:", width=14).pack(side=tk.LEFT)
        ttk.Entry(row2, textvariable=self.pub_path, width=62, state="readonly").pack(side=tk.LEFT, padx=(6, 6))
        ttk.Button(row2, text="Load public", command=self._load_public).pack(side=tk.LEFT)

        fp_frame = ttk.Frame(keys)
        fp_frame.pack(fill=tk.X, pady=(8, 0))
        ttk.Label(fp_frame, text="Fingerprint (SHA-256):").pack(anchor=tk.W)
        ttk.Label(fp_frame, textvariable=self.fingerprint, font=("Courier New", 10)).pack(anchor=tk.W)

        # Recovery
        rec = ttk.LabelFrame(frm, text="Recover Hidden File", padding=8)
        rec.pack(fill=tk.X, pady=(0, pad))

        r1 = ttk.Frame(rec)
        r1.pack(fill=tk.X, pady=4)
        ttk.Label(r1, text="Stego WAV:", width=14).pack(side=tk.LEFT)
        ttk.Entry(r1, textvariable=self.stego_path, width=62).pack(side=tk.LEFT, padx=(6, 6))
        ttk.Button(r1, text="Browse", command=self._browse_stego).pack(side=tk.LEFT)

        r2 = ttk.Frame(rec)
        r2.pack(fill=tk.X, pady=4)
        ttk.Label(r2, text="Output folder:", width=14).pack(side=tk.LEFT)
        ttk.Entry(r2, textvariable=self.out_dir, width=62).pack(side=tk.LEFT, padx=(6, 6))
        ttk.Button(r2, text="Choose", command=self._choose_outdir).pack(side=tk.LEFT)

        r3 = ttk.Frame(rec)
        r3.pack(fill=tk.X, pady=4)
        ttk.Label(r3, text="LSB used:", width=14).pack(side=tk.LEFT)
        ttk.OptionMenu(r3, self.lsb, self.lsb.get(), 1, 2).pack(side=tk.LEFT)
        self.btn_recover = ttk.Button(r3, text="Start Recovery", command=self._start_recover)
        self.btn_recover.pack(side=tk.RIGHT)

        # status + progress
        status_frame = ttk.Frame(frm)
        status_frame.pack(fill=tk.X, pady=(0, pad))
        ttk.Label(status_frame, textvariable=self.status).pack(anchor=tk.W)
        self.progress = ttk.Progressbar(status_frame, mode="indeterminate")
        self.progress.pack(fill=tk.X, pady=(6, 0))

        # log
        log_frame = ttk.LabelFrame(frm, text="Activity Log", padding=6)
        log_frame.pack(fill=tk.BOTH, expand=True)
        self.logbox = ScrolledText(log_frame, height=14, font=("Courier New", 10), state="disabled")
        self.logbox.pack(fill=tk.BOTH, expand=True)

    # --------- UI helpers ----------
    def _enqueue_log(self, msg: str):
        LOG_Q.put(f"{time.strftime('%H:%M:%S')}  {msg}")

    def _poll_log_queue(self):
        try:
            while True:
                line = LOG_Q.get_nowait()
                self.logbox.configure(state="normal")
                self.logbox.insert("end", line + "\n")
                self.logbox.configure(state="disabled")
                self.logbox.see("end")
        except queue.Empty:
            pass
        self.root.after(150, self._poll_log_queue)

    def _load_private(self):
        p = filedialog.askopenfilename(title="Select private.pem", filetypes=[("PEM", "*.pem"), ("All files", "*.*")])
        if not p:
            return
        self.priv_path.set(str(p))
        self._enqueue_log(f"Loaded private key: {Path(p).name}")
        # try to auto-find public
        pub = Path(p).parent / "public.pem"
        if pub.exists():
            self.pub_path.set(str(pub))
            self._update_fingerprint(pub)

    def _load_public(self):
        p = filedialog.askopenfilename(title="Select public.pem", filetypes=[("PEM", "*.pem"), ("All files", "*.*")])
        if not p:
            return
        self.pub_path.set(str(p))
        self._update_fingerprint(Path(p))

    def _update_fingerprint(self, pub_path: Path):
        try:
            data = pub_path.read_bytes()
            self.fingerprint.set(_sha256_fingerprint(data))
            self._enqueue_log(f"Public key loaded: {pub_path.name}")
        except Exception as e:
            self.fingerprint.set(f"Error: {e}")
            self._enqueue_log(f"Fingerprint error: {e}")

    def _browse_stego(self):
        p = filedialog.askopenfilename(title="Select stego WAV", filetypes=[("WAV files", "*.wav"), ("All files", "*.*")])
        if p:
            self.stego_path.set(p)
            self._enqueue_log(f"Selected stego: {Path(p).name}")

    def _choose_outdir(self):
        p = filedialog.askdirectory(title="Select output folder")
        if p:
            self.out_dir.set(p)
            self._enqueue_log(f"Output folder: {p}")

    def _set_busy(self, busy: bool, status_text: Optional[str] = None):
        state = "disabled" if busy else "normal"
        self.btn_recover.config(state=state)
        if busy:
            self.status.set(status_text or "Working...")
            self.progress.start(12)
        else:
            self.status.set("Ready")
            self.progress.stop()

    def _generate_keys(self):
        dest = filedialog.askdirectory(title="Choose folder to save keys (new folder recommended)")
        if not dest:
            return
        password = simpledialog.askstring("Password (optional)", "Enter password to protect your private key (optional):", show="*")
        pwd_bytes = password.encode("utf-8") if password else None

        def worker():
            self._set_busy(True, "Generating keys...")
            try:
                self._enqueue_log("Generating RSA key pair...")
                priv_p, pub_p = generate_and_save_keys(dest, pwd_bytes)
                self.priv_path.set(str(priv_p))
                self.pub_path.set(str(pub_p))
                self._update_fingerprint(Path(pub_p))
                messagebox.showinfo("Keys Generated", f"Private: {priv_p}\nPublic:  {pub_p}\n\nKeep private.pem safe.")
                self._enqueue_log("Key generation completed.")
            except Exception as ex:
                messagebox.showerror("Key generation failed", str(ex))
                self._enqueue_log(f"Key gen error: {ex}")
            finally:
                self._set_busy(False)

        threading.Thread(target=worker, daemon=True).start()

    # --------- Recovery flow ----------
    def _start_recover(self):
        stego = self.stego_path.get().strip()
        priv = self.priv_path.get().strip()
        outdir = self.out_dir.get().strip()
        lsb = int(self.lsb.get())

        if not stego:
            messagebox.showerror("Missing stego", "Please select the stego WAV file.")
            return
        if not priv:
            messagebox.showerror("Missing private key", "Please load your private key (private.pem).")
            return

        # prompt for password here (GUI) so backend won't block on getpass
        password = simpledialog.askstring("Private Key Password", "Enter private key password (leave blank if none):", show="*")
        password_bytes = password.encode("utf-8") if password else None

        def worker():
            self._set_busy(True, "Recovering file...")
            self._enqueue_log("Starting recovery...")
            try:
                # Try calling receive_file with password_bytes named parameter if supported.
                sig = inspect.signature(receive_file)
                params = sig.parameters
                if "password_bytes" in params or "password" in params:
                    # call with kwargs (backward/forward compatible)
                    kwargs: dict[str, Any] = {}
                    # prefer parameter names if present
                    if "stego_path" in params:
                        kwargs["stego_path"] = Path(stego)
                    elif "stego" in params:
                        kwargs["stego"] = Path(stego)
                    else:
                        # fallback to positional calling below
                        kwargs = {}

                    if "private_pem_path" in params:
                        kwargs["private_pem_path"] = Path(priv)
                    elif "private" in params:
                        kwargs["private"] = Path(priv)

                    if "outdir" in params:
                        kwargs["outdir"] = Path(outdir)
                    elif "out_dir" in params:
                        kwargs["out_dir"] = Path(outdir)

                    if "lsb_count" in params:
                        kwargs["lsb_count"] = lsb
                    elif "lsb" in params:
                        kwargs["lsb"] = lsb

                    # pass password param if available
                    if "password_bytes" in params:
                        kwargs["password_bytes"] = password_bytes
                    elif "password" in params:
                        kwargs["password"] = password_bytes

                    # Call and capture returned path (if any)
                    result = receive_file(**kwargs)  # type: ignore
                else:
                    # Old signature: receive_file(stego, private, outdir, lsb)
                    result = receive_file(Path(stego), Path(priv), Path(outdir), lsb)  # type: ignore

                # result is expected to be path (string or Path)
                self._enqueue_log(f"Recovery finished. Output: {result}")
                messagebox.showinfo("Recovery Complete", f"Recovered file saved to:\n{result}")
            except Exception as e:
                self._enqueue_log(f"Recovery error: {e}")
                messagebox.showerror("Recovery failed", f"{e}")
            finally:
                self._set_busy(False)

        threading.Thread(target=worker, daemon=True).start()

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    ReceiverGUI().run()
