# src/receiver.py
"""
Receiver Module and Command-Line Tool (Refactored for Reusability)

This file serves two purposes:
1. Provides a reusable `receive_file` function for other parts of the
   application (like the GUI) to import and use.
2. Acts as a standalone command-line tool when run directly.
"""

import argparse
import getpass
import json
import logging
import sys
from pathlib import Path
from typing import Optional

# Use relative imports to find modules within the same 'src' package
from .stego import (ChecksumMismatchError, InvalidHeaderError,
                    SteganographyError, extract_bytes_from_wav,
                    parse_container)
from .crypto import DecryptionError, decrypt_hybrid

# --- Logger Configuration ---
log = logging.getLogger("receiver")
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
log.addHandler(handler)
log.setLevel(logging.INFO)

# --- REUSABLE CORE FUNCTION ---

def receive_file(
    stego_path: Path,
    private_pem_path: Path,
    outdir: Path,
    lsb_count: int = 1,
    password_bytes: Optional[bytes] = None  # <-- CHANGED: Accepts password
) -> Path:
    """
    Core logic to extract and decrypt a file. This is the main "API"
    function that the GUI or other scripts should call.
    """
    log.info("--- Starting File Recovery ---")
    
    # --- STAGE 1: EXTRACTION ---
    log.info(f"Extracting data from '{stego_path.name}' with LSB={lsb_count}...")
    try:
        container_bytes = extract_bytes_from_wav(stego_path, lsb_count)
        log.info(f"Container extracted ({len(container_bytes)} bytes). Parsing header...")
        json_bundle_bytes = parse_container(container_bytes)
        log.info("Container parsed successfully.")
    except (InvalidHeaderError, ChecksumMismatchError) as e:
        raise SteganographyError(f"Container is invalid or corrupted. Wrong LSB? Error: {e}") from e

    # --- STAGE 2: DECRYPTION ---
    log.info("Decrypting bundle...")
    try:
        bundle_dict = json.loads(json_bundle_bytes)
        # --- CHANGED: Passes the password directly to the decrypt function ---
        plaintext = decrypt_hybrid(bundle_dict, private_pem_path, privkey_password=password_bytes)
        original_filename = bundle_dict.get("filename", "recovered_file")
        log.info(f"Decryption successful! Original filename: '{original_filename}'")
    except DecryptionError as e:
        log.error("DECRYPTION FAILED. Critical error.")
        raise DecryptionError(f"Could not decrypt data. Wrong private key/password or tampered file. Details: {e}") from e

    # --- STAGE 3: SAVE FILE ---
    outdir.mkdir(parents=True, exist_ok=True)
    output_path = outdir / Path(original_filename).name

    if output_path.exists():
        i = 1
        base, suffix = output_path.stem, output_path.suffix
        while output_path.exists():
            output_path = outdir / f"{base}_{i}{suffix}"
            i += 1
        log.warning(f"File '{original_filename}' already exists. Saving as '{output_path.name}'.")

    log.info(f"Saving recovered file to: {output_path.resolve()}")
    output_path.write_bytes(plaintext)
    log.info("--- Workflow Complete ---")
    
    return output_path.resolve()

# --- COMMAND-LINE INTERFACE (for running the script directly) ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extract and decrypt a file hidden in a WAV file.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    # ... (rest of the CLI code is the same)
    parser.add_argument("--stego", type=Path, required=True, help="Path to the steganography WAV file.")
    parser.add_argument("--private", type=Path, required=True, help="Path to your private RSA key PEM file.")
    parser.add_argument("--outdir", type=Path, default=Path("recovered_files"), help="Directory to save the recovered file.")
    parser.add_argument("--lsb", type=int, default=1, choices=[1, 2], help="Number of LSBs used.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose DEBUG logging.")
    
    args = parser.parse_args()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    # --- CLI-specific password prompt ---
    password = None
    try:
        from cryptography.hazmat.primitives import serialization
        key_bytes = args.private.read_bytes()
        serialization.load_pem_private_key(key_bytes, password=None)
    except TypeError:
        password_str = getpass.getpass("Enter private key password: ")
        if password_str:
            password = password_str.encode('utf-8')
            
    try:
        final_path = receive_file(
            stego_path=args.stego,
            private_pem_path=args.private,
            outdir=args.outdir,
            lsb_count=args.lsb,
            password_bytes=password # Pass the password from the CLI
        )
        print(f"✅ Success! File recovered and saved to: {final_path}")
    except Exception as e:
        log.error(f"❌ Operation failed: {e}", exc_info=args.verbose)
        sys.exit(1)