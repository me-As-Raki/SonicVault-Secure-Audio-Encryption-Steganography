# src/key_management.py
"""
Advanced RSA Key Management Module
---------------------------------
Generates 4096-bit RSA key pairs and saves them securely to disk.
Supports optional password protection for the private key.
Includes overwrite protection to prevent accidental key loss.

Usage:
    python -m src.key_management
"""

import os
import sys
import getpass
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Recommended RSA parameters
RECOMMENDED_KEY_SIZE = 4096
RECOMMENDED_PUBLIC_EXPONENT = 65537


def generate_rsa_keypair(
    key_size: int = RECOMMENDED_KEY_SIZE,
    public_exponent: int = RECOMMENDED_PUBLIC_EXPONENT
) -> rsa.RSAPrivateKey:
    """
    Generate an RSA private key.
    """
    return rsa.generate_private_key(public_exponent=public_exponent, key_size=key_size)


def save_keys(
    private_key: rsa.RSAPrivateKey,
    output_dir: str,
    password: Optional[bytes] = None
) -> tuple[Path, Path]:
    """
    Saves private and public keys to the specified directory.
    Includes overwrite protection to prevent accidental key loss.

    Args:
        private_key: RSA private key object.
        output_dir: Directory to save keys.
        password: Optional password to encrypt the private key.

    Returns:
        Tuple of (private_key_path, public_key_path)
    """
    key_path = Path(output_dir)

    # Ensure the output directory exists
    key_path.mkdir(parents=True, exist_ok=True)

    # Paths for key files
    private_key_path = key_path / "private.pem"
    public_key_path = key_path / "public.pem"

    # --- OVERWRITE PROTECTION ---
    if private_key_path.exists() or public_key_path.exists():
        print(f"❌ Error: Key files already exist in '{key_path.resolve()}'.")
        print("Please choose a different folder or remove the existing keys first.")
        sys.exit(1)

    # Serialize private key
    enc_algo = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_algo
    )

    # Serialize public key
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Write keys to disk
    private_key_path.write_bytes(private_pem)
    public_key_path.write_bytes(public_pem)

    # Secure private key permissions (cross-platform)
    try:
        os.chmod(private_key_path, 0o600)
    except Exception:
        # Windows may ignore chmod; warn user
        print(f"⚠️  Ensure '{private_key_path}' is kept private!")

    return private_key_path, public_key_path


def generate_and_save_keys(output_dir: str, password: Optional[bytes] = None) -> tuple[Path, Path]:
    """
    High-level helper to generate and save RSA key pair.
    """
    print(f"🔐 Generating {RECOMMENDED_KEY_SIZE}-bit RSA key pair...")
    private_key = generate_rsa_keypair()
    priv_path, pub_path = save_keys(private_key, output_dir, password)
    print(f"✅ Keys saved successfully:")
    print(f"   -> Private: {priv_path.resolve()}")
    print(f"   -> Public:  {pub_path.resolve()}")
    print("\n⚠️  Keep the private key safe. Share ONLY the public key.")
    return priv_path, pub_path


def prompt_password() -> Optional[bytes]:
    """
    Prompt the user to enter an optional password for private key protection.
    """
    pwd = getpass.getpass("Enter a password to protect your private key (press Enter to skip): ").encode('utf-8')
    if pwd:
        confirm = getpass.getpass("Confirm password: ").encode('utf-8')
        if pwd != confirm:
            print("❌ Passwords do not match. Aborting.")
            sys.exit(1)
        return pwd
    return None


def main():
    print("=== RSA Key Pair Generator (Receiver) ===")
    try:
        output_dir = input("Enter output folder for keys (e.g., 'receiver_keys'): ").strip()
        if not output_dir:
            print("❌ Output folder cannot be empty. Exiting.")
            sys.exit(1)

        password = prompt_password()
        generate_and_save_keys(output_dir, password)

    except KeyboardInterrupt:
        print("\n⚠️ Operation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

