
# src/crypto.py
"""
Cryptographic core (hybrid RSA-OAEP + AES-256-GCM).
Exports:
  - encrypt_hybrid(plaintext, recipient_public_key) -> dict (base64 fields)
  - decrypt_hybrid(crypto_bundle, recipient_private_key) -> bytes
"""

from __future__ import annotations
import os
import base64
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# Constants
AES_KEY_BYTES = 32
AES_NONCE_BYTES = 12
AES_TAG_BYTES = 16

OAEP_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)

logger = logging.getLogger(__name__)


class DecryptionError(Exception):
    """Raised when decryption fails (RSA unwrap or AES-GCM auth failure)."""


# ------------------------
# Key loading helpers
# ------------------------
KeyLike = Union[
    rsa.RSAPublicKey, rsa.RSAPrivateKey, bytes, bytearray, str, Path
]


def _load_public_key(key: KeyLike) -> rsa.RSAPublicKey:
    if isinstance(key, rsa.RSAPublicKey):
        return key
    if isinstance(key, (bytes, bytearray)):
        return serialization.load_pem_public_key(bytes(key))
    if isinstance(key, (str, Path)):
        p = Path(key)
        if not p.exists():
            raise TypeError(f"Public key path does not exist: {key}")
        data = p.read_bytes()
        return serialization.load_pem_public_key(data)
    raise TypeError("Unsupported public key type")


def _load_private_key(key: KeyLike, password: Optional[bytes] = None) -> rsa.RSAPrivateKey:
    if isinstance(key, rsa.RSAPrivateKey):
        return key
    if isinstance(key, (bytes, bytearray)):
        return serialization.load_pem_private_key(bytes(key), password=password)
    if isinstance(key, (str, Path)):
        p = Path(key)
        if not p.exists():
            raise TypeError(f"Private key path does not exist: {key}")
        data = p.read_bytes()
        return serialization.load_pem_private_key(data, password=password)
    raise TypeError("Unsupported private key type")


# ------------------------
# Public API
# ------------------------
def encrypt_hybrid(
    plaintext: bytes,
    recipient_public_key: KeyLike,
) -> Dict[str, str]:
    """
    Hybrid-encrypt plaintext for the recipient.

    Returns dict with base64-encoded fields:
      { encrypted_key, nonce, ciphertext, tag }
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")

    pub = _load_public_key(recipient_public_key)

    # AES key + nonce
    aes_key = os.urandom(AES_KEY_BYTES)
    nonce = os.urandom(AES_NONCE_BYTES)
    aesgcm = AESGCM(aes_key)

    # Encrypt -> ciphertext || tag
    ct_with_tag = aesgcm.encrypt(nonce, bytes(plaintext), None)
    ciphertext = ct_with_tag[:-AES_TAG_BYTES]
    tag = ct_with_tag[-AES_TAG_BYTES :]

    # Wrap AES key with RSA-OAEP
    encrypted_key = pub.encrypt(aes_key, OAEP_PADDING)

    return {
        "encrypted_key": base64.b64encode(encrypted_key).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }


def decrypt_hybrid(
    crypto_bundle: Dict[str, Any],
    recipient_private_key: KeyLike,
    privkey_password: Optional[bytes] = None,
) -> bytes:
    """
    Decrypt a crypto_bundle produced by encrypt_hybrid.

    crypto_bundle must be a dict with base64 strings:
      'encrypted_key', 'nonce', 'ciphertext', 'tag'

    recipient_private_key may be a key object, PEM bytes, or a path to a PEM file.
    If the private key PEM is encrypted, provide privkey_password (bytes).
    """
    # Validate bundle fields
    required = ("encrypted_key", "nonce", "ciphertext", "tag")
    if not isinstance(crypto_bundle, dict):
        raise DecryptionError("crypto_bundle must be a dict")
    for k in required:
        if k not in crypto_bundle:
            raise DecryptionError(f"Missing bundle field: {k}")

    try:
        encrypted_key = base64.b64decode(crypto_bundle["encrypted_key"])
        nonce = base64.b64decode(crypto_bundle["nonce"])
        ciphertext = base64.b64decode(crypto_bundle["ciphertext"])
        tag = base64.b64decode(crypto_bundle["tag"])
    except Exception as e:
        raise DecryptionError(f"Invalid base64 in bundle: {e}")

    # Load private key (may raise TypeError)
    priv = _load_private_key(recipient_private_key, password=privkey_password)

    # RSA unwrap
    try:
        aes_key = priv.decrypt(encrypted_key, OAEP_PADDING)
    except Exception as e:
        raise DecryptionError(f"RSA unwrap failed (wrong key or corrupted encrypted_key): {e}")

    # AES-GCM decrypt (will raise InvalidTag if tampered)
    try:
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
        return plaintext
    except InvalidTag:
        raise DecryptionError("AES-GCM authentication failed: tag mismatch (possible tampering)")
    except Exception as e:
        raise DecryptionError(f"AES-GCM decryption error: {e}")


# ------------------------
# Utilities
# ------------------------
def bundle_to_json_bytes(bundle: Dict[str, Any]) -> bytes:
    return json.dumps(bundle, separators=(",", ":")).encode("utf-8")


def json_bytes_to_bundle(b: bytes) -> Dict[str, Any]:
    return json.loads(b.decode("utf-8"))


# ------------------------
# Self-test / demo (safe, in-memory)
# ------------------------
def _selftest() -> None:
    import shutil

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
    logger.info("Running crypto self-test (in-memory keys)")

    # Generate ephemeral RSA keypair for test (in-memory only)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    message = b"Crypto module self-test: hello world"
    logger.info("Encrypting test message")
    bundle = encrypt_hybrid(message, public_key)

    logger.info("Decrypting test message")
    recovered = decrypt_hybrid(bundle, private_key)
    assert recovered == message, "roundtrip failed"
    logger.info("Roundtrip OK")

    # Tamper test: flip a single bit in ciphertext bytes
    logger.info("Running tamper-detection test")
    ct = bytearray(base64.b64decode(bundle["ciphertext"]))
    if len(ct) == 0:
        logger.info("No ciphertext to tamper with (skipping tamper test)")
    else:
        ct[len(ct) // 2] ^= 0x01
        tampered_bundle = dict(bundle)
        tampered_bundle["ciphertext"] = base64.b64encode(bytes(ct)).decode("ascii")
        try:
            _ = decrypt_hybrid(tampered_bundle, private_key)
            raise AssertionError("Tamper not detected (decryption unexpectedly succeeded)")
        except DecryptionError:
            logger.info("Tamper detected as expected")

    logger.info("Self-test completed successfully")


if __name__ == "__main__":
    _selftest()
