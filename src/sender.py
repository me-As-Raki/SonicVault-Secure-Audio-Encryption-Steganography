
# src/sender.py
"""
Polished Sender CLI
- Auto-converts cover audio to 16-bit PCM WAV via ffmpeg when needed.
- Encrypts file using recipient public key (RSA-OAEP + AES-256-GCM).
- Builds container and embeds using LSB steganography.
- Auto-generates output filename from cover: <cover_stem>_stego.wav
- Options: --pad (add silence if needed), --force (overwrite), --lsb (1 or 2), --no-compress
"""

from __future__ import annotations
import argparse
import json
import logging
import shutil
import subprocess
import sys
import tempfile
import wave
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Callable

# Try to import from package layout (src.*) else local module names
try:
    from src.crypto import encrypt_hybrid
    from src.stego import build_container, embed_in_wav, wav_capacity_bytes  # prefer newer names
except Exception:
    # fallback to top-level imports
    try:
        from .crypto import encrypt_hybrid
    except Exception as e:
        raise ImportError("Cannot import encrypt_hybrid from src.crypto or crypto.py") from e
    try:
        from .stego import build_container, embed_in_wav, wav_capacity_bytes
    except Exception:
        # older API names compatibility: embed_bytes_in_wav / wav_capacity_bytes
        from .stego import build_container, embed_bytes_in_wav as embed_in_wav, wav_capacity_bytes  # type: ignore

# cryptography loader (for public key)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# logging
log = logging.getLogger("sender")
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
log.addHandler(handler)
log.setLevel(logging.INFO)


# -----------------------
# Helpers
# -----------------------
FILENAME_SAFE_RE = re.compile(r'[^A-Za-z0-9_.-]')

def sanitize_stem(stem: str) -> str:
    s = stem.replace(" ", "_")
    s = FILENAME_SAFE_RE.sub("", s)
    s = s.strip("._-")
    return s or "cover"

def find_ffmpeg() -> Optional[str]:
    return shutil.which("ffmpeg") or shutil.which("ffmpeg.exe")

def convert_to_wav_if_needed(cover: Path, temp_dir: Path) -> Path:
    """
    Ensure we have a 16-bit PCM WAV file.
    If cover is already a wav and 16-bit PCM, return it.
    Else convert via ffmpeg into temp_dir/converted.wav and return that.
    """
    try:
        with wave.open(str(cover), "rb") as wf:
            sampwidth = wf.getsampwidth()
            comp = wf.getcomptype()
            if sampwidth == 2 and comp == "NONE":
                log.info("Cover is already 16-bit PCM WAV; using it directly.")
                return cover
            else:
                log.info("Cover is WAV but not 16-bit PCM; converting with FFmpeg.")
    except wave.Error:
        log.info("Cover is not a valid WAV => will convert with FFmpeg.")

    ff = find_ffmpeg()
    if not ff:
        raise RuntimeError("FFmpeg not found (required to convert non-16-bit WAV files). Install ffmpeg or add it to PATH.")

    out = temp_dir / "cover_converted.wav"
    cmd = [
        ff, "-y", "-i", str(cover),
        "-vn", "-acodec", "pcm_s16le", "-ar", "44100", "-ac", "2",
        str(out)
    ]
    log.info("Converting cover to 16-bit PCM WAV using FFmpeg...")
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log.info(f"Converted cover to WAV: {out}")
        return out
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode(errors='ignore') if e.stderr else ""
        log.error("FFmpeg conversion failed: %s", stderr)
        raise RuntimeError("FFmpeg conversion failed") from e

def compute_capacity(wav_path: Path, lsb: int) -> int:
    """Return capacity in bytes (integer)."""
    with wave.open(str(wav_path), "rb") as wf:
        n_frames = wf.getnframes()
        n_channels = wf.getnchannels()
    total_samples = n_frames * n_channels
    return (total_samples * lsb) // 8

def pad_wav_with_silence(src_wav: Path, required_bytes: int, out_wav: Path, lsb: int) -> Path:
    """
    Pad WAV with silence frames until capacity >= required_bytes.
    Writes out_wav and returns path. Works only for 16-bit PCM WAV.
    """
    with wave.open(str(src_wav), "rb") as wf:
        params = wf.getparams()
        n_channels, sampwidth, framerate, n_frames, comptype, compname = params
        if sampwidth != 2 or comptype != "NONE":
            raise RuntimeError("pad_wav_with_silence supports only 16-bit PCM WAV input")
        original_frames = wf.readframes(n_frames)

    total_samples = n_frames * n_channels
    capacity_bytes = (total_samples * lsb) // 8
    if capacity_bytes >= required_bytes:
        # just copy
        if src_wav.resolve() != out_wav.resolve():
            shutil.copy2(src_wav, out_wav)
        return out_wav

    needed_bytes = required_bytes - capacity_bytes
    needed_bits = needed_bytes * 8
    needed_samples = (needed_bits + lsb - 1) // lsb
    needed_frames = (needed_samples + n_channels - 1) // n_channels

    log.info("Padding WAV: need %d extra frames (~%d samples) to fit payload", needed_frames, needed_samples)

    silence_sample = (0).to_bytes(2, "little", signed=True)
    silence_frame = silence_sample * n_channels

    with wave.open(str(out_wav), "wb") as wf:
        wf.setparams((n_channels, sampwidth, framerate, n_frames + needed_frames, comptype, compname))
        wf.writeframes(original_frames)
        # write silence in chunks
        chunk = 4096
        frames_left = needed_frames
        while frames_left > 0:
            write_n = min(chunk, frames_left)
            wf.writeframes(silence_frame * write_n)
            frames_left -= write_n

    log.info("WAV padded and written to %s", out_wav)
    return out_wav

def find_public_key(pub_path: Path) -> bytes:
    if not pub_path.is_file():
        raise FileNotFoundError(f"Recipient public key not found: {pub_path}")
    data = pub_path.read_bytes()
    # basic sanity: try load
    try:
        load_pem_public_key(data)
    except Exception as e:
        raise ValueError("Invalid recipient public key (failed to parse PEM).") from e
    return data

def generate_output_path(cover_path: Path, out_arg: Optional[Path], force: bool=False) -> Path:
    """
    If user provided --out, respect it (but ensure extension .wav).
    Else build from cover name: <cover_stem>_stego.wav
    Avoid clobbering existing files unless --force.
    """
    if out_arg:
        out = out_arg
        if out.suffix.lower() != ".wav":
            out = out.with_suffix(".wav")
    else:
        stem = sanitize_stem(cover_path.stem)
        out = cover_path.parent / f"{stem}_stego.wav"

    if out.exists() and not force:
        # append counter
        base = out.stem
        i = 1
        while out.exists():
            out = out.with_name(f"{base}_{i}.wav")
            i += 1
    return out

def load_public_key_obj(pub_bytes: bytes):
    return serialization.load_pem_public_key(pub_bytes)


# -----------------------
# Main workflow
# -----------------------
def run(
    infile: Path,
    cover: Path,
    recipient_pub: Path,
    out: Optional[Path] = None,
    lsb: int = 1,
    pad: bool = False,
    force: bool = False,
    compress: bool = True,
):
    log.info("Sender run started")
    if lsb not in (1,2):
        raise ValueError("lsb must be 1 or 2")

    # read payload
    log.info("Reading input file: %s", infile)
    payload = infile.read_bytes()
    log.info("Input size: %d bytes", len(payload))

    # load public key bytes and object
    pub_bytes = find_public_key(recipient_pub)
    pub_obj = load_public_key_obj(pub_bytes)

    # prepare temp dir
    with tempfile.TemporaryDirectory(prefix="sender_tmp_") as tmpd:
        tmp = Path(tmpd)
        # ensure cover is a 16-bit PCM WAV
        prepared_wav = convert_to_wav_if_needed(cover, tmp)

        # encrypt payload => returns dictionary (base64 strings)
        # adaptively call encrypt_hybrid: some versions accept pub_obj, other expect bytes
        log.info("Encrypting payload (compress=%s)...", compress)
        try:
            # if encrypt_hybrid signature expects (plaintext, public_key_obj)
            crypto_result = encrypt_hybrid(payload, pub_obj)  # type: ignore
        except TypeError:
            # fallback: call with pem bytes
            crypto_result = encrypt_hybrid(payload, pub_bytes)  # type: ignore

        # build final JSON bundle (compact)
        bundle = {
            "version": "1.0",
            "alg": {"symmetric": "AES-256-GCM", "asymmetric": "RSA-OAEP-SHA256"},
            "filename": infile.name,
            "original_size": len(payload),
            "timestamp": datetime.now(timezone.utc).isoformat(timespec='seconds'),
            **crypto_result
        }
        bundle_bytes = json.dumps(bundle, separators=(",", ":")).encode("utf-8")
        log.info("Bundle size (bytes): %d", len(bundle_bytes))

        # build container
        container = build_container(bundle_bytes)
        container_len = len(container)
        log.info("Container (header+payload) size: %d bytes", container_len)

        # compute capacity
        capacity = compute_capacity(prepared_wav, lsb)
        log.info("Cover capacity: %d bytes (lsb=%d)", capacity, lsb)

        final_wav = generate_output_path(prepared_wav, out, force=force)
        # if not enough capacity:
        if container_len > capacity:
            if pad:
                log.info("Container too large; pad requested -> padding WAV")
                padded = tmp / "cover_padded.wav"
                final_prep = pad_wav_with_silence(prepared_wav, container_len, padded, lsb)
                capacity = compute_capacity(final_prep, lsb)
                log.info("New capacity after padding: %d bytes", capacity)
                if container_len > capacity:
                    raise RuntimeError(f"Even after padding container({container_len}) > capacity({capacity})")
                prepared_for_embed = final_prep
            else:
                raise RuntimeError(f"Container ({container_len}) does not fit into cover (capacity {capacity}). "
                                   "Use --pad to add silence or choose a longer cover or --lsb 2.")
        else:
            prepared_for_embed = prepared_wav

        # compute final output path (may be in same dir as cover)
        if out:
            final_out = out
        else:
            final_out = generate_output_path(cover, None, force=force)

        if final_out.exists() and not force:
            log.info("Output already exists; generating incremented filename.")
            final_out = generate_output_path(final_out, None, force=True)

        # embed
        log.info("Embedding container into %s -> %s", prepared_for_embed, final_out)
        # support embed function name differences
        try:
            embed_in_wav(container, str(prepared_for_embed), str(final_out), lsb)
        except TypeError:
            # older signature: embed_in_wav(container_bytes, cover_wav_path, out_wav_path, lsb)
            embed_in_wav(container, str(prepared_for_embed), str(final_out), lsb)  # type: ignore

        log.info("Embedding complete. Stego file created: %s", final_out.resolve())
        return final_out.resolve()


# -----------------------
# CLI
# -----------------------
def _build_parser():
    p = argparse.ArgumentParser(description="Encrypt a file and hide it in a WAV file (sender).")
    p.add_argument("--infile", required=True, type=Path, help="Path to file to hide (binary/text).")
    p.add_argument("--cover", required=True, type=Path, help="Path to cover audio (wav/mp3/ogg/flac).")
    p.add_argument("--recipient-pub", required=True, type=Path, help="Path to recipient's public PEM file.")
    p.add_argument("--out", type=Path, help="Optional explicit output .wav path (default: <cover_stem>_stego.wav).")
    p.add_argument("--lsb", type=int, default=1, choices=[1,2], help="LSB bits per sample (1 or 2).")
    p.add_argument("--pad", action="store_true", help="If container does not fit, pad the WAV with silence to fit.")
    p.add_argument("--force", action="store_true", help="Overwrite output or use same name without incrementing.")
    p.add_argument("--no-compress", dest="compress", action="store_false", help="Do not gzip-compress plaintext before encryption.")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose debug logging.")
    return p

def main():
    parser = _build_parser()
    args = parser.parse_args()
    if args.verbose:
        log.setLevel(logging.DEBUG)

    try:
        out = run(
            infile=args.infile,
            cover=args.cover,
            recipient_pub=args.recipient_pub,
            out=args.out,
            lsb=args.lsb,
            pad=args.pad,
            force=args.force,
            compress=args.compress,
        )
        print(f"SUCCESS: Stego written to: {out}")
    except Exception as e:
        log.error("Operation failed: %s", e, exc_info=args.verbose)
        sys.exit(1)

if __name__ == "__main__":
    main()
