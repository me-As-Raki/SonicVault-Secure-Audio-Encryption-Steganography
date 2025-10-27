# src/stego.py
"""
Steganography Core Module (production-quality)

- Container format: HEADER (17 bytes) + payload
  HEADER: MAGIC(4) | VERSION(1) | PAYLOAD_LEN(4 BE) | CHECKSUM(8)
- LSB embedding into 16-bit PCM WAV (interleaved samples)
- Functions:
    build_container(payload_bytes) -> bytes
    parse_container(container_bytes) -> payload_bytes
    wav_capacity_bytes(wav_path, lsb_count=1) -> int (bytes)
    embed_bytes_in_wav(container_bytes, cover_wav_path, stego_wav_path, lsb_count=1)
    extract_bytes_from_wav(stego_wav_path, lsb_count=1) -> container_bytes
"""

from __future__ import annotations
import wave
import struct
import hashlib
import logging
from pathlib import Path
from typing import Union, Iterator

# Configure logger
logger = logging.getLogger("stego")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%H:%M:%S"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# --- Container header ---
MAGIC_BYTES = b"STEG"
HEADER_VERSION = 0x01
HEADER_FORMAT = "!4s B I 8s"   # big-endian: 4s, 1 byte, 4-byte unsigned int, 8 bytes checksum
HEADER_LENGTH = struct.calcsize(HEADER_FORMAT)  # expected 17
CHECKSUM_LENGTH = 8

# --- Exceptions ---
class SteganographyError(Exception):
    pass

class CapacityError(SteganographyError):
    pass

class InvalidHeaderError(SteganographyError):
    pass

class ChecksumMismatchError(SteganographyError):
    pass


# -----------------------
# Container helpers
# -----------------------
def build_container(payload_bytes: bytes) -> bytes:
    """Return container bytes with header + payload."""
    if not isinstance(payload_bytes, (bytes, bytearray)):
        raise TypeError("payload_bytes must be bytes")
    payload_len = len(payload_bytes)
    checksum = hashlib.sha256(payload_bytes).digest()[:CHECKSUM_LENGTH]
    header = struct.pack(HEADER_FORMAT, MAGIC_BYTES, HEADER_VERSION, payload_len, checksum)
    return header + payload_bytes


def parse_container(container_bytes: bytes) -> bytes:
    """Validate container and return payload_bytes (raises on error)."""
    if not isinstance(container_bytes, (bytes, bytearray)):
        raise TypeError("container_bytes must be bytes")
    if len(container_bytes) < HEADER_LENGTH:
        raise InvalidHeaderError(f"Container too short: {len(container_bytes)} bytes (need {HEADER_LENGTH})")

    header = container_bytes[:HEADER_LENGTH]
    payload = container_bytes[HEADER_LENGTH:]
    magic, version, payload_len, checksum = struct.unpack(HEADER_FORMAT, header)

    if magic != MAGIC_BYTES:
        raise InvalidHeaderError(f"Invalid magic: {magic!r}")
    if version != HEADER_VERSION:
        raise InvalidHeaderError(f"Unsupported header version: {version}")
    if payload_len != len(payload):
        raise InvalidHeaderError(f"Header payload length {payload_len} != actual {len(payload)}")

    expected_checksum = hashlib.sha256(payload).digest()[:CHECKSUM_LENGTH]
    if checksum != expected_checksum:
        raise ChecksumMismatchError("Checksum mismatch: payload may be corrupted")

    return payload


# -----------------------
# WAV capacity helper
# -----------------------
def wav_capacity_bytes(wav_path: Union[str, Path], lsb_count: int = 1) -> int:
    """Return how many payload bytes can be embedded into wav_path with given lsb_count."""
    if lsb_count not in (1, 2):
        raise ValueError("lsb_count must be 1 or 2")
    with wave.open(str(wav_path), "rb") as wf:
        sampwidth = wf.getsampwidth()
        if sampwidth != 2:
            raise SteganographyError("Only 16-bit PCM WAV supported for capacity calculation")
        n_frames = wf.getnframes()
        n_channels = wf.getnchannels()
    total_samples = n_frames * n_channels
    capacity_bits = total_samples * lsb_count
    return capacity_bits // 8


# -----------------------
# Bit generators
# -----------------------
def _bits_from_bytes(payload: bytes) -> Iterator[int]:
    """Yield bits MSB -> LSB for each payload byte."""
    for b in payload:
        for i in range(7, -1, -1):
            yield (b >> i) & 1


def _bytes_from_bits(bits_iter: Iterator[int], num_bits: int) -> bytes:
    """
    Consume num_bits from bits_iter (generator) and return bytes assembled
    MSB-first per byte. Assumes num_bits is a multiple of 8.
    """
    if num_bits % 8 != 0:
        raise ValueError("num_bits must be a multiple of 8")
    out = bytearray()
    bits_collected = 0
    current = 0
    for _ in range(num_bits):
        try:
            bit = next(bits_iter)
        except StopIteration:
            raise SteganographyError("Ran out of bits while assembling bytes")
        current = (current << 1) | (bit & 1)
        bits_collected += 1
        if bits_collected == 8:
            out.append(current)
            bits_collected = 0
            current = 0
    return bytes(out)


# -----------------------
# Embedding / Extraction
# -----------------------
def embed_bytes_in_wav(
    container_bytes: bytes,
    cover_wav_path: Union[str, Path],
    stego_wav_path: Union[str, Path],
    lsb_count: int = 1,
    start_sample: int = 0,
) -> None:
    """
    Embed container_bytes into a 16-bit PCM WAV cover file and write stego WAV.

    - container_bytes: full container (header + payload)
    - start_sample: sample index to start embedding (default 0)
    """
    if lsb_count not in (1, 2):
        raise ValueError("lsb_count must be 1 or 2")
    if not isinstance(container_bytes, (bytes, bytearray)):
        raise TypeError("container_bytes must be bytes")

    cover_path = Path(cover_wav_path)
    out_path = Path(stego_wav_path)

    with wave.open(str(cover_path), "rb") as fin:
        params = fin.getparams()   # nchannels, sampwidth, framerate, nframes, comptype, compname
        n_channels = fin.getnchannels()
        sampwidth = fin.getsampwidth()
        n_frames = fin.getnframes()
        comptype = fin.getcomptype()
        compname = fin.getcompname()
        frames_bytes = bytearray(fin.readframes(n_frames))

    if sampwidth != 2:
        raise SteganographyError("Only 16-bit PCM WAV files supported")

    total_samples = n_frames * n_channels
    capacity_bytes = (total_samples * lsb_count) // 8
    if len(container_bytes) > capacity_bytes:
        raise CapacityError(f"Container too large: requires {len(container_bytes)} bytes, capacity {capacity_bytes} bytes (lsb={lsb_count})")

    logger.info("Embedding: samples=%d, capacity_bytes=%d, payload_bytes=%d", total_samples, capacity_bytes, len(container_bytes))

    bit_iter = _bits_from_bytes(container_bytes)

    mask = (1 << lsb_count) - 1
    clear_mask = (~mask) & 0xFFFF  # operate on 16-bit unsigned

    # iterate samples from start_sample
    sample_index = start_sample
    bytes_len = len(frames_bytes)
    # Each sample is 2 bytes (little-endian). total_samples = bytes_len // 2
    for sample_index in range(start_sample, total_samples):
        byte_off = sample_index * 2
        if byte_off + 2 > bytes_len:
            break
        # read signed 16-bit sample
        sample = struct.unpack_from("<h", frames_bytes, byte_off)[0]
        u = sample & 0xFFFF  # unsigned 0..65535

        # collect up to lsb_count bits
        bits_value = 0
        got_any = False
        for bpos in range(lsb_count):
            try:
                bit = next(bit_iter)
            except StopIteration:
                bit = None
            if bit is None:
                # finished embedding all bits
                got_any = got_any or False
                break
            got_any = True
            # place bit into position bpos (LSB is position 0)
            bits_value |= (bit & 1) << bpos

        if not got_any:
            # nothing left to embed; stop looping
            break

        # clear current LSBs and set new bits
        u = (u & clear_mask) | bits_value

        # convert back to signed
        if u & 0x8000:
            new_sample = u - 0x10000
        else:
            new_sample = u

        # write back
        struct.pack_into("<h", frames_bytes, byte_off, new_sample)

    # write out WAV with same params
    with wave.open(str(out_path), "wb") as fout:
        fout.setparams((n_channels, sampwidth, fin.getframerate(), n_frames, comptype, compname))
        fout.writeframes(bytes(frames_bytes))

    logger.info("Embedding complete. Output: %s", str(out_path))


def extract_bytes_from_wav(stego_wav_path: Union[str, Path], lsb_count: int = 1, start_sample: int = 0) -> bytes:
    """
    Extract the embedded container from stego WAV and return container_bytes.
    Raises exceptions if header invalid or truncated.
    """
    if lsb_count not in (1, 2):
        raise ValueError("lsb_count must be 1 or 2")

    path = Path(stego_wav_path)
    with wave.open(str(path), "rb") as fin:
        n_channels = fin.getnchannels()
        sampwidth = fin.getsampwidth()
        n_frames = fin.getnframes()
        frames_bytes = fin.readframes(n_frames)

    if sampwidth != 2:
        raise SteganographyError("Only 16-bit PCM WAV files supported")

    total_samples = n_frames * n_channels
    total_bits_available = total_samples * lsb_count

    # Helper to generate the sequence of embedded bits, sample by sample
    def embedded_bit_stream() -> Iterator[int]:
        bytes_len = len(frames_bytes)
        for sample_index in range(start_sample, total_samples):
            byte_off = sample_index * 2
            if byte_off + 2 > bytes_len:
                break
            sample = struct.unpack_from("<h", frames_bytes, byte_off)[0]
            u = sample & 0xFFFF
            for bpos in range(lsb_count):
                yield (u >> bpos) & 1

    bit_gen = embedded_bit_stream()

    # 1) Extract header bits
    header_bits = HEADER_LENGTH * 8
    if header_bits > total_bits_available:
        raise SteganographyError("Not enough embedded bits for header")

    header_bytes = _bytes_from_bits(bit_gen, header_bits)
    try:
        magic, version, payload_len, checksum = struct.unpack(HEADER_FORMAT, header_bytes)
    except Exception as e:
        raise InvalidHeaderError(f"Failed to unpack header: {e}")

    if magic != MAGIC_BYTES:
        raise InvalidHeaderError(f"Invalid magic: {magic!r}")

    # 2) Determine total container bits
    total_container_bits = (HEADER_LENGTH + payload_len) * 8
    if total_container_bits > total_bits_available:
        raise SteganographyError(f"Not enough embedded bits for full container: need {total_container_bits}, have {total_bits_available}")

    # We've consumed HEADER_LENGTH*8 bits already from bit_gen; now consume the remaining payload bits
    remaining_bits = (HEADER_LENGTH + payload_len) * 8 - header_bits
    payload_bytes = _bytes_from_bits(bit_gen, remaining_bits)

    container_bytes = header_bytes + payload_bytes

    # Validate container (checksum, lengths)
    # parse_container returns payload and raises on mismatch; we want to raise same exceptions here
    _ = parse_container(container_bytes)  # will raise if corrupted
    logger.info("Extraction complete: container %d bytes", len(container_bytes))
    return container_bytes


# -----------------------
# Small helpers & self-test
# -----------------------
def _make_test_wav(path: Union[str, Path], duration_s: float = 1.0, framerate: int = 44100, nchannels: int = 2):
    """Create a deterministic 16-bit PCM WAV (silence) for tests."""
    n_frames = int(duration_s * framerate)
    with wave.open(str(path), "wb") as wf:
        wf.setparams((nchannels, 2, framerate, n_frames, "NONE", "not compressed"))
        # write silence
        frame_sample = (0).to_bytes(2, "little", signed=True)
        frame = frame_sample * nchannels
        # write in chunks for performance
        chunk = 1024
        frames_left = n_frames
        while frames_left > 0:
            write_n = min(chunk, frames_left)
            wf.writeframes(frame * write_n)
            frames_left -= write_n


if __name__ == "__main__":
    import tempfile
    import os

    logger.setLevel(logging.INFO)
    print("=== stego.py self-test ===")
    with tempfile.TemporaryDirectory() as td:
        cover = os.path.join(td, "cover.wav")
        stego = os.path.join(td, "stego.wav")
        _make_test_wav(cover, duration_s=0.5, framerate=44100, nchannels=2)
        print("Created test cover:", cover)

        payload = b'{"msg":"stego test","value":12345}'
        container = build_container(payload)
        print("Container size:", len(container))
        cap = wav_capacity_bytes(cover, lsb_count=1)
        print("Cover capacity (bytes):", cap)
        assert len(container) <= cap

        embed_bytes_in_wav(container, cover, stego, lsb_count=1)
        print("Embedded to:", stego)

        extracted = extract_bytes_from_wav(stego, lsb_count=1)
        parsed = parse_container(extracted)
        assert parsed == payload
        print("Roundtrip OK")

        # capacity error test
        try:
            big = bytes(cap + 10)
            embed_bytes_in_wav(build_container(big), cover, stego, lsb_count=1)
            raise AssertionError("CapacityError expected")
        except CapacityError:
            print("CapacityError correctly raised")

        # tamper test: embed tampered container, extraction should raise checksum error
        tampered = bytearray(container)
        tampered[-1] ^= 0x01
        embed_bytes_in_wav(bytes(tampered), cover, stego, lsb_count=1)
        try:
            extract_bytes_from_wav(stego, lsb_count=1)
            raise AssertionError("ChecksumMismatchError expected")
        except ChecksumMismatchError:
            print("ChecksumMismatchError correctly raised")

    print("=== stego.py self-test passed ===")
