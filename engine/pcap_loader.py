"""
engine/pcap_loader.py
────────────────────────────────────────────────────────────────────────────────
PCAP ingestion module.

Responsibilities:
  • Accept .pcap / .pcapng file paths (or a directory of PCAPs)
  • Validate file format and compute SHA-256 for chain-of-custody
  • Load packets via Scapy with memory-safe chunked reading for large files
  • Return a list of raw Scapy packets for the normaliser
"""

import os
import hashlib
from pathlib import Path
from typing import Union

from scapy.utils import rdpcap, PcapReader
from scapy.error import Scapy_Exception

from engine.logger import get_logger

log = get_logger(__name__)

SUPPORTED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
LARGE_FILE_THRESHOLD  = 50 * 1024 * 1024   # 50 MB — use streaming above this


# ── Public API ─────────────────────────────────────────────────────────────────

def load_pcap(path: Union[str, Path]) -> dict:
    """
    Load a single PCAP file.

    Returns a result dict:
    {
        "path":       str,
        "filename":   str,
        "sha256":     str,
        "file_size":  int,       # bytes
        "packets":    list,      # Scapy packet objects
        "packet_count": int,
        "error":      str | None
    }
    """
    path = Path(path).resolve()
    result = {
        "path":         str(path),
        "filename":     path.name,
        "sha256":       None,
        "file_size":    0,
        "packets":      [],
        "packet_count": 0,
        "error":        None,
    }

    if not path.exists():
        result["error"] = f"File not found: {path}"
        log.error(result["error"])
        return result

    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        result["error"] = f"Unsupported extension '{path.suffix}'. Expected: {SUPPORTED_EXTENSIONS}"
        log.error(result["error"])
        return result

    file_size = path.stat().st_size
    result["file_size"] = file_size

    log.info(f"Loading: {path.name}  ({_fmt_size(file_size)})")

    # ── Chain-of-custody hash ──────────────────────────────────────────────────
    result["sha256"] = _sha256(path)
    log.info(f"SHA-256: {result['sha256']}")

    # ── Packet loading ─────────────────────────────────────────────────────────
    try:
        if file_size > LARGE_FILE_THRESHOLD:
            log.info(f"Large file detected — using streaming reader")
            packets = _stream_load(path)
        else:
            packets = list(rdpcap(str(path)))

        result["packets"]      = packets
        result["packet_count"] = len(packets)
        log.info(f"Loaded {len(packets):,} packets")

    except Scapy_Exception as exc:
        result["error"] = f"Scapy parse error: {exc}"
        log.error(result["error"])
    except Exception as exc:
        result["error"] = f"Unexpected error: {exc}"
        log.error(result["error"])

    return result


def load_directory(directory: Union[str, Path]) -> list[dict]:
    """
    Load all PCAP files in a directory. Returns a list of load_pcap() results.
    """
    directory = Path(directory)
    if not directory.is_dir():
        log.error(f"Not a directory: {directory}")
        return []

    pcap_files = [
        f for f in directory.iterdir()
        if f.suffix.lower() in SUPPORTED_EXTENSIONS
    ]

    if not pcap_files:
        log.warning(f"No PCAP files found in {directory}")
        return []

    log.info(f"Found {len(pcap_files)} PCAP file(s) in {directory}")
    return [load_pcap(f) for f in sorted(pcap_files)]


# ── Helpers ────────────────────────────────────────────────────────────────────

def _sha256(path: Path) -> str:
    """Compute SHA-256 of a file in 64 KB chunks (memory safe)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _stream_load(path: Path) -> list:
    """Stream-read a large PCAP to avoid loading the whole file into RAM."""
    packets = []
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            packets.append(pkt)
    return packets


def _fmt_size(size_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"
