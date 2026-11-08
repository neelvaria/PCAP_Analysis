"""
modules/file_extractor.py
────────────────────────────────────────────────────────────────────────────────
File extraction module — Week 3.

Extracts files transferred over network flows:
  1. tshark --export-objects (HTTP) — pulls files from HTTP streams
  2. Raw carving from TCP payloads — detects files by magic bytes
  3. python-magic — identifies true file type regardless of extension
  4. MD5 + SHA256 hash computation for each extracted file
  5. VirusTotal API lookup (optional — requires API key in config)

Output:
  • Extracted files written to extracted_files/ directory
  • ExtractedFile objects with full metadata
"""

from __future__ import annotations

import os
import hashlib
import subprocess
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests

from engine.session_tracker import Flow
from engine.logger import get_logger
from config import VIRUSTOTAL_API_KEY, EXTRACTED_DIR

log = get_logger(__name__)

# ── Magic byte signatures for file carving ────────────────────────────────────
# Format: (magic_bytes, offset, extension, description)
MAGIC_SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n",         0,  ".png",  "PNG image"),
    (b"\xff\xd8\xff",              0,  ".jpg",  "JPEG image"),
    (b"GIF87a",                    0,  ".gif",  "GIF image"),
    (b"GIF89a",                    0,  ".gif",  "GIF image"),
    (b"%PDF",                      0,  ".pdf",  "PDF document"),
    (b"PK\x03\x04",                0,  ".zip",  "ZIP archive"),
    (b"PK\x05\x06",                0,  ".zip",  "ZIP archive (empty)"),
    (b"\x1f\x8b\x08",              0,  ".gz",   "Gzip archive"),
    (b"Rar!\x1a\x07",              0,  ".rar",  "RAR archive"),
    (b"\x7fELF",                   0,  ".elf",  "ELF executable"),
    (b"MZ",                        0,  ".exe",  "Windows PE executable"),
    (b"\xd0\xcf\x11\xe0",          0,  ".doc",  "MS Office document"),
    (b"ftyp",                      4,  ".mp4",  "MP4 video"),
    (b"<!DOCTYPE html",            0,  ".html", "HTML document"),
    (b"<html",                     0,  ".html", "HTML document"),
    (b"#!/",                       0,  ".sh",   "Shell script"),
    (b"#!/usr/bin/python",         0,  ".py",   "Python script"),
    (b"\x50\x4b\x03\x04\x14\x00\x06\x00", 0, ".docx", "DOCX document"),
]

# VirusTotal API base URL
VT_URL = "https://www.virustotal.com/api/v3/files"


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class ExtractedFile:
    filename:      str
    filepath:      str
    size_bytes:    int
    md5:           str
    sha256:        str
    file_type:     str          # from python-magic or magic byte detection
    extension:     str
    source_flow:   str          # "src_ip:port → dst_ip:port"
    extract_method: str         # "tshark" | "carve"

    # VirusTotal results
    vt_checked:    bool = False
    vt_malicious:  int  = 0
    vt_suspicious: int  = 0
    vt_harmless:   int  = 0
    vt_undetected: int  = 0
    vt_total:      int  = 0
    vt_verdict:    str  = "UNKNOWN"   # UNKNOWN | UNDETECTED | SUSPICIOUS | MALICIOUS | SKIPPED | ERROR
    vt_link:       str  = ""


# ── Public API ─────────────────────────────────────────────────────────────────

def extract_files(pcap_path: str, flows: list[Flow]) -> list[ExtractedFile]:
    """
    Main extraction pipeline.
    1. Run tshark HTTP object export on the PCAP
    2. Carve files from raw TCP payloads of large flows
    3. Hash all extracted files
    4. VirusTotal lookup (if API key configured)
    """
    os.makedirs(EXTRACTED_DIR, exist_ok=True)
    extracted: list[ExtractedFile] = []

    # Method 1: tshark HTTP object export
    tshark_files = _tshark_export(pcap_path)
    extracted.extend(tshark_files)

    # Method 2: raw payload carving from TCP flows
    carved = _carve_from_flows(flows)
    extracted.extend(carved)

    # Deduplicate by SHA256
    seen: set[str] = set()
    unique: list[ExtractedFile] = []
    for ef in extracted:
        if ef.sha256 not in seen:
            seen.add(ef.sha256)
            unique.append(ef)
        else:
            # remove duplicate file from disk
            try: os.remove(ef.filepath)
            except: pass

    # VirusTotal lookup
    if VIRUSTOTAL_API_KEY:
        for ef in unique:
            _vt_lookup(ef)
    else:
        for ef in unique:
            ef.vt_verdict = "SKIPPED (no API key)"

    log.info(
        f"Extracted {len(unique)} unique files "
        f"(tshark:{len(tshark_files)} carved:{len(carved)})"
    )
    return unique


# ── Method 1: tshark export ────────────────────────────────────────────────────

def _tshark_export(pcap_path: str) -> list[ExtractedFile]:
    """Use tshark --export-objects to pull HTTP-transferred files."""
    out_dir = os.path.join(EXTRACTED_DIR, "tshark")
    os.makedirs(out_dir, exist_ok=True)

    cmd = [
        "tshark", "-r", pcap_path,
        "--export-objects", f"http,{out_dir}",
        "-q"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=30)
        if result.returncode != 0:
            log.debug(f"tshark export stderr: {result.stderr.decode()[:200]}")
    except subprocess.TimeoutExpired:
        log.warning("tshark export timed out")
        return []
    except FileNotFoundError:
        log.warning("tshark not found — skipping HTTP object export")
        return []

    files = []
    for fname in os.listdir(out_dir):
        fpath = os.path.join(out_dir, fname)
        if not os.path.isfile(fpath):
            continue
        ef = _build_extracted_file(fpath, fname, "tshark", "unknown flow")
        if ef:
            files.append(ef)

    if files:
        log.info(f"tshark exported {len(files)} file(s)")
    return files


# ── Method 2: Magic byte carving ───────────────────────────────────────────────

def _carve_from_flows(flows: list[Flow]) -> list[ExtractedFile]:
    """
    Scan TCP flow payloads for magic byte signatures.
    Only scan flows with significant payload (> 512 bytes).
    """
    carved: list[ExtractedFile] = []
    carve_dir = os.path.join(EXTRACTED_DIR, "carved")
    os.makedirs(carve_dir, exist_ok=True)

    for flow in flows:
        if flow.protocol != "TCP" or len(flow.payload_bytes) < 512:
            continue
        payload = flow.payload_bytes
        flow_id = f"{flow.src_ip}:{flow.src_port}→{flow.dst_ip}:{flow.dst_port}"

        for magic, offset, ext, desc in MAGIC_SIGNATURES:
            pos = 0
            while True:
                idx = payload.find(magic, pos)
                if idx == -1:
                    break
                if offset > 0 and idx < offset:
                    pos = idx + 1
                    continue

                # Extract from idx to end (or next magic boundary)
                chunk = payload[idx:]
                if len(chunk) < 64:   # too small to be real
                    pos = idx + 1
                    continue

                # Trim to estimated file boundary for common types
                chunk = _trim_to_file_boundary(chunk, ext)

                # Write to disk
                h       = hashlib.sha256(chunk).hexdigest()[:12]
                fname   = f"carved_{h}{ext}"
                fpath   = os.path.join(carve_dir, fname)
                with open(fpath, "wb") as f:
                    f.write(chunk)

                ef = _build_extracted_file(fpath, fname, "carve", flow_id)
                if ef:
                    ef.source_flow = flow_id
                    carved.append(ef)

                pos = idx + len(magic)

    if carved:
        log.info(f"Carved {len(carved)} file(s) from TCP payloads")
    return carved


def _trim_to_file_boundary(data: bytes, ext: str) -> bytes:
    """Attempt to trim carved data to a reasonable file size."""
    max_sizes = {
        ".exe": 10_000_000,
        ".pdf": 5_000_000,
        ".zip": 10_000_000,
        ".jpg": 2_000_000,
        ".png": 2_000_000,
        ".html": 500_000,
    }
    limit = max_sizes.get(ext, 1_000_000)
    return data[:limit]


# ── File metadata builder ──────────────────────────────────────────────────────

def _build_extracted_file(fpath: str, fname: str,
                           method: str, flow_id: str) -> Optional[ExtractedFile]:
    """Hash a file, detect its type, and return an ExtractedFile object."""
    try:
        data = open(fpath, "rb").read()
        if not data:
            return None

        md5    = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()
        ext    = Path(fname).suffix or ".bin"

        # Detect file type
        file_type = _detect_file_type(data, fpath)

        # Override extension from detected type if tshark gave us a generic name
        if not ext or ext in (".bin", ".dat", ""):
            for magic, offset, sig_ext, _ in MAGIC_SIGNATURES:
                if data[offset:offset+len(magic)] == magic:
                    ext = sig_ext
                    break

        return ExtractedFile(
            filename       = fname,
            filepath       = fpath,
            size_bytes     = len(data),
            md5            = md5,
            sha256         = sha256,
            file_type      = file_type,
            extension      = ext,
            source_flow    = flow_id,
            extract_method = method,
        )
    except Exception as e:
        log.debug(f"Failed to process {fpath}: {e}")
        return None


def _detect_file_type(data: bytes, fpath: str = "") -> str:
    """
    Detect file type.
    Strategy: magic byte table first (reliable on partial data),
    then python-magic for enrichment, then printability check.
    """
    # 1. Our own magic byte table — works on minimal data
    for magic_bytes, offset, _, desc in MAGIC_SIGNATURES:
        if len(data) >= offset + len(magic_bytes):
            if data[offset:offset+len(magic_bytes)] == magic_bytes:
                # Try python-magic for a richer description
                try:
                    import magic as libmagic
                    rich = libmagic.from_buffer(data, mime=False)
                    if rich and rich != "data" and len(rich) > 4:
                        return rich
                except Exception:
                    pass
                return desc

    # 2. python-magic without a prior hit
    try:
        import magic as libmagic
        mime = libmagic.from_buffer(data, mime=True)
        if mime and mime not in ("application/octet-stream", "application/x-empty"):
            return mime
        desc = libmagic.from_buffer(data, mime=False)
        if desc and desc != "data":
            return desc
    except Exception:
        pass

    # 3. Printability check
    printable = sum(1 for b in data[:256] if 32 <= b < 127)
    if len(data) > 0 and printable / min(len(data), 256) > 0.75:
        return "ASCII text"
    return "Binary data"


# ── VirusTotal lookup ──────────────────────────────────────────────────────────

def _vt_lookup(ef: ExtractedFile):
    """Query VirusTotal for a file hash. Updates ef in-place."""
    if not VIRUSTOTAL_API_KEY:
        ef.vt_verdict = "SKIPPED"
        return

    try:
        headers  = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(
            f"{VT_URL}/{ef.sha256}",
            headers=headers,
            timeout=10
        )

        if response.status_code == 404:
            ef.vt_verdict = "NOT_FOUND"
            ef.vt_checked = True
            return

        if response.status_code == 200:
            stats = (response.json()
                     .get("data", {})
                     .get("attributes", {})
                     .get("last_analysis_stats", {}))

            ef.vt_malicious  = stats.get("malicious",  0)
            ef.vt_suspicious = stats.get("suspicious", 0)
            ef.vt_harmless   = stats.get("harmless",   0)
            ef.vt_undetected = stats.get("undetected", 0)
            ef.vt_total      = sum(stats.values())
            ef.vt_checked    = True
            ef.vt_link       = f"https://www.virustotal.com/gui/file/{ef.sha256}"

            if ef.vt_malicious > 3:
                ef.vt_verdict = "MALICIOUS"
            elif ef.vt_malicious > 0 or ef.vt_suspicious > 0:
                ef.vt_verdict = "SUSPICIOUS"
            else:
                ef.vt_verdict = "UNDETECTED"  # 0 detections, not confirmed clean
        else:
            ef.vt_verdict = f"API_ERROR_{response.status_code}"
            ef.vt_checked = True

    except requests.RequestException as e:
        ef.vt_verdict = "NETWORK_ERROR"
        log.debug(f"VT lookup failed for {ef.sha256[:12]}: {e}")
