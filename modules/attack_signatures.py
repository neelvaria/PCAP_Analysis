"""
modules/attack_signatures.py
────────────────────────────────────────────────────────────────────────────────
Signature-based attack detection layer — SOC upgrade.

Detects specific attack tools and behaviors by matching payload bytes,
port patterns, and behavioral fingerprints. Distinct from statistical
beacon analysis — this is rule-based detection.

Detects:
  - Metasploit Meterpreter (stage 1 & 2 patterns)
  - Reverse TCP/UDP shells
  - Bind shells
  - PowerShell Empire / Cobalt Strike HTTP signatures
  - Common RAT command patterns
  - Credential harvesting patterns
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from engine.session_tracker import Flow
from engine.logger import get_logger

log = get_logger(__name__)


# ── Signature database ─────────────────────────────────────────────────────────

@dataclass
class Signature:
    id:          str
    name:        str
    description: str
    severity:    str    # CRITICAL | HIGH | MEDIUM
    score:       int    # points to add to threat score
    mitre_id:    str
    mitre_name:  str


# Port-based signatures (no payload needed)
PORT_SIGNATURES: dict[int, Signature] = {
    4444:  Signature("SIG-001", "Metasploit default port",
                     "TCP 4444 is Metasploit Meterpreter's default listener port",
                     "CRITICAL", 55, "T1571", "Non-Standard Port"),
    4445:  Signature("SIG-002", "Metasploit alternate port",
                     "TCP 4445 used by Metasploit when 4444 is blocked",
                     "HIGH", 45, "T1571", "Non-Standard Port"),
    1337:  Signature("SIG-003", "Leet/Hacktools port",
                     "Port 1337 associated with hacking tools and backdoors",
                     "HIGH", 40, "T1571", "Non-Standard Port"),
    31337: Signature("SIG-004", "Back Orifice / hacktools",
                     "Classic RAT port, Back Orifice malware",
                     "CRITICAL", 55, "T1571", "Non-Standard Port"),
    5555:  Signature("SIG-005", "Android ADB over network",
                     "Android Debug Bridge — remote device control",
                     "HIGH", 40, "T1437", "Application Layer Protocol"),
    9001:  Signature("SIG-006", "Tor relay or C2",
                     "Tor OR port or generic C2 tunnel",
                     "MEDIUM", 30, "T1090.003", "Multi-hop Proxy: Onion Routing"),
    6666:  Signature("SIG-007", "IRC C2 channel",
                     "Port 6666/6667 used by IRC-based botnets",
                     "HIGH", 45, "T1071.003", "Application Layer Protocol: Mail Protocols"),
    6667:  Signature("SIG-007", "IRC C2 channel",
                     "Port 6666/6667 used by IRC-based botnets",
                     "HIGH", 45, "T1071.003", "Application Layer Protocol: Mail Protocols"),
    8888:  Signature("SIG-008", "Generic C2/RAT port",
                     "8888 used by various RAT frameworks",
                     "MEDIUM", 25, "T1571", "Non-Standard Port"),
}

# Payload byte signatures (applied to TCP stream payloads)
# Format: (pattern_bytes_or_regex, signature_object)
PAYLOAD_SIGNATURES: list[tuple] = [
    # Meterpreter stage 1: MZ header over raw TCP (reflective DLL injection)
    (b"\x4d\x5a\x90\x00\x03\x00",
     Signature("SIG-100", "Meterpreter PE stage",
               "MZ PE header transmitted over raw TCP — Meterpreter DLL injection",
               "CRITICAL", 70, "T1055.001", "Process Injection: Dynamic-link Library Injection")),

    # Meterpreter reverse_tcp stage 2 marker
    (b"\x60\x89\xe5\x31\xc0\x64\x8b",
     Signature("SIG-101", "Meterpreter shellcode",
               "x86 shellcode prologue matching Metasploit reverse_tcp stager",
               "CRITICAL", 75, "T1059.003", "Command and Scripting Interpreter: Windows Command Shell")),

    # PowerShell Empire beacon check-in (base64 encoded PS)
    (b"powershell -nop -w hidden -encodedcommand",
     Signature("SIG-102", "PowerShell Empire beacon",
               "PowerShell Empire C2 check-in with encoded command",
               "CRITICAL", 70, "T1059.001", "Command and Scripting Interpreter: PowerShell")),

    # Cobalt Strike default HTTP malleable C2
    (b"Cookie: __cfduid=",
     Signature("SIG-103", "Cobalt Strike HTTP beacon",
               "Cobalt Strike default HTTP malleable C2 cookie pattern",
               "CRITICAL", 65, "T1071.001", "Application Layer Protocol: Web Protocols")),

    # Netcat reverse shell
    (b"/bin/sh",
     Signature("SIG-104", "Reverse shell /bin/sh",
               "Shell binary path transmitted — likely reverse shell command",
               "CRITICAL", 60, "T1059.004", "Command and Scripting Interpreter: Unix Shell")),

    (b"/bin/bash",
     Signature("SIG-105", "Reverse shell /bin/bash",
               "Bash binary path transmitted — likely reverse shell command",
               "CRITICAL", 60, "T1059.004", "Command and Scripting Interpreter: Unix Shell")),

    # cmd.exe over network
    (b"cmd.exe",
     Signature("SIG-106", "cmd.exe over network",
               "Windows command interpreter path in network payload",
               "HIGH", 50, "T1059.003", "Windows Command Shell")),

    # Mimikatz
    (b"sekurlsa",
     Signature("SIG-107", "Mimikatz credential dump",
               "Mimikatz sekurlsa module — credential harvesting",
               "CRITICAL", 80, "T1003.001", "OS Credential Dumping: LSASS Memory")),

    (b"lsadump",
     Signature("SIG-108", "Mimikatz lsadump",
               "Mimikatz lsadump — Active Directory credential extraction",
               "CRITICAL", 80, "T1003.003", "OS Credential Dumping: NTDS")),

    # Reverse shell pattern: bash -i >& /dev/tcp/
    (b"bash -i",
     Signature("SIG-109", "Interactive reverse shell",
               "bash -i pattern — interactive reverse shell initiation",
               "CRITICAL", 65, "T1059.004", "Unix Shell")),

    # Python reverse shell
    (b"import socket,subprocess",
     Signature("SIG-110", "Python reverse shell",
               "Python socket+subprocess pattern — scripted reverse shell",
               "CRITICAL", 65, "T1059.006", "Python")),

    # WMI lateral movement
    (b"wmic",
     Signature("SIG-111", "WMI remote execution",
               "WMIC in network payload — possible WMI lateral movement",
               "HIGH", 50, "T1047", "Windows Management Instrumentation")),

    # PsExec
    (b"\\psexesvc",
     Signature("SIG-112", "PsExec service",
               "PsExec service name in payload — remote lateral movement",
               "HIGH", 55, "T1021.002", "Remote Services: SMB/Windows Admin Shares")),
]

# Behavioral signatures (applied to flow statistics, not payload)
@dataclass
class BehavioralResult:
    triggered: bool = False
    signatures: list[Signature] = field(default_factory=list)
    total_score: int = 0
    reasons: list[str] = field(default_factory=list)


def check_signatures(flow: Flow) -> BehavioralResult:
    """
    Run all signature checks against a flow.
    Returns BehavioralResult with all triggered signatures.
    """
    result = BehavioralResult()

    # 1. Port-based checks
    for port in (flow.dst_port, flow.src_port):
        if port and port in PORT_SIGNATURES:
            sig = PORT_SIGNATURES[port]
            result.signatures.append(sig)
            result.total_score += sig.score
            result.reasons.append(
                f"[{sig.id}] {sig.name}: {sig.description} "
                f"(port={port}, MITRE {sig.mitre_id})"
            )

    # 2. Payload byte signatures
    payload = flow.payload_bytes
    if payload:
        payload_lower = payload.lower()
        for pattern, sig in PAYLOAD_SIGNATURES:
            if isinstance(pattern, bytes):
                needle = pattern.lower()
                if needle in payload_lower:
                    result.signatures.append(sig)
                    result.total_score += sig.score
                    offset = payload_lower.find(needle)
                    result.reasons.append(
                        f"[{sig.id}] {sig.name}: {sig.description} "
                        f"(offset={offset}, MITRE {sig.mitre_id})"
                    )

    # 3. Behavioral: reverse shell profile
    #    Low packet count, bidirectional, external IP, non-standard port
    if (flow.protocol == "TCP"
            and flow.packet_count >= 4
            and flow.dst_port not in (80, 443, 22, 25, 53)
            and flow.byte_count < 50_000
            and flow.duration_sec > 10):
        # Check for interactive pattern: roughly equal tx/rx sizes suggest shell
        # (we approximate: if payload exists and is small and bidirectional)
        if flow.payload_bytes and 100 < len(flow.payload_bytes) < 5000:
            sig = Signature(
                "SIG-200", "Reverse shell behavioral profile",
                "Small bidirectional TCP flow on non-standard port "
                "with interactive-sized payloads matches reverse shell pattern",
                "HIGH", 35, "T1059", "Command and Scripting Interpreter"
            )
            result.signatures.append(sig)
            result.total_score += sig.score
            result.reasons.append(
                f"[{sig.id}] {sig.name}: {sig.description}"
            )

    result.triggered = result.total_score > 0
    return result


def get_highest_severity(result: BehavioralResult) -> str:
    """Return the highest severity from all triggered signatures."""
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    if not result.signatures:
        return "LOW"
    return max(result.signatures, key=lambda s: order.get(s.severity, 0)).severity
