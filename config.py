"""
config.py  —  PCAP Engine Configuration
Edit API keys and thresholds here, or set environment variables.
"""
import os

# ── Project paths ─────────────────────────────────────────────────────────────
BASE_DIR       = os.path.dirname(os.path.abspath(__file__))
DATA_DIR       = os.path.join(BASE_DIR, "data")
SAMPLES_DIR    = os.path.join(DATA_DIR, "samples")
EXTRACTED_DIR  = os.path.join(BASE_DIR, "extracted_files")
CASES_DIR      = os.path.join(BASE_DIR, "cases")          # per-case output folders
REPORTS_DIR    = os.path.join(BASE_DIR, "reports")
DB_PATH        = os.path.join(DATA_DIR, "flows.db")

# ── API Keys ──────────────────────────────────────────────────────────────────
# Set via environment variable:  export VT_API_KEY="your_key"
# Or replace the empty string below with your key directly.
VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY", "")

# ── Detection thresholds ──────────────────────────────────────────────────────
BEACON_INTERVAL_STD_MAX     = 2.0     # legacy — beacon_detector uses CV_STRONG/CV_WEAK
BEACON_MIN_PACKETS          = 10      # min packets to check for beacon (raised — reduces FP on short flows)
DNS_ENTROPY_THRESHOLD       = 4.0     # Shannon entropy above this = suspicious (raised — 3.5 catches legitimate b64 subdomains)
DNS_LONG_SUBDOMAIN_CHARS    = 50      # chars above this = tunnelling candidate
DNS_HIGH_QUERY_RATE         = 80      # queries/min above this = suspicious (raised — 20 fires on normal resolvers)
HTTP_LARGE_UPLOAD_BYTES     = 1_000_000 # POST body above this = exfiltration flag (1MB — 500KB too sensitive)

# ── Beacon CV thresholds (calibrated against real malware data) ──────────────
# CV_STRONG: very tight beacon (Cobalt Strike, TrickBot, Dridex) — high confidence
# CV_WEAK:   jittered beacon (QakBot, Emotet) — moderate confidence
# Replacing old CV_STRICT/CV_MODERATE constants in beacon_detector.py
BEACON_INTERVAL_CV_STRONG   = 0.3   # below this = strong beacon signal
BEACON_INTERVAL_CV_WEAK     = 0.8   # below this = weak/jittered beacon signal
BEACON_MIN_CONNECTIONS      = 4     # min host-pair connections to analyse

# ── Severity thresholds (0-100 score) ─────────────────────────────────────────
SEVERITY_CRITICAL_THRESHOLD = 80
SEVERITY_HIGH_THRESHOLD     = 60
SEVERITY_MEDIUM_THRESHOLD   = 40

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_LEVEL = "INFO"   # DEBUG | INFO | WARNING | ERROR
