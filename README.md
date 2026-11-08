# PCAP Session Reconstruction Engine — v2.5

SOC-grade network forensics platform. Ingests `.pcap`/`.pcapng` files and produces reconstructed sessions, C2 beacon detection, DNS exfiltration analysis, MITRE ATT&CK-mapped IOC reports, attack chain correlation, a Flask web dashboard, and court-ready PDF forensics reports. Every investigation is stored in an isolated case folder.

---

## Quick Start

### 1. System dependencies

```bash
# Ubuntu / Debian / Kali
sudo apt-get install tshark libmagic1 -y

# macOS
brew install wireshark libmagic

# Windows — install Wireshark from https://www.wireshark.org
# Tick "Add tshark to PATH" during install.
# pip install python-magic-bin      (Windows-only replacement for python-magic)
```

### 2. Python packages

```bash
cd pcap_engine
pip install -r requirements.txt
```

### 3. VirusTotal API key (optional)

```bash
export VT_API_KEY="your_key"          # Linux/macOS
set VT_API_KEY=your_key               # Windows CMD
$env:VT_API_KEY="your_key"            # Windows PowerShell
```

Or set directly in `config.py`:
```python
VIRUSTOTAL_API_KEY = "your_key_here"
```

---

## Web Dashboard

```bash
python web/app.py
# → http://127.0.0.1:5000
```

1. Click **+ New Investigation**
2. Enter a unique **Case Number** (e.g. `IR-2025-001`)
3. Drop or browse your `.pcap` / `.pcapng` file
4. Click **Start Analysis →**
5. Navigate: Sessions · Beacons · DNS · Files · IOCs · Chains · Timeline
6. Download **PDF Report**, **IOC CSV**, or **IOC JSON** from the analysis page

All files written to: `cases/web/<CASE_NUMBER>_<uuid8>/`

---

## CLI — main.py (batch, positional PCAP)

Accepts the PCAP as a positional argument. **Prompts for Case Number** after path validation.

```bash
python main.py <pcap_path> [flags]
```

### Examples

```bash
# Prompts for case number, prints sessions + beacons + DNS + IOCs
python main.py capture.pcap --sessions --beacons --dns --iocs

# Windows path (prompts for case number)
python main.py "C:\Users\Varia neel\Downloads\HackAttempts_Network_Capture.pcap" --sessions --beacons --dns --iocs

# All sections + PDF (prompts for case number)
python main.py capture.pcap --all --pdf

# Skip prompt with -c
python main.py capture.pcap --all --pdf -c CASE-2025-001

# Custom analyst name and organisation in PDF
python main.py capture.pcap --pdf -c IR-001 --analyst "Neel Patel" --org "NFSU CSDF"
```

### Flags

| Flag | Description |
|---|---|
| `-c`, `--case` | Case number — skips interactive prompt |
| `--sessions` | Print reconstructed flow table |
| `--http` | Print HTTP request/response pairs |
| `--dissect` | Print protocol dissection summary |
| `--files` | Print extracted files + VirusTotal verdicts |
| `--beacons` | Print C2 beacon detection results |
| `--dns` | Print DNS analysis (DGA, tunnelling, entropy) |
| `--iocs` | Print IOC report with MITRE ATT&CK mapping |
| `--chains` | Print attack chain correlation |
| `--pdf` | Generate PDF forensics report into case folder |
| `--json` | Show case folder file listing |
| `--all` | Enable all output flags |
| `--analyst` | Analyst name for PDF (default: SOC Analyst) |
| `--org` | Organisation name for PDF |

Output location: `cases/cli/<CASE_NUMBER>_<uuid8>/`

---

## CLI — cli.py (interactive mode)

```bash
python cli.py                                          # fully interactive
python cli.py -f capture.pcap -c IR-001 --all          # scripted
python cli.py -f capture.pcap -c IR-001 --beacons --iocs --pdf
python cli.py -f capture.pcap -c IR-001 --all --pdf --json --open-folder
python cli.py --list-cases                             # show all cases + folders
```

### Additional cli.py flags

| Flag | Description |
|---|---|
| `-f`, `--pcap` | PCAP file path |
| `--list-cases` | List all cases with folder paths and exit |
| `--open-folder` | Open case folder in file manager after analysis |

Output location: `cases/cli/<CASE_NUMBER>_<uuid8>/`

---

## Running Tests

```bash
python tests/test_calibration.py   # 25/25  — beacon + DNS calibration
python tests/test_week1.py         # 5/5    — ingestion, normalisation
python tests/test_week2.py         # 7/7    — session reconstruction
python tests/test_week3.py         # 9/9    — protocol dissection, file extraction
python tests/test_week4.py         # 10/10  — beacon, DNS, IOC detection
python tests/test_week6.py         # 10/10  — PDF report generation
# Total: 66 tests, 0 failures
```

---

## Case Folder Layout

```
cases/
├── cli/                              ← main.py and cli.py analyses
│   └── IR-2025-001_b93aed11/
│       ├── case_meta.json
│       ├── HackAttempts.pcap         ← chain-of-custody copy
│       ├── iocs.csv
│       ├── iocs.json
│       ├── summary.json
│       └── forensic_report_<ts>.pdf
└── web/                              ← web dashboard analyses
    └── CASE-2025-002_9e340a1a/
        ├── case_meta.json
        ├── upload.pcap
        ├── iocs.csv
        ├── iocs.json
        ├── summary.json
        └── forensic_report_<ts>.pdf
```

---

## Web Routes

| Route | Description |
|---|---|
| `GET /` | Dashboard — history, severity chart |
| `GET /upload` | Upload form |
| `POST /upload` | Run pipeline, redirect to analysis |
| `GET /analysis/<uuid>` | Per-case overview |
| `GET /sessions?analysis_id=` | Flow table with search |
| `GET /beacons?analysis_id=` | C2 beacon findings |
| `GET /dns?analysis_id=` | DNS findings |
| `GET /files?analysis_id=` | Extracted files |
| `GET /iocs?analysis_id=` | IOC report |
| `GET /chains?analysis_id=` | Attack chain correlation |
| `GET /timeline?analysis_id=` | D3.js network graph |
| `GET /api/graph?analysis_id=` | JSON graph (weighted edges) |
| `GET /api/iocs?analysis_id=` | JSON IOC list |
| `GET /api/severity_breakdown?analysis_id=` | JSON severity counts |
| `GET /api/timeline?analysis_id=` | JSON timeline buckets |
| `GET /export/iocs.csv?analysis_id=` | Download + save IOC CSV |
| `GET /export/iocs.json?analysis_id=` | Download + save IOC JSON |
| `GET /export/report.pdf?analysis_id=` | Download + save PDF |

---

## Project Structure

```
pcap_engine/
├── main.py                     ← Batch CLI (positional PCAP, prompts case number)
├── cli.py                      ← Interactive CLI
├── config.py                   ← Thresholds, paths, API keys
├── requirements.txt
├── engine/
│   ├── case_manager.py         ← Persistent case state, folder management, DB
│   ├── pipeline.py             ← Unified pipeline (CLI + Web use this)
│   ├── pcap_loader.py
│   ├── normaliser.py
│   ├── session_tracker.py
│   ├── packet_stats.py
│   ├── database.py             ← SQLite schema + self-healing migrations
│   ├── flow_store.py           ← Single-transaction batch writes
│   ├── printer.py
│   └── logger.py
├── modules/
│   ├── traffic_classifier.py   ← IP classification + cloud risk modifiers
│   ├── attack_signatures.py    ← Byte-level signatures (Meterpreter, shells)
│   ├── beacon_detector.py      ← Host-pair CV analysis + JA3
│   ├── dns_analyser.py         ← Entropy, DGA, tunnelling
│   ├── protocol_dissector.py   ← HTTP/DNS/TLS/FTP/SMTP
│   ├── file_extractor.py       ← HTTP stream extraction + VirusTotal
│   ├── ioc_aggregator.py       ← IOC list + MITRE mapping + clustering
│   ├── ioc_enrichment.py
│   └── attack_chain.py         ← Recon→Access→Lateral→C2→Exfil correlation
├── reports/
│   └── pdf_generator.py        ← ReportLab 9-section PDF
├── web/
│   ├── app.py                  ← Flask 21 routes
│   └── templates/              ← 11 Jinja2 templates
├── tests/
│   ├── test_calibration.py     ← 25 ground-truth tests
│   ├── test_week1.py — test_week6.py
└── data/
    └── flows.db                ← SQLite (auto-created + auto-migrated)
```

---

## Configuration

```python
# config.py
VIRUSTOTAL_API_KEY        = ""          # set via VT_API_KEY env var

BEACON_MIN_PACKETS        = 10
BEACON_INTERVAL_CV_STRONG = 0.3         # Cobalt Strike / TrickBot profile
BEACON_INTERVAL_CV_WEAK   = 0.8         # QakBot / Emotet profile
BEACON_MIN_CONNECTIONS    = 4

DNS_ENTROPY_THRESHOLD     = 4.0
DNS_LONG_SUBDOMAIN_CHARS  = 50
DNS_HIGH_QUERY_RATE       = 80

HTTP_LARGE_UPLOAD_BYTES   = 1_000_000

SEVERITY_CRITICAL_THRESHOLD = 80
SEVERITY_HIGH_THRESHOLD     = 60
SEVERITY_MEDIUM_THRESHOLD   = 40
```

---

## Troubleshooting

### `sqlite3.OperationalError: table cases has no column named source`
Your local `flows.db` predates v2.5. The fix is automatic — v2.5 runs a self-healing migration
on every startup. Just run the application again; the column is added instantly.

### `tshark not found`
Install Wireshark. File extraction falls back to magic-byte carving.

### `python-magic` errors on Windows
Use `pip install python-magic-bin` instead of `python-magic`.

### Dashboard shows empty after server restart
Re-upload the PCAP. Case metadata and IOCs reload from the DB, but detection objects
(beacons, chains) require re-running the pipeline.

### Port 5000 in use
Edit `web/app.py` last line: `app.run(port=5001)`

---

*PCAP Engine v2.5 — NFSU School of Cyber Security & Digital Forensics*
