<div align="center">

```
███████╗███████╗███╗   ██╗██████╗ ██╗██████╗
██╔════╝██╔════╝████╗  ██║██╔══██╗██║██╔══██╗
█████╗  █████╗  ██╔██╗ ██║██████╔╝██║██████╔╝
██╔══╝  ██╔══╝  ██║╚██╗██║██╔══██╗██║██╔══██╗
██║     ███████╗██║ ╚████║██║  ██║██║██║  ██║
╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
```

**Multi-Module Security Scanner & Penetration Testing Framework**

*Created by Sully*

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-green)]()
[![License](https://img.shields.io/badge/License-MIT-yellow)]()
[![Version](https://img.shields.io/badge/Version-2.0.0-red)]()

</div>

---

## What is Fenrir?

Fenrir is a self-contained penetration testing and network security assessment framework. It combines a full graphical interface, a rich command-line interface, and a comprehensive offline intelligence database — no cloud dependency, no per-scan API calls required.

Everything from port scanning and CVE lookup through to credential spraying, IoT enumeration, artefact analysis, network topology mapping, and SIEM detection rule generation runs locally from a single folder. Drop it onto any machine running Python 3.10+ and it works.

---

## Table of Contents

1. [Features](#features)
2. [Quick Start](#quick-start)
3. [Installation](#installation)
4. [Graphical Interface](#graphical-interface)
5. [Command-Line Interface](#command-line-interface)
6. [Scanner Modules](#scanner-modules)
7. [Offline Intelligence Database](#offline-intelligence-database)
8. [API Keys](#api-keys)
9. [Branding](#branding)
10. [Portable Bundle](#portable-bundle)
11. [Scheduled Scans](#scheduled-scans)
12. [Artefact & Hash Analysis](#artefact--hash-analysis)
13. [Network Topology](#network-topology)
14. [Detection Engineering](#detection-engineering)
15. [Results & Reporting](#results--reporting)
16. [Project Structure](#project-structure)
17. [Dependencies](#dependencies)
18. [Legal Notice](#legal-notice)
19. [Credits](#credits)

---

## Features

### Scanning
- **Async TCP port scanner** — concurrent scanning with configurable concurrency and timeouts
- **Service version detection** — nmap `-sV` integration with banner grabbing fallback
- **OS fingerprinting** — 5-layer approach: nmap service elements, banner inference, SMB discovery, nmap `-O`, TTL heuristic
- **CVE lookup** — NVD API with offline database fallback, EPSS probability scores
- **Exploit matching** — offline Exploit-DB search across 57,000+ exploits and shellcodes
- **Web scanning** — HTTP header analysis, security header checks, redirect following
- **Directory brute force** — async path enumeration against web targets
- **Technology detection** — CMS, framework, CDN, server fingerprinting
- **DNS enumeration** — A, AAAA, MX, NS, TXT, SOA, CNAME, PTR, zone transfer attempts
- **Subdomain discovery** — wordlist brute force + certificate transparency logs
- **WHOIS** — domain registration, registrar, expiry, abuse contact
- **OSINT aggregation** — Shodan, Censys, VirusTotal, AbuseIPDB, Google dork GHDB
- **Threat intelligence** — AlienVault OTX, VirusTotal, local IP reputation database
- **Credential spraying** — SSH, FTP, Telnet, HTTP Basic, HTTP form; lockout detection
- **IoT scanning** — MQTT, RTSP, UPnP, CoAP, Modbus, BACnet, ONVIF, Bluetooth LE
- **OT/ICS detection** — Siemens S7, Modbus, DNP3, BACnet, EtherNet/IP, IEC 61850
- **Mobile device scanning** — ADB over TCP, iOS lockdownd, MDM endpoints
- **Android analysis** — ADB shell property extraction, APK static analysis
- **RF spectrum** — RTL-SDR / HackRF spectrum monitoring (optional hardware)
- **Network topology** — interactive browser-based diagram with logical device connections

### Intelligence Database (fully offline)
- 250,000+ NVD CVEs with CVSS scores and EPSS probabilities
- 57,000+ Exploit-DB exploits and shellcodes
- MITRE ATT&CK Enterprise, ICS, and Mobile (techniques, groups, software, campaigns, relationships)
- MITRE CWE, CAPEC
- CISA Known Exploited Vulnerabilities (KEV)
- AlienVault OTX pulses and IOC indicators
- MalwareBazaar, ThreatFox, URLhaus full exports (with auth-key)
- Sigma detection rules (5,000+ rules, ATT&CK-tagged)
- YARA malware detection rules
- Google Hacking Database (GHDB) dorks
- Nuclei vulnerability templates
- Feodo Tracker C2 botnet IPs
- SSL Blacklist JA3 fingerprints
- Default credential lists (routers, IoT, OT, industrial)
- SecLists, PayloadsAllTheThings, FuzzDB wordlists

### Reporting & Detection
- Per-scan JSON + TXT reports in timestamped result folders
- EPSS enrichment applied post-scan to all CVEs
- ATT&CK TTP chain expansion from CVEs
- Sigma rule matching to scan findings
- SIEM rule export (Elastic, Splunk, Suricata, Snort, QRadar, Azure Sentinel)
- Scan history with full diff comparison (new ports, new CVEs, resolved CVEs)
- Scheduled recurring scans

---

## Quick Start

```bash
# Clone and enter the project
git clone https://github.com/Gloomling/Fenrir.git
cd Fenrir

# Install dependencies (Kali / Debian system Python)
pip3 install -e . --break-system-packages

# Launch the GUI
./run.sh --gui

# OR run a CLI scan
./run.sh 192.168.1.1
./run.sh 192.168.1.0/24 --network
```

---

## Installation

### Requirements
- Python 3.10 or later
- Linux, macOS, or Windows
- Optional: `nmap` on PATH for service detection and OS fingerprinting
- Optional: `adb` on PATH for Android device scanning
- Optional: RTL-SDR hardware for RF scanning

### Standard install (from source)

```bash
# Kali Linux / Debian (externally managed Python)
pip3 install -e . --break-system-packages

# macOS / standard Linux
pip3 install -e .

# Windows
python -m pip install -e .
```

### First-time setup

```bash
# Copy the API key template
cp .env.example .env
# Edit .env and add your keys (all optional — see API Keys section)

# Build the offline intelligence database
./run.sh --db-build --tier core       # ~5 GB, ~30 minutes
# or
./run.sh --db-build --tier standard   # ~9 GB, ~60 minutes
```

---

## Graphical Interface

Launch with `./run.sh --gui` or `fenrir-gui`.

### Tabs

| Tab | Purpose |
|-----|---------|
| **Scan** | Single-host scan with module checkboxes, port configuration, output path |
| **Network Scan** | Two-phase: discovery sweep → select hosts → deep assessment |
| **Results** | Ports / Vulnerabilities / Exploits / Recon / Threats — filterable by host |
| **History** | All past scans with parent/child tree for network scans; diff comparison |
| **Schedules** | Add recurring scans on a timer; auto-fires every 60 seconds while GUI is open |
| **Debug** | Per-module timing, memory gauge, live log stream |
| **Database** | Build/update offline intelligence DB, view record counts |

### Key controls

- **🔑 API Keys** button (top-right of header) — enter and save all API keys in one place
- **⬡ View Topology** button (Network Scan tab) — generates an interactive network diagram after a scan
- **Results host selector** — after a network scan, filter the Results tab to a single IP
- **Search results** bar — live search across all results trees
- Double-click any exploit row to open a full exploitation guide window

---

## Command-Line Interface

```
Usage: fenrir [TARGET] [OPTIONS]

TARGET:
  Single host:   192.168.1.1
  CIDR range:    192.168.1.0/24   (use with --network)
  Domain:        example.com

Scan options:
  --ports PORTS         Port list/range: "80,443,1000-2000"
  --network             Run network discovery + deep scan
  --modules MOD,...     Enable specific modules only
  --all                 Enable all available modules
  --timeout SECS        Per-module timeout (default: 300s)
  --output DIR          Custom output directory

GUI:
  --gui                 Launch the graphical interface

Database:
  --db-build            Build the offline intelligence database
  --db-build --tier TIER       core | standard | full
  --db-update                  Update all database sources
  --db-update --source SOURCE  Update one source (nvd, sigma, otx, ...)
  --db-status                  Show record counts and last-update timestamps

API key management:
  --keys                Open the API key configuration window (GUI mode)

Examples:
  fenrir 192.168.1.1
  fenrir 192.168.1.1 --modules port_scan,vuln_scan,exploit_scan
  fenrir 192.168.1.0/24 --network --all
  fenrir --gui
  fenrir --db-build --tier core
  fenrir --db-update --source sigma
```

---

## Scanner Modules

| Module | CLI flag | Description |
|--------|----------|-------------|
| Port Scanner | `port_scan` | Async TCP scan, banner grabbing |
| Vulnerability Scanner | `vuln_scan` | NVD CVE lookup with EPSS scores |
| Exploit Scanner | `exploit_scan` | Exploit-DB offline search |
| Web Scanner | `web_scan` | HTTP headers, security checks |
| Directory Bruteforce | `dir_scan` | Async path enumeration |
| Technology Detection | `tech_detect` | CMS/framework fingerprinting |
| DNS Scanner | `dns_scan` | Full DNS record enumeration |
| Subdomain Scanner | `subdomain_scan` | Wordlist + CT log discovery |
| WHOIS | `whois_scan` | Domain registration data |
| OSINT | `osint_scan` | Multi-source aggregation |
| Threat Intelligence | `threat_intel` | OTX, VirusTotal, reputation |
| IoT Scanner | `iot_scan` | MQTT, RTSP, UPnP, BACnet |
| OT/ICS Scanner | `ot_scan` | S7, Modbus, DNP3, EtherNet/IP |
| Mobile Scanner | `mobile_scan` | ADB, iOS lockdownd, MDM |
| Android Scanner | `android_scan` | ADB shell + APK analysis |
| Password Sprayer | `cred_spray` | SSH/FTP/Telnet/HTTP credential testing |
| RF Scanner | `rf_scan` | SDR spectrum monitoring (hardware required) |
| Network Scanner | `network` | Multi-host discovery + full pipeline |
| Artefact Scanner | — | Hash/file lookup across all offline databases |

---

## Offline Intelligence Database

### Building the database

```bash
# Core — NVD CVEs, Exploit-DB, ATT&CK, CISA KEV, Sigma, OTX, threat feeds (~5 GB)
fenrir --db-build --tier core

# Standard — adds wordlists, ThreatFox, URLhaus, C2 tracker (~9 GB)
fenrir --db-build --tier standard

# Full — adds RockYou, HIBP password hashes, all wordlists (~26 GB)
fenrir --db-build --tier full

# Update specific sources
fenrir --db-update --source nvd
fenrir --db-update --source sigma
fenrir --db-update --source otx
fenrir --db-update --source attack
```

### What's in the database

| Source | Records | Key | Notes |
|--------|---------|-----|-------|
| NVD CVEs | 250,000+ | Optional | Rate-limited without key |
| EPSS Scores | All CVEs | None | Exploit probability |
| CISA KEV | ~1,000 | None | Known exploited vulns |
| Exploit-DB | 57,000+ | None | Full source file mirror |
| MITRE ATT&CK | 700+ techniques | None | Enterprise + ICS + Mobile |
| ATT&CK Groups | 130+ | None | Threat actor profiles |
| ATT&CK Software | 700+ | None | Malware and tools |
| ATT&CK Relationships | 10,000+ | None | Cross-links between all objects |
| MITRE CWE | 900+ | None | Weakness enumeration |
| MITRE CAPEC | 500+ | None | Attack pattern catalogue |
| Sigma Rules | 5,000+ | None | SIEM detection rules |
| YARA Rules | 2,000+ | None | Malware detection signatures |
| Nuclei Templates | 10,000+ | None | CVE/vuln scan templates |
| AlienVault OTX | Varies | Optional | More pulses with key |
| MalwareBazaar | 1,000,000+ | auth.abuse.ch | Full export needs key |
| ThreatFox | 500,000+ | auth.abuse.ch | Full export needs key |
| URLhaus | 2,000,000+ | auth.abuse.ch | Full export needs key |
| Feodo Tracker | ~1,000 | None | Botnet C2 IPs |
| SSL Blacklist | ~1,000 | None | Malicious JA3 fingerprints |
| Google Hacking DB | 6,000+ | None | Search dorks |
| Default Credentials | 10,000+ | None | Router/IoT/OT defaults |
| Emerging Threats | Varies | None | Open Snort/Suricata rules |
| Spamhaus DROP | Varies | None | BGP drop lists |
| IP Reputation | 500,000+ | None | Abuse, scanning, C2 IPs |
| SecLists | Varies | None | Wordlists and payloads |

---

## API Keys

Click **🔑 API Keys** in the header bar (GUI), or edit `.env` / `fenrir_keys.json` directly.

Keys are stored in `fenrir_keys.json` (portable, GUI-managed — takes priority) and `.env` (traditional dotenv). The JSON keyfile can be copied between machines to transfer all keys at once.

### Exporting and importing keys

```bash
# GUI: 📤 Export… saves fenrir_keys.json to any path
# GUI: 📥 Import… loads from any path

# CLI equivalents:
python3 fenrir_brand.py   # for branding only — use the GUI API Keys button for keys
```

### Key reference

| Key | Service | Free? | What it unlocks | Get it |
|-----|---------|-------|----------------|--------|
| `NVD_API_KEY` | NVD | ✅ | Rate limit 5→50 req/30s | nvd.nist.gov |
| `VULNCHECK_API_KEY` | VulnCheck | ✅ | NVD++ data + offline ZIP | vulncheck.com |
| `VIRUSTOTAL_API_KEY` | VirusTotal | ✅ | 500 lookups/day | virustotal.com |
| `ALIENVAULT_OTX_API_KEY` | AlienVault OTX | ✅ | Full subscribed pulse feed | otx.alienvault.com |
| `MALWAREBAZAAR_API_KEY` | MalwareBazaar | ✅ | Full hash export | auth.abuse.ch |
| `THREATFOX_API_KEY` | ThreatFox | ✅ | Full IOC export (same account) | auth.abuse.ch |
| `URLHAUS_API_KEY` | URLhaus | ✅ | Full URL DB dump (same account) | auth.abuse.ch |
| `SHODAN_API_KEY` | Shodan | ⚠️ | Full search API ($49/yr) | shodan.io |
| `CENSYS_API_ID` | Censys | ✅ | 250 queries/month | censys.io |
| `CENSYS_API_SECRET` | Censys | ✅ | Paired with API ID | censys.io |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | ✅ | 1000 checks/day | abuseipdb.com |
| `GREYNOISE_API_KEY` | GreyNoise | ✅ | Noise/scanner IP context | greynoise.io |
| `HUNTER_API_KEY` | Hunter.io | ✅ | 25 email searches/month | hunter.io |
| `SECURITYTRAILS_API_KEY` | SecurityTrails | ✅ | 50 DNS queries/month | securitytrails.com |
| `GITHUB_TOKEN` | GitHub | ✅ | 60→5000 req/hr for DB builds | github.com/settings/tokens |

> All keys are optional. Fenrir uses offline data when keys are absent.
> auth.abuse.ch registration (free, personal email) gives one key that works for MalwareBazaar, ThreatFox, URLhaus, and SSLBL.

---

## Branding

Fenrir's appearance is managed by a separate operator tool that end users never see. This means you can configure the look once, save it, and deploy it to any number of machines — users see the configured branding and have no controls to change it.

```bash
# Open the branding tool (GUI)
python3 fenrir_brand.py --target ~/Desktop/Fenrir

# Export your theme for deployment to other machines
python3 fenrir_brand.py --export my_theme.json

# Apply a theme to a Fenrir install
python3 fenrir_brand.py --target /opt/fenrir --import-theme my_theme.json
```

### What you can configure

- Window title, logo/icon (PNG/JPG/ICO, 256×256 recommended)
- Background image with opacity blend (0–100%)
- Twelve individual UI colours (accent, background, text, severity indicators)
- Font family and size

Settings are stored in `branding.json` at the project root. Fenrir reads this file on every launch. Delete it to reset to the default dark theme.

---

## Portable Bundle

Package Fenrir and all its dependencies into a single folder that runs anywhere:

```bash
# Source-only bundle (lightweight, requires pip on target)
python3 bundle_fenrir.py bundle --output ~/fenrir-portable

# Full offline bundle (includes pre-downloaded Python wheels)
python3 bundle_fenrir.py bundle \
    --output ~/fenrir-portable \
    --bundle-deps

# Complete bundle (source + deps + offline database)
python3 bundle_fenrir.py bundle \
    --output ~/fenrir-portable \
    --bundle-deps \
    --include-db \
    --zip

# Windows: embed Python 3.12 so no Python install is needed at all
python3 bundle_fenrir.py bundle \
    --output ~/fenrir-portable \
    --bundle-deps \
    --embed-python \
    --zip
```

### Deploying the bundle

```bash
# Linux / macOS
chmod +x bin/fenrir bin/fenrir-gui
./bin/fenrir-gui

# Windows
bin\fenrir-gui.bat
```

### Keeping the bundle updated

```bash
# Linux / macOS (from inside the bundle directory)
./bin/update.sh

# Windows
bin\update.bat
```

`update.sh` / `update.bat` will `git pull` the latest source (if the bundle was created from a git clone) and reinstall dependencies from the bundled `lib/` directory — no internet connection needed for the dependency step.

---

## Scheduled Scans

Set up recurring scans from the **Schedules** tab:

1. Enter a name, target, scan type (single/network), and interval in hours
2. Click **+ Add Schedule**
3. The scheduler fires automatically every 60 seconds while the GUI is open
4. Completed scheduled scans appear in the History tab under the parent schedule entry
5. Results are saved to timestamped folders in `Results/`

Scheduled scans can also be managed programmatically:

```python
from fenrir.scan_history import get_scan_history
history = get_scan_history()
history.add_schedule("Nightly check", "192.168.1.0/24", "network", interval_h=24)
```

---

## Artefact & Hash Analysis

Query a file or hash against all offline intelligence sources simultaneously:

```python
from fenrir.artefact_scanner import ArtefactScanner
scanner = ArtefactScanner()

# From a file
result = await scanner.scan_file("/path/to/suspicious.exe")

# From a hash (SHA256, SHA1, or MD5)
result = await scanner.scan_hash("44d88612fea8a8f36de82e1278abb02f")
```

The artefact scanner queries:
- `artefact_hashes` — unified hash table (OTX + MalwareBazaar merged)
- `hash_reputation` — MalwareBazaar entries
- `ioc_threatfox` — ThreatFox hash IOCs
- `otx_indicators` — OTX raw hash indicators

Results include: verdict (clean/suspicious/malicious/unknown), threat score (0–100), matched pulse names, linked ATT&CK technique IDs, Sigma rules matching those TTPs, and recommended SIEM queries.

---

## Network Topology

After a network scan, click **⬡ View Topology** to open an interactive HTML diagram in your browser.

### Layout

- **Network devices** (routers, switches, firewalls) — centre/top, diamond shape, red
- **Servers** — right column, rack-unit shape, blue
- **Workstations** — centre grid, monitor shape, green
- **IoT devices** — bottom, chip shape, orange
- **Mobile devices** — bottom, phone shape, purple
- Subnets drawn as labelled coloured regions
- Logical connections inferred from ARP tables and routing discovery

### Interacting with the diagram

- **Pan** — click and drag
- **Zoom** — scroll wheel
- **Hover** a device — tooltip shows IP, hostname, OS, ports, CVE count
- **Click** any device or its CVE count — switches back to Fenrir and opens the Results tab filtered to that host
- **⤢ Fit all** — zoom to show all devices
- **↓ SVG** — export the diagram as an SVG file

---

## Detection Engineering

Fenrir can translate scan findings into SIEM detection rules. After a scan:

1. **CVEs found** → mapped to ATT&CK techniques via the relationships table
2. **Techniques** → matched to Sigma rules tagged with those technique IDs
3. **Sigma rules** → converted to your SIEM's native format

```python
from fenrir.artefact_scanner import ArtefactScanner
scanner = ArtefactScanner()

# Get detection rules for a CVE
rules = scanner.get_sigma_rules_for_cve("CVE-2021-41773")
# → returns list of Sigma rule dicts with detection_yaml field

# Get ATT&CK techniques for a CVE
ttps = scanner.get_attack_ttps_for_cve("CVE-2021-41773")
# → [{"id": "T1190", "name": "Exploit Public-Facing Application", ...}]
```

### Converting Sigma rules to SIEM format

```bash
# Install sigma-cli
pip3 install sigma-cli

# Convert to various SIEM formats
sigma convert -t elasticsearch rule.yml
sigma convert -t splunk rule.yml
sigma convert -t qradar rule.yml
sigma convert -t sentinel rule.yml
sigma convert -t suricata rule.yml
sigma convert -t snort rule.yml
```

---

## Results & Reporting

Every scan creates a timestamped sub-folder:

```
Results/
  2025-06-01_14-30_192.168.1.1/
    fenrir_report_192.168.1.1_20250601_143000.json   (full findings)
    fenrir_report_192.168.1.1_20250601_143000.txt    (human-readable summary)
    mobile_192_168_1_5.json                          (mobile findings, if any)
    network_topology.html                            (topology diagram, if network scan)
  
  2025-06-01_15-00_192.168.1.0-24_network/
    fenrir_report_....json
    host_192.168.1.1.json    (per-host detail)
    host_192.168.1.5.json
    network_topology.html
```

The History tab lists every scan. Select two scans and click **⬛ Diff** to see what changed between them:
- New open ports, closed ports
- New CVEs, resolved CVEs
- New exploits
- OS fingerprint changes

---

## Project Structure

```
Fenrir/
├── fenrir/                      Python package
│   ├── __init__.py
│   ├── cli.py                   Full argparse CLI
│   ├── fenrir_gui.py            Tkinter GUI (all tabs and features)
│   ├── config.py                API key management + key registry
│   ├── logging_config.py        Coloured logging + GUI queue handler
│   ├── report_manager.py        JSON + TXT report writing
│   ├── branding_config.py       Reads branding.json (read-only at runtime)
│   ├── fenrir_paths.py          Central path constants
│   ├── scan_history.py          SQLite scan history + scheduler
│   ├── epss_client.py           EPSS score fetcher (FIRST.org API)
│   ├── network_diagram.py       Interactive HTML topology generator
│   ├── artefact_scanner.py      Hash/file offline analysis
│   │
│   ├── port_scanner.py          Async TCP scan
│   ├── vulnerability_scanner.py NVD CVE lookup
│   ├── exploit_scanner.py       Exploit-DB search
│   ├── network_scanner.py       Multi-host discovery + deep pipeline
│   ├── web_scanner.py           HTTP analysis
│   ├── dir_brute_forcer.py      Directory enumeration
│   ├── tech_detector.py         Technology fingerprinting
│   ├── dns_scanner.py           DNS enumeration
│   ├── subdomain_scanner.py     Subdomain discovery
│   ├── whois_scanner.py         WHOIS lookup
│   ├── osint_scanner.py         OSINT aggregation
│   ├── threat_intel_scanner.py  Threat intelligence
│   ├── iot_scanner.py           IoT protocol detection
│   ├── ot_scanner.py            OT/ICS detection
│   ├── mobile_scanner.py        Mobile device scanning
│   ├── android_scanner.py       Android ADB + APK analysis
│   ├── password_sprayer.py      Credential spraying
│   ├── rf_scanner.py            RF spectrum (SDR hardware)
│   │
│   ├── modules/
│   │   └── __init__.py          Module registry (lazy imports)
│   │
│   └── database/
│       ├── __init__.py
│       ├── schema.py            SQLite DDL for all tables
│       ├── db_manager.py        Query interface
│       ├── db_builder.py        Downloads and indexes all sources
│       └── fenrir.db            Runtime database (gitignored, built locally)
│
├── assets/                      Logo, background image (managed by fenrir_brand.py)
├── data/                        Wordlists, rule repos, raw feeds (gitignored)
├── Results/                     Scan output (gitignored)
├── fenrir_brand.py              Operator branding tool (not for end users)
├── bundle_fenrir.py             Portable bundle builder
├── run.sh                       Unix launcher
├── run.bat                      Windows launcher
├── install_fenrir.sh            Full Linux/macOS installer
├── fenrir-gui.bat               Windows GUI launcher
├── pyproject.toml               Package definition
├── .env.example                 API key template
├── branding.json                GUI appearance (auto-created, gitignored)
├── fenrir_keys.json             API keys (auto-created, gitignored)
└── scan_history.db              Scan history database (auto-created, gitignored)
```

---

## Dependencies

### Required
| Package | Purpose |
|---------|---------|
| Pillow | Background image, logo resize, wolf icon |
| requests / httpx | HTTP scanning and API calls |
| python-dotenv | Load .env API keys |
| colorama | Coloured terminal output (Windows) |
| PyYAML | Config and Sigma rule parsing |
| beautifulsoup4 | HTML parsing |
| aiodns | Async DNS resolution |
| paho-mqtt | MQTT broker enumeration |
| webtech | Technology fingerprinting |
| python-whois | WHOIS lookups |

### Optional (install as needed)
| Package | Purpose | Install |
|---------|---------|---------|
| paramiko | SSH credential testing | `pip3 install paramiko` |
| scapy | ARP sweep, raw socket scanning | `pip3 install scapy` |
| cryptography | APK certificate parsing | `pip3 install cryptography` |
| androguard | APK static analysis | `pip3 install androguard` |
| bleak | Bluetooth LE (Python < 3.13) | `pip3 install bleak` |
| pyrtlsdr | RTL-SDR RF scanning | `pip3 install pyrtlsdr` |
| nvdlib | NVD CVE API client | `pip3 install nvdlib` |
| sigma-cli | SIEM rule conversion | `pip3 install sigma-cli` |

---

## Legal Notice

> **This tool is intended exclusively for authorised security testing.**
>
> Use of Fenrir against systems without explicit written permission from the owner is illegal under the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act (CMA), and equivalent legislation in most jurisdictions.
>
> The authors accept no liability for misuse. You are responsible for ensuring you have proper authorisation before scanning any target. Always obtain written permission. Never use this tool against production systems, cloud infrastructure, or any network you do not own or administer.
>
> Penetration testing is a professional discipline. Follow responsible disclosure when vulnerabilities are found.

---

## Credits

<div align="center">

### Created by Sully

*Built for security professionals who need a capable, self-contained,
fully offline penetration testing framework that works the same way
on any machine from a Kali workstation to an air-gapped assessment laptop.*

</div>

---

### Intelligence Sources

Fenrir's offline database is built from the following public sources. We thank the organisations that make this data freely available to the security community:

- [MITRE ATT&CK](https://attack.mitre.org/) — ATT&CK Framework
- [MITRE CWE](https://cwe.mitre.org/) — Common Weakness Enumeration
- [MITRE CAPEC](https://capec.mitre.org/) — Attack Pattern Enumeration
- [NVD / NIST](https://nvd.nist.gov/) — National Vulnerability Database
- [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — Known Exploited Vulnerabilities
- [Exploit-DB](https://www.exploit-db.com/) — Exploit and shellcode database
- [abuse.ch](https://abuse.ch/) — MalwareBazaar, ThreatFox, URLhaus, Feodo Tracker, SSLBL
- [AlienVault OTX](https://otx.alienvault.com/) — Open Threat Exchange
- [SigmaHQ](https://github.com/SigmaHQ/sigma) — Sigma detection rules
- [Yara-Rules](https://github.com/Yara-Rules/rules) — Community YARA rules
- [Emerging Threats](https://rules.emergingthreats.net/) — Open Snort/Suricata rules
- [ProjectDiscovery](https://github.com/projectdiscovery/nuclei-templates) — Nuclei templates
- [Daniel Miessler](https://github.com/danielmiessler/SecLists) — SecLists
- [VulnCheck](https://vulncheck.com/) — Enhanced vulnerability intelligence
- [FIRST.org](https://www.first.org/epss/) — EPSS exploit prediction scores

---

<div align="center">

*Fenrir — Named for the great wolf of Norse mythology.*
*Like its namesake, it does not ask permission.*

</div>
