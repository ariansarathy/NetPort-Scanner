# 🔍 NetPort Scanner

A Python-based TCP port scanner with multi-threaded scanning, detailed security reporting, and an optional Flask web interface.

---

## Features

- **Multi-threaded scanning** — configurable thread pool (default 200) for fast parallel scans
- **Banner grabbing** — attempts to capture service banners from open ports
- **Security recommendations** — per-service security advice for every open port
- **CSV & JSON export** — export results for further analysis or record-keeping
- **Real-time CLI feedback** — live progress bar + open port alerts as they're found
- **Flask web interface** — browser-based GUI with live progress, results table, and export buttons

---

## Installation

```bash
git clone https://github.com/yourname/netport-scanner.git
cd netport-scanner
pip install -r requirements.txt
```

---

## Usage

### CLI

```bash
# Basic scan (ports 1–1024)
python cli.py 192.168.1.1

# Custom range
python cli.py scanme.nmap.org --range 1-10000

# Export results
python cli.py example.com --export both --output my_scan

# Full options
python cli.py <host> --range 1-65535 --threads 300 --timeout 0.8 --export json
```

**CLI Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--range` | `1-1024` | Port range (`start-end`) |
| `--threads` | `200` | Concurrent threads |
| `--timeout` | `1.0` | TCP timeout in seconds |
| `--export` | _(none)_ | `json`, `csv`, or `both` |
| `--output` | `scan_results` | Output filename (no extension) |

---

### Web Interface

```bash
python app.py
# Open http://localhost:5000
```

The web UI lets you configure and run scans from a browser, watch live progress, and download reports.

---

## Project Structure

```
netport-scanner/
├── scanner.py          # Core scanning engine (port scan, export logic)
├── cli.py              # Command-line interface
├── app.py              # Flask web application
├── templates/
│   └── index.html      # Web UI
├── reports/            # Auto-created; stores exported reports
└── requirements.txt
```

---

## ⚠️ Legal Notice

Only scan hosts you own or have explicit written permission to test. Unauthorized port scanning may be illegal in your jurisdiction.

---

## License

MIT
