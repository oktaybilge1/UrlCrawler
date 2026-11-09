<div align="center">

# 🛰️ UrlCrawler

**A lightweight web dashboard that chains WhatWeb, Nmap, Assetfinder and Nuclei into a single reconnaissance workflow.**

![Go](https://img.shields.io/badge/Go-1.18+-00ADD8?logo=go&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-storage-003B57?logo=sqlite&logoColor=white)
![Status](https://img.shields.io/badge/status-hobby%20%2F%20educational-blue)

</div>

---

## ✨ Features

| | Tool | What it does |
|---|---|---|
| 🔍 | **WhatWeb** | Fingerprints the target's technology stack before scanning |
| 🔌 | **Nmap** | Active port scan of common service ports (21, 22, 80, 443) |
| 🌐 | **Assetfinder** | Passive subdomain enumeration to map the attack surface |
| 🛡️ | **Nuclei** | Template-based vulnerability scanning (CVEs, exposed files, panels, takeovers, …) |

- Clean, responsive web UI with automatic light / dark theme
- Pick exactly which scans and Nuclei template groups to run
- Per-tool timing and total scan duration
- Every scan is saved to a local SQLite database and browsable from the **History** page
- Single self-contained binary: UI assets are embedded, no external CDN calls

## 🧭 How it works

1. Enter a target URL → WhatWeb fingerprints its technologies.
2. Choose which scans to run (Nmap, Assetfinder, Nuclei) and which Nuclei template groups to use.
3. Results are shown per tool with timings and stored in SQLite for later review.

## 🚀 Quick start

### 1. Install the scanners

All four tools must be available in your `PATH`:

```bash
sudo apt install nmap whatweb                              # Debian / Ubuntu
go install github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates                                    # downloads ~/nuclei-templates
```

### 2. Build and run

You need Go 1.18+ and a C compiler (the SQLite driver uses cgo).

```bash
git clone https://github.com/oktaybilge1/UrlCrawler.git
cd UrlCrawler
go build -o UrlCrawler
./UrlCrawler
```

Open **http://localhost:8000**, enter a target such as `www.example.com`, and follow the steps.

## 🗂️ Project structure

```
UrlCrawler/
├── main.go                 # HTTP handlers, scan runners, SQLite storage
└── web/
    ├── static/style.css    # UI theme
    └── templates/pages.html# All pages (embedded into the binary)
```

## 🔒 Security notes

- Targets must be valid `www.` domain names; scanner commands run **without a shell**, and Nuclei template names are checked against a fixed allow-list.
- All output shown in the UI is HTML-escaped.
- The dashboard has **no authentication**. Run it on localhost or behind a trusted network only.

## ⚠️ Legal notice

This tool is intended for **educational use and authorized security testing only**. Scan only systems you own or have explicit written permission to test. The author accepts no responsibility for misuse.

## 📖 Background

UrlCrawler was built during the author's internship, before AI coding assistants were widespread, through entirely manual research and implementation. It served as the starting point for the more advanced **Mangudai ASM (Attack Surface Management)** platform.

## 🤝 Contributing

Issues and pull requests are welcome.

## 📬 Contact

**Oktay Bilge** · [bilge.oktay.944@gmail.com](mailto:bilge.oktay.944@gmail.com) · [@oktaybilge1](https://github.com/oktaybilge1)
