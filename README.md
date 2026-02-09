# AI-VAPT (Automated Vulnerability Assessment & Reporting Tool)

AI-VAPT is an automated Vulnerability Assessment and Penetration Testing (VAPT) tool built on Kali Linux.
It performs fast scanning using Nmap + Nuclei + Web Header checks and generates a professional PDF report with screenshots and an AI Executive Summary (Ollama).

---

## Features
- Accepts IP address or Domain as input
- Auto resolves domain → IP
- Runs Nmap fast scan (top 1000 ports)
- Detects HTTP/HTTPS services automatically
- Runs Nuclei scan (fast limited templates)
- Captures website screenshot using Playwright
- Generates a clean professional PDF report (A4 format)
- Adds AI Executive Summary using Ollama (Local LLM)

---

## Tools Used
- Nmap
- Curl
- Nuclei
- Playwright
- ReportLab
- Ollama (Local AI Model)

---

## Installation

### 1) Clone repository
```bash
git clone https://github.com/YOUR_USERNAME/AI-VAPT.git
cd AI-VAPT

