cat > README.md << 'EOF'
# AI-VAPT (AI-Based Vulnerability Assessment & Penetration Testing)

AI-VAPT is an automated vulnerability assessment tool that performs scanning on a target IP address or domain and generates a professional PDF security report.  
This project integrates AI (Ollama LLM) to create an executive summary and recommendations based on scan results.

---

## Features
- Nmap port scanning (fast network reconnaissance)
- Web URL extraction and basic web checks
- AI-generated executive summary using Ollama
- Automatic professional PDF report generation (A4 format)
- Organized output storage with timestamps

---

## Tools & Technologies Used
- Python 3
- Nmap
- Ollama (Local LLM AI)
- ReportLab (PDF generation)
- Playwright (web automation)
- Kali Linux

---

## Installation

### 1) Clone the repository
```bash
git clone https://github.com/Sujan-bs/AI_VAPT.git
cd AI_VAPT

