#!/usr/bin/env python3
import os
import re
import sys
import json
import socket
import subprocess
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image as RLImage
)

# ============================
# CONFIG
# ============================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "..", "outputs")
SCAN_DIR = os.path.join(BASE_DIR, "..", "scans")

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(SCAN_DIR, exist_ok=True)

# PDF LIMIT (4-5 pages)
MAX_FINDINGS_IN_PDF = 10
MAX_SCREENSHOTS_IN_PDF = 1
MAX_PORTS_IN_PDF = 15

# FAST nuclei mode
NUCLEI_SEVERITY = "critical,high,medium,low"
NUCLEI_RATE_LIMIT = "10"
NUCLEI_CONCURRENCY = "10"
NUCLEI_TIMEOUT = "10"
NUCLEI_RETRIES = "1"

# only fast tags (important)
NUCLEI_TAGS = "cve,misconfig,exposure,default-login,token,auth,ssl"

# AI (OLLAMA)
OLLAMA_MODEL = "llama3"   # if you use mistral or llama3.2 change here
AI_TIMEOUT = 90           # seconds

PREPARED_BY = "Sujan Gowda"


# ============================
# HELPERS
# ============================
def run_cmd(cmd, timeout=None):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT"


def is_ip(target):
    try:
        socket.inet_aton(target)
        return True
    except:
        return False


def resolve_domain_to_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None


def sanitize_name(x):
    return re.sub(r"[^a-zA-Z0-9._-]", "_", x)


def safe_text(x):
    if x is None:
        return ""
    return str(x).replace("\t", " ").strip()


def detect_web_targets(ip):
    """
    Detect web URLs quickly (http/https)
    """
    urls = []
    for proto, port in [("http", 80), ("https", 443)]:
        cmd = ["curl", "-I", "-m", "4", "-s", f"{proto}://{ip}:{port}"]
        code, out, err = run_cmd(cmd, timeout=6)
        if out.strip():
            urls.append(f"{proto}://{ip}:{port}")
    return urls


def parse_nmap_open_ports(nmap_text):
    open_ports = []
    for line in nmap_text.splitlines():
        if "/tcp" in line and " open " in line:
            parts = line.split()
            if len(parts) >= 3:
                open_ports.append(parts[0])
    return open_ports


# ============================
# SCANNERS
# ============================
def run_nmap(ip, stamp):
    out_file = os.path.join(OUTPUT_DIR, f"{sanitize_name(ip)}_{stamp}_nmap.txt")

    cmd = [
        "nmap", "-sV", "-sC", "-Pn", "-T4",
        "--top-ports", "1000", ip,
        "-oN", out_file
    ]

    print("\n[+] Running Nmap (Fast):")
    print("    " + " ".join(cmd))
    run_cmd(cmd, timeout=600)

    nmap_text = ""
    if os.path.exists(out_file):
        with open(out_file, "r", errors="ignore") as f:
            nmap_text = f.read()

    return out_file, nmap_text


def run_web_headers(url, stamp):
    out_file = os.path.join(OUTPUT_DIR, f"{sanitize_name(url)}_{stamp}_headers.txt")
    cmd = ["curl", "-I", "-L", "-m", "12", "-s", url]
    code, out, err = run_cmd(cmd, timeout=20)

    with open(out_file, "w") as f:
        f.write(out if out else err)

    return out_file, out


def run_nuclei(url, stamp):
    out_json = os.path.join(SCAN_DIR, f"{sanitize_name(url)}_{stamp}_nuclei.jsonl")

    cmd = [
        "nuclei",
        "-u", url,
        "-jsonl",
        "-o", out_json,
        "-severity", NUCLEI_SEVERITY,
        "-tags", NUCLEI_TAGS,
        "-rl", NUCLEI_RATE_LIMIT,
        "-c", NUCLEI_CONCURRENCY,
        "-timeout", NUCLEI_TIMEOUT,
        "-retries", NUCLEI_RETRIES,
        "-silent"
    ]

    print("\n[+] Running Nuclei (FAST / LIMITED):")
    print("    " + " ".join(cmd))
    run_cmd(cmd, timeout=420)  # 7 min max

    return out_json


def parse_nuclei_jsonl(jsonl_path):
    findings = []
    if not os.path.exists(jsonl_path):
        return findings

    with open(jsonl_path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                info = obj.get("info", {})
                findings.append({
                    "name": info.get("name", "Unknown"),
                    "severity": info.get("severity", "unknown"),
                    "template": obj.get("template-id", ""),
                    "matched": obj.get("matched-at", obj.get("host", "")),
                    "description": safe_text(info.get("description", ""))[:200],
                })
            except:
                continue

    return findings


def take_screenshot(url, stamp):
    out_png = os.path.join(OUTPUT_DIR, f"{sanitize_name(url)}_{stamp}_screenshot.png")

    py = f"""
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    page.goto("{url}", timeout=60000, wait_until="domcontentloaded")
    page.wait_for_timeout(2000)
    page.screenshot(path="{out_png}", full_page=True)
    browser.close()
print("DONE")
"""

    cmd = ["python3", "-c", py]

    print("\n[+] Taking Website Screenshot (Playwright):")
    print(f"    {url}")
    run_cmd(cmd, timeout=120)

    if os.path.exists(out_png):
        return out_png
    return None


# ============================
# AI PART (OLLAMA)
# ============================
def ai_generate_summary(target, resolved_ip, ports, urls, nuclei_findings):
    """
    This is the AI part of AI-VAPT.
    It summarizes scan results into human readable text.
    """
    try:
        ports_str = ", ".join(ports[:10]) if ports else "None"
        urls_str = ", ".join(urls[:2]) if urls else "None"

        top_findings = []
        for f in nuclei_findings[:8]:
            top_findings.append(f"{f['severity'].upper()}: {f['name']} ({f['matched']})")
        findings_str = "\n".join(top_findings) if top_findings else "No findings detected."

        prompt = f"""
You are a cybersecurity VAPT report assistant.

Generate a short professional executive summary and recommendations.
Keep it very short (max 10 lines).

Target: {target}
Resolved IP: {resolved_ip}
Open Ports: {ports_str}
Web URLs: {urls_str}
Nuclei Findings:
{findings_str}

Output format:
Executive Summary:
- ...
Recommendations:
- ...
"""

        cmd = ["ollama", "run", OLLAMA_MODEL, prompt]
        code, out, err = run_cmd(cmd, timeout=AI_TIMEOUT)

        if out.strip():
            return out.strip()

        return "Executive Summary:\n- AI summary not available.\nRecommendations:\n- Validate results manually."

    except:
        return "Executive Summary:\n- AI summary not available.\nRecommendations:\n- Validate results manually."


# ============================
# PDF REPORT
# ============================
def build_pdf(report_path, target, resolved_ip, nmap_ports, urls, nuclei_findings, screenshots, ai_text):
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "Title",
        parent=styles["Title"],
        fontSize=18,
        spaceAfter=10,
        alignment=1
    )

    h_style = ParagraphStyle(
        "Heading",
        parent=styles["Heading2"],
        fontSize=13,
        spaceAfter=8
    )

    normal = ParagraphStyle(
        "NormalSmall",
        parent=styles["BodyText"],
        fontSize=10,
        leading=13
    )

    small = ParagraphStyle(
        "Small",
        parent=styles["BodyText"],
        fontSize=9,
        leading=12
    )

    doc = SimpleDocTemplate(
        report_path,
        pagesize=A4,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        topMargin=1.2 * cm,
        bottomMargin=1.2 * cm
    )

    story = []

    # ============================
    # COVER PAGE (PRO)
    # ============================
    story.append(Paragraph("Vulnerability Assessment Report", title_style))
    story.append(Spacer(1, 0.5 * cm))

    cover_data = [
        ["Project", "AI-VAPT (Automated Vulnerability Assessment & Reporting Tool)"],
        ["Prepared By", PREPARED_BY],
        ["Target", safe_text(target)],
        ["Resolved IP", safe_text(resolved_ip)],
        ["Tools Used", "Nmap, Curl, Nuclei, Playwright, ReportLab, Ollama(AI)"],
        ["Generated On", datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
    ]

    cover_table = Table(cover_data, colWidths=[4.0 * cm, 12.0 * cm])
    cover_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F4E79")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),

        ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
        ("GRID", (0, 0), (-1, -1), 0.6, colors.grey),

        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),

        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))

    story.append(cover_table)
    story.append(Spacer(1, 1.0 * cm))

    story.append(Paragraph("<b>High-Level Recommendations</b>", h_style))
    story.append(Paragraph("• Patch and update exposed services where possible.", normal))
    story.append(Paragraph("• Restrict unnecessary open ports using firewall rules.", normal))
    story.append(Paragraph("• Use HTTPS and enable strong security headers.", normal))
    story.append(Paragraph("• Validate findings manually before remediation decisions.", normal))

    story.append(PageBreak())

    # ============================
    # AI SUMMARY PAGE
    # ============================
    story.append(Paragraph("AI Executive Summary (Ollama)", h_style))
    for line in ai_text.splitlines():
        story.append(Paragraph(safe_text(line), normal))
    story.append(PageBreak())

    # ============================
    # NMAP PAGE
    # ============================
    story.append(Paragraph("Network Scan Summary (Nmap)", h_style))

    if nmap_ports:
        ports_data = [["Port", "State"]]
        for p in nmap_ports[:MAX_PORTS_IN_PDF]:
            ports_data.append([p, "open"])

        ports_table = Table(ports_data, colWidths=[6 * cm, 10 * cm])
        ports_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F4E79")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(ports_table)
    else:
        story.append(Paragraph("No open ports detected.", normal))

    story.append(Spacer(1, 0.7 * cm))

    story.append(Paragraph("Web Targets Detected", h_style))
    if urls:
        for u in urls[:2]:
            story.append(Paragraph(f"• {safe_text(u)}", normal))
    else:
        story.append(Paragraph("No web services detected (HTTP/HTTPS).", normal))

    story.append(PageBreak())

    # ============================
    # NUCLEI FINDINGS PAGE
    # ============================
    story.append(Paragraph("Web Vulnerability Findings (Nuclei)", h_style))

    if nuclei_findings:
        limited = nuclei_findings[:MAX_FINDINGS_IN_PDF]

        findings_table_data = [["Severity", "Finding", "Matched URL"]]
        for f in limited:
            findings_table_data.append([
                safe_text(f["severity"]).upper(),
                safe_text(f["name"]),
                safe_text(f["matched"])
            ])

        ft = Table(findings_table_data, colWidths=[2.5 * cm, 8.0 * cm, 5.5 * cm])
        ft.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F4E79")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
        ]))
        story.append(ft)

        story.append(Spacer(1, 0.5 * cm))

        story.append(Paragraph("Top Finding Details (Short)", h_style))
        for f in limited[:4]:
            story.append(Paragraph(f"<b>{safe_text(f['name'])}</b> ({safe_text(f['severity']).upper()})", small))
            if f["description"]:
                story.append(Paragraph(safe_text(f["description"]), small))
            story.append(Spacer(1, 0.2 * cm))

    else:
        story.append(Paragraph("No Nuclei findings detected in fast mode.", normal))

    story.append(PageBreak())

    # ============================
    # SCREENSHOT PAGE
    # ============================
    story.append(Paragraph("Website Screenshot", h_style))
    if screenshots:
        for s in screenshots[:MAX_SCREENSHOTS_IN_PDF]:
            if os.path.exists(s):
                try:
                    img = RLImage(s, width=16 * cm, height=9 * cm)
                    story.append(img)
                    story.append(Spacer(1, 0.5 * cm))
                except:
                    continue
    else:
        story.append(Paragraph("No screenshot generated.", normal))

    doc.build(story)


# ============================
# MAIN
# ============================
def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ai_vapt.py <IP_or_domain>")
        sys.exit(1)

    target = sys.argv[1].strip()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Resolve
    if is_ip(target):
        resolved_ip = target
    else:
        resolved_ip = resolve_domain_to_ip(target)
        if not resolved_ip:
            print("[!] Could not resolve domain.")
            sys.exit(1)

    # Nmap
    nmap_file, nmap_text = run_nmap(resolved_ip, stamp)
    open_ports = parse_nmap_open_ports(nmap_text)

    # Detect web URLs
    urls = detect_web_targets(resolved_ip)

    nuclei_findings = []
    screenshots = []

    # Scan only first 1-2 URLs (to keep PDF short)
    for url in urls[:2]:
        run_web_headers(url, stamp)
        nuclei_jsonl = run_nuclei(url, stamp)
        nuclei_findings.extend(parse_nuclei_jsonl(nuclei_jsonl))

        shot = take_screenshot(url, stamp)
        if shot:
            screenshots.append(shot)

    # AI summary
    print("\n[+] Running AI Summary (Ollama) ...")
    ai_text = ai_generate_summary(target, resolved_ip, open_ports, urls, nuclei_findings)

    # PDF
    report_path = os.path.join(OUTPUT_DIR, f"{sanitize_name(target)}_{stamp}_report.pdf")
    print("\n[+] Generating PDF report ...")
    build_pdf(report_path, target, resolved_ip, open_ports, urls, nuclei_findings, screenshots, ai_text)

    print("\n" + "=" * 60)
    print("[+] DONE!")
    print(f"[+] PDF Report: {report_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
