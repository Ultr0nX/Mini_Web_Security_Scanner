# mini_web_scanner.py
# Safe, beginner-friendly mini web vulnerability scanner
# Only run on your own lab targets (DVWA, Juice Shop, or local web apps)

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import json

# -------------------------------
# Configuration
# -------------------------------
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]

# -------------------------------
# Crawler / Discovery
# -------------------------------
def crawl(url, max_depth=2):
    visited = set()
    to_visit = [(url, 0)]
    urls = []

    while to_visit:
        current, depth = to_visit.pop(0)
        if current in visited or depth > max_depth:
            continue
        visited.add(current)
        urls.append(current)
        try:
            r = requests.get(current, timeout=5)
            soup = BeautifulSoup(r.text, "html.parser")
            for link in soup.find_all("a", href=True):
                absolute = urljoin(current, link['href'])
                if urlparse(absolute).netloc == urlparse(url).netloc:
                    to_visit.append((absolute, depth + 1))
        except Exception as e:
            print(f"[!] Error crawling {current}: {e}")
    return urls

# -------------------------------
# Passive Header Checks
# -------------------------------
def check_headers(url):
    try:
        r = requests.get(url, timeout=5)
    except Exception as e:
        return {"error": str(e)}
    result = {"url": url, "status": r.status_code, "missing_headers": []}
    for h in SECURITY_HEADERS:
        if h not in r.headers:
            result["missing_headers"].append(h)
    return result

# -------------------------------
# Simple Reflected XSS Detector (Safe)
# -------------------------------
def reflected_xss_check(url):
    payload = "scanner-test-12345"
    test_url = url
    if "?" not in url:
        test_url += f"?test={payload}"
    else:
        test_url += f"&test={payload}"
    try:
        r = requests.get(test_url, timeout=5)
        if payload in r.text:
            return {"url": url, "reflected": True}
        else:
            return {"url": url, "reflected": False}
    except Exception as e:
        return {"url": url, "error": str(e)}

# -------------------------------
# Main Scanner
# -------------------------------
def scan(target_url):
    print(f"[+] Starting scan on: {target_url}")
    discovered_urls = crawl(target_url)
    print(f"[+] Discovered {len(discovered_urls)} URLs.")

    scan_results = []
    for url in discovered_urls:
        headers_result = check_headers(url)
        xss_result = reflected_xss_check(url)
        scan_results.append({
            "url": url,
            "headers": headers_result,
            "xss": xss_result
        })

    # Save report
    with open("scan_report.json", "w") as f:
        json.dump(scan_results, f, indent=4)
    print("[+] Scan complete! Report saved to scan_report.json")

# -------------------------------
# CLI
# -------------------------------
if __name__ == "__main__":
    target = input("Enter target URL (e.g., http://localhost:3000): ").strip()
    scan(target)
