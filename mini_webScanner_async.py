import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import json

# -----------------------------
# CONFIGURATION
# -----------------------------
MAX_DEPTH = 2
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy"
]

# -----------------------------
# CRAWLER - async version
# -----------------------------
async def fetch(session, url):
    try:
        async with session.get(url, timeout=10) as response:
            text = await response.text(errors="ignore")
            return text, response
    except Exception as e:
        print(f"[!] Error fetching {url}: {e}")
        return None, None

async def crawl(session, start_url, max_depth=2):
    seen = set()
    to_visit = [(start_url, 0)]
    found_urls = []

    while to_visit:
        url, depth = to_visit.pop()
        if url in seen or depth > max_depth:
            continue
        seen.add(url)

        html, response = await fetch(session, url)
        if html is None:
            continue

        found_urls.append(url)
        print(f"[+] Crawled: {url} (depth {depth})")

        if depth < max_depth:
            soup = BeautifulSoup(html, "html.parser")
            for link in soup.find_all("a", href=True):
                full_url = urljoin(url, link["href"])
                # Keep only same-domain URLs
                if urlparse(full_url).netloc == urlparse(start_url).netloc:
                    to_visit.append((full_url, depth + 1))

    return found_urls

# -----------------------------
# HEADER CHECKS
# -----------------------------
async def check_security_headers(session, url):
    _, response = await fetch(session, url)
    if not response:
        return {"url": url, "status": "Error", "missing_headers": []}

    missing = []
    for h in SECURITY_HEADERS:
        if h not in response.headers:
            missing.append(h)

    return {
        "url": url,
        "status": response.status,
        "missing_headers": missing
    }

# -----------------------------
# REFLECTED XSS CHECK
# -----------------------------
async def check_reflected_xss(session, url):
    test_token = "scanner-test-12345"
    sep = "&" if "?" in url else "?"
    test_url = f"{url}{sep}test={test_token}"

    html, _ = await fetch(session, test_url)
    reflected = False
    if html and test_token in html:
        reflected = True

    return {"url": url, "reflected": reflected}

# -----------------------------
# MAIN SCAN FUNCTION
# -----------------------------
async def scan_site(start_url):
    results = []
    async with aiohttp.ClientSession() as session:
        print("[*] Starting crawl...")
        urls = await crawl(session, start_url, MAX_DEPTH)

        tasks = []
        for url in urls:
            tasks.append(scan_single_url(session, url))

        all_results = await asyncio.gather(*tasks)
        results.extend(all_results)

    with open("scan_report_async.json", "w") as f:
        json.dump(results, f, indent=2)
    print("\n✅ Scan completed. Results saved in scan_report_async.json")

async def scan_single_url(session, url):
    header_result = await check_security_headers(session, url)
    xss_result = await check_reflected_xss(session, url)
    return {"url": url, "headers": header_result, "xss": xss_result}

# -----------------------------
# ENTRY POINT
# -----------------------------
if __name__ == "__main__":
    target = input("Enter target URL (e.g., http://localhost:3000): ").strip()
    asyncio.run(scan_site(target))
