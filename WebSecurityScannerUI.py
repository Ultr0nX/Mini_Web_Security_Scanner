# mini_web_scanner_flask_ui.py
# Single-file Flask web UI + Async scanner
# Usage: pip install flask aiohttp beautifulsoup4
# Run: python mini_web_scanner_flask_ui.py
# Open http://127.0.0.1:5000 in your browser (only test on your lab targets)

from flask import Flask, request, redirect, url_for, render_template_string, jsonify
import asyncio
import aiohttp
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import json
import threading
import time

app = Flask(__name__)

# -----------------------------
# Scanner configuration (same as async scanner)
# -----------------------------
MAX_DEPTH = 2
SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy"
]
REPORT_FILE = "scan_report_async.json"
scan_status = {
    "running": False,
    "started_at": None,
    "finished_at": None,
    "target": None
}

# -----------------------------
# Async scanner functions
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

async def check_reflected_xss(session, url):
    test_token = "scanner-test-12345"
    sep = "&" if "?" in url else "?"
    test_url = f"{url}{sep}test={test_token}"

    html, _ = await fetch(session, test_url)
    reflected = False
    if html and test_token in html:
        reflected = True

    return {"url": url, "reflected": reflected}

async def scan_single_url(session, url):
    header_result = await check_security_headers(session, url)
    xss_result = await check_reflected_xss(session, url)
    return {"url": url, "headers": header_result, "xss": xss_result}

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

    with open(REPORT_FILE, "w") as f:
        json.dump(results, f, indent=2)
    print("\n✅ Scan completed. Results saved in", REPORT_FILE)

# -----------------------------
# Helper to run the async scanner in a background thread
# -----------------------------
def background_scan(target):
    global scan_status
    scan_status["running"] = True
    scan_status["started_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    scan_status["finished_at"] = None
    scan_status["target"] = target

    try:
        asyncio.run(scan_site(target))
    except Exception as e:
        print("Scan error:", e)
    finally:
        scan_status["running"] = False
        scan_status["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")

# -----------------------------
# Flask routes - very simple UI
# -----------------------------
INDEX_HTML = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Mini Web Scanner UI</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body class="bg-dark text-light">
    <div class="container py-5">
      <h1 class="mb-3">Mini Web Scanner - UI</h1>

      <div class="card mb-4">
        <div class="card-body bg-secondary text-light">
          <form method="post" action="/start">
            <div class="mb-3">
              <label class="form-label">Target URL </label>
              <input name="target" class="form-control" placeholder="http://localhost:3000" required />
            </div>
            <button class="btn btn-success">Start Scan</button>
            <a href="/report" class="btn btn-primary ms-2">View Last Report</a>
          </form>
        </div>
      </div>

      <div class="card">
        <div class="card-body bg-secondary">
          <h5>Status</h5>
          <p>Running: <strong>{{ running }}</strong></p>
          <p>Target: <strong>{{ target or '—' }}</strong></p>
          <p>Started at: <strong>{{ started_at or '—' }}</strong></p>
          <p>Finished at: <strong>{{ finished_at or '—' }}</strong></p>
        </div>
      </div>

      
    </div>
  </body>
</html>
"""

REPORT_HTML = """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Scan Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  </head>
  <body class="bg-dark text-dark ">
    <div class="container py-4">
      <h1 class="mb-3 text-light">Last Scan Report</h1>
      <a href="/" class="btn btn-secondary mb-3">Back</a>

      {% if results %}
        <div class="accordion" id="reportAccordion">
          {% for item in results %}
            <div class="accordion-item bg-black text-light mb-2">
              <h2 class="accordion-header" id="heading{{ loop.index }}">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse{{ loop.index }}" aria-expanded="false">
                  {{ item.url }} — status: {{ item.headers.status }}
                </button>
              </h2>
              <div id="collapse{{ loop.index }}" class="accordion-collapse collapse" data-bs-parent="#reportAccordion">
                <div class="accordion-body">
                  <h6>Missing Security Headers</h6>
                  {% if item.headers.missing_headers %}
                    <ul>
                      {% for h in item.headers.missing_headers %}
                        <li>{{ h }}</li>
                      {% endfor %}
                    </ul>
                  {% else %}
                    <p><em>None — good</em></p>
                  {% endif %}

                  <h6>Reflected XSS</h6>
                  <p>{{ 'REFLECTED — investigate' if item.xss.reflected else 'No reflection detected' }}</p>

                  <pre class="mt-2">{{ item | tojson(indent=2) }}</pre>
                </div>
              </div>
            </div>
          {% endfor %}
        </div>
      {% else %}
        <p>No report found. Run a scan first.</p>
      {% endif %}

    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(INDEX_HTML, running=scan_status["running"], target=scan_status["target"], started_at=scan_status["started_at"], finished_at=scan_status["finished_at"])

@app.route('/start', methods=['POST'])
def start():
    target = request.form.get('target')
    if not target:
        return redirect(url_for('index'))

    if scan_status["running"]:
        return "A scan is already running. Please wait until it finishes.", 400

    # Start background thread
    t = threading.Thread(target=background_scan, args=(target,), daemon=True)
    t.start()

    return redirect(url_for('index'))

@app.route('/report')
def report():
    try:
        with open(REPORT_FILE, 'r') as f:
            results = json.load(f)
    except Exception:
        results = None
    return render_template_string(REPORT_HTML, results=results)

@app.route('/api/status')
def api_status():
    return jsonify(scan_status)

@app.route('/api/report')
def api_report():
    try:
        with open(REPORT_FILE, 'r') as f:
            results = json.load(f)
    except Exception:
        results = []
    return jsonify(results)

if __name__ == '__main__':
    print("Starting Flask UI on http://127.0.0.1:5000")
    app.run(debug=True)
