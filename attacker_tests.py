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