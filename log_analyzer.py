import json
from collections import Counter, defaultdict

PROXY_LOG_FILE = "proxy_logs.json"
ATTACK_LOG_FILE = "proxy_logs.json"

def analyze_summary():
    """Summarize proxy logs: status codes, methods, payloads, proxy success/fail."""
    logs = []
    with open(PROXY_LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue  # skip non-JSON lines
            try:
                logs.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"Skipping malformed line: {line[:50]}... ({e})")

    status_counter = Counter()
    method_counter = Counter()
    payload_results = defaultdict(list)
    proxy_success = Counter()
    proxy_fail = Counter()

    # ✅ Track credit keyword detections
    credit_hits = []

    for entry in logs:
        status = entry.get("status")
        method = entry.get("method")
        payload = entry.get("payload")
        proxy = entry.get("proxy")
        body = entry.get("body", entry.get("body_preview", ""))  # full body if available

        if status:
            status_counter[status] += 1
        if method:
            method_counter[method] += 1
        if payload:
            payload_results[entry["url"]].append((payload, status))

        if proxy:
            if "error" in entry:
                proxy_fail[proxy] += 1
            else:
                proxy_success[proxy] += 1

        # 👇 Detect "credit" keyword in body
        if body and "credit" in body.lower():
            credit_hits.append(entry.get("url", "unknown"))

    print("\n=== Log Analysis Summary ===")
    print("Top Status Codes:", status_counter.most_common())
    print("HTTP Method Usage:", method_counter.most_common())

    print("\nPayload Injection Results:")
    for url, results in payload_results.items():
        print(f"  {url}")
        for payload, status in results:
            print(f"    ▸ {payload} -> {status}")

    print("\nProxy Success/Failure:")
    for proxy in set(list(proxy_success.keys()) + list(proxy_fail.keys())):
        print(f"  {proxy}: success={proxy_success[proxy]}, fail={proxy_fail[proxy]}")

    # ✅ Report credit keyword findings
    print("\nCredit Keyword Findings:")
    if credit_hits:
        for url in credit_hits:
            print(f"  [SUCCESS] 'credit' keyword detected in response from {url}")
    else:
        print("  No 'credit' keyword detected in any response.")

def analyze_suspicious():
    """Highlight suspicious findings from attack logs."""
    suspicious = []
    with open(ATTACK_LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
                url = entry.get("url", "")
                status = entry.get("status", "")
                body = entry.get("body", entry.get("body_preview", ""))  # full body if available
                payload = entry.get("payload", "")
                headers = entry.get("headers", "")
                cookies = entry.get("cookies", "")

                if payload and payload in body:
                    suspicious.append(f"[XSS Reflection] Payload reflected at {url} -> {payload}")

                if "Invalid" not in body and status == 200 and payload:
                    suspicious.append(f"[Potential Injection] {url} with {payload}")

                if headers:
                    suspicious.append(f"[Header Injection Tested] {url} with {headers}")

                if cookies:
                    suspicious.append(f"[Cookie Tampering Tested] {url} with {cookies}")

                if status in [401, 403, 405]:
                    suspicious.append(f"[Blocked/Rejected] {url} -> {status}")

                # 👇 Extra check for "credit" keyword
                if body and "credit" in body.lower():
                    suspicious.append(f"[Login Success Detected] {url} contains 'credit' keyword")

            except json.JSONDecodeError as e:
                print(f"Skipping malformed line: {line[:50]}... ({e})")

    print("\n=== Suspicious Findings ===")
    for s in suspicious:
        print(s)

if __name__ == "__main__":
    analyze_summary()
    analyze_suspicious()