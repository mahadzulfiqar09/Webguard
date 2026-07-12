"""
headers_check.py - Security Header Analysis Module
Fetches the target's HTTP response headers and flags missing or weak
security headers, one of the most common web misconfiguration issues.
"""

import requests

HEADERS = {"User-Agent": "WebGuard-Scanner/1.0 (+authorized-security-testing)"}

# header_name -> (severity, description)
SECURITY_HEADERS = {
    "Content-Security-Policy": ("High", "Mitigates XSS and data-injection attacks by restricting sources"),
    "Strict-Transport-Security": ("High", "Forces browsers to use HTTPS, preventing downgrade/MITM attacks"),
    "X-Frame-Options": ("Medium", "Prevents clickjacking by controlling framing of the page"),
    "X-Content-Type-Options": ("Medium", "Prevents MIME-sniffing attacks"),
    "Referrer-Policy": ("Low", "Controls how much referrer information is leaked"),
    "Permissions-Policy": ("Low", "Restricts use of powerful browser features (camera, geolocation, etc.)"),
}


def check_headers(url, timeout=8):
    """
    Returns a list of finding dicts:
    {check, severity, status, detail}
    """
    findings = []
    print(f"\n[Security Headers] Analyzing: {url}")
    print("-" * 55)

    try:
        resp = requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        print(f"[-] Failed to fetch {url}: {e}")
        return [{"check": "Connectivity", "severity": "Info", "status": "Error", "detail": str(e)}]

    resp_headers = resp.headers

    for header, (severity, desc) in SECURITY_HEADERS.items():
        if header in resp_headers:
            print(f"[OK] {header} is present")
            findings.append({"check": header, "severity": "Info", "status": "Present", "detail": desc})
        else:
            print(f"[MISSING] {header} - {severity} severity")
            findings.append({"check": header, "severity": severity, "status": "Missing", "detail": desc})

    # Server banner exposure
    if "Server" in resp_headers:
        print(f"[INFO] Server header exposed: {resp_headers['Server']}")
        findings.append({
            "check": "Server Header",
            "severity": "Low",
            "status": "Exposed",
            "detail": f"Server banner disclosed: {resp_headers['Server']}",
        })

    # X-Powered-By exposure
    if "X-Powered-By" in resp_headers:
        print(f"[INFO] X-Powered-By exposed: {resp_headers['X-Powered-By']}")
        findings.append({
            "check": "X-Powered-By Header",
            "severity": "Low",
            "status": "Exposed",
            "detail": f"Technology banner disclosed: {resp_headers['X-Powered-By']}",
        })

    return findings


if __name__ == "__main__":
    target = input("Enter target URL (e.g., https://example.com): ")
    results = check_headers(target)
    print("\nSummary:")
    for r in results:
        print(f" - [{r['severity']}] {r['check']}: {r['status']}")
