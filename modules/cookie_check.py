"""
cookie_check.py - Cookie Security Analysis Module
Inspects Set-Cookie headers for missing Secure, HttpOnly, and SameSite
attributes, which commonly lead to session hijacking or CSRF exposure.
"""

import requests

HEADERS = {"User-Agent": "WebGuard-Scanner/1.0 (+authorized-security-testing)"}


def check_cookies(url, timeout=8):
    """
    Returns a list of finding dicts:
    {check, severity, status, detail}
    """
    findings = []
    print(f"\n[Cookie Security] Analyzing: {url}")
    print("-" * 55)

    try:
        resp = requests.get(url, headers=HEADERS, timeout=timeout)
    except requests.RequestException as e:
        print(f"[-] Failed to fetch {url}: {e}")
        return [{"check": "Connectivity", "severity": "Info", "status": "Error", "detail": str(e)}]

    raw_cookies = resp.raw.headers.get_all("Set-Cookie") if resp.raw and resp.raw.headers else None

    if not raw_cookies:
        print("[INFO] No cookies set by this endpoint.")
        return [{"check": "Cookies", "severity": "Info", "status": "None Found", "detail": "No Set-Cookie headers returned"}]

    for cookie_str in raw_cookies:
        name = cookie_str.split("=")[0].strip()
        lower = cookie_str.lower()

        print(f"\n[Cookie] {name}")

        if "secure" in lower:
            print("  [OK] Secure flag present")
            findings.append({"check": f"{name} - Secure flag", "severity": "Info", "status": "Present", "detail": "Cookie only sent over HTTPS"})
        else:
            print("  [MISSING] Secure flag")
            findings.append({"check": f"{name} - Secure flag", "severity": "Medium", "status": "Missing", "detail": "Cookie may be sent over unencrypted HTTP"})

        if "httponly" in lower:
            print("  [OK] HttpOnly flag present")
            findings.append({"check": f"{name} - HttpOnly flag", "severity": "Info", "status": "Present", "detail": "Cookie inaccessible to client-side JavaScript"})
        else:
            print("  [MISSING] HttpOnly flag")
            findings.append({"check": f"{name} - HttpOnly flag", "severity": "High", "status": "Missing", "detail": "Cookie may be readable via JavaScript - increases XSS/session theft impact"})

        if "samesite" in lower:
            print("  [OK] SameSite attribute present")
            findings.append({"check": f"{name} - SameSite attribute", "severity": "Info", "status": "Present", "detail": "Cookie has CSRF protection via SameSite"})
        else:
            print("  [MISSING] SameSite attribute")
            findings.append({"check": f"{name} - SameSite attribute", "severity": "Medium", "status": "Missing", "detail": "Cookie may be vulnerable to CSRF"})

    return findings


if __name__ == "__main__":
    target = input("Enter target URL (e.g., https://example.com): ")
    results = check_cookies(target)
    print("\nSummary:")
    for r in results:
        print(f" - [{r['severity']}] {r['check']}: {r['status']}")
