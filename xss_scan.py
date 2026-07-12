"""
xss_scan.py - Reflected XSS Detection Module
Injects a unique, harmless marker string into discovered form fields and
URL parameters, then checks whether the marker is reflected back
UNESCAPED in the response - a strong signal of reflected XSS.

This module only tests for reflection of an inert marker string. It does
not execute scripts, exfiltrate data, or perform any destructive action.
"""

import requests
import uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

HEADERS = {"User-Agent": "WebGuard-Scanner/1.0 (+authorized-security-testing)"}


def _marker():
    return f"wg_{uuid.uuid4().hex[:8]}"


def _test_reflection(response_text, marker):
    """A hit means the marker appears without HTML-encoding (i.e. '<' survived)."""
    probe = f"<{marker}>"
    return probe in response_text


def scan_query_params(url, timeout=8):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return findings

    for param in params:
        marker = _marker()
        test_params = params.copy()
        test_params[param] = [f"<{marker}>"]
        new_query = urlencode(test_params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        try:
            resp = requests.get(test_url, headers=HEADERS, timeout=timeout)
        except requests.RequestException:
            continue

        if _test_reflection(resp.text, marker):
            print(f"[!] Possible Reflected XSS - parameter '{param}' at {url}")
            findings.append({
                "check": f"Reflected XSS - query param '{param}'",
                "severity": "High",
                "status": "Vulnerable (unconfirmed)",
                "detail": f"Unescaped marker reflected in response for {test_url}",
            })
        else:
            findings.append({
                "check": f"Reflected XSS - query param '{param}'",
                "severity": "Info",
                "status": "Not Detected",
                "detail": "Marker was not reflected unescaped",
            })

    return findings


def scan_forms(forms, timeout=8):
    findings = []
    for form in forms:
        marker = _marker()
        payload = {field: f"<{marker}>" for field in form["inputs"]}

        try:
            if form["method"] == "post":
                resp = requests.post(form["action"], data=payload, headers=HEADERS, timeout=timeout)
            else:
                resp = requests.get(form["action"], params=payload, headers=HEADERS, timeout=timeout)
        except requests.RequestException:
            continue

        if _test_reflection(resp.text, marker):
            print(f"[!] Possible Reflected XSS - form at {form['action']}")
            findings.append({
                "check": f"Reflected XSS - form ({form['method'].upper()} {form['action']})",
                "severity": "High",
                "status": "Vulnerable (unconfirmed)",
                "detail": f"Unescaped marker reflected for fields: {form['inputs']}",
            })
        else:
            findings.append({
                "check": f"Reflected XSS - form ({form['method'].upper()} {form['action']})",
                "severity": "Info",
                "status": "Not Detected",
                "detail": "Marker was not reflected unescaped",
            })

    return findings


def scan_xss(target_url, forms=None):
    print(f"\n[XSS Scan] Testing: {target_url}")
    print("-" * 55)
    results = scan_query_params(target_url)
    if forms:
        results += scan_forms(forms)
    if not results:
        print("[INFO] No testable parameters or forms found on this URL.")
    return results


if __name__ == "__main__":
    target = input("Enter target URL with parameters (e.g., https://example.com/search?q=test): ")
    findings = scan_xss(target)
    print("\nSummary:")
    for f in findings:
        print(f" - [{f['severity']}] {f['check']}: {f['status']}")
