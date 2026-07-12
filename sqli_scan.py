"""
sqli_scan.py - SQL Injection Detection Module (Error-Based)
Sends a single benign probe character to each discovered parameter/field
and checks the response for common database error signatures. This is a
passive, non-destructive detection technique - it does not attempt to
extract data, bypass authentication, or modify the database in any way.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

HEADERS = {"User-Agent": "WebGuard-Scanner/1.0 (+authorized-security-testing)"}

# A single quote is enough to break most naive/unsanitized SQL queries
PROBE = "'"

# Common DB error signatures that indicate the probe reached a query
ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "pg_query()",
    "ora-00933",
    "ora-01756",
    "microsoft odbc",
    "sqlite3.operationalerror",
    "syntax error in query expression",
    "psycopg2.errors",
]


def _has_sql_error(text):
    lowered = text.lower()
    return any(sig in lowered for sig in ERROR_SIGNATURES)


def scan_query_params(url, timeout=8):
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return findings

    for param in params:
        test_params = params.copy()
        test_params[param] = [f"{params[param][0]}{PROBE}"]
        new_query = urlencode(test_params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))

        try:
            resp = requests.get(test_url, headers=HEADERS, timeout=timeout)
        except requests.RequestException:
            continue

        if _has_sql_error(resp.text):
            print(f"[!] Possible SQL Injection - parameter '{param}' at {url}")
            findings.append({
                "check": f"SQL Injection - query param '{param}'",
                "severity": "Critical",
                "status": "Vulnerable (unconfirmed)",
                "detail": f"Database error signature returned after probing {test_url}",
            })
        else:
            findings.append({
                "check": f"SQL Injection - query param '{param}'",
                "severity": "Info",
                "status": "Not Detected",
                "detail": "No database error signature observed",
            })

    return findings


def scan_forms(forms, timeout=8):
    findings = []
    for form in forms:
        payload = {field: PROBE for field in form["inputs"]}

        try:
            if form["method"] == "post":
                resp = requests.post(form["action"], data=payload, headers=HEADERS, timeout=timeout)
            else:
                resp = requests.get(form["action"], params=payload, headers=HEADERS, timeout=timeout)
        except requests.RequestException:
            continue

        if _has_sql_error(resp.text):
            print(f"[!] Possible SQL Injection - form at {form['action']}")
            findings.append({
                "check": f"SQL Injection - form ({form['method'].upper()} {form['action']})",
                "severity": "Critical",
                "status": "Vulnerable (unconfirmed)",
                "detail": f"Database error signature returned for fields: {form['inputs']}",
            })
        else:
            findings.append({
                "check": f"SQL Injection - form ({form['method'].upper()} {form['action']})",
                "severity": "Info",
                "status": "Not Detected",
                "detail": "No database error signature observed",
            })

    return findings


def scan_sqli(target_url, forms=None):
    print(f"\n[SQLi Scan] Testing: {target_url}")
    print("-" * 55)
    results = scan_query_params(target_url)
    if forms:
        results += scan_forms(forms)
    if not results:
        print("[INFO] No testable parameters or forms found on this URL.")
    return results


if __name__ == "__main__":
    target = input("Enter target URL with parameters (e.g., https://example.com/item?id=1): ")
    findings = scan_sqli(target)
    print("\nSummary:")
    for f in findings:
        print(f" - [{f['severity']}] {f['check']}: {f['status']}")
