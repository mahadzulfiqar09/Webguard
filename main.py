"""
main.py - WebGuard Main Controller
Interactive entry point that runs the full scan pipeline (crawl -> headers
-> cookies -> XSS -> SQLi -> report) against a single target.
"""

from modules import crawler, headers_check, cookie_check, xss_scan, sqli_scan, report


def main():
    print("=== WebGuard - Web Vulnerability Scanner ===")
    target = input("Enter target URL (e.g., https://example.com): ").strip()

    if not target.startswith("http"):
        print("[-] Please include the scheme, e.g. https://example.com")
        return

    all_findings = {}

    print("\n--- CRAWLING & DISCOVERY ---")
    pages, forms = crawler.crawl(target)
    all_findings["Crawler - Pages & Forms Discovered"] = [
        {"check": "Pages Crawled", "severity": "Info", "status": f"{len(pages)} pages",
         "detail": ", ".join(sorted(pages)[:10]) + (" ..." if len(pages) > 10 else "")},
        {"check": "Forms Discovered", "severity": "Info", "status": f"{len(forms)} forms",
         "detail": "; ".join(f"{f['method'].upper()} {f['action']}" for f in forms[:10])},
    ]

    print("\n--- SECURITY HEADERS ---")
    all_findings["Security Headers"] = headers_check.check_headers(target)

    print("\n--- COOKIE SECURITY ---")
    all_findings["Cookie Security"] = cookie_check.check_cookies(target)

    print("\n--- REFLECTED XSS ---")
    all_findings["Reflected XSS"] = xss_scan.scan_xss(target, forms)

    print("\n--- SQL INJECTION ---")
    all_findings["SQL Injection"] = sqli_scan.scan_sqli(target, forms)

    print("\n--- GENERATING REPORT ---")
    report.generate_txt_report(target, all_findings)
    report.generate_html_report(target, all_findings)

    print("\n[+] Scan complete.")


if __name__ == "__main__":
    main()
