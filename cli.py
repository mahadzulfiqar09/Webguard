"""
cli.py - WebGuard Command-Line Interface
Run individual scan modules or a full scan via subcommands and flags.
"""

import argparse
import sys

from modules import crawler, headers_check, cookie_check, xss_scan, sqli_scan, report


def run_full_scan(target, output_format):
    all_findings = {}

    pages, forms = crawler.crawl(target)
    all_findings["Crawler - Pages & Forms Discovered"] = [
        {"check": "Pages Crawled", "severity": "Info", "status": f"{len(pages)} pages",
         "detail": ", ".join(sorted(pages)[:10]) + (" ..." if len(pages) > 10 else "")},
        {"check": "Forms Discovered", "severity": "Info", "status": f"{len(forms)} forms",
         "detail": "; ".join(f"{f['method'].upper()} {f['action']}" for f in forms[:10])},
    ]

    all_findings["Security Headers"] = headers_check.check_headers(target)
    all_findings["Cookie Security"] = cookie_check.check_cookies(target)
    all_findings["Reflected XSS"] = xss_scan.scan_xss(target, forms)
    all_findings["SQL Injection"] = sqli_scan.scan_sqli(target, forms)

    if output_format == "html":
        report.generate_html_report(target, all_findings)
    else:
        report.generate_txt_report(target, all_findings)


def main():
    parser = argparse.ArgumentParser(description="WebGuard - Modular Web Vulnerability Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target URL, e.g. https://example.com")
    parser.add_argument("-o", "--output", choices=["txt", "html"], default="txt", help="Report format (full scan only)")

    subparsers = parser.add_subparsers(dest="mode")

    subparsers.add_parser("all", help="Run the full scan (crawler + all checks) and generate a report")

    single = subparsers.add_parser("single", help="Run a single module")
    single.add_argument(
        "--tool",
        choices=["crawl", "headers", "cookies", "xss", "sqli"],
        required=True,
        help="Which module to run",
    )

    args = parser.parse_args()

    if not args.target.startswith("http"):
        print("[-] Target must include the scheme, e.g. https://example.com")
        sys.exit(1)

    if args.mode == "all" or args.mode is None:
        run_full_scan(args.target, args.output)
        return

    if args.mode == "single":
        if args.tool == "crawl":
            crawler.crawl(args.target)
        elif args.tool == "headers":
            headers_check.check_headers(args.target)
        elif args.tool == "cookies":
            cookie_check.check_cookies(args.target)
        elif args.tool == "xss":
            _, forms = crawler.crawl(args.target, max_pages=5)
            xss_scan.scan_xss(args.target, forms)
        elif args.tool == "sqli":
            _, forms = crawler.crawl(args.target, max_pages=5)
            sqli_scan.scan_sqli(args.target, forms)


if __name__ == "__main__":
    main()
