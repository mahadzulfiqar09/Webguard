"""
crawler.py - Site Crawler / Spider Module
Maps internal links and HTML forms within the target domain so other
modules (xss_scan, sqli_scan) know what surfaces to test.
"""

import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

HEADERS = {"User-Agent": "WebGuard-Scanner/1.0 (+authorized-security-testing)"}


def _same_domain(base_url, link):
    return urlparse(base_url).netloc == urlparse(link).netloc


def crawl(base_url, max_pages=25, timeout=6):
    """
    Breadth-first crawl of base_url, staying within the same domain.
    Returns:
        pages   -> set of visited URLs
        forms   -> list of dicts: {page, action, method, inputs: [name, ...]}
    """
    visited = set()
    to_visit = [base_url]
    forms = []

    print(f"\n[Crawler] Starting crawl of {base_url} (max {max_pages} pages)")
    print("-" * 55)

    while to_visit and len(visited) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue

        try:
            resp = requests.get(url, headers=HEADERS, timeout=timeout)
        except requests.RequestException as e:
            print(f"[-] Failed to fetch {url}: {e}")
            continue

        visited.add(url)
        print(f"[+] Crawled: {url}")

        if "text/html" not in resp.headers.get("Content-Type", ""):
            continue

        soup = BeautifulSoup(resp.text, "html.parser")

        # Collect links
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"]).split("#")[0]
            if _same_domain(base_url, link) and link not in visited:
                to_visit.append(link)

        # Collect forms
        for form in soup.find_all("form"):
            action = urljoin(url, form.get("action") or url)
            method = (form.get("method") or "get").lower()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs.append(name)
            if inputs:
                forms.append({"page": url, "action": action, "method": method, "inputs": inputs})

    print(f"\n[+] Crawl complete: {len(visited)} pages, {len(forms)} forms with input fields")
    return visited, forms


if __name__ == "__main__":
    target = input("Enter target URL (e.g., https://example.com): ")
    pages, discovered_forms = crawl(target)
    print("\nDiscovered pages:")
    for p in sorted(pages):
        print(f" - {p}")
    print("\nDiscovered forms:")
    for f in discovered_forms:
        print(f" - {f['method'].upper()} {f['action']} | fields: {f['inputs']}")
