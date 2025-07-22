import argparse
import requests
import json
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager

# list that loads payloads 
PAYLOADS = [
    '<script>alert(1)</script>',
    '"><svg/onload=alert(1)>',
    '<img src=x onerror=alert(1)>',
    '\";alert(1);//',
    '<iframe src=javascript:alert(1)>',
    '<body onload=alert(1)>',
]

HEADERS_TO_TEST = ['User-Agent', 'Referer', 'X-Forwarded-For']

# function that injects the payloads into the url
def inject_payloads(url: str, payloads: list) -> list:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    test_urls = []

    for payload in payloads:
        for param in query:
            temp_query = query.copy()
            temp_query[param] = payload
            encoded_query = urlencode(temp_query, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', encoded_query, ''))
            test_urls.append((test_url, param, payload))

    return test_urls

# function that opens url in a headless browser and checks for javascript alerts
def scan_with_browser(url: str, timeout: int = 5) -> bool:
    try:
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--disable-gpu')
        options.add_argument('--no-sandbox')
        driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)

        driver.set_page_load_timeout(timeout)
        driver.get(url)
        time.sleep(1)

        alert_present = False
        try:
            alert = driver.switch_to.alert
            alert_text = alert.text
            alert.accept()
            alert_present = True
        except:
            pass

        driver.quit()
        return alert_present
    except Exception:
        return False

# primary xss scanner function that tracks the results
def scan_xss(url: str, timeout: int = 5):
    test_urls = inject_payloads(url, PAYLOADS)
    vulnerable = []

    for test_url, param, payload in test_urls:
        try:
            res = requests.get(test_url, timeout=timeout)
            if payload in res.text:
                print(f"|!| Reflected XSS found in param: {param}\n    - URL: {test_url}")
                vulnerable.append((test_url, param, 'reflected'))
            elif scan_with_browser(test_url):
                print(f"|!| DOM-based XSS detected via payload in param: {param}\n    - URL: {test_url}")
                vulnerable.append((test_url, param, 'DOM'))
        except requests.RequestException as e:
            print(f"|x| Error testing {test_url}: {e}")

    for header in HEADERS_TO_TEST:
        for payload in PAYLOADS:
            try:
                headers = {header: payload}
                res = requests.get(url, headers=headers, timeout=timeout)
                if payload in res.text:
                    print(f"|!| XSS via HTTP header: {header}\n    - Payload: {payload}")
                    vulnerable.append((url, header, 'header'))
            except requests.RequestException:
                continue

    if not vulnerable:
        print("|*| No XSS vulnerabilities detected.")
    else:
        print(f"\n|+| Scan complete. {len(vulnerable)} potential issue(s) found.")

    return vulnerable

# arg parser for cli customazbility
def cli():
    parser = argparse.ArgumentParser(description="Advanced Reflected & DOM XSS Scanner")
    parser.add_argument("url", help='Target URL (e.g., "http://example.com/page.php?q=test")')
    parser.add_argument("-o", "--output", help="Optional path to JSON report file")
    args = parser.parse_args()

    print("[*] Starting XSS scan...")
    results = scan_xss(args.url)

    if args.output and results:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[+] Results saved to {args.output}")

if __name__ == "__main__":
    cli()
