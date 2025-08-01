import argparse
import zipfile
import rarfile
from tqdm import tqdm
import concurrent.futures
import os
import json
import csv

# function that attempts to open a zip archive with a password
def try_zip_password(zip_path, pw):
    try:
        with zipfile.ZipFile(zip_path) as zipf:
            zipf.extractall(pwd=pw.encode())
            return pw
    except:
        return None

# function that uses concurrent threads to repeatedly use the previous function to crack zip passwords en masse using wordlists
def crack_zip(zip_path, wordlist, threads=1, max_attempts=None, quiet=False):
    with open(wordlist, "r", encoding="latin-1", errors="ignore") as f:
        passwords = [pw.strip() for pw in f if pw.strip()]
    
    if max_attempts:
        passwords = passwords[:max_attempts]

    if not quiet:
        print(f"|*| Cracking ZIP: {zip_path} with {len(passwords)} passwords")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_pw = {executor.submit(try_zip_password, zip_path, pw): pw for pw in passwords}
        for future in tqdm(concurrent.futures.as_completed(future_to_pw), total=len(future_to_pw), desc="Trying ZIP passwords", disable=quiet):
            result = future.result()
            if result:
                print(f"\n|+| Found ZIP password: {result}")
                return result

    print("|-| Password not found.")
    return None

# function that attempts to open a rar archive with a password
def try_rar_password(rar_path, pw):
    try:
        with rarfile.RarFile(rar_path) as rf:
            rf.extractall(pwd=pw)
            return pw
    except:
        return None

# function that uses concurrent threads to repeatedly use the try password function to crack the rar passwords using wordlists
def crack_rar(rar_path, wordlist, threads=1, max_attempts=None, quiet=False):
    with open(wordlist, "r", encoding="latin-1", errors="ignore") as f:
        passwords = [pw.strip() for pw in f if pw.strip()]

    if max_attempts:
        passwords = passwords[:max_attempts]

    if not quiet:
        print(f"|*| Cracking RAR: {rar_path} with {len(passwords)} passwords")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_pw = {executor.submit(try_rar_password, rar_path, pw): pw for pw in passwords}
        for future in tqdm(concurrent.futures.as_completed(future_to_pw), total=len(future_to_pw), desc="Trying RAR passwords", disable=quiet):
            result = future.result()
            if result:
                print(f"\n|+| Found RAR password: {result}")
                return result

    print("|-| Password not found.")
    return None

# functions that export the info into csv or json formats
def export_result(archive, password, out_file, fmt="json"):
    result = {
        "archive": archive,
        "password": password if password else "<not found>"
    }
    if fmt == "json":
        with open(out_file, "w") as f:
            json.dump(result, f, indent=2)
        print(f"|+| Result saved to {out_file}")
    elif fmt == "csv":
        with open(out_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=result.keys())
            writer.writeheader()
            writer.writerow(result)
        print(f"|+| Result saved to {out_file}")
    else:
        print("|x| Unsupported export format")

# arg parser of cli customizability
def cli():
    parser = argparse.ArgumentParser(description="ZIP/RAR Archive Password Cracker")
    parser.add_argument("archive", help="Path to .zip or .rar file")
    parser.add_argument("wordlist", help="Path to password wordlist (e.g., rockyou.txt)")
    parser.add_argument("--threads", type=int, default=4, help="Number of threads to use (default: 4)")
    parser.add_argument("--max", type=int, help="Maximum passwords to try")
    parser.add_argument("--quiet", action="store_true", help="Suppress output except results")
    parser.add_argument("--out", help="Output file for cracked password (JSON/CSV based on extension)")
    args = parser.parse_args()

    archive = args.archive.lower()
    password = None

    if archive.endswith('.zip'):
        password = crack_zip(args.archive, args.wordlist, threads=args.threads, max_attempts=args.max, quiet=args.quiet)
    elif archive.endswith('.rar'):
        password = crack_rar(args.archive, args.wordlist, threads=args.threads, max_attempts=args.max, quiet=args.quiet)
    else:
        print("|x| Unsupported archive format. Must be .zip or .rar.")
        return

    if args.out:
        ext = os.path.splitext(args.out)[1].lower()
        fmt = "json" if ext == ".json" else "csv" if ext == ".csv" else "json"
        export_result(args.archive, password, args.out, fmt)

if __name__ == "__main__":
    cli()
