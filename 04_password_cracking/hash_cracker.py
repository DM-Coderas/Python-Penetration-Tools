import argparse
import hashlib
import importlib.util
from pathlib import Path
import csv
import json
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

# function to get the correct hashing algorithm
def get_hash_function(hash_type, custom_path=None):
    if hash_type.lower() == "custom" and custom_path:
        spec = importlib.util.spec_from_file_location("custom_module", custom_path)
        custom_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(custom_module)
        if hasattr(custom_module, "custom_hash"):
            return custom_module.custom_hash
        else:
            print("|x| custom_hash function not found in custom module.")
            return None
    try:
        return getattr(hashlib, hash_type.lower())
    except AttributeError:
        print(f"|x| Unsupported hash type: {hash_type}")
        return None

# attempts to identify the type of hash through the string length
def detect_hash_type(hash_str):
    length_map = {
        32: 'md5',
        40: 'sha1',
        64: 'sha256',
        128: 'sha512'
    }
    return length_map.get(len(hash_str), 'unknown')

# function that iterates through the wordlist to crack the hash
def crack_hash_single(hash_value, hash_func, wordlist_path):
    with open(wordlist_path, "r", encoding="latin-1", errors="ignore") as f:
        for pw in f:
            pw = pw.strip()
            if not pw:
                continue
            try:
                candidate = hash_func(pw.encode()).hexdigest()
            except Exception:
                candidate = hash_func(pw)
            if candidate == hash_value.lower():
                return pw
    return None

# function that orchestrates multi-threaded hash cracking
def crack_hashes_concurrent(hashes, hash_func, wordlist_path, threads=4):
    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_hash = {
            executor.submit(crack_hash_single, h, hash_func, wordlist_path): h
            for h in hashes
        }
        for future in tqdm(as_completed(future_to_hash), total=len(hashes), desc="Cracking"):
            h = future_to_hash[future]
            try:
                pw = future.result()
                results.append({
                    "hash": h,
                    "password": pw if pw else "<not found>",
                    "type": hash_func.__name__ if hasattr(hash_func, '__name__') else "custom"
                })
                if pw:
                    print(f"|+| {h} → {pw}")
                else:
                    print(f"|-| {h} not found")
            except Exception as e:
                print(f"|!| Error cracking {h}: {e}")
    return results

# functions to output results into a json or csv format
def export_results(results, fmt="csv", out_file="cracked_hashes"):
    out_file = Path(out_file)
    if fmt == "csv":
        with open(out_file.with_suffix(".csv"), "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["hash", "password", "type"])
            writer.writeheader()
            writer.writerows(results)
        print(f"|+| Results saved to {out_file.with_suffix('.csv')}")
    elif fmt == "json":
        with open(out_file.with_suffix(".json"), "w") as f:
            json.dump(results, f, indent=2)
        print(f"|+| Results saved to {out_file.with_suffix('.json')}")
    else:
        print(f"|x| Unsupported export format: {fmt}")

# arg parser for cli customizability
def cli():
    parser = argparse.ArgumentParser(description="Advanced Python Hash Cracker (Multithreaded, Custom Hash Support)")
    parser.add_argument("hash", help="Single hash or path to file containing hashes (one per line)")
    parser.add_argument("wordlist", help="Path to wordlist file (e.g., rockyou.txt)")
    parser.add_argument("--type", help="Hash type (md5, sha1, sha256, sha512, or 'custom')")
    parser.add_argument("--custom", help="Path to custom hash Python file (must define `custom_hash(input_bytes)`)")
    parser.add_argument("--guess", action="store_true", help="Attempt to guess hash type based on length")
    parser.add_argument("--out", help="Output base name (without extension)")
    parser.add_argument("--format", choices=["csv", "json"], help="Export results to file")
    parser.add_argument("--threads", type=int, default=4, help="Number of threads for concurrent cracking")
    args = parser.parse_args()

    hash_input = args.hash

    if Path(hash_input).is_file():
        with open(hash_input) as f:
            hashes = [line.strip() for line in f if line.strip()]
    else:
        hashes = [hash_input.strip()]

    if args.guess:
        guessed = detect_hash_type(hashes[0])
        if guessed == "unknown":
            print("|!| Couldn't guess hash type. Please specify with --type.")
            return
        else:
            print(f"|*| Guessed hash type: {guessed}")
            args.type = guessed

    if not args.type:
        print("|x| Please specify hash type using --type or --guess.")
        return

    hash_func = get_hash_function(args.type, args.custom)
    if not hash_func:
        return

    results = crack_hashes_concurrent(hashes, hash_func, args.wordlist, threads=args.threads)

    if args.format and args.out:
        export_results(results, fmt=args.format, out_file=args.out)

if __name__ == "__main__":
    cli()
