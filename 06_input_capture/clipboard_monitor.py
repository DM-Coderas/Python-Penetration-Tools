import time
import json
import argparse
import pyperclip
from datetime import datetime
from threading import Lock

# lock for safe file writing in multi threaded environments
log_lock = Lock()

# function to log clipboard content to a file
def log_clipboard(content, output, json_mode):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with log_lock:
        if json_mode:
            entry = {"timestamp": timestamp, "clipboard": content}
            try:
                with open(output, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                data = []

            data.append(entry)
            with open(output, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        else:
            with open(output, "a", encoding="utf-8") as f:
                f.write(f"[{timestamp}] {content}\n")

# function to create the main monitor loop
def monitor_clipboard(output, interval, silent, json_mode):
    print(f"|*| Clipboard monitor started. Logging to '{output}'. Press Ctrl+C to stop.")
    last_content = ""

    try:
        while True:
            content = pyperclip.paste()
            if content and content != last_content:
                last_content = content
                log_clipboard(content, output, json_mode)
                if not silent:
                    print(f"|+| New clipboard content captured:\n{content}\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n|*| Clipboard monitor stopped.")

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Clipboard Monitor with Logging Options")
    parser.add_argument(
        "-o", "--output", default="clipboard_log.txt",
        help="Output file name (default: clipboard_log.txt)"
    )
    parser.add_argument(
        "-i", "--interval", type=float, default=0.5,
        help="Polling interval in seconds (default: 0.5)"
    )
    parser.add_argument(
        "--silent", action="store_true",
        help="Suppress output to console"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Log clipboard data in JSON format"
    )

    args = parser.parse_args()
    monitor_clipboard(args.output, args.interval, args.silent, args.json)

if __name__ == "__main__":
    main()
