#!/usr/bin/env python3
import argparse
from pynput import mouse
import datetime
import json
import os

# function to log the event to the file and possibly print it
def log_event(event_data, logfile, json_format=False, silent=False):
    if json_format:
        log_entry = json.dumps(event_data)
    else:
        log_entry = event_data["text"]

    with open(logfile, "a", encoding="utf-8") as f:
        f.write(log_entry + "\n")

    if not silent:
        print(log_entry)

def on_move(x, y, args):
    if args.only_click or args.only_scroll:
        return  
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    event_data = {
        "timestamp": timestamp,
        "event": "move",
        "x": x,
        "y": y,
        "text": f"[{timestamp}] Mouse moved to ({x}, {y})"
    }
    log_event(event_data, args.output, args.json, args.silent)

# function that tracks any event when mouse is clicked
def on_click(x, y, button, pressed, args):
    if args.only_move or args.only_scroll:
        return  # Skip click events if filtering is enabled
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    action = "pressed" if pressed else "released"
    event_data = {
        "timestamp": timestamp,
        "event": "click",
        "button": str(button),
        "action": action,
        "x": x,
        "y": y,
        "text": f"[{timestamp}] Mouse {action} at ({x}, {y}) with {button}"
    }
    log_event(event_data, args.output, args.json, args.silent)

# function that tracks any event that is triggered by the scroll wheel
def on_scroll(x, y, dx, dy, args):
    if args.only_move or args.only_click:
        return  
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    event_data = {
        "timestamp": timestamp,
        "event": "scroll",
        "x": x,
        "y": y,
        "dx": dx,
        "dy": dy,
        "text": f"[{timestamp}] Mouse scrolled at ({x}, {y}) - delta ({dx}, {dy})"
    }
    log_event(event_data, args.output, args.json, args.silent)

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Python Mouse Event Tracker with Filtering and JSON Support")
    parser.add_argument("-o", "--output", default="mouse_log.txt", help="Output log file")
    parser.add_argument("--json", action="store_true", help="Log in JSON format instead of plain text")
    parser.add_argument("--silent", action="store_true", help="Do not print events to terminal")
    parser.add_argument("--only-move", dest="only_move", action="store_true", help="Log only move events")
    parser.add_argument("--only-click", dest="only_click", action="store_true", help="Log only click events")
    parser.add_argument("--only-scroll", dest="only_scroll", action="store_true", help="Log only scroll events")
    args = parser.parse_args()

    print(f"|*| Mouse tracker started. Logging to {args.output}. Press Ctrl+C to stop.")

    with mouse.Listener(
        on_move=lambda x, y: on_move(x, y, args),
        on_click=lambda x, y, button, pressed: on_click(x, y, button, pressed, args),
        on_scroll=lambda x, y, dx, dy: on_scroll(x, y, dx, dy, args)
    ) as listener:
        listener.join()

if __name__ == "__main__":
    main()
