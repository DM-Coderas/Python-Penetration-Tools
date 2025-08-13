import sys
import datetime
import argparse
import json
import csv
from PyQt5.QtWidgets import QApplication, QWidget
from PyQt5.QtCore import Qt

# class of functions that uses pyqt5.qt for touchscreen capabilities
class TouchWidget(QWidget):
    def __init__(self, logfile, log_format):
        super().__init__()
        self.setWindowTitle("Touchscreen Capturer")
        self.setGeometry(300, 300, 400, 400)
        self.logfile = logfile
        self.log_format = log_format

    def log_event(self, event_type, pos):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = {
            "timestamp": timestamp,
            "event": event_type,
            "x": pos.x(),
            "y": pos.y()
        }

        print(f"[{timestamp}] {event_type} at ({pos.x()}, {pos.y()})")

        if self.log_format == "text":
            with open(self.logfile, "a") as f:
                f.write(f"[{timestamp}] {event_type} at ({pos.x()}, {pos.y()})\n")
        elif self.log_format == "json":
            with open(self.logfile, "a") as f:
                f.write(json.dumps(entry) + "\n")
        elif self.log_format == "csv":
            file_exists = False
            try:
                with open(self.logfile, "r"):
                    file_exists = True
            except FileNotFoundError:
                pass
            with open(self.logfile, "a", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["timestamp", "event", "x", "y"])
                if not file_exists:
                    writer.writeheader()
                writer.writerow(entry)

    def mousePressEvent(self, event):
        if event.source() == Qt.MouseEventNotSynthesized and event.button() == Qt.LeftButton:
            self.log_event("Touch Down", event.pos())

    def mouseReleaseEvent(self, event):
        if event.source() == Qt.MouseEventNotSynthesized and event.button() == Qt.LeftButton:
            self.log_event("Touch Up", event.pos())

    def mouseMoveEvent(self, event):
        if event.source() == Qt.MouseEventNotSynthesized and event.buttons() & Qt.LeftButton:
            self.log_event("Touch Move", event.pos())

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Touchscreen Event Logger")
    parser.add_argument("-o", "--output", default="touch_events.txt",
                        help="Output log file (default: touch_events.txt)")
    parser.add_argument("-f", "--format", choices=["text", "json", "csv"], default="text",
                        help="Log file format: text, json, or csv (default: text)")
    args = parser.parse_args()

    print(f"|*| Touchscreen capturer started. Logging to {args.output} in {args.format.upper()} format.")
    app = QApplication(sys.argv)
    w = TouchWidget(logfile=args.output, log_format=args.format)
    w.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
