import cv2
import argparse
import datetime
import time
import os

# function that uses video capture to capture snapshots
def capture_snapshot(device=0, output=None, resolution=None, count=1, interval=0, preview=False, img_format="png"):
    cap = cv2.VideoCapture(device)
    if not cap.isOpened():
        print(f"|!| Could not open webcam (device={device})")
        return

    if resolution:
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, resolution[0])
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, resolution[1])

    for i in range(count):
        ret, frame = cap.read()
        if not ret:
            print("|!| Failed to capture image")
            break

        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if output:
            filename = output
            if count > 1:  
                name, ext = os.path.splitext(output)
                filename = f"{name}_{i+1}{ext}"
        else:
            filename = f"snapshot_{ts}.{img_format}"

        cv2.imwrite(filename, frame)
        print(f"|+| Snapshot saved as {filename}")

        if preview:
            cv2.imshow("Snapshot Preview", frame)
            if cv2.waitKey(500) & 0xFF == ord('q'):
                break

        if i < count - 1:
            time.sleep(interval)

    cap.release()
    if preview:
        cv2.destroyAllWindows()

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Python Webcam Snapshot Tool (Enhanced)")
    parser.add_argument("-d", "--device", type=int, default=0, help="Webcam device index (default: 0)")
    parser.add_argument("-o", "--output", default=None, help="Output filename (default: timestamped)")
    parser.add_argument("-r", "--resolution", nargs=2, type=int, metavar=("WIDTH", "HEIGHT"), help="Set resolution")
    parser.add_argument("-n", "--count", type=int, default=1, help="Number of snapshots to take")
    parser.add_argument("-i", "--interval", type=float, default=0, help="Interval between snapshots in seconds")
    parser.add_argument("-p", "--preview", action="store_true", help="Show preview window")
    parser.add_argument("-f", "--format", choices=["png", "jpg"], default="png", help="Image format (default: png)")

    args = parser.parse_args()
    capture_snapshot(
        device=args.device,
        output=args.output,
        resolution=args.resolution,
        count=args.count,
        interval=args.interval,
        preview=args.preview,
        img_format=args.format
    )

if __name__ == "__main__":
    main()
