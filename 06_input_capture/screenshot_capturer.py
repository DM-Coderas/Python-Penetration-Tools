import pyautogui
import argparse
import os
import datetime
import subprocess
import platform
import pyperclip
from PIL import Image

# function that uses pyautogui to create a screenshot of the victim’s screen
def take_screenshot(output_path, region=None, clip=False, silent=False):
    img = pyautogui.screenshot(region=region)

    img.save(output_path)

    if clip:
        try:
            img.convert("RGB").save("temp_clip.png")
            if platform.system() == "Windows":
                from io import BytesIO
                import win32clipboard
                output = BytesIO()
                img.convert("RGB").save(output, "BMP")
                data = output.getvalue()[14:] t
                output.close()
                win32clipboard.OpenClipboard()
                win32clipboard.EmptyClipboard()
                win32clipboard.SetClipboardData(win32clipboard.CF_DIB, data)
                win32clipboard.CloseClipboard()
            else:
                print("|!| Clipboard copy not supported on this OS without additional tools.")
        except Exception as e:
            print(f"|!| Failed to copy to clipboard: {e}")
    
    if not silent:
        print(f"|+| Screenshot saved to {output_path}")

# function to automatically open the screenshot after saving it
def open_image(filepath):
    try:
        if platform.system() == "Darwin":  
            subprocess.call(["open", filepath])
        elif platform.system() == "Windows":
            os.startfile(filepath)
        else:  
            subprocess.call(["xdg-open", filepath])
    except Exception as e:
        print(f"|!| Failed to open image: {e}")

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Python Screenshot Capturer with CLI Options")
    parser.add_argument("-o", "--output", default=None,
                        help="Output file name (default: auto timestamped .png)")
    parser.add_argument("-r", "--region", nargs=4, type=int, metavar=('LEFT', 'TOP', 'WIDTH', 'HEIGHT'),
                        help="Region to capture: left top width height (default: full screen)")
    parser.add_argument("--clip", action="store_true", help="Copy screenshot to clipboard")
    parser.add_argument("--open", action="store_true", help="Open screenshot after saving")
    parser.add_argument("--silent", action="store_true", help="Suppress output messages")

    args = parser.parse_args()

    if args.output:
        output_file = args.output
    else:
        dt = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"screenshot_{dt}.png"

    if not output_file.lower().endswith(('.png', '.jpg', '.jpeg', '.bmp')):
        output_file += ".png"

    region = tuple(args.region) if args.region else None

    take_screenshot(output_file, region, clip=args.clip, silent=args.silent)

    if args.open:
        open_image(output_file)

if __name__ == "__main__":
    main()
