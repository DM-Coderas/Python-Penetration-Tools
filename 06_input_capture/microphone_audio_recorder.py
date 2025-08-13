import sounddevice as sd
from scipy.io.wavfile import write
import argparse
import datetime
import numpy as np
import os
import sys
import soundfile as sf  # pip install soundfile

# function that queries through potential audio input devices
def list_devices():
    print("|*| Available audio input devices:")
    devices = sd.query_devices()
    for idx, dev in enumerate(devices):
        if dev['max_input_channels'] > 0:
            print(f"{idx}: {dev['name']} ({dev['max_input_channels']} channels)")

# function that cleans up the audio for use
def normalize_audio(audio):
    max_val = np.max(np.abs(audio))
    if max_val == 0:
        return audio
    return (audio / max_val * np.iinfo(audio.dtype).max).astype(audio.dtype)

# function that does the process of recording using sd
def record_audio(duration, filename, samplerate=44100, channels=1, device=None, normalize=False, file_format="wav"):
    print(f"|*| Recording for {duration} seconds...")
    audio = sd.rec(int(duration * samplerate), samplerate=samplerate, channels=channels, dtype='int16', device=device)
    sd.wait()

    if normalize:
        audio = normalize_audio(audio)

    if file_format.lower() == "wav":
        write(filename, samplerate, audio)
    elif file_format.lower() == "flac":
        sf.write(filename, audio, samplerate, format='FLAC')
    else:
        print(f"|!| Unsupported format: {file_format}")
        return

    print(f"|+| Saved recording to {filename}")

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Python Microphone Audio Recorder (Enhanced)")
    parser.add_argument("-d", "--duration", type=int, default=10, help="Duration to record (seconds)")
    parser.add_argument("-o", "--output", default=None, help="Output filename (default: timestamped)")
    parser.add_argument("-r", "--rate", type=int, default=44100, help="Sample rate (Hz)")
    parser.add_argument("-c", "--channels", type=int, default=1, help="Number of input channels (1=mono, 2=stereo)")
    parser.add_argument("--device", type=int, help="Device index for microphone")
    parser.add_argument("-l", "--list", action="store_true", help="List available input devices and exit")
    parser.add_argument("-n", "--takes", type=int, default=1, help="Number of recordings to make")
    parser.add_argument("-i", "--interval", type=float, default=0, help="Pause between takes (seconds)")
    parser.add_argument("--normalize", action="store_true", help="Normalize audio before saving")
    parser.add_argument("-f", "--format", choices=["wav", "flac"], default="wav", help="Output file format")

    args = parser.parse_args()

    if args.list:
        list_devices()
        sys.exit()

    for take in range(args.takes):
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        ext = args.format
        filename = args.output or f"mic_recording_{timestamp}.{ext}"

        if args.takes > 1:
            name, extn = os.path.splitext(filename)
            filename = f"{name}_{take+1}{extn}"

        record_audio(
            duration=args.duration,
            filename=filename,
            samplerate=args.rate,
            channels=args.channels,
            device=args.device,
            normalize=args.normalize,
            file_format=args.format
        )

        if take < args.takes - 1:
            time.sleep(args.interval)

if __name__ == "__main__":
    main()
