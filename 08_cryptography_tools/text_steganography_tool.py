import argparse
import zlib
import base64

# zero width chars
ZWSP = '\u200B'  # 0
ZWNJ = '\u200C'  # 1
ZWDJ = '\u200D'  # optional padding/noise

# functions that serve as helpers
def to_bits(data: bytes):
    return ''.join(format(byte, '08b') for byte in data)

def from_bits(bits: str):
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))

def encode_zws(secret: bytes, cover: str, compress=False, b64=False):
    if compress:
        secret = zlib.compress(secret)
    if b64:
        secret = base64.b64encode(secret)

    bits = to_bits(secret)
    steg = ''.join(ZWSP if b == '0' else ZWNJ for b in bits)
    return cover + steg

# function that uses zlib to do the process of decoding zws and return data
def decode_zws(steg: str, decompress=False, b64=False):
    bits = ''.join('0' if c == ZWSP else '1' for c in steg if c in {ZWSP, ZWNJ})
    if not bits:
        return b"[No hidden data found]"

    data = from_bits(bits)

    if b64:
        try:
            data = base64.b64decode(data)
        except Exception:
            return b"[Invalid base64 hidden data]"

    if decompress:
        try:
            data = zlib.decompress(data)
        except Exception:
            return b"[Invalid compressed data]"

    return data

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Zero-width Steganography Tool")
    parser.add_argument("mode", choices=["hide", "reveal"], help="Mode: hide or reveal")
    parser.add_argument("-m", "--message", help="Secret message to hide (string)")
    parser.add_argument("-c", "--cover", help="Cover text (for hide mode)")
    parser.add_argument("-s", "--stegtext", help="Text with hidden data (for reveal mode)")
    parser.add_argument("--infile", help="Read secret message from file (binary safe)")
    parser.add_argument("--outfile", help="Write output (steg text or revealed secret) to file")
    parser.add_argument("--compress", action="store_true", help="Compress secret before hiding")
    parser.add_argument("--b64", action="store_true", help="Base64 encode secret (useful for binary)")
    args = parser.parse_args()

    if args.mode == "hide":
        if not args.cover:
            parser.error("Hiding requires --cover text")

        if args.infile:
            with open(args.infile, "rb") as f:
                secret = f.read()
        elif args.message:
            secret = args.message.encode()
        else:
            parser.error("Hiding requires --message or --infile")

        steg = encode_zws(secret, args.cover, compress=args.compress, b64=args.b64)

        if args.outfile:
            with open(args.outfile, "w", encoding="utf-8") as f:
                f.write(steg)
            print(f"|+| Steg text written to {args.outfile}")
        else:
            print("\n|*| Steganographic text:\n")
            print(steg)

    elif args.mode == "reveal":
        if not args.stegtext and not args.infile:
            parser.error("Reveal requires --stegtext or --infile")

        if args.infile:
            with open(args.infile, "r", encoding="utf-8") as f:
                stegtext = f.read()
        else:
            stegtext = args.stegtext

        secret = decode_zws(stegtext, decompress=args.compress, b64=args.b64)

        if args.outfile:
            with open(args.outfile, "wb") as f:
                f.write(secret)
            print(f"|+| Hidden message written to {args.outfile}")
        else:
            try:
                print("\n|*| Revealed hidden message:\n")
                print(secret.decode())
            except UnicodeDecodeError:
                print("\n|*| Revealed hidden data (binary):\n")
                print(secret)

if __name__ == "__main__":
    main()
