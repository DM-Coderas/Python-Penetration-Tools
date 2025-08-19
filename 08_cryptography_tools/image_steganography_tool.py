from PIL import Image
import argparse, zlib, base64, os

# functions that serve as helpers for the tool
def text_to_bin(data: bytes):
    return ''.join(format(byte, '08b') for byte in data)

def bin_to_bytes(binstr: str):
    return bytes(int(binstr[i:i+8], 2) for i in range(0, len(binstr), 8))

def xor_data(data: bytes, key: str):
    if not key:
        return data
    key_bytes = key.encode()
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])

# function that encodes image using zlib and secrets
def encode_image(input_image, output_image, secret: bytes, compress=False, b64=False, password=None):
    img = Image.open(input_image)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    if compress:
        secret = zlib.compress(secret)
    if b64:
        secret = base64.b64encode(secret)
    if password:
        secret = xor_data(secret, password)

    data = text_to_bin(secret) + '00000000'  # Null terminator
    encoded = img.copy()
    pixels = list(encoded.getdata())

    capacity = len(pixels) * 3
    if len(data) > capacity:
        raise ValueError(f"Secret too large! Needs {len(data)} bits but image holds {capacity} bits.")

    data_idx = 0
    new_pixels = []
    for pixel in pixels:
        r, g, b = pixel
        for i in range(3):
            if data_idx < len(data):
                channel_bin = list(format([r, g, b][i], '08b'))
                channel_bin[-1] = data[data_idx]
                val = int(''.join(channel_bin), 2)
                if i == 0:
                    r = val
                elif i == 1:
                    g = val
                else:
                    b = val
                data_idx += 1
        new_pixels.append((r, g, b))

    encoded.putdata(new_pixels)
    encoded.save(output_image)
    print(f"|+| Secret embedded in '{output_image}' (used {len(data)} / {capacity} bits).")

# function that decodes the image, aka creates the secret/key needed to decode the image
def decode_image(stego_image, decompress=False, b64=False, password=None):
    img = Image.open(stego_image)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    pixels = list(img.getdata())
    bits = ""
    for pixel in pixels:
        for val in pixel[:3]:
            bits += format(val, '08b')[-1]

    # Stop at terminator
    bytes_out = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if byte == "00000000":
            break
        bytes_out.append(byte)
    data = bin_to_bytes(''.join(bytes_out))

    if password:
        data = xor_data(data, password)
    if b64:
        data = base64.b64decode(data)
    if decompress:
        data = zlib.decompress(data)

    return data

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="Image Steganography Tool (Enhanced LSB)")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    # Hide mode
    enc = subparsers.add_parser("hide", help="Hide message or file in image")
    enc.add_argument("-i", "--input", required=True, help="Input image")
    enc.add_argument("-o", "--output", required=True, help="Output stego image")
    enc.add_argument("-m", "--message", help="Secret text message")
    enc.add_argument("--infile", help="Secret file to embed")
    enc.add_argument("--compress", action="store_true", help="Compress secret before hiding")
    enc.add_argument("--b64", action="store_true", help="Base64 encode secret")
    enc.add_argument("--password", help="Password (XOR obfuscation)")

    dec = subparsers.add_parser("reveal", help="Extract message or file from image")
    dec.add_argument("-i", "--input", required=True, help="Stego image")
    dec.add_argument("--outfile", help="Write extracted data to file")
    dec.add_argument("--compress", action="store_true", help="Decompress after extraction")
    dec.add_argument("--b64", action="store_true", help="Base64 decode after extraction")
    dec.add_argument("--password", help="Password used during hiding")

    args = parser.parse_args()

    if args.mode == "hide":
        if not args.message and not args.infile:
            parser.error("Need --message or --infile to hide data")

        if args.infile:
            with open(args.infile, "rb") as f:
                secret = f.read()
        else:
            secret = args.message.encode()

        encode_image(args.input, args.output, secret, compress=args.compress, b64=args.b64, password=args.password)

    elif args.mode == "reveal":
        secret = decode_image(args.input, decompress=args.compress, b64=args.b64, password=args.password)

        if args.outfile:
            with open(args.outfile, "wb") as f:
                f.write(secret)
            print(f"|+| Extracted secret written to {args.outfile}")
        else:
            try:
                print("|+| Hidden message:\n" + secret.decode())
            except UnicodeDecodeError:
                print("|+| Extracted binary data (not text). Use --outfile to save.")

if __name__ == "__main__":
    main()
