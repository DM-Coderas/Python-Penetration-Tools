import argparse
import base64

# function that encrypts a text using caesar cipher
def caesar_encrypt(text, key):
    result = ""
    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            result += chr((ord(char) - offset + key) % 26 + offset)
        else:
            result += char
    return result

# function that creates a caesar key
def caesar_decrypt(text, key):
    return caesar_encrypt(text, -key)

# function that bruteforces a caesar cipher
def caesar_bruteforce(text):
    results = {}
    for key in range(26):
        results[key] = caesar_decrypt(text, key)
    return results

# function that encrypts a text using a vigenere cipher
def vigenere_encrypt(text, key):
    key = key.upper()
    result, j = "", 0
    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            idx = (ord(char.upper()) - 65 + ord(key[j % len(key)]) - 65) % 26
            char_enc = chr(idx + offset)
            result += char_enc if char.isupper() else char_enc.lower()
            j += 1
        else:
            result += char
    return result

# function that creates a key to the vigenere cipher
def vigenere_decrypt(text, key):
    key = key.upper()
    result, j = "", 0
    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            idx = (ord(char.upper()) - 65 - (ord(key[j % len(key)]) - 65)) % 26
            char_dec = chr(idx + offset)
            result += char_dec if char.isupper() else char_dec.lower()
            j += 1
        else:
            result += char
    return result

# dictionary of bacon cipher necessities
BACON_DICT = {
    "A":"AAAAA", "B":"AAAAB", "C":"AAABA", "D":"AAABB", "E":"AABAA",
    "F":"AABAB", "G":"AABBA", "H":"AABBB", "I":"ABAAA", "J":"ABAAB",
    "K":"ABABA", "L":"ABABB", "M":"ABBAA", "N":"ABBAB", "O":"ABBBA",
    "P":"ABBBB", "Q":"BAAAA", "R":"BAAAB", "S":"BAABA", "T":"BAABB",
    "U":"BABAA", "V":"BABAB", "W":"BABBA", "X":"BABBB", "Y":"BBAAA", "Z":"BBAAB"
}
REVERSE_BACON = {v:k for k,v in BACON_DICT.items()}

# function that encrypts a text using a bacon cipher
def bacon_encrypt(text):
    result = []
    for char in text.upper():
        if char in BACON_DICT:
            result.append(BACON_DICT[char])
    return ' '.join(result)

# function that creates a key for a bacon cipher
def bacon_decrypt(code):
    words = code.upper().split()
    result = ''
    for w in words:
        result += REVERSE_BACON.get(w, '?')
    return result

# function that creates an atbash cipher
def atbash(text):
    result = ""
    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            result += chr(offset + (25 - (ord(char) - offset)))
        else:
            result += char
    return result

# function that creates a rot13 cipher
def rot13(text):
    return caesar_encrypt(text, 13)

# functions that are a base64 encoder and decoder
def b64_encrypt(text):
    return base64.b64encode(text.encode()).decode()

def b64_decrypt(text):
    return base64.b64decode(text).decode(errors="ignore")

# arg parser for cli customizability
def main():
    parser = argparse.ArgumentParser(description="General Cipher Tool")
    parser.add_argument("cipher", choices=["caesar", "vigenere", "bacon", "atbash", "rot13", "base64"], help="Cipher method")
    parser.add_argument("mode", choices=["encrypt", "decrypt", "bruteforce"], help="Mode (encrypt/decrypt/bruteforce)")
    parser.add_argument("-t", "--text", help="Text to process")
    parser.add_argument("-k", "--key", help="Key (for Caesar/Vigenère)")
    parser.add_argument("--infile", help="Read input text from file")
    parser.add_argument("--outfile", help="Write result to file")
    args = parser.parse_args()

    if args.infile:
        with open(args.infile, "r", encoding="utf-8") as f:
            text = f.read()
    else:
        if not args.text:
            parser.error("Must provide --text or --infile")
        text = args.text

    res = ""
    if args.cipher == "caesar":
        if args.mode == "bruteforce":
            results = caesar_bruteforce(text)
            res = "\n".join([f"[{k}] {v}" for k,v in results.items()])
        else:
            if not args.key: parser.error("Caesar cipher requires --key (integer shift)")
            key = int(args.key)
            res = caesar_encrypt(text, key) if args.mode == "encrypt" else caesar_decrypt(text, key)

    elif args.cipher == "vigenere":
        if not args.key: parser.error("Vigenère cipher requires --key (string)")
        res = vigenere_encrypt(text, args.key) if args.mode == "encrypt" else vigenere_decrypt(text, args.key)

    elif args.cipher == "bacon":
        res = bacon_encrypt(text) if args.mode == "encrypt" else bacon_decrypt(text)

    elif args.cipher == "atbash":
        res = atbash(text)

    elif args.cipher == "rot13":
        res = rot13(text)  # ROT13 is symmetric

    elif args.cipher == "base64":
        res = b64_encrypt(text) if args.mode == "encrypt" else b64_decrypt(text)

    if args.outfile:
        with open(args.outfile, "w", encoding="utf-8") as f:
            f.write(res)
        print(f"|+| Result saved to {args.outfile}")
    else:
        print(f"\n|*| Result:\n{res}\n")

if __name__ == "__main__":
    main()
