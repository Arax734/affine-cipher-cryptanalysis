import sys
from math import gcd

from histogram import plot_histogram

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

P_ENG = {'A': .082, 'B': .015, 'C': .028, 'D': .043, 'E': .127, 'F': .022,
         'G': .020, 'H': .061, 'I': .070, 'J': .002, 'K': .008, 'L': .040,
         'M': .024, 'N': .067, 'O': .075, 'P': .019, 'Q': .001, 'R': .060,
         'S': .063, 'T': .091, 'U': .028, 'V': .010, 'W': .023, 'X': .001,
         'Y': .020, 'Z': .001}

def encrypt(text, a, b):
    return "".join(ALPHABET[(a * ALPHABET.index(c) + b) % 26] for c in text.upper())

def decrypt(ciphertext, a, b):
    a_inv = pow(a, -1, 26)
    return "".join(ALPHABET[a_inv * (ALPHABET.index(c) - b) % 26] for c in ciphertext).lower()

def solve_system(x1, y1, x2, y2):
    dx, dy = (x1 - x2) % 26, (y1 - y2) % 26
    g = gcd(dx, 26)
    if dy % g:
        return []
    m = 26 // g
    a0 = (dy // g) * pow(dx // g, -1, m) % m
    return [(a, (y1 - a * x1) % 26) for a in range(a0, 26, m)]

def cryptanalysis(ciphertext, threshold=0.055):
    cipher_top = sorted(ALPHABET, key=lambda c: (-ciphertext.count(c), c))[:6]
    plain_top = sorted(ALPHABET, key=lambda c: -P_ENG[c])[:6]

    for i in range(len(plain_top)):
        for j in range(i + 1, len(plain_top)):
            for c1 in cipher_top:
                for c2 in cipher_top:
                    if c1 == c2:
                        continue
                    for a, b in solve_system(ALPHABET.index(plain_top[i]), ALPHABET.index(c1),
                                             ALPHABET.index(plain_top[j]), ALPHABET.index(c2)):
                        if gcd(a, 26) != 1:
                            continue
                        plaintext = decrypt(ciphertext, a, b)
                        M = sum(P_ENG[c.upper()] for c in plaintext) / len(plaintext)
                        if M >= threshold:
                            return a, b, plaintext
    return None

if sys.argv[1] == "encrypt":
    a, b = int(sys.argv[2]), int(sys.argv[3])
    if gcd(a, 26) != 1:
        print(f"Invalid key")
    else:
        print("Ciphertext:", encrypt(sys.argv[4], a, b))
elif sys.argv[1] == "decrypt":
    plot_histogram(sys.argv[2])
    result = cryptanalysis(sys.argv[2].upper())
    if result:
        a, b, plaintext = result
        print(f"Plaintext: {plaintext}")
    else:
        print("Key not found.")