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
    print("Most frequent ciphertext letters:", cipher_top)
    print("Most frequent English letters:   ", [p.lower() for p in plain_top])

    failed = []
    for i in range(len(plain_top)):
        for j in range(i + 1, len(plain_top)):
            p1, p2 = plain_top[i], plain_top[j]
            for c1 in cipher_top:
                for c2 in cipher_top:
                    if c1 == c2:
                        continue
                    x1, y1 = ALPHABET.index(p1), ALPHABET.index(c1)
                    x2, y2 = ALPHABET.index(p2), ALPHABET.index(c2)
                    hyp = f"{c1}={p1.lower()}, {c2}={p2.lower()}"
                    # a*(x1-x2) = (y1-y2) mod 26, then b = y1 - a*x1 mod 26
                    keys = solve_system(x1, y1, x2, y2)
                    if not keys:
                        print(f"{hyp}: a*{(x1 - x2) % 26} = {(y1 - y2) % 26} (mod 26) -> no solution")
                        continue
                    for a, b in keys:
                        if gcd(a, 26) != 1:
                            print(f"{hyp}: (a, b) = ({a}, {b}) -> rejected, gcd({a}, 26) = {gcd(a, 26)}")
                            failed.append((a, b, "gcd(a, 26) != 1"))
                            continue
                        plaintext = decrypt(ciphertext, a, b)
                        M = sum(P_ENG[c.upper()] for c in plaintext) / len(plaintext)
                        print(f"{hyp}: (a, b) = ({a}, {b}) -> {plaintext[:40]}...  M = {M:.3f}")
                        if M >= threshold:
                            print("\nFailed keys:", ", ".join(f"({fa}, {fb}) [{r}]" for fa, fb, r in failed) or "none")
                            print(f"Chosen key: (a, b) = ({a}, {b}), a^-1 = {pow(a, -1, 26)}, "
                                  f"M = {M:.3f} >= {threshold} (English text ~0.065, gibberish ~0.038)")
                            return a, b, plaintext
                        failed.append((a, b, f"M = {M:.3f}"))
    print("\nFailed keys:", ", ".join(f"({fa}, {fb}) [{r}]" for fa, fb, r in failed) or "none")
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
        print(f"Key: a = {a}, b = {b}")
        print(f"Plaintext: {plaintext}")
    else:
        print("Key not found.")