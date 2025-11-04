---
title: osu!gaming CTF 2025 - Crypto
published: 2025-10-31
description: 'Writeup for all solved Crypto challenge in osu!gaming CTF 2025 by #MogamiShizuka'
image: './osuctf2025x2.jpg'
tags: [Cryptography]
category: 'Writeup'
draft: false 
lang: 'en'
---

# rot727

> `aeg{at_imuf_nussqd_zgynqd_paqezf_yqmz_yadq_eqogdq}`

As the title mentioned, we can see that ROT727 is almost similar to ROT13. So we can put that in some decoder to brute-force the ROT, and the flag is encrypted in ROT14.

Flag: :spoiler[osu{oh_wait_bigger_number_doesnt_mean_more_secure}]

# beyond-wood

```py  {7, 13-14} title="script.py"
from PIL import Image
import random

FLAG = Image.open("flag.png")
width, height = FLAG.size

key = [random.randrange(0, 256) for _ in range(width+height+3)]

out = FLAG.copy()
for i in range(width):
    for j in range(height):
        pixel = FLAG.getpixel((i, j))
        pixel = tuple(x ^ k for x, k in zip(pixel, key))
        newi, newj = (2134266 + i * 727) % width, (4501511 + j * 727) % height 
        out.putpixel((newi, newj), pixel)

out.save("output.png")
```

`key` is built with random bytes of length `width + height + 3`. For each `(i, j)` it XORS the pixel channels with `key` starting from `key[0]`. Meaning that XOR key takes the first 3 bytes of `key`, and it's constant per channel (one byte for `R`, one byte for `G` and one byte for `B`).

Then it write that XORed pixel to a new permuted location.

```py
newi = (2134266 + i * 727) % width
newj = (4501511 + j * 727) % height
```

This is a linear (affine) permutation on each axis, so it's reversible.

To solve this challenge, we first invert the permutation, by using the formula, and place it at the original pixel.

```py
inv_i[(2134266 + i * 727) % width] = i
inv_j[(4501511 + j * 727) % height] = j
```

Then recover the 3 key bytes. Because XOR key is global, so that we can use some frequency assumptions such as black `(0, 0, 0)` or white `(255, 255, 255)`, to XOR the unshuffled image with the recovered key to get the original.

```py title="decode.py"
from PIL import Image
from collections import Counter

def build_inverse_map(length, offset, mult):
    inv = [None] * length
    for i in range(length):
        new = (offset + i * mult) % length
        inv[new] = i
    return inv

def unshuffle(img):
    width, height = img.size
    inv_i = build_inverse_map(width, 2134266, 727)
    inv_j = build_inverse_map(height, 4501511, 727)
    out = Image.new(img.mode, (width, height))
    src = img.load()
    dst = out.load()
    for x in range(width):
        for y in range(height):
            dst[inv_i[x], inv_j[y]] = src[x, y]
    return out

def xor_pixel(pixel, key):
    return tuple(p ^ k for p, k in zip(pixel, key))

def apply_key(img, key):
    width, height = img.size
    out = Image.new(img.mode, (width, height))
    src = img.load()
    dst = out.load()
    for x in range(width):
        for y in range(height):
            dst[x, y] = xor_pixel(src[x, y], key)
    return out

def main():
    img = Image.open("output.png").convert("RGB")
    width, height = img.size
    unshuffled = unshuffle(img)

    for bg in [(0,0,0), (255,255,255)]:
        key = tuple(mc[i] ^ bg[i] for i in range(3))
        print(f"Recovering {bg}, key = {key}")
        recovered = apply_key(unshuffled, key)
        recovered.save(f"recovered_{bg[0]}_{bg[1]}_{bg[2]}.png")

if __name__ == "__main__":
    main()
```

Flag: :spoiler[osu{h1_05u_d351gn_t34m}]

# xnor-xnor-xnor

```py title="script.py" {4-12, 29}
import os
flag = open("flag.txt", "rb").read()

def xnor_gate(a, b):
    if a == 0 and b == 0:
        return 1
    elif a == 0 and b == 1:
        return 0
    elif a == 1 and b == 0:
        return 0
    else:
        return 1

def str_to_bits(s):
    bits = []
    for x in s:
        bits += [(x >> i) & 1 for i in range(8)][::-1]
    return bits

def bits_to_str(bits):
    return bytes([sum(x * 2 ** j for j, x in enumerate(bits[i:i+8][::-1])) for i in range(0, len(bits), 8)])

def xnor(pt_bits, key_bits):
    return [xnor_gate(pt_bit, key_bit) for pt_bit, key_bit in zip(pt_bits, key_bits)]

key = os.urandom(4) * (1 + len(flag) // 4)
key_bits = str_to_bits(key)
flag_bits = str_to_bits(flag)
enc_flag = xnor(xnor(xnor(flag_bits, key_bits), key_bits), key_bits)

print(bits_to_str(enc_flag).hex())
# 7e5fa0f2731fb9b9671fb1d62254b6e5645fe4ff2273b8f04e4ee6e5215ae6ed6c
```

We have `XNOR(a, b) = 1 - (a XOR b)`, so if we have `t = XNOR(XNOR(XNOR(a, k), k), k)`, meaning that if `k = 1` then `t = a`, and `k = 0` then `t = NOT a`. Therefore the whole triple-XNOR is just a bitwise XOR with the bitwise complement of the key. In bytes:

```py
mask_byte = 0xff - key_byte
cipher = plaintext XOR mask
plaintext = cipher XOR mask
```

Because `key` is `os.urandom(4)` repeated, `mask` repeats every 4 bytes. So if we know the what the plaintext is, it's reversible.

We know the flag format is `osu{`, it's `0x6f 0x73 0x75 0x7b`. Calculate the first 4 mask bytes:

```py
mask0 = 0x7e XOR 0x6f = 0x11
mask1 = 0x5f XOR 0x73 = 0x2c
mask2 = 0xa0 XOR 0x75 = 0xd5
mask3 = 0xf2 XOR 0x7b = 0x89
```

We have the 4-byte repeated `mask` as `0x11 0x2c 0xd5 0x89`, so the `key` is `0xff - mask_byte`, meaning `0xee 0xd3 0x2a 0x76`. XOR it with the cipher text, and we have the flag.

```py title="decode.py"
c = bytes.fromhex("7e5fa0f2731fb9b9671fb1d62254b6e5645fe4ff2273b8f04e4ee6e5215ae6ed6c")
known = b"osu{"
mask = [c[i] ^ known[i] for i in range(4)]
t = bytes(c[i] ^ mask[i % 4] for i in range(len(c)))
print(t.decode())
```

Flag: :spoiler[osu{b3l0v3d_3xclus1v3_my_b3l0v3d}]

# pls-nominate

```py title="script.py" {5, 6, 9}
from Crypto.Util.number import * 
FLAG = open("flag.txt", "rb").read() 
message = bytes_to_long( b"hello there can you pls nominate my map https://osu.ppy.sh/beatmapsets/2436259 :steamhappy: i can bribe you with a flag if you do: " + FLAG ) 

ns = [getPrime(727) * getPrime(727) for _ in range(5)] 
e = 5 
print(len(FLAG)) 
print(ns) 
print([pow(message, e, n) for n in ns])
```

This challenge is a simple Hastad-style broadcast RSA with `e = 5`. So we just need to combine 5 ciphertexts with the Chinese Remainder Theorem and search for the small multiple `k` so that `M_e + k * N` is a perfect 5th power.

```py title="decode.py"
ns = [...]
ciphers = [...]
e = 5

def prod(a):
    p = 1
    for x in a: p *= x
    return p

def ith_root(x, n):
    if x < 2: return x, True
    lo, hi = 0, 1 << ((x.bit_length() + n - 1) // n + 1)
    while lo + 1 < hi:
        m = (lo + hi) // 2
        if m ** n == x: return m, True
        if m ** n < x: lo = m
        else: hi = m
    return (lo, lo ** n == x)

# CRT
N = prod(ns)
Me = 0
for n, c in zip(ns, ciphers):
    Ni = N // n
    inv = pow(Ni, -1, n)
    Me += c * Ni * inv
Me %= N

# Search small k
r, exact = ith_root(Me, e)
if not exact:
    for k in range(0, 500000):
        r, exact = ith_root(Me + k*N, e)
        if exact:
            break

m = r
b = m.to_bytes((m.bit_length() + 7) // 8, 'big')
i = b.find(b"osu{")
print(b[i:i + 200].decode() if i != -1 else b[:200])
```

Flag: :spoiler[osu{pr3tty_pl3453_w1th_4_ch3rry_0n_t0p!?:pleading:}]

# linear-feedback

```py title="script.py" {11-14, 22-25, 27, 31-32}
from secrets import randbits 
from math import floor 
from hashlib import sha256 

class LFSR: 
    def __init__(self, key, taps, format): 
        self.key = key 
        self.taps = taps 
        self.state = list(map(int, list(format.format(key)))) 
        
    def _clock(self): 
        ob = self.state[0] 
        self.state = self.state[1:] + [sum([self.state[t] for t in self.taps]) % 2] 
        return ob 
        
def xnor_gate(a, b): 
    if a == 0 and b == 0: return 1 
    elif a == 0 and b == 1: return 0 
    elif a == 1 and b == 0: return 0 
    else: return 1 
        
key1 = randbits(21) 
key2 = randbits(29) 
L1 = LFSR(key1, [2, 4, 5, 1, 7, 9, 8], "{:021b}") 
L2 = LFSR(key2, [5, 3, 5, 5, 9, 9, 7], "{:029b}") 

bits = [xnor_gate(L1._clock(), L2._clock()) for _ in range(floor(72.7))] 
print(bits) 

FLAG = open("flag.txt", "rb").read() 
keystream = sha256((str(key1) + str(key2)).encode()).digest() * 2 
print(bytes([b1 ^ b2 for b1, b2 in zip(FLAG, keystream)]).hex())
```

This is the challenge where turning the LFSRs into a linear system over GF(2) and solving the initial register bits.

- The two LFSRs are linear over GF(2), where each output bit at `t` is a linear function of the initial state bits.
- The program prints `bits = xnor(L1._clock(), L2._clock())`. Since `xnor(a, b) = 1` when `a == b`, we have: `L1_t XOR L2_t = 1 ^ bits_t`.
- Build coefficient vectors for each LFSR output as linear combinations of their initial state bits, for every observed time step. That gives a linear system with 50 unknowns (21 + 29 initial bits) and 72 equations (observed outputs).
- Solve the GF(2) linear system (Gaussian elimination). The system had 2 free variables; try 4 assignments, check which produces ASCII flag when decrypting the provided ciphertext.

Based on these steps, we can have the recovered values as:
```py
key1 = 776071    #binary 10111101101001000111 as a 21-bit string
key2 = 340835109 #binary 0101000100010010101100010110101 as a 29-bit string
```

Flag: :spoiler[osu{th1s_hr1_i5_th3_m0st_fun_m4p_3v3r_1n_0wc}]

# ssss

```py title="script.py" {12-15, 17-18}
#!/usr/local/bin/python3 
from Crypto.Util.number import * 
import random 

p = 2**255 - 19 
k = 15 
SECRET = random.randrange(0, p) 

def lcg(x, a, b, p): 
    return (a * x + b) % p 
    
a = random.randrange(0, p) 
b = random.randrange(0, p) 
poly = [SECRET] 
while len(poly) != k: poly.append(lcg(poly[-1], a, b, p)) 

def evaluate_poly(f, x): 
    return sum(c * pow(x, i, p) for i, c in enumerate(f)) % p 
    
print("welcome to ssss", flush=True) 
for _ in range(k - 1): 
    x = int(input()) 
    assert 0 < x < p, "no cheating!" 
    print(evaluate_poly(poly, x), flush=True) 
    
if int(input("secret? ")) == SECRET: 
    FLAG = open("flag.txt").read() 
    print(FLAG, flush=True)
```

1. Server returns 
$$y = \sum_{i=0}^{k-1} c_i x^i$$ with $$c_{i+1} = ac_i + b, c_0 = SECRET$$.
2. Because $$c_i = C_1a^i + C_2$$, then $$y(x) = C_1S(x, a) + C_2U(x)$$ 

where $$S(x, a) = \frac{1 - (ax)^k}{1 - ax}$$ and $$U(x) = \frac{1 - x^k}{1 - x}$$

3. Send 3 values `x` (e.x. 2, 3, 5), receive 3 values `y` and calculate 3 nonlinear system for $$a, C_1, C_2$$. 
4. Eliminate $$C_1, C_2$$ to get one polynomial equation in $$a$$, solve it modulo $$p$$, then recover $$C_1, C_2$$  by linear solve.
5. Compute $$SECRET = C_1 + C_2 \pmod{b}$$, send this `SECRET` to the server to receive the flag.

```py title="decode.py"
import socket, re, sys, time
from sympy import symbols, together, expand, Poly, factor_list, Integer
from Crypto.Util.number import inverse, long_to_bytes

HOST = "ssss.challs.sekai.team"
PORT = 1337

p = 2**255 - 19
k = 15
xs_to_send = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43]  # length 14

def recv_line(sock, timeout=10):
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            ch = sock.recv(1)
            if not ch:
                break
            data += ch
            if ch == b"\n":
                break
    except socket.timeout:
        pass
    return data

def extract_last_int_from_bytes(b: bytes):
    m = re.search(rb"(-?\d+)\s*$", b.strip())
    if not m:
        return None
    return int(m.group(1))

def query_server_and_get_results(host, port, xs):
    s = socket.create_connection((host, port))
    s.settimeout(5)
    for _ in range(4):
        line = recv_line(s, timeout=0.5)
        if not line:
            break

    outputs = []
    for x in xs:
        # send x
        s.sendall(f"{x}\n".encode())
        val = None
        start = time.time()
        while True:
            line = recv_line(s, timeout=5)
            if not line:
                break
            val = extract_last_int_from_bytes(line)
            if val is not None:
                break
            if time.time() - start > 8:
                break
        if val is None:
            remaining = line.decode(errors='ignore') if line else "<no data>"
            print(remaining)
            s.close()
            sys.exit(1)
        outputs.append((x, val))
    return s, outputs

def recover_secret_from_three_pairs(pairs):
    (x1, y1), (x2, y2), (x3, y3) = pairs
    a = symbols('a')
    def S_sym(x):
        return (1 - (a * Integer(x))**k) / (1 - a * Integer(x))
    def U_sym(x):
        xI = Integer(x)
        return (1 - xI**k) / (1 - xI)
    S1, S2, S3 = S_sym(x1), S_sym(x2), S_sym(x3)
    U1, U2, U3 = U_sym(x1), U_sym(x2), U_sym(x3)
    Y1, Y2, Y3 = map(Integer, [y1, y2, y3])
    expr = (Y1 * U2 - Y2 * U1) * S3 + (-Y1 * S2 + Y2 * S1) * U3 - Y3 * (S1 * U2 - S2 * U1)
    expr_s = together(expr)
    num, den = expr_s.as_numer_denom()
    poly_expr = expand(num)
    P = Poly(poly_expr, a)
    print("[*] Integer polynomial degree:", P.degree())
    coeffs_mod_p = [int(c % p) for c in P.all_coeffs()]
    Pp = Poly(coeffs_mod_p, a, modulus=p)
    print("[*] Degree over GF(p):", Pp.degree())
    print("[*] Factoring polynomial mod p (may take a moment)...")
    try:
        fact = factor_list(Pp.as_expr(), modulus=p)
        factors = fact[1]
    except Exception as e:
        print("[!] factor_list failed:", e)
        factors = []

    candidates = set()
    for fpol, mult in factors:
        fpoly = Poly(fpol, a, modulus=p)
        if fpoly.degree() == 1:
            coefs = fpoly.all_coeffs()
            Acoef, Bcoef = int(coefs[0]) % p, int(coefs[1]) % p
            root = (-Bcoef * inverse(Acoef, p)) % p
            candidates.add(root)

    if not candidates:
        print("[*] No linear factors found")
        for guess in range(0, 200000):
            if Pp.eval(guess) % p == 0:
                candidates.add(guess)
                print("[*] Found a by scanning:", guess)
                break

    if not candidates:
        raise RuntimeError("No candidate 'a' found.")

    def compute_S_num(x, a_val):
        ax = (a_val * x) % p
        if (1 - ax) % p == 0:
            return None
        num = (1 - pow(ax, k, p)) % p
        den = (1 - ax) % p
        return (num * inverse(den, p)) % p

    def compute_U_num(x):
        if (1 - x) % p == 0:
            return None
        num = (1 - pow(x, k, p)) % p
        den = (1 - x) % p
        return (num * inverse(den, p)) % p

    for a_cand in candidates:
        S1v = compute_S_num(x1, a_cand)
        S2v = compute_S_num(x2, a_cand)
        S3v = compute_S_num(x3, a_cand)
        U1v = compute_U_num(x1)
        U2v = compute_U_num(x2)
        U3v = compute_U_num(x3)
        if None in (S1v, S2v, S3v, U1v, U2v, U3v):
            continue
        det = (S1v * U2v - S2v * U1v) % p
        if det == 0:
            continue
        inv_det = inverse(det, p)
        C1 = ((Integer(y1) * U2v - Integer(y2) * U1v) * inv_det) % p
        C2 = ((-Integer(y1) * S2v + Integer(y2) * S1v) * inv_det) % p
        y3calc = (C1 * S3v + C2 * U3v) % p
        if y3calc == Integer(y3) % p:
            SECRET = int((C1 + C2) % p)
            return a_cand, SECRET
    raise RuntimeError("No candidate 'a' produced valid C1/C2.")

def send_secret_and_get_flag(sock, secret):
    sock.sendall(f"{secret}\n".encode())
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data.decode(errors='ignore')

def main():
    print("Connecting server")
    s, outputs = query_server_and_get_results(HOST, PORT, xs_to_send)
    print("Queried pairs:", outputs[:3], "... (total returned {})".format(len(outputs)))
    three = outputs[:3]
    try:
        a_val, secret = recover_secret_from_three_pairs(three)
    except Exception as e:
        print("Recovery failed:", e)
        s.close()
        sys.exit(1)

    print("Recovered a =", a_val)
    print("Recovered SECRET (int):", secret)
    try:
        print("SECRET (bytes):", long_to_bytes(secret))
    except Exception:
        pass

    print("Sending secret")
    flag_text = send_secret_and_get_flag(s, secret)
    s.close()
    print("---- SERVER OUTPUT ----")
    print(flag_text)
    print("-----------------------")

if __name__ == "__main__":
    main()
```

Flag: :spoiler[osu{0n3_hundr3d_p3rc3nt_4ccur4cy!}]