"""
IS LAB MANUAL - copy-paste snippets for Labs 1-6      (pip install cryptography sympy numpy matplotlib)
Every lab is a section of functions.  Run this file to see all sections self-test:  python 4_lab_snippets.py
Or in your own file:  from 4_lab_snippets import *   (rename file to lab_snippets.py first) and call what you need.
"""
import os, time, json, random, hashlib, socket, threading, logging
from datetime import datetime, timedelta
import numpy as np
from sympy import Matrix, randprime, factorint, isprime
from cryptography.hazmat.primitives import hashes, serialization, padding as sympad
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES   # new versions
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES  # older versions


# ============================================================================
# LAB 1 : CLASSICAL CIPHERS   (plaintext = lowercase, ciphertext = UPPERCASE)
# ============================================================================
def clean(t):
    return "".join(c for c in t.lower() if c.isalpha())          # remove spaces/punctuation


def additive_enc(pt, k):  return "".join(chr((ord(c) - 97 + k) % 26 + 65) for c in clean(pt))
def additive_dec(ct, k):  return "".join(chr((ord(c) - 65 - k) % 26 + 97) for c in ct if c.isalpha())
def mult_enc(pt, k):      return "".join(chr(((ord(c) - 97) * k) % 26 + 65) for c in clean(pt))
def mult_dec(ct, k):
    ki = pow(k, -1, 26)                                           # multiplicative inverse mod 26
    return "".join(chr(((ord(c) - 65) * ki) % 26 + 97) for c in ct if c.isalpha())
def affine_enc(pt, a, b): return "".join(chr(((ord(c) - 97) * a + b) % 26 + 65) for c in clean(pt))
def affine_dec(ct, a, b):
    ai = pow(a, -1, 26)
    return "".join(chr(((ord(c) - 65 - b) * ai) % 26 + 97) for c in ct if c.isalpha())


def vigenere_enc(pt, key):
    pt, key = clean(pt), clean(key)
    return "".join(chr((ord(c) - 97 + ord(key[i % len(key)]) - 97) % 26 + 65) for i, c in enumerate(pt))
def vigenere_dec(ct, key):
    key = clean(key)
    return "".join(chr((ord(c) - 65 - (ord(key[i % len(key)]) - 97)) % 26 + 97) for i, c in enumerate(ct))


def autokey_enc(pt, k):                                           # k = integer key (e.g. 7)
    pt = clean(pt)
    stream = [k] + [ord(c) - 97 for c in pt]                      # key stream = k, P1, P2, ...
    return "".join(chr((ord(c) - 97 + stream[i]) % 26 + 65) for i, c in enumerate(pt))
def autokey_dec(ct, k):
    out, prev = "", k
    for c in ct:
        p = (ord(c) - 65 - prev) % 26
        out += chr(p + 97)
        prev = p                                                  # recovered plaintext becomes next key
    return out


def playfair_matrix(key):
    seen = []
    for c in clean(key).replace("j", "i") + "abcdefghiklmnopqrstuvwxyz":
        if c not in seen:
            seen.append(c)
    return [seen[i:i + 5] for i in range(0, 25, 5)]

def playfair(text, key, decrypt=False):
    M = playfair_matrix(key)
    pos = {M[r][c]: (r, c) for r in range(5) for c in range(5)}
    s = clean(text).replace("j", "i")
    pairs, i = [], 0
    while i < len(s):                                             # build digraphs, insert 'x' between doubles
        a = s[i]
        b = s[i + 1] if i + 1 < len(s) else "x"
        if a == b:
            b, i = "x", i + 1
        else:
            i += 2
        pairs.append((a, b))
    d, out = (-1 if decrypt else 1), ""
    for a, b in pairs:
        (r1, c1), (r2, c2) = pos[a], pos[b]
        if r1 == r2:   out += M[r1][(c1 + d) % 5] + M[r2][(c2 + d) % 5]      # same row
        elif c1 == c2: out += M[(r1 + d) % 5][c1] + M[(r2 + d) % 5][c2]      # same column
        else:          out += M[r1][c2] + M[r2][c1]                          # rectangle
    return out.upper() if not decrypt else out.lower()


def hill_enc(pt, K):
    K, n = np.array(K), len(K)
    nums = [ord(c) - 97 for c in clean(pt)]
    nums += [23] * (-len(nums) % n)                               # pad with 'x'
    out = ""
    for i in range(0, len(nums), n):
        out += "".join(chr(v + 65) for v in (np.array(nums[i:i + n]) @ K) % 26)
    return out
def hill_dec(ct, K):
    Kinv = np.array(Matrix(K).inv_mod(26).tolist(), dtype=int)   # inverse of key matrix mod 26
    return hill_enc(ct.lower(), Kinv).lower()


def brute_additive(ct, only=range(26)):
    for k in only:
        print(f"key={k:2d} -> {additive_dec(ct, k)}")
def brute_affine(ct, known_pt="ab", known_ct="GL"):
    """Try all valid (a,b); keep those where known_pt encrypts to known_ct."""
    for a in [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]:
        for b in range(26):
            if affine_enc(known_pt, a, b) == known_ct:
                return (a, b), affine_dec(ct, a, b)


# ============================================================================
# LAB 2 : DES / 3DES / AES  (ECB, CBC, CFB, OFB, CTR)  + timing + AES step-by-step
# ============================================================================
def DES(key8):
    return TripleDES(key8 * 3)                                    # 3DES with K1=K2=K3 == single DES

def make_mode(name, iv):
    return {"ECB": lambda: modes.ECB(), "CBC": lambda: modes.CBC(iv), "CFB": lambda: modes.CFB(iv),
            "OFB": lambda: modes.OFB(iv), "CTR": lambda: modes.CTR(iv)}[name]()

def sym_encrypt(algo, data, mode="ECB", iv=None):
    bs = algo.block_size // 8
    if mode in ("ECB", "CBC"):
        p = sympad.PKCS7(algo.block_size).padder()
        data = p.update(data) + p.finalize()
    e = Cipher(algo, make_mode(mode, iv)).encryptor()
    return e.update(data) + e.finalize()

def sym_decrypt(algo, ct, mode="ECB", iv=None):
    d = Cipher(algo, make_mode(mode, iv)).decryptor()
    pt = d.update(ct) + d.finalize()
    if mode in ("ECB", "CBC"):
        u = sympad.PKCS7(algo.block_size).unpadder()
        pt = u.update(pt) + u.finalize()
    return pt

def timing_compare(msg=b"Performance Testing of Encryption Algorithms", n=2000):
    rows = {"DES": (DES(b"A1B2C3D4"), 8), "3DES": (TripleDES(bytes(range(24))), 8),
            "AES-128": (algorithms.AES(bytes(16)), 16), "AES-256": (algorithms.AES(bytes(32)), 16)}
    res = {}
    for name, (algo, ivlen) in rows.items():
        iv = bytes(ivlen)
        t0 = time.perf_counter()
        for _ in range(n): ct = sym_encrypt(algo, msg, "CBC", iv)
        te = (time.perf_counter() - t0) / n
        t0 = time.perf_counter()
        for _ in range(n): sym_decrypt(algo, ct, "CBC", iv)
        td = (time.perf_counter() - t0) / n
        res[name] = (te, td)
        print(f"{name:8} enc={te*1e6:8.1f} us   dec={td*1e6:8.1f} us")
    return res
# for the graph:  import matplotlib.pyplot as plt; plt.bar(res.keys(), [v[0] for v in res.values()]); plt.show()


# ---- AES from scratch, prints every step (key expansion, initial round, main rounds, final round) ----
def _gmul(a, b):
    r = 0
    while b:
        if b & 1: r ^= a
        a = ((a << 1) ^ 0x11b) if a & 0x80 else (a << 1)
        b >>= 1
    return r & 0xff
def _make_sbox():
    inv = [0] + [next(b for b in range(1, 256) if _gmul(a, b) == 1) for a in range(1, 256)]
    rot = lambda x, n: ((x << n) | (x >> (8 - n))) & 0xff
    return [inv[a] ^ rot(inv[a], 1) ^ rot(inv[a], 2) ^ rot(inv[a], 3) ^ rot(inv[a], 4) ^ 0x63 for a in range(256)]
SBOX = _make_sbox()

def _hexs(state): return " ".join(f"{b:02x}" for b in state)

def key_expansion(key, verbose=False):
    Nk = len(key) // 4
    Nr = Nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(Nk)]
    rcon, rc = [], 1
    for _ in range(15):
        rcon.append(rc)
        rc = _gmul(rc, 2)
    for i in range(Nk, 4 * (Nr + 1)):
        t = w[i - 1][:]
        if i % Nk == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon[i // Nk - 1]
        elif Nk > 6 and i % Nk == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i - Nk][j] ^ t[j] for j in range(4)])
    if verbose:
        for r in range(Nr + 1):
            print(f"  Round key {r:2d}: {_hexs(sum(w[4 * r:4 * r + 4], []))}")
    return [sum(w[4 * r:4 * r + 4], []) for r in range(Nr + 1)], Nr

def aes_block_verbose(block16, key):
    """State is 16 bytes in column-major order (index = row + 4*col), same as the AES standard."""
    print(f"KEY ({len(key)*8}-bit): {key.hex()}\nPLAINTEXT BLOCK: {block16.hex()}\nKEY EXPANSION:")
    rks, Nr = key_expansion(key, verbose=True)
    s = [a ^ b for a, b in zip(block16, rks[0])]
    print(f"\nInitial round (AddRoundKey): {_hexs(s)}")
    for rnd in range(1, Nr + 1):
        s = [SBOX[b] for b in s];                                   a = _hexs(s)
        s = [s[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]; b = _hexs(s)
        if rnd != Nr:
            m = []
            for c in range(4):
                x = s[4 * c:4 * c + 4]
                m += [_gmul(x[0], 2) ^ _gmul(x[1], 3) ^ x[2] ^ x[3], x[0] ^ _gmul(x[1], 2) ^ _gmul(x[2], 3) ^ x[3],
                      x[0] ^ x[1] ^ _gmul(x[2], 2) ^ _gmul(x[3], 3), _gmul(x[0], 3) ^ x[1] ^ x[2] ^ _gmul(x[3], 2)]
            s = m
        c_ = _hexs(s)
        s = [x ^ y for x, y in zip(s, rks[rnd])]
        tag = "FINAL round" if rnd == Nr else f"Round {rnd}"
        print(f"\n{tag}:\n  SubBytes   : {a}\n  ShiftRows  : {b}" +
              ("" if rnd == Nr else f"\n  MixColumns : {c_}") + f"\n  AddRoundKey: {_hexs(s)}")
    return bytes(s)


# ============================================================================
# LAB 3 : RSA, ElGamal, ECC, Diffie-Hellman
# ============================================================================
def rsa_textbook(p, q, e):
    n, phi = p * q, (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return (n, e), (n, d)
def rsa_text_enc(msg, pub):   n, e = pub; return [pow(ord(c), e, n) for c in msg]    # char by char
def rsa_text_dec(cs, priv):   n, d = priv; return "".join(chr(pow(c, d, n)) for c in cs)
# e.g. pub, priv = rsa_textbook(17, 19, 5) -> n=323, e=5, d=173  (Lab 3 additional Q3)

def rsa_oaep_keys(bits=2048):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return priv, priv.public_key()
OAEP = lambda: padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def elgamal_enc(msg, p, g, h):
    out = []
    for ch in msg:
        k = random.randint(2, p - 2)
        out.append((pow(g, k, p), ord(ch) * pow(h, k, p) % p))
    return out
def elgamal_dec(cs, p, x):
    return "".join(chr(c2 * pow(pow(c1, x, p), -1, p) % p) for c1, c2 in cs)
def elgamal_demo(msg, p=7919, g=2, x=2999, h_given=6465):
    h = pow(g, x, p)
    if h_given is not None and h != h_given:
        print(f"WARNING: manual gives h={h_given} but g^x mod p = {h}. Using computed h so decryption works.")
    cs = elgamal_enc(msg, p, g, h)
    print("cipher:", cs[:4], "...")
    print("plain :", elgamal_dec(cs, p, x))


def ecc_encrypt(recv_pub, data):
    """ECC (secp256r1) hybrid: ephemeral ECDH -> HKDF -> AES-GCM  (this is what 'ElGamal on ECC' / ECIES means)."""
    eph = ec.generate_private_key(ec.SECP256R1())
    key = HKDF(hashes.SHA256(), 32, None, b"ecies").derive(eph.exchange(ec.ECDH(), recv_pub))
    nonce = os.urandom(12)
    return eph.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint), \
        nonce, AESGCM(key).encrypt(nonce, data, None)
def ecc_decrypt(recv_priv, eph_bytes, nonce, ct):
    eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), eph_bytes)
    key = HKDF(hashes.SHA256(), 32, None, b"ecies").derive(recv_priv.exchange(ec.ECDH(), eph_pub))
    return AESGCM(key).decrypt(nonce, ct, None)


def rsa_hybrid(data, priv):     # RSA can't encrypt MBs directly: AES-GCM the file, RSA-OAEP the AES key
    k, n = AESGCM.generate_key(256), os.urandom(12)
    return priv.public_key().encrypt(k, OAEP()), n, AESGCM(k).encrypt(n, data, None)
def rsa_hybrid_dec(priv, wrapped, n, ct):
    return AESGCM(priv.decrypt(wrapped, OAEP())).decrypt(n, ct, None)

def file_transfer_benchmark(sizes_mb=(1, 10)):
    """Lab 3 Q4: RSA-2048 vs ECC secp256r1 : keygen time, encrypt/decrypt time for 1MB, 10MB."""
    t = time.perf_counter(); rpriv, _ = rsa_oaep_keys(2048); print(f"RSA keygen: {time.perf_counter()-t:.3f}s")
    t = time.perf_counter(); epriv = ec.generate_private_key(ec.SECP256R1()); print(f"ECC keygen: {time.perf_counter()-t:.4f}s")
    for mb in sizes_mb:
        data = os.urandom(mb * 1024 * 1024)
        t = time.perf_counter(); w, n, c = rsa_hybrid(data, rpriv); te = time.perf_counter() - t
        t = time.perf_counter(); assert rsa_hybrid_dec(rpriv, w, n, c) == data; td = time.perf_counter() - t
        print(f"{mb}MB RSA-hybrid: enc {te:.4f}s dec {td:.4f}s")
        t = time.perf_counter(); e, n, c = ecc_encrypt(epriv.public_key(), data); te = time.perf_counter() - t
        t = time.perf_counter(); assert ecc_decrypt(epriv, e, n, c) == data; td = time.perf_counter() - t
        print(f"{mb}MB ECC-hybrid: enc {te:.4f}s dec {td:.4f}s")


_DH_P = None
def dh_params(bits=512):
    global _DH_P
    if _DH_P is None:
        _DH_P = randprime(2 ** (bits - 1), 2 ** bits)            # demo prime (real systems: RFC 3526 groups)
    return _DH_P, 2
def dh_exchange():
    p, g = dh_params()
    t = time.perf_counter()
    a, b = random.randrange(2, p - 2), random.randrange(2, p - 2)
    A, B = pow(g, a, p), pow(g, b, p)                            # public values exchanged over insecure channel
    kA, kB = pow(B, a, p), pow(A, b, p)
    print(f"DH shared secrets equal: {kA == kB}   time={time.perf_counter()-t:.6f}s")
    return kA


# ============================================================================
# LAB 4 : Rabin, SecureCorp (RSA + DH + key mgmt), Rabin key-management service, weak-RSA attack
# ============================================================================
def rabin_keygen(bits=512):
    def prime3mod4():
        while True:
            p = randprime(2 ** (bits - 1), 2 ** bits)
            if p % 4 == 3: return p
    p, q = prime3mod4(), prime3mod4()
    while q == p: q = prime3mod4()
    return p * q, (p, q)                                          # public n, private (p, q)
def rabin_enc(msg, n):
    m = int.from_bytes(msg.encode(), "big")
    m = (m << 16) | (m & 0xFFFF)                                  # redundancy: repeat last 16 bits -> pick right root
    assert m < n, "message too long for this key size"
    return pow(m, 2, n)
def rabin_dec(c, priv):
    p, q = priv; n = p * q
    mp, mq = pow(c, (p + 1) // 4, p), pow(c, (q + 1) // 4, q)
    yp, yq = pow(p, -1, q), pow(q, -1, p)                         # yp*p + yq*q = 1 (mod n parts)
    r1 = (yp * p * mq + yq * q * mp) % n
    r3 = (yp * p * mq - yq * q * mp) % n
    for r in (r1, n - r1, r3, n - r3):                            # the four square roots
        if (r >> 16) & 0xFFFF == r & 0xFFFF:                      # redundancy check
            m = r >> 16
            return m.to_bytes((m.bit_length() + 7) // 8, "big").decode()
    return None


class SecureCorp:
    """Lab 4 Q1: subsystems A/B/C talk over RSA-signed Diffie-Hellman; AES-GCM channel; key mgmt with revoke."""
    def __init__(self):
        self.keys, self.revoked, self.p, self.g = {}, set(), *dh_params()
    def register(self, name):                                     # add new subsystem (scalable)
        self.keys[name] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    def revoke(self, name):   self.revoked.add(name)
    def rotate(self, name):   self.register(name); self.revoked.discard(name)
    def _sign(self, name, val):
        return self.keys[name].sign(str(val).encode(), padding.PKCS1v15(), hashes.SHA256())
    def _verify(self, name, val, sig):
        if name in self.revoked: raise PermissionError(f"{name} keys revoked")
        self.keys[name].public_key().verify(sig, str(val).encode(), padding.PKCS1v15(), hashes.SHA256())
    def secure_channel(self, a, b, message):
        x, y = random.randrange(2, self.p - 2), random.randrange(2, self.p - 2)
        X, Y = pow(self.g, x, self.p), pow(self.g, y, self.p)
        self._verify(a, X, self._sign(a, X)); self._verify(b, Y, self._sign(b, Y))    # authenticate DH values
        k_a = HKDF(hashes.SHA256(), 32, None, b"corp").derive(pow(Y, x, self.p).to_bytes(64, "big"))
        k_b = HKDF(hashes.SHA256(), 32, None, b"corp").derive(pow(X, y, self.p).to_bytes(64, "big"))
        nonce = os.urandom(12)
        ct = AESGCM(k_a).encrypt(nonce, message.encode(), None)
        return AESGCM(k_b).decrypt(nonce, ct, None).decode()


class RabinKMS:
    """Lab 4 Q2: keygen / distribution / revocation / renewal / secure storage / audit log."""
    def __init__(self, bits=512, lifetime_days=365):
        self.bits, self.life = bits, timedelta(days=lifetime_days)
        self.master = Fernet(Fernet.generate_key())               # encrypts private keys at rest
        self.store, self.tokens = {}, {}
        logging.basicConfig(filename="kms_audit.log", level=logging.INFO, format="%(asctime)s %(message)s")
    def _log(self, m): logging.info(m)
    def generate(self, entity):
        n, (p, q) = rabin_keygen(self.bits)
        self.store[entity] = {"n": n, "priv": self.master.encrypt(json.dumps([p, q]).encode()),
                              "created": datetime.now(), "status": "active"}
        self.tokens[entity] = os.urandom(8).hex()
        self._log(f"GENERATE {entity}")
        return self.tokens[entity]
    def request_keys(self, entity, token):                        # 'secure API'
        if self.tokens.get(entity) != token or self.store[entity]["status"] != "active":
            self._log(f"DENIED {entity}"); raise PermissionError("denied")
        self._log(f"DISTRIBUTE {entity}")
        return self.store[entity]["n"], tuple(json.loads(self.master.decrypt(self.store[entity]["priv"])))
    def revoke(self, entity):  self.store[entity]["status"] = "revoked"; self._log(f"REVOKE {entity}")
    def renew_due(self):                                          # call from a scheduler / threading.Timer
        for e, r in list(self.store.items()):
            if datetime.now() - r["created"] > self.life: self.generate(e); self._log(f"RENEW {e}")
# Trade-off Rabin vs RSA: Rabin enc = 1 squaring (faster than RSA enc), security PROVABLY equals factoring,
# BUT decryption gives 4 roots (needs redundancy/padding), and is vulnerable to chosen-ciphertext attack.
# RSA: single unique plaintext, standardised (OAEP/PSS), widely supported.


def weak_rsa_attack(n, e, c):
    """Lab 4 add. Q2: primes too small / close -> factor n, rebuild d, decrypt."""
    t = time.perf_counter()
    f = factorint(n)                                             # or Fermat / trial division
    p, q = list(f)
    d = pow(e, -1, (p - 1) * (q - 1))
    print(f"Factored n={n} -> p={p}, q={q} in {time.perf_counter()-t:.4f}s; recovered d={d}")
    return pow(c, d, n)
# Mitigation: >=2048-bit modulus, random independent primes from a CSPRNG (|p-q| large), OAEP padding,
# use vetted libraries, key rotation, protect private key (HSM), monitor/revoke on compromise.


# ============================================================================
# LAB 5 : HASHING
# ============================================================================
def custom_hash(s):
    h = 5381
    for ch in s:
        h = h * 33 + ord(ch)                                     # h = h*33 + ascii
        h ^= (h >> 15)                                            # bit mixing
        h &= 0xFFFFFFFF                                           # keep within 32 bits
    return h

END = b"<END>"
def hash_server(port=5050, ready=None, tamper=False):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(1)
    if ready: ready.set()
    conn, _ = s.accept(); data = b""
    while not data.endswith(END):                                 # reassemble message sent in parts
        chunk = conn.recv(1024)
        if not chunk: break
        data += chunk
    data = data[:-len(END)]
    if tamper and data: data = bytes([data[0] ^ 1]) + data[1:]    # simulate corruption in transit
    conn.sendall(hashlib.sha256(data).hexdigest().encode()); conn.close(); s.close()
def hash_client(parts, port=5050):
    c = socket.socket(); c.connect(("127.0.0.1", port))
    for p in parts:
        c.sendall(p.encode()); time.sleep(0.05)
    c.sendall(END)
    server_hash = c.recv(64).decode(); c.close()
    local = hashlib.sha256("".join(parts).encode()).hexdigest()
    print("server hash:", server_hash, "\nlocal  hash:", local)
    print("INTEGRITY OK" if server_hash == local else "DATA CORRUPTED / TAMPERED")
def socket_demo(tamper=False, port=5050):
    ev = threading.Event()
    threading.Thread(target=hash_server, args=(port, ev, tamper), daemon=True).start()
    ev.wait(); hash_client(["Hello ", "secure ", "world"], port)

def hash_performance(count=100):
    import string
    data = ["".join(random.choices(string.ascii_letters + string.digits, k=random.randint(10, 30))) for _ in range(count)]
    for name in ("md5", "sha1", "sha256"):
        t = time.perf_counter(); hashes_ = [hashlib.new(name, s.encode()).hexdigest() for s in data]
        el = time.perf_counter() - t
        seen, coll = {}, 0
        for s, h in zip(data, hashes_):
            if h in seen and seen[h] != s: coll += 1
            seen[h] = s
        print(f"{name:7} time={el*1e3:.3f} ms  collisions={coll}")


# ============================================================================
# LAB 6 : DIGITAL SIGNATURES (RSA, ElGamal, Schnorr) + CIA triad
# ============================================================================
def rsa_sign(priv, msg):    return priv.sign(msg, padding.PKCS1v15(), hashes.SHA256())    # hashes msg with SHA-256 internally
def rsa_verify(pub, msg, sig):
    try: pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256()); return True
    except Exception: return False

# --- Lab 6 Part 1: verify Alice's / BOB's signature from the manual with the raw (textbook) RSA public key ---
LAB_N = int("d94d889e88853dd89769a18015a0a2e6bf82bf356fe14f251fb4f5e2df0d9f9a94a68a30c428b39e3362fb3779a497eceaea37100f264d7fb9fb1a97fbf621133de55fdcb9b1ad0d7a31b379216d79252f5c527b9bc63d83d4ecf4d1d45cbf843e8474babc655e9bb6799cba77a47eafa838296474afc24beb9c825b73ebf549", 16)
def raw_rsa_verify(sig_text, n=LAB_N, e=0x10001):
    sig = int.from_bytes(bytes(int(x, 16) for x in sig_text.split()), "big")
    return pow(sig, e, n).to_bytes(128, "big").lstrip(b"\x00").decode()      # -> 'Alice' / 'BOB'
LAB_ALICE_SIG = ("0xc8 0x93 0xa9 0x0d 0x8f 0x4e 0xc5 0xc3 0x64 0xec 0x86 0x9d 0x2b 0x2e 0xc9 0x21 0xe3 0x8b 0xab 0x23 0x4a 0x4f 0x45 0xe8 0x96 0x9b 0x98 0xbe 0x25 0x41 0x15 0x9e 0xab 0x6a 0xfb 0x75 0x9a 0x13 0xb6 0x26 0x04 0xc0 0x60 0x72 0x28 0x1a 0x73 0x45 0x71 0x83 0x42 0xd4 0x7f 0x57 0xd1 0xac 0x91 0x8c 0xae 0x2f 0x3b 0xd2 0x99 0x30 0x3e 0xe8 0xa8 0x3a 0xb3 0x5d 0xfb 0x4a 0xc9 0x18 0x19 0xfd 0x3f 0x0c 0x0a 0x1f 0x3d 0xa4 0xa4 0xfe 0x02 0x9d 0x96 0x2f 0x50 0x34 0xd3 0x95 0x55 0xe0 0xb7 0x2a 0x46 0xa4 0x9e 0xae 0x80 0xc9 0x77 0x43 0x16 0xc0 0xab 0xfd 0xdc 0x88 0x95 0x05 0x56 0xdf 0xc4 0xfc 0x13 0xa6 0x48 0xa3 0x3c 0xe2 0x87 0x52 0xc5 0x3f 0x0c 0x0d")
LAB_BOB_SIG = ("0x6c 0x99 0xd6 0xa8 0x42 0x53 0xee 0xb5 0x2d 0x7f 0x0b 0x27 0x17 0xf1 0x1b 0x62 0x92 0x7f 0x92 0x6d 0x42 0xbd 0xc6 0xd5 0x3e 0x5c 0xe9 0xb5 0xd2 0x96 0xad 0x22 0x5d 0x18 0x64 0xf3 0x89 0x52 0x08 0x62 0xe2 0xa2 0x91 0x47 0x94 0xe8 0x75 0xce 0x02 0xf8 0xe9 0xf8 0x49 0x72 0x20 0x12 0xe2 0xac 0x99 0x25 0x9a 0x27 0xe0 0x99 0x38 0x54 0x54 0x93 0x06 0x97 0x71 0x69 0xb1 0xb6 0x24 0xed 0x1c 0x89 0x62 0x3d 0xd2 0xdf 0xda 0x7a 0x0b 0xd3 0x36 0x37 0xa3 0xcb 0x32 0xbb 0x1d 0x5e 0x13 0xbc 0xca 0x78 0x3e 0xe6 0xfc 0x5a 0x81 0x66 0x4e 0xa0 0x66 0xce 0xb3 0x1b 0x93 0x32 0x2c 0x91 0x4c 0x58 0xbf 0xff 0xd8 0x97 0x2f 0xa8 0x57 0xd7 0x49 0x93 0xb1 0x62")


def _H(*parts, mod):                                              # hash -> integer
    return int.from_bytes(hashlib.sha256("|".join(map(str, parts)).encode()).digest(), "big") % mod

def elgamal_sig_keys(bits=256):
    p = randprime(2 ** (bits - 1), 2 ** bits); g = 2; x = random.randrange(2, p - 2)
    return (p, g, pow(g, x, p)), x
def elgamal_sign(msg, pub, x):
    p, g, y = pub
    while True:
        k = random.randrange(2, p - 2)
        if __import__("math").gcd(k, p - 1) == 1: break
    r = pow(g, k, p)
    s = (_H(msg, mod=p - 1) - x * r) * pow(k, -1, p - 1) % (p - 1)
    return r, s
def elgamal_verify(msg, sig, pub):
    p, g, y = pub; r, s = sig
    return 0 < r < p and (pow(y, r, p) * pow(r, s, p)) % p == pow(g, _H(msg, mod=p - 1), p)

def schnorr_params(qbits=160, pbits=512):
    q = randprime(2 ** (qbits - 1), 2 ** qbits)
    while True:
        k = random.getrandbits(pbits - qbits) | (1 << (pbits - qbits - 1))
        p = k * q + 1
        if p % 2 == 1 and isprime(p): break
    h = 2
    while pow(h, (p - 1) // q, p) == 1: h += 1
    return p, q, pow(h, (p - 1) // q, p)                          # g has order q
def schnorr_keys(params):
    p, q, g = params; x = random.randrange(1, q); return pow(g, x, p), x
def schnorr_sign(msg, params, x):
    p, q, g = params; k = random.randrange(1, q); r = pow(g, k, p)
    e = _H(r, msg, mod=q); return e, (k + x * e) % q
def schnorr_verify(msg, sig, params, y):
    p, q, g = params; e, s = sig
    r = (pow(g, s, p) * pow(y, -e % q, p)) % p                   # g^s * y^-e
    return _H(r, msg, mod=q) == e


def cia_demo(message="Transfer 5000 to account 1234"):
    """Confidentiality (RSA-OAEP over AES key) + Integrity (SHA-256) + Authenticity/Non-repudiation (RSA signature)."""
    alice_priv, bob_priv = rsa_oaep_keys(), rsa_oaep_keys()
    aes_key, nonce = AESGCM.generate_key(128), os.urandom(12)
    ct = AESGCM(aes_key).encrypt(nonce, message.encode(), None)                  # confidentiality
    wrapped = bob_priv[1].encrypt(aes_key, OAEP())
    digest = hashlib.sha256(ct).digest()                                          # integrity
    sig = alice_priv[0].sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))   # authenticity
    # --- Bob receives ---
    ok_hash = hashlib.sha256(ct).digest() == digest
    try: alice_priv[1].verify(sig, digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())); ok_sig = True
    except Exception: ok_sig = False
    if ok_hash and ok_sig:
        k = bob_priv[0].decrypt(wrapped, OAEP())
        print("CIA OK. Bob reads:", AESGCM(k).decrypt(nonce, ct, None).decode())
    else:
        print("Integrity/authenticity FAILED - not decrypting")


# ============================================================================
# SELF-TEST  (python 4_lab_snippets.py)
# ============================================================================
if __name__ == "__main__":
    print("=== LAB 1 ===")
    m1 = "I am learning information security"
    assert additive_dec(additive_enc(m1, 20), 20) == clean(m1)
    assert mult_dec(mult_enc(m1, 15), 15) == clean(m1)
    assert affine_dec(affine_enc(m1, 15, 20), 15, 20) == clean(m1)
    print("additive k=20 :", additive_enc(m1, 20)); print("mult k=15     :", mult_enc(m1, 15))
    print("affine (15,20):", affine_enc(m1, 15, 20))
    m2 = "the house is being sold tonight"
    v = vigenere_enc(m2, "dollars"); a = autokey_enc(m2, 7)
    assert vigenere_dec(v, "dollars") == clean(m2) and autokey_dec(a, 7) == clean(m2)
    print("vigenere:", v, "| autokey:", a)
    m3 = "The key is hidden under the door pad"
    pf = playfair(m3, "GUIDANCE"); print("playfair matrix:", playfair_matrix("GUIDANCE")); print("playfair:", pf, "->", playfair(pf, "GUIDANCE", True))
    K = [[3, 3], [2, 7]]; h = hill_enc("We live in an insecure world", K)
    print("hill:", h, "->", hill_dec(h, K)); assert hill_dec(h, K).startswith("weliveinaninsecureworld")
    print("Ex5 known-plaintext attack: 'CIW' -> 'yes' gives key =", (ord("C") - 65 - (ord("y") - 97)) % 26,
          "->", additive_dec("XVIEWYWI", 4))
    print("Ex6 affine brute force:", brute_affine("XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"))
    print("Add.Ex1 (Alice birthday 13 -> try keys 10..16):"); brute_additive("NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY".replace("/", "").replace("&", ""), range(10, 17))
    print("Vigenere HEALTH:", vigenere_enc("Life is full of surprises", "HEALTH"))

    print("\n=== LAB 2 ===")
    ct = sym_encrypt(DES(b"A1B2C3D4"), b"Confidential Data", "ECB"); print("DES ECB:", ct.hex(), "->", sym_decrypt(DES(b"A1B2C3D4"), ct, "ECB"))
    ak = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
    for mode in ("ECB", "CBC", "CFB", "OFB", "CTR"):
        iv = None if mode == "ECB" else (b"0" * 16)
        c = sym_encrypt(algorithms.AES(ak), b"Sensitive Information", mode, iv)
        assert sym_decrypt(algorithms.AES(ak), c, mode, iv) == b"Sensitive Information"
    print("AES-128 all modes OK"); timing_compare(n=300)
    blk = b"Top Secret Data\x01"; key = bytes.fromhex("FEDCBA9876543210FEDCBA9876543210")
    out = aes_block_verbose(blk, key)                                            # 32 hex chars = 16 bytes -> AES-128 rounds
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor(); assert out == e.update(blk) + e.finalize(); print("\nmatches library AES: True")

    print("\n=== LAB 3 ===")
    pub, priv = rsa_textbook(17, 19, 5); cs = rsa_text_enc("Cryptographic Protocols", pub)
    print("textbook RSA n,e,d =", pub, priv[1], "->", rsa_text_dec(cs, priv))
    rp, rpub = rsa_oaep_keys(); c = rpub.encrypt(b"Asymmetric Encryption", OAEP()); print("RSA-OAEP:", rp.decrypt(c, OAEP()))
    elgamal_demo("Asymmetric Algorithms")
    ek = ec.generate_private_key(ec.SECP256R1()); pack = ecc_encrypt(ek.public_key(), b"Secure Transactions")
    print("ECC:", ecc_decrypt(ek, *pack)); dh_exchange(); file_transfer_benchmark((1,))

    print("\n=== LAB 4 ===")
    n, pr = rabin_keygen(256); c = rabin_enc("Rabin test", n); print("Rabin:", rabin_dec(c, pr))
    corp = SecureCorp()
    for s in "ABC": corp.register(s)
    print("SecureCorp A->B:", corp.secure_channel("A", "B", "Q3 financial report"))
    corp.revoke("C")
    try: corp.secure_channel("A", "C", "x")
    except PermissionError as ex: print("SecureCorp revoked ->", ex)
    kms = RabinKMS(256); tok = kms.generate("Hospital1"); n1, pk = kms.request_keys("Hospital1", tok); print("KMS Rabin:", rabin_dec(rabin_enc("patient 42", n1), pk))
    p_, q_ = 1000003, 1000033; nn = p_ * q_; cc = pow(65, 65537, nn); print("Weak RSA attack recovered:", weak_rsa_attack(nn, 65537, cc))

    print("\n=== LAB 5 ===")
    print("custom hash('hello') =", custom_hash("hello"), custom_hash("hellp"))
    socket_demo(False); socket_demo(True); hash_performance(100)

    print("\n=== LAB 6 ===")
    print("Alice sig ->", raw_rsa_verify(LAB_ALICE_SIG), "| Bob sig ->", raw_rsa_verify(LAB_BOB_SIG))
    rk, rpk = rsa_oaep_keys(); sg = rsa_sign(rk, b"legal doc"); print("RSA sign verify:", rsa_verify(rpk, b"legal doc", sg), rsa_verify(rpk, b"tampered", sg))
    ep, ex_ = elgamal_sig_keys(); es = elgamal_sign("hello", ep, ex_); print("ElGamal sig:", elgamal_verify("hello", es, ep), elgamal_verify("hellO", es, ep))
    sp = schnorr_params(); sy, sx = schnorr_keys(sp); ss = schnorr_sign("hello", sp, sx); print("Schnorr sig:", schnorr_verify("hello", ss, sp, sy), schnorr_verify("hellO", ss, sp, sy))
    cia_demo()
    print("\nALL SELF-TESTS PASSED")
