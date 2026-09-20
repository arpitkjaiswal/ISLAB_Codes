"""
Hospital Management System  -  AES-128 + RSA + ElGamal + SHA-256 integrity check
Install: pip install cryptography
Run    : python 2_hospital_aes_rsa_elgamal.py

SENDER side                                      RECEIVER side
 1. create original.txt                           1. hash received cipher file (SHA-256)
 2. AES-128 encrypt -> aes_encrypted.txt (hex)    2. compare with sender's hash
 3. RSA encrypt the AES key -> aes_key_rsa.txt    3. MATCH    -> RSA-decrypt AES key, AES-decrypt file,
 4. ElGamal encrypt authorization code                          ElGamal-decrypt auth code, show everything
 5. SHA-256 of AES cipher text -> sender_hash.txt 4. MISMATCH -> "INTEGRITY FAILED", NO decryption
Menu option 4 flips ONE character of the cipher text to demonstrate the failure.
"""
import os, json, random, hashlib
from cryptography.hazmat.primitives import hashes, padding as sympad
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ORIG = "original.txt"
CIPHER = "aes_encrypted.txt"
CIPHER_TAMPERED = "aes_encrypted_tampered.txt"
KEYFILE = "aes_key_rsa.txt"
AUTHFILE = "auth_code_elgamal.json"
HASHFILE = "sender_hash.txt"

# ElGamal parameters (from the lab manual: p=7919, g=2, x=2999). Change here / or type them in at runtime.
# NOTE: h is always COMPUTED as g^x mod p. (The manual's h=6465 does NOT equal 2^2999 mod 7919 = 3868.)
DEFAULT_P, DEFAULT_G, DEFAULT_X = 7919, 2, 2999

state = {}     # keeps private/public values between menu steps


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write(path, text):
    with open(path, "w") as f:
        f.write(text)


def read(path):
    with open(path) as f:
        return f.read().strip()


# ---------------- AES-128 (CBC, random IV stored in front of the cipher text) ----------------
def aes_encrypt(key, data):
    iv = os.urandom(16)
    padder = sympad.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv + enc.update(padder.update(data) + padder.finalize()) + enc.finalize()


def aes_decrypt(key, blob):
    iv, ct = blob[:16], blob[16:]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    unpadder = sympad.PKCS7(128).unpadder()
    return unpadder.update(dec.update(ct) + dec.finalize()) + unpadder.finalize()


# ---------------- ElGamal (character by character) ----------------
def elgamal_encrypt(msg, p, g, h):
    out = []
    for ch in msg:
        k = random.randint(2, p - 2)
        out.append((pow(g, k, p), (ord(ch) * pow(h, k, p)) % p))    # (c1, c2)
    return out


def elgamal_decrypt(cipher, p, x):
    text = ""
    for c1, c2 in cipher:
        s = pow(c1, x, p)                        # shared secret
        text += chr((c2 * pow(s, -1, p)) % p)    # m = c2 * s^-1 mod p
    return text


def OAEP():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


# ---------------- menu actions ----------------
def create_file(auto=False):
    if auto:
        text = "Patient: Rahul Sharma | Age 34 | Blood Group O+ | Diagnosis: Type 2 Diabetes | Rx: Metformin 500mg"
    else:
        print("Type file content (empty line to finish):")
        lines = []
        while True:
            line = input()
            if not line:
                break
            lines.append(line)
        text = "\n".join(lines) or "Default patient record: Name=John, Age=40, Diagnosis=Flu"
    write(ORIG, text)
    print(f"Created {ORIG} with content:\n{text}")


def sender(auto=False):
    if not os.path.exists(ORIG):
        print("Create the file first (option 1).")
        return
    data = open(ORIG, "rb").read()
    print("\n========== SENDER ==========")
    print("Original file content :", data.decode())

    # 1. AES-128 encrypt the file content -> another file
    aes_key = os.urandom(16)                                   # 128-bit key
    blob = aes_encrypt(aes_key, data)
    write(CIPHER, blob.hex())
    print("\nAES key (hex)         :", aes_key.hex())
    print("AES encrypted msg (hex):", blob.hex(), f"-> saved in {CIPHER}")

    # 2. RSA encrypt the AES key -> another file
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    enc_key = pub.encrypt(aes_key, OAEP())
    write(KEYFILE, enc_key.hex())
    nums = priv.private_numbers()
    print("\nRSA public key  n =", nums.public_numbers.n)
    print("RSA public key  e =", nums.public_numbers.e)
    print("RSA private key d =", nums.d)
    print("RSA p =", nums.p)
    print("RSA q =", nums.q)
    print("RSA-encrypted AES key (hex):", enc_key.hex(), f"-> saved in {KEYFILE}")

    # 3. ElGamal encrypt the authorization code
    if auto:
        p, g, x, code = DEFAULT_P, DEFAULT_G, DEFAULT_X, "AUTH-2024"
    else:
        raw = input(f"\nElGamal p g x (Enter = {DEFAULT_P} {DEFAULT_G} {DEFAULT_X}): ").split()
        p, g, x = map(int, raw) if len(raw) == 3 else (DEFAULT_P, DEFAULT_G, DEFAULT_X)
        code = input("Authorization code: ").strip() or "AUTH-2024"
    if p < 256:
        print("p must be > 255 so every ASCII character fits (m < p).")
        return
    h = pow(g, x, p)                                            # public value h = g^x mod p
    cipher = elgamal_encrypt(code, p, g, h)
    write(AUTHFILE, json.dumps({"p": p, "g": g, "h": h, "cipher": cipher}))
    print(f"\nElGamal public key (p, g, h) = ({p}, {g}, {h})   private x = {x}")
    print("Authorization code    :", code)
    print("ElGamal cipher (c1,c2):", cipher, f"-> saved in {AUTHFILE}")

    # 4. SHA-256 of the AES cipher text (sender's hash)
    sender_hash = sha256_hex(read(CIPHER).encode())
    write(HASHFILE, sender_hash)
    print("\nSender SHA-256 of AES cipher text:", sender_hash)

    state.update(priv=priv, x=x, p=p)


def receiver(cipher_file=CIPHER):
    if "priv" not in state:
        print("Run the sender first (option 2).")
        return
    print(f"\n========== RECEIVER (checking {cipher_file}) ==========")
    ct_hex = read(cipher_file)
    recv_hash = sha256_hex(ct_hex.encode())
    sender_hash = read(HASHFILE)
    print("Sender   hash:", sender_hash)
    print("Receiver hash:", recv_hash)

    if recv_hash != sender_hash:                                 # integrity check
        print("\n*** ERROR: INTEGRITY FAILED - hashes do not match. ***")
        print("*** Cipher text was tampered with. Decryption NOT performed. ***")
        return
    print("INTEGRITY VERIFIED - hashes match. Proceeding to decryption.\n")

    enc_key = bytes.fromhex(read(KEYFILE))
    aes_key = state["priv"].decrypt(enc_key, OAEP())             # RSA decrypt AES key
    plaintext = aes_decrypt(aes_key, bytes.fromhex(ct_hex)).decode()

    auth = json.load(open(AUTHFILE))
    code = elgamal_decrypt([tuple(c) for c in auth["cipher"]], auth["p"], state["x"])

    print("Encrypted msg (hex)            :", ct_hex)
    print("RSA-encrypted AES key (hex)    :", enc_key.hex())
    print("Decrypted AES key (hex)        :", aes_key.hex())
    print("Decrypted authorization code   :", code)
    print("Decrypted original file content:", plaintext)


def tamper_and_check():
    if "priv" not in state:
        print("Run the sender first (option 2).")
        return
    ct = read(CIPHER)
    i = 20
    new_char = "0" if ct[i] != "0" else "1"
    write(CIPHER_TAMPERED, ct[:i] + new_char + ct[i + 1:])
    print(f"Changed 1 character (position {i}: '{ct[i]}' -> '{new_char}') in the AES cipher text.")
    print("Original cipher hash :", sha256_hex(ct.encode()))
    print("Tampered cipher hash :", sha256_hex(read(CIPHER_TAMPERED).encode()))
    receiver(CIPHER_TAMPERED)


def full_demo():
    create_file(auto=True)
    sender(auto=True)
    receiver()                 # should pass
    print("\n" + "=" * 60 + "\nNow tampering with the cipher text ...\n" + "=" * 60)
    tamper_and_check()         # should fail


if __name__ == "__main__":
    while True:
        print("\n===== Hospital System (AES-128 + RSA + ElGamal) =====")
        print("1. Create file and add content")
        print("2. SENDER: AES encrypt, RSA-encrypt key, ElGamal auth code, SHA-256")
        print("3. RECEIVER: verify hash -> decrypt (normal case)")
        print("4. TAMPER 1 char of cipher text -> receiver check (integrity failure demo)")
        print("5. Run complete demo automatically")
        print("0. Exit")
        c = input("Choice: ").strip()
        if c == "1": create_file()
        elif c == "2": sender()
        elif c == "3": receiver()
        elif c == "4": tamper_and_check()
        elif c == "5": full_demo()
        elif c == "0": break
        else: print("Invalid choice.")
