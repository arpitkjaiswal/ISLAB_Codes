"""
MediSecure - AES (user-provided key + IV) + SHA-256 + RSA digital signature + RBAC
Roles : Patient, Doctor, Auditor
Install: pip install cryptography
Run   : python 3_medisecure.py

Demo logins ->  patient / pat123  (Patient)
                doctor  / doc123  (Doctor)
                auditor / aud123  (Auditor)

AES key must be 16, 24 or 32 characters (AES-128/192/256).  IV must be exactly 16 characters.
e.g.  key = "0123456789ABCDEF"   iv = "1234567890123456"

Patient : read .txt -> AES-CBC encrypt -> SHA-256(cipher) -> sign hash with Patient PRIVATE key -> store
Doctor  : verify hash + verify signature (Patient PUBLIC key) -> only then AES-decrypt and display
Auditor : sees filename/hash/timestamp only, verifies signature, can never decrypt (no key/IV asked)
"""
import os, json, base64, hashlib
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization, padding as sympad
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

PRIV_FILE = "patient_private.pem"   # only the Patient uses this
PUB_FILE = "patient_public.pem"
DB_FILE = "medisecure_db.json"


def sha_hex(s):
    return hashlib.sha256(s.encode()).hexdigest()


USERS = {
    "patient": ("Patient", sha_hex("pat123")),
    "doctor": ("Doctor", sha_hex("doc123")),
    "auditor": ("Auditor", sha_hex("aud123")),
}
session = {"user": None, "role": None, "pw": None}
b64e = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s)


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def require(role):
    if session["role"] != role:
        print(f"ACCESS DENIED: this action is only for {role}.")
        return False
    return True


# ---------------- storage ----------------
def load_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE) as f:
            return json.load(f)
    return []


def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)


def pick_record(db):
    if not db:
        print("No records uploaded yet.")
        return None
    for i, r in enumerate(db, 1):
        print(f"  {i}. {r['filename']}  ({r['timestamp']})")
    c = input("Select record number: ").strip()
    if c.isdigit() and 1 <= int(c) <= len(db):
        return db[int(c) - 1]
    print("Invalid selection.")
    return None


# ---------------- RSA keys ----------------
def keys_exist():
    return os.path.exists(PRIV_FILE) and os.path.exists(PUB_FILE)


def gen_keys(passphrase):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(PRIV_FILE, "wb") as f:
        f.write(priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.BestAvailableEncryption(passphrase.encode())))
    with open(PUB_FILE, "wb") as f:
        f.write(priv.public_key().public_bytes(serialization.Encoding.PEM,
                                               serialization.PublicFormat.SubjectPublicKeyInfo))


def load_public():
    with open(PUB_FILE, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_private():   # Patient only
    with open(PRIV_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=session["pw"].encode())


# ---------------- AES (CBC + PKCS7) with user-supplied key & IV ----------------
def get_key_iv(default_iv=None):
    key = input("Shared AES key (16/24/32 chars): ").encode()
    if len(key) not in (16, 24, 32):
        print("Invalid key length. Use 16, 24 or 32 characters.")
        return None, None
    prompt = "IV (exactly 16 chars)" + (" [Enter = use stored IV]" if default_iv else "") + ": "
    iv_in = input(prompt)
    iv = default_iv if (not iv_in and default_iv) else iv_in.encode()
    if len(iv) != 16:
        print("Invalid IV length. IV must be exactly 16 characters.")
        return None, None
    return key, iv


def aes_encrypt(key, iv, data):
    padder = sympad.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(padder.update(data) + padder.finalize()) + enc.finalize()


def aes_decrypt(key, iv, ct):
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    unpadder = sympad.PKCS7(128).unpadder()
    return unpadder.update(dec.update(ct) + dec.finalize()) + unpadder.finalize()


# ---------------- verification (shared) ----------------
def check_integrity(rec):
    return hashlib.sha256(b64d(rec["enc"])).hexdigest() == rec["hash"]


def check_signature(rec, pub):
    try:
        digest = hashlib.sha256(b64d(rec["enc"])).digest()
        pub.verify(b64d(rec["signature"]), digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


# =====================  PATIENT  =====================
def p_generate():
    if not require("Patient"): return
    if keys_exist() and input("Keys exist. Regenerating invalidates old signatures. Continue? (y/n): ").lower() != "y":
        return
    gen_keys(session["pw"])
    print(f"RSA-2048 key pair created -> {PRIV_FILE} (private), {PUB_FILE} (public)")


def p_upload():
    if not require("Patient"): return
    if not keys_exist():
        print("Generate RSA keys first (option 1).")
        return
    path = input("Path of medical record .txt file: ").strip()
    if not path.lower().endswith(".txt") or not os.path.isfile(path):
        print("File not found or not a .txt file.")
        return
    key, iv = get_key_iv()
    if key is None: return
    data = open(path, "rb").read()
    enc = aes_encrypt(key, iv, data)                                   # 1. AES encrypt
    digest = hashlib.sha256(enc).digest()                              # 2. SHA-256 of cipher text
    try:
        priv = load_private()
    except ValueError:
        print("Cannot open private key.")
        return
    sig = priv.sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))   # 3. sign hash
    db = load_db()
    rec = {"filename": os.path.basename(path), "enc": b64e(enc), "hash": digest.hex(),
           "signature": b64e(sig), "iv": iv.hex(), "timestamp": now(), "verifications": []}
    db.append(rec)
    save_db(db)
    print(f"\nUploaded '{rec['filename']}' at {rec['timestamp']}")
    print("Encrypted (b64):", rec["enc"][:70] + "...")
    print("SHA-256 hash   :", rec["hash"])
    print("Signature (b64):", rec["signature"][:70] + "...")


def p_view():
    if not require("Patient"): return
    db = load_db()
    if not db:
        print("No uploaded records.")
    for r in db:
        print(f"\nFile      : {r['filename']}\nTimestamp : {r['timestamp']}\nSHA-256   : {r['hash']}\n"
              f"Encrypted : {r['enc'][:60]}...")


# =====================  DOCTOR  =====================
def d_view():
    if not require("Doctor"): return
    db = load_db()
    if not db:
        print("No records available.")
    for i, r in enumerate(db, 1):
        print(f"{i}. {r['filename']} | uploaded {r['timestamp']}")


def d_decrypt():
    if not require("Doctor"): return
    db = load_db()
    rec = pick_record(db)
    if not rec: return
    key, iv = get_key_iv(default_iv=bytes.fromhex(rec["iv"]))
    if key is None: return
    integ = check_integrity(rec)
    sig = check_signature(rec, load_public())
    print("\nIntegrity (SHA-256) :", "PASS" if integ else "FAIL")
    print("Signature (RSA)     :", "VALID" if sig else "INVALID")
    ok = integ and sig
    result = "SUCCESS - integrity and signature verified" if ok else "FAILED - record NOT decrypted"
    text = None
    if ok:
        try:
            text = aes_decrypt(key, iv, b64d(rec["enc"])).decode()
        except Exception:
            result = "VERIFIED but decryption failed (wrong AES key/IV)"
    stamp = now()
    rec["verifications"].append({"by": session["user"], "integrity": integ, "signature": sig,
                                 "result": result, "timestamp": stamp})
    save_db(db)
    print(f"Result: {result}   [{stamp}]")
    if text is not None:
        print(f"\n--- Decrypted medical record: {rec['filename']} ---\n{text}")


def d_log():
    if not require("Doctor"): return
    db = load_db()
    any_log = False
    for r in db:
        for v in r.get("verifications", []):
            any_log = True
            print(f"{v['timestamp']} | {r['filename']} | integrity={v['integrity']} "
                  f"sig={v['signature']} | {v['result']}")
    if not any_log:
        print("No verification results stored yet.")


# =====================  AUDITOR  =====================
def a_view():
    if not require("Auditor"): return
    db = load_db()
    if not db:
        print("No records.")
    for i, r in enumerate(db, 1):
        print(f"{i}. {r['filename']} | {r['hash']} | {r['timestamp']}")


def a_verify():
    if not require("Auditor"): return
    db = load_db()
    rec = pick_record(db)
    if not rec: return
    print(f"Signature of '{rec['filename']}':", "VALID" if check_signature(rec, load_public()) else "INVALID")
    print("Checked at:", now())


def tamper_demo():
    """DEMO ONLY (Patient menu): change 1 char of a stored cipher text to show detection."""
    if not require("Patient"): return
    db = load_db()
    rec = pick_record(db)
    if not rec: return
    s = rec["enc"]
    rec["enc"] = s[:10] + ("A" if s[10] != "A" else "B") + s[11:]
    save_db(db)
    print("1 character of the stored cipher text changed.")


MENUS = {
    "Patient": [("Generate RSA key pair", p_generate),
                ("Upload medical record (.txt) - encrypt, hash, sign", p_upload),
                ("View uploaded records", p_view),
                ("[DEMO] Tamper with a stored record", tamper_demo)],
    "Doctor": [("View available records", d_view),
               ("Verify + decrypt a record", d_decrypt),
               ("View verification log", d_log)],
    "Auditor": [("View filename / hash / timestamp", a_view),
                ("Verify a record's signature", a_verify)],
}


def role_menu():
    actions = MENUS[session["role"]]
    while True:
        print(f"\n=== {session['role'].upper()} MENU ({session['user']}) ===")
        for i, (title, _) in enumerate(actions, 1):
            print(f"{i}. {title}")
        print("0. Logout")
        c = input("Choice: ").strip()
        if c == "0":
            break
        if c.isdigit() and 1 <= int(c) <= len(actions):
            actions[int(c) - 1][1]()
        else:
            print("Invalid choice.")
    session.update(user=None, role=None, pw=None)


def login():
    user = input("Username: ").strip()
    pw = input("Password: ")
    if user in USERS and USERS[user][1] == sha_hex(pw):
        session.update(user=user, role=USERS[user][0], pw=pw)
        print(f"Welcome {user} - role: {session['role']}")
        return True
    print("Invalid credentials.")
    return False


if __name__ == "__main__":
    while True:
        print("\n===== MediSecure =====\n1. Login\n2. Exit")
        ch = input("Choice: ").strip()
        if ch == "1":
            if login():
                role_menu()
        elif ch == "2":
            break
        else:
            print("Invalid choice.")
