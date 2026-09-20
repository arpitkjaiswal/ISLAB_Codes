"""
HealthSecure - RSA encryption + SHA-256 + RSA digital signature + RBAC
Roles : Doctor, Nurse, Admin
Install: pip install cryptography
Run   : python 1_healthsecure.py

Demo logins ->  drhouse / doc123   (Doctor)
                nancy   / nurse123 (Nurse)
                admin   / admin123 (Admin)

Flow (Doctor adds record):
  patient info -> RSA-OAEP encrypt (Doctor PUBLIC key) -> SHA-256 of ciphertext
  -> sign that hash (Doctor PRIVATE key) -> store {enc, hash, signature, timestamp}
Nurse/Admin only ever load the PUBLIC key, so they cannot decrypt.
"""
import os, json, base64, hashlib
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.exceptions import InvalidSignature

PRIV_FILE = "doctor_private.pem"   # ONLY the Doctor ever opens this file
PUB_FILE = "doctor_public.pem"     # public - anyone can read
DB_FILE = "healthsecure_records.json"   # encrypted records, hashes, signatures, timestamps
CHUNK = 190                        # max bytes per RSA-2048 OAEP-SHA256 block


def sha_hex(s):
    return hashlib.sha256(s.encode()).hexdigest()


# ---------- RBAC: users, roles (passwords stored only as SHA-256 hashes) ----------
USERS = {
    "drhouse": ("Doctor", sha_hex("doc123")),
    "nancy": ("Nurse", sha_hex("nurse123")),
    "admin": ("Admin", sha_hex("admin123")),
}
session = {"user": None, "role": None, "pw": None}
patients = []   # in-memory list of plaintext patient dicts (Doctor only, never written to disk)


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def require(role):
    """RBAC check - every action calls this first."""
    if session["role"] != role:
        print(f"ACCESS DENIED: this action is only for {role}.")
        return False
    return True


b64e = lambda b: base64.b64encode(b).decode()
b64d = lambda s: base64.b64decode(s)


def OAEP():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


# ---------- key handling ----------
def keys_exist():
    return os.path.exists(PRIV_FILE) and os.path.exists(PUB_FILE)


def gen_keys(passphrase):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(PRIV_FILE, "wb") as f:   # private key is encrypted with the doctor's password
        f.write(priv.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.PKCS8,
                                   serialization.BestAvailableEncryption(passphrase.encode())))
    with open(PUB_FILE, "wb") as f:
        f.write(priv.public_key().public_bytes(serialization.Encoding.PEM,
                                               serialization.PublicFormat.SubjectPublicKeyInfo))


def load_public():
    with open(PUB_FILE, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_private():   # called ONLY from Doctor functions
    with open(PRIV_FILE, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=session["pw"].encode())


# ---------- RSA on long data (block by block) ----------
def rsa_encrypt(pub, data):
    return b"".join(pub.encrypt(data[i:i + CHUNK], OAEP()) for i in range(0, len(data), CHUNK))


def rsa_decrypt(priv, ct):
    size = priv.key_size // 8
    return b"".join(priv.decrypt(ct[i:i + size], OAEP()) for i in range(0, len(ct), size))


# ---------- storage ----------
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
        print("No records stored yet.")
        return None
    rid = input("Enter Record ID (e.g. REC001): ").strip().upper()
    for r in db:
        if r["id"] == rid:
            return r
    print("Record not found.")
    return None


# ---------- verification (shared by Doctor / Nurse / Admin) ----------
def check_integrity(rec):
    """Recompute SHA-256 of encrypted data and compare with stored hash."""
    return hashlib.sha256(b64d(rec["enc"])).hexdigest() == rec["hash"]


def check_signature(rec, pub):
    """Verify Doctor's RSA signature (over SHA-256 of the encrypted data) using the PUBLIC key.
    Hash is recomputed from the data, so a tampered record also gives INVALID."""
    try:
        digest = hashlib.sha256(b64d(rec["enc"])).digest()
        pub.verify(b64d(rec["signature"]), digest,
                   padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


# =====================  DOCTOR  =====================
def d_generate():
    if not require("Doctor"): return
    if keys_exist() and input("Keys already exist. Regenerating makes OLD records "
                              "undecryptable. Continue? (y/n): ").lower() != "y":
        return
    gen_keys(session["pw"])
    print(f"RSA-2048 key pair generated -> {PRIV_FILE} (private, passphrase protected), {PUB_FILE} (public)")


def d_add():
    if not require("Doctor"): return
    if not keys_exist():
        print("Generate RSA keys first (option 1).")
        return
    info = {"Name": input("Name        : ").strip()}
    while True:
        age = input("Age         : ").strip()
        if age.isdigit() and 0 < int(age) < 130:
            break
        print("Enter a valid age.")
    info["Age"] = age
    info["Gender"] = input("Gender      : ").strip()
    info["Blood Group"] = input("Blood Group : ").strip().upper()
    info["Diagnosis"] = input("Diagnosis   : ").strip()
    info["Other Details"] = input("Other details: ").strip()
    patients.append(info)                                   # store in list (memory)

    try:
        priv = load_private()
    except ValueError:
        print("Could not open private key (wrong passphrase / corrupted).")
        return
    enc = rsa_encrypt(priv.public_key(), json.dumps(info).encode())   # 1. RSA encrypt
    digest = hashlib.sha256(enc).digest()                             # 2. SHA-256 of ciphertext
    sig = priv.sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))  # 3. sign hash
    db = load_db()
    rec = {"id": f"REC{len(db) + 1:03d}", "name": info["Name"], "enc": b64e(enc),
           "hash": digest.hex(), "signature": b64e(sig), "timestamp": now()}
    db.append(rec)
    save_db(db)
    print(f"\nStored as {rec['id']} at {rec['timestamp']}")
    print("SHA-256 hash :", rec["hash"])
    print("Ciphertext   :", rec["enc"][:70] + "...")


def d_view():
    if not require("Doctor"): return
    db = load_db()
    if not db:
        print("No records stored.")
    for r in db:
        print(f"{r['id']} | {r['name']} | {r['timestamp']} | hash={r['hash'][:24]}...")


def d_decrypt():
    if not require("Doctor"): return
    db = load_db()
    rec = pick_record(db)
    if not rec: return
    try:
        priv = load_private()
    except (ValueError, FileNotFoundError):
        print("Cannot open private key.")
        return
    integ = check_integrity(rec)
    sig = check_signature(rec, priv.public_key())
    print("Integrity (SHA-256 match) :", "PASS" if integ else "FAIL")
    print("Signature (RSA verify)    :", "VALID" if sig else "INVALID")
    if not (integ and sig):
        print("ACCESS DENIED: verification failed - NOT decrypting (record may be tampered).")
        return
    info = json.loads(rsa_decrypt(priv, b64d(rec["enc"])).decode())
    print(f"\n--- Decrypted record {rec['id']} ---")
    for k, v in info.items():
        print(f"{k:14}: {v}")


def d_session_list():
    if not require("Doctor"): return
    if not patients:
        print("No patients entered in this session.")
    for i, p in enumerate(patients, 1):
        print(i, p)


def d_tamper():
    """DEMO ONLY: flips one char of stored ciphertext to show that verification fails."""
    if not require("Doctor"): return
    db = load_db()
    rec = pick_record(db)
    if not rec: return
    s = rec["enc"]
    rec["enc"] = s[:10] + ("A" if s[10] != "A" else "B") + s[11:]
    save_db(db)
    print(f"{rec['id']} tampered (1 character changed). Now try verify/decrypt.")


# =====================  NURSE  =====================
def n_view():
    if not require("Nurse"): return
    db = load_db()
    if not db:
        print("No records.")
    for r in db:
        print(f"\nRecord ID : {r['id']}\nTimestamp : {r['timestamp']}\n"
              f"Encrypted : {r['enc'][:60]}... ({len(r['enc'])} chars)\n"
              f"SHA-256   : {r['hash']}\nSignature : {r['signature'][:60]}...")


def n_verify():
    if not require("Nurse"): return
    db = load_db()
    rec = pick_record(db)
    if not rec: return
    pub = load_public()      # Nurse loads ONLY the public key
    print(f"\nRecord {rec['id']}")
    print("Integrity :", "PASS (hash matches)" if check_integrity(rec) else "FAIL (data altered)")
    print("Signature :", "VALID (authentic Doctor)" if check_signature(rec, pub) else "INVALID")
    print("Verified at:", now())


# =====================  ADMIN  =====================
def a_view():
    if not require("Admin"): return
    db = load_db()
    if not db:
        print("No records.")
    for r in db:
        print(f"{r['id']} | {r['name']} | {r['hash']} | {r['timestamp']}")


def a_verify():
    if not require("Admin"): return
    db = load_db()
    rec = pick_record(db)
    if not rec: return
    print(f"Signature of {rec['id']}:", "VALID" if check_signature(rec, load_public()) else "INVALID")


MENUS = {
    "Doctor": [("Generate RSA key pair", d_generate),
               ("Enter patient info (encrypt + hash + sign + store)", d_add),
               ("View stored records", d_view),
               ("Decrypt a record (after integrity + signature check)", d_decrypt),
               ("Show patients entered this session (list)", d_session_list),
               ("[DEMO] Tamper with a stored record", d_tamper)],
    "Nurse": [("View encrypted records", n_view),
              ("Verify integrity + signature of a record", n_verify)],
    "Admin": [("View record ID/name, hash, timestamp", a_view),
              ("Verify digital signature (VALID/INVALID)", a_verify)],
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
        print("\n===== HealthSecure =====\n1. Login\n2. Exit")
        ch = input("Choice: ").strip()
        if ch == "1":
            if login():
                role_menu()
        elif ch == "2":
            break
        else:
            print("Invalid choice.")
