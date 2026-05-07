import os
import base64
import requests

from crypto_utils import (
    generate_rsa_keypair,
    sign_challenge,
    generate_aes_key,
    encrypt_private_key,
    decrypt_private_key,
    compute_device_hash,
)

BASE_URL = "http://127.0.0.1:5000"


def _device_key_paths(user_id: str, device_id: str):
    """
    build filenames for this user/device pair.
    """
    u = user_id.replace(" ", "_")
    d = device_id.replace(" ", "_")

    priv_file = f"privkey_{u}_{d}.enc"
    aes_file = f"aeskey_{u}_{d}.bin"
    return priv_file, aes_file


def register_device(user_id, device_id):
    """
    Register a device:
       generate RSA + AES keys
       encrypt private key locally
       compute integrity hash
       send public key + hash to server
    """
    # RSA keys
    priv_pem, pub_pem = generate_rsa_keypair()

    # AES key for local storage protection
    aes_key = generate_aes_key()

    # encrypt private key with AES-GCM
    enc_priv_b64 = encrypt_private_key(aes_key, priv_pem)

    # bind device to user/public key via SHA-256
    integrity_hash = compute_device_hash(user_id, device_id, pub_pem)

    # store encrypted private key + AES key on disk
    priv_file, aes_file = _device_key_paths(user_id, device_id)

    with open(priv_file, "w", encoding="utf-8") as f:
        f.write(enc_priv_b64)

    with open(aes_file, "wb") as f:
        f.write(aes_key)

    print(f"[+] encrypted private key -> {priv_file}")
    print(f"[+] AES key -> {aes_file}")

    # send registration info to backend
    resp = requests.post(f"{BASE_URL}/register_device", json={
        "user_id": user_id,
        "device_id": device_id,
        "public_key_b64": base64.b64encode(pub_pem).decode(),
        "integrity_hash": integrity_hash,
    })

    return resp.json()


def _load_private_key(user_id: str, device_id: str) -> bytes:
    """
    load AES key and encrypted private key for this device,
    decrypt, and return PEM bytes
    """
    priv_file, aes_file = _device_key_paths(user_id, device_id)

    if not os.path.exists(priv_file) or not os.path.exists(aes_file):
        raise FileNotFoundError(
            f"Local key files not found for '{user_id}' / '{device_id}' "
            f"(expected {priv_file} and {aes_file})"
        )

    with open(aes_file, "rb") as f:
        aes_key = f.read()

    with open(priv_file, "r", encoding="utf-8") as f:
        enc_priv_b64 = f.read().strip()

    return decrypt_private_key(aes_key, enc_priv_b64)


def login(user_id, device_id, legacy_private_key_pem=None):
    """
    Passwordless login:
      1 ask server for a challenge
      2 decrypt private key from disk
      3 sign challenge
      4 send signature back
    legacy_private_key_pem is ignored kept for GUI only
    """
    # request challenge
    resp = requests.post(f"{BASE_URL}/login/request_challenge", json={
        "user_id": user_id,
        "device_id": device_id
    })

    data = resp.json()

    # server might return an error instead of a challenge
    if "challenge" not in data:
        return data

    challenge_b64 = data["challenge"]
    challenge = base64.b64decode(challenge_b64)

    # load private key from disk and sign
    priv_pem = _load_private_key(user_id, device_id)
    signature = sign_challenge(priv_pem, challenge)


    # DEBUG PRINTS for replay attack testing
    signature_b64 = base64.b64encode(signature).decode()
    print("DEBUG: challenge_b64 =", challenge_b64)
    print("DEBUG: signature_b64 =", signature_b64)


    resp2 = requests.post(f"{BASE_URL}/login/verify", json={
        "user_id": user_id,
        "device_id": device_id,
        "challenge": challenge_b64,
"signature": signature_b64
    })

    return resp2.json()
