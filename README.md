# Passwordless Authentication Demo  

This project is a cybersecurity proof-of-concept for passwordless authentication using public-key cryptography. Instead of using passwords, the system verifies the user by checking a signed challenge from a registered device.

## Main Features

- RSA-2048 public-key cryptography
- AES-256-GCM encryption for local private key protection
- Challenge-response login using digital signatures
- SHA-256 device binding and integrity checking
- Replay attack protection
- Device revocation support
- Flask backend server
- Tkinter GUI client

## Project Files

- `server.py` – Flask backend server for registration, challenge generation, verification, and device management
- `client.py` – Client-side logic for registration and login
- `gui_client.py` – Tkinter GUI for user interaction
- `crypto_utils.py` – RSA, AES-GCM, hashing, and signature helper functions
- `db_utils.py` – JSON-based database helper functions
- `replay_test.py` – Test script for replay attack validation
- `revoke_test.py` – Test script for device revocation
- `requirements.txt` – Python dependencies

## Setup

1. Create and activate a virtual environment:

```bash
python -m venv venv
