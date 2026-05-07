import requests

BASE_URL = "http://127.0.0.1:5000"


def replay():
    # Paste the exact values from your DEBUG output here:
    challenge_b64 = "U5tC+VzDAxvNCC9jLpjAIUzswvB49ICRn8Q6pNPx+Os="
    signature_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    data = {
        "user_id": "student_test",
        "device_id": "pc_test",
        "challenge": challenge_b64,
        "signature": signature_b64,
    }

    r = requests.post(f"{BASE_URL}/login/verify", json=data)
    print("HTTP status:", r.status_code)
    try:
        print("Response JSON:", r.json())
    except Exception:
        print("Raw response text:", r.text)


if __name__ == "__main__":
    replay()
