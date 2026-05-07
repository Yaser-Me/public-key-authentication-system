import requests

BASE_URL = "http://127.0.0.1:5000"

def revoke():
    data = {
        "user_id": "ya_test",
        "device_id": "device1"
    }
    r = requests.post(f"{BASE_URL}/device/revoke", json=data)
    print("HTTP Status:", r.status_code)
    try:
        print("Response JSON:", r.json())
    except Exception:
        print("Raw response text:", r.text)

if __name__ == "__main__":
    revoke()
