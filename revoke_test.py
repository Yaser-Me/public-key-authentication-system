"""Deprecated manual helper retained only to point operators to trusted revocation."""


if __name__ == "__main__":
    print(
        "HTTP revocation is retired. Use: "
        "python manage.py revoke USER_ID DEVICE_ID REASON"
    )
