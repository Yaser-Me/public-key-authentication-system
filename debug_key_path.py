"""Print the nonsecret current and pending credential locations for a scope."""

from credential_store import credential_paths


if __name__ == "__main__":
    print(credential_paths("student2_test", "pc2_test"))
