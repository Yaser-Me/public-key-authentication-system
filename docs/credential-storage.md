# Credential Storage

Each enrolled client stores its RSA private key in a Credential-v1 JSON envelope.
The envelope contains DER PKCS#8 material protected with Argon2id (64 MiB, three
iterations, four lanes) and AES-256-GCM. Its authenticated data binds the format,
identity, binding label, public-key fingerprint, salt, and nonce. Parsing is
strict and does not accept KDF settings supplied by a credential file.

This is an application format, not standard encrypted PKCS#8 or hardware-backed
storage. It protects a copied credential file by requiring offline passphrase
guessing; it does not protect against malware running as the trusted local OS
account.

Before enrollment, the client writes, reopens, and validates a complete
credential, then claims the final path with a no-overwrite hard link. Once an
enrollment request has been sent, it retains the credential for every denied or
uncertain outcome because the server may have committed the binding. Retrying uses
the same key.

The client unlocks Credential-v1 locally before requesting an authentication
challenge, so a local unlock failure does not create a server request or challenge.

Legacy AES/ciphertext pairs are used only through explicit inspection and
migration commands. Migration requires an exact trusted binding match, creates a
validated pending credential, claims the current location, and then removes the
legacy files. Interrupted cleanup leaves recognizable pending state instead of
silently discarding material. CURRENT/PENDING conflicts block normal use until
safe resume or discard completes. A matching revoked binding may permit cleanup of
migration residue, but it never restores credential usability or reactivates the
binding.
