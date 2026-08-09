# Passphrase-Protected Client Credentials

## Purpose

Milestone 2 replaces the earlier pair of an AES-GCM ciphertext and adjacent raw
AES key with one local credential-v1 file. It strengthens software-authenticator
custody without changing the server enrollment authorization or legacy login
protocol.

## Credential-v1

Credential-v1 is a JSON application envelope containing DER PKCS#8 RSA private
key material. It uses a random 16-byte salt, Argon2id (64 MiB, 3 iterations,
4 lanes), a 32-byte derived key, and AES-256-GCM with a random 12-byte nonce.
The authenticated associated data length-prefixes the format identifier, user
ID, binding label, fingerprint, salt, and nonce. The parser accepts only this
exact bounded format and does not accept KDF parameters from files.

This is not standard encrypted PKCS#8, hardware-backed storage, device
attestation, secure backup, or protection from malware running as the trusted
local OS account. It makes a copied credential file depend on offline
passphrase guessing before use.

## Local lifecycle

New enrollment creates and independently reopens a credential before using a
no-overwrite hard link to claim the current location. It then sends the existing
Milestone 1 enrollment request. Every response after the request begins keeps
the credential, because the server may have committed the binding. Retry uses
the same private key.

Legacy AES/ciphertext material is considered only when an operator supplies its
directory explicitly. Migration decrypts the legacy key, requires the exact
active user/binding/fingerprint record in sanitized local inventory, creates a
validated pending credential, claims the current path, and only then removes the
legacy AES key followed by the ciphertext. Current and pending links block
routine use until cleanup completes. If the preserved matching binding is later
revoked, cleanup may finish as local secret reduction; authentication remains
unusable.

`credential-status` recognizes only bounded, structurally valid regular
credential files and labels them as not yet passphrase-unlocked. Empty, corrupt,
symlink-like, or unexpected occupants are reported as invalid/conflicting rather
than as current credentials. Explicit discard of unclaimed staging uses the same
short active-binding claim boundary as migration: if a claim has already won,
the pending marker remains for cleanup instead of being removed. If the binding
is no longer active, discard fails closed and preserves staging for operator
resolution.

The automated suite includes independent envelope decryption, bounded-read,
tamper, no-overwrite, race, migration, interrupted-cleanup, revocation, and
post-send preservation evidence. See the README for operational commands and
limitations.
