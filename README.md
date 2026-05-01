# pqcrypt

> **Post-quantum file encryption and signing from the command line.**  
> Keys live on a microSD card. Everyday encryption needs no card inserted.

[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![PyPI Version](https://img.shields.io/pypi/v/pqcrypt)](https://pypi.org/project/pqcrypt/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/xvi-xv-xii-ix-xxii-ix-xiv/pqcrypt/actions/workflows/ci.yml/badge.svg)](https://github.com/xvi-xv-xii-ix-xxii-ix-xiv/pqcrypt/actions)
[![No dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](#requirements)
[![Platforms](https://img.shields.io/badge/platform-macOS%20%7C%20Ubuntu-lightgrey.svg)](#requirements)

---

## ✨ Quick start

```bash
# Install
pip install pqcrypt

# Generate your encryption key (SD card must be inserted)
pqcrypt init

# Encrypt a file (no SD card needed after caching)
pqcrypt encrypt secret.pdf

# Decrypt (requires SD card)
pqcrypt decrypt secret.pdf.age
```

---

## What it does

`pqcrypt` wraps two audited, battle-tested command-line tools behind a
single ergonomic interface:

| Layer          | Tool                                                | Algorithm                           | NIST standard |
| -------------- | --------------------------------------------------- | ----------------------------------- | ------------- |
| **Encryption** | [`age`](https://github.com/FiloSottile/age) ≥ 1.3.0 | HPKE / ML-KEM-768 + X25519 (hybrid) | FIPS 203      |
| **Signing**    | `openssl` ≥ 3.5 (or 3.x + oqs-provider)             | ML-DSA-65                           | FIPS 204      |

Both algorithms are **post-quantum**: they resist attacks from future
large-scale quantum computers. The hybrid encryption scheme (ML-KEM-768 +
X25519) additionally retains classical security — if either primitive is
ever broken, the other continues to protect your files.

---

## Why microSD?

Your private keys live **only on the card**.

- Encryption and signature verification work every day **without** the card.
- Decryption and signing require the card + a passphrase — physical
  possession and knowledge combined.
- Losing the workstation does not expose the keys. Losing the card without
  the passphrase does not expose them either.

---

## Security design

```
┌─────────────────── microSD card ────────────────────┐
│  main.key.age          ← age identity               │
│    └── passphrase-encrypted by age itself           │
│  signing.key.pem       ← ML-DSA-65 private key      │
│    └── AES-256-CBC PKCS#8, passphrase by openssl    │
│  main.pub              ← age public recipient (copy)│
│  signing.pub.pem       ← ML-DSA public key   (copy) │
└─────────────────────────────────────────────────────┘

~/.config/pqcrypt/
  main.pub              ← cached for offline encryption
  signing.pub.pem       ← cached for offline verification
```

### Key invariants

1. **Cleartext age identity never touches disk.**  
   Two `age` processes are connected by an OS pipe: the first decrypts
   the passphrase-protected identity; the second receives it via `stdin`
   (`age -d -i -`). The cleartext key is never written by `pqcrypt`.

2. **All writes are atomic.**  
   Output goes to `<dst>.part`, then `rename()` (POSIX atomic on the same
   filesystem). A crash or `Ctrl-C` never leaves a confusing half-written
   file behind.

3. **Encrypt-then-sign.**  
   When `--sign` is used, the signature covers the **ciphertext**, not the
   plaintext. This means verification works with only the public key, and
   you can detect tampering before attempting decryption.

4. **Verify-then-decrypt ordering.**  
   `decrypt --verify` checks the signature first and refuses to decrypt if
   it fails — even before the SD card passphrase is requested.

5. **Path-traversal protection.**  
   Every tar member is validated before extraction. Absolute paths,
   `..`-traversal, and links escaping the destination directory are
   rejected (`CVE-2007-4559` mitigation).

---

## Requirements

### Both platforms

| Tool      | Version                        | Install   |
| --------- | ------------------------------ | --------- |
| Python    | ≥ 3.10                         | system    |
| `age`     | **≥ 1.3.0**                    | see below |
| `openssl` | ≥ 3.5, _or_ 3.x + oqs-provider | see below |

> **age 1.3.0 is the minimum** because ML-KEM support (`age1pq1…`
> recipients) was introduced in that release (December 2025).

### macOS

```bash
brew install age
brew install openssl@3          # ships ML-DSA in 3.5+
```

If your Homebrew openssl is older than 3.5, also install the
[oqs-provider](https://github.com/open-quantum-safe/oqs-provider).

### Ubuntu

```bash
# age — use the system package on 24.10+ which ships 1.3;
# on older releases grab the static binary from GitHub releases.
sudo apt install age

# openssl 3.5 landed in Ubuntu 25.04+
sudo apt install openssl

# On older Ubuntu, install oqs-provider:
# https://github.com/open-quantum-safe/oqs-provider/releases
```

### Verify the stack is ready

```bash
pqcrypt status
```

Expected output:

```
OS:                 Linux (6.8.0-51-generic)
age:                /usr/bin/age  (age v1.3.0)
openssl:            /usr/bin/openssl  (OpenSSL 3.5.0 ...)
SD card:            /media/alice/PQKEYS  ✓
Encryption key:     /media/alice/PQKEYS/main.key.age  ✓
Encryption pub:     /home/alice/.config/pqcrypt/main.pub  ✓
Signing key:        /media/alice/PQKEYS/signing.key.pem  ✓
Signing pub:        /home/alice/.config/pqcrypt/signing.pub.pem  ✓
```

---

## Installation

```bash
# Install from PyPI
pip install pqcrypt

# Or install directly from GitHub (latest development version)
pip install git+https://github.com/xvi-xv-xii-ix-xxii-ix-xiv/pqcrypt.git
```

After installation, the `pqcrypt` command is globally available.

---

## Getting started

### Step 1 — Format the microSD

Format the card as **exFAT** with the label `PQKEYS` (readable on both
macOS and Linux without extra drivers).

> **💡 Recommended:** Use the official [SD Memory Card Formatter](https://www.sdcard.org/downloads/formatter/). This free tool from the SD Association ensures optimal performance and compliance with SD specifications, avoiding potential formatting errors that can occur with built-in OS tools.

**Alternative methods:**

**macOS:** Disk Utility → Erase → ExFAT, name `PQKEYS`.

**Linux:**

```bash
# Identify your card first — triple-check before mkfs!
lsblk -f
sudo mkfs.exfat -n PQKEYS /dev/sdX1
```

### Step 2 — Generate your encryption key

Insert the card, then:

```bash
pqcrypt init
```

You will be prompted **twice** for a passphrase (choose a strong one — a
6-word diceware phrase works well). The tool will:

- Generate a hybrid ML-KEM-768 + X25519 key pair.
- Write the **passphrase-encrypted** private identity to the card
  (`PQKEYS/main.key.age`).
- Cache the public recipient locally (`~/.config/pqcrypt/main.pub`).

### Step 3 — Generate your signing key _(optional)_

```bash
pqcrypt init-signing
```

You will be prompted for a passphrase to encrypt the ML-DSA-65 private
key. The public key is cached locally for offline verification.

> The signing key can use a **different passphrase** from the encryption
> key — this is recommended.

### Step 4 — Back up the SD card

```bash
# On Linux — create a bit-for-bit image backup
dd if=/dev/sdX of=~/pqkeys-backup.img bs=4M status=progress

# Store a second physical copy in a different location.
```

**Without a backup, losing the card means losing access to everything
encrypted with it.**

---

## Usage

### Encrypt a file

```bash
# SD card NOT required — uses the locally cached public recipient
pqcrypt encrypt ~/Documents/passport.pdf
# → ~/Documents/passport.pdf.age
```

### Encrypt a directory

```bash
pqcrypt encrypt ~/Projects/client-secrets/
# → ~/Projects/client-secrets.tar.gz.age
```

### Encrypt and sign in one step

```bash
# SD card IS required for signing (private signing key)
pqcrypt encrypt ~/Documents/passport.pdf --sign
# → ~/Documents/passport.pdf.age
# → ~/Documents/passport.pdf.age.sig
```

### Decrypt a file

```bash
# SD card required — you will be prompted for the encryption passphrase
pqcrypt decrypt ~/Documents/passport.pdf.age
# → ~/Documents/passport.pdf
```

### Decrypt and verify before decrypting

```bash
pqcrypt decrypt ~/Documents/passport.pdf.age --verify
# Aborts with exit code 1 if the signature is missing or invalid.
```

### Verify a signature without decrypting

```bash
# SD card NOT required — uses the locally cached public signing key
pqcrypt verify ~/Documents/passport.pdf.age
# Exit 0 = valid, exit 2 = invalid
```

### Custom output path

```bash
pqcrypt encrypt report.pdf -o /tmp/report_encrypted.pdf.age
pqcrypt decrypt report.pdf.age -o ~/safe/report.pdf
```

### Show file metadata

```bash
pqcrypt info passport.pdf.age
# Requires age-inspect (ships with age >= 1.3.0)
```

### Diagnostics

```bash
pqcrypt status
```

---

## File layout reference

| File              | Location             | Required for                  |
| ----------------- | -------------------- | ----------------------------- |
| `main.key.age`    | microSD              | Decryption                    |
| `signing.key.pem` | microSD              | Signing                       |
| `main.pub`        | `~/.config/pqcrypt/` | Encryption (no card needed)   |
| `signing.pub.pem` | `~/.config/pqcrypt/` | Verification (no card needed) |

| Extension     | Contents                     |
| ------------- | ---------------------------- |
| `.age`        | Single encrypted file        |
| `.tar.gz.age` | Encrypted directory archive  |
| `.sig`        | Detached ML-DSA-65 signature |

---

## Configuration via environment variables

| Variable             | Default      | Description                                              |
| -------------------- | ------------ | -------------------------------------------------------- |
| `PQCRYPT_SD_LABEL`   | `PQKEYS`     | Volume label of the microSD card                         |
| `PQCRYPT_AGE`        | `age`        | Path to the `age` binary                                 |
| `PQCRYPT_AGE_KEYGEN` | `age-keygen` | Path to `age-keygen`                                     |
| `PQCRYPT_OPENSSL`    | `openssl`    | Path to the `openssl` binary                             |
| `PQCRYPT_SIGN_ALG`   | `ML-DSA-65`  | ML-DSA variant (`ML-DSA-44` / `ML-DSA-65` / `ML-DSA-87`) |
| `XDG_CONFIG_HOME`    | `~/.config`  | Override the config cache directory                      |

Example — using a non-default label and a Homebrew openssl on macOS:

```bash
export PQCRYPT_SD_LABEL=MYKEYS
export PQCRYPT_OPENSSL=/opt/homebrew/opt/openssl@3/bin/openssl
pqcrypt status
```

---

## Running the tests

```bash
# Clone the repository first
git clone https://github.com/xvi-xv-xii-ix-xxii-ix-xiv/pqcrypt.git
cd pqcrypt

python -m unittest test_pqcrypt -v
```

The test suite has **53 tests** and no external dependencies — it does not
require `age` or `openssl` to be installed. Every subprocess call is
replaced by `unittest.mock`.

Coverage areas:

- SD card locator factory dispatching by OS
- Operation applicability and dispatcher ordering
- Default destination path computation
- Atomic-write invariants (failure, success, `KeyboardInterrupt`, existing destination)
- Path-traversal protection (absolute paths, `..`, symlinks, hardlinks)
- `OpenSSLBackend` pre-flight: ML-DSA present / absent / non-hyphenated form
- `Signer`: correct arguments, atomic `.sig` write, cleanup on failure, duplicate guard
- `Verifier`: True/False return, default `.sig` path, missing file errors
- `SigningKeyManager`: cache preference, SD fallback, `KeyMissingError`
- `EncryptCommand --sign` integration
- `DecryptCommand --verify` integration (abort on bad sig, proceed on good)
- `VerifyCommand` exit codes
- `Config` sanity (algorithm names, suffixes, minimum versions)

---

## Algorithm selection rationale

### Why ML-KEM-768 + X25519 (hybrid)?

- **ML-KEM-768** provides NIST security level 3 (~AES-192) against quantum
  adversaries.
- **X25519** provides classical Diffie-Hellman security.
- The hybrid KEM means an attacker must break **both** to compromise the
  key exchange. This protects against _harvest-now-decrypt-later_ attacks
  (recording ciphertexts today, decrypting them once a quantum computer
  exists) without abandoning time-tested classical security.
- The `age` specification for hybrid PQ recipients is published at
  https://age-encryption.org/v1 and the implementation has been publicly
  reviewed.

### Why ML-DSA-65?

- NIST security level 3 — a good balance of security and performance for
  personal use.
- If you need stronger guarantees (archival, high-value data), set
  `PQCRYPT_SIGN_ALG=ML-DSA-87` (level 5) — no other changes required.
- `-rawin` is passed to `openssl pkeyutl` because ML-DSA performs its own
  domain-separated hashing; pre-hashing the message externally would
  undermine that design.

---

## Threat model and limitations

### Protected against

- Passive adversary with classical or quantum computer intercepting stored
  files.
- Attacker who steals only the workstation (no card, no passphrase).
- Attacker who steals only the SD card (no passphrase).
- Maliciously crafted archives attempting path traversal.
- Tampered ciphertexts (with `--sign` / `--verify`).

### Not protected against

- Attacker with both the SD card **and** the passphrase.
- Malware running as the same user at the time of decryption (the cleartext
  is in memory / written to disk by your application, not by `pqcrypt`).
- Side-channel attacks on the CPU (ML-KEM is constant-time in `age`'s Go
  implementation; the Python wrapper itself does not perform any
  cryptographic operations).
- Loss of the SD card without a backup — this is an availability risk, not
  a confidentiality risk.

---

## Backup checklist

After `init` and `init-signing`, verify you have:

- [ ] Primary microSD card in a safe location.
- [ ] At least one physical backup card (bank safe-deposit box, trusted
      person off-site).
- [ ] Passphrases stored in a separate, offline password manager or written
      and stored securely (not with the card).
- [ ] A test decryption: encrypt a small test file, eject the card, reinsert
      it, decrypt, compare.
- [ ] Reminder in your calendar to re-test every 6 months.

---

## Contributing

Pull requests are welcome. Please:

1. Run `python -m unittest test_pqcrypt -v` — all tests must pass.
2. Add tests for any new behaviour.
3. Keep `pqcrypt.py` a single file with no third-party imports — the
   zero-dependency property is a feature.
4. Do not weaken the security invariants described above without a detailed
   justification in the PR description.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Acknowledgements

- [FiloSottile/age](https://github.com/FiloSottile/age) — the encryption
  engine powering this tool.
- [NIST PQC Standardisation](https://csrc.nist.gov/projects/post-quantum-cryptography) — ML-KEM (FIPS 203) and ML-DSA (FIPS 204).
- [Open Quantum Safe / oqs-provider](https://github.com/open-quantum-safe/oqs-provider) — OpenSSL provider for systems not yet on OpenSSL 3.5.
