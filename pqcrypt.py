#!/usr/bin/env python3
"""
pqcrypt — Post-Quantum file encryption & signing tool.

Encryption is delegated to the `age` CLI (>= 1.3.0), which provides hybrid
post-quantum file encryption (HPKE / ML-KEM-768 + X25519, NIST FIPS 203).
Signing is delegated to OpenSSL (>= 3.5, or any 3.x with the oqs-provider
loaded), using ML-DSA (NIST FIPS 204) for post-quantum digital signatures.

Both private keys live passphrase-encrypted on a removable microSD card.
The corresponding public keys are cached locally on each workstation so
that everyday `encrypt` / `verify` operations do not require the card.

Security invariants (do not relax these without thinking twice):
    1. Cleartext age identities are NEVER written to disk. They are
       streamed via OS pipes from one `age` subprocess (passphrase
       decryption) into the next (`age -d -i - <ciphertext>`).
    2. ML-DSA private keys are stored as OpenSSL PKCS#8 PEM encrypted
       with AES-256-CBC. The passphrase prompt happens inside openssl
       on /dev/tty; the cleartext key is never written by us.
    3. All output files are written atomically (tmp + rename).
    4. Tar extraction validates every member against path traversal.
    5. Encrypt-then-sign: the signature covers the ciphertext, so a
       verifier can detect tampering before decryption is attempted.

Cross-platform: macOS and Ubuntu Linux.

Usage:
    pqcrypt init                    # generate new encryption key on SD card
    pqcrypt init-signing            # generate new signing key on SD card
    pqcrypt encrypt PATH [--sign]   # encrypt file or directory
    pqcrypt decrypt PATH [--verify] # decrypt file or archive
    pqcrypt verify  PATH            # verify a detached signature
    pqcrypt info    PATH            # show metadata
    pqcrypt status                  # diagnostics
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Iterator, List, Optional, Type


# ════════════════════════════════════════════════════════════════════════════
# Exceptions
# ════════════════════════════════════════════════════════════════════════════

class PQCryptError(Exception):
    """Base class for all pqcrypt errors."""


class AgeMissingError(PQCryptError):
    """`age` or `age-keygen` is not on PATH."""


class AgeVersionError(PQCryptError):
    """Installed age does not support post-quantum recipients."""


class OpenSSLMissingError(PQCryptError):
    """`openssl` is not on PATH."""


class OpenSSLVersionError(PQCryptError):
    """Installed OpenSSL build does not expose ML-DSA."""


class SDCardNotFoundError(PQCryptError):
    """A microSD with the expected label is not mounted."""


class KeyMissingError(PQCryptError):
    """A required key file (private on SD, or public in cache) is missing."""


class OperationFailedError(PQCryptError):
    """An encrypt / decrypt / sign / verify subprocess failed."""


class UnsafeArchiveError(PQCryptError):
    """A tar member tries to escape the extraction directory."""


class SignatureInvalidError(PQCryptError):
    """A signature did not verify against the public key."""


# ════════════════════════════════════════════════════════════════════════════
# Configuration  (Frozen Dataclass — single immutable source of truth)
# ════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class Config:
    """All tunables in one place. Override via env vars where useful."""
    # SD card
    sd_label: str = os.environ.get("PQCRYPT_SD_LABEL", "PQKEYS")

    # Encryption (age / ML-KEM-768 + X25519)
    age_bin: str = os.environ.get("PQCRYPT_AGE", "age")
    keygen_bin: str = os.environ.get("PQCRYPT_AGE_KEYGEN", "age-keygen")
    min_age_version: tuple = (1, 3, 0)
    key_filename: str = "main.key.age"
    pub_filename: str = "main.pub"
    encrypted_suffix: str = ".age"
    archive_suffix: str = ".tar.gz.age"

    # Signing (OpenSSL / ML-DSA)
    openssl_bin: str = os.environ.get("PQCRYPT_OPENSSL", "openssl")
    signing_algorithm: str = os.environ.get("PQCRYPT_SIGN_ALG", "ML-DSA-65")
    signing_key_filename: str = "signing.key.pem"
    signing_pub_filename: str = "signing.pub.pem"
    signature_suffix: str = ".sig"

    # Local cache
    config_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
        ) / "pqcrypt"
    )

    @property
    def pub_cache(self) -> Path:
        return self.config_dir / self.pub_filename

    @property
    def signing_pub_cache(self) -> Path:
        return self.config_dir / self.signing_pub_filename


CONFIG = Config()


# ════════════════════════════════════════════════════════════════════════════
# SD Card Locator   (Strategy + Factory)
# ════════════════════════════════════════════════════════════════════════════

class SDCardLocator(ABC):
    @abstractmethod
    def find(self, label: str) -> Optional[Path]: ...


class _MacOSLocator(SDCardLocator):
    def find(self, label: str) -> Optional[Path]:
        candidate = Path("/Volumes") / label
        return candidate if candidate.is_dir() else None


class _LinuxLocator(SDCardLocator):
    def find(self, label: str) -> Optional[Path]:
        user = os.environ.get("USER", "")
        for base in (Path("/media") / user,
                     Path("/run/media") / user,
                     Path("/mnt")):
            candidate = base / label
            if candidate.is_dir():
                return candidate
        return None


class SDCardLocatorFactory:
    """Pick the right locator strategy for the host OS."""
    @staticmethod
    def create() -> SDCardLocator:
        system = platform.system()
        if system == "Darwin":
            return _MacOSLocator()
        if system == "Linux":
            return _LinuxLocator()
        raise PQCryptError(f"Unsupported platform: {system}")


# ════════════════════════════════════════════════════════════════════════════
# Age Backend  (Facade for the encryption tool)
# ════════════════════════════════════════════════════════════════════════════

class AgeBackend:
    """
    Centralises every subprocess invocation of `age` / `age-keygen`. The rest
    of the program never imports `subprocess` for these calls and never
    assembles argv arrays — that's the point of the Facade pattern here.
    """

    _VERSION_RE = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")

    def __init__(self,
                 age_bin: str = CONFIG.age_bin,
                 keygen_bin: str = CONFIG.keygen_bin):
        self.age = age_bin
        self.keygen = keygen_bin
        self._check_installed()
        self._check_version()

    # ── Pre-flight ─────────────────────────────────────────────────────

    def _check_installed(self) -> None:
        for binary in (self.age, self.keygen):
            if shutil.which(binary) is None:
                raise AgeMissingError(
                    f"'{binary}' not found in PATH.\n"
                    "  Install: `brew install age`  (macOS)\n"
                    "           `apt install age`   (Ubuntu)"
                )

    def _check_version(self) -> None:
        result = subprocess.run(
            [self.age, "--version"],
            capture_output=True, text=True, check=False,
        )
        match = self._VERSION_RE.search(result.stdout + result.stderr)
        if not match:
            raise AgeVersionError(
                f"Cannot parse age version from: "
                f"{result.stdout!r} {result.stderr!r}"
            )
        version = tuple(int(x) for x in match.groups())
        if version < CONFIG.min_age_version:
            need = ".".join(map(str, CONFIG.min_age_version))
            have = ".".join(map(str, version))
            raise AgeVersionError(
                f"age {have} is too old; need >= {need} for ML-KEM "
                "recipients.\n"
                "  Upgrade: `brew upgrade age` or download from "
                "https://github.com/FiloSottile/age/releases"
            )

    # ── Key generation ──────────────────────────────────────────────────

    def generate_pq_identity(self) -> bytes:
        """Run `age-keygen -pq`. Returns the cleartext identity file."""
        try:
            return subprocess.run(
                [self.keygen, "-pq"],
                capture_output=True, check=True,
            ).stdout
        except subprocess.CalledProcessError as e:
            raise OperationFailedError(
                f"age-keygen failed: {e.stderr.decode(errors='replace')}"
            ) from e

    def derive_recipient(self, identity: bytes) -> bytes:
        try:
            return subprocess.run(
                [self.keygen, "-y"],
                input=identity, capture_output=True, check=True,
            ).stdout
        except subprocess.CalledProcessError as e:
            raise OperationFailedError("Failed to derive public key") from e

    def passphrase_encrypt_to_file(self, data: bytes, dst: Path) -> None:
        """`age -p -o dst`. age prompts on /dev/tty for the passphrase."""
        try:
            subprocess.run(
                [self.age, "-p", "-o", str(dst)],
                input=data, check=True,
            )
        except subprocess.CalledProcessError as e:
            raise OperationFailedError("Passphrase encryption failed") from e

    # ── Public-key encryption ───────────────────────────────────────────

    def encrypt_to_recipient(self,
                             recipient_file: Path,
                             stdin: Optional[IO[bytes]],
                             stdout: IO[bytes]) -> None:
        try:
            subprocess.run(
                [self.age, "-R", str(recipient_file)],
                stdin=stdin, stdout=stdout, check=True,
            )
        except subprocess.CalledProcessError as e:
            raise OperationFailedError(f"Encryption failed: {e}") from e

    def spawn_encrypt_to_recipient(self,
                                   recipient_file: Path,
                                   stdout: IO[bytes]) -> subprocess.Popen:
        """Returns Popen so the caller can stream into .stdin (tarfile)."""
        return subprocess.Popen(
            [self.age, "-R", str(recipient_file)],
            stdin=subprocess.PIPE, stdout=stdout,
        )

    # ── Decryption — security-critical part ─────────────────────────────
    #
    # Two age processes are wired together by an OS pipe:
    #
    #   age -d ENCRYPTED_KEY ──pipe──► age -d -i - CIPHERTEXT ──► plaintext
    #         (asks passphrase            (reads identity from stdin)
    #          on /dev/tty)
    #
    # The cleartext identity exists only as bytes flowing through that pipe
    # — never as a file. If the user mistypes the passphrase, the first
    # process exits non-zero, the second sees an empty/short identity and
    # also exits non-zero; we surface a clear error.

    @contextmanager
    def decrypted_identity_pipe(self,
                                encrypted_identity: Path
                                ) -> Iterator[IO[bytes]]:
        """Yield a readable pipe carrying the cleartext identity."""
        proc = subprocess.Popen(
            [self.age, "-d", str(encrypted_identity)],
            stdout=subprocess.PIPE,
        )
        try:
            assert proc.stdout is not None
            yield proc.stdout
        finally:
            if proc.stdout and not proc.stdout.closed:
                proc.stdout.close()
            proc.wait()
            if proc.returncode != 0:
                raise OperationFailedError(
                    "Could not decrypt the private identity "
                    "(wrong passphrase, or the key file is corrupted)."
                )

    def decrypt_with_identity(self,
                              identity_stream: IO[bytes],
                              src: Path,
                              stdout: IO[bytes]) -> None:
        try:
            subprocess.run(
                [self.age, "-d", "-i", "-", str(src)],
                stdin=identity_stream, stdout=stdout, check=True,
            )
        except subprocess.CalledProcessError as e:
            raise OperationFailedError(f"Decryption failed: {e}") from e

    def spawn_decrypt_with_identity(self,
                                    identity_stream: IO[bytes],
                                    src: Path) -> subprocess.Popen:
        return subprocess.Popen(
            [self.age, "-d", "-i", "-", str(src)],
            stdin=identity_stream, stdout=subprocess.PIPE,
        )

    # ── Inspection ──────────────────────────────────────────────────────

    def inspect(self, src: Path) -> str:
        if shutil.which("age-inspect"):
            try:
                return subprocess.run(
                    ["age-inspect", str(src)],
                    capture_output=True, text=True, check=True,
                ).stdout
            except subprocess.CalledProcessError as e:
                return f"age-inspect failed: {e.stderr or e}"
        return (f"(age-inspect not installed — basic info only)\n"
                f"path: {src}\n"
                f"size: {src.stat().st_size} bytes")


# ════════════════════════════════════════════════════════════════════════════
# OpenSSL Backend  (Facade for the signing tool)
# ════════════════════════════════════════════════════════════════════════════

class OpenSSLBackend:
    """
    Facade for ML-DSA signing/verification via the `openssl` CLI.

    Requires either OpenSSL >= 3.5 (which ships ML-DSA / ML-KEM natively) or
    an older 3.x with the oqs-provider configured. We don't care which one
    — we probe `openssl list -signature-algorithms` and only fail if the
    algorithm is genuinely unavailable.
    """

    def __init__(self, openssl_bin: str = CONFIG.openssl_bin):
        self.openssl = openssl_bin
        self._check_installed()
        self._check_ml_dsa_available()

    # ── Pre-flight ─────────────────────────────────────────────────────

    def _check_installed(self) -> None:
        if shutil.which(self.openssl) is None:
            raise OpenSSLMissingError(
                f"'{self.openssl}' not found in PATH.\n"
                "  Install: `brew install openssl@3`  (macOS)\n"
                "           `apt install openssl`     (Ubuntu)"
            )

    def _check_ml_dsa_available(self) -> None:
        result = subprocess.run(
            [self.openssl, "list", "-signature-algorithms"],
            capture_output=True, text=True, check=False,
        )
        haystack = (result.stdout + result.stderr).upper()
        if "ML-DSA" not in haystack and "MLDSA" not in haystack:
            raise OpenSSLVersionError(
                "Your OpenSSL build does not expose ML-DSA.\n"
                "  Need OpenSSL >= 3.5, or an older 3.x with the\n"
                "  oqs-provider loaded (set OPENSSL_MODULES or edit "
                "openssl.cnf).\n"
                "  See: https://github.com/open-quantum-safe/oqs-provider"
            )

    # ── Key generation ──────────────────────────────────────────────────

    def generate_signing_keypair(self,
                                 encrypted_priv_path: Path,
                                 pub_path: Path,
                                 algorithm: str = CONFIG.signing_algorithm
                                 ) -> None:
        """
        Generate an ML-DSA key pair.

        The private key is written as PKCS#8 PEM encrypted with AES-256-CBC,
        passphrase prompted by openssl on /dev/tty. The public key is
        derived in a separate step (openssl will prompt once for the
        passphrase to read the private key).
        """
        try:
            subprocess.run(
                [self.openssl, "genpkey",
                 "-algorithm", algorithm,
                 "-aes-256-cbc",
                 "-out", str(encrypted_priv_path)],
                check=True,
            )
        except subprocess.CalledProcessError as e:
            raise OperationFailedError(
                f"Signing key generation failed: {e}"
            ) from e

        try:
            subprocess.run(
                [self.openssl, "pkey",
                 "-in", str(encrypted_priv_path),
                 "-pubout",
                 "-out", str(pub_path)],
                check=True,
            )
        except subprocess.CalledProcessError as e:
            raise OperationFailedError(
                f"Public key derivation failed: {e}"
            ) from e

    # ── Signing & verification ──────────────────────────────────────────

    def sign_file(self,
                  encrypted_priv: Path,
                  src: Path,
                  sig_dst: Path) -> None:
        """
        Produce a detached signature with `openssl pkeyutl -sign -rawin`.

        `-rawin` is required for ML-DSA: the algorithm performs its own
        message hashing, so we must hand it the raw bytes (not a digest).
        openssl will prompt for the private-key passphrase on /dev/tty.
        """
        try:
            subprocess.run(
                [self.openssl, "pkeyutl", "-sign",
                 "-inkey", str(encrypted_priv),
                 "-rawin",
                 "-in", str(src),
                 "-out", str(sig_dst)],
                check=True,
            )
        except subprocess.CalledProcessError as e:
            raise OperationFailedError(
                "Signing failed (wrong passphrase or I/O error)."
            ) from e

    def verify_file(self,
                    public_key: Path,
                    src: Path,
                    sig: Path) -> bool:
        """
        Returns True if the detached signature `sig` is valid for `src`
        under the public key `public_key`. Returns False on signature
        mismatch; raises on hard errors (missing files, broken openssl).
        """
        result = subprocess.run(
            [self.openssl, "pkeyutl", "-verify",
             "-pubin",
             "-inkey", str(public_key),
             "-rawin",
             "-in", str(src),
             "-sigfile", str(sig)],
            capture_output=True, text=True, check=False,
        )
        # openssl pkeyutl exits 0 on success and prints "Signature Verified
        # Successfully" (3.0+) or similar. On bad sig, exit code is non-zero.
        if result.returncode == 0:
            return True
        # Distinguish "bad signature" from "broken invocation" by looking
        # at stderr. Anything that mentions verification is a soft fail.
        combined = (result.stdout + result.stderr).lower()
        if "verification" in combined or "failure" in combined:
            return False
        # Otherwise something else is wrong (missing key file, bad PEM, …).
        raise OperationFailedError(
            f"openssl pkeyutl -verify failed unexpectedly: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )


# ════════════════════════════════════════════════════════════════════════════
# Key Managers
#
# Two thin classes own the on-disk layout for the two key kinds. They share
# the SD-card locator but otherwise stay separate — different key types,
# different passphrases, different lifecycles (signing is optional).
# ════════════════════════════════════════════════════════════════════════════

class _SDStore:
    """Mixin: a class that knows where the SD card is."""

    def __init__(self,
                 locator: Optional[SDCardLocator],
                 config: Config):
        self._locator = locator or SDCardLocatorFactory.create()
        self._config = config

    def sd_root(self) -> Path:
        path = self._locator.find(self._config.sd_label)
        if path is None:
            raise SDCardNotFoundError(
                f"microSD with label '{self._config.sd_label}' is not "
                "mounted.\n"
                "  Insert the card or check the label "
                "(`diskutil list` on macOS, `lsblk -f` on Linux)."
            )
        return path


class KeyManager(_SDStore):
    """Owns the encryption (age) keypair: private on SD, public cached."""

    def __init__(self,
                 backend: AgeBackend,
                 locator: Optional[SDCardLocator] = None,
                 config: Config = CONFIG):
        super().__init__(locator, config)
        self._backend = backend

    def encrypted_identity_path(self) -> Path:
        path = self.sd_root() / self._config.key_filename
        if not path.is_file():
            raise KeyMissingError(
                f"Encrypted identity not found on SD card: {path}\n"
                "  Run `pqcrypt init` first."
            )
        return path

    def public_recipient_path(self) -> Path:
        path = self._config.pub_cache
        if not path.is_file():
            raise KeyMissingError(
                f"Public recipient cache is missing: {path}\n"
                "  Run `pqcrypt init`, or copy main.pub from the SD card to "
                f"{path}."
            )
        return path

    def initialize(self, force: bool = False) -> None:
        sd = self.sd_root()
        encrypted_key = sd / self._config.key_filename
        sd_pub = sd / self._config.pub_filename

        if encrypted_key.exists() and not force:
            raise PQCryptError(
                f"{encrypted_key} already exists. Use --force to overwrite.\n"
                "  WARNING: overwriting destroys access to anything "
                "encrypted with the previous key."
            )

        identity: Optional[bytes] = None
        try:
            print("→ Generating post-quantum identity "
                  "(ML-KEM-768 + X25519)…")
            identity = self._backend.generate_pq_identity()

            print("→ Deriving public recipient…")
            recipient = self._backend.derive_recipient(identity)

            print(f"→ Writing public recipient to SD card:  {sd_pub}")
            sd_pub.write_bytes(recipient)
            try:
                sd_pub.chmod(0o644)
            except OSError:
                pass  # exFAT does not honour POSIX modes — that is fine

            print(f"→ Caching public recipient locally:      "
                  f"{self._config.pub_cache}")
            self._config.pub_cache.parent.mkdir(parents=True, exist_ok=True)
            self._config.pub_cache.write_bytes(recipient)
            self._config.pub_cache.chmod(0o644)

            print(f"→ Encrypting private identity to:        {encrypted_key}")
            print("  (you will be prompted twice for the passphrase)")
            self._backend.passphrase_encrypt_to_file(identity, encrypted_key)
            try:
                encrypted_key.chmod(0o600)
            except OSError:
                pass

            print()
            print("✓ Encryption key initialization complete.")
            print()
            print("Recipient (public, safe to share):")
            print("  " + recipient.decode().strip())
            print()
            print("⚠  Make at least one backup of this SD card NOW.")
            print("⚠  Store the passphrase in a separate, secure location.")
            print("⚠  Without both, encrypted files are unrecoverable.")
        finally:
            # Best-effort: erase the in-memory copy of the cleartext key.
            if identity is not None:
                try:
                    identity = b"\x00" * len(identity)  # noqa: F841
                except Exception:
                    pass
                del identity


class SigningKeyManager(_SDStore):
    """Owns the ML-DSA signing keypair (optional; only used with --sign)."""

    def __init__(self,
                 backend: OpenSSLBackend,
                 locator: Optional[SDCardLocator] = None,
                 config: Config = CONFIG):
        super().__init__(locator, config)
        self._backend = backend

    def encrypted_signing_key_path(self) -> Path:
        path = self.sd_root() / self._config.signing_key_filename
        if not path.is_file():
            raise KeyMissingError(
                f"Signing private key not found on SD card: {path}\n"
                "  Run `pqcrypt init-signing` first."
            )
        return path

    def signing_pub_path(self) -> Path:
        """Prefer local cache; fall back to SD card if it's mounted."""
        cached = self._config.signing_pub_cache
        if cached.is_file():
            return cached
        try:
            on_sd = self.sd_root() / self._config.signing_pub_filename
            if on_sd.is_file():
                return on_sd
        except SDCardNotFoundError:
            pass
        raise KeyMissingError(
            f"Signing public key is missing: {cached}\n"
            "  Run `pqcrypt init-signing`, or copy "
            f"{self._config.signing_pub_filename} from the SD card to "
            f"{cached}."
        )

    def initialize(self, force: bool = False) -> None:
        sd = self.sd_root()
        priv_path = sd / self._config.signing_key_filename
        sd_pub = sd / self._config.signing_pub_filename

        if priv_path.exists() and not force:
            raise PQCryptError(
                f"{priv_path} already exists. Use --force to overwrite.\n"
                "  WARNING: overwriting invalidates every existing "
                "signature you produced with the previous key."
            )

        print(f"→ Generating {self._config.signing_algorithm} signing "
              "keypair…")
        print("  (you will be prompted for a passphrase to encrypt the "
              "private key)")
        self._backend.generate_signing_keypair(
            priv_path, sd_pub, self._config.signing_algorithm,
        )
        try:
            priv_path.chmod(0o600)
            sd_pub.chmod(0o644)
        except OSError:
            pass

        print(f"→ Caching signing public key locally:    "
              f"{self._config.signing_pub_cache}")
        self._config.signing_pub_cache.parent.mkdir(parents=True,
                                                    exist_ok=True)
        shutil.copyfile(sd_pub, self._config.signing_pub_cache)
        self._config.signing_pub_cache.chmod(0o644)

        print()
        print("✓ Signing key initialization complete.")
        print()
        print("⚠  Back up the SD card now (the signing key cannot be "
              "recovered).")


# ════════════════════════════════════════════════════════════════════════════
# Crypto Operations  (Template Method)
# ════════════════════════════════════════════════════════════════════════════

class CryptoOperation(ABC):
    def __init__(self, backend: AgeBackend, key_manager: KeyManager):
        self._backend = backend
        self._km = key_manager

    @abstractmethod
    def applies_to(self, src: Path) -> bool: ...

    @abstractmethod
    def default_destination(self, src: Path) -> Path: ...

    @abstractmethod
    def _do_execute(self, src: Path, tmp_dst: Path) -> None: ...

    def execute(self, src: Path, dst: Optional[Path]) -> Path:
        if dst is None:
            dst = self.default_destination(src)
        if dst.exists():
            raise PQCryptError(f"Destination already exists: {dst}")
        dst.parent.mkdir(parents=True, exist_ok=True)
        tmp = dst.with_name(dst.name + ".part")
        try:
            self._do_execute(src, tmp)
            tmp.rename(dst)  # atomic on POSIX same-fs
            return dst
        except BaseException:
            # Be paranoid: on any error, including KeyboardInterrupt,
            # do not leave a half-written file with a confusing name.
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass
            raise


class FileEncryptor(CryptoOperation):
    def applies_to(self, src: Path) -> bool:
        return src.is_file()

    def default_destination(self, src: Path) -> Path:
        return src.with_name(src.name + CONFIG.encrypted_suffix)

    def _do_execute(self, src: Path, tmp_dst: Path) -> None:
        recipient = self._km.public_recipient_path()
        with open(src, "rb") as fin, open(tmp_dst, "wb") as fout:
            self._backend.encrypt_to_recipient(recipient, fin, fout)


class DirectoryEncryptor(CryptoOperation):
    """Stream tar.gz directly into age — no on-disk intermediate archive."""

    def applies_to(self, src: Path) -> bool:
        return src.is_dir()

    def default_destination(self, src: Path) -> Path:
        return src.parent / (src.name + CONFIG.archive_suffix)

    def _do_execute(self, src: Path, tmp_dst: Path) -> None:
        recipient = self._km.public_recipient_path()
        with open(tmp_dst, "wb") as fout:
            age_proc = self._backend.spawn_encrypt_to_recipient(recipient,
                                                                fout)
            try:
                # `w|gz` is the streaming mode — no random seeks needed,
                # which lets us write directly into the pipe.
                with tarfile.open(fileobj=age_proc.stdin, mode="w|gz") as tar:
                    tar.add(src, arcname=src.name)
            finally:
                if age_proc.stdin and not age_proc.stdin.closed:
                    age_proc.stdin.close()
                rc = age_proc.wait()
            if rc != 0:
                raise OperationFailedError(f"age (encrypt) exited with {rc}")


class FileDecryptor(CryptoOperation):
    """Decrypt a single .age file (not a .tar.gz.age archive)."""

    def applies_to(self, src: Path) -> bool:
        return (src.is_file()
                and src.suffix == CONFIG.encrypted_suffix
                and not src.name.endswith(CONFIG.archive_suffix))

    def default_destination(self, src: Path) -> Path:
        return src.with_suffix("")  # strip ".age"

    def _do_execute(self, src: Path, tmp_dst: Path) -> None:
        encrypted_id = self._km.encrypted_identity_path()
        with self._backend.decrypted_identity_pipe(encrypted_id) as id_stream:
            with open(tmp_dst, "wb") as fout:
                self._backend.decrypt_with_identity(id_stream, src, fout)


class ArchiveDecryptor(CryptoOperation):
    """Decrypt a .tar.gz.age archive and extract it into a directory."""

    def applies_to(self, src: Path) -> bool:
        return src.is_file() and src.name.endswith(CONFIG.archive_suffix)

    def default_destination(self, src: Path) -> Path:
        # /a/b/foo.tar.gz.age  →  /a/b/foo
        stem = src.name[: -len(CONFIG.archive_suffix)]
        return src.parent / stem

    def execute(self, src: Path, dst: Optional[Path]) -> Path:
        # Override: archives extract to a directory, not a single file,
        # so the tmp+rename idiom uses a directory.
        if dst is None:
            dst = self.default_destination(src)
        if dst.exists():
            raise PQCryptError(f"Destination already exists: {dst}")
        tmp_dir = dst.with_name(dst.name + ".part")
        if tmp_dir.exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)
        tmp_dir.mkdir(parents=True)
        try:
            self._do_execute(src, tmp_dir)
            tmp_dir.rename(dst)
            return dst
        except BaseException:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise

    def _do_execute(self, src: Path, tmp_dst: Path) -> None:
        encrypted_id = self._km.encrypted_identity_path()
        with self._backend.decrypted_identity_pipe(encrypted_id) as id_stream:
            age_proc = self._backend.spawn_decrypt_with_identity(id_stream,
                                                                 src)
            try:
                assert age_proc.stdout is not None
                with tarfile.open(fileobj=age_proc.stdout, mode="r|gz") as tar:
                    self._safe_extract(tar, tmp_dst)
            finally:
                if age_proc.stdout and not age_proc.stdout.closed:
                    age_proc.stdout.close()
                rc = age_proc.wait()
            if rc != 0:
                raise OperationFailedError(f"age (decrypt) exited with {rc}")

    @staticmethod
    def _safe_extract(tar: tarfile.TarFile, dst: Path) -> None:
        """
        Extract while rejecting absolute paths, '..' traversal, and
        symlink / hardlink members that point outside `dst`.
        Mitigates CVE-2007-4559.
        """
        dst_resolved = dst.resolve()
        for member in tar:
            target = (dst / member.name).resolve()
            try:
                target.relative_to(dst_resolved)
            except ValueError as e:
                raise UnsafeArchiveError(
                    f"Refusing to extract '{member.name}' — would escape "
                    "destination directory."
                ) from e
            if member.issym() or member.islnk():
                link_target = (dst / member.name).parent / member.linkname
                try:
                    link_target.resolve().relative_to(dst_resolved)
                except ValueError as e:
                    raise UnsafeArchiveError(
                        f"Refusing to extract link '{member.name}' → "
                        f"'{member.linkname}'."
                    ) from e
        tar.extractall(dst)


# ════════════════════════════════════════════════════════════════════════════
# Signer / Verifier
#
# Orthogonal to encryption: signing always covers the *ciphertext*, so
# verification works with only the public signing key (no SD card needed,
# no encryption passphrase needed).
# ════════════════════════════════════════════════════════════════════════════

class Signer:
    def __init__(self,
                 backend: OpenSSLBackend,
                 key_manager: SigningKeyManager):
        self._backend = backend
        self._km = key_manager

    def sign(self, src: Path) -> Path:
        """Produce a detached <src>.sig next to src. Returns its path."""
        if not src.is_file():
            raise PQCryptError(f"Cannot sign — not a file: {src}")
        sig_path = src.with_name(src.name + CONFIG.signature_suffix)
        if sig_path.exists():
            raise PQCryptError(f"Signature already exists: {sig_path}")
        encrypted_key = self._km.encrypted_signing_key_path()
        tmp = sig_path.with_name(sig_path.name + ".part")
        try:
            self._backend.sign_file(encrypted_key, src, tmp)
            tmp.rename(sig_path)
            return sig_path
        except BaseException:
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass
            raise


class Verifier:
    def __init__(self,
                 backend: OpenSSLBackend,
                 key_manager: SigningKeyManager):
        self._backend = backend
        self._km = key_manager

    def verify(self, src: Path, sig: Optional[Path] = None) -> bool:
        if sig is None:
            sig = src.with_name(src.name + CONFIG.signature_suffix)
        if not src.is_file():
            raise PQCryptError(f"File to verify not found: {src}")
        if not sig.is_file():
            raise PQCryptError(f"Signature file not found: {sig}")
        public_key = self._km.signing_pub_path()
        return self._backend.verify_file(public_key, src, sig)


# ════════════════════════════════════════════════════════════════════════════
# Operation Dispatcher  (small Chain-of-Responsibility)
# ════════════════════════════════════════════════════════════════════════════

class OperationDispatcher:
    def __init__(self, ops: List[CryptoOperation]):
        self._ops = ops

    def dispatch(self, src: Path) -> CryptoOperation:
        for op in self._ops:
            if op.applies_to(src):
                return op
        raise PQCryptError(
            f"No applicable operation for: {src}\n"
            "  (expected an existing file or directory; or a *.age / "
            "*.tar.gz.age file for decrypt)"
        )


# ════════════════════════════════════════════════════════════════════════════
# CLI Commands  (Command pattern)
# ════════════════════════════════════════════════════════════════════════════

class Command(ABC):
    name: str = ""
    help: str = ""

    @classmethod
    @abstractmethod
    def configure(cls, parser: argparse.ArgumentParser) -> None: ...

    @abstractmethod
    def run(self, args: argparse.Namespace) -> int: ...


class InitCommand(Command):
    name = "init"
    help = "Generate a new post-quantum encryption key on the SD card."

    @classmethod
    def configure(cls, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--force", action="store_true",
                            help="Overwrite an existing key on the SD card.")

    def run(self, args: argparse.Namespace) -> int:
        backend = AgeBackend()
        KeyManager(backend).initialize(force=args.force)
        return 0


class InitSigningCommand(Command):
    name = "init-signing"
    help = "Generate a new ML-DSA signing key on the SD card (optional)."

    @classmethod
    def configure(cls, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--force", action="store_true",
                            help="Overwrite an existing signing key on the "
                                 "SD card.")

    def run(self, args: argparse.Namespace) -> int:
        backend = OpenSSLBackend()
        SigningKeyManager(backend).initialize(force=args.force)
        return 0


class EncryptCommand(Command):
    name = "encrypt"
    help = "Encrypt a file or directory to your public recipient."

    @classmethod
    def configure(cls, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("path", type=Path,
                            help="File or directory to encrypt.")
        parser.add_argument("-o", "--output", type=Path, default=None,
                            help="Output path (default: <input>.age or "
                                 "<input>.tar.gz.age).")
        parser.add_argument("--sign", action="store_true",
                            help="Also produce a detached ML-DSA signature "
                                 "of the ciphertext (requires SD card and "
                                 "signing-key passphrase).")

    def run(self, args: argparse.Namespace) -> int:
        if not args.path.exists():
            raise PQCryptError(f"Path not found: {args.path}")
        backend = AgeBackend()
        km = KeyManager(backend)
        dispatcher = OperationDispatcher([
            DirectoryEncryptor(backend, km),
            FileEncryptor(backend, km),
        ])
        op = dispatcher.dispatch(args.path)
        result = op.execute(args.path, args.output)
        print(f"✓ {args.path}  →  {result}")

        if args.sign:
            openssl = OpenSSLBackend()
            skm = SigningKeyManager(openssl)
            signer = Signer(openssl, skm)
            sig = signer.sign(result)
            print(f"  signature  →  {sig}")
        return 0


class DecryptCommand(Command):
    name = "decrypt"
    help = ("Decrypt a .age file or .tar.gz.age archive "
            "(requires the SD card).")

    @classmethod
    def configure(cls, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("path", type=Path,
                            help="Encrypted file to decrypt.")
        parser.add_argument("-o", "--output", type=Path, default=None,
                            help="Output path or directory.")
        parser.add_argument("--verify", action="store_true",
                            help="Verify a detached ML-DSA signature "
                                 "BEFORE decrypting; abort if invalid or "
                                 "missing.")

    def run(self, args: argparse.Namespace) -> int:
        if not args.path.is_file():
            raise PQCryptError(f"Not a file: {args.path}")

        # Verify-then-decrypt order is intentional: never decrypt content
        # whose authenticity we already know is broken.
        if args.verify:
            openssl = OpenSSLBackend()
            skm = SigningKeyManager(openssl)
            verifier = Verifier(openssl, skm)
            if not verifier.verify(args.path):
                raise SignatureInvalidError(
                    f"Signature verification FAILED for {args.path}\n"
                    "  Refusing to decrypt — file may have been tampered "
                    "with."
                )
            print(f"✓ Signature verified for {args.path}")

        backend = AgeBackend()
        km = KeyManager(backend)
        dispatcher = OperationDispatcher([
            ArchiveDecryptor(backend, km),  # archive first (more specific)
            FileDecryptor(backend, km),
        ])
        op = dispatcher.dispatch(args.path)
        result = op.execute(args.path, args.output)
        print(f"✓ {args.path}  →  {result}")
        return 0


class VerifyCommand(Command):
    name = "verify"
    help = "Verify a detached ML-DSA signature (no decryption)."

    @classmethod
    def configure(cls, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("path", type=Path,
                            help="The (typically encrypted) file whose "
                                 "signature to verify.")
        parser.add_argument("--sig", type=Path, default=None,
                            help="Signature file (default: <path>.sig).")

    def run(self, args: argparse.Namespace) -> int:
        openssl = OpenSSLBackend()
        skm = SigningKeyManager(openssl)
        verifier = Verifier(openssl, skm)
        ok = verifier.verify(args.path, args.sig)
        if ok:
            print(f"✓ Signature is valid for {args.path}")
            return 0
        print(f"✗ Signature is INVALID for {args.path}", file=sys.stderr)
        return 2


class InfoCommand(Command):
    name = "info"
    help = "Show metadata of an encrypted file."

    @classmethod
    def configure(cls, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("path", type=Path)

    def run(self, args: argparse.Namespace) -> int:
        if not args.path.is_file():
            raise PQCryptError(f"Not a file: {args.path}")
        print(AgeBackend().inspect(args.path))
        return 0


class StatusCommand(Command):
    name = "status"
    help = "Show diagnostics: OS, age/openssl versions, SD card, keys."

    @classmethod
    def configure(cls, parser: argparse.ArgumentParser) -> None:
        pass

    def run(self, args: argparse.Namespace) -> int:
        print(f"OS:                 {platform.system()} "
              f"({platform.release()})")

        # Encryption stack
        try:
            age_backend = AgeBackend()
            ver = subprocess.run(
                [age_backend.age, "--version"],
                capture_output=True, text=True,
            ).stdout.strip()
            print(f"age:                {shutil.which(age_backend.age)}  "
                  f"({ver})")
        except PQCryptError as e:
            print(f"age:                ERROR — {e}")
            return 1

        # Signing stack (optional — don't fail if absent)
        ossl_backend: Optional[OpenSSLBackend]
        try:
            ossl_backend = OpenSSLBackend()
            ver = subprocess.run(
                [ossl_backend.openssl, "version"],
                capture_output=True, text=True,
            ).stdout.strip()
            print(f"openssl:            "
                  f"{shutil.which(ossl_backend.openssl)}  ({ver})")
        except PQCryptError as e:
            ossl_backend = None
            print(f"openssl:            unavailable — {e}")

        # SD card & keys
        km = KeyManager(age_backend)
        try:
            sd = km.sd_root()
            print(f"SD card:            {sd}  ✓")
        except SDCardNotFoundError:
            print(f"SD card:            not mounted "
                  f"(label='{CONFIG.sd_label}')")
        try:
            ek = km.encrypted_identity_path()
            print(f"Encryption key:     {ek}  ✓")
        except (SDCardNotFoundError, KeyMissingError):
            print("Encryption key:     unavailable")
        try:
            pk = km.public_recipient_path()
            print(f"Encryption pub:     {pk}  ✓")
        except KeyMissingError:
            print(f"Encryption pub:     missing  ({CONFIG.pub_cache})")

        if ossl_backend is not None:
            skm = SigningKeyManager(ossl_backend)
            try:
                sk = skm.encrypted_signing_key_path()
                print(f"Signing key:        {sk}  ✓")
            except (SDCardNotFoundError, KeyMissingError):
                print("Signing key:        unavailable (signing optional)")
            try:
                spk = skm.signing_pub_path()
                print(f"Signing pub:        {spk}  ✓")
            except KeyMissingError:
                print(f"Signing pub:        missing  "
                      f"({CONFIG.signing_pub_cache})")
        return 0


COMMANDS: List[Type[Command]] = [
    InitCommand,
    InitSigningCommand,
    EncryptCommand,
    DecryptCommand,
    VerifyCommand,
    InfoCommand,
    StatusCommand,
]


# ════════════════════════════════════════════════════════════════════════════
# Entry point
# ════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pqcrypt",
        description=("Post-quantum file encryption & signing tool "
                     "(age / ML-KEM-768 + X25519 ; openssl / ML-DSA)."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)
    for cmd_cls in COMMANDS:
        sp = sub.add_parser(cmd_cls.name, help=cmd_cls.help)
        cmd_cls.configure(sp)
        sp.set_defaults(_command=cmd_cls)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    cmd_cls: Type[Command] = args._command
    try:
        return cmd_cls().run(args)
    except PQCryptError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
