#!/usr/bin/env python3
"""
Unit-test suite for pqcrypt.

Coverage goals
──────────────
  Encryption layer (age)
    • SDCardLocatorFactory dispatches by platform
    • FileEncryptor / DirectoryEncryptor / FileDecryptor / ArchiveDecryptor
      — applies_to() routing
    • Default destination path computation
    • Atomic-write guarantees (no .part garbage on failure, no clobber)
    • ArchiveDecryptor._safe_extract path-traversal protection
    • OperationDispatcher chain-of-responsibility ordering

  Signing layer (OpenSSL / ML-DSA)
    • OpenSSLBackend._check_ml_dsa_available: passes when haystack contains
      "ML-DSA", raises OpenSSLVersionError when it does not
    • Signer.sign: calls backend.sign_file with the right arguments and
      returns the expected .sig path; cleans up on failure
    • Verifier.verify: delegates to backend.verify_file; returns True/False
    • SigningKeyManager.signing_pub_path: prefers local cache, falls back to
      SD card, raises KeyMissingError when neither exists

  Integration
    • EncryptCommand.run with --sign calls both encrypt and sign code paths
    • DecryptCommand.run with --verify: aborts on bad signature, proceeds on
      good one
    • VerifyCommand.run returns 0 / 2 depending on backend result

The tests do NOT require the real `age` or `openssl` binaries.
All subprocess calls are replaced by MagicMock / side_effect.
"""

from __future__ import annotations

import io
import os
import shutil
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

sys.path.insert(0, str(Path(__file__).parent))
import pqcrypt as pq  # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
# Factories for fakes — avoid repeating boilerplate in every test
# ─────────────────────────────────────────────────────────────────────────────

def _fake_age_backend() -> pq.AgeBackend:
    """AgeBackend with pre-flight completely bypassed."""
    b = pq.AgeBackend.__new__(pq.AgeBackend)
    b.age = "age"
    b.keygen = "age-keygen"
    return b


def _fake_openssl_backend() -> pq.OpenSSLBackend:
    """OpenSSLBackend with pre-flight completely bypassed."""
    b = pq.OpenSSLBackend.__new__(pq.OpenSSLBackend)
    b.openssl = "openssl"
    return b


def _make_key_manager(tmp: Path) -> pq.KeyManager:
    """
    KeyManager whose SD card root is tmp/sd.
    Seeds both the encrypted identity and the public recipient cache.
    """
    (tmp / "sd").mkdir(exist_ok=True)
    (tmp / "sd" / pq.CONFIG.key_filename).write_bytes(b"FAKE-ENC-ID")
    pub_dir = tmp / "pub_cache"
    pub_dir.mkdir(exist_ok=True)
    (pub_dir / pq.CONFIG.pub_filename).write_text("age1pq1fake\n")

    km = pq.KeyManager.__new__(pq.KeyManager)
    km._backend = _fake_age_backend()
    km._config = pq.CONFIG
    km._locator = MagicMock()
    km._locator.find.return_value = tmp / "sd"
    km._fake_pub = pub_dir / pq.CONFIG.pub_filename
    km.public_recipient_path = lambda: km._fake_pub
    return km


def _make_signing_key_manager(tmp: Path) -> pq.SigningKeyManager:
    """
    SigningKeyManager whose SD card root is tmp/sd.
    Seeds both the encrypted private key and the public key cache.
    """
    sd = tmp / "sd"
    sd.mkdir(exist_ok=True)
    (sd / pq.CONFIG.signing_key_filename).write_text("-----BEGIN FAKE KEY-----\n")
    pub_cache = tmp / "signing_pub_cache"
    pub_cache.mkdir(exist_ok=True)
    pub_file = pub_cache / pq.CONFIG.signing_pub_filename
    pub_file.write_text("-----BEGIN FAKE PUBLIC KEY-----\n")

    skm = pq.SigningKeyManager.__new__(pq.SigningKeyManager)
    skm._backend = _fake_openssl_backend()
    skm._config = pq.CONFIG
    skm._locator = MagicMock()
    skm._locator.find.return_value = sd
    skm._fake_signing_pub = pub_file
    skm._fake_signing_priv = sd / pq.CONFIG.signing_key_filename
    # Patch path helpers so tests are filesystem-independent
    skm.encrypted_signing_key_path = lambda: skm._fake_signing_priv
    skm.signing_pub_path = lambda: skm._fake_signing_pub
    return skm


# ─────────────────────────────────────────────────────────────────────────────
# 1. SD Card Locator Factory
# ─────────────────────────────────────────────────────────────────────────────

class TestSDCardLocatorFactory(unittest.TestCase):

    def test_macos_returns_macos_locator(self):
        with patch("platform.system", return_value="Darwin"):
            self.assertIsInstance(
                pq.SDCardLocatorFactory.create(), pq._MacOSLocator
            )

    def test_linux_returns_linux_locator(self):
        with patch("platform.system", return_value="Linux"):
            self.assertIsInstance(
                pq.SDCardLocatorFactory.create(), pq._LinuxLocator
            )

    def test_unknown_platform_raises(self):
        with patch("platform.system", return_value="Plan9"):
            with self.assertRaises(pq.PQCryptError):
                pq.SDCardLocatorFactory.create()


# ─────────────────────────────────────────────────────────────────────────────
# 2. Operation applicability & dispatcher
# ─────────────────────────────────────────────────────────────────────────────

class TestOperationApplicability(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.km = _make_key_manager(self.tmp)
        self.be = self.km._backend

        self.plain_file = self.tmp / "doc.pdf"
        self.plain_file.write_bytes(b"data")
        self.plain_dir = self.tmp / "mydir"
        self.plain_dir.mkdir()
        self.enc_file = self.tmp / "doc.pdf.age"
        self.enc_file.write_bytes(b"FAKE-CIPHERTEXT")
        self.enc_arch = self.tmp / "mydir.tar.gz.age"
        self.enc_arch.write_bytes(b"FAKE-ARCHIVE")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # FileEncryptor
    def test_file_encryptor_claims_plain_file(self):
        op = pq.FileEncryptor(self.be, self.km)
        self.assertTrue(op.applies_to(self.plain_file))

    def test_file_encryptor_rejects_directory(self):
        op = pq.FileEncryptor(self.be, self.km)
        self.assertFalse(op.applies_to(self.plain_dir))

    # DirectoryEncryptor
    def test_dir_encryptor_claims_directory(self):
        op = pq.DirectoryEncryptor(self.be, self.km)
        self.assertTrue(op.applies_to(self.plain_dir))

    def test_dir_encryptor_rejects_file(self):
        op = pq.DirectoryEncryptor(self.be, self.km)
        self.assertFalse(op.applies_to(self.plain_file))

    # ArchiveDecryptor
    def test_archive_decryptor_claims_tar_gz_age(self):
        op = pq.ArchiveDecryptor(self.be, self.km)
        self.assertTrue(op.applies_to(self.enc_arch))

    def test_archive_decryptor_rejects_plain_age(self):
        op = pq.ArchiveDecryptor(self.be, self.km)
        self.assertFalse(op.applies_to(self.enc_file))

    # FileDecryptor
    def test_file_decryptor_claims_plain_age(self):
        op = pq.FileDecryptor(self.be, self.km)
        self.assertTrue(op.applies_to(self.enc_file))

    def test_file_decryptor_rejects_tar_gz_age(self):
        op = pq.FileDecryptor(self.be, self.km)
        self.assertFalse(op.applies_to(self.enc_arch))

    # Dispatcher ordering: ArchiveDecryptor must precede FileDecryptor so
    # that *.tar.gz.age files are never routed to the file decryptor.
    def test_dispatcher_routes_archive_to_archive_decryptor(self):
        dispatcher = pq.OperationDispatcher([
            pq.ArchiveDecryptor(self.be, self.km),
            pq.FileDecryptor(self.be, self.km),
        ])
        self.assertIsInstance(
            dispatcher.dispatch(self.enc_arch),
            pq.ArchiveDecryptor,
        )

    def test_dispatcher_routes_plain_age_to_file_decryptor(self):
        dispatcher = pq.OperationDispatcher([
            pq.ArchiveDecryptor(self.be, self.km),
            pq.FileDecryptor(self.be, self.km),
        ])
        self.assertIsInstance(
            dispatcher.dispatch(self.enc_file),
            pq.FileDecryptor,
        )

    def test_dispatcher_raises_on_no_match(self):
        dispatcher = pq.OperationDispatcher([
            pq.FileEncryptor(self.be, self.km),
        ])
        with self.assertRaises(pq.PQCryptError):
            dispatcher.dispatch(self.plain_dir)


# ─────────────────────────────────────────────────────────────────────────────
# 3. Default destination paths
# ─────────────────────────────────────────────────────────────────────────────

class TestDefaultDestinations(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.km = _make_key_manager(self.tmp)
        self.be = self.km._backend

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_file_encrypt_appends_dot_age(self):
        op = pq.FileEncryptor(self.be, self.km)
        self.assertEqual(
            op.default_destination(Path("/x/report.pdf")),
            Path("/x/report.pdf.age"),
        )

    def test_dir_encrypt_appends_tar_gz_age(self):
        op = pq.DirectoryEncryptor(self.be, self.km)
        self.assertEqual(
            op.default_destination(Path("/x/photos")),
            Path("/x/photos.tar.gz.age"),
        )

    def test_file_decrypt_strips_dot_age(self):
        op = pq.FileDecryptor(self.be, self.km)
        self.assertEqual(
            op.default_destination(Path("/x/report.pdf.age")),
            Path("/x/report.pdf"),
        )

    def test_archive_decrypt_strips_tar_gz_age(self):
        op = pq.ArchiveDecryptor(self.be, self.km)
        self.assertEqual(
            op.default_destination(Path("/x/photos.tar.gz.age")),
            Path("/x/photos"),
        )


# ─────────────────────────────────────────────────────────────────────────────
# 4. Atomic-write semantics for encryption
# ─────────────────────────────────────────────────────────────────────────────

class TestAtomicWriteSemantics(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.km = _make_key_manager(self.tmp)
        self.be = self.km._backend

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_failure_cleans_up_part_file(self):
        src = self.tmp / "doc.txt"
        src.write_text("hello")
        op = pq.FileEncryptor(self.be, self.km)

        with patch.object(self.be, "encrypt_to_recipient",
                          side_effect=pq.OperationFailedError("boom")):
            with self.assertRaises(pq.OperationFailedError):
                op.execute(src, None)

        dst = src.with_name("doc.txt.age")
        self.assertFalse(dst.exists(), "dst must not exist after failure")
        self.assertFalse(
            dst.with_name(dst.name + ".part").exists(),
            ".part file must be removed on failure",
        )

    def test_success_produces_dst_and_no_part(self):
        src = self.tmp / "doc.txt"
        src.write_text("hello")
        op = pq.FileEncryptor(self.be, self.km)

        def passthrough(_recipient, stdin, stdout):
            stdout.write(stdin.read())

        with patch.object(self.be, "encrypt_to_recipient",
                          side_effect=passthrough):
            result = op.execute(src, None)

        self.assertTrue(result.exists())
        self.assertEqual(result.read_bytes(), b"hello")
        self.assertFalse(result.with_name(result.name + ".part").exists())

    def test_existing_dst_raises_without_touching_it(self):
        src = self.tmp / "doc.txt"
        src.write_text("hello")
        dst = self.tmp / "doc.txt.age"
        dst.write_text("original")
        op = pq.FileEncryptor(self.be, self.km)

        with self.assertRaises(pq.PQCryptError):
            op.execute(src, None)

        self.assertEqual(dst.read_text(), "original",
                         "existing dst must be untouched")

    def test_keyboard_interrupt_cleans_up_part_file(self):
        src = self.tmp / "doc.txt"
        src.write_text("hello")
        op = pq.FileEncryptor(self.be, self.km)

        with patch.object(self.be, "encrypt_to_recipient",
                          side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                op.execute(src, None)

        dst = src.with_name("doc.txt.age")
        self.assertFalse(dst.with_name(dst.name + ".part").exists())


# ─────────────────────────────────────────────────────────────────────────────
# 5. Path-traversal protection
# ─────────────────────────────────────────────────────────────────────────────

class TestPathTraversalProtection(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_tar(self, member_name: str,
                  link_type: str = "file",
                  linkname: str = "") -> Path:
        tar_path = self.tmp / "payload.tar"
        with tarfile.open(tar_path, "w") as tar:
            if link_type == "symlink":
                info = tarfile.TarInfo(name=member_name)
                info.type = tarfile.SYMTYPE
                info.linkname = linkname
                tar.addfile(info)
            elif link_type == "hardlink":
                info = tarfile.TarInfo(name=member_name)
                info.type = tarfile.LNKTYPE
                info.linkname = linkname
                tar.addfile(info)
            else:
                data = b"content"
                info = tarfile.TarInfo(name=member_name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return tar_path

    def _extract(self, tar_path: Path) -> Path:
        dst = self.tmp / "out"
        dst.mkdir()
        with tarfile.open(tar_path, "r") as tar:
            pq.ArchiveDecryptor._safe_extract(tar, dst)
        return dst

    def test_absolute_path_rejected(self):
        tar = self._make_tar("/etc/passwd")
        with self.assertRaises(pq.UnsafeArchiveError):
            self._extract(tar)

    def test_dotdot_traversal_rejected(self):
        tar = self._make_tar("../../../tmp/evil_file")
        with self.assertRaises(pq.UnsafeArchiveError):
            self._extract(tar)

    def test_symlink_escape_rejected(self):
        tar = self._make_tar("link",
                             link_type="symlink",
                             linkname="/etc/shadow")
        with self.assertRaises(pq.UnsafeArchiveError):
            self._extract(tar)

    def test_hardlink_escape_rejected(self):
        tar = self._make_tar("hlink",
                             link_type="hardlink",
                             linkname="/etc/passwd")
        with self.assertRaises(pq.UnsafeArchiveError):
            self._extract(tar)

    def test_safe_member_extracted(self):
        tar = self._make_tar("subdir/data.txt")
        dst = self._extract(tar)
        self.assertTrue((dst / "subdir" / "data.txt").exists())
        self.assertEqual((dst / "subdir" / "data.txt").read_bytes(),
                         b"content")


# ─────────────────────────────────────────────────────────────────────────────
# 6. OpenSSL backend pre-flight
# ─────────────────────────────────────────────────────────────────────────────

class TestOpenSSLBackendPreflight(unittest.TestCase):

    def _make_backend_with_haystack(self, haystack: str) -> pq.OpenSSLBackend:
        """Build an OpenSSLBackend whose algorithm probe returns `haystack`."""
        b = pq.OpenSSLBackend.__new__(pq.OpenSSLBackend)
        b.openssl = "openssl"
        return b, haystack

    def test_ml_dsa_present_does_not_raise(self):
        b = pq.OpenSSLBackend.__new__(pq.OpenSSLBackend)
        b.openssl = "openssl"
        fake_result = MagicMock()
        fake_result.stdout = "ML-DSA-65\nML-DSA-87\n"
        fake_result.stderr = ""
        with patch("subprocess.run", return_value=fake_result):
            with patch("shutil.which", return_value="/usr/bin/openssl"):
                # Should not raise
                b._check_ml_dsa_available()

    def test_ml_dsa_absent_raises_version_error(self):
        b = pq.OpenSSLBackend.__new__(pq.OpenSSLBackend)
        b.openssl = "openssl"
        fake_result = MagicMock()
        fake_result.stdout = "RSA\nECDSA\nED25519\n"
        fake_result.stderr = ""
        with patch("subprocess.run", return_value=fake_result):
            with self.assertRaises(pq.OpenSSLVersionError):
                b._check_ml_dsa_available()

    def test_mldsa_without_dash_accepted(self):
        """Some providers advertise 'MLDSA65' instead of 'ML-DSA-65'."""
        b = pq.OpenSSLBackend.__new__(pq.OpenSSLBackend)
        b.openssl = "openssl"
        fake_result = MagicMock()
        fake_result.stdout = "MLDSA65\n"
        fake_result.stderr = ""
        with patch("subprocess.run", return_value=fake_result):
            b._check_ml_dsa_available()  # must not raise


# ─────────────────────────────────────────────────────────────────────────────
# 7. Signer
# ─────────────────────────────────────────────────────────────────────────────

class TestSigner(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.ossl = _fake_openssl_backend()
        self.skm = _make_signing_key_manager(self.tmp)
        self.signer = pq.Signer(self.ossl, self.skm)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_sign_calls_backend_and_returns_sig_path(self):
        src = self.tmp / "archive.tar.gz.age"
        src.write_bytes(b"CIPHERTEXT")

        # Fake sign_file: write dummy bytes to sig_dst
        def fake_sign(enc_key, in_file, out_file):
            out_file.write_bytes(b"SIG-BYTES")

        with patch.object(self.ossl, "sign_file", side_effect=fake_sign):
            sig = self.signer.sign(src)

        self.assertEqual(sig, src.with_name(src.name + ".sig"))
        self.assertTrue(sig.exists())
        self.assertEqual(sig.read_bytes(), b"SIG-BYTES")

    def test_sign_passes_correct_key_and_source(self):
        src = self.tmp / "archive.tar.gz.age"
        src.write_bytes(b"DATA")
        captured: dict = {}

        def capture_sign(enc_key, in_file, out_file):
            captured["enc_key"] = enc_key
            captured["in_file"] = in_file
            out_file.write_bytes(b"SIG")

        with patch.object(self.ossl, "sign_file", side_effect=capture_sign):
            self.signer.sign(src)

        self.assertEqual(captured["enc_key"],
                         self.skm._fake_signing_priv)
        self.assertEqual(captured["in_file"], src)

    def test_sign_cleans_up_part_file_on_failure(self):
        src = self.tmp / "archive.tar.gz.age"
        src.write_bytes(b"DATA")

        with patch.object(self.ossl, "sign_file",
                          side_effect=pq.OperationFailedError("oops")):
            with self.assertRaises(pq.OperationFailedError):
                self.signer.sign(src)

        sig = src.with_name(src.name + ".sig")
        self.assertFalse(sig.exists())
        self.assertFalse(sig.with_name(sig.name + ".part").exists())

    def test_sign_raises_if_sig_already_exists(self):
        src = self.tmp / "archive.tar.gz.age"
        src.write_bytes(b"DATA")
        (self.tmp / "archive.tar.gz.age.sig").write_bytes(b"OLD-SIG")

        with self.assertRaises(pq.PQCryptError):
            self.signer.sign(src)

    def test_sign_raises_on_non_file(self):
        with self.assertRaises(pq.PQCryptError):
            self.signer.sign(self.tmp)  # directory, not a file


# ─────────────────────────────────────────────────────────────────────────────
# 8. Verifier
# ─────────────────────────────────────────────────────────────────────────────

class TestVerifier(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.ossl = _fake_openssl_backend()
        self.skm = _make_signing_key_manager(self.tmp)
        self.verifier = pq.Verifier(self.ossl, self.skm)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_pair(self) -> tuple[Path, Path]:
        """Return (src, sig) — both files exist."""
        src = self.tmp / "file.tar.gz.age"
        sig = self.tmp / "file.tar.gz.age.sig"
        src.write_bytes(b"CT")
        sig.write_bytes(b"SIG")
        return src, sig

    def test_returns_true_on_valid_signature(self):
        src, sig = self._make_pair()
        with patch.object(self.ossl, "verify_file", return_value=True):
            self.assertTrue(self.verifier.verify(src, sig))

    def test_returns_false_on_invalid_signature(self):
        src, sig = self._make_pair()
        with patch.object(self.ossl, "verify_file", return_value=False):
            self.assertFalse(self.verifier.verify(src, sig))

    def test_default_sig_path_derived_correctly(self):
        """Without an explicit sig path, Verifier appends .sig to the source."""
        src = self.tmp / "file.tar.gz.age"
        sig = self.tmp / "file.tar.gz.age.sig"
        src.write_bytes(b"CT")
        sig.write_bytes(b"SIG")
        captured: dict = {}

        def capture(*args, **kwargs):
            captured["sig"] = args[2]
            return True

        with patch.object(self.ossl, "verify_file", side_effect=capture):
            self.verifier.verify(src)  # no sig kwarg

        self.assertEqual(captured["sig"], sig)

    def test_raises_if_source_missing(self):
        sig = self.tmp / "ghost.sig"
        sig.write_bytes(b"S")
        with self.assertRaises(pq.PQCryptError):
            self.verifier.verify(self.tmp / "ghost.age", sig)

    def test_raises_if_sig_missing(self):
        src = self.tmp / "file.age"
        src.write_bytes(b"CT")
        with self.assertRaises(pq.PQCryptError):
            self.verifier.verify(src, self.tmp / "no.sig")


# ─────────────────────────────────────────────────────────────────────────────
# 9. SigningKeyManager path logic
# ─────────────────────────────────────────────────────────────────────────────

class TestSigningKeyManagerPaths(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.be = _fake_openssl_backend()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_skm(self,
                  has_cache: bool = False,
                  has_sd: bool = False) -> pq.SigningKeyManager:
        """
        Build a SigningKeyManager whose paths live entirely under self.tmp.
        We override config properties to point at tmp, not ~/.config/pqcrypt.
        """
        skm = pq.SigningKeyManager.__new__(pq.SigningKeyManager)
        skm._backend = self.be
        skm._locator = MagicMock()

        cache_dir = self.tmp / "cache"
        cache_dir.mkdir(exist_ok=True)
        sd_dir = self.tmp / "sd"
        sd_dir.mkdir(exist_ok=True)

        cfg = MagicMock(spec=pq.Config)
        cfg.signing_pub_cache = cache_dir / pq.CONFIG.signing_pub_filename
        cfg.signing_key_filename = pq.CONFIG.signing_key_filename
        cfg.signing_pub_filename = pq.CONFIG.signing_pub_filename
        cfg.sd_label = pq.CONFIG.sd_label
        skm._config = cfg

        if has_cache:
            cfg.signing_pub_cache.write_text("CACHED-PUB\n")
        if has_sd:
            (sd_dir / pq.CONFIG.signing_pub_filename).write_text("SD-PUB\n")
            skm._locator.find.return_value = sd_dir
        else:
            skm._locator.find.side_effect = pq.SDCardNotFoundError("no sd")

        return skm

    def test_prefers_local_cache_over_sd(self):
        skm = self._make_skm(has_cache=True, has_sd=True)
        path = skm.signing_pub_path()
        self.assertEqual(path.read_text(), "CACHED-PUB\n")

    def test_falls_back_to_sd_when_no_cache(self):
        # Re-create with SD available and without SDCardNotFoundError
        skm = self._make_skm(has_cache=False, has_sd=False)
        sd_dir = self.tmp / "sd"
        (sd_dir / pq.CONFIG.signing_pub_filename).write_text("SD-PUB\n")
        skm._locator.find.return_value = sd_dir
        skm._locator.find.side_effect = None  # clear the exception side_effect

        path = skm.signing_pub_path()
        self.assertEqual(path.read_text(), "SD-PUB\n")

    def test_raises_key_missing_when_neither_exists(self):
        skm = self._make_skm(has_cache=False, has_sd=False)
        with self.assertRaises(pq.KeyMissingError):
            skm.signing_pub_path()


# ─────────────────────────────────────────────────────────────────────────────
# 10. EncryptCommand with --sign (integration)
# ─────────────────────────────────────────────────────────────────────────────

class TestEncryptCommandWithSign(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_sign_flag_triggers_signer(self):
        src = self.tmp / "secret.pdf"
        src.write_bytes(b"sensitive")
        expected_ct = src.with_name("secret.pdf.age")
        expected_sig = src.with_name("secret.pdf.age.sig")

        with (
            patch("pqcrypt.AgeBackend._check_installed"),
            patch("pqcrypt.AgeBackend._check_version"),
            patch("pqcrypt.OpenSSLBackend._check_installed"),
            patch("pqcrypt.OpenSSLBackend._check_ml_dsa_available"),
            patch("pqcrypt.KeyManager.public_recipient_path",
                  return_value=self.tmp / "pub"),
            patch("pqcrypt.KeyManager.encrypted_identity_path",
                  return_value=self.tmp / "key.age"),
            patch("pqcrypt.AgeBackend.encrypt_to_recipient",
                  side_effect=lambda _r, fin, fout: fout.write(fin.read())),
            patch("pqcrypt.SigningKeyManager.encrypted_signing_key_path",
                  return_value=self.tmp / "signing.key.pem"),
            patch("pqcrypt.OpenSSLBackend.sign_file",
                  side_effect=lambda _k, _s, dst: dst.write_bytes(b"SIG")),
        ):
            rc = pq.main(["encrypt", str(src), "--sign"])

        self.assertEqual(rc, 0)
        self.assertTrue(expected_ct.exists(), "ciphertext must be created")
        self.assertTrue(expected_sig.exists(), "signature must be created")

    def test_no_sign_flag_does_not_create_sig(self):
        src = self.tmp / "secret.pdf"
        src.write_bytes(b"sensitive")

        with (
            patch("pqcrypt.AgeBackend._check_installed"),
            patch("pqcrypt.AgeBackend._check_version"),
            patch("pqcrypt.KeyManager.public_recipient_path",
                  return_value=self.tmp / "pub"),
            patch("pqcrypt.AgeBackend.encrypt_to_recipient",
                  side_effect=lambda _r, fin, fout: fout.write(fin.read())),
        ):
            rc = pq.main(["encrypt", str(src)])

        self.assertEqual(rc, 0)
        sig = src.with_name("secret.pdf.age.sig")
        self.assertFalse(sig.exists(), ".sig must NOT be created without --sign")


# ─────────────────────────────────────────────────────────────────────────────
# 11. DecryptCommand with --verify (integration)
# ─────────────────────────────────────────────────────────────────────────────

class TestDecryptCommandWithVerify(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _setup_encrypted_pair(self) -> tuple[Path, Path]:
        ct = self.tmp / "secret.pdf.age"
        sig = self.tmp / "secret.pdf.age.sig"
        ct.write_bytes(b"CIPHERTEXT")
        sig.write_bytes(b"SIG-BYTES")
        return ct, sig

    def test_verify_good_signature_then_decrypts(self):
        ct, sig = self._setup_encrypted_pair()
        decrypted = self.tmp / "secret.pdf"

        # decrypted_identity_pipe is a @contextmanager that spawns a real
        # subprocess — we must replace it with a context manager that yields
        # a dummy bytes stream instead.
        from contextlib import contextmanager

        @contextmanager
        def fake_pipe(_self, _encrypted_id):
            yield io.BytesIO(b"FAKE-IDENTITY")

        with (
            patch("pqcrypt.AgeBackend._check_installed"),
            patch("pqcrypt.AgeBackend._check_version"),
            patch("pqcrypt.OpenSSLBackend._check_installed"),
            patch("pqcrypt.OpenSSLBackend._check_ml_dsa_available"),
            patch("pqcrypt.SigningKeyManager.signing_pub_path",
                  return_value=self.tmp / "signing.pub.pem"),
            patch("pqcrypt.OpenSSLBackend.verify_file", return_value=True),
            patch("pqcrypt.KeyManager.encrypted_identity_path",
                  return_value=self.tmp / "key.age"),
            patch("pqcrypt.AgeBackend.decrypted_identity_pipe",
                  new=fake_pipe),
            patch("pqcrypt.AgeBackend.decrypt_with_identity",
                  side_effect=lambda _id, _src, fout: fout.write(b"PLAIN")),
        ):
            rc = pq.main(["decrypt", str(ct), "--verify"])

        self.assertEqual(rc, 0)
        self.assertTrue(decrypted.exists())

    def test_verify_bad_signature_aborts_before_decrypt(self):
        ct, sig = self._setup_encrypted_pair()
        decrypt_called = []

        def record_decrypt(*_a, **_kw):
            decrypt_called.append(True)

        with (
            patch("pqcrypt.AgeBackend._check_installed"),
            patch("pqcrypt.AgeBackend._check_version"),
            patch("pqcrypt.OpenSSLBackend._check_installed"),
            patch("pqcrypt.OpenSSLBackend._check_ml_dsa_available"),
            patch("pqcrypt.SigningKeyManager.signing_pub_path",
                  return_value=self.tmp / "signing.pub.pem"),
            patch("pqcrypt.OpenSSLBackend.verify_file", return_value=False),
            patch("pqcrypt.AgeBackend.decrypt_with_identity",
                  side_effect=record_decrypt),
        ):
            rc = pq.main(["decrypt", str(ct), "--verify"])

        self.assertEqual(rc, 1,
                         "must exit 1 when signature is invalid")
        self.assertFalse(decrypt_called,
                         "decrypt_with_identity must NOT be called")


# ─────────────────────────────────────────────────────────────────────────────
# 12. VerifyCommand (integration)
# ─────────────────────────────────────────────────────────────────────────────

class TestVerifyCommand(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _make_pair(self) -> Path:
        ct = self.tmp / "archive.tar.gz.age"
        sig = ct.with_name(ct.name + ".sig")
        ct.write_bytes(b"CT")
        sig.write_bytes(b"SIG")
        return ct

    def test_verify_command_returns_0_on_valid(self):
        ct = self._make_pair()
        with (
            patch("pqcrypt.OpenSSLBackend._check_installed"),
            patch("pqcrypt.OpenSSLBackend._check_ml_dsa_available"),
            patch("pqcrypt.SigningKeyManager.signing_pub_path",
                  return_value=self.tmp / "signing.pub.pem"),
            patch("pqcrypt.OpenSSLBackend.verify_file", return_value=True),
        ):
            rc = pq.main(["verify", str(ct)])
        self.assertEqual(rc, 0)

    def test_verify_command_returns_2_on_invalid(self):
        ct = self._make_pair()
        with (
            patch("pqcrypt.OpenSSLBackend._check_installed"),
            patch("pqcrypt.OpenSSLBackend._check_ml_dsa_available"),
            patch("pqcrypt.SigningKeyManager.signing_pub_path",
                  return_value=self.tmp / "signing.pub.pem"),
            patch("pqcrypt.OpenSSLBackend.verify_file", return_value=False),
        ):
            rc = pq.main(["verify", str(ct)])
        self.assertEqual(rc, 2)


# ─────────────────────────────────────────────────────────────────────────────
# 13. Config sanity
# ─────────────────────────────────────────────────────────────────────────────

class TestConfigSanity(unittest.TestCase):

    def test_min_age_version_is_1_3_0(self):
        # PQ support (ML-KEM-768 + X25519) landed in age 1.3.0 (Dec 2025).
        # Bumping this without updating the check is a regression.
        self.assertEqual(pq.CONFIG.min_age_version, (1, 3, 0))

    def test_default_signing_algorithm_is_ml_dsa_65(self):
        # ML-DSA-65 gives NIST security level 3 (roughly AES-192 equivalent),
        # a good default for personal use. Tests break loudly if this changes.
        self.assertEqual(pq.CONFIG.signing_algorithm, "ML-DSA-65")

    def test_signature_suffix(self):
        self.assertEqual(pq.CONFIG.signature_suffix, ".sig")

    def test_archive_suffix(self):
        self.assertEqual(pq.CONFIG.archive_suffix, ".tar.gz.age")


if __name__ == "__main__":
    unittest.main(verbosity=2)
