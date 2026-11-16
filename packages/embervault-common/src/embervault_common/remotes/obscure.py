"""Rclone password obscuring and de-obscuring utilities.

Implements Rclone's internal reversible encryption format (AES-CTR with standard key)
so that plain-text passwords provided by users can be consumed by Rclone backends
(e.g., SMB, SFTP, WebDAV, FTP) which require obscured input for `pass`.
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Standard hardcoded Rclone cryptKey from github.com/rclone/rclone/fs/config/obscure
RCLONE_CRYPT_KEY = bytes(
    [
        0x9C,
        0x93,
        0x5B,
        0x48,
        0x73,
        0x0A,
        0x55,
        0x4D,
        0x6B,
        0xFD,
        0x7C,
        0x63,
        0xC8,
        0x86,
        0xA9,
        0x2B,
        0xD3,
        0x90,
        0x19,
        0x8E,
        0xB8,
        0x12,
        0x8A,
        0xFB,
        0xF4,
        0xDE,
        0x16,
        0x2B,
        0x8B,
        0x95,
        0xF6,
        0x38,
    ]
)


def rclone_obscure(plaintext: str, rclone_bin: str = "rclone") -> str:
    """Obscure a plaintext password for Rclone configuration.

    If rclone binary is present in system PATH, uses native CLI.
    Otherwise falls back to pure-Python AES-CTR implementation matching Rclone exactly.
    """
    if not plaintext:
        return ""

    if shutil.which(rclone_bin):
        try:
            res = subprocess.run(
                [rclone_bin, "obscure", plaintext],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )
            out = res.stdout.strip()
            if out:
                return out
        except Exception:
            pass

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(RCLONE_CRYPT_KEY), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode("utf-8")) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + ciphertext).rstrip(b"=").decode("ascii")


def rclone_deobscure(obscured: str) -> str:
    """De-obscure an Rclone obscured password back to plaintext."""
    if not obscured:
        return ""

    rem = len(obscured) % 4
    padded = obscured + ("=" * (4 - rem) if rem > 0 else "")
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        if len(raw) < 16:
            return obscured
        iv = raw[:16]
        ciphertext = raw[16:]
        cipher = Cipher(algorithms.AES(RCLONE_CRYPT_KEY), modes.CTR(iv))
        decryptor = cipher.decryptor()
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode("utf-8")
    except Exception:
        return obscured
