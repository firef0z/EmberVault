"""Time-based One-Time Password (TOTP) and Recovery Code helpers (Milestone M3).

Compliant with RFC 6238 and RFC 4226:
- Secret generation: 32-character Base32 random secrets (160-bit entropy).
- QR code provisioning: provisioning URI standard (otpauth://totp/...).
- Constant-time verification with clock drift tolerance (±1 step = 30 seconds).
- Recovery code hashing: Argon2id or SHA256 hashed one-time backup codes.
"""

from __future__ import annotations

import hashlib
import io
import secrets
from typing import TYPE_CHECKING

import pyotp
import qrcode
import qrcode.image.svg

if TYPE_CHECKING:
    pass

# Standard TOTP parameters
DEFAULT_TOTP_INTERVAL = 30
DEFAULT_TOTP_DIGITS = 6
DEFAULT_ISSUER_NAME = "EmberVault"
NUM_RECOVERY_CODES = 10
RECOVERY_CODE_LENGTH = 10  # 10 chars, e.g. 'a8f3-4b9c12'


def generate_totp_secret() -> str:
    """Generate a high-entropy 32-character Base32 TOTP secret."""
    return pyotp.random_base32(length=32)


def get_totp_provisioning_uri(
    secret: str,
    username: str,
    issuer_name: str = DEFAULT_ISSUER_NAME,
) -> str:
    """Return otpauth:// provisioning URI for authenticator apps."""
    totp = pyotp.TOTP(
        secret,
        interval=DEFAULT_TOTP_INTERVAL,
        digits=DEFAULT_TOTP_DIGITS,
        issuer=issuer_name,
    )
    return totp.provisioning_uri(name=username, issuer_name=issuer_name)


def generate_totp_qr_svg(
    secret: str,
    username: str,
    issuer_name: str = DEFAULT_ISSUER_NAME,
) -> str:
    """Generate an SVG string representation of the QR code for TOTP provisioning."""
    uri = get_totp_provisioning_uri(secret, username, issuer_name)
    qr = qrcode.QRCode(
        box_size=10,
        border=4,
        image_factory=qrcode.image.svg.SvgPathFillImage,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image()
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode("utf-8")


def generate_totp_qr_png_data_uri(
    secret: str,
    username: str,
    issuer_name: str = DEFAULT_ISSUER_NAME,
) -> str:
    """Generate a standard PNG Data URI (data:image/png;base64,...) of the QR code.

    Guarantees seamless scanning by browser extensions (Bitwarden, 1Password, etc.)
    and mobile cameras with a solid white background and clear quiet zone.
    """
    import base64

    uri = get_totp_provisioning_uri(secret, username, issuer_name)
    qr = qrcode.QRCode(
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"


def verify_totp_code(
    secret: str,
    code: str,
    valid_window: int = 1,
) -> bool:
    """Verify a user-provided 6-digit TOTP code with time drift window.

    Args:
        secret: Base32 TOTP secret.
        code: 6-digit code string supplied by the user.
        valid_window: Allowed time step drift (1 means ±30 seconds).

    Returns:
        True if the code is valid and within the allowed time window.
    """
    clean_code = str(code).strip().replace(" ", "").replace("-", "")
    if not clean_code.isdigit() or len(clean_code) != DEFAULT_TOTP_DIGITS:
        return False

    totp = pyotp.TOTP(secret, interval=DEFAULT_TOTP_INTERVAL, digits=DEFAULT_TOTP_DIGITS)
    return bool(totp.verify(clean_code, valid_window=valid_window))


def generate_recovery_codes(count: int = NUM_RECOVERY_CODES) -> list[str]:
    """Generate a list of formatted, high-entropy plaintext recovery codes.

    Format: e.g. '8f3a-4b9c-12' (human friendly, 10 hex characters).
    """
    codes: list[str] = []
    for _ in range(count):
        raw = secrets.token_hex(5)  # 10 hex digits
        formatted = f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"
        codes.append(formatted)
    return codes


def normalize_recovery_code(code: str) -> str:
    """Normalize user-entered recovery code for lookup/hashing (lowercase, no dashes or spaces)."""
    return str(code).strip().lower().replace("-", "").replace(" ", "")


def hash_recovery_code(code: str) -> str:
    """Hash a normalized recovery code using SHA-256 for one-time verification.

    We use SHA-256 with an application salt prefix since recovery codes are 10 random
    hex characters (40 bits entropy) and are only valid once.
    """
    normalized = normalize_recovery_code(code)
    salted = f"embervault-recovery:{normalized}".encode()
    return hashlib.sha256(salted).hexdigest()
