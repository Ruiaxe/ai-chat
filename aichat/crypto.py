"""
ai-chat v3 cryptographic and time helpers.
Provides scrypt-based password hashing/verification for humans,
SHA-256 token hashing for agents, and ISO-8601 UTC timestamp formatting.
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone

SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN = 2**14, 8, 1, 32  # 16384, 8, 1, 32 bytes


def utc_now() -> str:
    """Returns current UTC timestamp in ISO-8601 format ending in 'Z'."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_password(password: str) -> str:
    """
    Hashes a human password using scrypt with a secure 16-byte random salt.
    Format: scrypt$<n>$<r>$<p>$<salt_hex>$<hash_hex>
    """
    if not password:
        raise ValueError("Password cannot be empty")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """
    Verifies a human password against an scrypt stored hash string.
    Returns True if valid, False otherwise.
    """
    if not password or not stored:
        return False
    try:
        parts = stored.split("$")
        if len(parts) != 6:
            return False
        algo, n, r, p, salt_hex, hash_hex = parts
        if algo != "scrypt":
            return False
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(hash_hex) // 2,
        )
        return secrets.compare_digest(digest.hex(), hash_hex)
    except Exception:
        return False


def new_agent_token() -> str:
    """
    Generates a secure 256-bit agent token with 'aic_' prefix.
    Format: aic_<urlsafe_base64_32_bytes>
    """
    return "aic_" + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """
    Returns the SHA-256 hex digest of an agent token or session token.
    Only hashes are stored in the database.
    """
    if not token:
        return ""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_hint(token: str) -> str:
    """Returns the last 4 characters of a token for identification."""
    if len(token) <= 4:
        return token
    return token[-4:]


def new_session_token() -> str:
    """Generates a secure random session token for browser cookies."""
    return "aicsess_" + secrets.token_urlsafe(32)
