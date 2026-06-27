"""
utils.py
--------
Shared utility functions used across the project.

Provides:
    - SHA-256 hashing with optional salt
    - Hex encoding / decoding helpers
    - Pretty console printing helpers
"""

import hashlib
import secrets


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------

def sha256(data: str) -> str:
    """Return the SHA-256 hex-digest of *data* (a plain string)."""
    return hashlib.sha256(data.encode()).hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Return the SHA-256 hex-digest of raw *data* bytes."""
    return hashlib.sha256(data).hexdigest()


def double_sha256(a: str, b: str) -> str:
    """
    Concatenate two hex strings and return their combined SHA-256 hash.
    Used by the Merkle tree when hashing parent nodes.
    """
    combined = (a + b).encode()
    return hashlib.sha256(combined).hexdigest()


def generate_random_hex(byte_length: int = 32) -> str:
    """
    Generate a cryptographically secure random hex string.

    Args:
        byte_length: Number of random bytes to produce (default 32 → 64 hex chars).

    Returns:
        A hex string of length ``byte_length * 2``.
    """
    return secrets.token_hex(byte_length)


# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------

SEPARATOR = "=" * 70
THIN_SEP  = "-" * 70


def print_section(title: str) -> None:
    """Print a bold section header to the console."""
    print(f"\n{SEPARATOR}")
    print(f"  {title}")
    print(SEPARATOR)


def print_subsection(title: str) -> None:
    """Print a thinner subsection header to the console."""
    print(f"\n{THIN_SEP}")
    print(f"  {title}")
    print(THIN_SEP)


def truncate(hex_str: str, chars: int = 16) -> str:
    """Return the first *chars* characters of *hex_str* followed by '…'."""
    return hex_str[:chars] + "…" if len(hex_str) > chars else hex_str
