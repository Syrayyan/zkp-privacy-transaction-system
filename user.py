"""
user.py
-------
User model for the privacy-preserving transaction system.

Each ``User`` represents a participant who wants to deposit and later
withdraw anonymously.  Only the *commitment hash* (a one-way hash of
the secret) is ever made public; the secret itself stays with the user.

Lifecycle:
    1. User is created → secret & commitment generated automatically.
    2. User deposits  → commitment is added to the mixer pool.
    3. User withdraws → ZKP is generated and verified; nullifier marked.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from utils import sha256, generate_random_hex, truncate
from nullifier import NullifierRegistry


@dataclass
class User:
    """
    Represents a single participant in the anonymous transaction system.

    Attributes:
        name:            Human-readable identifier (e.g. "Alice").
        secret:          Private 32-byte random hex string — NEVER shared.
        commitment:      SHA-256(secret) — the only value stored on-chain.
        nullifier_hash:  SHA-256(secret + "nullifier") — prevents double-spend.
        has_deposited:   True once the user has placed a deposit.
        has_withdrawn:   True once the user has successfully withdrawn.
    """

    name:           str
    secret:         str          = field(init=False)
    commitment:     str          = field(init=False)
    nullifier_hash: str          = field(init=False)
    has_deposited:  bool         = field(default=False, init=False)
    has_withdrawn:  bool         = field(default=False, init=False)

    def __post_init__(self) -> None:
        # Generate a 32-byte (256-bit) cryptographically secure secret
        self.secret         = generate_random_hex(32)
        # Public commitment = H(secret)
        self.commitment     = sha256(self.secret)
        # Nullifier = H(secret || "nullifier")  — unique per deposit
        self.nullifier_hash = NullifierRegistry.compute(self.secret)

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a compact, human-readable summary (secrets truncated)."""
        return (
            f"User          : {self.name}\n"
            f"  Secret      : {truncate(self.secret)}  ← PRIVATE, never shared\n"
            f"  Commitment  : {truncate(self.commitment)}  ← stored on-chain\n"
            f"  Nullifier   : {truncate(self.nullifier_hash)}  ← spent on withdrawal\n"
            f"  Deposited?  : {self.has_deposited}\n"
            f"  Withdrawn?  : {self.has_withdrawn}"
        )

    def __repr__(self) -> str:
        return f"<User name={self.name!r} deposited={self.has_deposited}>"


def create_users(names: list[str]) -> list[User]:
    """
    Convenience factory — create one ``User`` for each name.

    Args:
        names: List of user name strings.

    Returns:
        A list of freshly initialised ``User`` objects.
    """
    return [User(name) for name in names]
