"""
nullifier.py
------------
Nullifier Hash Registry — prevents double-spending.

Concept (inspired by Tornado Cash):
    When a user wishes to withdraw, they derive a *nullifier hash* from their
    secret.  The contract (here: ``NullifierRegistry``) stores every nullifier
    that has already been used.  If the same nullifier is presented a second
    time the withdrawal is rejected, even though the real secret is never
    revealed.

Design:
    nullifier_hash = SHA-256(secret + "nullifier")

    This binds the nullifier uniquely to the secret but reveals nothing about
    the secret itself to an external observer.
"""

from utils import sha256


class NullifierRegistry:
    """
    A simple on-chain registry that tracks spent nullifiers.

    Attributes:
        _used: Set of nullifier hashes that have already been spent.
    """

    def __init__(self) -> None:
        self._used: set[str] = set()

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    @staticmethod
    def compute(secret: str) -> str:
        """
        Derive the nullifier hash for *secret*.

        Args:
            secret: The user's private secret (never stored by this class).

        Returns:
            A 64-character hex string uniquely identifying this secret for
            withdrawal purposes.
        """
        return sha256(secret + "nullifier")

    def is_spent(self, nullifier_hash: str) -> bool:
        """
        Return ``True`` if *nullifier_hash* has already been used.

        Args:
            nullifier_hash: The nullifier to check.
        """
        return nullifier_hash in self._used

    def mark_spent(self, nullifier_hash: str) -> None:
        """
        Record *nullifier_hash* as spent (called after a successful withdrawal).

        Args:
            nullifier_hash: The nullifier to mark as used.

        Raises:
            ValueError: If the nullifier was already marked as spent
                        (should never happen if callers check first).
        """
        if nullifier_hash in self._used:
            raise ValueError(
                f"Double-spend attempted! Nullifier already used: {nullifier_hash[:16]}…"
            )
        self._used.add(nullifier_hash)

    def count(self) -> int:
        """Return the total number of spent nullifiers recorded."""
        return len(self._used)

    def __contains__(self, nullifier_hash: str) -> bool:
        return self.is_spent(nullifier_hash)
