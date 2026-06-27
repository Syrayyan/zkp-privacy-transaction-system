"""
blockchain.py
-------------
Simplified blockchain storage for commitment hashes.

In a real system (e.g. Tornado Cash) commitments are stored as leaves of
an on-chain Merkle tree inside a smart contract.  Here we simulate a
minimal immutable ledger:

    • Each ``Block`` holds one commitment hash and is linked to the
      previous block via its hash (classic blockchain chaining).
    • The ``Blockchain`` class exposes deposit() and lookup methods.
    • Only the commitment hash is ever written — secrets stay off-chain.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from utils import sha256, truncate
import time


# ---------------------------------------------------------------------------
# Block
# ---------------------------------------------------------------------------

@dataclass
class Block:
    """
    A single immutable entry in the commitment chain.

    Attributes:
        index:          Block height (0 = genesis).
        commitment:     The SHA-256 commitment hash being stored.
        timestamp:      UNIX timestamp of block creation.
        previous_hash:  Hash of the preceding block (chaining).
        block_hash:     SHA-256 of (index + commitment + timestamp + previous_hash).
    """

    index:         int
    commitment:    str
    timestamp:     float        = field(default_factory=time.time)
    previous_hash: str          = ""
    block_hash:    str          = field(init=False)

    def __post_init__(self) -> None:
        raw = f"{self.index}{self.commitment}{self.timestamp}{self.previous_hash}"
        self.block_hash = sha256(raw)

    def __repr__(self) -> str:
        return (
            f"Block(index={self.index}, "
            f"commitment={truncate(self.commitment)}, "
            f"hash={truncate(self.block_hash)})"
        )


# ---------------------------------------------------------------------------
# Blockchain
# ---------------------------------------------------------------------------

class Blockchain:
    """
    A minimal append-only ledger of commitment blocks.

    The blockchain stores *only* commitment hashes — original secrets are
    never written here.

    Attributes:
        chain: Ordered list of ``Block`` objects (index 0 = genesis).
    """

    def __init__(self) -> None:
        # Genesis block has no real commitment
        genesis = Block(
            index=0,
            commitment="0" * 64,   # placeholder
            previous_hash="0" * 64,
        )
        self.chain: list[Block] = [genesis]

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def add_commitment(self, commitment: str) -> Block:
        """
        Append a new commitment hash to the chain.

        Args:
            commitment: The 64-character SHA-256 commitment to store.

        Returns:
            The newly created ``Block``.

        Raises:
            ValueError: If *commitment* is already recorded (replay guard).
        """
        if self.contains(commitment):
            raise ValueError(
                f"Commitment {truncate(commitment)} already on chain!"
            )

        prev_block = self.chain[-1]
        new_block  = Block(
            index=len(self.chain),
            commitment=commitment,
            previous_hash=prev_block.block_hash,
        )
        self.chain.append(new_block)
        return new_block

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def contains(self, commitment: str) -> bool:
        """Return True if *commitment* is already recorded on-chain."""
        return any(b.commitment == commitment for b in self.chain[1:])

    def get_all_commitments(self) -> list[str]:
        """Return all stored commitments (genesis block excluded)."""
        return [b.commitment for b in self.chain[1:]]

    def commitment_pool(self) -> set[str]:
        """Return a set of all commitment hashes (for O(1) lookup)."""
        return set(self.get_all_commitments())

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def display(self) -> None:
        """Print a visual representation of the chain."""
        print()
        for block in self.chain:
            label = "[GENESIS]" if block.index == 0 else f"[Block {block.index:>2}]"
            print(
                f"  {label}  commitment={truncate(block.commitment)}"
                f"  hash={truncate(block.block_hash)}"
            )
            if block.index < len(self.chain) - 1:
                print("       |")
        print()

    def is_valid(self) -> bool:
        """
        Verify the integrity of the entire chain by re-checking block hashes
        and the previous_hash linkage.

        Returns:
            ``True`` if the chain has not been tampered with.
        """
        for i in range(1, len(self.chain)):
            current  = self.chain[i]
            previous = self.chain[i - 1]

            # Recompute block hash
            raw      = f"{current.index}{current.commitment}{current.timestamp}{current.previous_hash}"
            expected = sha256(raw)
            if current.block_hash != expected:
                return False

            # Check linkage
            if current.previous_hash != previous.block_hash:
                return False

        return True
