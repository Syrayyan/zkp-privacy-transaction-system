"""
merkle.py
---------
A simplified binary Merkle Tree built over the commitment pool.

Why a Merkle tree?
    In real ZKP systems (e.g. Tornado Cash on Ethereum) users prove their
    commitment exists inside the tree *without* revealing which leaf it is.
    Here we implement the tree structure and Merkle-proof generation /
    verification so the concept is demonstrable in plain Python.

Structure:
    Leaves  = list of commitment hashes (one per depositor)
    Parents = SHA-256(left_child + right_child)
    Root    = single 64-char hex string

If the number of leaves is odd the last leaf is duplicated to form a
complete binary tree.
"""

from __future__ import annotations
from typing import Optional
from utils import double_sha256


class MerkleTree:
    """
    Binary Merkle Tree over a list of commitment hashes.

    Args:
        leaves: Iterable of commitment hash strings (hex).

    Attributes:
        leaves: The original (padded) leaf layer.
        layers: All tree layers from leaves to root.
        root:   The Merkle root hash (empty string if no leaves).
    """

    def __init__(self, leaves: list[str]) -> None:
        if not leaves:
            self.leaves: list[str] = []
            self.layers: list[list[str]] = []
            self.root: str = ""
            return

        # Pad to even length by duplicating the last leaf
        padded = list(leaves)
        if len(padded) % 2 != 0:
            padded.append(padded[-1])

        self.leaves = padded
        self.layers = self._build(padded)
        self.root   = self.layers[-1][0]

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    @staticmethod
    def _build(layer: list[str]) -> list[list[str]]:
        """Iteratively construct all layers up to the root."""
        layers: list[list[str]] = [layer]
        current = layer
        while len(current) > 1:
            next_layer: list[str] = []
            for i in range(0, len(current), 2):
                left  = current[i]
                right = current[i + 1] if i + 1 < len(current) else current[i]
                next_layer.append(double_sha256(left, right))
            layers.append(next_layer)
            current = next_layer
        return layers

    # ------------------------------------------------------------------
    # Proof generation & verification
    # ------------------------------------------------------------------

    def get_proof(self, leaf: str) -> Optional[list[dict]]:
        """
        Generate a Merkle proof for *leaf*.

        Args:
            leaf: A commitment hash that should exist in ``self.leaves``.

        Returns:
            A list of ``{"sibling": <hash>, "position": "left"|"right"}``
            dictionaries that, together with the leaf, reconstruct the root.
            Returns ``None`` if the leaf is not found.
        """
        if leaf not in self.leaves:
            return None

        proof: list[dict] = []
        index = self.leaves.index(leaf)

        for layer in self.layers[:-1]:          # all layers except the root
            sibling_idx = index ^ 1             # XOR with 1 → flip last bit
            if sibling_idx < len(layer):
                sibling = layer[sibling_idx]
            else:
                sibling = layer[index]          # duplicate if odd

            position = "right" if index % 2 == 0 else "left"
            proof.append({"sibling": sibling, "position": position})
            index //= 2                         # move up to parent index

        return proof

    def verify_proof(self, leaf: str, proof: list[dict]) -> bool:
        """
        Verify that *leaf* is included in the tree by re-computing the root.

        Args:
            leaf:  The commitment hash to verify.
            proof: The list returned by ``get_proof``.

        Returns:
            ``True`` if the re-computed root matches ``self.root``.
        """
        current = leaf
        for step in proof:
            sibling  = step["sibling"]
            position = step["position"]
            if position == "right":
                # current is the left child
                current = double_sha256(current, sibling)
            else:
                # current is the right child
                current = double_sha256(sibling, current)
        return current == self.root

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------

    def display(self, truncate_to: int = 12) -> None:
        """Print an ASCII representation of the tree layers."""
        print("\n  [Merkle Tree Layers]")
        for depth, layer in enumerate(reversed(self.layers)):
            label = "Root  " if depth == 0 else f"L{len(self.layers) - 1 - depth}    "
            hashes = "  |  ".join(h[:truncate_to] + "…" for h in layer)
            print(f"  {label}: {hashes}")
        print()
