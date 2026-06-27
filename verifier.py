"""
verifier.py
-----------
The on-chain Verifier contract (simulated in Python).

Responsibilities:
    1. Accept a ZKProof from a withdrawing user.
    2. Confirm the commitment exists in the mixer pool.
    3. Confirm the nullifier has NOT been spent (double-spend guard).
    4. Confirm the ZKP response is mathematically valid.
    5. Mark the nullifier as spent if all checks pass.
    6. Return True (success) or False (rejection) — never the secret.

This mirrors the role of the Tornado Cash smart contract's withdraw()
function on Ethereum.
"""

from __future__ import annotations
from nullifier import NullifierRegistry
from zkp import ZKProof, Verifier as ZKVerifier
from utils import truncate


class OnChainVerifier:
    """
    Simulates the smart-contract verifier that processes withdrawal requests.

    Args:
        commitment_pool: The set of all accepted commitment hashes
                         (provided by the Mixer / Blockchain).
        nullifier_registry: Shared registry of spent nullifiers.

    Attributes:
        _pool:      Reference to the commitment pool (read-only from here).
        _nullifiers: Reference to the nullifier registry (written on success).
    """

    def __init__(
        self,
        commitment_pool: set[str],
        nullifier_registry: NullifierRegistry,
    ) -> None:
        self._pool       = commitment_pool
        self._nullifiers = nullifier_registry

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def process_withdrawal(self, proof: ZKProof, verbose: bool = True) -> bool:
        """
        Attempt to process a withdrawal using the supplied ZKP.

        Args:
            proof:   The ``ZKProof`` submitted by the user.
            verbose: If True, print a step-by-step trace to the console.

        Returns:
            ``True``  — proof is valid; nullifier marked as spent.
            ``False`` — proof is invalid; withdrawal rejected.
        """
        if verbose:
            print(f"\n  [Verifier] Processing withdrawal …")
            print(f"    Commitment    : {truncate(proof.commitment)}")
            print(f"    Nullifier     : {truncate(proof.nullifier_hash)}")
            print(f"    Challenge     : {truncate(proof.challenge)}")
            print(f"    Response      : {truncate(proof.response)}")

        # --- Check 1: commitment exists in pool -------------------------
        if proof.commitment not in self._pool:
            if verbose:
                print("    ✗ REJECTED — commitment not found in pool")
            return False

        if verbose:
            print("    ✓ Commitment found in pool")

        # --- Check 2: nullifier not already spent -----------------------
        if self._nullifiers.is_spent(proof.nullifier_hash):
            if verbose:
                print("    ✗ REJECTED — nullifier already spent (double-spend!)")
            return False

        if verbose:
            print("    ✓ Nullifier is fresh (not spent)")

        # --- Check 3: ZKP response is valid -----------------------------
        if not ZKVerifier.verify(proof, self._pool):
            if verbose:
                print("    ✗ REJECTED — ZKP verification failed")
            return False

        if verbose:
            print("    ✓ ZKP response verified")

        # --- All checks passed: mark nullifier as spent -----------------
        self._nullifiers.mark_spent(proof.nullifier_hash)
        if verbose:
            print("    ✓ Nullifier marked as spent")
            print("    ✓ WITHDRAWAL APPROVED")

        return True
