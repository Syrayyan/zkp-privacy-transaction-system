"""
mixer.py
--------
Privacy Mixer — the core of the Tornado Cash-inspired anonymity layer.

How anonymity is achieved
--------------------------
1. **Deposit**: Users deposit by submitting *only* their commitment hash.
   The mixer records it alongside many other commitments.  No link to the
   user's identity is stored.

2. **Mixing**: All commitments sit in a shared, randomly ordered pool.
   From the outside, it is impossible to tell which commitment belongs to
   whom.

3. **Withdrawal**: Users prove ownership via a ZKP (challenge-response)
   and a fresh nullifier.  The verifier only checks that *some* commitment
   in the pool was deposited by someone who knows the corresponding secret.
   The link between depositor and withdrawer is broken.

This module coordinates:
    - The ``Blockchain`` (immutable record of commitments)
    - The ``MerkleTree``  (cryptographic membership proof)
    - The ``NullifierRegistry`` (double-spend prevention)
    - The ``OnChainVerifier``  (ZKP validation)
"""

from __future__ import annotations
import random
from blockchain import Blockchain
from merkle import MerkleTree
from nullifier import NullifierRegistry
from verifier import OnChainVerifier
from zkp import Prover, Verifier as ZKVerifier
from user import User
from utils import truncate, print_subsection


class Mixer:
    """
    Coordinates deposits and withdrawals for the anonymous transaction pool.

    Attributes:
        blockchain:   Immutable commitment ledger.
        nullifiers:   Registry of spent nullifiers.
        verifier:     On-chain withdrawal verifier.
        merkle_tree:  Merkle tree rebuilt after each deposit.
    """

    def __init__(self) -> None:
        self.blockchain   = Blockchain()
        self.nullifiers   = NullifierRegistry()
        self.verifier     = OnChainVerifier(
            commitment_pool=self.blockchain.commitment_pool(),
            nullifier_registry=self.nullifiers,
        )
        self.merkle_tree: MerkleTree = MerkleTree([])

    # ------------------------------------------------------------------
    # Deposit
    # ------------------------------------------------------------------

    def deposit(self, user: User) -> bool:
        """
        Accept a deposit from *user*.

        Only the commitment hash is stored — the user's secret is never
        transmitted to the mixer.

        Args:
            user: The depositing user.

        Returns:
            ``True`` on success, ``False`` if already deposited.
        """
        if user.has_deposited:
            print(f"  [Mixer] {user.name} has already deposited.")
            return False

        block = self.blockchain.add_commitment(user.commitment)
        user.has_deposited = True

        # Rebuild Merkle tree and refresh the verifier's pool reference
        self._rebuild_merkle()
        self.verifier = OnChainVerifier(
            commitment_pool=self.blockchain.commitment_pool(),
            nullifier_registry=self.nullifiers,
        )

        print(
            f"  [Mixer] Deposit accepted — "
            f"Block #{block.index}  commitment={truncate(user.commitment)}"
        )
        return True

    # ------------------------------------------------------------------
    # Withdraw
    # ------------------------------------------------------------------

    def withdraw(self, user: User, verbose: bool = True) -> bool:
        """
        Process a withdrawal request for *user*.

        Steps:
            1. User's Prover receives a random challenge from the Verifier.
            2. Prover computes response = H(secret || challenge).
            3. OnChainVerifier checks commitment, nullifier, and ZKP.
            4. If valid, nullifier is marked spent and withdrawal succeeds.

        Args:
            user:    The withdrawing user.
            verbose: If True, print detailed step trace.

        Returns:
            ``True`` if withdrawal was approved, ``False`` otherwise.
        """
        if not user.has_deposited:
            if verbose:
                print(f"  [Mixer] {user.name} has not deposited yet.")
            return False

        if user.has_withdrawn:
            if verbose:
                print(f"  [Mixer] {user.name} has already withdrawn.")
            return False

        # Build a Prover from the user's private data
        prover    = Prover(user.secret, user.commitment, user.nullifier_hash)
        challenge = ZKVerifier.generate_challenge()

        if verbose:
            print_subsection(f"Withdrawal: {user.name}")
            print(f"  Challenge issued  : {truncate(challenge)}")

        proof     = prover.generate_proof(challenge)
        approved  = self.verifier.process_withdrawal(proof, verbose=verbose)

        if approved:
            user.has_withdrawn = True

        return approved

    # ------------------------------------------------------------------
    # Merkle helpers
    # ------------------------------------------------------------------

    def _rebuild_merkle(self) -> None:
        """Rebuild the Merkle tree over the current commitment list."""
        commitments = self.blockchain.get_all_commitments()
        random.shuffle(commitments)          # simulate pool ordering
        self.merkle_tree = MerkleTree(commitments)

    def merkle_proof_for(self, user: User) -> bool:
        """
        Generate and verify a Merkle inclusion proof for *user*.

        Demonstrates that the user's commitment is inside the pool
        without revealing which position it occupies.

        Args:
            user: A user who has already deposited.

        Returns:
            True if the membership proof verifies correctly.
        """
        proof = self.merkle_tree.get_proof(user.commitment)
        if proof is None:
            print(f"  [Merkle] {user.name}'s commitment not found in tree.")
            return False

        result = self.merkle_tree.verify_proof(user.commitment, proof)
        print(
            f"  [Merkle] Membership proof for {user.name}: "
            f"{'✓ VALID' if result else '✗ INVALID'}"
        )
        return result

    # ------------------------------------------------------------------
    # Pool info
    # ------------------------------------------------------------------

    def pool_size(self) -> int:
        """Return the number of commitments currently in the pool."""
        return len(self.blockchain.get_all_commitments())

    def display_pool(self) -> None:
        """Print the anonymised commitment pool (hashes only, shuffled)."""
        commitments = list(self.blockchain.commitment_pool())
        random.shuffle(commitments)
        print("\n  [Anonymous Pool — commitments in random order]")
        for i, c in enumerate(commitments, 1):
            print(f"    {i:>2}.  {truncate(c)}")
        print()
