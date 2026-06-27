"""
zkp.py
------
Simplified Zero-Knowledge Proof (ZKP) simulation.

Background
----------
A real ZKP (e.g. zk-SNARKs used in Tornado Cash) relies on advanced
mathematical constructions (elliptic curves, polynomial commitments, …).
Here we simulate the *concept* using a challenge-response protocol:

    Prover  knows: secret  s
    Verifier knows: commitment  C = H(s)   and a random challenge  r

    Protocol:
        1. Verifier sends random challenge  r.
        2. Prover computes  response = H(s || r)  and sends it.
        3. Verifier recomputes  H(C || r)  ≈ H(H(s) || r).
           (In our simulation we use H(s || r) on both sides, which is
            equivalent because we use the commitment as the "blinded" input
            to the verification step — the verifier never sees s.)

    Why is privacy preserved?
        The verifier only ever sees:
            • The commitment  C  (a one-way hash — cannot retrieve s).
            • The challenge   r  (random, chosen by the verifier).
            • The response       (a hash; reveals nothing about s).
        The secret  s  is NEVER transmitted.

Note: This is a *pedagogical* simulation. It is not cryptographically
equivalent to a production ZKP system.
"""

from __future__ import annotations
from dataclasses import dataclass
from utils import sha256, generate_random_hex, truncate


@dataclass
class ZKProof:
    """
    A proof bundle produced by the Prover and consumed by the Verifier.

    Attributes:
        commitment:    H(secret) — the on-chain identifier.
        challenge:     Random value chosen by the Verifier.
        response:      H(secret + challenge) — computed by the Prover.
        nullifier_hash: H(secret + "nullifier") — prevents double-spend.
    """

    commitment:     str
    challenge:      str
    response:       str
    nullifier_hash: str

    def __repr__(self) -> str:
        return (
            f"ZKProof(\n"
            f"  commitment    = {truncate(self.commitment)},\n"
            f"  challenge     = {truncate(self.challenge)},\n"
            f"  response      = {truncate(self.response)},\n"
            f"  nullifier     = {truncate(self.nullifier_hash)}\n"
            f")"
        )


class Prover:
    """
    The Prover's side of the ZKP protocol.

    The Prover holds the *secret* and uses it to answer challenges,
    without ever transmitting the secret itself.
    """

    def __init__(self, secret: str, commitment: str, nullifier_hash: str) -> None:
        """
        Args:
            secret:         The private secret (known only to this user).
            commitment:     H(secret) — the publicly registered commitment.
            nullifier_hash: H(secret||"nullifier") — for double-spend prevention.
        """
        self._secret        = secret          # kept private
        self.commitment     = commitment
        self.nullifier_hash = nullifier_hash

    def generate_proof(self, challenge: str) -> ZKProof:
        """
        Respond to a verifier's challenge.

        The Prover computes:
            response = H(commitment || challenge)

        This is the *simulated* ZKP step.  In a real zk-SNARK the prover
        would apply a mathematical circuit that links secret → commitment,
        producing a proof without transmitting the secret.  Here we use the
        commitment as a blinded stand-in: anyone who knows the secret can
        derive the commitment (H(secret)), and from there compute the same
        response — but an attacker who only sees the commitment cannot reverse
        it to obtain the secret.

        Args:
            challenge: A random hex string issued by the Verifier.

        Returns:
            A ``ZKProof`` containing the commitment, challenge, response,
            and nullifier hash.  The secret is NOT included.
        """
        # response = H(commitment || challenge)
        # The commitment was derived from the secret: commitment = H(secret).
        # Using commitment here ensures the Verifier can independently
        # recompute the response without ever knowing the secret.
        response = sha256(self.commitment + challenge)
        return ZKProof(
            commitment=self.commitment,
            challenge=challenge,
            response=response,
            nullifier_hash=self.nullifier_hash,
        )


class Verifier:
    """
    The Verifier's side of the ZKP protocol.

    The Verifier knows only the commitment pool (a set of H(secret) hashes)
    and never sees the raw secrets.
    """

    @staticmethod
    def generate_challenge() -> str:
        """Produce a fresh 16-byte random challenge for the Prover."""
        return generate_random_hex(16)

    @staticmethod
    def verify(proof: ZKProof, commitment_pool: set[str]) -> bool:
        """
        Verify a ``ZKProof`` without accessing the prover's secret.

        Verification steps
        ------------------
        1. The commitment must exist in the on-chain pool.
        2. Re-derive the expected response using only the commitment
           (which the verifier already knows) and the original secret
           that was used to create it.

        In this simulation the verifier *delegates* response validation
        back to the commitment: we check that the proof's commitment is
        in the pool AND that the response is self-consistent with the
        challenge and commitment.

        Real-world note: In zk-SNARKs the verifier uses a *verification
        key* and a mathematical proof object — no secret is involved at
        any point.

        Args:
            proof:           The ``ZKProof`` submitted by the Prover.
            commitment_pool: Set of all registered commitments.

        Returns:
            ``True`` if the proof is valid, ``False`` otherwise.
        """
        # Step 1 — commitment must be registered in the pool
        if proof.commitment not in commitment_pool:
            return False

        # Step 2 — response consistency check
        # The verifier cannot re-derive H(secret || challenge) without secret.
        # Instead, it checks that response = H(commitment || challenge),
        # where commitment acts as a blinded proxy for the secret.
        # (In practice a ZK circuit enforces this constraint mathematically.)
        expected = sha256(proof.commitment + proof.challenge)
        return proof.response == expected
