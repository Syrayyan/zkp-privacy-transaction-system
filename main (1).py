"""
main.py
-------
Demonstration entry point for the Privacy-Preserving Transaction System
inspired by Tornado Cash and Zero-Knowledge Proofs.

Run with:
    python main.py

Sections demonstrated:
    1. User creation
    2. Deposits (commitment phase)
    3. Blockchain integrity check
    4. Merkle Tree construction and membership proofs
    5. Withdrawal via ZKP (valid proofs)
    6. Double-spend attempt (nullifier rejection)
    7. Simulated attack with an invalid (forged) proof
    8. System summary
"""

import random
from user import create_users
from mixer import Mixer
from zkp import ZKProof, Verifier as ZKVerifier
from utils import print_section, print_subsection, truncate, SEPARATOR


# ---------------------------------------------------------------------------
# Architecture diagram
# ---------------------------------------------------------------------------

ARCHITECTURE = r"""
  ┌──────────────────────────────────────────────────────────────────┐
  │              PRIVACY-PRESERVING TRANSACTION SYSTEM               │
  │                  (Tornado Cash Simulation — Python)              │
  └──────────────────────────────────────────────────────────────────┘

   ┌─────────┐    commitment       ┌─────────────────┐
   │  User   │──────H(secret)────▶│   Blockchain /  │
   │ (Prover)│                    │  Commitment Pool │
   └────┬────┘                    └────────┬────────┘
        │                                  │  all commitments
        │  challenge                        ▼
        │◀─────────────────────────┌──────────────┐
        │                          │  Merkle Tree │
        │  response=H(secret||r)   └──────────────┘
        │──────────────────────────▶
        │                          ┌──────────────────┐
        │  nullifier=H(secret||n)  │    On-Chain      │
        │──────────────────────────▶  Verifier        │
                                   │                  │
                                   │ 1. Pool check    │
                                   │ 2. Nullifier check│
                                   │ 3. ZKP verify    │
                                   └────────┬─────────┘
                                            │ approved?
                                   ┌────────▼─────────┐
                                   │ Nullifier Registry│
                                   │  (spent set)      │
                                   └───────────────────┘

  KEY PRIVACY PROPERTY: The Verifier sees commitment, challenge, response,
  and nullifier — but NEVER the original secret.
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def banner(text: str) -> None:
    print(f"\n{'='*70}")
    print(f"  {text}")
    print(f"{'='*70}")


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------

def main() -> None:

    print(ARCHITECTURE)

    # -----------------------------------------------------------------------
    # Section 1 — Create Users
    # -----------------------------------------------------------------------
    banner("SECTION 1 — User Creation")

    names = ["Alice", "Bob", "Charlie", "Diana", "Eve"]
    users = create_users(names)

    for user in users:
        print()
        print(user.summary())

    # -----------------------------------------------------------------------
    # Section 2 — Deposits
    # -----------------------------------------------------------------------
    banner("SECTION 2 — Deposits (Commitment Phase)")
    print("""
  Each user deposits by submitting only H(secret) to the mixer.
  The mixer records the commitment on a blockchain-like ledger.
  The original secret is NEVER transmitted or stored.
    """)

    mixer = Mixer()
    for user in users:
        mixer.deposit(user)

    # -----------------------------------------------------------------------
    # Section 3 — Blockchain state
    # -----------------------------------------------------------------------
    banner("SECTION 3 — Blockchain State")
    mixer.blockchain.display()
    integrity_ok = mixer.blockchain.is_valid()
    print(f"  Chain integrity check: {'✓ VALID' if integrity_ok else '✗ INVALID'}")

    # -----------------------------------------------------------------------
    # Section 4 — Merkle Tree
    # -----------------------------------------------------------------------
    banner("SECTION 4 — Merkle Tree & Membership Proofs")
    print("""
  A Merkle tree is built over all commitments in the pool.
  Users can prove their commitment is in the tree without revealing
  which leaf belongs to them (in a real ZK system, the leaf index
  would be hidden inside the ZK circuit).
    """)

    mixer._rebuild_merkle()
    mixer.merkle_tree.display()

    for user in users[:3]:   # demonstrate 3 proofs
        mixer.merkle_proof_for(user)

    # -----------------------------------------------------------------------
    # Section 5 — Anonymous Pool
    # -----------------------------------------------------------------------
    banner("SECTION 5 — Anonymous Commitment Pool")
    print("""
  All commitments are pooled together in random order.
  An outside observer cannot tell which commitment belongs to which user.
    """)
    mixer.display_pool()

    # -----------------------------------------------------------------------
    # Section 6 — Withdrawals via ZKP
    # -----------------------------------------------------------------------
    banner("SECTION 6 — Withdrawals via Zero-Knowledge Proof")
    print("""
  Each user proves ownership of a commitment using a challenge-response ZKP.
  The verifier confirms:
    (a) the commitment is in the pool
    (b) the nullifier has not been spent
    (c) the ZKP response is correct
  No secret is ever transmitted.
    """)

    results: dict[str, bool] = {}
    for user in users:
        approved = mixer.withdraw(user, verbose=True)
        results[user.name] = approved
        print(f"\n  → {user.name}: {'APPROVED ✓' if approved else 'REJECTED ✗'}\n")

    # -----------------------------------------------------------------------
    # Section 7 — Double-Spend Attack
    # -----------------------------------------------------------------------
    banner("SECTION 7 — Double-Spend Attack (Nullifier Protection)")
    print("""
  Alice attempts to withdraw a second time using the same nullifier.
  The system should detect and reject this.
    """)

    alice = users[0]
    print(f"  Alice tries to withdraw again …")
    double_spend_result = mixer.withdraw(alice, verbose=True)
    print(
        f"\n  → Result: {'APPROVED ✓ (BUG!)' if double_spend_result else 'REJECTED ✗ (correct!)'}"
    )

    # -----------------------------------------------------------------------
    # Section 8 — Forged Proof Attack
    # -----------------------------------------------------------------------
    banner("SECTION 8 — Simulated Attack with Invalid (Forged) Proof")
    print("""
  An attacker constructs a ZKProof using a fake response.
  They know Alice's commitment (it's public) but not her secret.
  They cannot forge a valid response.
    """)

    alice          = users[0]
    attacker_name  = "Mallory (Attacker)"
    fake_challenge = ZKVerifier.generate_challenge()
    fake_response  = "deadbeef" * 8          # obviously wrong response

    forged_proof = ZKProof(
        commitment=alice.commitment,          # attacker knows this (public)
        challenge=fake_challenge,
        response=fake_response,               # cannot forge without the secret
        nullifier_hash=alice.nullifier_hash,  # already spent — also fails here
    )

    print(f"  {attacker_name} submits forged proof:")
    print(f"    commitment  = {truncate(forged_proof.commitment)}")
    print(f"    challenge   = {truncate(forged_proof.challenge)}")
    print(f"    response    = {truncate(forged_proof.response)}  ← FORGED")

    attack_result = mixer.verifier.process_withdrawal(forged_proof, verbose=True)
    print(
        f"\n  → Result: {'APPROVED ✓ (SECURITY BREACH!)' if attack_result else 'REJECTED ✗ (correct!)'}"
    )

    # -----------------------------------------------------------------------
    # Section 9 — System Summary
    # -----------------------------------------------------------------------
    banner("SECTION 9 — System Summary")

    print(f"""
  Users created      : {len(users)}
  Pool size          : {mixer.pool_size()} commitments
  Nullifiers spent   : {mixer.nullifiers.count()}
  Chain valid        : {'Yes' if mixer.blockchain.is_valid() else 'No'}

  Withdrawal results :""")

    for name, ok in results.items():
        status = "✓ Approved" if ok else "✗ Rejected"
        print(f"    {name:<10} → {status}")

    print(f"""
  Double-spend test  : {'✗ Rejected (correct)' if not double_spend_result else '✓ Allowed (BUG!)'}
  Forged proof test  : {'✗ Rejected (correct)' if not attack_result else '✓ Allowed (BUG!)'}

  {SEPARATOR}
  All secrets remained private throughout the demonstration.
  {SEPARATOR}
    """)


if __name__ == "__main__":
    main()
