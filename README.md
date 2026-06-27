# Privacy-Preserving Transaction System
### Inspired by Tornado Cash · Zero-Knowledge Proofs · Python 3.12+

---

## Overview

This project implements a **simplified, educational simulation** of a
privacy-preserving cryptocurrency mixer inspired by
[Tornado Cash](https://tornado.cash).  Users can deposit funds
anonymously and withdraw them later by proving ownership of a secret
**without ever revealing the secret itself** — the core idea behind
Zero-Knowledge Proofs (ZKPs).

---

## Architecture

```
┌─────────┐    commitment       ┌─────────────────┐
│  User   │──────H(secret)────▶│   Blockchain /  │
│ (Prover)│                    │  Commitment Pool │
└────┬────┘                    └────────┬────────┘
     │                                  │  all commitments
     │  challenge                        ▼
     │◀─────────────────────────┌──────────────┐
     │                          │  Merkle Tree │
     │  response=H(commit||r)   └──────────────┘
     │──────────────────────────▶
     │                          ┌──────────────────┐
     │  nullifier=H(secret||n)  │    On-Chain      │
     │──────────────────────────▶  Verifier        │
                                │  1. Pool check   │
                                │  2. Nullifier ck │
                                │  3. ZKP verify   │
                                └────────┬─────────┘
                                         │ approved?
                                ┌────────▼─────────┐
                                │ Nullifier Registry│
                                │  (spent set)      │
                                └───────────────────┘
```

---

## Project Structure

```
project/
│
├── main.py          ← Entry point — full demo with all 9 sections
├── blockchain.py    ← Append-only commitment ledger (chained blocks)
├── user.py          ← User model (secret, commitment, nullifier)
├── zkp.py           ← Zero-Knowledge Proof (Prover + Verifier classes)
├── verifier.py      ← On-chain verifier: pool + nullifier + ZKP checks
├── mixer.py         ← Anonymity mixer coordinating deposit/withdrawal
├── nullifier.py     ← Nullifier registry (double-spend prevention)
├── merkle.py        ← Binary Merkle Tree + membership proofs
├── utils.py         ← SHA-256 helpers, pretty-print, random generation
├── README.md        ← This file
└── requirements.txt ← No third-party dependencies
```

---

## Quick Start

```bash
# Python 3.12+ required, no pip installs needed
python main.py
```

---

## Module Descriptions

| Module | Responsibility |
|---|---|
| `utils.py` | SHA-256 hashing, random hex generation, console helpers |
| `user.py` | Creates users with private secret, public commitment, nullifier hash |
| `blockchain.py` | Immutable, chained ledger of commitment hashes only |
| `nullifier.py` | Tracks spent nullifiers to prevent double-spending |
| `zkp.py` | Challenge-response ZKP simulation (Prover + Verifier) |
| `verifier.py` | On-chain verifier enforcing 3-step withdrawal validation |
| `mixer.py` | Coordinates deposit/withdrawal; builds Merkle tree |
| `merkle.py` | Binary Merkle Tree; generates & verifies membership proofs |
| `main.py` | Runs a full 9-section console demonstration |

---

## Key Concepts

### Commitment Scheme
Each user generates a random 32-byte secret and computes:
```
commitment = SHA-256(secret)
```
Only the commitment is stored on-chain.  The secret stays with the user.

### Nullifier Hash
To prevent double-spending, each secret also produces a nullifier:
```
nullifier_hash = SHA-256(secret + "nullifier")
```
Once used in a withdrawal, this hash is permanently marked as spent.

### ZKP Challenge-Response (Simulated)
```
Verifier generates:   challenge  = random_hex(16)
Prover computes:      response   = SHA-256(commitment + challenge)
Verifier checks:      expected   = SHA-256(commitment + challenge)
                      valid      = (response == expected)
```
The verifier never needs the secret to validate the response.

### Anonymity (Mixing)
- All commitments sit in a shared, randomly-ordered pool.
- No link between depositor identity and commitment position is stored.
- Withdrawals only prove membership in the pool, not which deposit.

### Merkle Tree
Built over all commitments; supports membership proofs:
- Leaf = commitment hash
- Parent = SHA-256(left_child + right_child)
- Root = single 64-char hex fingerprint of the entire pool

---

## Security Properties Demonstrated

| Property | How |
|---|---|
| Secret privacy | Secret never transmitted; only H(secret) is public |
| Double-spend prevention | Nullifier registry rejects re-used nullifiers |
| Forged proof rejection | Attacker cannot compute valid response without secret |
| Commitment integrity | Blockchain hash-linking detects tampering |
| Merkle membership | Membership proofs verify inclusion without revealing position |

---

## Limitations (Educational Simulation)

This is a **pedagogical model**, not production cryptography:

- Uses SHA-256 as a commitment scheme; real systems use Pedersen commitments
- ZKP is a hash-based simulation; production uses zk-SNARKs (Groth16, PLONK)
- No actual value transfer (ETH, ERC-20) is simulated
- No Solidity / EVM execution
- Merkle position privacy is not enforced (in a real ZK circuit it would be)

---

## Requirements

- Python 3.12+
- No third-party packages (standard library only)
