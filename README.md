# DrygaAI Release Gate

Public release authority for the private `5244d6nwf9-sketch/DrygaAI` repository.

This repository contains **no DrygaAI source code and no private signing keys**. A DrygaAI commit is eligible for production only when an attestation for the exact commit SHA and Git tree SHA:

1. is cryptographically valid under a trusted Ed25519 public key;
2. passes the `Test` workflow;
3. is merged into the protected `main` branch of this repository.

Production must fail closed when an attestation is missing, malformed, has an invalid signature, names a different repository/commit/tree, or is not present on protected `main`.

## Layout

- `attestations/` — signed release attestations only.
- `trusted_keys/` — public verification keys only; private keys must never be committed.
- `scripts/verify.mjs` — normative verifier used by CI and later by deployment integration.
- `contract/attestation-v1.md` — exact attestation format and signing payload.
- `.github/CODEOWNERS` — owner review boundary for security/control-plane files.

The gate starts intentionally **closed**: until a trusted public key is installed through an owner-reviewed change, no release attestation can validate.
