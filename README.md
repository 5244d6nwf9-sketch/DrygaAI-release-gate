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
- `scripts/keygen.mjs` — creates a new Ed25519 key pair without overwriting existing files.
- `scripts/sign.mjs` — signs an exact DrygaAI commit SHA + tree SHA attestation.
- `scripts/verify.mjs` — normative fail-closed verifier used by CI and deployment integration.
- `contract/attestation-v1.md` — exact attestation format and signing payload.
- `.github/CODEOWNERS` — owner review boundary for security/control-plane files.

## One-time key bootstrap

Generate the key pair on a trusted machine, never inside the repository checkout:

```sh
node scripts/keygen.mjs /secure/path/dryga-release-private.pem ./trusted_keys/dryga-release-1.pem
```

Commit only `trusted_keys/dryga-release-1.pem`. Keep `/secure/path/dryga-release-private.pem` outside git with mode `0600` and place it only in the intended secret store used by the release signer.

The gate remains intentionally **closed** until a trusted public key is merged through the protected branch.

## Create an attestation

Resolve both identifiers from the exact private DrygaAI commit being released:

```sh
git -C /path/to/DrygaAI rev-parse HEAD
git -C /path/to/DrygaAI rev-parse HEAD^{tree}
```

Then sign those exact values:

```sh
node scripts/sign.mjs \
  --private-key /secure/path/dryga-release-private.pem \
  --key-id dryga-release-1 \
  --commit-sha <40-lowercase-commit-sha> \
  --tree-sha <40-lowercase-tree-sha> \
  --issued-at 2026-09-04T00:00:00Z \
  --output attestations/<40-lowercase-commit-sha>.json
```

The attestation itself is public. The private key is not.
