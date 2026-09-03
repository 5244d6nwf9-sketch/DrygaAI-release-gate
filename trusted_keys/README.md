# Trusted public keys

Only Ed25519 **public** verification keys belong here, as `<key_id>.pem`.

Private signing keys must never be committed to this repository or stored in GitHub Actions secrets for this public repository.

The release gate intentionally starts with no trusted key. Until an owner-reviewed PR installs a trusted public key, every release attestation must fail closed.
