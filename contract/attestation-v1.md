# DrygaAI release attestation v1

Each release attestation is a UTF-8 JSON object stored as `attestations/<commit_sha>.json`.

Required fields:

```json
{
  "version": 1,
  "repository": "5244d6nwf9-sketch/DrygaAI",
  "commit_sha": "<40 lowercase hex>",
  "tree_sha": "<40 lowercase hex>",
  "issued_at": "<UTC ISO-8601 timestamp ending in Z>",
  "key_id": "<trusted key id>",
  "signature": "<base64 Ed25519 signature>"
}
```

No additional fields are permitted.

The Ed25519 signature is calculated over the exact UTF-8 bytes of this canonical payload, including the final newline:

```text
dryga-release-attestation-v1
repository=<repository>
commit_sha=<commit_sha>
tree_sha=<tree_sha>
issued_at=<issued_at>
key_id=<key_id>
```

The verifier resolves `key_id` only to `trusted_keys/<key_id>.pem` on the protected release-gate branch. The key must be an Ed25519 public key.

An attestation is invalid if any field, filename, signature, key, repository identity, commit SHA, or tree SHA is ambiguous or malformed. Verification fails closed.
