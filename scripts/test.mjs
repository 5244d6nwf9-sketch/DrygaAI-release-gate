import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateKeyPairSync, sign } from 'node:crypto';
import { canonicalPayload, validateAttestationFile, verifyRepository } from './verify.mjs';

function withFixture(run) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dryga-release-gate-'));
  try {
    fs.mkdirSync(path.join(root, 'attestations'));
    fs.mkdirSync(path.join(root, 'trusted_keys'));
    return run(root);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

function makeSignedAttestation(root, overrides = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const keyId = overrides.key_id ?? 'test-key';
  fs.writeFileSync(
    path.join(root, 'trusted_keys', `${keyId}.pem`),
    publicKey.export({ type: 'spki', format: 'pem' }),
  );

  const attestation = {
    version: 1,
    repository: '5244d6nwf9-sketch/DrygaAI',
    commit_sha: 'a'.repeat(40),
    tree_sha: 'b'.repeat(40),
    issued_at: '2026-09-04T00:00:00Z',
    key_id: keyId,
    signature: '',
    ...overrides,
  };
  attestation.signature = sign(null, canonicalPayload(attestation), privateKey).toString('base64');

  const filePath = path.join(root, 'attestations', `${attestation.commit_sha}.json`);
  fs.writeFileSync(filePath, `${JSON.stringify(attestation, null, 2)}\n`);
  return { attestation, filePath };
}

withFixture((root) => {
  const { attestation, filePath } = makeSignedAttestation(root);
  assert.equal(validateAttestationFile(root, filePath).commit_sha, attestation.commit_sha);
  assert.deepEqual(verifyRepository(root), { attestationCount: 1 });
});

withFixture((root) => {
  const { filePath } = makeSignedAttestation(root);
  const value = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  value.tree_sha = 'c'.repeat(40);
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
  assert.throws(() => validateAttestationFile(root, filePath), /invalid signature/);
});

withFixture((root) => {
  const { filePath } = makeSignedAttestation(root, { repository: 'someone/else' });
  assert.throws(() => validateAttestationFile(root, filePath), /repository must be exactly/);
});

withFixture((root) => {
  fs.writeFileSync(path.join(root, 'attestations', 'unexpected.txt'), 'nope\n');
  assert.throws(() => verifyRepository(root), /unexpected entries/);
});

withFixture((root) => {
  fs.writeFileSync(path.join(root, 'attestations', '.gitkeep'), '\n');
  assert.deepEqual(verifyRepository(root), { attestationCount: 0 });
});

console.log('release gate tests passed');
