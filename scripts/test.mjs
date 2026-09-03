import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, sign } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { canonicalPayload, validateAttestationFile, verifyRepository } from './verify.mjs';

const scriptsDir = path.dirname(fileURLToPath(import.meta.url));

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
  const { filePath } = makeSignedAttestation(root);
  const value = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  value.commit_sha = 'c'.repeat(40);
  const renamed = path.join(root, 'attestations', `${value.commit_sha}.json`);
  fs.renameSync(filePath, renamed);
  fs.writeFileSync(renamed, `${JSON.stringify(value, null, 2)}\n`);
  assert.throws(() => validateAttestationFile(root, renamed), /invalid signature/);
});

withFixture((root) => {
  const { filePath } = makeSignedAttestation(root, { repository: 'someone/else' });
  assert.throws(() => validateAttestationFile(root, filePath), /repository must be exactly/);
});

withFixture((root) => {
  const { filePath } = makeSignedAttestation(root);
  const value = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  value.key_id = 'missing-key';
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
  assert.throws(() => validateAttestationFile(root, filePath), /trusted key not found/);
});

withFixture((root) => {
  const { filePath } = makeSignedAttestation(root);
  const wrongPath = path.join(root, 'attestations', `${'c'.repeat(40)}.json`);
  fs.renameSync(filePath, wrongPath);
  assert.throws(() => validateAttestationFile(root, wrongPath), /attestation filename must be/);
});

withFixture((root) => {
  fs.writeFileSync(path.join(root, 'attestations', 'unexpected.txt'), 'nope\n');
  assert.throws(() => verifyRepository(root), /unexpected entries/);
});

withFixture((root) => {
  fs.writeFileSync(path.join(root, 'attestations', '.gitkeep'), '\n');
  assert.deepEqual(verifyRepository(root), { attestationCount: 0 });
});

withFixture((root) => {
  const privatePath = path.join(root, 'secrets', 'release-private.pem');
  const publicPath = path.join(root, 'trusted_keys', 'integration.pem');
  execFileSync(process.execPath, [path.join(scriptsDir, 'keygen.mjs'), privatePath, publicPath]);
  assert.equal(fs.statSync(privatePath).mode & 0o777, 0o600);

  const commitSha = 'd'.repeat(40);
  const treeSha = 'e'.repeat(40);
  const output = path.join(root, 'attestations', `${commitSha}.json`);
  execFileSync(process.execPath, [
    path.join(scriptsDir, 'sign.mjs'),
    '--private-key', privatePath,
    '--key-id', 'integration',
    '--commit-sha', commitSha,
    '--tree-sha', treeSha,
    '--issued-at', '2026-09-04T00:00:00Z',
    '--output', output,
  ]);
  const verified = validateAttestationFile(root, output);
  assert.equal(verified.commit_sha, commitSha);
  assert.equal(verified.tree_sha, treeSha);
});

console.log('release gate tests passed');
