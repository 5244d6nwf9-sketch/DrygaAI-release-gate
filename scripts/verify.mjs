import fs from 'node:fs';
import path from 'node:path';
import { createPublicKey, verify as verifySignature } from 'node:crypto';
import { pathToFileURL } from 'node:url';

export const EXPECTED_REPOSITORY = '5244d6nwf9-sketch/DrygaAI';
const REQUIRED_FIELDS = [
  'version',
  'repository',
  'commit_sha',
  'tree_sha',
  'issued_at',
  'key_id',
  'signature',
];

function fail(message) {
  throw new Error(message);
}

function assertExactFields(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('attestation must be a JSON object');
  }
  const actual = Object.keys(value).sort();
  const expected = [...REQUIRED_FIELDS].sort();
  if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i])) {
    fail(`attestation fields must be exactly: ${REQUIRED_FIELDS.join(', ')}`);
  }
}

function assertSha(name, value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{40}$/.test(value)) {
    fail(`${name} must be 40 lowercase hexadecimal characters`);
  }
}

function assertIssuedAt(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) {
    fail('issued_at must be a UTC ISO-8601 timestamp ending in Z');
  }
  if (Number.isNaN(Date.parse(value))) {
    fail('issued_at is not a valid timestamp');
  }
}

function assertKeyId(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(value)) {
    fail('key_id contains invalid characters');
  }
}

function decodeBase64Strict(value) {
  if (typeof value !== 'string' || value.length === 0) {
    fail('signature must be non-empty base64');
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length === 0 || decoded.toString('base64') !== value) {
    fail('signature must be canonical base64');
  }
  return decoded;
}

export function canonicalPayload(attestation) {
  return Buffer.from(
    'dryga-release-attestation-v1\n' +
      `repository=${attestation.repository}\n` +
      `commit_sha=${attestation.commit_sha}\n` +
      `tree_sha=${attestation.tree_sha}\n` +
      `issued_at=${attestation.issued_at}\n` +
      `key_id=${attestation.key_id}\n`,
    'utf8',
  );
}

export function validateShape(attestation) {
  assertExactFields(attestation);
  if (attestation.version !== 1) fail('version must be 1');
  if (attestation.repository !== EXPECTED_REPOSITORY) {
    fail(`repository must be exactly ${EXPECTED_REPOSITORY}`);
  }
  assertSha('commit_sha', attestation.commit_sha);
  assertSha('tree_sha', attestation.tree_sha);
  assertIssuedAt(attestation.issued_at);
  assertKeyId(attestation.key_id);
  decodeBase64Strict(attestation.signature);
}

export function validateAttestationFile(rootDir, filePath) {
  let attestation;
  try {
    attestation = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (error) {
    fail(`cannot parse ${path.relative(rootDir, filePath)}: ${error.message}`);
  }

  validateShape(attestation);

  const expectedFilename = `${attestation.commit_sha}.json`;
  if (path.basename(filePath) !== expectedFilename) {
    fail(`attestation filename must be ${expectedFilename}`);
  }

  const keyPath = path.join(rootDir, 'trusted_keys', `${attestation.key_id}.pem`);
  if (!fs.existsSync(keyPath)) {
    fail(`trusted key not found: trusted_keys/${attestation.key_id}.pem`);
  }

  let publicKey;
  try {
    publicKey = createPublicKey(fs.readFileSync(keyPath, 'utf8'));
  } catch (error) {
    fail(`cannot load trusted key ${attestation.key_id}: ${error.message}`);
  }

  if (publicKey.asymmetricKeyType !== 'ed25519') {
    fail(`trusted key ${attestation.key_id} must be Ed25519`);
  }

  const signature = decodeBase64Strict(attestation.signature);
  const valid = verifySignature(null, canonicalPayload(attestation), publicKey, signature);
  if (!valid) {
    fail(`invalid signature for ${attestation.commit_sha}`);
  }

  return attestation;
}

export function verifyRepository(rootDir = process.cwd()) {
  const attestationsDir = path.join(rootDir, 'attestations');
  const trustedKeysDir = path.join(rootDir, 'trusted_keys');

  if (!fs.existsSync(attestationsDir) || !fs.statSync(attestationsDir).isDirectory()) {
    fail('attestations directory is missing');
  }
  if (!fs.existsSync(trustedKeysDir) || !fs.statSync(trustedKeysDir).isDirectory()) {
    fail('trusted_keys directory is missing');
  }

  const entries = fs.readdirSync(attestationsDir, { withFileTypes: true });
  const unexpected = entries.filter(
    (entry) => !entry.isFile() || (entry.name !== '.gitkeep' && !entry.name.endsWith('.json')),
  );
  if (unexpected.length > 0) {
    fail(`unexpected entries in attestations/: ${unexpected.map((entry) => entry.name).join(', ')}`);
  }

  const seenCommits = new Set();
  const files = entries
    .filter((entry) => entry.isFile() && entry.name.endsWith('.json'))
    .map((entry) => path.join(attestationsDir, entry.name))
    .sort();

  for (const filePath of files) {
    const attestation = validateAttestationFile(rootDir, filePath);
    if (seenCommits.has(attestation.commit_sha)) {
      fail(`duplicate attestation for commit ${attestation.commit_sha}`);
    }
    seenCommits.add(attestation.commit_sha);
  }

  return { attestationCount: files.length };
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    const result = verifyRepository(process.cwd());
    console.log(`release gate verification passed (${result.attestationCount} attestations)`);
  } catch (error) {
    console.error(`release gate verification failed: ${error.message}`);
    process.exitCode = 1;
  }
}
