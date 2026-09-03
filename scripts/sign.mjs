import fs from 'node:fs';
import path from 'node:path';
import { createPrivateKey, sign } from 'node:crypto';
import { canonicalPayload, EXPECTED_REPOSITORY, validateShape } from './verify.mjs';

function fail(message) {
  throw new Error(message);
}

function parseArgs(argv) {
  const values = {};
  for (let i = 0; i < argv.length; i += 2) {
    const name = argv[i];
    const value = argv[i + 1];
    if (!name?.startsWith('--') || value === undefined) fail('arguments must be --name value pairs');
    if (Object.hasOwn(values, name)) fail(`duplicate argument: ${name}`);
    values[name] = value;
  }
  return values;
}

const args = parseArgs(process.argv.slice(2));
const allowed = new Set(['--private-key', '--key-id', '--commit-sha', '--tree-sha', '--issued-at', '--output']);
for (const name of Object.keys(args)) {
  if (!allowed.has(name)) fail(`unknown argument: ${name}`);
}
for (const name of allowed) {
  if (!args[name]) fail(`missing required argument: ${name}`);
}

const outputPath = path.resolve(args['--output']);
const expectedOutput = `${args['--commit-sha']}.json`;
if (path.basename(outputPath) !== expectedOutput) fail(`output filename must be ${expectedOutput}`);
if (fs.existsSync(outputPath)) fail('refusing to overwrite an existing attestation');

let privateKey;
try {
  privateKey = createPrivateKey(fs.readFileSync(path.resolve(args['--private-key']), 'utf8'));
} catch (error) {
  fail(`cannot load private key: ${error.message}`);
}
if (privateKey.asymmetricKeyType !== 'ed25519') fail('private key must be Ed25519');

const attestation = {
  version: 1,
  repository: EXPECTED_REPOSITORY,
  commit_sha: args['--commit-sha'],
  tree_sha: args['--tree-sha'],
  issued_at: args['--issued-at'],
  key_id: args['--key-id'],
  signature: '',
};

const unsignedForShapeCheck = { ...attestation, signature: Buffer.alloc(64).toString('base64') };
validateShape(unsignedForShapeCheck);
attestation.signature = sign(null, canonicalPayload(attestation), privateKey).toString('base64');
validateShape(attestation);

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(attestation, null, 2)}\n`, { flag: 'wx' });
console.log(`attestation written to ${outputPath}`);
