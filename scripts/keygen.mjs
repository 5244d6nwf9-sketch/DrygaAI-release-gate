import fs from 'node:fs';
import path from 'node:path';
import { generateKeyPairSync } from 'node:crypto';

function fail(message) {
  throw new Error(message);
}

const [privatePathArg, publicPathArg] = process.argv.slice(2);
if (!privatePathArg || !publicPathArg) {
  fail('usage: node scripts/keygen.mjs <private-key.pem> <public-key.pem>');
}

const privatePath = path.resolve(privatePathArg);
const publicPath = path.resolve(publicPathArg);
if (privatePath === publicPath) fail('private and public key paths must differ');
if (fs.existsSync(privatePath) || fs.existsSync(publicPath)) fail('refusing to overwrite an existing key file');

for (const target of [privatePath, publicPath]) {
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
}

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });
const publicPem = publicKey.export({ type: 'spki', format: 'pem' });

fs.writeFileSync(privatePath, privatePem, { mode: 0o600, flag: 'wx' });
try {
  fs.writeFileSync(publicPath, publicPem, { mode: 0o644, flag: 'wx' });
} catch (error) {
  fs.rmSync(privatePath, { force: true });
  throw error;
}

console.log(`private key written to ${privatePath}`);
console.log(`public key written to ${publicPath}`);
console.log('Keep the private key outside git and secret stores only.');
