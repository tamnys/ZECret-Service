#!/usr/bin/env node
// Seal issuer keys using Phala's X25519 + AES-256-GCM encrypted_env format.
import {
  createCipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  randomBytes,
  createHash,
} from 'node:crypto';
import { constants, closeSync, fsyncSync, lstatSync, openSync, readFileSync, writeSync } from 'node:fs';
import { resolve } from 'node:path';

if (process.argv.length !== 6) {
  throw new Error('usage: node seal_env.mjs KMS_PUBKEY_HEX_FILE ISSUER_PRIVATE_DER ONION_SECRET_KEY OUTPUT_FILE');
}
const [kmsPath, issuerPath, onionPath, outputPath] = process.argv.slice(2).map((path) => resolve(path));

function privateBytes(path) {
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.uid !== process.getuid() || (metadata.mode & 0o077) !== 0) {
    throw new Error('owner-private regular input required');
  }
  return readFileSync(path);
}

const kmsHex = privateBytes(kmsPath).toString('ascii').trim().replace(/^0x/, '');
if (!/^[0-9a-fA-F]{64}$/.test(kmsHex)) throw new Error('Phala KMS X25519 public key unavailable');
const kmsRaw = Buffer.from(kmsHex, 'hex');
const issuerPrivate = privateBytes(issuerPath);
const onionSecret = privateBytes(onionPath);
if (onionSecret.length !== 96) throw new Error('Tor onion key format differs');

const expectedIssuerPublic = readFileSync(new URL('./issuer-public.der', import.meta.url));
const issuerPublic = createPublicKey(createPrivateKey({ key: issuerPrivate, format: 'der', type: 'pkcs1' }))
  .export({ format: 'der', type: 'spki' });
if (!issuerPublic.equals(expectedIssuerPublic)) throw new Error('issuer signing key and published key differ');

const x25519SpkiPrefix = Buffer.from('302a300506032b656e032100', 'hex');
const kmsPublic = createPublicKey({ key: Buffer.concat([x25519SpkiPrefix, kmsRaw]), format: 'der', type: 'spki' });
const ephemeral = generateKeyPairSync('x25519');
const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: kmsPublic });
const iv = randomBytes(12);
const payload = Buffer.from(JSON.stringify({ env: [
  { key: 'ZRPC_ISSUER_PRIVATE_DER_B64', value: issuerPrivate.toString('base64') },
  { key: 'ZRPC_ONION_SECRET_KEY_B64', value: onionSecret.toString('base64') },
] }), 'utf8');
const cipher = createCipheriv('aes-256-gcm', shared, iv);
const ciphertext = Buffer.concat([cipher.update(payload), cipher.final()]);
const tag = cipher.getAuthTag();
const ephemeralRaw = ephemeral.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
const sealed = Buffer.concat([ephemeralRaw, iv, ciphertext, tag]).toString('hex');
const descriptor = openSync(outputPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
try {
  writeSync(descriptor, sealed + '\n');
  fsyncSync(descriptor);
} finally {
  closeSync(descriptor);
}
console.log(JSON.stringify({
  encrypted_env_sha256: createHash('sha256').update(sealed).digest('hex'),
  public_key_sha256: createHash('sha256').update(kmsHex).digest('hex'),
  env_keys: ['ZRPC_ISSUER_PRIVATE_DER_B64', 'ZRPC_ONION_SECRET_KEY_B64'],
}));
