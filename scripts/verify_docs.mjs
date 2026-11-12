import { readFileSync } from 'node:fs';

const required = new Map([
  ['README.md', [
    'Registration and key upload',
    'Double Ratchet',
    'Delivery model',
    'Transport ACK',
    'TOFU',
    'no passphrase recovery',
    'polling rather than WebSockets',
    'One account per vault',
    'no multi-device synchronization',
    'sealed sender',
    'Attachment bytes are not uploaded',
    'no independent cryptographic or security audit',
    'cargo test --workspace --all-targets',
  ].map((text) => text.toLowerCase())],
  ['docs/protocol.md', [
    'Registration and key upload',
    'DH1 = X25519(IK_A_secret, SPK_B_public)',
    'DH2 = X25519(EK_A_secret, IK_B_public)',
    'DH3 = X25519(EK_A_secret, SPK_B_public)',
    'DH4 = X25519(EK_A_secret, OPK_B_public)',
    'Symmetric sending step',
    'post-compromise',
    '2,000 skipped keys',
    'out-of-order',
    'Transport ACK',
    'Encrypted delivery receipt',
    'Encrypted read receipt',
    'Argon2id',
    'fresh random 96-bit nonce',
    'TOFU',
    'Attachment bytes are not transported',
    'one account',
    'no passphrase reset or recovery',
    'WebSockets/push delivery',
    'multi-device synchronization',
    'sealed sender',
  ].map((text) => text.toLowerCase())],
]);

const missing = [];
for (const [path, phrases] of required) {
  const content = readFileSync(new URL(`../${path}`, import.meta.url), 'utf8').toLowerCase();
  for (const phrase of phrases) {
    if (!content.includes(phrase)) {
      missing.push(`${path}: ${phrase}`);
    }
  }
}
if (missing.length > 0) {
  console.error(`documentation is missing required topics:\n${missing.join('\n')}`);
  process.exit(1);
}
console.log('documentation verification passed');
