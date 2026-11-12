# Protocol lifecycle and security model

This document specifies the implemented protocol, not the Signal wire format. Domain strings, identity encoding, serialization, headers, and APIs are specific to this workspace. There is no claim of Signal interoperability or an independent security audit.

## 1. Actors, keys, and encodings

Each account has a long-term identity consisting of two independently generated secrets:

- `IK_dh`: an X25519 static secret, with public key `IK_pub`.
- `IK_sig`: an Ed25519 signing secret, with public verification key `IK_verify`.

An `IdentityPublic` is the pair `(IK_pub, IK_verify)`. Its display fingerprint is lowercase hex of `SHA256(IK_pub || IK_verify)`. Separate X25519 and Ed25519 keys are used directly; there is no birational key conversion.

A signed pre-key `SPK` is an X25519 key pair with a nonzero `u32` ID. Its signature is Ed25519 over:

```
"signal-rust/signed-prekey/v1" || id_be_u32 || SPK_pub
```

A one-time pre-key `OPK` is an X25519 key pair with a nonzero `u32` ID. Registration generates signed pre-key 1 and one-time pre-keys 1 through 20. A fresh ephemeral X25519 key `EK` is generated for each initiation.

All random keys, bearer tokens, and AEAD nonces use the operating system random source exposed by the Rust random-number crates. X25519 outputs that are all zero are rejected. Ed25519 uses strict signature verification.

Public structures and content use serde JSON at API boundaries. Ratchet snapshots use bincode inside the encrypted vault. Integer lengths and protocol domain strings make associated-data boundaries explicit.

## 2. Registration and key upload

Sequence:

1. The operator supplies a vault path, relay URL, and valid lowercase username. The client reads a hidden passphrase and creates/opens the vault.
2. The client generates `IK`, `SPK`, and 20 `OPK` values locally. Private material never appears in a registration request.
3. The client signs the signed pre-key and sends `RegistrationRequest` to `POST /v1/users/register`.
4. The relay validates the username, verifies the signed-pre-key signature against `IK_verify`, and checks that one-time IDs are unique, nonzero, and bounded in count.
5. The relay generates 32 random bearer-token bytes, encodes them with URL-safe base64 without padding, and stores only `SHA256(token)`. It stores the UUID, username, public identity, and public pre-keys in one SQL transaction.
6. The client stores the returned bearer token and all private key material in its encrypted vault. The CLI prints the username and UUID, not the token.

The bearer token authenticates relay API access. It is not an end-to-end identity key and does not decrypt messages. Anyone who obtains it can fetch that account's queue and pre-key bundles or ACK/delete its queued packets, so vault and TLS protection are essential.

`POST /v1/users/me/prekeys` requires the bearer token. Rotation creates the next signed-pre-key ID and 20 new one-time keys. The relay verifies the new signed pre-key against the already-registered identity. The client keeps up to three signed secrets so an initial packet sent before rotation can still be opened.

Fetching `GET /v1/users/:username/bundle` atomically marks at most one unconsumed one-time pre-key as consumed and returns the latest signed pre-key. The server consumes a public one-time key at bundle fetch, not at first-message delivery. A fallback bundle with no one-time key is permitted after the supply is exhausted. Repeated contact adds can therefore consume keys without creating a session.

## 3. Contact pinning and identity verification

Before using a bundle, the client verifies the signed pre-key again locally. Relay verification is not a substitute for client verification.

The first bundle for a username pins its UUID and complete identity using trust on first use (TOFU). Later bundles must retain both identity public keys. A changed identity under the same UUID, or a different UUID claiming an already-pinned username, produces an identity-change error. Verification state is preserved only while the identity is unchanged.

Users compare the 64-hex-character fingerprint out of band and enter it with `/verify`. Without this step, the first fetch is vulnerable to an active relay/network attacker who substitutes an identity and valid signatures for that substitute identity. Verification is a local UI assertion; there is no identity transparency log or automatic safety-number migration protocol.

## 4. X3DH session initialization

Alice initiates to Bob using Bob's verified bundle. `SPK_B` is Bob's current signed pre-key and `OPK_B` is the optional one-time key. Alice generates a fresh `EK_A` and computes:

```
DH1 = X25519(IK_A_secret, SPK_B_public)
DH2 = X25519(EK_A_secret, IK_B_public)
DH3 = X25519(EK_A_secret, SPK_B_public)
DH4 = X25519(EK_A_secret, OPK_B_public)   // when OPK_B exists

X3DH_root = HKDF-SHA256(
    salt = "signal-rust-x3dh-v1",
    ikm = DH1 || DH2 || DH3 [|| DH4],
    info = "root",
    length = 32
)
```

The signed pre-key's Ed25519 signature is checked before any DH output is accepted. The initial header contains:

- Alice's complete public identity;
- Bob's signed-pre-key ID;
- Bob's optional one-time-pre-key ID;
- Alice's ephemeral X25519 public key;
- Alice's Ed25519 signature over the same header with its signature field empty.

Alice derives the initial Double Ratchet sending chain with `DH(EK_A, SPK_B)` and a root step. The first encrypted message includes the initial header. Bob does not upload or derive anything from Alice's plaintext.

Bob's receive sequence is:

1. Require a known, pinned contact whose identity exactly matches the initial header.
2. Select the referenced signed secret and optional one-time secret. Missing keys fail without acknowledging the packet.
3. Verify Alice's initial-header signature with Alice's pinned Ed25519 key.
4. Compute the four commutative DH values in receiver orientation: `DH(SPK_B, IK_A)`, `DH(IK_B, EK_A)`, `DH(SPK_B, EK_A)`, and optional `DH(OPK_B, EK_A)`.
5. Derive the same X3DH root and the initial receiving chain with `DH(SPK_B, EK_A)`.
6. Decrypt and authenticate the content and all associated data. Only after successful initial decryption does the client remove the consumed one-time secret from the encrypted account record.

The initial header is carried only until the relay first accepts the initial packet. If several sends occur before that acceptance, each persisted outbox packet carries it. After acceptance, later packets depend on the already established receiving state. Processing a later headerless packet before the first yields `NoSession`, leaves it queued, and allows a later retry.

## 5. Double Ratchet message flow

A session contains:

- a 32-byte root key;
- the current local X25519 ratchet secret and the remote public ratchet key;
- optional sending and receiving chain keys with next message indices;
- the previous sending-chain length;
- skipped message keys indexed by `(remote_ratchet_public, message_number)`.

### Symmetric sending step

For each message:

```
MK       = HMAC-SHA256(CK_send, "signal-rust-message-key/v1")
CK_send' = HMAC-SHA256(CK_send, "signal-rust-chain-key/v1")
N_send'  = N_send + 1
```

The header contains the current local ratchet public key, previous-chain length `PN`, and message number `N`. The payload uses ChaCha20-Poly1305 with `MK` and a fresh random 96-bit nonce. The chain advances after every encryption, so a message key is not reused by a later send.

The authenticated data comprises:

```
len(application_aad) || application_aad || message_uuid || bincode(ratchet_header)
```

Application associated data contains the content domain, sender and recipient UUIDs, both pinned identity public keys, and a length-prefixed encoding of the optional initial header. This binds the ciphertext to the conversation, both identities, relay/message UUID, initial parameters, and ratchet header. Modifying any of them fails AEAD authentication.

The plaintext is bounded JSON `MessageContent`:

- `Text { text }`, limited to 64 KiB;
- `Media { filename, mime_type, size, sha256 }`;
- `DeliveryReceipt { message_id }`;
- `ReadReceipt { message_ids }`, with 1 through 256 IDs.

Media metadata includes SHA-256 of local source bytes. Attachment bytes are not transported.

### Receiving, skipping, and replay rejection

The receiver first looks for a skipped key matching the header's ratchet public key and message number. A successful skipped-key decryption consumes that stored key.

For a new remote ratchet public key, the receiver:

1. Advances and stores keys through the advertised previous-chain length, subject to limits.
2. Computes a receiving root step with `DH(local_ratchet, new_remote_ratchet)`.
3. Generates a new local ratchet key and computes a sending root step with `DH(new_local_ratchet, new_remote_ratchet)`.

A root step is HKDF-SHA256 with the old root as salt, DH output as input key material, and `"signal-rust/root-ratchet/v1"` as info. Its 64-byte output splits into the new root and chain keys. This DH ratchet provides post-compromise recovery when fresh honest DH secrets become available and the attacker no longer controls every subsequent exchange.

Within a receiving chain, gaps produce and retain intermediate message keys. Decryption is transactional in memory: the ratchet operates on a candidate clone and commits only after AEAD and parsing succeed. Tampered ciphertext does not advance persisted session state. At most 2,000 skipped keys are retained, and a chain gap may not exceed 2,000 messages.

The client separately stores `SHA256(serialized_queued_packet)` in an encrypted seen record. An identical duplicate is acknowledged without re-decryption or duplicate history. Reusing the UUID for a different packet is rejected. The protocol's message UUID and header are AEAD-authenticated as well.

### Persist-send-ack sequence

For ordinary outgoing content:

1. Load/create the session and serialize content.
2. Encrypt, then persist the advanced ratchet state, exact encrypted outbox packet, and `Queued` local history.
3. Send the opaque packet to the relay with the bearer token.
4. On relay acceptance, delete the outbox packet, change history to `Sent`, and clear the pending initial header.
5. On failure or timeout, retain the exact ciphertext. `flush_outbox`, `/retry`, and `poll` resend it without another ratchet step.

The relay's enqueue operation is idempotent for an identical sender/recipient/packet ID/payload. A conflicting use of the same ID returns conflict. This resolves an ambiguous timeout where the server committed but the response was lost. Independent local writes are not one distributed transaction with the server; the durable outbox is the recovery mechanism.

## 6. Relay, transport ACK, delivery, and read receipts

The Axum routes are:

- `POST /v1/users/register`: public registration;
- `GET /v1/health`: health text;
- `POST /v1/users/me/prekeys`: authenticated pre-key rotation;
- `GET /v1/users/:username/bundle`: authenticated public bundle retrieval;
- `POST /v1/messages`: authenticated opaque enqueue;
- `GET /v1/messages?limit=N`: authenticated retrieval of the recipient's queue;
- `POST /v1/messages/:id/ack`: authenticated deletion from the recipient's queue.

SQLx stores serialized `EncryptedMessage` ciphertext. It has no private identity, signed, one-time, root, chain, or message keys and cannot decrypt content. Request bodies are capped at one MiB, ciphertext at 256 KiB, recipient queues at 1,000 messages, and retrieval at 100 packets per request.

There are three distinct acknowledgment meanings:

1. **Transport ACK:** after successful local processing and persistence, the recipient calls the authenticated ACK route. SQL deletion is constrained by both message ID and recipient UUID. A non-recipient cannot delete the packet. Repeated client ACKs treat an already absent message as complete; this does not grant cross-recipient deletion.
2. **Encrypted delivery receipt:** successful text/media processing automatically encrypts a receipt back to the sender. It means the recipient client processed the content, not that a person read it.
3. **Encrypted read receipt:** `/read` batches unread incoming text/media IDs and updates local incoming history. The original sender marks matching outgoing records `Read`. A later delivery receipt does not downgrade `Read`.

Receipts themselves do not trigger more delivery receipts. Their outbox retry behavior is the same as for text. Poll warnings identify packets left unacknowledged because they are malformed, from an unknown contact, or cannot yet initialize a session. Adding a pinned contact permits a later poll to process its retained packet.

## 7. Encrypted local persistence

Opening a vault derives 64 bytes using Argon2id with a random 16-byte salt, 19 MiB memory cost, two iterations, one lane, and Argon2 version 1.3. The first 32 bytes are the record-encryption key and the second 32 bytes are the lookup-index key. A fresh vault stores an encrypted key-check record. An existing vault missing that record fails closed rather than reinitializing under a wrong passphrase.

Each value is JSON inside an envelope containing its namespace and logical key. A lookup is:

```
HMAC-SHA256(index_key,
    "signal-rust/local-vault/v1" ||
    len(namespace) || namespace || len(key) || key)
```

The entire envelope is encrypted with ChaCha20-Poly1305 using a fresh random 96-bit nonce and the lookup bytes as associated data. Reads authenticate both the envelope and its namespace/key. Wrong passphrases, modified ciphertext, and substituted records fail closed.

Encrypted namespaces cover the account and bearer token, Double Ratchet snapshots and pending initial headers, contacts, message history, outbox packets, and seen-packet digests. Sensitive key material is zeroized in the principal account/ratchet/storage structures on drop, although this is not a guarantee that every compiler, allocator, swap, or library copy is erased.

SQLite `secure_delete` is enabled. Journals, backups, copy-on-write filesystems, SSD wear leveling, and swapped memory can still retain old bytes. Full-disk encryption and OS account permissions remain necessary. The deterministic lookup index reveals record equality and access patterns to someone inspecting the live database; it does not expose plaintext logical keys.

One vault holds one account. There is no passphrase reset or recovery mechanism.

## 8. Security properties and boundaries

When correctly keyed and verified, X3DH supplies asynchronous authenticated key agreement and the optional one-time DH strengthens initial-key freshness. Chain-key erasure and advancement provide forward secrecy for earlier message keys. Fresh DH ratchets provide post-compromise security under the usual honest-future-DH assumption. AEAD protects payload integrity and binds protocol metadata selected by the application.

The design does **not** protect against:

- a compromised endpoint, unlocked vault, malicious operating system, or memory inspection;
- an active attacker during an unverified TOFU first fetch;
- sender/recipient/timing/size/social-graph metadata collection by the relay;
- a stolen bearer token's relay-level actions;
- denial of service, pre-key exhaustion, queue starvation, or malicious registration floods;
- loss of the only vault/passphrase, rollback of files or backups, or physical forensic recovery;
- absent attachment bytes, multi-device consistency, group membership, or sealed-sender requirements.

Production Signal features not implemented include WebSockets/push delivery, multi-device synchronization, sealed sender, private contact discovery, group protocols, calls, disappearing messages, secure backups, and post-quantum agreements. The relay lacks built-in TLS termination and abuse rate limiting. No independent implementation, cryptographic, side-channel, or deployment audit has been performed.

## 9. Verification map

- `crates/protocol/tests/protocol.rs`: DH agreement, bidirectional ratchets, skipped keys, out-of-order delivery, replay rejection, tamper rollback, serialization, invalid signed pre-keys, and root evolution.
- `crates/server/tests/relay.rs`: registration, signatures, atomic pre-key consumption, rotation, opaque/idempotent relay, bad tokens, and recipient-only ACK behavior.
- `crates/storage/tests/storage.rs`: wrong passphrases, ciphertext tampering, fresh nonces, encrypted records, persistence, and session/history restoration.
- `crates/client/tests/end_to_end.rs`: real TCP/HTTP clients, independent vaults, X3DH, delayed out-of-order messages, delivery/read ordering, duplicate suppression, media metadata, pre-key rotation, unknown contacts, and session reload.

The integration test prints `END_TO_END_PASSED` only after its assertions succeed. `scripts/verify_docs.mjs` checks that this lifecycle and the operational guide retain the principal security topics and limitations.
