# Signal Rust

A clean-room, Signal-inspired secure messenger written in Rust. It implements X3DH-style asynchronous key agreement, a Double Ratchet with skipped-message-key handling, an authenticated store-and-forward relay, encrypted SQLite vaults, and a Ratatui terminal client.

**Security status:** this is an independently written protocol implementation, not Signal and not wire-compatible with Signal. It has tests, but no independent cryptographic or security audit. Do not represent it as the production Signal application or use it as the sole protection for high-risk communications.

## Workspace

- `crates/protocol` (`crypto_core`): X25519 Diffie-Hellman, Ed25519 signatures, X3DH, Double Ratchet, HKDF/HMAC-SHA256, and ChaCha20-Poly1305.
- `crates/server` (`signal_server`): Tokio/Axum HTTP API and SQLx/SQLite persistence for users, public pre-keys, and opaque ciphertext.
- `crates/storage` (`signal_storage`): Argon2id key derivation and authenticated encryption of accounts, sessions, contacts, history, seen packets, and the outbox.
- `crates/client` (`signal_client`): session management, durable delivery, encrypted receipts, media metadata, Clap CLI, and Ratatui/crossterm interface.
- `docs/protocol.md`: exact state transitions, lifecycle sequences, formats, limits, and threat model.

Cryptographic arithmetic and standard primitives come from ordinary Rust crates. Protocol composition, state transitions, persistence, relay behavior, and client logic are implemented in this workspace; elliptic-curve arithmetic and AES/ChaCha internals are not reinvented.

## Build and test

Rust 1.82 or newer is required. SQLx and rusqlite use bundled SQLite, so no database server is needed.

```sh
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Run the real HTTP integration scenario on its own:

```sh
cargo test -p signal_client --test end_to_end -- --nocapture
```

It starts a real loopback TCP listener, creates two independent encrypted vaults, establishes X3DH, decrypts later messages out of order, exchanges delivery/read receipts, relays media metadata, rotates pre-keys, reopens a vault, and checks wrong-passphrase rejection.

## Run the relay

```sh
export SIGNAL_DATABASE_URL='sqlite://signal_server.db?mode=rwc'
export SIGNAL_BIND='127.0.0.1:3000'
cargo run -p signal_server
```

The default values are the values shown above. SQLite creates the file if necessary. Keep the relay database private: it cannot decrypt payloads, but it contains social-graph and timing metadata.

The API listens on plain HTTP. Use a TLS-terminating reverse proxy and an `https://` server URL for any non-loopback deployment. The Rust client refuses non-HTTPS server URLs except for `localhost`, `127.0.0.1`, and `::1`. The relay does not provide TLS termination, registration rate limiting, or production abuse controls.

## Registration and key upload; client startup

Registration creates one account in one encrypted vault. A passphrase is read interactively with terminal echo disabled; it is never accepted as a command-line argument.

```sh
cargo run -p signal_client -- \
  --vault ./alice.sqlite \
  --server http://127.0.0.1:3000 \
  register alice
```

New-vault passphrases must contain at least 12 UTF-8 bytes and are entered twice. There is **no passphrase recovery**. Losing the passphrase or vault loses the account credentials, private keys, sessions, and history.

Open the TUI:

```sh
cargo run -p signal_client -- \
  --vault ./alice.sqlite \
  --server http://127.0.0.1:3000 \
  tui
```

Omit `tui` to open the interface by default. `SIGNAL_VAULT` and `SIGNAL_SERVER` can supply defaults when the corresponding command-line options are absent. Do not put bearer tokens or passphrases in environment variables, shell history, or the server URL.

## TUI commands

Text that does not begin with `/` is sent to the selected contact. Up/down selects a contact; Enter runs a command; Escape clears input; Ctrl-C quits.

- `/add USER` fetches a signed bundle and pins the contact identity using trust on first use (TOFU).
- `/open USER` selects an existing contact.
- `/session USER` explicitly establishes a session. Sending also does this automatically.
- `/send TEXT` encrypts and sends text, up to 64 KiB.
- `/media PATH MIME` hashes local source bytes with SHA-256 and sends encrypted filename, MIME type, size, and digest metadata.
- `/poll` retrieves pending packets immediately. The interface also polls every five seconds.
- `/read` marks incoming text/media as read and sends a batched encrypted read receipt.
- `/fingerprint` displays the selected contact's SHA-256 identity fingerprint.
- `/verify HEX` marks a contact verified only when the entered 64-hex-character fingerprint matches exactly. Compare it through an authenticated out-of-band channel first.
- `/rotate` uploads a fresh signed pre-key and 20 one-time pre-keys.
- `/retry` retries persisted outbox packets without re-encrypting them.
- `/help`, `/quit` show help and exit.

Every `/add` or new `/session` bundle fetch can consume a server one-time pre-key, even if no first message is subsequently sent. Rotate pre-keys periodically and after extended offline use. The client retains the three most recent signed pre-key secrets for delayed initial messages and removes a one-time secret only after successful initial decryption.

## Delivery model

The sender persists the advanced ratchet state, exact encrypted packet, and local queued history before contacting the relay. After acceptance, it removes the outbox record and marks ordinary history `Sent`. A timeout can therefore be retried with `/retry` or `poll`; the relay accepts a duplicate only when message ID, sender, recipient, and serialized ciphertext are identical.

A transport ACK is different from a delivery receipt:

1. The recipient authenticates to the relay and retrieves opaque packets.
2. Successful local decryption and persistence produce an authenticated transport ACK, which deletes the relay copy.
3. Text/media decryption also queues an encrypted delivery receipt to the sender.
4. `/read` queues an encrypted read receipt. A later delivery receipt never downgrades `Read` to `Delivered`.

Malformed packets, unknown contacts, and messages lacking a required initial header remain unacknowledged and generate warnings. Adding the unknown contact allows a later poll to retry the packet. The first packet must be processed before later packets that do not carry an initial header; subsequent packets may then arrive out of order.

**Media limitation:** attachment bytes are not uploaded, downloaded, or relayed. Only encrypted metadata and a digest of the local source are supported. The recipient must obtain the actual bytes independently and compare the SHA-256 digest.

## Local security

The vault derives independent encryption and lookup-index keys with Argon2id. Records use ChaCha20-Poly1305 with fresh random 96-bit nonces and an authenticated HMAC lookup key. Private keys, bearer tokens, session roots/chains, skipped keys, contacts, message contents, outbox packets, and replay records are ciphertext in SQLite. Wrong passphrases and modified records fail closed.

TOFU pinning alone does not authenticate the first contact fetch against a malicious relay or network. Fingerprint verification is necessary for strong contact authentication. An identity-key change is rejected instead of silently replacing a verified contact; the code deliberately provides no one-click trust reset.

See `docs/protocol.md` for the precise cryptographic and persistence flows and their limitations.

## Scope and deployment limits

- Signal-inspired, not the complete production Signal feature set and not protocol-compatible with Signal.
- HTTP polling rather than WebSockets or push notifications.
- One account per vault; no multi-device synchronization or linked-device protocol.
- TOFU contact verification; no server-backed identity transparency or sealed sender.
- No group messaging, calls, disappearing messages, secure value recovery, or post-quantum key agreement.
- No attachment-byte relay: only media metadata is transported.
- No passphrase recovery, online backup, contact discovery privacy, or sealed-sender metadata protection.
- No registration/abuse rate limiting, production TLS listener, operational monitoring, or independent side-channel/audit review.
- SQLite `secure_delete` is enabled, but physical erasure is not guaranteed on copy-on-write, journaling, SSD, or backed-up storage.

The relay learns account IDs, usernames, public identity/pre-key material, sender/recipient IDs, packet sizes, ratchet headers, and timing. End-to-end encryption protects content, not this metadata.
