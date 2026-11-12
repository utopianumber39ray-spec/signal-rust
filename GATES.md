# Gates: Signal-inspired Rust secure messenger

OWNS: Cargo.toml, Cargo.lock, .gitignore, GATES.md, README.md, crates/**, docs/**, scripts/**

Scope: Deliver a tested Rust workspace with clean-room X3DH and Double Ratchet logic, authenticated encrypted message relay, encrypted local persistence, interactive client flows, and lifecycle documentation.

- [x] G0: this ledger has valid, fail-capable outcome checks
  CHECK: node /home/ai/.kimi-code/skills/unlazy/scripts/gate-lint.mjs GATES.md
  EXPECT: LINT OK
  EVIDENCE: automatic-evidence=v1; definition-sha256=1610f6a916b2b5cc81bcd2c8e79eb6e39bbf4f5f1b1e3b1ed84b464c0567138d; exit=0; EXPECT=matched; output-sha256=48630b7361dd44ee870917b12c3d19b9d7bdea738aaca16bb04d4cab83b772d2; output-bytes=8; shell=/bin/sh; cwd=/home/ai/signal-rust; path=ed7550b752b6/12 entries

- [x] G1: X3DH and Double Ratchet transitions, replay rejection, out-of-order delivery, and serialization pass cryptographic tests
  CHECK: cargo test -p crypto_core --all-features && node -e "console.log('protocol verification passed')"
  EXPECT: protocol verification passed
  EVIDENCE: automatic-evidence=v1; definition-sha256=cfcbbc37998faa246a4fa2fca57a2bd6d967b3b2dcb7cb369d7030bc57dba15b; exit=0; EXPECT=matched; output-sha256=b085f6a31518d93b94f2ec732a1841ff7649b5adaa0952756012bc29c9d79c1a; output-bytes=1001; shell=/bin/sh; cwd=/home/ai/signal-rust; path=ed7550b752b6/12 entries

- [x] G2: authenticated registration, pre-key management, store-and-forward relay, and owner-only ACK behavior pass handler tests
  CHECK: cargo test -p signal_server --all-targets && node -e "console.log('server verification passed')"
  EXPECT: server verification passed
  EVIDENCE: automatic-evidence=v1; definition-sha256=cd235b363dc87357d83504bed518e0e1cdd868c198a1785c85a8dfb59fc87aeb; exit=0; EXPECT=matched; output-sha256=c98db9c0511d6c734986a4a0da6fde07a673b5c311fc53286583287b73a015fe; output-bytes=987; shell=/bin/sh; cwd=/home/ai/signal-rust; path=ed7550b752b6/12 entries

- [x] G3: encrypted-at-rest local storage preserves accounts, sessions, contacts, and message history while rejecting wrong passphrases
  CHECK: cargo test -p signal_storage --all-targets && node -e "console.log('storage verification passed')"
  EXPECT: storage verification passed
  EVIDENCE: automatic-evidence=v1; definition-sha256=4d9fae04c202c7063ba9dfca0c3ffc983ca2e0178a21ab6b8e7cb3aac43316fb; exit=0; EXPECT=matched; output-sha256=d833b49e4a6261e1532917edcbc1be6dcd275a5a0a76b0e890f9f425a08d05fc; output-bytes=825; shell=/bin/sh; cwd=/home/ai/signal-rust; path=ed7550b752b6/12 entries

- [x] G4: two clients register, initialize sessions, exchange out-of-order encrypted payloads, process receipts, and ACK through a live HTTP server
  CHECK: cargo test -p signal_client --test end_to_end -- --nocapture
  EXPECT: END_TO_END_PASSED
  EVIDENCE: automatic-evidence=v1; definition-sha256=b15355faab54dced637897230d88f01550015c895aabda882fa02634909204d6; exit=0; EXPECT=matched; output-sha256=13389fd74f1fee09bb047d90b786046f65c280295fb92d9b6e5ff54f0bbed00a; output-bytes=324; shell=/bin/sh; cwd=/home/ai/signal-rust; path=ed7550b752b6/12 entries

- [x] G5: protocol and operational documentation covers all requested lifecycle and security topics
  CHECK: node scripts/verify_docs.mjs
  EXPECT: documentation verification passed
  EVIDENCE: automatic-evidence=v1; definition-sha256=f12681e050a232c767417a8dbc945bb6d767c1aa61aa0d2b3334cdf4579f7738; exit=0; EXPECT=matched; output-sha256=5fdf546167baf5bdc4f619c1af10c1e37213d323a8196b34f4125c38449975d3; output-bytes=34; shell=/bin/sh; cwd=/home/ai/signal-rust; path=ed7550b752b6/12 entries

- [x] G6: the complete workspace is formatted, compiles without warnings, and all unit and integration tests pass
  CHECK: cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace --all-targets && node -e "console.log('workspace quality verification passed')"
  EXPECT: workspace quality verification passed
  EVIDENCE: automatic-evidence=v1; definition-sha256=ca86ca372d4c7a2c3d31896c3b0ec5747ab33634f35611c5d667ffa4c97d9eb5; exit=0; EXPECT=matched; output-sha256=b93e5045afb1bc3f60403231f873aa77b1c8a065c66dd453579feb0a3e218a1b; output-bytes=2896; shell=/bin/sh; cwd=/home/ai/signal-rust; path=ed7550b752b6/12 entries
