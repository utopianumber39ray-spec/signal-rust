use crypto_core::{
    DoubleRatchet, IdentityKeyPair, PreKeyBundle, RatchetKeyPair, SignedPreKeyPublic,
};
use signal_storage::{
    Contact, DeliveryState, Direction, MediaMetadata, MessageContent, MessageRecord,
    PreKeyMaterial, StorageError, Store, StoredAccount,
};
use std::error::Error;
use uuid::Uuid;

type TestResult = Result<(), Box<dyn Error>>;

fn sample_account() -> StoredAccount {
    let identity = IdentityKeyPair::generate();
    StoredAccount {
        user_id: Uuid::new_v4(),
        username: "alice".to_owned(),
        token: "private-bearer-token".to_owned(),
        identity_dh: identity.dh_secret_bytes(),
        identity_signing: identity.signing_bytes(),
        signed_prekeys: vec![PreKeyMaterial {
            id: 1,
            secret: RatchetKeyPair::generate().secret_bytes(),
        }],
        one_time_prekeys: Vec::new(),
        next_prekey_id: 1,
    }
}

fn contains_bytes(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|window| window == needle)
}

#[test]
fn vault_persists_secrets_sessions_contacts_and_messages() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("vault.sqlite");
    let account = sample_account();
    let identity = account.identity();
    let peer = IdentityKeyPair::generate();
    let signed = RatchetKeyPair::generate();
    let bundle = PreKeyBundle {
        identity: peer.public(),
        signed_prekey: SignedPreKeyPublic::new(&peer, 1, &signed),
        one_time_prekey: None,
    };
    let (session, _) = DoubleRatchet::new_initiator(&peer, &bundle)?;
    let peer_id = Uuid::new_v4();
    let message_id = Uuid::new_v4();
    let store = Store::open(&path, "correct horse battery staple")?;
    store.save_account(&account)?;
    store.save_contact(&Contact::new(peer_id, "bob".to_owned(), identity.public()))?;
    store.save_message(&MessageRecord {
        id: message_id,
        peer_id,
        direction: Direction::Outgoing,
        content: MessageContent::Text {
            text: "private history".to_owned(),
        },
        state: DeliveryState::Sent,
        created_at: 1,
    })?;
    store.save_message(&MessageRecord {
        id: Uuid::new_v4(),
        peer_id,
        direction: Direction::Incoming,
        content: MessageContent::Media(MediaMetadata {
            filename: "photo.jpg".to_owned(),
            mime_type: "image/jpeg".to_owned(),
            size: 128,
            sha256: [3; 32],
        }),
        state: DeliveryState::Delivered,
        created_at: 2,
    })?;
    store.save_session(peer_id, &session)?;
    assert!(store.mark_delivered(message_id)?);
    assert!(store.mark_read(message_id)?);
    store.set_contact_verified(peer_id, true)?;
    drop(store);

    assert!(matches!(
        Store::open(&path, "wrong"),
        Err(StorageError::WrongPassphrase)
    ));
    let reopened = Store::open(&path, "correct horse battery staple")?;
    let restored = reopened.account()?;
    assert_eq!(restored.user_id, account.user_id);
    assert_eq!(restored.token, account.token);
    let loaded_session = reopened.load_session(peer_id)?.ok_or("session missing")?;
    assert_eq!(
        loaded_session.snapshot().root_key,
        session.snapshot().root_key
    );
    assert!(
        reopened
            .contact(peer_id)?
            .ok_or("contact missing")?
            .verified
    );
    let messages = reopened.messages(peer_id)?;
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].state, DeliveryState::Read);
    assert_eq!(
        messages[0].content,
        MessageContent::Text {
            text: "private history".to_owned()
        }
    );
    let connection = rusqlite::Connection::open(&path)?;
    let mut statement = connection.prepare("SELECT nonce,ciphertext FROM vault_records")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    for row in rows {
        let (nonce, ciphertext) = row?;
        assert!(!nonce.is_empty());
        assert!(!ciphertext.is_empty());
    }
    drop(reopened);
    let raw = std::fs::read(path)?;
    assert!(!contains_bytes(&raw, b"alice"));
    assert!(!contains_bytes(&raw, b"private history"));
    assert!(!contains_bytes(&raw, &identity.dh_secret_bytes()));
    Ok(())
}

#[test]
fn tampering_is_detected_and_wrong_passphrase_is_rejected() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("vault.sqlite");
    let store = Store::open(&path, "correct-passphrase")?;
    store.save_account(&sample_account())?;
    drop(store);
    let connection = rusqlite::Connection::open(&path)?;
    let rowid: i64 = connection.query_row(
        "SELECT rowid FROM vault_records ORDER BY rowid LIMIT 1 OFFSET 1",
        [],
        |row| row.get(0),
    )?;
    connection.execute(
        "UPDATE vault_records SET ciphertext=x'00' WHERE rowid=?1",
        [rowid],
    )?;
    drop(connection);
    let store = Store::open(&path, "correct-passphrase")?;
    assert!(matches!(store.account(), Err(StorageError::Authentication)));
    assert!(matches!(
        Store::open(&path, "wrong"),
        Err(StorageError::WrongPassphrase)
    ));
    Ok(())
}

#[test]
fn same_plaintext_gets_fresh_nonce_and_ciphertext() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("fresh.sqlite");
    let store = Store::open(&path, "a strong passphrase")?;
    let account = sample_account();
    store.save_account(&account)?;
    let connection = rusqlite::Connection::open(&path)?;
    let first: (Vec<u8>, Vec<u8>) = connection.query_row(
        "SELECT nonce,ciphertext FROM vault_records ORDER BY rowid LIMIT 1 OFFSET 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    store.save_account(&account)?;
    let second: (Vec<u8>, Vec<u8>) = connection.query_row(
        "SELECT nonce,ciphertext FROM vault_records ORDER BY rowid LIMIT 1 OFFSET 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_ne!(first, second);
    Ok(())
}
