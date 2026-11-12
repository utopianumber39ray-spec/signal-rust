use signal_client::{Client, ClientError};
use signal_server::QueuedMessage;
use signal_storage::{
    DeliveryState, Direction, MediaMetadata, MessageContent, StorageError, Store,
};
use std::error::Error;
use tokio::net::TcpListener;
use uuid::Uuid;

type TestResult = Result<(), Box<dyn Error>>;

fn packet(packets: &[QueuedMessage], id: Uuid) -> Result<QueuedMessage, Box<dyn Error>> {
    packets
        .iter()
        .find(|packet| packet.id == id)
        .cloned()
        .ok_or_else(|| format!("packet {id} was not queued").into())
}

fn assert_state(client: &Client, peer_id: Uuid, id: Uuid, state: DeliveryState) -> TestResult {
    let record = client
        .history(peer_id)?
        .into_iter()
        .find(|message| message.id == id)
        .ok_or("message history record missing")?;
    assert_eq!(record.state, state);
    Ok(())
}

#[tokio::test]
async fn live_end_to_end_messaging() -> TestResult {
    let directory = tempfile::tempdir()?;
    let alice_path = directory.path().join("alice.sqlite");
    let bob_path = directory.path().join("bob.sqlite");
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let database = signal_server::Database::in_memory().await?;
    let server = tokio::spawn(async move { signal_server::serve(listener, database).await });
    let server_url = format!("http://{address}");

    let mut alice = Client::register(
        Store::open(&alice_path, "alice test passphrase")?,
        &server_url,
        "alice",
    )
    .await?;
    let mut bob = Client::register(
        Store::open(&bob_path, "bob test passphrase")?,
        &server_url,
        "bob",
    )
    .await?;
    let alice_id = alice.user_id();
    let bob_id = bob.user_id();

    let bob_contact = alice.add_contact("bob").await?;
    let alice_contact = bob.add_contact("alice").await?;
    assert_eq!(bob_contact.fingerprint.len(), 64);
    assert_eq!(alice_contact.fingerprint.len(), 64);
    alice.verify_contact(bob_id)?;
    bob.verify_contact(alice_id)?;
    assert!(alice.contact("bob")?.verified);
    alice.start_session("bob").await?;

    let first_id = alice.send_text("bob", "first").await?;
    let second_id = alice.send_text("bob", "second").await?;
    let third_id = alice.send_text("bob", "third").await?;
    bob.rotate_prekeys().await?;

    let queued = bob.pending().await?;
    assert_eq!(queued.len(), 3);
    let first_packet = packet(&queued, first_id)?;
    assert!(first_packet.payload.initial.is_some());
    assert!(!String::from_utf8_lossy(&first_packet.payload.ciphertext).contains("first"));
    let first_event = bob
        .process_packet(first_packet.clone())
        .await?
        .ok_or("first event missing")?;
    assert_eq!(
        first_event.content,
        MessageContent::Text {
            text: "first".to_owned()
        }
    );
    let duplicate = bob.process_packet(first_packet).await?;
    assert!(duplicate.is_none());
    let third_event = bob
        .process_packet(packet(&queued, third_id)?)
        .await?
        .ok_or("third event missing")?;
    let second_event = bob
        .process_packet(packet(&queued, second_id)?)
        .await?
        .ok_or("second event missing")?;
    assert_eq!(
        third_event.content,
        MessageContent::Text {
            text: "third".to_owned()
        }
    );
    assert_eq!(
        second_event.content,
        MessageContent::Text {
            text: "second".to_owned()
        }
    );
    assert!(bob.pending().await?.is_empty());

    for id in [first_id, second_id, third_id] {
        bob.send_delivery_receipt("alice", id).await?;
    }
    let delivery_report = alice.poll().await?;
    assert!(delivery_report.warnings.is_empty());
    for id in [first_id, second_id, third_id] {
        assert_state(&alice, bob_id, id, DeliveryState::Delivered)?;
    }
    bob.send_read_receipt("alice").await?;
    alice.poll().await?;
    for id in [first_id, second_id, third_id] {
        assert_state(&alice, bob_id, id, DeliveryState::Read)?;
    }
    bob.send_delivery_receipt("alice", first_id).await?;
    alice.poll().await?;
    assert_state(&alice, bob_id, first_id, DeliveryState::Read)?;

    let media_path = directory.path().join("note.txt");
    std::fs::write(&media_path, b"local attachment bytes are not relayed")?;
    let reply_id = bob.send_text("alice", "reply").await?;
    let media_id = bob.send_media("alice", &media_path, "text/plain").await?;
    let incoming = alice.poll().await?;
    assert!(incoming.warnings.is_empty());
    assert_eq!(incoming.events.len(), 2);
    assert!(incoming.events.iter().any(|event| {
        event.content
            == MessageContent::Text {
                text: "reply".to_owned(),
            }
    }));
    assert!(incoming.events.iter().any(|event| {
        matches!(
            &event.content,
            MessageContent::Media(MediaMetadata { filename, size, .. })
                if filename == "note.txt" && *size == 38
        )
    }));
    alice.send_read_receipt("bob").await?;
    bob.poll().await?;
    assert_state(&bob, alice_id, reply_id, DeliveryState::Read)?;
    assert_state(&bob, alice_id, media_id, DeliveryState::Read)?;
    assert!(alice
        .history(bob_id)?
        .into_iter()
        .filter(|message| message.direction == Direction::Incoming)
        .all(|message| message.state == DeliveryState::Read));

    let expected_alice_id = alice_id;
    drop(alice);
    assert!(matches!(
        Store::open(&alice_path, "wrong passphrase"),
        Err(StorageError::WrongPassphrase)
    ));
    let mut alice = Client::open(
        Store::open(&alice_path, "alice test passphrase")?,
        &server_url,
    )?;
    assert_eq!(alice.user_id(), expected_alice_id);
    let after_reopen = bob.send_text("alice", "after reopen").await?;
    let reopened_report = alice.poll().await?;
    assert!(reopened_report.warnings.is_empty());
    assert!(reopened_report.events.iter().any(|event| {
        event.message_id == after_reopen
            && event.content
                == MessageContent::Text {
                    text: "after reopen".to_owned(),
                }
    }));

    let unknown_id = Uuid::new_v4();
    let unknown = QueuedMessage {
        id: unknown_id,
        sender_id: Uuid::new_v4(),
        recipient_id: alice_id,
        payload: crypto_core::EncryptedMessage {
            id: unknown_id,
            initial: None,
            header: crypto_core::RatchetHeader {
                ratchet_public: [0; 32],
                previous_chain_length: 0,
                message_number: 0,
            },
            nonce: [0; 12],
            ciphertext: vec![0; 16],
        },
        created_at: 0,
    };
    assert!(matches!(
        alice.process_packet(unknown).await,
        Err(ClientError::UnknownContact)
    ));

    server.abort();
    let _ = server.await;
    println!("END_TO_END_PASSED");
    Ok(())
}
