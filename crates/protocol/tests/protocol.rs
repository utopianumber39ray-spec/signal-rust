use crypto_core::{
    DoubleRatchet, Error, IdentityKeyPair, OneTimePreKey, PreKeyBundle, RatchetKeyPair, Result,
    SignedPreKeyPublic,
};

struct Fixture {
    alice: IdentityKeyPair,
    bob: IdentityKeyPair,
    bundle: PreKeyBundle,
    signed: RatchetKeyPair,
    one_time: OneTimePreKey,
}

fn fixture(with_one_time: bool) -> Fixture {
    let alice = IdentityKeyPair::generate();
    let bob = IdentityKeyPair::generate();
    let signed = RatchetKeyPair::generate();
    let one_time = OneTimePreKey::generate(11);
    let bundle = PreKeyBundle {
        identity: bob.public(),
        signed_prekey: SignedPreKeyPublic::new(&bob, 1, &signed),
        one_time_prekey: with_one_time.then(|| one_time.public()),
    };
    Fixture {
        alice,
        bob,
        signed,
        one_time,
        bundle,
    }
}

fn connected() -> Result<(DoubleRatchet, DoubleRatchet)> {
    let fixture = fixture(true);
    let (mut alice, initial) = DoubleRatchet::new_initiator(&fixture.alice, &fixture.bundle)?;
    let mut bob = DoubleRatchet::new_receiver(
        &fixture.bob,
        1,
        &fixture.signed,
        Some(&fixture.one_time),
        &initial,
    )?;
    let alice_snapshot = alice.snapshot();
    let bob_snapshot = bob.snapshot();
    assert_eq!(alice_snapshot.root_key, bob_snapshot.root_key);
    assert_eq!(
        alice_snapshot.sending_chain.as_ref().map(|chain| chain.key),
        bob_snapshot.receiving_chain.as_ref().map(|chain| chain.key)
    );
    let mut first = alice.encrypt(b"hello", b"aad")?;
    first.initial = Some(initial);
    assert_eq!(bob.decrypt(&first, b"aad")?, b"hello");
    Ok((alice, bob))
}

#[test]
fn handshake_and_bidirectional_ratchet() -> Result<()> {
    let (mut alice, mut bob) = connected()?;
    for index in 0..12 {
        let expected = format!("message-{index}");
        let message = alice.encrypt(expected.as_bytes(), b"aad")?;
        assert_eq!(bob.decrypt(&message, b"aad")?, expected.as_bytes());
        let response = bob.encrypt(format!("response-{index}").as_bytes(), b"aad")?;
        assert_eq!(
            alice.decrypt(&response, b"aad")?,
            format!("response-{index}").as_bytes()
        );
    }
    Ok(())
}

#[test]
fn out_of_order_delivery_and_replay_rejection() -> Result<()> {
    let fixture = fixture(true);
    let (mut alice, initial) = DoubleRatchet::new_initiator(&fixture.alice, &fixture.bundle)?;
    let mut bob = DoubleRatchet::new_receiver(
        &fixture.bob,
        1,
        &fixture.signed,
        Some(&fixture.one_time),
        &initial,
    )?;
    let first = alice.encrypt(b"zero", b"aad")?;
    let second = alice.encrypt(b"one", b"aad")?;
    let third = alice.encrypt(b"third", b"aad")?;
    assert_eq!(bob.decrypt(&third, b"aad")?, b"third");
    assert_eq!(bob.decrypt(&first, b"aad")?, b"zero");
    assert_eq!(bob.decrypt(&second, b"aad")?, b"one");
    assert!(matches!(
        bob.decrypt(&second, b"aad"),
        Err(Error::MessageKeyUnavailable)
    ));
    Ok(())
}

#[test]
fn tampering_does_not_advance_state() -> Result<()> {
    let (mut alice, mut bob) = connected()?;
    let valid = alice.encrypt(b"valid", b"aad")?;
    let mut forged = valid.clone();
    forged.ciphertext[0] ^= 1;
    assert!(matches!(
        bob.decrypt(&forged, b"aad"),
        Err(Error::Authentication)
    ));
    assert_eq!(bob.decrypt(&valid, b"aad")?, b"valid");
    Ok(())
}

#[test]
fn serialization_preserves_skipped_keys_and_replay_state() -> Result<()> {
    let (mut alice, mut bob) = connected()?;
    let first = alice.encrypt(b"first", b"aad")?;
    let second = alice.encrypt(b"second", b"aad")?;
    let third = alice.encrypt(b"third", b"aad")?;
    assert_eq!(bob.decrypt(&third, b"aad")?, b"third");
    let mut restored = DoubleRatchet::from_bytes(&bob.to_bytes()?)?;
    assert_eq!(restored.decrypt(&first, b"aad")?, b"first");
    assert_eq!(restored.decrypt(&second, b"aad")?, b"second");
    assert!(restored.decrypt(&second, b"aad").is_err());
    Ok(())
}

#[test]
fn invalid_prekey_signature_is_rejected() -> Result<()> {
    let alice = IdentityKeyPair::generate();
    let bob = IdentityKeyPair::generate();
    let signed = RatchetKeyPair::generate();
    let mut public = crypto_core::SignedPreKeyPublic::new(&bob, 1, &signed);
    public.signature[0] ^= 1;
    let bundle = crypto_core::PreKeyBundle {
        identity: bob.public(),
        signed_prekey: public,
        one_time_prekey: None,
    };
    assert!(matches!(
        DoubleRatchet::new_initiator(&alice, &bundle),
        Err(Error::InvalidSignedPreKey)
    ));
    Ok(())
}

#[test]
fn post_reply_root_key_changes() -> Result<()> {
    let (mut alice, mut bob) = connected()?;
    let initial_root = alice.snapshot().root_key;
    let reply = bob.encrypt(b"reply", b"aad")?;
    alice.decrypt(&reply, b"aad")?;
    assert_ne!(alice.snapshot().root_key, initial_root);
    assert_ne!(alice.snapshot().root_key, [0_u8; 32]);
    Ok(())
}
