use crate::keys::{IdentityKeyPair, OneTimePreKey, RatchetKeyPair};
use crate::x3dh;
use crate::{Error, InitialHeader, PreKeyBundle, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use uuid::Uuid;
use x25519_dalek::PublicKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

const ROOT_CONTEXT: &[u8] = b"signal-rust/root-ratchet/v1";
const MESSAGE_KEY_INFO: &[u8] = b"signal-rust-message-key/v1";
const CHAIN_KEY_INFO: &[u8] = b"signal-rust-chain-key/v1";
const MAX_SKIPPED: usize = 2_000;
const MAX_CHAIN_GAP: u32 = 2_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RatchetHeader {
    pub ratchet_public: [u8; 32],
    pub previous_chain_length: u32,
    pub message_number: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub id: Uuid,
    pub initial: Option<InitialHeader>,
    pub header: RatchetHeader,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SkippedKeyId {
    pub ratchet_public: [u8; 32],
    pub message_number: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ChainSnapshot {
    pub key: [u8; 32],
    pub next_index: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SessionSnapshot {
    pub root_key: [u8; 32],
    pub own_ratchet_secret: [u8; 32],
    pub remote_ratchet: Option<[u8; 32]>,
    pub sending_chain: Option<ChainSnapshot>,
    pub receiving_chain: Option<ChainSnapshot>,
    pub previous_sending_length: u32,
    pub skipped_keys: Vec<(SkippedKeyId, [u8; 32])>,
}

impl Drop for SessionSnapshot {
    fn drop(&mut self) {
        self.root_key.zeroize();
        self.own_ratchet_secret.zeroize();
        for (_, key) in &mut self.skipped_keys {
            key.zeroize();
        }
    }
}

#[derive(Clone)]
pub struct DoubleRatchet {
    root_key: [u8; 32],
    own_ratchet: RatchetKeyPair,
    remote_ratchet: Option<PublicKey>,
    sending_chain: Option<ChainState>,
    receiving_chain: Option<ChainState>,
    previous_sending_length: u32,
    skipped_keys: HashMap<SkippedKeyId, [u8; 32]>,
}

#[derive(Clone)]
struct ChainState {
    key: [u8; 32],
    next_index: u32,
}

impl DoubleRatchet {
    pub fn new_initiator(
        identity: &IdentityKeyPair,
        bundle: &PreKeyBundle,
    ) -> Result<(Self, InitialHeader)> {
        let ephemeral = RatchetKeyPair::generate();
        let (root, initial_header) = x3dh::initiate(identity, &ephemeral, bundle)?;
        let remote_ratchet = PublicKey::from(bundle.signed_prekey.public_key);
        let dh = ephemeral.dh(&remote_ratchet)?;
        let (root_key, sending_key) = root_step(root, &dh)?;
        Ok((
            Self {
                root_key,
                own_ratchet: ephemeral,
                remote_ratchet: Some(remote_ratchet),
                sending_chain: Some(ChainState {
                    key: sending_key,
                    next_index: 0,
                }),
                receiving_chain: None,
                previous_sending_length: 0,
                skipped_keys: HashMap::new(),
            },
            initial_header,
        ))
    }

    pub fn new_receiver(
        identity: &IdentityKeyPair,
        signed_prekey_id: u32,
        signed_prekey: &RatchetKeyPair,
        one_time_prekey: Option<&OneTimePreKey>,
        initial: &InitialHeader,
    ) -> Result<Self> {
        if initial.signed_prekey_id != signed_prekey_id {
            return Err(Error::InvalidInitialAuthentication);
        }
        let root = x3dh::respond(identity, signed_prekey, one_time_prekey, initial)?;
        let remote = PublicKey::from(initial.ephemeral_public);
        let dh = signed_prekey.dh(&remote)?;
        let (root_key, receiving_key) = root_step(root, &dh)?;
        Ok(Self {
            root_key,
            own_ratchet: signed_prekey.clone(),
            remote_ratchet: Some(remote),
            sending_chain: None,
            receiving_chain: Some(ChainState {
                key: receiving_key,
                next_index: 0,
            }),
            previous_sending_length: 0,
            skipped_keys: HashMap::new(),
        })
    }

    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedMessage> {
        if self.sending_chain.is_none() {
            self.begin_sending_ratchet()?;
        }
        let sending = self
            .sending_chain
            .as_mut()
            .ok_or(Error::InvalidState("missing sending chain"))?;
        let mut message_key = hmac_output(&sending.key, MESSAGE_KEY_INFO)?;
        let header = RatchetHeader {
            ratchet_public: self.own_ratchet.public_bytes(),
            previous_chain_length: self.previous_sending_length,
            message_number: sending.next_index,
        };
        let nonce = random_nonce();
        let id = Uuid::new_v4();
        let ciphertext = encrypt_with_key(&message_key, &nonce, plaintext, aad, &header, &id)?;
        sending.next_index = sending
            .next_index
            .checked_add(1)
            .ok_or(Error::InvalidState("sending chain exhausted"))?;
        sending.key = hmac_output(&sending.key, CHAIN_KEY_INFO)?;
        message_key.zeroize();
        Ok(EncryptedMessage {
            id,
            header,
            initial: None,
            nonce,
            ciphertext,
        })
    }

    pub fn decrypt(
        &mut self,
        message: &EncryptedMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let mut candidate = self.clone();
        let plaintext = candidate.decrypt_inner(message, associated_data)?;
        *self = candidate;
        Ok(plaintext)
    }

    fn decrypt_inner(
        &mut self,
        message: &EncryptedMessage,
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let key_id = SkippedKeyId {
            ratchet_public: message.header.ratchet_public,
            message_number: message.header.message_number,
        };
        if let Some(key) = self.skipped_keys.get(&key_id).copied() {
            let plaintext = decrypt_payload(
                &key,
                &message.nonce,
                &message.ciphertext,
                associated_data,
                &message.header,
                &message.id,
            )?;
            self.skipped_keys.remove(&key_id);
            return Ok(plaintext);
        }
        let remote = message.header.ratchet_public;
        if self.remote_ratchet.map(|value| value.to_bytes()) != Some(remote) {
            self.skip_to(message.header.previous_chain_length)?;
            self.dh_ratchet(&PublicKey::from(remote))?;
        }
        self.skip_to(message.header.message_number)?;
        let chain = self
            .receiving_chain
            .as_mut()
            .ok_or(Error::InvalidState("receiving chain missing"))?;
        let mut message_key = next_message_key(chain)?;
        let plaintext = decrypt_payload(
            &message_key,
            &message.nonce,
            &message.ciphertext,
            associated_data,
            &message.header,
            &message.id,
        )?;
        message_key.zeroize();
        Ok(plaintext)
    }

    fn begin_sending_ratchet(&mut self) -> Result<()> {
        let remote = self
            .remote_ratchet
            .ok_or(Error::InvalidState("missing remote ratchet key"))?;
        let own = RatchetKeyPair::generate();
        let (root, sending_key) = root_step(self.root_key, &own.dh(&remote)?)?;
        self.previous_sending_length = self
            .sending_chain
            .as_ref()
            .map_or(0, |chain| chain.next_index);
        self.root_key = root;
        self.sending_chain = Some(ChainState {
            key: sending_key,
            next_index: 0,
        });
        self.own_ratchet = own;
        Ok(())
    }

    fn dh_ratchet(&mut self, remote: &PublicKey) -> Result<()> {
        let dh = self.own_ratchet.dh(remote)?;
        let (root, receiving_key) = root_step(self.root_key, &dh)?;
        self.previous_sending_length = self
            .sending_chain
            .as_ref()
            .map_or(0, |chain| chain.next_index);
        self.root_key = root;
        self.remote_ratchet = Some(*remote);
        self.receiving_chain = Some(ChainState {
            key: receiving_key,
            next_index: 0,
        });
        let own = RatchetKeyPair::generate();
        let dh = own.dh(remote)?;
        let (root, sending_key) = root_step(self.root_key, &dh)?;
        self.root_key = root;
        self.own_ratchet = own;
        self.sending_chain = Some(ChainState {
            key: sending_key,
            next_index: 0,
        });
        Ok(())
    }

    fn skip_to(&mut self, target: u32) -> Result<()> {
        let Some(chain) = self.receiving_chain.as_mut() else {
            return if target == 0 {
                Ok(())
            } else {
                Err(Error::MessageKeyUnavailable)
            };
        };
        if target < chain.next_index {
            return Err(Error::MessageKeyUnavailable);
        }
        let gap = target - chain.next_index;
        if gap > MAX_CHAIN_GAP || self.skipped_keys.len().saturating_add(gap as usize) > MAX_SKIPPED
        {
            return Err(Error::TooManySkippedKeys);
        }
        let ratchet_public = self
            .remote_ratchet
            .ok_or(Error::InvalidState("missing remote ratchet key"))?
            .to_bytes();
        while chain.next_index < target {
            let message_number = chain.next_index;
            let key = next_message_key(chain)?;
            self.skipped_keys.insert(
                SkippedKeyId {
                    ratchet_public,
                    message_number,
                },
                key,
            );
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(&self.snapshot())?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let snapshot: SessionSnapshot = bincode::deserialize(bytes)?;
        Ok(Self {
            root_key: snapshot.root_key,
            own_ratchet: RatchetKeyPair::from_bytes(snapshot.own_ratchet_secret),
            remote_ratchet: snapshot.remote_ratchet.map(PublicKey::from),
            sending_chain: snapshot.sending_chain.as_ref().map(|chain| ChainState {
                key: chain.key,
                next_index: chain.next_index,
            }),
            receiving_chain: snapshot.receiving_chain.as_ref().map(|chain| ChainState {
                key: chain.key,
                next_index: chain.next_index,
            }),
            previous_sending_length: snapshot.previous_sending_length,
            skipped_keys: snapshot.skipped_keys.iter().cloned().collect(),
        })
    }

    pub fn snapshot(&self) -> SessionSnapshot {
        SessionSnapshot {
            root_key: self.root_key,
            own_ratchet_secret: self.own_ratchet.secret_bytes(),
            remote_ratchet: self.remote_ratchet.map(|key| key.to_bytes()),
            sending_chain: self.sending_chain.as_ref().map(ChainState::snapshot),
            receiving_chain: self.receiving_chain.as_ref().map(ChainState::snapshot),
            previous_sending_length: self.previous_sending_length,
            skipped_keys: self
                .skipped_keys
                .iter()
                .map(|(id, key)| (id.clone(), *key))
                .collect(),
        }
    }
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        self.root_key.zeroize();
        if let Some(chain) = &mut self.sending_chain {
            chain.key.zeroize();
        }
        if let Some(chain) = &mut self.receiving_chain {
            chain.key.zeroize();
        }
        for key in self.skipped_keys.values_mut() {
            key.zeroize();
        }
    }
}

impl ChainState {
    fn snapshot(&self) -> ChainSnapshot {
        ChainSnapshot {
            key: self.key,
            next_index: self.next_index,
        }
    }
}

fn root_step(root: [u8; 32], dh: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    let hkdf = Hkdf::<Sha256>::new(Some(&root), dh);
    let mut output = [0_u8; 64];
    hkdf.expand(ROOT_CONTEXT, &mut output)
        .map_err(|_| Error::InvalidLength)?;
    let mut root_key = [0_u8; 32];
    let mut chain_key = [0_u8; 32];
    root_key.copy_from_slice(&output[..32]);
    chain_key.copy_from_slice(&output[32..]);
    output.zeroize();
    Ok((root_key, chain_key))
}

fn next_message_key(chain: &mut ChainState) -> Result<[u8; 32]> {
    let next_index = chain
        .next_index
        .checked_add(1)
        .ok_or(Error::InvalidState("receiving chain exhausted"))?;
    let message_key = hmac_output(&chain.key, MESSAGE_KEY_INFO)?;
    chain.key = hmac_output(&chain.key, CHAIN_KEY_INFO)?;
    chain.next_index = next_index;
    Ok(message_key)
}

fn hmac_output(key: &[u8; 32], info: &[u8]) -> Result<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| Error::InvalidLength)?;
    mac.update(info);
    let output = mac.finalize().into_bytes();
    let mut result = [0_u8; 32];
    result.copy_from_slice(&output);
    Ok(result)
}

fn random_nonce() -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn full_aad(associated_data: &[u8], header: &RatchetHeader, message_id: &Uuid) -> Result<Vec<u8>> {
    let encoded_header = bincode::serialize(header)?;
    let mut aad = Vec::with_capacity(associated_data.len() + 24 + encoded_header.len());
    aad.extend_from_slice(&(associated_data.len() as u64).to_be_bytes());
    aad.extend_from_slice(associated_data);
    aad.extend_from_slice(message_id.as_bytes());
    aad.extend_from_slice(&encoded_header);
    Ok(aad)
}

fn encrypt_with_key(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    associated_data: &[u8],
    header: &RatchetHeader,
    message_id: &Uuid,
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::InvalidLength)?;
    let aad = full_aad(associated_data, header, message_id)?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Authentication)
}

fn decrypt_payload(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    associated_data: &[u8],
    header: &RatchetHeader,
    message_id: &Uuid,
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::InvalidLength)?;
    let aad = full_aad(associated_data, header, message_id)?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Authentication)
}
