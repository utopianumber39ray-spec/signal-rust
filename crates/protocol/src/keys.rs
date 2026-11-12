use crate::{Error, Result, SignedPreKeyPublic};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

const SIGNED_PREKEY_CONTEXT: &[u8] = b"signal-rust/signed-prekey/v1";

#[derive(Clone)]
pub struct IdentityKeyPair {
    dh: StaticSecret,
    signing: SigningKey,
}

impl IdentityKeyPair {
    pub fn generate() -> Self {
        Self {
            dh: StaticSecret::random_from_rng(OsRng),
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn public(&self) -> IdentityPublic {
        IdentityPublic {
            dh: PublicKey::from(&self.dh).to_bytes(),
            signing: self.signing.verifying_key().to_bytes(),
        }
    }

    pub(crate) fn dh(&self, peer: &[u8; 32]) -> Result<[u8; 32]> {
        checked_dh(&self.dh, &PublicKey::from(*peer))
    }

    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.signing.sign(data).to_bytes()
    }

    pub fn dh_secret_bytes(&self) -> [u8; 32] {
        self.dh.to_bytes()
    }

    pub fn signing_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn from_bytes(dh_secret: [u8; 32], signing_secret: [u8; 32]) -> Self {
        Self {
            dh: dh_secret.into(),
            signing: SigningKey::from_bytes(&signing_secret),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityPublic {
    pub dh: [u8; 32],
    pub signing: [u8; 32],
}

impl IdentityPublic {
    pub fn verify_signed_prekey(&self, signed: &SignedPreKeyPublic) -> Result<()> {
        let key =
            VerifyingKey::from_bytes(&self.signing).map_err(|_| Error::InvalidSignedPreKey)?;
        let signature =
            Signature::from_slice(&signed.signature).map_err(|_| Error::InvalidSignedPreKey)?;
        key.verify_strict(
            &signed_prekey_signed_bytes(signed.id, &signed.public_key),
            &signature,
        )
        .map_err(|_| Error::InvalidSignedPreKey)
    }

    pub fn fingerprint(&self) -> String {
        let mut input = Vec::with_capacity(64);
        input.extend_from_slice(&self.dh);
        input.extend_from_slice(&self.signing);
        hex::encode(Sha256::digest(input))
    }
}

#[derive(Clone)]
pub struct RatchetKeyPair {
    pub(crate) secret: StaticSecret,
    pub(crate) public: PublicKey,
}

impl RatchetKeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn from_bytes(secret: [u8; 32]) -> Self {
        let secret = StaticSecret::from(secret);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public(&self) -> PublicKey {
        self.public
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    pub fn dh(&self, peer: &PublicKey) -> Result<[u8; 32]> {
        checked_dh(&self.secret, peer)
    }
}

#[derive(Clone)]
pub struct OneTimePreKey {
    pub id: u32,
    pub key: RatchetKeyPair,
}

impl OneTimePreKey {
    pub fn generate(id: u32) -> Self {
        Self {
            id,
            key: RatchetKeyPair::generate(),
        }
    }

    pub fn public(&self) -> PublicOneTimePreKey {
        PublicOneTimePreKey {
            id: self.id,
            public_key: self.key.public_bytes(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicOneTimePreKey {
    pub id: u32,
    pub public_key: [u8; 32],
}

pub(crate) fn checked_dh(secret: &StaticSecret, peer: &PublicKey) -> Result<[u8; 32]> {
    let shared = secret.diffie_hellman(peer);
    if shared.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(Error::InvalidState("degenerate Diffie-Hellman output"));
    }
    Ok(shared.to_bytes())
}

pub(crate) fn signed_prekey_signed_bytes(id: u32, public_key: &[u8; 32]) -> Vec<u8> {
    let mut input = Vec::with_capacity(SIGNED_PREKEY_CONTEXT.len() + 36);
    input.extend_from_slice(SIGNED_PREKEY_CONTEXT);
    input.extend_from_slice(&id.to_be_bytes());
    input.extend_from_slice(public_key);
    input
}
