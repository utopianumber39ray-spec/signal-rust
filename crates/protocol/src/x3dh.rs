use crate::keys::{IdentityKeyPair, IdentityPublic, OneTimePreKey, RatchetKeyPair};
use crate::{Error, PublicOneTimePreKey, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::PublicKey;
use zeroize::Zeroize;

pub const X3DH_CONTEXT: &[u8] = b"signal-rust-x3dh-v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedPreKeyPublic {
    pub id: u32,
    pub public_key: [u8; 32],
    pub signature: Vec<u8>,
}

impl SignedPreKeyPublic {
    pub fn new(identity: &IdentityKeyPair, id: u32, key: &RatchetKeyPair) -> Self {
        Self {
            id,
            public_key: key.public_bytes(),
            signature: identity
                .sign(&crate::keys::signed_prekey_signed_bytes(
                    id,
                    &key.public_bytes(),
                ))
                .to_vec(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub identity: IdentityPublic,
    pub signed_prekey: SignedPreKeyPublic,
    pub one_time_prekey: Option<PublicOneTimePreKey>,
}

impl PreKeyBundle {
    pub fn verify(&self) -> Result<()> {
        self.identity.verify_signed_prekey(&self.signed_prekey)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitialHeader {
    pub sender_identity: IdentityPublic,
    pub signed_prekey_id: u32,
    pub one_time_prekey_id: Option<u32>,
    pub ephemeral_public: [u8; 32],
    pub signature: Vec<u8>,
}

impl InitialHeader {
    pub(crate) fn verify(&self) -> Result<()> {
        let verifying = VerifyingKey::from_bytes(&self.sender_identity.signing)
            .map_err(|_| Error::InvalidInitialAuthentication)?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| Error::InvalidInitialAuthentication)?;
        let message = self.signing_bytes()?;
        verifying
            .verify_strict(&message, &signature)
            .map_err(|_| Error::InvalidInitialAuthentication)
    }

    pub(crate) fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut signed = self.clone();
        signed.signature.clear();
        Ok(bincode::serialize(&signed)?)
    }
}

pub(crate) fn initiate(
    identity: &IdentityKeyPair,
    ephemeral: &RatchetKeyPair,
    bundle: &PreKeyBundle,
) -> Result<([u8; 32], InitialHeader)> {
    bundle.verify()?;
    let dh1 = identity.dh(&bundle.signed_prekey.public_key)?;
    let dh2 = ephemeral.dh(&PublicKey::from(bundle.identity.dh))?;
    let dh3 = ephemeral.dh(&PublicKey::from(bundle.signed_prekey.public_key))?;
    let dh4 = match &bundle.one_time_prekey {
        Some(key) => Some(ephemeral.dh(&PublicKey::from(key.public_key))?),
        None => None,
    };
    let root_key = derive_root(&dh1, &dh2, &dh3, dh4.as_ref())?;
    let mut header = InitialHeader {
        sender_identity: identity.public(),
        signed_prekey_id: bundle.signed_prekey.id,
        one_time_prekey_id: bundle.one_time_prekey.as_ref().map(|key| key.id),
        ephemeral_public: ephemeral.public_bytes(),
        signature: Vec::new(),
    };
    header.signature = identity.sign(&header.signing_bytes()?).to_vec();
    Ok((root_key, header))
}

pub(crate) fn respond(
    identity: &IdentityKeyPair,
    signed_prekey: &RatchetKeyPair,
    one_time: Option<&OneTimePreKey>,
    header: &InitialHeader,
) -> Result<[u8; 32]> {
    header.verify()?;
    if header.one_time_prekey_id != one_time.map(|key| key.id) {
        return Err(Error::InvalidInitialAuthentication);
    }
    let dh1 = signed_prekey.dh(&PublicKey::from(header.sender_identity.dh))?;
    let dh2 = identity.dh(&header.ephemeral_public)?;
    let dh3 = signed_prekey.dh(&PublicKey::from(header.ephemeral_public))?;
    let dh4 = match one_time {
        Some(key) => Some(key.key.dh(&PublicKey::from(header.ephemeral_public))?),
        None => None,
    };
    derive_root(&dh1, &dh2, &dh3, dh4.as_ref())
}

fn derive_root(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    dh4: Option<&[u8; 32]>,
) -> Result<[u8; 32]> {
    let mut input = Vec::with_capacity(128);
    input.extend_from_slice(dh1);
    input.extend_from_slice(dh2);
    input.extend_from_slice(dh3);
    if let Some(value) = dh4 {
        input.extend_from_slice(value);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(X3DH_CONTEXT), &input);
    let mut root = [0_u8; 32];
    hkdf.expand(b"root", &mut root)
        .map_err(|_| Error::InvalidLength)?;
    input.zeroize();
    Ok(root)
}
