use crate::{Client, ClientError, PollReport, ReceivedEvent, Result};
use chrono::Utc;
use crypto_core::{DoubleRatchet, IdentityPublic, InitialHeader};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use signal_server::{QueuedMessage, SendMessageRequest};
use signal_storage::{
    DeliveryState, Direction, MediaMetadata, MessageContent, MessageRecord, OutgoingMessage,
};
use std::path::Path;
use tokio::io::AsyncReadExt;
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_READ_RECEIPTS: usize = 256;
const CONTENT_AAD: &[u8] = b"signal-rust/content/v1";

#[derive(Deserialize)]
struct RelayResponse {
    id: Uuid,
}

impl Client {
    pub async fn send_text(&mut self, username: &str, text: &str) -> Result<Uuid> {
        if text.len() > MAX_TEXT_BYTES {
            return Err(ClientError::InvalidInput(
                "text messages are limited to 64 KiB".to_owned(),
            ));
        }
        self.send_content(
            username,
            MessageContent::Text {
                text: text.to_owned(),
            },
        )
        .await
    }

    pub async fn send_media(
        &mut self,
        username: &str,
        path: impl AsRef<Path>,
        mime_type: &str,
    ) -> Result<Uuid> {
        let path = path.as_ref();
        if mime_type.is_empty()
            || mime_type.len() > 128
            || !mime_type.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(ClientError::InvalidInput(
                "invalid media MIME type".to_owned(),
            ));
        }
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty() && name.len() <= 512)
            .ok_or_else(|| ClientError::InvalidInput("invalid media filename".to_owned()))?
            .to_owned();
        let mut file = tokio::fs::File::open(path).await.map_err(|error| {
            ClientError::InvalidInput(format!("cannot open media metadata source: {error}"))
        })?;
        let mut hasher = Sha256::new();
        let mut size = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer).await.map_err(|error| {
                ClientError::InvalidInput(format!("cannot read media metadata source: {error}"))
            })?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
            size = size
                .checked_add(count as u64)
                .ok_or_else(|| ClientError::InvalidInput("media source is too large".to_owned()))?;
        }
        self.send_content(
            username,
            MessageContent::Media(MediaMetadata {
                filename,
                mime_type: mime_type.to_owned(),
                size,
                sha256: hasher.finalize().into(),
            }),
        )
        .await
    }

    pub async fn send_delivery_receipt(
        &mut self,
        username: &str,
        message_id: Uuid,
    ) -> Result<Uuid> {
        self.send_content(username, MessageContent::DeliveryReceipt { message_id })
            .await
    }

    pub async fn send_read_receipt(&mut self, username: &str) -> Result<Option<Uuid>> {
        let contact = self.contact(username)?;
        let unread: Vec<Uuid> = self
            .store
            .messages(contact.user_id)?
            .into_iter()
            .filter(|message| {
                message.direction == Direction::Incoming
                    && message.state != DeliveryState::Read
                    && matches!(
                        message.content,
                        MessageContent::Text { .. } | MessageContent::Media(_)
                    )
            })
            .take(MAX_READ_RECEIPTS)
            .map(|message| message.id)
            .collect();
        if unread.is_empty() {
            return Ok(None);
        }
        let id = self
            .send_content(
                username,
                MessageContent::ReadReceipt {
                    message_ids: unread.clone(),
                },
            )
            .await?;
        for message_id in unread {
            self.store.mark_local_read(message_id)?;
        }
        Ok(Some(id))
    }

    async fn send_content(&mut self, username: &str, content: MessageContent) -> Result<Uuid> {
        validate_content(&content)?;
        if self
            .store
            .load_session(self.contact(username)?.user_id)?
            .is_none()
        {
            self.start_session(username).await?;
        }
        let contact = self.contact(username)?;
        let mut session = self
            .store
            .load_session(contact.user_id)?
            .ok_or(ClientError::NoSession)?;
        let initial = self.store.pending_initial(contact.user_id)?;
        let aad = content_associated_data(
            self.account.user_id,
            &self.account.identity().public(),
            contact.user_id,
            &contact.identity,
            &initial,
        )?;
        let plaintext = Zeroizing::new(serde_json::to_vec(&content)?);
        let mut message = session.encrypt(&plaintext, &aad)?;
        message.initial = initial;
        self.store.save_session(contact.user_id, &session)?;
        let outgoing = OutgoingMessage {
            peer_id: contact.user_id,
            message: message.clone(),
        };
        self.store.save_outgoing(&outgoing)?;
        if matches!(
            content,
            MessageContent::Text { .. } | MessageContent::Media(_)
        ) {
            self.store.save_message(&MessageRecord {
                id: message.id,
                peer_id: contact.user_id,
                direction: Direction::Outgoing,
                content,
                state: DeliveryState::Queued,
                created_at: Utc::now().timestamp_millis(),
            })?;
        }
        self.flush_packet(&outgoing).await?;
        Ok(message.id)
    }

    pub async fn flush_outbox(&mut self) -> Result<usize> {
        let outbox = self.store.outbox()?;
        let mut delivered = 0_usize;
        for packet in outbox {
            self.flush_packet(&packet).await?;
            delivered = delivered.saturating_add(1);
        }
        Ok(delivered)
    }

    async fn flush_packet(&self, packet: &OutgoingMessage) -> Result<()> {
        let response: RelayResponse = crate::net::request_json(
            &self.http,
            &self.server,
            Some(&self.account.token),
            reqwest::Method::POST,
            "/v1/messages",
            Some(&SendMessageRequest {
                recipient_id: packet.peer_id,
                message: packet.message.clone(),
            }),
        )
        .await?;
        if response.id != packet.message.id {
            return Err(ClientError::InvalidInput(
                "relay returned a different message id".to_owned(),
            ));
        }
        self.store.delete_outgoing(packet.message.id)?;
        if let Some(mut record) = self.store.message(packet.message.id)? {
            if record.direction == Direction::Outgoing && record.state == DeliveryState::Queued {
                record.state = DeliveryState::Sent;
                self.store.save_message(&record)?;
            }
        }
        if packet.message.initial.is_some() {
            self.store.clear_pending_initial(packet.peer_id)?;
        }
        Ok(())
    }

    pub async fn pending(&self) -> Result<Vec<QueuedMessage>> {
        crate::net::request_json(
            &self.http,
            &self.server,
            Some(&self.account.token),
            reqwest::Method::GET,
            "/v1/messages?limit=100",
            None::<&()>,
        )
        .await
    }

    pub async fn process_packet(&mut self, packet: QueuedMessage) -> Result<Option<ReceivedEvent>> {
        if packet.id != packet.payload.id || packet.recipient_id != self.account.user_id {
            return Err(ClientError::InvalidInput(
                "inconsistent relay packet metadata".to_owned(),
            ));
        }
        let contact = self
            .store
            .contact(packet.sender_id)?
            .ok_or(ClientError::UnknownContact)?;
        let digest: [u8; 32] = Sha256::digest(serde_json::to_vec(&packet)?).into();
        if let Some(previous) = self.store.seen(packet.id)? {
            if previous != digest {
                return Err(ClientError::InvalidInput(
                    "a relay packet id was reused for different ciphertext".to_owned(),
                ));
            }
            self.acknowledge(packet.id).await?;
            return Ok(None);
        }

        let mut session = self.store.load_session(packet.sender_id)?;
        let mut consumed_prekey = None;
        if session.is_none() {
            let initial = packet
                .payload
                .initial
                .as_ref()
                .ok_or(ClientError::NoSession)?;
            if initial.sender_identity != contact.identity {
                return Err(ClientError::InvalidInput(
                    "initial header does not match the pinned identity".to_owned(),
                ));
            }
            let signed = self
                .account
                .signed_prekeys
                .iter()
                .find(|key| key.id == initial.signed_prekey_id)
                .cloned()
                .ok_or(ClientError::NoSession)?;
            let one_time = match initial.one_time_prekey_id {
                Some(id) => {
                    let key = self
                        .account
                        .one_time_prekeys
                        .iter()
                        .find(|key| key.id == id)
                        .cloned()
                        .ok_or(ClientError::NoSession)?;
                    consumed_prekey = Some(id);
                    Some(key.one_time_key())
                }
                None => None,
            };
            session = Some(DoubleRatchet::new_receiver(
                &self.account.identity(),
                signed.id,
                &signed.ratchet_key(),
                one_time.as_ref(),
                initial,
            )?);
        }
        let mut session = session.ok_or(ClientError::NoSession)?;
        let aad = content_associated_data(
            contact.user_id,
            &contact.identity,
            self.account.user_id,
            &self.account.identity().public(),
            &packet.payload.initial,
        )?;
        let plaintext = Zeroizing::new(session.decrypt(&packet.payload, &aad)?);
        let content: MessageContent = serde_json::from_slice(&plaintext)?;
        validate_content(&content)?;
        let created_at = Utc::now().timestamp_millis();

        match &content {
            MessageContent::Text { .. } | MessageContent::Media(_) => {
                self.store.save_message(&MessageRecord {
                    id: packet.id,
                    peer_id: contact.user_id,
                    direction: Direction::Incoming,
                    content: content.clone(),
                    state: DeliveryState::Delivered,
                    created_at,
                })?;
            }
            MessageContent::DeliveryReceipt { message_id } => {
                self.store.mark_delivered(*message_id)?;
            }
            MessageContent::ReadReceipt { message_ids } => {
                for message_id in message_ids {
                    self.store.mark_read(*message_id)?;
                }
            }
        }
        self.store.save_session(contact.user_id, &session)?;
        if let Some(prekey_id) = consumed_prekey {
            let mut account = self.account.clone();
            account.one_time_prekeys.retain(|key| key.id != prekey_id);
            self.store.save_account(&account)?;
            self.account = account;
        }
        self.store.save_seen(packet.id, digest)?;
        self.acknowledge(packet.id).await?;
        Ok(Some(ReceivedEvent {
            peer_id: contact.user_id,
            message_id: packet.id,
            content,
            created_at,
        }))
    }

    pub async fn poll(&mut self) -> Result<PollReport> {
        let packets = self.pending().await?;
        let mut report = PollReport::default();
        for packet in packets {
            let packet_id = packet.id;
            match self.process_packet(packet).await {
                Ok(Some(event)) => {
                    if matches!(
                        event.content,
                        MessageContent::Text { .. } | MessageContent::Media(_)
                    ) {
                        let contact = self
                            .store
                            .contact(event.peer_id)?
                            .ok_or(ClientError::UnknownContact)?;
                        if let Err(error) = self
                            .send_delivery_receipt(&contact.username, event.message_id)
                            .await
                        {
                            report.warnings.push(format!(
                                "delivery receipt for {} is queued or failed: {error}",
                                contact.username
                            ));
                        }
                    }
                    report.events.push(event);
                }
                Ok(None) => {}
                Err(error) => report
                    .warnings
                    .push(format!("unacknowledged packet {}: {error}", packet_id)),
            }
        }
        if let Err(error) = self.flush_outbox().await {
            report
                .warnings
                .push(format!("outbox retry failed: {error}"));
        }
        Ok(report)
    }

    async fn acknowledge(&self, message_id: Uuid) -> Result<()> {
        match self
            .post_no_content(&format!("/v1/messages/{message_id}/ack"), &())
            .await
        {
            Err(ClientError::Server { status: 404, .. }) => Ok(()),
            result => result,
        }
    }
}

fn validate_content(content: &MessageContent) -> Result<()> {
    match content {
        MessageContent::Text { text } if text.len() > MAX_TEXT_BYTES => Err(
            ClientError::InvalidInput("text messages are limited to 64 KiB".to_owned()),
        ),
        MessageContent::ReadReceipt { message_ids }
            if message_ids.is_empty() || message_ids.len() > MAX_READ_RECEIPTS =>
        {
            Err(ClientError::InvalidInput(
                "read receipt batch must contain 1 to 256 ids".to_owned(),
            ))
        }
        MessageContent::Media(metadata)
            if metadata.filename.is_empty()
                || metadata.filename.len() > 512
                || metadata.mime_type.is_empty()
                || metadata.mime_type.len() > 128 =>
        {
            Err(ClientError::InvalidInput(
                "invalid media metadata".to_owned(),
            ))
        }
        _ => Ok(()),
    }
}

fn content_associated_data(
    sender_id: Uuid,
    sender_identity: &IdentityPublic,
    recipient_id: Uuid,
    recipient_identity: &IdentityPublic,
    initial: &Option<InitialHeader>,
) -> Result<Vec<u8>> {
    let initial = serde_json::to_vec(initial)?;
    let mut aad = Vec::with_capacity(CONTENT_AAD.len() + 168 + initial.len());
    aad.extend_from_slice(CONTENT_AAD);
    aad.extend_from_slice(sender_id.as_bytes());
    aad.extend_from_slice(recipient_id.as_bytes());
    aad.extend_from_slice(&sender_identity.dh);
    aad.extend_from_slice(&sender_identity.signing);
    aad.extend_from_slice(&recipient_identity.dh);
    aad.extend_from_slice(&recipient_identity.signing);
    aad.extend_from_slice(&(initial.len() as u64).to_be_bytes());
    aad.extend_from_slice(&initial);
    Ok(aad)
}
