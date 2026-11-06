//! Key replay precedes changed-head checks and all provider/credential work.
use super::{service::*, *};
use crate::client::lease::Deadline;
use hmac::{Hmac, Mac};
use se_store::channel::{Change, Connection, Pairing};
use se_types::{Result, Secret};
use sha2::{Digest, Sha256};

/// Pairing ticket is returned only by a protected native Owner call. Its Debug
/// and serialization are intentionally absent, keeping it out of normal logs.
pub struct PairingTicket {
    pub connection: ChannelId,
    pub revision: u64,
    pub expires_at_us: i64,
    pub(crate) link: Secret,
    pub receipt: Option<se_store::CommitReceipt>,
}
impl PairingTicket {
    pub fn expose_link(&self) -> &[u8] {
        self.link.expose()
    }
}
pub struct Connected {
    pub connection: Connection,
    pub ticket: PairingTicket,
    pub receipt: se_store::CommitReceipt,
}
pub struct Disconnected {
    pub receipt: se_store::CommitReceipt,
    pub credential_removal: CredentialRemoval,
}
impl Channels {
    pub async fn connect_telegram(
        &self,
        input: ConnectTelegram,
        deadline: &Deadline,
    ) -> Result<Connected> {
        let request = intent("channel.connect", input.key.clone(), &input)?;
        if let Some(receipt) = self
            .replay(input.target.project.clone(), request.clone(), deadline)
            .await?
        {
            let Change::Connected { connection } = self
                .committed_change(input.target.project, &receipt, deadline)
                .await?
            else {
                return Err(channel_error(ChannelError::IdempotencyConflict));
            };
            return Ok(Connected {
                ticket: self.ticket(&connection)?,
                connection,
                receipt,
            });
        }
        self.validate_resume_consent(&input, deadline).await?;
        let resume_configuration = self.resume_configuration(&input.policy)?;
        if input.credential.owner != self.owner {
            return Err(channel_error(ChannelError::CredentialScopeMismatch));
        }
        let credential = input.credential.clone();
        let credentials = self.credentials.clone();
        let token = self
            .context
            .blocking
            .run(crate::BlockingClass::Foreground, deadline, move || {
                credentials.resolve(&credential).map_err(channel_error)
            })
            .await?;
        let bot = self
            .telegram
            .identity(&token)
            .await
            .map_err(channel_error)?;
        deadline.remaining()?;
        let random = se_proc::random_secret()
            .map_err(|_| channel_error(ChannelError::CredentialStoreUnavailable))?;
        let id = ChannelId::new(format!(
            "chn-{}",
            se_types::hex_lower(&random.expose()[..16])
        ))
        .map_err(|_| channel_error(ChannelError::InvalidInput))?;
        let token = self.challenge(&id, 1)?;
        let connection = Connection {
            id,
            owner: self.owner.clone(),
            credential: input.credential,
            target: input.target,
            bot,
            policy: input.policy,
            pairing: Pairing::Challenge {
                digest: Sha256::digest(token.expose()).into(),
                expires_at_us: now()?
                    .checked_add(600_000_000)
                    .ok_or_else(|| channel_error(ChannelError::InvalidInput))?,
            },
            revision: 1,
            credential_removed: false,
            resume_configuration,
        };
        let receipt = self
            .change(
                connection.target.project.clone(),
                request,
                Change::Connected {
                    connection: connection.clone(),
                },
                deadline,
            )
            .await?;
        let Change::Connected { connection } = self
            .committed_change(connection.target.project, &receipt, deadline)
            .await?
        else {
            return Err(channel_error(ChannelError::IdempotencyConflict));
        };
        Ok(Connected {
            ticket: self.ticket(&connection)?,
            connection,
            receipt,
        })
    }
    pub async fn confirm_pairing(
        &self,
        input: ConfirmPairing,
        deadline: &Deadline,
    ) -> Result<se_store::CommitReceipt> {
        let connection = self.connection(input.connection.clone(), deadline).await?;
        let request = intent("channel.pairing.confirm", input.key.clone(), &input)?;
        if let Some(receipt) = self
            .replay(connection.target.project.clone(), request.clone(), deadline)
            .await?
        {
            return Ok(receipt);
        }
        self.change(
            connection.target.project,
            request,
            Change::PairingConfirmed {
                connection: input.connection,
                expected: input.expected_pairing_revision,
            },
            deadline,
        )
        .await
    }
    pub async fn restart_pairing(
        &self,
        input: ChannelControl,
        deadline: &Deadline,
    ) -> Result<PairingTicket> {
        let connection = self.connection(input.connection.clone(), deadline).await?;
        let request = intent("channel.pairing.restart", input.key.clone(), &input)?;
        let project = connection.target.project.clone();
        let receipt = match self
            .replay(project.clone(), request.clone(), deadline)
            .await?
        {
            Some(receipt) => receipt,
            None => {
                let revision = input
                    .expected_revision
                    .checked_add(1)
                    .filter(|v| *v <= i64::MAX as u64)
                    .ok_or_else(|| channel_error(ChannelError::InvalidInput))?;
                let challenge = self.challenge(&input.connection, revision)?;
                self.change(
                    project.clone(),
                    request,
                    Change::PairingRestarted {
                        connection: input.connection.clone(),
                        expected: input.expected_revision,
                        digest: Sha256::digest(challenge.expose()).into(),
                        expires_at_us: now()?
                            .checked_add(600_000_000)
                            .ok_or_else(|| channel_error(ChannelError::InvalidInput))?,
                    },
                    deadline,
                )
                .await?
            }
        };
        let Change::PairingRestarted {
            expected,
            expires_at_us,
            ..
        } = self.committed_change(project, &receipt, deadline).await?
        else {
            return Err(channel_error(ChannelError::IdempotencyConflict));
        };
        let mut ticket = self.make_ticket(&connection, expected + 1, expires_at_us)?;
        ticket.receipt = Some(receipt);
        Ok(ticket)
    }
    pub async fn disconnect(
        &self,
        input: ChannelControl,
        deadline: &Deadline,
    ) -> Result<Disconnected> {
        let gate = self.output_gate(&input.connection)?;
        let _release = tokio::time::timeout(deadline.remaining()?, gate.lock_owned())
            .await
            .map_err(|_| channel_error(ChannelError::ReceiverNotRunning))?;
        let connection = self.connection(input.connection.clone(), deadline).await?;
        let project = connection.target.project.clone();
        let request = intent("channel.disconnect", input.key.clone(), &input)?;
        let receipt = match self
            .replay(project.clone(), request.clone(), deadline)
            .await?
        {
            Some(r) => r,
            None => {
                self.change(
                    project.clone(),
                    request,
                    Change::Disconnected {
                        connection: input.connection.clone(),
                        expected: input.expected_revision,
                    },
                    deadline,
                )
                .await?
            }
        };
        // Durable revoke always wins. A failed forget is a separate fact and
        // cannot reopen admission, restart a challenge, or release private output.
        let credential = connection.credential.clone();
        let credentials = self.credentials.clone();
        let removal = self
            .context
            .blocking
            .run_owned(deadline, move || Ok(credentials.forget(&credential)))
            .await;
        let credential_removal = match removal {
            Ok(Ok(())) => {
                let key = se_types::IdempotencyKey::new(format!(
                    "channel-forget-{}",
                    se_types::hex_lower(&Sha256::digest(input.key.as_str().as_bytes()))
                ))
                .map_err(|_| channel_error(ChannelError::InvalidInput))?;
                let request = intent("channel.credential.removed", key, &connection.credential)?;
                match self
                    .change(
                        project,
                        request,
                        Change::CredentialRemoved {
                            connection: input.connection,
                            credential: connection.credential,
                        },
                        deadline,
                    )
                    .await
                {
                    Ok(_) => CredentialRemoval::Removed,
                    Err(_) => CredentialRemoval::Unknown {
                        code: "credential_removal_commit_unknown".into(),
                    },
                }
            }
            Ok(Err(_)) => CredentialRemoval::Pending {
                code: "credential_store_unavailable".into(),
            },
            Err(_) => CredentialRemoval::Unknown {
                code: "credential_removal_unknown".into(),
            },
        };
        Ok(Disconnected {
            receipt,
            credential_removal,
        })
    }
    fn challenge(&self, id: &ChannelId, revision: u64) -> Result<Secret> {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.pairing_key.expose())
            .map_err(|_| channel_error(ChannelError::CredentialStoreUnavailable))?;
        mac.update(b"StateEngine Telegram pairing v1\0");
        mac.update(id.as_str().as_bytes());
        mac.update(&revision.to_be_bytes());
        Secret::new(se_types::hex_lower(&mac.finalize().into_bytes()).into_bytes())
            .map_err(|_| channel_error(ChannelError::InvalidInput))
    }
    fn ticket(&self, state: &Connection) -> Result<PairingTicket> {
        let Pairing::Challenge { expires_at_us, .. } = state.pairing else {
            return Err(channel_error(ChannelError::InvalidInput));
        };
        self.make_ticket(state, state.revision, expires_at_us)
    }
    fn make_ticket(
        &self,
        state: &Connection,
        revision: u64,
        expires_at_us: i64,
    ) -> Result<PairingTicket> {
        let challenge = self.challenge(&state.id, revision)?;
        let challenge = std::str::from_utf8(challenge.expose())
            .map_err(|_| channel_error(ChannelError::InvalidInput))?;
        let link = Secret::new(
            format!("https://t.me/{}?start={challenge}", state.bot.username).into_bytes(),
        )
        .map_err(|_| channel_error(ChannelError::InvalidInput))?;
        Ok(PairingTicket {
            connection: state.id.clone(),
            revision,
            expires_at_us,
            link,
            receipt: None,
        })
    }
}
