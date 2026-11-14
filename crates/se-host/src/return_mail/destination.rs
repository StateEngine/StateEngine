//! Destination receipt recovery and authenticated return-mail pagination.
use super::*;
use crate::remote::{auth, service::Service, view_request};
impl Service {
    pub(crate) async fn contact(
        &self,
        request: auth::AuthorizedRemoteRequest,
    ) -> Result<RemoteContactResult> {
        let RemoteRequest::ResolveContact(input) = request.request() else {
            return Err(SeError::invalid(
                "contact recovery",
                "an authorized source receipt request",
            ));
        };
        let input = input.clone();
        let source = request.attribution().source.clone().ok_or_else(|| {
            SeError::invalid("contact recovery", "an authenticated source agent address")
        })?;
        let key = se_core::remote::request_key(request.attribution(), &input.idempotency_key)?;
        let grant = request.admission().grant().clone();
        let service = self.clone();
        self.blocking(move || {
            let now = session::now()?;
            let value = service.store.read(|phase| {
                phase.remote_contact_receipt(se_store::remote::ContactReceiptQuery {
                    grant: &grant.grant,
                    revision: grant.authority_revision,
                    original_grant: &input.original_grant,
                    target: &input.target,
                    source: &source,
                    request_key: &key,
                    now,
                })
            })?;
            let body = match value {
                se_types::Read::Present {
                    value: (message, event),
                } => se_types::Read::Present {
                    value: RemoteResolvedContact {
                        message,
                        event,
                        source: source.address(),
                        target: input.target,
                        original_grant: input.original_grant,
                        idempotency_key: input.idempotency_key,
                    },
                },
                se_types::Read::Absent { checked } => se_types::Read::Absent { checked },
                se_types::Read::Unreadable {
                    source,
                    reason,
                    error,
                } => se_types::Read::Unreadable {
                    source,
                    reason,
                    error,
                },
                se_types::Read::Unknown { what } => se_types::Read::Unknown { what },
            };
            Ok(RemoteContactResult {
                schema: RemoteContactResult::SCHEMA.into(),
                body,
            })
        })
        .await
    }
}

impl Service {
    pub(crate) async fn replies(
        &self,
        request: auth::AuthorizedRemoteRequest,
    ) -> Result<RemoteRepliesResult> {
        let RemoteRequest::Replies(input) = request.request() else {
            return Err(SeError::invalid(
                "return mail",
                "an authorized reply-mailbox request",
            ));
        };
        let input = input.clone();
        let source = request.attribution().source.clone().ok_or_else(|| {
            SeError::invalid("return mail", "an authenticated source agent address")
        })?;
        let grant = request.admission().grant().clone();
        let service = self.clone();
        let view = view_request::ViewRequest::Remote(Box::new(request));
        self.blocking(move || {
            let after = input
                .after
                .as_ref()
                .map(|cursor| {
                    service
                        .cursors
                        .open(&view, Some(&input.target), "return-mail", cursor)
                        .and_then(|bytes| {
                            se_store::remote::position_from_payload(&bytes)
                                .map_err(|e| store_error(&e))
                        })
                })
                .transpose()?;
            let now = session::now()?;
            let page = service.store.read(|phase| {
                phase.remote_replies(se_store::remote::ReplyQuery {
                    grant_id: &grant.grant,
                    revision: grant.authority_revision,
                    source: &source,
                    target: &input.target,
                    after: after.as_ref(),
                    limit: input.limit,
                    now,
                })
            })?;
            let mut result = RemoteRepliesResult {
                schema: RemoteRepliesResult::SCHEMA.into(),
                body: RemoteRepliesBody {
                    messages: Vec::new(),
                    next: input.after.clone(),
                    more: page.more,
                },
            };
            for (message, position) in page.messages {
                let previous = result.next.clone();
                result.body.messages.push(message);
                result.body.next = Some(service.cursors.seal(
                    &view,
                    Some(&input.target),
                    "return-mail",
                    &se_store::remote::position_payload(&position).map_err(|e| store_error(&e))?,
                )?);
                let size = serde_json::to_vec(&result)
                    .map_err(|_| SeError::invalid("return mail", "serializable bounded messages"))?
                    .len();
                if size > input.budget as usize {
                    result.body.messages.pop();
                    result.body.next = previous;
                    result.body.more = true;
                    if result.messages.is_empty() {
                        return Err(SeError::too_large(
                            "remote reply delivery frame",
                            input.budget as usize,
                            size,
                        ));
                    }
                    break;
                }
            }
            Ok(result)
        })
        .await
    }
}
