//! Authoritative record rendering. Atlas's cached pointers never grant access.
mod captured;
mod excerpt;
pub mod feed;
use crate::{ops::receipt, scope, store_error::store_error};
use se_store::{
    Actor, Admission, EventBody, EventHeader, Scope, Snapshot, StoreErrorCode, StoredEvent,
    StoredText,
};
use se_types::{ProjectId, Read, Result, SeError, code::*};

pub struct RecordAccess<'a, R: Snapshot> {
    read: &'a mut R,
    admission: &'a Admission,
}
impl<'a, R: Snapshot> RecordAccess<'a, R> {
    pub fn new(read: &'a mut R, admission: &'a Admission) -> Self {
        Self { read, admission }
    }
    pub fn hit(
        &mut self,
        project: &ProjectId,
        viewer: &AtlasPrincipal,
        pointer: &RecordPointer,
        query: Option<&QueryText>,
    ) -> Result<Read<RecordHit>> {
        Ok(self
            .load(project, viewer, pointer)?
            .map(|record| RecordHit {
                pointer: pointer.clone(),
                actor: record.actor,
                occurred_unix_ms: record.at,
                line: excerpt::line(&record.body, query),
                body_truncated: record.body.len() > 65536,
                mentions: Vec::new(),
            }))
    }
    /// Token indexes propose candidates; literal matching is rechecked against
    /// the authorized current text so punctuation/case cannot create false hits.
    pub fn literal_hit(
        &mut self,
        project: &ProjectId,
        viewer: &AtlasPrincipal,
        pointer: &RecordPointer,
        query: &QueryText,
    ) -> Result<Read<RecordHit>> {
        Ok(match self.load(project, viewer, pointer)? {
            Read::Present { value } => {
                let smart = query.as_str().chars().any(char::is_uppercase);
                let found = if smart {
                    value.body.contains(query.as_str())
                } else {
                    value
                        .body
                        .to_lowercase()
                        .contains(&query.as_str().to_lowercase())
                };
                if found {
                    Read::Present {
                        value: RecordHit {
                            pointer: pointer.clone(),
                            actor: value.actor,
                            occurred_unix_ms: value.at,
                            line: excerpt::line(&value.body, Some(query)),
                            body_truncated: value.body.len() > 65536,
                            mentions: Vec::new(),
                        },
                    }
                } else {
                    Read::Absent {
                        checked: "literal absent from the authorized current record text".into(),
                    }
                }
            }
            Read::Absent { checked } => Read::Absent { checked },
            Read::Unknown { what } => Read::Unknown { what },
            Read::Unreadable {
                source,
                reason,
                error,
            } => Read::Unreadable {
                source,
                reason,
                error,
            },
        })
    }
    pub fn body(
        &mut self,
        project: &ProjectId,
        viewer: &AtlasPrincipal,
        pointer: &RecordPointer,
        query: Option<&QueryText>,
    ) -> Result<Read<HitBody>> {
        match self.load(project, viewer, pointer)? {
            Read::Present { value } => {
                let (text, complete) = excerpt::body(&value.body, query);
                Ok(Read::Present {
                    value: HitBody::new(
                        BodyOrigin::AuthoritativeRecord(pointer.clone()),
                        text,
                        complete,
                    )?,
                })
            }
            Read::Absent { checked } => Ok(Read::Absent { checked }),
            Read::Unknown { what } => Ok(Read::Unknown { what }),
            Read::Unreadable {
                source,
                reason,
                error,
            } => Ok(Read::Unreadable {
                source,
                reason,
                error,
            }),
        }
    }
    fn load(
        &mut self,
        project: &ProjectId,
        viewer: &AtlasPrincipal,
        pointer: &RecordPointer,
    ) -> Result<Read<Document>> {
        admitted_viewer(self.admission, viewer, project)?;
        let source = match self.source_event(pointer, project)? {
            Read::Present { value } => value,
            Read::Absent { checked } => return Ok(Read::Absent { checked }),
            Read::Unknown { what } => return Ok(Read::Unknown { what }),
            Read::Unreadable {
                source,
                reason,
                error,
            } => {
                return Ok(Read::Unreadable {
                    source,
                    reason,
                    error,
                });
            }
        };
        if matches!(
            &source.body,
            EventBody::MessageSent {
                body: StoredText::Erased { .. },
                ..
            } | EventBody::WorkMessageSent {
                body: StoredText::Erased { .. },
                ..
            }
        ) {
            return Ok(Read::Absent {
                checked: "authoritative message text was erased".into(),
            });
        }
        let at = receipt::event_time(&source) / 1000;
        let captured = if pointer.kind == RecordKind::Edit {
            captured::successful(&source)?
        } else {
            None
        };
        let body = match (source.body, pointer.kind) {
            (_, RecordKind::Decision) => return Ok(Read::Absent {
                checked: "decision ledger records are retired; original events remain readable through history".into(),
            }),
            (
                EventBody::MessageSent { message, body, .. }
                | EventBody::WorkMessageSent { message, body, .. },
                RecordKind::Message,
            ) if message.as_str() == pointer.key.as_str() => text(body)?,
            (
                EventBody::WorkingStateSet {
                    agent, text: body, ..
                },
                RecordKind::Working,
            ) if agent.as_str() == pointer.key.as_str() => {
                let current = match visible(self.read.working_state(agent.clone()))? {
                    Read::Present { value } => value,
                    Read::Absent { checked } => return Ok(Read::Absent { checked }),
                    Read::Unknown { what } => return Ok(Read::Unknown { what }),
                    Read::Unreadable {
                        source,
                        reason,
                        error,
                    } => {
                        return Ok(Read::Unreadable {
                            source,
                            reason,
                            error,
                        });
                    }
                };
                if current.current.header.event != pointer.source_event {
                    return Ok(stale());
                }
                text(body)?
            }
            (EventBody::SessionTurn { .. }, RecordKind::Edit) => {
                return self.edit_document(project, pointer, captured, at);
            }
            // Chat/transcript text is never an edit record. Git commit bodies
            // are supplied by Atlas's separately labelled history adapter.
            _ => {
                return Ok(Read::Absent {
                    checked: "event is not the referenced code-linked record kind/key".into(),
                });
            }
        };
        self.record_document(&source.header, at, body)
    }
    fn source_event(
        &mut self,
        pointer: &RecordPointer,
        project: &ProjectId,
    ) -> Result<Read<StoredEvent>> {
        let source = match visible(self.read.event(pointer.source_event.clone()))? {
            Read::Present { value } => value,
            read => return Ok(read),
        };
        if source.header.scope != Scope::Project(project.clone())
            || source.header.event != pointer.source_event
        {
            return Err(scope::unreadable(
                "Atlas record authority",
                "source event differs from its project or ID",
            ));
        }
        Ok(Read::Present { value: source })
    }
    fn edit_document(
        &mut self,
        project: &ProjectId,
        pointer: &RecordPointer,
        captured: Option<captured::Successful>,
        at: i64,
    ) -> Result<Read<Document>> {
        let Some(tool) = captured else {
            return Ok(stale());
        };
        tool.validate_source(self.read, project)?;
        if tool.key()? != pointer.key {
            return Ok(stale());
        }
        Ok(Read::Present {
            value: Document {
                actor: Some(tool.actor()),
                at,
                body: tool.description(),
            },
        })
    }
    fn record_document(
        &mut self,
        header: &EventHeader,
        at: i64,
        body: String,
    ) -> Result<Read<Document>> {
        let principal = match &header.actor {
            Actor::Guest => return Err(scope::unreadable("Atlas record", "guest cannot author")),
            Actor::Agent(id) => AtlasPrincipal::Agent(id.clone()),
            Actor::Human(id) => AtlasPrincipal::Human(id.clone()),
            Actor::Remote(id) => {
                return Ok(Read::Present {
                    value: Document {
                        actor: Some(AtlasActor {
                            principal: AtlasPrincipal::Remote(id.clone()),
                            name: format!("Remote device {id}"),
                        }),
                        at,
                        body,
                    },
                });
            }
        };
        let actor = match visible(self.read.principal(header.actor.clone()))? {
            Read::Present { value } => {
                let name = match value.current.body {
                    EventBody::PrincipalRegistered { name, .. }
                    | EventBody::PrincipalRenamed { name, .. } => name,
                    _ => {
                        return Err(scope::unreadable(
                            "Atlas record actor",
                            "principal metadata has an unexpected event kind",
                        ));
                    }
                };
                Some(AtlasActor { principal, name })
            }
            Read::Absent { .. } => None,
            Read::Unknown { what } => return Err(scope::unreadable("Atlas record actor", &what)),
            Read::Unreadable { source, reason, .. } => {
                return Err(scope::unreadable(&source, &reason));
            }
        };
        Ok(Read::Present {
            value: Document { actor, at, body },
        })
    }
}
struct Document {
    actor: Option<AtlasActor>,
    at: i64,
    body: String,
}
fn text(value: StoredText) -> Result<String> {
    match value {
        StoredText::Present(value) => Ok(value),
        StoredText::Erased { .. } => Err(scope::unreadable(
            "Atlas record body",
            "authoritative text was erased; no cached body is available",
        )),
    }
}
fn visible<T>(value: se_store::StoreResult<Read<T>>) -> Result<Read<T>> {
    match value {
        Ok(read) => Ok(read),
        Err(error) if error.code == StoreErrorCode::ScopeMismatch => Ok(Read::Absent {
            checked: "record excluded by authoritative project/visibility policy".into(),
        }),
        Err(error) => Err(store_error(&error)),
    }
}
fn stale<T>() -> Read<T> {
    Read::Absent {
        checked: "cached pointer was superseded by the authoritative record revision".into(),
    }
}
fn admitted_viewer(
    admission: &Admission,
    viewer: &AtlasPrincipal,
    project: &ProjectId,
) -> Result<()> {
    let expected = match viewer {
        AtlasPrincipal::Agent(id) => Actor::Agent(id.clone()),
        AtlasPrincipal::Human(id) => Actor::Human(id.clone()),
        AtlasPrincipal::Guest => Actor::Guest,
        AtlasPrincipal::Remote(_) => {
            return Err(SeError::invalid(
                "Atlas record viewer",
                "an admitted local Owner or agent; remote grants cover list, watch and send only",
            ));
        }
    };
    if admission.scope != Scope::Project(project.clone()) || admission.actor != expected {
        return Err(SeError::invalid(
            "Atlas record viewer",
            "the same admitted project and principal",
        ));
    }
    Ok(())
}
