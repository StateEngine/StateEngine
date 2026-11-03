//! The public unread inbox is the same authorized, bounded message reader.
use super::{MessageBox, MessageList, MessagePage, MessageView, Validate};
use crate::commit::Cx;
use schemars::JsonSchema;
use se_store::Snapshot;
use se_types::{Cursor, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageInbox {
    pub agent: Option<String>,
    #[serde(default)]
    pub full: bool,
    #[serde(default = "default_limit")]
    pub limit: u16,
    pub preview_chars: Option<u16>,
    pub cursor: Option<Cursor>,
}
fn default_limit() -> u16 {
    20
}
impl MessageInbox {
    fn query(&self) -> MessageList {
        MessageList {
            cli_list: self.agent.is_some(),
            view: MessageView::Unread,
            mailbox: MessageBox::Inbox,
            from: None,
            kind: None,
            full: self.full,
            limit: self.limit,
            preview_chars: self.preview_chars,
            cursor: self.cursor.clone(),
            owner_to: self.agent.clone(),
        }
    }
}
impl Validate for MessageInbox {
    fn validate(&self) -> Result<()> {
        self.query().validate()
    }
}
pub fn read<R: Snapshot>(input: MessageInbox, cx: &mut Cx<'_, R>) -> Result<MessagePage> {
    let mut page = super::message::list(input.query(), cx)?;
    page.view.op = "inbox".into();
    page.view.r#box = "inbox".into();
    Ok(page)
}
