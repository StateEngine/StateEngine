//! Connector setup and limits are native data shared by all user interfaces.
use super::*;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorCapability {
    Edits,
    Threads,
    Media,
    Buttons,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConnectorCapabilities(u8);

impl ConnectorCapabilities {
    pub const NONE: Self = Self(0);
    pub const EDITS: Self = Self(1 << 0);
    pub const THREADS: Self = Self(1 << 1);
    pub const MEDIA: Self = Self(1 << 2);
    pub const BUTTONS: Self = Self(1 << 3);

    pub const fn with(self, capability: ConnectorCapability) -> Self {
        Self(self.0 | Self::bit(capability))
    }

    pub const fn supports(self, capability: ConnectorCapability) -> bool {
        self.0 & Self::bit(capability) != 0
    }

    const fn bit(capability: ConnectorCapability) -> u8 {
        match capability {
            ConnectorCapability::Edits => Self::EDITS.0,
            ConnectorCapability::Threads => Self::THREADS.0,
            ConnectorCapability::Media => Self::MEDIA.0,
            ConnectorCapability::Buttons => Self::BUTTONS.0,
        }
    }
}

impl Serialize for ConnectorCapabilities {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ConnectorCapabilities", 4)?;
        state.serialize_field("edits", &self.supports(ConnectorCapability::Edits))?;
        state.serialize_field("threads", &self.supports(ConnectorCapability::Threads))?;
        state.serialize_field("media", &self.supports(ConnectorCapability::Media))?;
        state.serialize_field("buttons", &self.supports(ConnectorCapability::Buttons))?;
        state.end()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ConnectorDescriptor {
    pub connector: Connector,
    pub name: &'static str,
    pub max_text_utf16: usize,
    #[serde(flatten)]
    pub capabilities: ConnectorCapabilities,
    pub identity_proof: &'static str,
    pub acknowledgement: &'static str,
    pub reconnect: &'static str,
    pub retention_seconds: Option<u64>,
    pub setup: &'static [SetupField],
    pub instructions: &'static str,
}

impl ConnectorDescriptor {
    pub const fn supports(&self, capability: ConnectorCapability) -> bool {
        self.capabilities.supports(capability)
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct SetupField {
    pub key: &'static str,
    pub label: &'static str,
    pub secret: bool,
    pub required: bool,
}
#[derive(Clone, Debug)]
pub struct ActionButton {
    pub label: String,
    pub data: String,
}
