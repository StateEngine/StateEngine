//! Current native-protected binding selection; the connection cache holds no
//! authority and cannot bypass a fresh saved-record/key check for each call.
use super::*;
use crate::client::lease::Deadline;
type ConnectionKey = ([u8; 32], RemoteGrantId);
#[derive(Default)]
pub(super) struct Connections {
    entries: BTreeMap<ConnectionKey, CachedConnection>,
}
impl Connections {
    pub(super) fn remove_host(&mut self, host: RemoteHostId) -> Vec<Arc<dyn RemoteClient>> {
        let keys: Vec<_> = self
            .entries
            .keys()
            .filter(|key| key.0 == *host.0.as_bytes())
            .cloned()
            .collect();
        keys.into_iter()
            .filter_map(|key| {
                self.entries
                    .remove(&key)
                    .and_then(|entry| entry.client.get().cloned())
            })
            .collect()
    }
    pub(super) fn clients(&self) -> Vec<Arc<dyn RemoteClient>> {
        self.entries
            .values()
            .filter_map(|entry| entry.client.get().cloned())
            .collect()
    }
}
struct CachedConnection {
    device: RemoteDeviceId,
    client: Arc<OnceCell<Arc<dyn RemoteClient>>>,
}
pub(super) trait BindingResolver: Send + Sync {
    fn resolve(
        &self,
        alias: String,
        call: RemoteCallContext,
        admission: Admission,
        terminal: HumanTerminal,
        deadline: Deadline,
    ) -> RemoteFuture<'_, BrokerBinding>;
}
impl RemoteBroker {
    pub(super) async fn resolve(
        &self,
        alias: &str,
        call: RemoteCallContext,
        admission: &Admission,
        terminal: &HumanTerminal,
        deadline: &Deadline,
    ) -> Result<Binding> {
        self.check_open()?;
        validate_alias(alias)?;
        call.check_current()?;
        let source = call.source().cloned();
        let config = self
            .resolver
            .resolve(
                alias.to_owned(),
                call,
                admission.clone(),
                terminal.clone(),
                deadline.clone(),
            )
            .await?;
        deadline.remaining()?;
        config.route.validate()?;
        config.device.scope.validate()?;
        if config.alias != alias
            || config.route.host != config.device.host
            || !config.device.subject.admits_source(source.as_ref())
        {
            return Err(refused(
                "saved binding does not match this exact alias, host and source subject",
            ));
        }
        let key = (
            *config.device.host.0.as_bytes(),
            config.device.grant.clone(),
        );
        let mut connections = self.connections.lock().map_err(|_| poisoned())?;
        if let Some(cached) = connections.entries.get(&key) {
            if cached.device != config.device.device {
                return Err(refused(
                    "the retained grant's device or route changed; restore its original forward or explicitly reconnect through SSH",
                ));
            }
        } else {
            connections.entries.insert(
                key.clone(),
                CachedConnection {
                    device: config.device.device.clone(),
                    client: Arc::new(OnceCell::new()),
                },
            );
        }
        let client = Arc::clone(&connections.entries.get(&key).ok_or_else(poisoned)?.client);
        Ok(Binding { config, client })
    }
    #[cfg(feature = "remote")]
    pub fn from_protected(
        source_host: RemoteHostId,
        connector: Arc<dyn RemoteConnector>,
        records: Arc<crate::remote::bindings::ProtectedBindings>,
        blocking: crate::BlockingPool,
    ) -> Self {
        Self::with_resolver(
            source_host,
            connector,
            Arc::new(ProtectedResolver { records, blocking }),
        )
    }
}
#[cfg(feature = "remote")]
struct ProtectedResolver {
    records: Arc<crate::remote::bindings::ProtectedBindings>,
    blocking: crate::BlockingPool,
}
#[cfg(feature = "remote")]
impl BindingResolver for ProtectedResolver {
    fn resolve(
        &self,
        alias: String,
        call: RemoteCallContext,
        admission: Admission,
        _terminal: HumanTerminal,
        deadline: Deadline,
    ) -> RemoteFuture<'_, BrokerBinding> {
        let records = Arc::clone(&self.records);
        Box::pin(async move {
            self.blocking
                .run_owned(&deadline, move || {
                    let record = se_core::scope::require_present(
                        records.read(&alias)?,
                        "remote binding",
                        "Connect this machine through native Owner control; a missing binding never selects another credential.",
                    )?;
                    if !record.binding.connected {return Err(refused("this machine is disconnected; explicitly add it again to reconnect"));}
                    let signer = if call.source().is_some() {
                        records.lead_signer(&record, &call)?
                    } else {
                        let owner = crate::remote::auth::VerifiedLocalOwner::from_machine(&admission)?;
                        records.human_signer(&owner, &record)?
                    };
                    call.check_current()?;
                    Ok(BrokerBinding {
                        alias,
                        route: RemoteRoute {
                            forward: record.binding.forward,
                            address: record.binding.route,
                            host: record.binding.paired.host,
                        },
                        device: record.binding.paired,
                        signer,
                    })
                })
                .await
        })
    }
}
