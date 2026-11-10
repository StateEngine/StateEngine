use super::super::channel::busy;
use super::*;
use std::{
    collections::BTreeMap,
    sync::{
        Mutex, Weak,
        atomic::{AtomicUsize, Ordering},
    },
};
#[derive(Default)]
pub(super) struct Limits {
    handshakes: AtomicUsize,
    devices: Mutex<BTreeMap<RemoteDeviceId, Weak<DeviceLimits>>>,
}
pub(super) struct Handshake {
    limits: Arc<Limits>,
}
impl Drop for Handshake {
    fn drop(&mut self) {
        self.limits.handshakes.fetch_sub(1, Ordering::AcqRel);
    }
}
pub(super) struct DeviceLimits {
    connections: AtomicUsize,
    requests: Arc<Semaphore>,
    mutations: Arc<Semaphore>,
}
pub(super) struct DeviceSlot {
    pub limits: Arc<DeviceLimits>,
}
impl Drop for DeviceSlot {
    fn drop(&mut self) {
        self.limits.connections.fetch_sub(1, Ordering::AcqRel);
    }
}
pub(super) struct RequestSlot {
    _limits: Arc<DeviceLimits>,
    _request: OwnedSemaphorePermit,
    _mutation: Option<OwnedSemaphorePermit>,
}
impl Limits {
    pub fn handshake(self: &Arc<Self>) -> Result<Handshake> {
        // SSH forwards all arrive on loopback. An IP quota would merge every
        // legitimate device into one two-handshake budget.
        self.handshakes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < 8).then_some(n + 1)
            })
            .map_err(|_| busy("bounded handshake capacity reached"))?;
        Ok(Handshake {
            limits: self.clone(),
        })
    }
    pub fn device(&self, id: &RemoteDeviceId) -> Result<DeviceSlot> {
        let mut map = self
            .devices
            .lock()
            .map_err(|_| super::super::channel::unavailable("device admission unreadable"))?;
        map.retain(|_, entry| entry.strong_count() > 0);
        let limits = if let Some(entry) = map.get(id).and_then(Weak::upgrade) {
            entry
        } else {
            let entry = Arc::new(DeviceLimits {
                connections: AtomicUsize::new(0),
                requests: Arc::new(Semaphore::new(REMOTE_MAX_REQUESTS)),
                mutations: Arc::new(Semaphore::new(REMOTE_MAX_MUTATIONS)),
            });
            map.insert(id.clone(), Arc::downgrade(&entry));
            entry
        };
        limits
            .connections
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < 4).then_some(n + 1)
            })
            .map_err(|_| {
                busy(
                    "four connections already use this device; share its multiplexed source broker",
                )
            })?;
        Ok(DeviceSlot { limits })
    }
}
impl DeviceLimits {
    pub fn request(self: &Arc<Self>, mutation: bool) -> Result<RequestSlot> {
        let request = self
            .requests
            .clone()
            .try_acquire_owned()
            .map_err(|_| busy("outstanding request capacity reached for this device"))?;
        let mutation = if mutation {
            Some(
                self.mutations
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| busy("outstanding mutation capacity reached for this device"))?,
            )
        } else {
            None
        };
        Ok(RequestSlot {
            _limits: self.clone(),
            _request: request,
            _mutation: mutation,
        })
    }
}
