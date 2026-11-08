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
    handshakes: Mutex<BTreeMap<IpAddr, usize>>,
    devices: Mutex<BTreeMap<RemoteDeviceId, Weak<DeviceLimits>>>,
}
pub(super) struct Handshake {
    limits: Arc<Limits>,
    ip: IpAddr,
}
impl Drop for Handshake {
    fn drop(&mut self) {
        if let Ok(mut map) = self.limits.handshakes.lock()
            && let Some(count) = map.get_mut(&self.ip)
        {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.ip);
            }
        }
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
    pub fn handshake(self: &Arc<Self>, ip: IpAddr) -> Result<Handshake> {
        let mut map = self
            .handshakes
            .lock()
            .map_err(|_| super::super::channel::unavailable("handshake admission unreadable"))?;
        if map.values().sum::<usize>() >= 8 || map.get(&ip).copied().unwrap_or(0) >= 2 {
            return Err(super::super::channel::unavailable(
                "bounded handshake capacity reached",
            ));
        }
        *map.entry(ip).or_default() += 1;
        Ok(Handshake {
            limits: self.clone(),
            ip,
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
                requests: Arc::new(Semaphore::new(32)),
                mutations: Arc::new(Semaphore::new(4)),
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
                super::super::channel::unavailable(
                    "four connections already use this device; share its multiplexed source broker",
                )
            })?;
        Ok(DeviceSlot { limits })
    }
}
impl DeviceLimits {
    pub fn request(self: &Arc<Self>, mutation: bool) -> Result<RequestSlot> {
        let request = self.requests.clone().try_acquire_owned().map_err(|_| {
            super::super::channel::unavailable("32 requests already use this device")
        })?;
        let mutation = if mutation {
            Some(self.mutations.clone().try_acquire_owned().map_err(|_| {
                super::super::channel::unavailable("four mutations already use this device")
            })?)
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
