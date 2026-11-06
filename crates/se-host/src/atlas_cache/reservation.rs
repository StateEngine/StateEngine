//! Durable custody for a completed database reservation. Acquiring the native
//! home writer lock proves its former writer no longer holds the lease. The
//! journal pins the exact native database identity; names alone grant no erase.
use super::*;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    epoch: CacheEpoch,
    volume: [u8; 16],
    file: [u8; 16],
}
impl NativeAtlasCache {
    pub(super) fn claim_reservation(&self, epoch: &CacheEpoch) -> AtlasResult<()> {
        self.require_writer()?;
        self.check_unpublished(epoch)?;
        let record = self
            .read_reservation()?
            .ok_or_else(|| fail("cold candidate reservation journal absent"))?;
        if &record.epoch != epoch {
            return Err(fail("cold candidate differs from reserved epoch"));
        }
        let pin = self
            .pin_database(epoch)?
            .ok_or_else(|| fail("cold candidate database absent"))?;
        let identity = observe_file_revision(&pin.file).map_err(fail)?;
        if identity.volume != record.volume || identity.file != record.file {
            return Err(fail(
                "cold candidate native identity changed; preserve epoch",
            ));
        }
        *self.reserved.borrow_mut() = Some((record.epoch, identity));
        Ok(())
    }
    fn journal(&self) -> PathBuf {
        self.root.root().join("reservation.json")
    }
    pub(super) fn remember_reservation(
        &self,
        epoch: &CacheEpoch,
        pin: &DatabasePin,
    ) -> AtlasResult<()> {
        self.require_writer()?;
        let identity = observe_file_revision(&pin.file).map_err(fail)?;
        let bytes = serde_json::to_vec(&Record {
            epoch: epoch.clone(),
            volume: identity.volume,
            file: identity.file,
        })
        .map_err(|error| fail("reservation custody JSON cannot be encoded").with_cause(error))?;
        let mut stage = self.root.create_staging(self.root.root()).map_err(fail)?;
        stage.file.write_all(&bytes).map_err(fail)?;
        drop(stage.file);
        self.root
            .publish_no_replace(&stage.path, &self.journal())
            .map_err(fail)?;
        if self.read_reservation()?.is_none_or(|r| {
            r.epoch != *epoch || r.volume != identity.volume || r.file != identity.file
        }) {
            return Err(fail("reservation custody journal readback differs"));
        }
        Ok(())
    }
    fn read_reservation(&self) -> AtlasResult<Option<Record>> {
        let Some(file) = self.root.readback(&self.journal()).map_err(fail)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.take(1025).read_to_end(&mut bytes).map_err(fail)?;
        if bytes.len() > 1024 {
            return Err(fail("reservation custody journal exceeds 1024 bytes"));
        }
        serde_json::from_slice(&bytes).map(Some).map_err(|error| {
            fail("malformed reservation custody JSON; preserve cache").with_cause(error)
        })
    }
    pub(super) fn clear_reservation(&self) -> AtlasResult<()> {
        self.require_writer()?;
        if let Some(mut journal) = OwnedFile::open(&self.journal()).map_err(fail)? {
            let digest = journal.sha256().map_err(fail)?;
            journal.remove(digest).map_err(fail)?;
        }
        if self.root.readback(&self.journal()).map_err(fail)?.is_some() {
            return Err(fail("reservation journal removal absence not witnessed"));
        }
        Ok(())
    }
    pub(super) fn recover_reservation(&self) -> AtlasResult<()> {
        self.require_writer()?;
        let Some(record) = self.read_reservation()? else {
            return Ok(());
        };
        if let Some(bytes) = self.read_pointer()? {
            let pointer = se_atlas::cache::pointer::decode(&bytes, &self.scope)?;
            if pointer.epoch == record.epoch {
                // Publication won before a crash. Never erase this database.
                self.clear_reservation()?;
                return Ok(());
            }
        }
        let Some(pin) = self.pin_database(&record.epoch)? else {
            let directory = self
                .path(&record.epoch)
                .parent()
                .ok_or_else(|| fail("reservation epoch parent missing"))?
                .to_path_buf();
            match std::fs::read_dir(&directory) {
                Ok(mut entries) => {
                    if entries.next().transpose().map_err(fail)?.is_some() {
                        return Err(fail(
                            "reservation database absent but unknown epoch bytes remain; preserve them",
                        ));
                    }
                    se_proc::remove_empty_directory(&directory).map_err(fail)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(fail(error)),
            }
            self.clear_reservation()?;
            return Ok(());
        };
        let identity = observe_file_revision(&pin.file).map_err(fail)?;
        if identity.volume != record.volume || identity.file != record.file {
            return Err(fail(
                "crashed reservation native identity changed; preserve epoch",
            ));
        }
        *self.reserved.borrow_mut() = Some((record.epoch, identity));
        self.discard_unpublished(&pin)
    }
}
