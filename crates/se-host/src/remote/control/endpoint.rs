use super::*;
impl Control {
    pub(super) async fn start(
        &self,
        router: &crate::HostedRouter,
        address: std::net::SocketAddr,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<serde_json::Value> {
        router.check_open()?;
        self.startup.require_ready()?;
        let mut running = self.running.lock().await;
        if self.closing.load(Ordering::Acquire) {
            return Err(SeError::invalid(
                "remote listener startup",
                "a host before its shutdown fence",
            ));
        }
        if let Some(current) = &*running {
            if current
                .task
                .as_ref()
                .is_none_or(tokio::task::JoinHandle::is_finished)
            {
                return Err(SeError::invalid(
                    "remote listener",
                    "disable and join the stopped listener before enabling it again",
                ));
            }
            if current.address != address && address.port() != 0 {
                return Err(SeError::invalid(
                    "remote listener address",
                    "disable the current client listener before changing its explicit port",
                ));
            }
            return Ok(self.enabled(current.address));
        }
        let listener = listener::ClientListener::bind(address)?;
        let publisher = self.publisher(router, deadline).await?;
        let service = Arc::new(service::Service::new(
            router.clone(),
            self.security.store.clone(),
            publisher,
            self.cipher.clone(),
            self.security.host(),
        ));
        let endpoint = Arc::new(listener::ClientEndpoint {
            security: self.security.clone(),
            key: self.key.clone(),
            cipher: self.cipher.clone(),
            service,
            blocking: router.execution.blocking.clone(),
        });
        let address = listener.address();
        let (shutdown, stop) = watch::channel(false);
        let task = router
            .execution
            .blocking
            .handle()
            .spawn(listener.serve(endpoint, stop));
        *running = Some(Running {
            address,
            shutdown,
            task: Some(task),
            closed: false,
        });
        Ok(self.enabled(address))
    }
    pub(crate) async fn local_watch(
        router: &crate::HostedRouter,
        admission: se_store::Admission,
        input: se_core::ops::ClientWatchCall,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<RemoteWatchBatch> {
        let owner = auth::VerifiedLocalOwner::from_machine(&admission)?;
        let _work = router.execution.mail_waits.remote_work()?;
        let (control, _) = Self::prepare(router, owner, true, deadline).await?;
        let publisher = control.publisher(router, deadline).await?;
        let service = service::Service::new(
            router.clone(),
            control.security.store.clone(),
            publisher,
            control.cipher.clone(),
            control.security.host(),
        );
        let result = control
            .local_watches
            .read_local(
                &admission,
                service,
                (input.request, input.reader_id),
                input.wait_ms,
                deadline,
            )
            .await?;
        router.check_open()?;
        Ok(result)
    }

    async fn publisher(
        &self,
        router: &crate::HostedRouter,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<Arc<publish::LivePublisher>> {
        let _setup = self.live_setup.lock().await;
        router.check_open()?;
        if self.closing.load(Ordering::Acquire) {
            return Err(SeError::invalid(
                "client view",
                "a host before its shutdown fence",
            ));
        }
        if let Some(publisher) = self.live()? {
            return Ok(publisher);
        }
        let publisher = publish::LivePublisher::new(self.security.instance())?;
        *self
            .live
            .write()
            .map_err(|_| SeError::invalid("remote publisher", "unpoisoned optional state"))? =
            Some(publisher.clone());
        let refreshed = match router.execution.custody.get() {
            Some(custody) => custody.refresh_remote(deadline).await,
            None => Err(SeError::invalid(
                "remote publisher",
                "the owning native coordinator before enabling a provider view",
            )),
        };
        if let Err(error) = refreshed {
            publisher.fence()?;
            self.live
                .write()
                .map_err(|_| SeError::invalid("remote publisher", "unpoisoned optional state"))?
                .take();
            return Err(error);
        }
        router.check_open()?;
        if self.closing.load(Ordering::Acquire) {
            publisher.fence()?;
            return Err(SeError::invalid(
                "remote listener startup",
                "a host before shutdown",
            ));
        }
        Ok(publisher)
    }
    fn enabled(&self, address: std::net::SocketAddr) -> serde_json::Value {
        serde_json::json!({"state":"enabled","address":address,"host":self.security.host(),"instance":self.security.instance(),"generation":self.security.generation,"security_notice":self.startup.notice()})
    }
}
