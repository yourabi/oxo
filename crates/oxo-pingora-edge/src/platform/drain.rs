use super::*;

use pingora::server::ShutdownWatch;
use pingora::services::background::{background_service, BackgroundService, GenBackgroundService};
use tokio::sync::watch;

pub(super) const DEFAULT_EDGE_DRAIN_GRACE_MS: u64 = 2_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct EdgeDrainConfig {
    pub(super) grace_period_seconds: u64,
    pub(super) graceful_shutdown_timeout_seconds: u64,
}

impl EdgeDrainConfig {
    pub(super) fn from_millis(name: &'static str, millis: u64) -> Result<Self, EdgeError> {
        if millis == 0 {
            return Err(EdgeError::ConfigEnv {
                name,
                message: "drain grace must be greater than zero".to_string(),
            });
        }
        let seconds = millis.saturating_add(999) / 1_000;
        Ok(Self {
            grace_period_seconds: seconds,
            graceful_shutdown_timeout_seconds: 0,
        })
    }
}

#[derive(Clone)]
pub(super) struct DrainState {
    sender: watch::Sender<bool>,
    receiver: watch::Receiver<bool>,
}

impl DrainState {
    pub(super) fn new() -> Self {
        let (sender, receiver) = watch::channel(false);
        Self { sender, receiver }
    }

    pub(super) fn is_draining(&self) -> bool {
        *self.receiver.borrow()
    }

    pub(super) fn subscribe(&self) -> watch::Receiver<bool> {
        self.receiver.clone()
    }

    pub(super) fn begin_drain(&self) {
        let _ = self.sender.send(true);
    }
}

pub(super) struct DrainSignalService {
    state: DrainState,
}

#[async_trait]
impl BackgroundService for DrainSignalService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        if *shutdown.borrow() {
            self.state.begin_drain();
            return;
        }
        while shutdown.changed().await.is_ok() {
            if *shutdown.borrow() {
                self.state.begin_drain();
                return;
            }
        }
    }
}

pub(super) fn drain_background_service(
    state: DrainState,
) -> GenBackgroundService<DrainSignalService> {
    background_service("oxo drain signal", DrainSignalService { state })
}
