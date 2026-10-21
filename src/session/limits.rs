//! Account incoming bytes before fragment reassembly; opening and keepalive are separate.
use psrp_rs::PsrpError;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
pub(super) struct OutputBudget {
    limit: Option<usize>,
    used: AtomicUsize,
    active: AtomicBool,
}
impl OutputBudget {
    pub fn new(limit: Option<usize>) -> Self {
        Self {
            limit,
            used: AtomicUsize::new(0),
            active: AtomicBool::new(false),
        }
    }
    pub fn start(&self) {
        self.used.store(0, Ordering::Relaxed);
        self.active.store(true, Ordering::Release);
    }
    pub fn stop(&self) {
        self.active.store(false, Ordering::Release);
    }
    pub fn accept(&self, bytes: usize) -> Result<(), PsrpError> {
        if !self.active.load(Ordering::Acquire) {
            return Ok(());
        }
        let used = self
            .used
            .fetch_add(bytes, Ordering::Relaxed)
            .saturating_add(bytes);
        if let Some(limit) = self.limit
            && used > limit
        {
            return Err(PsrpError::OutputLimit(limit));
        }
        Ok(())
    }
}
