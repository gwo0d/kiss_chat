//! Shared test-only helpers.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// A throwaway directory under the system temp dir, removed on drop.
///
/// The name combines the process id (distinct per test binary), a nanosecond
/// timestamp, and a process-wide atomic counter. The counter is what actually
/// guarantees uniqueness: cargo runs a binary's tests on several threads at once,
/// and two calls can land within the same clock tick (the system clock's
/// resolution is coarser than the gap between them), so a name built only from
/// pid + timestamp can collide — leaving two tests sharing one directory and
/// clobbering each other's files. The monotonic counter never repeats within a
/// process, so every `TempDir` is isolated regardless of clock granularity.
pub(crate) struct TempDir(pub(crate) PathBuf);

impl TempDir {
    pub(crate) fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "kiss_chat_test_{}_{nanos}_{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
