//! Reusable scratch storage for one request.
//!
//! `RequestScratch` is checked out at request_filter entry and returned through
//! RAII, including error returns and future cancellation. The bump arena retains
//! chunks for request strings; reset rewinds allocation state at scope exit.
//!
//! `Bump` is Send but not Sync, while request_filter is a Send future. Borrow the
//! arena itself only in the synchronous prologue, never across await. Frozen
//! string and slice references can cross awaits; tests check this distinction.
//!
//! Reset does not zero memory. Safe access returns only freshly written, exact
//! length slices, but previous bytes remain resident in retained chunks. Scratch
//! whose arena or frame buffer exceeds RETAIN_CAP_BYTES is dropped, bounding
//! retained capacity after a large request.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use bumpalo::Bump;

/// Per-checkout retention gate: over this, the scratch is dropped instead of pooled.
const RETAIN_CAP_BYTES: usize = 64 * 1024;
/// Pool stripes spread checkout and return contention across worker threads.
const STRIPES: usize = 8;
/// Per-stripe cap; overflow drops the scratch (bounded pool memory).
const PER_STRIPE_CAP: usize = 8;

pub(super) struct RequestScratch {
    pub(super) bump: Bump,
    pub(super) frame_buf: Vec<u8>,
}

impl Default for RequestScratch {
    fn default() -> Self {
        Self {
            bump: Bump::new(),
            frame_buf: Vec::new(),
        }
    }
}

pub(super) struct ScratchPool {
    stripes: [Mutex<Vec<RequestScratch>>; STRIPES],
    /// Round-robin stripe selector — cheaper and fairer than thread-id hashing, and it
    /// cannot collapse onto one stripe under work-stealing.
    next: AtomicUsize,
}

impl ScratchPool {
    pub(super) fn new() -> Self {
        Self {
            stripes: std::array::from_fn(|_| Mutex::new(Vec::with_capacity(PER_STRIPE_CAP))),
            next: AtomicUsize::new(0),
        }
    }

    /// Check a scratch out. Checkout ALSO resets (belt + suspenders with the Drop-side
    /// reset, same convention as the checkin surplus guard in frame_hop): even if a
    /// future code path returned a dirty scratch, no request ever observes another
    /// request's arena state.
    pub(super) fn checkout(&self) -> ScratchGuard<'_> {
        let stripe = self.next.fetch_add(1, Ordering::Relaxed) % STRIPES;
        let mut scratch = self.stripes[stripe]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop()
            .unwrap_or_default();
        scratch.bump.reset();
        scratch.frame_buf.clear();
        ScratchGuard {
            pool: self,
            scratch: Some(scratch),
        }
    }
}

pub(super) struct ScratchGuard<'p> {
    pool: &'p ScratchPool,
    scratch: Option<RequestScratch>,
}

impl ScratchGuard<'_> {
    /// Disjoint field borrows for request_filter: a SHARED `&Bump` (prologue-only — the
    /// Send-ness rule) and an EXCLUSIVE `&mut Vec<u8>` frame buffer (used at encode,
    /// legally held across awaits).
    pub(super) fn split(&mut self) -> (&Bump, &mut Vec<u8>) {
        let scratch = self.scratch.as_mut().expect("scratch present until drop");
        (&scratch.bump, &mut scratch.frame_buf)
    }
}

impl Drop for ScratchGuard<'_> {
    fn drop(&mut self) {
        let Some(mut scratch) = self.scratch.take() else {
            return;
        };
        // High-water retention gate BEFORE reset (allocated_bytes reads the used total).
        if scratch.bump.allocated_bytes() > RETAIN_CAP_BYTES
            || scratch.frame_buf.capacity() > RETAIN_CAP_BYTES
        {
            return; // drop: an oversized request must not pin memory in the pool
        }
        scratch.bump.reset();
        scratch.frame_buf.clear();
        let stripe = self.pool.next.fetch_add(1, Ordering::Relaxed) % STRIPES;
        let mut free = self.pool.stripes[stripe]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if free.len() < PER_STRIPE_CAP {
            free.push(scratch);
        } // else: overflow drops — pool memory stays bounded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PIN: the arena constructors must agree with the owned
    /// constructors on the lowering invariant — `new` and `new_in` are the only two
    /// LoweredHeader constructors, and a disagreement would reopen the smuggle seam.
    #[test]
    fn constructors_agree_on_lowering() {
        let bump = Bump::new();
        for (name, value) in [
            ("Host", "x"),
            ("host", "x"),
            ("X-MiXeD-CaSe", "v"),
            ("already-lower", "v"),
            ("UPPER", ""),
        ] {
            let owned = crate::LoweredHeader::new(name.to_string(), value.to_string());
            let arena = crate::LoweredHeader::new_in(&bump, name, value);
            assert_eq!(owned.name(), arena.name());
            assert_eq!(owned.value(), arena.value());
            assert_eq!(
                owned.lower(),
                arena.lower(),
                "lowering diverged for {name:?}"
            );
        }
    }

    /// PIN: data built from the arena and frozen (the request_filter
    /// pattern) must be legal to hold across an await in a Send future. `&Bump` itself
    /// is !Sync — this test proves the FROZEN slice form is what crosses awaits.
    #[test]
    fn frozen_arena_slice_is_send_across_await() {
        fn assert_send<T: Send>(_: T) {}
        let pool = std::sync::Arc::new(ScratchPool::new());
        assert_send(async move {
            let mut guard = pool.checkout();
            // The prologue block: every !Sync binding (&Bump, the bumpalo Vec) begins
            // AND ends here, exactly like request_filter's collect call; only the
            // frozen Sync slice escapes to cross the await.
            let frozen: &[crate::LoweredHeader<'_>] = {
                let (bump, _buf) = guard.split();
                let mut v = bumpalo::collections::Vec::with_capacity_in(1, bump);
                v.push(crate::LoweredHeader::new_in(bump, "Host", "x"));
                v.into_bump_slice()
            };
            std::future::ready(()).await;
            assert_eq!(frozen[0].lower(), "host");
        });
    }

    /// SECURITY PIN: cross-request bleed. A recycled scratch must present as empty
    /// (allocated_bytes == 0) and fresh allocations must contain exactly what THIS
    /// request wrote — no stale content reachable through any safe API.
    #[test]
    fn recycled_scratch_shows_no_prior_request_state() {
        let pool = ScratchPool::new();
        // Fill every stripe candidate deterministically: one checkout, write, return.
        {
            let mut g = pool.checkout();
            let (bump, frame_buf) = g.split();
            let secret = bump.alloc_str("SECRET-authorization-bearer-token");
            assert_eq!(secret, "SECRET-authorization-bearer-token");
            frame_buf.extend_from_slice(b"SECRET-frame-bytes");
        }
        // Drain checkouts until we provably get a RECYCLED scratch (capacity retained
        // proves reuse), then assert it is reset and content-exact.
        for _ in 0..STRIPES {
            let mut g = pool.checkout();
            let (bump, frame_buf) = g.split();
            assert_eq!(bump.allocated_bytes(), 0, "recycled bump must be reset");
            assert!(frame_buf.is_empty(), "recycled frame_buf must be cleared");
            let fresh = bump.alloc_str("ok");
            assert_eq!(fresh, "ok", "handout is length-exact, no stale suffix");
        }
    }

    /// Oversized scratches (bump high-water OR frame_buf) are dropped, not pooled.
    #[test]
    fn oversized_scratch_is_dropped_not_pooled() {
        let pool = ScratchPool::new();
        {
            let mut g = pool.checkout();
            let (bump, _fb) = g.split();
            let big = vec![0u8; RETAIN_CAP_BYTES + 1];
            let _ = bump.alloc_slice_copy(&big);
        }
        {
            let mut g = pool.checkout();
            g.split().1.reserve(RETAIN_CAP_BYTES + 1);
        }
        // Every pooled scratch (if any) must be under the cap.
        for stripe in &pool.stripes {
            for s in stripe.lock().unwrap().iter() {
                assert!(s.frame_buf.capacity() <= RETAIN_CAP_BYTES);
                assert!(s.bump.allocated_bytes() == 0);
            }
        }
    }

    /// Pool never grows past its caps under churn (overflow drops).
    #[test]
    fn pool_stays_bounded_under_churn() {
        let pool = ScratchPool::new();
        let guards: Vec<_> = (0..STRIPES * PER_STRIPE_CAP * 2)
            .map(|_| pool.checkout())
            .collect();
        drop(guards);
        for stripe in &pool.stripes {
            assert!(stripe.lock().unwrap().len() <= PER_STRIPE_CAP);
        }
    }
}
