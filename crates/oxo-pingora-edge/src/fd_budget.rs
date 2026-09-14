//! the edge's boot-time file-descriptor budget.
//!
//! Two rules, in plain words. The edge refuses to boot only when it cannot serve at
//! all: the descriptors it holds before the first request (`fixed`: its listeners, one
//! hop connection per worker, and a constant reserve) exceed the process's soft
//! `RLIMIT_NOFILE`. The idle-pool ceiling is NOT a reservation: idle worker
//! connections are created lazily and the measured working set (, ) is a third
//! of the default ceiling, so a ceiling that would leave too little room for downstream
//! connections is a warning, never a refusal. The warning threshold is an absolute
//! remainder (`MIN_DOWNSTREAM`), not a fraction, so the stock configuration under the
//! common 1024 soft limit boots silently.
//!
//! Every concurrent request holds two descriptors: its downstream socket and an
//! in-flight hop connection to a worker, which is disjoint from the idle pool. When the
//! global in-flight cap is set the budget counts `2 x cap` as demand; when it is not,
//! the notice says so and the remainder is printed as descriptors AND as the number of
//! concurrent requests it can hold.
//!
//! Descriptor exhaustion is not a crash, which is why a boot-time budget is worth
//! having: pingora's accept loop logs `Accept() failed` and sleeps one second on
//! `EMFILE` (a stalling live listener), and a failed hop connect returns a 503 for that
//! one request. Neither symptom names the cause; the `fd-budget` notice does.
//!
//! This module compiles on every target (it lives at the crate root, not under the
//! Linux-only `platform`), so its arithmetic is unit-tested on the Windows dev box as
//! well as in the Linux gates. Only `read_nofile_limits` touches the process, and only
//! on Linux; everywhere else the limit is `Unknown` and the verdict is `Ok`.
//!
//! Rejected alternatives, so the choice is on record: raising the soft limit to
//! `min(hard, needed)` at boot (what Go does since 1.19) and clamping the ceiling to the
//! remainder. Both change a running process's posture without the operator asking; the
//! scope was warn-or-refuse. Either is a small follow-up if wanted.

/// Constant margin for descriptors the edge holds regardless of configuration: stdio,
/// the admin listener and its thread, one tokio runtime per pingora service (pingora
/// builds one multi-thread runtime per service, not per worker thread), the drain
/// runtime, TLS/ACME state, the request log. Deliberately generous; it only ever moves
/// the verdict towards `Warn`, and `Refuse` needs the whole `fixed` sum above the soft
/// limit, which no realistic reserve reaches.
pub const RESERVE: u64 = 32;

/// The smallest remainder the budget accepts without a warning: with the pool at its
/// ceiling and (when capped) every in-flight request holding its two descriptors, at
/// least this many descriptors must still be free for downstream connections.
pub const MIN_DOWNSTREAM: u64 = 256;

/// The process descriptor limit as the budget sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Nofile {
    /// Not a Linux process, or `getrlimit` failed: no limit is known and no verdict but
    /// `Ok` is possible.
    Unknown,
    /// `RLIM_INFINITY` on the soft limit.
    Unlimited,
    Limits {
        soft: u64,
        hard: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FdVerdict {
    Ok,
    Warn,
    Refuse,
}

impl FdVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            FdVerdict::Ok => "ok",
            FdVerdict::Warn => "warn",
            FdVerdict::Refuse => "refuse",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdBudget {
    pub listeners: u64,
    /// One hop connection per worker: the steady-state minimum a serving edge holds.
    pub hops: u64,
    pub reserve: u64,
    /// `listeners + hops + reserve`: held before the first request.
    pub fixed: u64,
    pub pool: u64,
    pub in_flight_cap: Option<u64>,
    /// `fixed + pool (+ 2 x cap)`, saturating.
    pub demand: u64,
    pub limits: Nofile,
    /// `soft - demand`, saturating; `None` when the limit is unknown or unlimited.
    pub remainder: Option<u64>,
    pub verdict: FdVerdict,
}

/// Pure: reads nothing from the process. `pool_ceiling` and the counts arrive as
/// `u64`, and every sum saturates, because the ceiling is an operator-supplied number
/// with no upper bound of its own.
pub fn fd_budget(
    limits: Nofile,
    listeners: u64,
    worker_count: u64,
    pool_ceiling: u64,
    in_flight_cap: Option<u64>,
) -> FdBudget {
    let hops = worker_count;
    let fixed = listeners.saturating_add(hops).saturating_add(RESERVE);
    let cap_demand = in_flight_cap.map_or(0, |c| c.saturating_mul(2));
    let demand = fixed
        .saturating_add(pool_ceiling)
        .saturating_add(cap_demand);
    let (remainder, verdict) = match limits {
        Nofile::Unknown | Nofile::Unlimited => (None, FdVerdict::Ok),
        Nofile::Limits { soft, .. } => {
            let verdict = if fixed > soft {
                FdVerdict::Refuse
            } else if demand.saturating_add(MIN_DOWNSTREAM) > soft {
                FdVerdict::Warn
            } else {
                FdVerdict::Ok
            };
            (Some(soft.saturating_sub(demand)), verdict)
        }
    };
    FdBudget {
        listeners,
        hops,
        reserve: RESERVE,
        fixed,
        pool: pool_ceiling,
        in_flight_cap,
        demand,
        limits,
        remainder,
        verdict,
    }
}

impl FdBudget {
    /// The posture line, printed on every boot and on `--check-config`.
    pub fn notice(&self) -> String {
        let cap = match self.in_flight_cap {
            Some(c) => format!(" + 2 x in-flight cap {c}"),
            None => String::new(),
        };
        let limit = match self.limits {
            Nofile::Unknown => {
                "process descriptor limit (RLIMIT_NOFILE) unknown on this platform".to_string()
            }
            Nofile::Unlimited => {
                "an unlimited process descriptor limit (RLIMIT_NOFILE)".to_string()
            }
            Nofile::Limits { soft, hard } => {
                format!("process descriptor limit (RLIMIT_NOFILE) soft {soft} / hard {hard}")
            }
        };
        let remainder = match self.remainder {
            Some(n) => format!(
                "; remainder {n} descriptors, about {} concurrent requests, each holding two descriptors",
                n / 2
            ),
            None => String::new(),
        };
        let excluded = if self.in_flight_cap.is_none() {
            "; in-flight hops excluded from the demand (no global in-flight cap)"
        } else {
            ""
        };
        format!(
            "oxo_edge_config_notice fd-budget: {} -- fixed {} (listeners {} + worker hops {} + reserve {}) + idle pool {}{} = demand {} against {}{}{}",
            self.verdict.as_str(),
            self.fixed,
            self.listeners,
            self.hops,
            self.reserve,
            self.pool,
            cap,
            self.demand,
            limit,
            remainder,
            excluded,
        )
    }

    /// The remedy for a limit that is too small for `needed` descriptors, branched on
    /// the hard limit: an unprivileged `ulimit -n` can only raise the soft limit up to
    /// the hard one.
    fn remedy(&self, needed: u64) -> String {
        let Nofile::Limits { soft, hard } = self.limits else {
            return String::new();
        };
        let pool_fit = soft.saturating_sub(
            self.fixed
                .saturating_add(MIN_DOWNSTREAM)
                .saturating_add(self.in_flight_cap.map_or(0, |c| c.saturating_mul(2))),
        );
        if needed <= hard {
            format!(
                "raise the soft limit to at least {needed}: `ulimit -n {needed}` before starting the edge, or `LimitNOFILE={needed}` in the systemd unit; or lower OXO_EDGE_FRAME_POOL_IDLE to at most {pool_fit}"
            )
        } else {
            format!(
                "the hard limit {hard} is below the {needed} needed: set `LimitNOFILE={needed}` in the systemd unit or raise the limit in /etc/security/limits.conf as root; or lower OXO_EDGE_FRAME_POOL_IDLE to at most {pool_fit}"
            )
        }
    }

    /// The warning line, present only on `Warn`.
    pub fn warning(&self) -> Option<String> {
        if self.verdict != FdVerdict::Warn {
            return None;
        }
        let needed = self.demand.saturating_add(MIN_DOWNSTREAM);
        Some(format!(
            "oxo_edge_config_warning fd-budget: with the idle pool at its ceiling ({}){} the process descriptor limit leaves {} descriptors for downstream connections, below the {} the edge wants; {}",
            self.pool,
            match self.in_flight_cap {
                Some(c) => format!(" and {c} in-flight requests"),
                None => String::new(),
            },
            self.remainder.unwrap_or(0),
            MIN_DOWNSTREAM,
            self.remedy(needed),
        ))
    }

    /// The refusal message, present only on `Refuse`; the caller turns it into the
    /// config error that exits 78.
    pub fn refusal(&self) -> Option<String> {
        if self.verdict != FdVerdict::Refuse {
            return None;
        }
        let soft = match self.limits {
            Nofile::Limits { soft, .. } => soft,
            _ => 0,
        };
        Some(format!(
            "the edge holds {} descriptors before its first request (listeners {} + worker hops {} + reserve {}) and the process descriptor limit (RLIMIT_NOFILE) soft limit is {}; it cannot serve. {}",
            self.fixed,
            self.listeners,
            self.hops,
            self.reserve,
            soft,
            self.remedy(self.fixed),
        ))
    }
}

/// The process's `RLIMIT_NOFILE`, Linux only. `libc` is a Linux-only dependency of
/// this crate, so the reader is gated on the same predicate as `platform`.
#[cfg(target_os = "linux")]
pub fn read_nofile_limits() -> Nofile {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into the struct we own and reads nothing else.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
    if rc != 0 {
        return Nofile::Unknown;
    }
    if lim.rlim_cur == libc::RLIM_INFINITY {
        return Nofile::Unlimited;
    }
    // rlim_t is u64 on every Linux target this crate builds for.
    Nofile::Limits {
        soft: lim.rlim_cur,
        hard: lim.rlim_max,
    }
}

#[cfg(not(target_os = "linux"))]
pub fn read_nofile_limits() -> Nofile {
    Nofile::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    const HARD: u64 = 1_048_576;

    fn limits(soft: u64) -> Nofile {
        Nofile::Limits { soft, hard: HARD }
    }

    /// The stock 16-worker edge with an admin bind under the common 1024 soft limit
    /// boots silently. Every expected number is derived from the named components.
    #[test]
    fn stock_configuration_under_1024_is_ok() {
        let (listeners, workers, pool) = (2u64, 16u64, 512u64);
        let b = fd_budget(limits(1024), listeners, workers, pool, None);
        assert_eq!(b.fixed, listeners + workers + RESERVE);
        assert_eq!(b.demand, b.fixed + pool);
        assert_eq!(b.remainder, Some(1024 - b.demand));
        assert!(b.remainder.unwrap() >= MIN_DOWNSTREAM, "{b:?}");
        assert_eq!(b.verdict, FdVerdict::Ok);
        let n = b.notice();
        assert!(
            n.starts_with("oxo_edge_config_notice fd-budget: ok -- "),
            "{n}"
        );
        assert!(n.contains("soft 1024 / hard 1048576"), "{n}");
        assert!(n.contains("in-flight hops excluded"), "{n}");
        assert!(
            n.contains(&format!(
                "remainder {} descriptors, about {} concurrent",
                1024 - b.demand,
                (1024 - b.demand) / 2
            )),
            "{n}"
        );
        assert_eq!(b.warning(), None);
        assert_eq!(b.refusal(), None);
    }

    /// The sentence wrote and nothing checked: at 32 workers the default ceiling
    /// (workers x 32 = 1024) meets a 1024 soft limit. That is a warning, not a refusal.
    #[test]
    fn thirty_two_workers_at_default_ceiling_warns_under_1024() {
        let workers = 32u64;
        let pool = workers * 32;
        let b = fd_budget(limits(1024), 1, workers, pool, None);
        assert_eq!(b.verdict, FdVerdict::Warn, "{b:?}");
        let w = b.warning().expect("warning present");
        assert!(w.starts_with("oxo_edge_config_warning fd-budget: "), "{w}");
        // needed = demand + MIN_DOWNSTREAM is below the hard limit: the ulimit remedy.
        assert!(w.contains("ulimit -n"), "{w}");
        assert!(w.contains("OXO_EDGE_FRAME_POOL_IDLE to at most"), "{w}");
        assert_eq!(b.refusal(), None);
    }

    #[test]
    fn verdict_boundaries_are_exact() {
        let (listeners, workers, pool) = (1u64, 4u64, 100u64);
        let fixed = listeners + workers + RESERVE;
        let demand = fixed + pool;
        // Refuse needs fixed strictly above soft.
        assert_eq!(
            fd_budget(limits(fixed - 1), listeners, workers, pool, None).verdict,
            FdVerdict::Refuse
        );
        assert_ne!(
            fd_budget(limits(fixed), listeners, workers, pool, None).verdict,
            FdVerdict::Refuse
        );
        // Warn needs demand + MIN_DOWNSTREAM strictly above soft.
        assert_eq!(
            fd_budget(
                limits(demand + MIN_DOWNSTREAM),
                listeners,
                workers,
                pool,
                None
            )
            .verdict,
            FdVerdict::Ok
        );
        assert_eq!(
            fd_budget(
                limits(demand + MIN_DOWNSTREAM - 1),
                listeners,
                workers,
                pool,
                None
            )
            .verdict,
            FdVerdict::Warn
        );
    }

    #[test]
    fn refusal_names_the_fixed_floor_and_the_soft_limit() {
        let b = fd_budget(limits(40), 2, 16, 512, None);
        assert_eq!(b.verdict, FdVerdict::Refuse);
        let r = b.refusal().expect("refusal present");
        assert!(
            r.contains(&format!("holds {} descriptors", 2 + 16 + RESERVE)),
            "{r}"
        );
        assert!(r.contains("soft limit is 40"), "{r}");
        assert!(r.contains("RLIMIT_NOFILE"), "{r}");
        assert!(
            r.contains(&format!("ulimit -n {}", 2 + 16 + RESERVE)),
            "{r}"
        );
        assert_eq!(b.warning(), None);
    }

    #[test]
    fn in_flight_cap_adds_two_descriptors_per_request() {
        let uncapped = fd_budget(limits(4096), 1, 16, 512, None);
        let capped = fd_budget(limits(4096), 1, 16, 512, Some(300));
        assert_eq!(capped.demand, uncapped.demand + 600);
        assert!(
            capped.notice().contains("+ 2 x in-flight cap 300"),
            "{}",
            capped.notice()
        );
        assert!(!capped.notice().contains("in-flight hops excluded"));
        // 49 + 512 + 600 = 1161; +256 > 1024 -> Warn under 1024, Ok under 4096.
        assert_eq!(
            fd_budget(limits(1024), 1, 16, 512, Some(300)).verdict,
            FdVerdict::Warn
        );
        assert_eq!(capped.verdict, FdVerdict::Ok);
    }

    #[test]
    fn unlimited_and_unknown_limits_are_ok_and_say_so() {
        for (lim, needle) in [
            (Nofile::Unlimited, "an unlimited process descriptor limit"),
            (Nofile::Unknown, "unknown on this platform"),
        ] {
            let b = fd_budget(lim, 2, 64, u64::MAX, Some(u64::MAX));
            assert_eq!(b.verdict, FdVerdict::Ok, "{b:?}");
            assert_eq!(b.remainder, None);
            assert!(b.notice().contains(needle), "{}", b.notice());
            assert!(!b.notice().contains("remainder"));
            assert_eq!(b.warning(), None);
        }
    }

    #[test]
    fn huge_ceiling_saturates_instead_of_overflowing() {
        let b = fd_budget(limits(1024), 1, 16, u64::MAX, Some(u64::MAX));
        assert_eq!(b.demand, u64::MAX);
        assert_eq!(b.verdict, FdVerdict::Warn);
        assert_eq!(b.remainder, Some(0));
        let w = b.warning().expect("warning");
        // needed saturates above the hard limit: the privileged remedy branch.
        assert!(w.contains("limits.conf"), "{w}");
    }

    #[test]
    fn remedy_branches_on_the_hard_limit() {
        // needed (demand + 256) fits under hard: ulimit suffices.
        let fits = fd_budget(
            Nofile::Limits {
                soft: 1024,
                hard: 4096,
            },
            1,
            32,
            1024,
            None,
        );
        let w = fits.warning().expect("warn");
        assert!(w.contains("ulimit -n") && !w.contains("limits.conf"), "{w}");
        // hard is also too small: only a privileged raise or a smaller pool can work.
        let stuck = fd_budget(
            Nofile::Limits {
                soft: 1024,
                hard: 1024,
            },
            1,
            32,
            1024,
            None,
        );
        let w = stuck.warning().expect("warn");
        assert!(
            w.contains("limits.conf") && w.contains("hard limit 1024"),
            "{w}"
        );
        assert!(w.contains("OXO_EDGE_FRAME_POOL_IDLE to at most"), "{w}");
    }

    #[test]
    fn pool_fit_in_the_remedy_is_the_largest_ceiling_that_would_have_been_ok() {
        let b = fd_budget(limits(1024), 1, 32, 1024, None);
        let w = b.warning().expect("warn");
        let fit = 1024 - (b.fixed + MIN_DOWNSTREAM);
        assert!(w.ends_with(&format!("to at most {fit}")), "{w}");
        assert_eq!(
            fd_budget(limits(1024), 1, 32, fit, None).verdict,
            FdVerdict::Ok
        );
        assert_eq!(
            fd_budget(limits(1024), 1, 32, fit + 1, None).verdict,
            FdVerdict::Warn
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_reader_returns_a_limit_on_linux() {
        match read_nofile_limits() {
            Nofile::Limits { soft, hard } => assert!(soft >= 1 && hard >= soft),
            Nofile::Unlimited => {}
            Nofile::Unknown => panic!("getrlimit failed on Linux"),
        }
    }
}
