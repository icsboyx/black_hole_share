//! Limits per client address: failed password attempts and uploads to request links.
//!
//! Addresses are grouped by [`client_key`]: an IPv6 client usually controls a whole /64,
//! so counting single IPv6 addresses would let it rotate past every limit.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr},
    sync::{Arc, Mutex},
};

/// Above this many tracked addresses, entries that no longer matter are dropped first.
const PRUNE_ABOVE: usize = 10_000;

/// The key a client is counted under: an IPv4 address (also when mapped into IPv6), or the
/// /64 prefix of an IPv6 address. Anything else is counted as itself.
pub fn client_key(ip: &str) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                let prefix = Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0);
                format!("{prefix}/64")
            }
        },
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Err(_) => ip.to_string(),
    }
}

#[derive(Debug, Clone, Copy)]
struct Window {
    /// Start of the current counting window, Unix ms.
    started: i64,
    count: u32,
    /// Set when the limit was reached: nothing is allowed before this time.
    blocked_until: Option<i64>,
}

/// Counts events per client within a time window; once `max` is reached the client is
/// blocked for the rest of the window.
#[derive(Debug, Clone, Default)]
pub struct Throttle {
    windows: Arc<Mutex<HashMap<String, Window>>>,
}

impl Throttle {
    /// `Err(milliseconds left)` while `key` is blocked.
    pub fn check(&self, key: &str, now: i64) -> Result<(), i64> {
        let windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        match windows.get(key).and_then(|w| w.blocked_until) {
            Some(until) if until > now => Err(until - now),
            _ => Ok(()),
        }
    }

    /// Counts one event. Returns `Err(milliseconds left)` when this event reached the limit
    /// or the client was already blocked.
    pub fn record(&self, key: &str, now: i64, max: u32, window_ms: i64) -> Result<(), i64> {
        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        if windows.len() > PRUNE_ABOVE {
            windows.retain(|_, w| w.started + window_ms > now || w.blocked_until > Some(now));
        }
        let window = windows.entry(key.to_string()).or_insert(Window {
            started: now,
            count: 0,
            blocked_until: None,
        });
        if let Some(until) = window.blocked_until
            && until > now
        {
            return Err(until - now);
        }
        if window.started + window_ms <= now || window.blocked_until.is_some() {
            *window = Window {
                started: now,
                count: 0,
                blocked_until: None,
            };
        }
        window.count += 1;
        if window.count >= max {
            let until = now + window_ms;
            window.blocked_until = Some(until);
            return Err(until - now);
        }
        Ok(())
    }

    /// Allows at most `max` events per window: `Err(milliseconds left)` for the ones over.
    /// Unlike `record`, the event that reaches `max` is still allowed.
    pub fn allow(&self, key: &str, now: i64, max: u32, window_ms: i64) -> Result<(), i64> {
        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        if windows.len() > PRUNE_ABOVE {
            windows.retain(|_, w| w.started + window_ms > now);
        }
        let window = windows.entry(key.to_string()).or_insert(Window {
            started: now,
            count: 0,
            blocked_until: None,
        });
        if window.started + window_ms <= now {
            *window = Window {
                started: now,
                count: 0,
                blocked_until: None,
            };
        }
        if window.count >= max {
            return Err(window.started + window_ms - now);
        }
        window.count += 1;
        Ok(())
    }

    /// Forgets `key`, after a successful login.
    pub fn reset(&self, key: &str) {
        self.windows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
    }
}

/// Seconds to put in `Retry-After`, rounded up.
pub fn retry_after_secs(ms: i64) -> i64 {
    (ms.max(0) + 999) / 1000
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: i64 = 60_000;

    #[test]
    fn failures_block_after_the_limit_until_the_window_ends() {
        let throttle = Throttle::default();
        assert!(throttle.record("a", 0, 3, MINUTE).is_ok());
        assert!(throttle.record("a", 1, 3, MINUTE).is_ok());
        assert_eq!(throttle.record("a", 2, 3, MINUTE), Err(MINUTE));
        assert_eq!(throttle.check("a", 10), Err(MINUTE - 8));
        assert!(throttle.check("b", 10).is_ok());
        // Further attempts while blocked do not extend the block.
        assert_eq!(throttle.record("a", 20, 3, MINUTE), Err(MINUTE - 18));
        assert!(throttle.check("a", MINUTE + 2).is_ok());
        assert!(throttle.record("a", MINUTE + 2, 3, MINUTE).is_ok());
    }

    #[test]
    fn old_failures_expire_and_success_resets() {
        let throttle = Throttle::default();
        throttle.record("a", 0, 2, MINUTE).unwrap();
        // The window has passed: the count starts again.
        assert!(throttle.record("a", MINUTE, 2, MINUTE).is_ok());
        throttle.reset("a");
        assert!(throttle.record("a", MINUTE + 1, 2, MINUTE).is_ok());
    }

    #[test]
    fn allow_lets_exactly_max_events_through_per_window() {
        let throttle = Throttle::default();
        assert!(throttle.allow("a", 0, 2, MINUTE).is_ok());
        assert!(throttle.allow("a", 1, 2, MINUTE).is_ok());
        assert_eq!(throttle.allow("a", 10, 2, MINUTE), Err(MINUTE - 10));
        assert!(throttle.allow("b", 10, 2, MINUTE).is_ok());
        assert!(throttle.allow("a", MINUTE, 2, MINUTE).is_ok());
    }

    #[test]
    fn ipv6_clients_are_grouped_by_their_64_prefix() {
        assert_eq!(client_key("2001:db8:1:2:aaaa::1"), "2001:db8:1:2::/64");
        assert_eq!(client_key("2001:db8:1:2:bbbb::9"), "2001:db8:1:2::/64");
        assert_ne!(client_key("2001:db8:1:3::1"), client_key("2001:db8:1:2::1"));
        assert_eq!(client_key("::ffff:192.0.2.7"), "192.0.2.7");
        assert_eq!(client_key("192.0.2.7"), "192.0.2.7");
        assert_eq!(client_key("-"), "-");
    }
}
