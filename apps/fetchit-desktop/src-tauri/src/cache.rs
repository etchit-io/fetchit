//! Process-local cache of fetched Autonomi bytes, keyed by [`Address`].
//!
//! Sized for a single user session: an HTML page can reference its own
//! `autonomi://` assets, and the WebView will issue parallel loads — caching
//! avoids re-fetching the same address from the network in the same session.

use bytes::Bytes;
use fetchit_core::Address;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Default)]
pub struct BytesCache {
    inner: Mutex<HashMap<Address, Bytes>>,
}

impl BytesCache {
    pub fn get(&self, addr: &Address) -> Option<Bytes> {
        self.inner.lock().ok()?.get(addr).cloned()
    }

    pub fn put(&self, addr: Address, bytes: Bytes) {
        if let Ok(mut g) = self.inner.lock() {
            g.insert(addr, bytes);
        }
    }

    pub fn clear(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const B: &str = "0000000000000000000000000000000000000000000000000000000000000002";

    fn addr(hex: &str) -> Address {
        hex.parse().expect("valid 64-hex test fixture")
    }

    #[test]
    fn put_then_get_round_trip() {
        let c = BytesCache::default();
        let bytes = Bytes::from_static(b"hello");
        c.put(addr(A), bytes.clone());
        assert_eq!(c.get(&addr(A)), Some(bytes));
    }

    #[test]
    fn get_missing_returns_none() {
        let c = BytesCache::default();
        assert_eq!(c.get(&addr(A)), None);
    }

    #[test]
    fn put_overwrites_existing() {
        let c = BytesCache::default();
        c.put(addr(A), Bytes::from_static(b"first"));
        c.put(addr(A), Bytes::from_static(b"second"));
        assert_eq!(c.get(&addr(A)), Some(Bytes::from_static(b"second")));
    }

    #[test]
    fn clear_removes_all_entries() {
        let c = BytesCache::default();
        c.put(addr(A), Bytes::from_static(b"x"));
        c.put(addr(B), Bytes::from_static(b"y"));
        c.clear();
        assert!(c.get(&addr(A)).is_none());
        assert!(c.get(&addr(B)).is_none());
    }

    #[test]
    fn entries_for_different_addresses_are_isolated() {
        let c = BytesCache::default();
        c.put(addr(A), Bytes::from_static(b"a"));
        c.put(addr(B), Bytes::from_static(b"b"));
        assert_eq!(c.get(&addr(A)), Some(Bytes::from_static(b"a")));
        assert_eq!(c.get(&addr(B)), Some(Bytes::from_static(b"b")));
    }
}
