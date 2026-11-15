//! Space-Saving top-K (Metwally et al., 2005) over an indexed min-heap: O(log K) per item,
//! fixed memory, and each count overestimates by at most its recorded `error`.
//!
//! Each entry can carry a small payload `T` (zero-sized `()` by default) that is reset when a
//! newcomer takes over an entry, so it covers the occurrences since the key entered the list:
//! `count - error` of them.

use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;

#[derive(Debug, Clone)]
struct Entry<K, T> {
    key: K,
    count: u64,
    error: u64,
    extra: T,
}

/// The `capacity` heaviest keys seen.
#[derive(Debug, Clone)]
pub struct SpaceSaving<K, T = ()> {
    capacity: usize,
    /// Key → position in `heap`.
    pos: HashMap<K, usize>,
    /// Min-heap by count: the root is the next to be replaced.
    heap: Vec<Entry<K, T>>,
}

/// One reported key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Top<K> {
    pub key: K,
    /// Upper bound of the true count.
    pub count: u64,
    /// The true count is at least `count - error`.
    pub error: u64,
}

impl<K: Hash + Eq + Clone> SpaceSaving<K> {
    pub fn new(capacity: usize) -> Self {
        Self::with_payload(capacity)
    }
}

impl<K: Hash + Eq + Clone, T: Default> SpaceSaving<K, T> {
    /// A list whose entries each carry a `T` (see [`Self::offer_with`]).
    pub fn with_payload(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            pos: HashMap::new(),
            heap: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.heap.len()
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    /// Counts one occurrence of `key`; `own` makes the stored key, and runs (allocating, for
    /// boxed keys) only when a new key is stored.
    pub fn offer<Q>(&mut self, key: &Q, own: impl FnOnce(&Q) -> K)
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.offer_with(key, own, |_| {});
    }

    /// [`Self::offer`], then `update` on the key's payload (a fresh `T::default()` when the
    /// key is new to the list, including when it replaces the minimum).
    pub fn offer_with<Q>(&mut self, key: &Q, own: impl FnOnce(&Q) -> K, update: impl FnOnce(&mut T))
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        if let Some(&i) = self.pos.get(key) {
            self.heap[i].count += 1;
            update(&mut self.heap[i].extra);
            self.sift_down(i);
            return;
        }
        let owned = own(key);
        let mut extra = T::default();
        update(&mut extra);
        if self.heap.len() < self.capacity {
            self.heap.push(Entry {
                key: owned.clone(),
                count: 1,
                error: 0,
                extra,
            });
            let i = self.heap.len() - 1;
            self.pos.insert(owned, i);
            self.sift_up(i);
            return;
        }
        // Replace the minimum: the newcomer inherits its count as possible overestimate.
        let min = self.heap[0].count;
        let old = std::mem::replace(
            &mut self.heap[0],
            Entry {
                key: owned.clone(),
                count: min + 1,
                error: min,
                extra,
            },
        );
        self.pos.remove::<K>(&old.key);
        self.pos.insert(owned, 0);
        self.sift_down(0);
    }

    /// The `n` heaviest keys, heaviest first.
    pub fn top(&self, n: usize) -> Vec<Top<K>> {
        self.heaviest(n).into_iter().map(Self::report).collect()
    }

    /// [`Self::top`] with each key's payload.
    pub fn top_with(&self, n: usize) -> Vec<(Top<K>, T)>
    where
        T: Clone,
    {
        self.heaviest(n)
            .into_iter()
            .map(|e| (Self::report(e), e.extra.clone()))
            .collect()
    }

    fn heaviest(&self, n: usize) -> Vec<&Entry<K, T>> {
        let mut v: Vec<&Entry<K, T>> = self.heap.iter().collect();
        v.sort_by(|a, b| b.count.cmp(&a.count).then(a.error.cmp(&b.error)));
        v.truncate(n);
        v
    }

    fn report(e: &Entry<K, T>) -> Top<K> {
        Top {
            key: e.key.clone(),
            count: e.count,
            error: e.error,
        }
    }

    fn swap(&mut self, a: usize, b: usize) {
        self.heap.swap(a, b);
        for i in [a, b] {
            if let Some(p) = self.pos.get_mut(&self.heap[i].key) {
                *p = i;
            }
        }
    }

    fn sift_up(&mut self, mut i: usize) {
        while i > 0 {
            let parent = (i - 1) / 2;
            if self.heap[i].count >= self.heap[parent].count {
                break;
            }
            self.swap(i, parent);
            i = parent;
        }
    }

    fn sift_down(&mut self, mut i: usize) {
        loop {
            let (l, r) = (2 * i + 1, 2 * i + 2);
            let mut smallest = i;
            if l < self.heap.len() && self.heap[l].count < self.heap[smallest].count {
                smallest = l;
            }
            if r < self.heap.len() && self.heap[r].count < self.heap[smallest].count {
                smallest = r;
            }
            if smallest == i {
                return;
            }
            self.swap(i, smallest);
            i = smallest;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // REQ: OBS-004 — a payload follows its key, and starts over when a newcomer takes the
    // minimum's place (it covers `count - error` occurrences).
    #[test]
    fn obs_004_payload_follows_key_and_resets_on_replacement() {
        let mut s: SpaceSaving<u8, u64> = SpaceSaving::with_payload(2);
        for _ in 0..3 {
            s.offer_with(&1, |k| *k, |n| *n += 1);
        }
        s.offer_with(&2, |k| *k, |n| *n += 10);
        // 3 replaces 2 (the minimum, count 1): count 2, error 1, payload fresh.
        s.offer_with(&3, |k| *k, |n| *n += 100);
        let top = s.top_with(2);
        assert_eq!(
            top,
            vec![
                (
                    Top {
                        key: 1,
                        count: 3,
                        error: 0
                    },
                    3
                ),
                (
                    Top {
                        key: 3,
                        count: 2,
                        error: 1
                    },
                    100
                ),
            ]
        );
        // Plain offers leave the payload alone.
        s.offer(&1, |k| *k);
        assert_eq!(s.top_with(1)[0].1, 3);
        assert_eq!(s.top(1)[0].count, 4);
    }
}
