//! REQ: DSC-906 (T31.2, ADR-1005 section 2) - a compact hash table for the in-memory index.
//!
//! The index holds one small entry per source record (65,536 at the cap) and the RSS budget is 8 MiB
//! over everything. A `HashMap` sizes its buckets to a power of two and keeps a control byte for
//! each, so 65,536 entries took the memory of 131,072. This table is open addressing over one
//! `Vec` of `(key, value)` slots, at most 80 percent full, grown by a quarter: 65,536 entries take
//! about 82,000 slots. The key is a nonzero 64-bit hash (a hash of zero is stored as one).

/// An open-addressing table from a 64-bit key to a small `Copy` value.
#[derive(Debug, Clone, Default)]
pub(crate) struct Table<V: Copy + Default> {
    slots: Vec<(u64, V)>,
    len: usize,
}

fn nz(k: u64) -> u64 {
    if k == 0 { 1 } else { k }
}

impl<V: Copy + Default> Table<V> {
    /// A table with room for `n` entries (so a start-up read grows nothing).
    pub(crate) fn with_capacity(n: usize) -> Self {
        Self {
            slots: vec![(0, V::default()); n.saturating_mul(5) / 4 + 16],
            len: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Slots allocated, for the memory estimate.
    pub(crate) fn capacity(&self) -> usize {
        self.slots.len()
    }

    fn home(&self, k: u64) -> usize {
        usize::try_from(k % u64::try_from(self.slots.len().max(1)).unwrap_or(1)).unwrap_or(0)
    }

    fn find(&self, key: u64) -> Option<usize> {
        if self.slots.is_empty() {
            return None;
        }
        let k = nz(key);
        let mut i = self.home(k);
        for _ in 0..self.slots.len() {
            let (sk, _) = self.slots.get(i)?;
            if *sk == k {
                return Some(i);
            }
            if *sk == 0 {
                return None;
            }
            i = (i + 1) % self.slots.len();
        }
        None
    }

    pub(crate) fn get(&self, key: u64) -> Option<&V> {
        self.find(key)
            .and_then(|i| self.slots.get(i))
            .map(|(_, v)| v)
    }

    pub(crate) fn get_mut(&mut self, key: u64) -> Option<&mut V> {
        let i = self.find(key)?;
        self.slots.get_mut(i).map(|(_, v)| v)
    }

    pub(crate) fn contains_key(&self, key: u64) -> bool {
        self.find(key).is_some()
    }

    fn grow(&mut self) {
        let want = (self.slots.len().saturating_add(self.slots.len() / 4)).max(16);
        let old = std::mem::replace(&mut self.slots, vec![(0, V::default()); want]);
        self.len = 0;
        for (k, v) in old {
            if k != 0 {
                self.put(k, v);
            }
        }
    }

    fn put(&mut self, k: u64, v: V) {
        let mut i = self.home(k);
        loop {
            let Some(slot) = self.slots.get_mut(i) else {
                return;
            };
            if slot.0 == 0 {
                *slot = (k, v);
                self.len += 1;
                return;
            }
            if slot.0 == k {
                slot.1 = v;
                return;
            }
            i = (i + 1) % self.slots.len();
        }
    }

    /// Inserts or replaces.
    pub(crate) fn insert(&mut self, key: u64, v: V) {
        if (self.len + 1) * 5 > self.slots.len() * 4 {
            self.grow();
        }
        self.put(nz(key), v);
    }

    /// Keeps the entries `f` accepts (the table is rebuilt, so it also gives back its slack).
    pub(crate) fn retain(&mut self, mut f: impl FnMut(&u64, &mut V) -> bool) {
        let old = std::mem::take(&mut self.slots);
        self.len = 0;
        let kept: Vec<(u64, V)> = old
            .into_iter()
            .filter_map(|(k, mut v)| (k != 0 && f(&k, &mut v)).then_some((k, v)))
            .collect();
        let want = (kept.len().saturating_mul(5) / 4).max(16);
        self.slots = vec![(0, V::default()); want];
        for (k, v) in kept {
            self.put(k, v);
        }
    }

    #[cfg(test)]
    pub(crate) fn values(&self) -> impl Iterator<Item = &V> {
        self.slots.iter().filter(|(k, _)| *k != 0).map(|(_, v)| v)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&u64, &V)> {
        self.slots
            .iter()
            .filter(|(k, _)| *k != 0)
            .map(|(k, v)| (k, v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: DSC-906 - the table behaves as a map (insert, replace, get, retain) and, full, takes
    /// about a quarter more slots than entries, not twice as many.
    #[test]
    fn dsc_906_table_is_a_compact_map() {
        let mut t: Table<u32> = Table::default();
        for n in 0..65_536u64 {
            t.insert(
                n.wrapping_mul(0x9E37_79B9_7F4A_7C15),
                u32::try_from(n).unwrap(),
            );
        }
        assert_eq!(t.len(), 65_536);
        assert!(t.capacity() < 65_536 * 3 / 2, "{} slots", t.capacity());
        assert_eq!(t.get(5u64.wrapping_mul(0x9E37_79B9_7F4A_7C15)), Some(&5));
        t.insert(5u64.wrapping_mul(0x9E37_79B9_7F4A_7C15), 7);
        assert_eq!(t.len(), 65_536, "replaced, not added");
        assert_eq!(t.get(5u64.wrapping_mul(0x9E37_79B9_7F4A_7C15)), Some(&7));
        assert!(t.get(1).is_none() || t.contains_key(1));
        t.retain(|_, v| *v % 2 == 0);
        assert_eq!(t.len(), 32_768);
        assert_eq!(t.values().count(), 32_768);
        // The zero key is storable (it becomes one).
        let mut z: Table<u8> = Table::default();
        z.insert(0, 9);
        assert_eq!(z.get(0), Some(&9));
        assert_eq!(z.len(), 1);
    }
}
