//! Bounds on what a pushed pack inflates to, checked as its bytes arrive.
//!
//! A pack of a few kilobytes can declare a 512 MiB object of zeros (a zlib bomb), a
//! delta that builds one, or thousands of tiny deltas that each build a large object.
//! `git index-pack` has no limit on any of these: it inflates and resolves whatever the
//! headers say, holding objects in memory while it does. [`PackGuard`] reads the pack as
//! it is received, before `index-pack` sees it, and refuses it at the first entry that
//! declares more than `max_object_bytes` (a delta: the object it builds), at the first
//! stream that inflates past what its header declares, and once the pack's objects add up
//! to more than `max_inflated_bytes`. It never holds an object: each stream is inflated
//! into a scratch buffer only to find where it ends and how much it yields.

use flate2::{Decompress, FlushDecompress, Status};

/// The limits a pushed pack is held to.
#[derive(Debug, Clone, Copy)]
pub struct PackLimits {
    /// Largest object an entry may declare or a delta may build.
    pub max_object_bytes: u64,
    /// Sum of every object's size (a delta counts the object it builds).
    pub max_inflated_bytes: u64,
}

/// Why a pack was refused.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct PackRefused(pub String);

const OBJ_OFS_DELTA: u8 = 6;
const OBJ_REF_DELTA: u8 = 7;
/// An entry header (type and size, then a delta's base) never needs more than this.
const MAX_HEADER: usize = 128;
const SCRATCH: usize = 64 * 1024;

enum State {
    Header,
    Entry,
    Stream(Box<Entry>),
    Trailer,
}

/// The zlib stream of one entry being inflated.
struct Entry {
    zlib: Decompress,
    /// Size the entry header declares (a delta: the delta's own size).
    declared: u64,
    /// Bytes inflated so far.
    produced: u64,
    /// For a delta: its first bytes, until the base and target sizes are read.
    delta_head: Option<Vec<u8>>,
}

/// A pack being checked, fed in pieces as they are received.
pub struct PackGuard {
    limits: PackLimits,
    hash_len: usize,
    state: State,
    pending: Vec<u8>,
    objects_left: u32,
    inflated: u64,
    scratch: Vec<u8>,
}

impl PackGuard {
    /// Check a pack whose `REF_DELTA` bases are `hash_len` bytes (20 for SHA-1, 32 for SHA-256).
    pub fn new(limits: PackLimits, hash_len: usize) -> Self {
        PackGuard {
            limits,
            hash_len,
            state: State::Header,
            pending: Vec::with_capacity(MAX_HEADER),
            objects_left: 0,
            inflated: 0,
            scratch: vec![0u8; SCRATCH],
        }
    }

    /// Bytes the pack's objects add up to so far.
    pub fn inflated(&self) -> u64 {
        self.inflated
    }

    /// Check the next piece of the pack.
    pub fn feed(&mut self, mut input: &[u8]) -> Result<(), PackRefused> {
        while !input.is_empty() {
            match &mut self.state {
                State::Header => {
                    let take = (12 - self.pending.len()).min(input.len());
                    let (head, rest) = input.split_at(take);
                    self.pending.extend_from_slice(head);
                    input = rest;
                    if self.pending.len() == 12 {
                        self.start()?;
                    }
                }
                State::Entry => {
                    let (byte, rest) = input
                        .split_first()
                        .ok_or_else(|| PackRefused("truncated entry header".into()))?;
                    self.pending.push(*byte);
                    input = rest;
                    if let Some(entry) = self.entry_header()? {
                        self.pending.clear();
                        self.state = State::Stream(Box::new(entry));
                    } else if self.pending.len() > MAX_HEADER {
                        return Err(PackRefused("malformed entry header".into()));
                    }
                }
                State::Stream(_) => {
                    input = self.inflate(input)?;
                }
                State::Trailer => return Ok(()),
            }
        }
        Ok(())
    }

    /// The whole pack was received: refuse one that ended inside an object.
    pub fn finish(&self) -> Result<(), PackRefused> {
        match self.state {
            State::Trailer => Ok(()),
            State::Header if self.pending.is_empty() => Ok(()),
            _ => Err(PackRefused("truncated pack".into())),
        }
    }

    /// Read the 12-byte pack header.
    fn start(&mut self) -> Result<(), PackRefused> {
        let head = &self.pending;
        if head.get(..4) != Some(b"PACK".as_slice()) {
            return Err(PackRefused("not a pack".into()));
        }
        let word = |at: usize| -> u32 {
            head.get(at..at + 4)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map_or(0, u32::from_be_bytes)
        };
        if !matches!(word(4), 2 | 3) {
            return Err(PackRefused(format!("unsupported pack version {}", word(4))));
        }
        self.objects_left = word(8);
        self.pending.clear();
        self.state = if self.objects_left == 0 {
            State::Trailer
        } else {
            State::Entry
        };
        Ok(())
    }

    /// Parse the pending entry header once it is complete, checking what it declares.
    fn entry_header(&mut self) -> Result<Option<Entry>, PackRefused> {
        let bytes = &self.pending;
        let Some(&first) = bytes.first() else {
            return Ok(None);
        };
        let kind = (first >> 4) & 7;
        let mut size = u64::from(first & 0x0f);
        let mut shift = 4u32;
        let mut at = 1;
        let mut byte = first;
        while byte & 0x80 != 0 {
            let Some(&next) = bytes.get(at) else {
                return Ok(None);
            };
            if shift > 57 {
                return Err(PackRefused("entry size overflows".into()));
            }
            size |= u64::from(next & 0x7f) << shift;
            shift += 7;
            at += 1;
            byte = next;
        }
        let delta = match kind {
            1..=4 => false,
            OBJ_OFS_DELTA => {
                // The base offset: a varint ending at the first byte without its top bit.
                let mut done = false;
                while let Some(&b) = bytes.get(at) {
                    at += 1;
                    if b & 0x80 == 0 {
                        done = true;
                        break;
                    }
                }
                if !done {
                    return Ok(None);
                }
                true
            }
            OBJ_REF_DELTA => {
                if bytes.len() < at + self.hash_len {
                    return Ok(None);
                }
                true
            }
            k => return Err(PackRefused(format!("unknown object type {k}"))),
        };
        let max = self.limits.max_object_bytes;
        if size > max {
            let what = if delta { "delta" } else { "object" };
            return Err(PackRefused(format!(
                "{what} of {size} bytes, over the {max} byte object limit"
            )));
        }
        if !delta {
            self.count(size)?;
        }
        Ok(Some(Entry {
            zlib: Decompress::new(true),
            declared: size,
            produced: 0,
            delta_head: delta.then(Vec::new),
        }))
    }

    /// Add an object's size to the pack's total.
    fn count(&mut self, size: u64) -> Result<(), PackRefused> {
        self.inflated = self.inflated.saturating_add(size);
        let max = self.limits.max_inflated_bytes;
        if self.inflated > max {
            return Err(PackRefused(format!(
                "pack inflates past {max} bytes, the push limit"
            )));
        }
        Ok(())
    }

    /// Inflate the current entry's stream from `input`; what is left after its end.
    fn inflate<'i>(&mut self, mut input: &'i [u8]) -> Result<&'i [u8], PackRefused> {
        loop {
            let State::Stream(entry) = &mut self.state else {
                return Ok(input);
            };
            let before_in = entry.zlib.total_in();
            let before_out = entry.zlib.total_out();
            let status = entry
                .zlib
                .decompress(input, &mut self.scratch, FlushDecompress::None)
                .map_err(|e| PackRefused(format!("corrupt object stream: {e}")))?;
            let used = usize::try_from(entry.zlib.total_in() - before_in)
                .map_err(|_| PackRefused("stream position overflows".into()))?;
            let made = usize::try_from(entry.zlib.total_out() - before_out)
                .map_err(|_| PackRefused("stream size overflows".into()))?;
            input = input.get(used..).unwrap_or_default();
            entry.produced += made as u64;
            if entry.produced > entry.declared {
                return Err(PackRefused(
                    "object inflates past the size its header declares".into(),
                ));
            }
            let mut built = None;
            if let Some(head) = &mut entry.delta_head {
                head.extend_from_slice(self.scratch.get(..made.min(20)).unwrap_or_default());
                if let Some(target) = delta_target(head) {
                    built = Some(target);
                    entry.delta_head = None;
                } else if head.len() >= 20 {
                    return Err(PackRefused("malformed delta header".into()));
                }
            }
            if let Some(target) = built {
                let max = self.limits.max_object_bytes;
                if target > max {
                    return Err(PackRefused(format!(
                        "delta builds an object of {target} bytes, over the {max} byte object limit"
                    )));
                }
                self.count(target)?;
            }
            let State::Stream(entry) = &mut self.state else {
                return Ok(input);
            };
            match status {
                Status::StreamEnd => {
                    if entry.produced != entry.declared || entry.delta_head.is_some() {
                        return Err(PackRefused(
                            "object inflates to less than its header declares".into(),
                        ));
                    }
                    self.objects_left -= 1;
                    self.state = if self.objects_left == 0 {
                        State::Trailer
                    } else {
                        State::Entry
                    };
                    return Ok(input);
                }
                // Out of input with nothing left to flush, or no progress possible without
                // more: wait for the next piece.
                _ if (input.is_empty() && made < SCRATCH) || (used == 0 && made == 0) => {
                    return Ok(input);
                }
                _ => {}
            }
        }
    }
}

/// The target size of a delta from its first bytes (base size, then target size), once
/// both varints are complete.
fn delta_target(head: &[u8]) -> Option<u64> {
    let mut at = 0;
    let mut sizes = [0u64; 2];
    for size in &mut sizes {
        let mut shift = 0u32;
        loop {
            let b = *head.get(at)?;
            at += 1;
            if shift > 63 {
                return None;
            }
            *size |= u64::from(b & 0x7f) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    let [_, target] = sizes;
    Some(target)
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        z.write_all(data).unwrap();
        z.finish().unwrap()
    }

    fn entry_head(kind: u8, size: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut byte = (kind << 4) | (size & 0x0f) as u8;
        let mut rest = size >> 4;
        while rest != 0 {
            out.push(byte | 0x80);
            byte = (rest & 0x7f) as u8;
            rest >>= 7;
        }
        out.push(byte);
        out
    }

    fn varint(mut n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let b = (n & 0x7f) as u8;
            n >>= 7;
            if n == 0 {
                out.push(b);
                return out;
            }
            out.push(b | 0x80);
        }
    }

    fn pack(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out = b"PACK".to_vec();
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&u32::try_from(entries.len()).unwrap().to_be_bytes());
        for e in entries {
            out.extend_from_slice(e);
        }
        out.extend_from_slice(&[0u8; 20]);
        out
    }

    fn blob(data: &[u8]) -> Vec<u8> {
        let mut e = entry_head(3, data.len() as u64);
        e.extend(deflate(data));
        e
    }

    fn ref_delta(target: u64, body: &[u8]) -> Vec<u8> {
        let mut delta = varint(10);
        delta.extend(varint(target));
        delta.extend_from_slice(body);
        let mut e = entry_head(OBJ_REF_DELTA, delta.len() as u64);
        e.extend_from_slice(&[7u8; 20]);
        e.extend(deflate(&delta));
        e
    }

    const LIMITS: PackLimits = PackLimits {
        max_object_bytes: 1024 * 1024,
        max_inflated_bytes: 4 * 1024 * 1024,
    };

    fn check(bytes: &[u8], piece: usize) -> Result<u64, PackRefused> {
        let mut guard = PackGuard::new(LIMITS, 20);
        for chunk in bytes.chunks(piece) {
            guard.feed(chunk)?;
        }
        guard.finish()?;
        Ok(guard.inflated())
    }

    #[test]
    fn an_ordinary_pack_passes_whatever_the_pieces() {
        let p = pack(&[
            blob(b"hello\n"),
            blob(&vec![7u8; 300_000]),
            ref_delta(500, b"x"),
        ]);
        for piece in [1, 3, 17, 4096, p.len()] {
            assert_eq!(check(&p, piece).unwrap(), 6 + 300_000 + 500);
        }
    }

    #[test]
    fn a_declared_bomb_is_refused_before_it_inflates() {
        let mut e = entry_head(3, 512 * 1024 * 1024);
        e.extend(deflate(b"tiny"));
        let err = check(&pack(&[e]), 4096).unwrap_err();
        assert!(err.0.contains("over the"), "{err}");
    }

    #[test]
    fn a_stream_inflating_past_its_header_is_refused() {
        let mut e = entry_head(3, 10);
        e.extend(deflate(&vec![0u8; 100_000]));
        let err = check(&pack(&[e]), 4096).unwrap_err();
        assert!(err.0.contains("past the size"), "{err}");
    }

    #[test]
    fn a_delta_building_too_much_is_refused() {
        let err = check(&pack(&[ref_delta(512 * 1024 * 1024, b"x")]), 4096).unwrap_err();
        assert!(err.0.contains("delta builds"), "{err}");
    }

    #[test]
    fn many_small_deltas_are_held_to_the_pack_total() {
        let deltas: Vec<_> = (0..8).map(|_| ref_delta(1024 * 1024, b"x")).collect();
        let err = check(&pack(&deltas), 4096).unwrap_err();
        assert!(err.0.contains("pack inflates past"), "{err}");
    }

    #[test]
    fn a_truncated_pack_is_refused() {
        let p = pack(&[blob(&vec![1u8; 50_000])]);
        let cut = p.get(..p.len() / 2).unwrap();
        assert!(check(cut, 4096).is_err());
    }
}
