//! Fragment framing + zlib (spec §4): instructions are serialized with
//! [`crate::wire`], zlib-compressed whole, and sliced into
//! `u64_be id || u16_be(final<<15 | index) || contents` fragments sized
//! to the connection MTU. Reassembly deduplicates retransmissions and
//! tolerates arbitrary arrival order; the instruction id advances only
//! when a header field (or the MTU) changed, which is what makes a
//! retransmission recognizable as the same instruction.

use std::io::Read;

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use thiserror::Error;

use super::wire::TransportInstruction;

/// `u64_be id + u16_be flags/index`.
pub const FRAG_HEADER_LEN: usize = 10;
/// mosh's decompress buffer (`2048 * 2048`, compressor.h:41) — anything
/// inflating past this is a protocol error, not an abort.
pub const DECOMPRESS_LIMIT: usize = 4 * 1024 * 1024;
/// Reassembly cap (defense beyond mosh: a hostile sender could deliver
/// 32k fragments; legitimate diffs are kilobytes).
const ASSEMBLY_LIMIT: usize = 8 * 1024 * 1024;
/// The wire fragment index carries 15 bits.
const MAX_FRAGMENT_INDEX: u16 = 0x7FFF;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FragmentError {
    #[error("fragment shorter than its 10-byte header")]
    TooShort,
    #[error("reassembled payload over the size cap")]
    AssemblyTooLarge,
    #[error("fragment index beyond the 15-bit wire limit")]
    IndexTooLarge,
    #[error("compressed stream failed to inflate: {0}")]
    Inflate(String),
    #[error("inflated instruction failed to parse: {0}")]
    Parse(String),
}

/// One wire fragment (spec §4).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Fragment {
    pub id: u64,
    pub fragment_num: u16,
    pub final_: bool,
    pub contents: Vec<u8>,
}

impl Fragment {
    pub fn tostring(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAG_HEADER_LEN + self.contents.len());
        out.extend_from_slice(&self.id.to_be_bytes());
        let flags = ((self.final_ as u16) << 15) | self.fragment_num;
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&self.contents);
        out
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, FragmentError> {
        if bytes.len() < FRAG_HEADER_LEN {
            return Err(FragmentError::TooShort);
        }
        let id = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        let flags = u16::from_be_bytes(bytes[8..10].try_into().unwrap());
        Ok(Fragment {
            id,
            final_: flags & 0x8000 != 0,
            fragment_num: flags & 0x7FFF,
            contents: bytes[FRAG_HEADER_LEN..].to_vec(),
        })
    }
}

fn zlib_compress(input: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input).expect("Vec write cannot fail");
    encoder.finish().expect("Vec write cannot fail")
}

fn zlib_decompress(input: &[u8]) -> Result<Vec<u8>, FragmentError> {
    let decoder = ZlibDecoder::new(input);
    let mut out = Vec::new();
    // cap the output: read at most LIMIT+1 so overflow is detectable
    let mut limited = decoder.take((DECOMPRESS_LIMIT + 1) as u64);
    limited
        .read_to_end(&mut out)
        .map_err(|e| FragmentError::Inflate(e.to_string()))?;
    if out.len() > DECOMPRESS_LIMIT {
        return Err(FragmentError::AssemblyTooLarge);
    }
    Ok(out)
}

use std::io::Write;

/// Slices a serialized+zlib'd instruction into MTU-sized fragments and
/// owns the id-bump rule (spec §4): the id advances only when any of
/// `old_num/new_num/ack_num/throwaway_num/chaff/protocol_version` or
/// the MTU changed since the previous send.
pub struct Fragmenter {
    next_instruction_id: u64,
    last_header: Option<(u32, u64, u64, u64, u64, Vec<u8>)>, // (ver, old, new, ack, throw, chaff)
    last_mtu: usize,
}

impl Default for Fragmenter {
    fn default() -> Self {
        Fragmenter {
            next_instruction_id: 0,
            last_header: None,
            last_mtu: usize::MAX,
        }
    }
}

impl Fragmenter {
    pub fn make_fragments(
        &mut self,
        inst: &TransportInstruction,
        mut mtu: usize,
    ) -> Result<Vec<Fragment>, FragmentError> {
        mtu = mtu.saturating_sub(FRAG_HEADER_LEN);

        let header = (
            inst.protocol_version,
            inst.old_num,
            inst.new_num,
            inst.ack_num,
            inst.throwaway_num,
            inst.chaff.clone(),
        );
        if self.last_header.as_ref() != Some(&header) || self.last_mtu != mtu {
            self.next_instruction_id += 1;
        }
        self.last_header = Some(header);
        self.last_mtu = mtu;

        let payload = zlib_compress(&inst.encode());
        let mut fragments = Vec::new();
        let mut rest = payload.as_slice();
        let mut index: u16 = 0;
        loop {
            if index > MAX_FRAGMENT_INDEX {
                return Err(FragmentError::IndexTooLarge);
            }
            let (chunk, final_);
            if rest.len() > mtu {
                chunk = &rest[..mtu];
                final_ = false;
            } else {
                chunk = rest;
                final_ = true;
            }
            fragments.push(Fragment {
                id: self.next_instruction_id,
                fragment_num: index,
                final_,
                contents: chunk.to_vec(),
            });
            index += 1;
            rest = &rest[chunk.len()..];
            if final_ {
                return Ok(fragments);
            }
        }
    }

    /// The last ack we framed (mosh's `last_ack_sent`; S3 uses this to
    /// avoid re-acking an unchanged ack).
    pub fn last_ack_sent(&self) -> Option<u64> {
        self.last_header.as_ref().map(|h| h.3)
    }
}

/// Out-of-order, duplicate-tolerant reassembly of one instruction at a
/// time (spec §4). A new id resets the buffer; a byte-identical
/// duplicate is a no-op; a differing duplicate is dropped (mosh asserts
/// — hardening difference, spec §9).
#[derive(Default)]
pub struct FragmentAssembly {
    fragments: Vec<Option<Fragment>>,
    current_id: u64,
    fragments_arrived: usize,
    fragments_total: Option<usize>,
    assembled_bytes: usize,
}

impl FragmentAssembly {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one fragment; `Some(inst)` when this completed a packet.
    pub fn add_fragment(&mut self, frag: Fragment) -> Option<TransportInstruction> {
        let idx = frag.fragment_num as usize;
        let is_final = frag.final_;
        if self.current_id != frag.id {
            self.fragments.clear();
            self.fragments.resize(idx + 1, None);
            self.fragments_arrived = 1;
            self.fragments_total = None;
            self.assembled_bytes = 0;
            self.current_id = frag.id;
            self.fragments[idx] = Some(frag);
        } else {
            if idx >= self.fragments.len() {
                self.fragments.resize(idx + 1, None);
            }
            match &self.fragments[idx] {
                Some(existing) => {
                    if *existing != frag {
                        // conflicting retransmission: drop (mosh asserts)
                        return None;
                    }
                }
                None => {
                    self.fragments[idx] = Some(frag);
                    self.fragments_arrived += 1;
                }
            }
        }

        if is_final {
            let total = idx + 1;
            if total < self.fragments.len() {
                // truncation can drop already-counted fragments: recount
                // so `arrived` can never equal `total` with a hole
                self.fragments.truncate(total);
                self.fragments_arrived = self.fragments.iter().filter(|f| f.is_some()).count();
            }
            self.fragments_total = Some(total);
        }

        if self.fragments_arrived == self.fragments_total? {
            return self.take_assembly();
        }
        None
    }

    fn take_assembly(&mut self) -> Option<TransportInstruction> {
        let mut encoded = Vec::new();
        let mut complete = true;
        for slot in &self.fragments {
            let Some(frag) = slot.as_ref() else {
                // a hole means counting went wrong (hostile sender):
                // reset so this id cannot wedge the assembly forever
                complete = false;
                break;
            };
            if self.assembled_bytes + frag.contents.len() > ASSEMBLY_LIMIT {
                self.reset();
                return None; // hostile assembly; drop whole instruction
            }
            self.assembled_bytes += frag.contents.len();
            encoded.extend_from_slice(&frag.contents);
        }
        if !complete {
            self.reset();
            return None;
        }
        let inflated = zlib_decompress(&encoded).ok()?;
        let inst = TransportInstruction::decode(&inflated)
            .map_err(|e| FragmentError::Parse(e.to_string()))
            .ok()?;
        self.reset();
        Some(inst)
    }

    fn reset(&mut self) {
        self.fragments.clear();
        self.fragments_arrived = 0;
        self.fragments_total = None;
        self.assembled_bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_instruction(diff: &[u8], ack: u64) -> TransportInstruction {
        TransportInstruction {
            protocol_version: 2,
            old_num: 1,
            new_num: 2,
            ack_num: ack,
            throwaway_num: 0,
            diff: diff.to_vec(),
            chaff: vec![1, 2, 3],
        }
    }

    #[test]
    fn single_fragment_roundtrip() {
        let mut fragmenter = Fragmenter::default();
        let inst = sample_instruction(b"hello diff", 5);
        let fragments = fragmenter.make_fragments(&inst, 1400).unwrap();
        assert_eq!(fragments.len(), 1);
        assert!(fragments[0].final_);
        assert_eq!(fragments[0].fragment_num, 0);
        assert_eq!(fragments[0].id, 1, "first id is 1, not 0");

        let mut assembly = FragmentAssembly::new();
        let parsed = assembly.add_fragment(fragments[0].clone()).unwrap();
        assert_eq!(parsed, inst);
    }

    #[test]
    fn multi_fragment_out_of_order_and_duplicated() {
        let mut fragmenter = Fragmenter::default();
        // incompressible payload: identical bytes would zlib down to one
        // fragment no matter the MTU
        let mut mix: u64 = 0x243F_6A88_85A3_08D3;
        let big_diff: Vec<u8> = (0..5000)
            .map(|_| {
                mix = mix
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (mix >> 56) as u8
            })
            .collect();
        let inst = sample_instruction(&big_diff, 1);
        let fragments = fragmenter.make_fragments(&inst, 200).unwrap();
        assert!(fragments.len() >= 10, "sliced into many fragments");

        let mut assembly = FragmentAssembly::new();
        // reverse order: completion lands on the last-fed fragment (index
        // 0), not on the final-flagged one
        let mut completions = 0;
        for frag in fragments.iter().rev() {
            if let Some(parsed) = assembly.add_fragment(frag.clone()) {
                assert_eq!(parsed, inst);
                completions += 1;
            }
        }
        assert_eq!(completions, 1, "exactly one completion per instruction");
        // a partial duplicate (missing piece 0) never completes; a full
        // duplicate would — completion resets the buffer — which is fine:
        // idempotency across retransmissions is the SSP layer's job
        for frag in &fragments[1..] {
            assert!(assembly.add_fragment(frag.clone()).is_none());
        }
    }

    #[test]
    fn id_bumps_only_on_change() {
        let mut fragmenter = Fragmenter::default();
        let a = sample_instruction(b"x", 1);
        let b = sample_instruction(b"x", 1); // identical -> same id
        let c = sample_instruction(b"x", 2); // ack changed -> new id

        let fa = fragmenter.make_fragments(&a, 1400).unwrap();
        let fb = fragmenter.make_fragments(&b, 1400).unwrap();
        let fc = fragmenter.make_fragments(&c, 1400).unwrap();
        assert_eq!(fa[0].id, fb[0].id, "identical retransmit keeps the id");
        assert_eq!(fc[0].id, fa[0].id + 1);

        // MTU change alone also re-ids
        let fd = fragmenter.make_fragments(&c, 700).unwrap();
        assert_eq!(fd[0].id, fc[0].id + 1);
    }

    #[test]
    fn conflicting_retransmission_is_dropped_not_fatal() {
        let mut fragmenter = Fragmenter::default();
        let inst = sample_instruction(b"payload", 1);
        let frag = fragmenter.make_fragments(&inst, 1400).unwrap().remove(0);

        let mut assembly = FragmentAssembly::new();
        assert!(assembly.add_fragment(frag.clone()).is_some());

        let mut evil = frag.clone();
        evil.contents[0] ^= 0xFF;
        assert!(assembly.add_fragment(evil).is_none());
    }

    #[test]
    fn zlib_roundtrip_and_corruption() {
        let data = b"the quick brown fox".repeat(100);
        let compressed = zlib_compress(&data);
        assert_eq!(zlib_decompress(&compressed).unwrap(), data);

        let mut bad = compressed.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0x40;
        assert!(zlib_decompress(&bad).is_err());
        assert!(zlib_decompress(b"not zlib at all").is_err());
    }

    #[test]
    fn decompression_bomb_is_capped() {
        // highly compressible 40 MiB of zeros inflates past the 4 MiB cap
        let bomb = zlib_compress(&vec![0u8; 40 * 1024 * 1024]);
        assert_eq!(
            zlib_decompress(&bomb).unwrap_err(),
            FragmentError::AssemblyTooLarge
        );
    }

    #[test]
    fn fragment_parse_rejects_short_input() {
        assert_eq!(
            Fragment::parse(&[0u8; 9]).unwrap_err(),
            FragmentError::TooShort
        );
        let frag = Fragment::parse(&[0x01, 0, 0, 0, 0, 0, 0, 2, 0x80, 0x01, 0xAA]).unwrap();
        assert_eq!(frag.id, 0x0100_0000_0000_0002);
        assert!(frag.final_);
        assert_eq!(frag.fragment_num, 1);
        assert_eq!(frag.contents, vec![0xAA]);
    }
}
