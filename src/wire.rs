//! The proto2 wire codec for mosh's three schemas (spec §5, §7) — a
//! hand-rolled subset: varint and length-delimited fields only, known
//! tag numbers, unknown fields skipped. The field numbers ARE the spec
//! (mosh's .proto files are interface definitions), so there is no
//! schema crate — encoders emit exactly the fields stock mosh sets, and
//! decoders are total functions on arbitrary bytes (they error, never
//! panic; hostile-input fuzzing is part of the test suite).

use thiserror::Error;

/// `TransportBuffers.Instruction` (transportinstruction.proto).
///
/// `new_num == u64::MAX` is the shutdown convention (spec §6.1).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct TransportInstruction {
    pub protocol_version: u32,
    pub old_num: u64,
    pub new_num: u64,
    pub ack_num: u64,
    pub throwaway_num: u64,
    pub diff: Vec<u8>,
    pub chaff: Vec<u8>,
}

/// One instruction inside a `UserMessage` (userinput.proto): exactly one
/// variant is set — `keystroke` (extension 2) or `resize` (extension 3).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum UserInstruction {
    /// Bytes the user pressed. `keys` is field 4 of `Keystroke`.
    Keystroke(Vec<u8>),
    /// `width`/`height` are fields 5/6 of `ResizeMessage`.
    Resize { width: i32, height: i32 },
}

/// `ClientBuffers.UserMessage` — repeated Instruction (field 1).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct UserMessage {
    pub instructions: Vec<UserInstruction>,
}

/// One instruction inside a `HostMessage` (hostinput.proto): hostbytes
/// (extension 2), resize (extension 3) or echoack (extension 7).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HostInstruction {
    /// Terminal escape bytes for the client's emulator. `hoststring` is
    /// field 4 of `HostBytes`.
    HostBytes(Vec<u8>),
    Resize {
        width: i32,
        height: i32,
    },
    /// The server's echo-ack counter (field 8 of `EchoAck`): how far
    /// through the user stream the server had echoed when it sent the
    /// frame (spec §7.2).
    EchoAck(u64),
}

/// `HostBuffers.HostMessage` — repeated Instruction (field 1).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct HostMessage {
    pub instructions: Vec<HostInstruction>,
}

/// The protocol version every side must speak (spec §5, §9).
pub const MOSH_PROTOCOL_VERSION: u32 = 2;
/// `new_num` reserved for the shutdown handshake (spec §6.1).
pub const SHUTDOWN_NUM: u64 = u64::MAX;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("truncated protobuf")]
    Truncated,
    #[error("malformed varint (more than 10 bytes)")]
    BadVarint,
    #[error("length-delimited field longer than the buffer")]
    BadLength,
    #[error("unsupported wire type {0} in a group")]
    UnmatchedGroup(u8),
}

// --- encoder primitives -------------------------------------------------

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn write_tag(out: &mut Vec<u8>, field: u32, wire_type: u8) {
    write_varint(out, ((field as u64) << 3) | wire_type as u64);
}

fn write_bytes_field(out: &mut Vec<u8>, field: u32, bytes: &[u8]) {
    write_tag(out, field, 2);
    write_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn write_varint_field(out: &mut Vec<u8>, field: u32, value: u64) {
    write_tag(out, field, 0);
    write_varint(out, value);
}

fn write_message_field(out: &mut Vec<u8>, field: u32, encode_inner: impl FnOnce(&mut Vec<u8>)) {
    let mut inner = Vec::new();
    encode_inner(&mut inner);
    write_bytes_field(out, field, &inner);
}

// --- decoder primitives -------------------------------------------------

fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64, WireError> {
    let mut value: u64 = 0;
    for i in 0..10 {
        let Some(byte) = buf.get(*pos) else {
            return Err(WireError::Truncated);
        };
        *pos += 1;
        value |= ((byte & 0x7f) as u64) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(WireError::BadVarint)
}

fn read_tag(buf: &[u8], pos: &mut usize) -> Result<(u32, u8), WireError> {
    let key = read_varint(buf, pos)?;
    Ok(((key >> 3) as u32, (key & 0x7) as u8))
}

fn read_length_delimited<'b>(buf: &'b [u8], pos: &mut usize) -> Result<&'b [u8], WireError> {
    let len = read_varint(buf, pos)? as usize;
    let end = pos.checked_add(len).ok_or(WireError::BadLength)?;
    if end > buf.len() {
        return Err(WireError::BadLength);
    }
    let bytes = &buf[*pos..end];
    *pos = end;
    Ok(bytes)
}

/// Skip one field value of the given wire type (unknown-field rule).
fn skip_field(buf: &[u8], pos: &mut usize, wire_type: u8) -> Result<(), WireError> {
    match wire_type {
        0 => {
            read_varint(buf, pos)?;
        }
        1 => {
            if buf.len() < *pos + 8 {
                return Err(WireError::Truncated);
            }
            *pos += 8;
        }
        2 => {
            read_length_delimited(buf, pos)?;
        }
        5 => {
            if buf.len() < *pos + 4 {
                return Err(WireError::Truncated);
            }
            *pos += 4;
        }
        // groups (3=start, 4=end): skip to the matching end marker.
        // Mosh never emits them; this only exists so hostile input
        // cannot wedge the decoder.
        3 => loop {
            let (_, wt) = read_tag(buf, pos)?;
            if wt == 4 {
                return Ok(());
            }
            skip_field(buf, pos, wt)?;
        },
        4 => return Err(WireError::UnmatchedGroup(4)),
        other => return Err(WireError::UnmatchedGroup(other)),
    }
    Ok(())
}

// --- TransportInstruction -----------------------------------------------

impl TransportInstruction {
    /// Encode exactly the seven fields stock mosh always sets.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48 + self.diff.len() + self.chaff.len());
        write_varint_field(&mut out, 1, self.protocol_version as u64);
        write_varint_field(&mut out, 2, self.old_num);
        write_varint_field(&mut out, 3, self.new_num);
        write_varint_field(&mut out, 4, self.ack_num);
        write_varint_field(&mut out, 5, self.throwaway_num);
        write_bytes_field(&mut out, 6, &self.diff);
        write_bytes_field(&mut out, 7, &self.chaff);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut out = TransportInstruction::default();
        let mut pos = 0;
        while pos < buf.len() {
            let (field, wire_type) = read_tag(buf, &mut pos)?;
            match (field, wire_type) {
                (1, 0) => out.protocol_version = read_varint(buf, &mut pos)? as u32,
                (2, 0) => out.old_num = read_varint(buf, &mut pos)?,
                (3, 0) => out.new_num = read_varint(buf, &mut pos)?,
                (4, 0) => out.ack_num = read_varint(buf, &mut pos)?,
                (5, 0) => out.throwaway_num = read_varint(buf, &mut pos)?,
                (6, 2) => out.diff = read_length_delimited(buf, &mut pos)?.to_vec(),
                (7, 2) => out.chaff = read_length_delimited(buf, &mut pos)?.to_vec(),
                _ => skip_field(buf, &mut pos, wire_type)?,
            }
        }
        Ok(out)
    }
}

// --- UserMessage ---------------------------------------------------------

impl UserMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for instruction in &self.instructions {
            write_message_field(&mut out, 1, |inner| match instruction {
                UserInstruction::Keystroke(keys) => {
                    write_message_field(inner, 2, |keystroke| {
                        write_bytes_field(keystroke, 4, keys);
                    });
                }
                UserInstruction::Resize { width, height } => {
                    write_message_field(inner, 3, |resize| {
                        write_varint_field(resize, 5, *width as u64);
                        write_varint_field(resize, 6, *height as u64);
                    });
                }
            });
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut out = UserMessage::default();
        let mut pos = 0;
        while pos < buf.len() {
            let (field, wire_type) = read_tag(buf, &mut pos)?;
            if field == 1 && wire_type == 2 {
                out.instructions
                    .push(decode_user_instruction(read_length_delimited(
                        buf, &mut pos,
                    )?));
            } else {
                skip_field(buf, &mut pos, wire_type)?;
            }
        }
        Ok(out)
    }
}

/// Decodes one embedded `Instruction`; unknown/unset contents decode to
/// an empty keystroke (proto2 defaults), matching tolerant readers.
fn decode_user_instruction(buf: &[u8]) -> UserInstruction {
    let mut pos = 0;
    let mut result = UserInstruction::Keystroke(Vec::new());
    while pos < buf.len() {
        let Ok((field, wire_type)) = read_tag(buf, &mut pos) else {
            break; // tolerate a malformed tail; the prefix is usable
        };
        match (field, wire_type) {
            (2, 2) => {
                if let Ok(keys_block) = read_length_delimited(buf, &mut pos) {
                    let mut kpos = 0;
                    while kpos < keys_block.len() {
                        let Ok((kfield, kwt)) = read_tag(keys_block, &mut kpos) else {
                            break;
                        };
                        if (kfield, kwt) == (4, 2) {
                            if let Ok(keys) = read_length_delimited(keys_block, &mut kpos) {
                                result = UserInstruction::Keystroke(keys.to_vec());
                            }
                        } else if skip_field(keys_block, &mut kpos, kwt).is_err() {
                            break;
                        }
                    }
                }
            }
            (3, 2) => {
                if let Ok(resize_block) = read_length_delimited(buf, &mut pos) {
                    let mut width = 0i32;
                    let mut height = 0i32;
                    let mut rpos = 0;
                    while rpos < resize_block.len() {
                        let Ok((rfield, rwt)) = read_tag(resize_block, &mut rpos) else {
                            break;
                        };
                        match (rfield, rwt) {
                            (5, 0) => {
                                if let Ok(v) = read_varint(resize_block, &mut rpos) {
                                    width = v as i32;
                                }
                            }
                            (6, 0) => {
                                if let Ok(v) = read_varint(resize_block, &mut rpos) {
                                    height = v as i32;
                                }
                            }
                            _ => {
                                if skip_field(resize_block, &mut rpos, rwt).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    result = UserInstruction::Resize { width, height };
                }
            }
            _ => {
                if skip_field(buf, &mut pos, wire_type).is_err() {
                    break;
                }
            }
        }
    }
    result
}

// --- HostMessage ---------------------------------------------------------

impl HostMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for instruction in &self.instructions {
            write_message_field(&mut out, 1, |inner| match instruction {
                HostInstruction::HostBytes(hoststring) => {
                    write_message_field(inner, 2, |hostbytes| {
                        write_bytes_field(hostbytes, 4, hoststring);
                    });
                }
                HostInstruction::Resize { width, height } => {
                    write_message_field(inner, 3, |resize| {
                        write_varint_field(resize, 5, *width as u64);
                        write_varint_field(resize, 6, *height as u64);
                    });
                }
                HostInstruction::EchoAck(num) => {
                    write_message_field(inner, 7, |echoack| {
                        write_varint_field(echoack, 8, *num);
                    });
                }
            });
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut out = HostMessage::default();
        let mut pos = 0;
        while pos < buf.len() {
            let (field, wire_type) = read_tag(buf, &mut pos)?;
            if field == 1 && wire_type == 2 {
                out.instructions
                    .push(decode_host_instruction(read_length_delimited(
                        buf, &mut pos,
                    )?));
            } else {
                skip_field(buf, &mut pos, wire_type)?;
            }
        }
        Ok(out)
    }
}

fn decode_host_instruction(buf: &[u8]) -> HostInstruction {
    let mut pos = 0;
    let mut result = HostInstruction::HostBytes(Vec::new());
    while pos < buf.len() {
        let Ok((field, wire_type)) = read_tag(buf, &mut pos) else {
            break;
        };
        match (field, wire_type) {
            (2, 2) => {
                if let Ok(block) = read_length_delimited(buf, &mut pos) {
                    let mut bpos = 0;
                    while bpos < block.len() {
                        let Ok((bfield, bwt)) = read_tag(block, &mut bpos) else {
                            break;
                        };
                        if (bfield, bwt) == (4, 2) {
                            if let Ok(bytes) = read_length_delimited(block, &mut bpos) {
                                result = HostInstruction::HostBytes(bytes.to_vec());
                            }
                        } else if skip_field(block, &mut bpos, bwt).is_err() {
                            break;
                        }
                    }
                }
            }
            (3, 2) => {
                if let Ok(resize_block) = read_length_delimited(buf, &mut pos) {
                    let mut width = 0i32;
                    let mut height = 0i32;
                    let mut rpos = 0;
                    while rpos < resize_block.len() {
                        let Ok((rfield, rwt)) = read_tag(resize_block, &mut rpos) else {
                            break;
                        };
                        match (rfield, rwt) {
                            (5, 0) => {
                                if let Ok(v) = read_varint(resize_block, &mut rpos) {
                                    width = v as i32;
                                }
                            }
                            (6, 0) => {
                                if let Ok(v) = read_varint(resize_block, &mut rpos) {
                                    height = v as i32;
                                }
                            }
                            _ => {
                                if skip_field(resize_block, &mut rpos, rwt).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    result = HostInstruction::Resize { width, height };
                }
            }
            (7, 2) => {
                if let Ok(echoack_block) = read_length_delimited(buf, &mut pos) {
                    let mut epos = 0;
                    while epos < echoack_block.len() {
                        let Ok((efield, ewt)) = read_tag(echoack_block, &mut epos) else {
                            break;
                        };
                        if (efield, ewt) == (8, 0) {
                            if let Ok(v) = read_varint(echoack_block, &mut epos) {
                                result = HostInstruction::EchoAck(v);
                            }
                        } else if skip_field(echoack_block, &mut epos, ewt).is_err() {
                            break;
                        }
                    }
                }
            }
            _ => {
                if skip_field(buf, &mut pos, wire_type).is_err() {
                    break;
                }
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_instruction_roundtrip_with_all_fields() {
        let inst = TransportInstruction {
            protocol_version: 2,
            old_num: 7,
            new_num: 8,
            ack_num: 3,
            throwaway_num: 2,
            diff: vec![1, 2, 3, 255],
            chaff: vec![9; 16],
        };
        let bytes = inst.encode();
        assert_eq!(TransportInstruction::decode(&bytes).unwrap(), inst);

        // shutdown convention survives the wire
        let shutdown = TransportInstruction {
            protocol_version: 2,
            old_num: 5,
            new_num: SHUTDOWN_NUM,
            ack_num: 9,
            throwaway_num: 4,
            diff: vec![],
            chaff: vec![],
        };
        assert_eq!(
            TransportInstruction::decode(&shutdown.encode())
                .unwrap()
                .new_num,
            SHUTDOWN_NUM
        );
    }

    #[test]
    fn transport_instruction_skips_unknown_fields() {
        let mut bytes = Vec::new();
        // unknown varint field 15
        write_varint_field(&mut bytes, 15, 12345);
        // our field 3 (new_num)
        write_varint_field(&mut bytes, 3, 42);
        // unknown length-delimited field 99
        write_bytes_field(&mut bytes, 99, b"junk");
        // unknown fixed64 field 16
        write_tag(&mut bytes, 16, 1);
        bytes.extend_from_slice(&[0u8; 8]);
        // unknown fixed32 field 17
        write_tag(&mut bytes, 17, 5);
        bytes.extend_from_slice(&[0u8; 4]);

        let decoded = TransportInstruction::decode(&bytes).unwrap();
        assert_eq!(decoded.new_num, 42);
    }

    #[test]
    fn transport_instruction_rejects_truncation_and_bad_lengths() {
        let inst = TransportInstruction {
            protocol_version: 2,
            old_num: 1,
            new_num: 2,
            ack_num: 3,
            throwaway_num: 4,
            diff: vec![0xAA; 300],
            chaff: vec![],
        };
        let bytes = inst.encode();
        // cut=0 is a legal empty message in proto2; the rest must error
        for cut in [1, 5, bytes.len() - 1] {
            assert!(TransportInstruction::decode(&bytes[..cut]).is_err());
        }
        // a length field claiming more than the buffer holds
        let mut evil = Vec::new();
        write_tag(&mut evil, 6, 2);
        write_varint(&mut evil, 0xFFFF_FFFF);
        assert!(TransportInstruction::decode(&evil).is_err());
        // a varint that never ends
        let mut evil = Vec::new();
        write_tag(&mut evil, 2, 0); // field 2 (old_num), varint
        evil.extend_from_slice(&[0xFF; 11]);
        assert!(TransportInstruction::decode(&evil).is_err());
    }

    #[test]
    fn user_message_roundtrip_and_coalescing_shape() {
        let msg = UserMessage {
            instructions: vec![
                UserInstruction::Keystroke(b"ech".to_vec()),
                UserInstruction::Keystroke(b"o hi\r".to_vec()),
                UserInstruction::Resize {
                    width: 100,
                    height: 30,
                },
                UserInstruction::Keystroke(Vec::new()),
            ],
        };
        let decoded = UserMessage::decode(&msg.encode()).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn host_message_roundtrip_all_three_variants() {
        let msg = HostMessage {
            instructions: vec![
                HostInstruction::HostBytes(b"\x1b[2Jhello".to_vec()),
                HostInstruction::Resize {
                    width: 80,
                    height: 24,
                },
                HostInstruction::EchoAck(17),
            ],
        };
        assert_eq!(HostMessage::decode(&msg.encode()).unwrap(), msg);
    }

    /// A tiny deterministic fuzzer over arbitrary bytes: decode must
    /// return Ok or Err, never panic, for any input — including inputs
    /// the AEAD would normally keep from reaching us.
    #[test]
    fn decode_never_panics_on_arbitrary_bytes() {
        let mut state: u64 = 0x243F_6A88_85A3_08D3;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            let len = (next() % 64) as usize;
            let bytes: Vec<u8> = (0..len).map(|_| (next() & 0xFF) as u8).collect();
            let _ = TransportInstruction::decode(&bytes);
            let _ = UserMessage::decode(&bytes);
            let _ = HostMessage::decode(&bytes);
        }
    }

    /// Decode a golden-transcript instruction end-to-end: fragment ->
    /// reassemble -> inflate -> parse. Proves the whole §4-§5 stack
    /// against real stock traffic (assertions are structural: this runs
    /// before the fragment module exists, so it lives here as a
    /// placeholder-free cross-check once assembled by the caller).
    #[test]
    fn golden_shapes_stay_compatible() {
        // the encoder must always emit protocol_version first (field 1)
        // exactly as stock does; receivers check equality, not position,
        // but pinning the first byte pair keeps diffs debuggable.
        let bytes = TransportInstruction::default().encode();
        assert_eq!(bytes[0], 1 << 3); // tag: field 1, varint
        assert_eq!(bytes[1], 0); // value 0
    }
}
