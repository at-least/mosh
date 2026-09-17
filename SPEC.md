# The mosh wire protocol, as conch implements it

Status: normative for conch's mosh client (read-reference: mobile-shell/mosh at
tag `mosh-1.4.0`; every constant below was read out of that tree and the file
it came from is named inline). Target server: `MOSH_PROTOCOL_VERSION = 2`.
The byte-stream model and all three proto schemas below have been byte-check-
against the `mosh-1.3.2` tag too — identical field numbers — so every
mosh-server since 1.3.2 (2017), including Ubuntu 20.04's, speaks this
protocol. The ancient pre-byte-stream cell-state model predates these proto
files entirely and is unreachable in practice; the `protocol_version` check
(§5) is what rejects an incompatible peer (§9).

conch implements the **client** side only. The client's job, bottom to top:

1. SSH-exec `mosh-server new` and parse `MOSH CONNECT` (§1)
2. AES-128-OCB3 datagram crypto (§2, RFC 7253)
3. Packet framing with timestamps and replay protection (§3)
4. Fragmentation + zlib (§4)
5. `TransportBuffers.Instruction` protobuf (§5)
6. State-synchronization protocol over all of the above (§6)
7. The two synchronized states: `UserStream` out, host `Complete` in (§7)
8. Session semantics: heartbeat, shutdown handshake, roaming (§8)

## 1. SSH bootstrap

The stock `mosh` wrapper (scripts/mosh.pl) execs over SSH:

```
sh -c '[ -n "$SSH_CONNECTION" ] && printf "\nMOSH SSH_CONNECTION %s\n" "$SSH_CONNECTION"' ; \
mosh-server new -c 256 -s [-p PORT] -l NAME=VALUE... [-- COMMAND...]
```

- `-c 256` — colors (conch terminals are 256-color).
- `-s` — mosh-server binds its UDP socket to the server-side IP of its **own**
  `$SSH_CONNECTION` environment (mosh-server.cc `get_SSH_IP()`), which sshd
  sets on the exec channel. Separately, the probe's `MOSH SSH_CONNECTION
  <cip> <cport> <sip> <sport>` line (word 4) tells the **client** which IP to
  send UDP to — the right answer on multihomed servers, where the SSH
  hostname is not necessarily the routable UDP target. conch parses the probe
  line and uses word 4 as the UDP destination.
- `-l LANG=<utf8-locale>` — one `-l` per locale variable present in the
  client environment (mosh.pl passes LANG, LANGUAGE, LC_*). mosh-server
  refuses to run without a UTF-8 locale (`mosh-server needs a UTF-8 native
  locale to run.` on stderr). conch passes `-l LANG=C.UTF-8` when the app
  provides no better locale.
- `-- COMMAND` — the payload; `mosh-server new -l ... -- tmux new-session
  -A -s conch` is how conch composes mosh with its tmux auto-attach.
- No `-p` by default: the server scans for a free UDP port itself (§8).
  `-p` is a single port or `LOW:HIGH` range.

**`MOSH CONNECT <port> <key>`** (stdout, then the parent process exits):

- mosh-server prints `MOSH CONNECT %s %s\n` (port, 22-char key) on stdout,
  then `fork()`s; the parent prints a banner and `[mosh-server detached,
  pid = N]` to **stderr** and `exit(0)`s — so the SSH exec channel closes
  promptly after the line appears (mosh-server.cc:441-478). No read-until-
  line-with-timeout is needed; a plain exec that also collects stderr
  suffices. Every failure message (bad locale, bind failure, `mosh-server:
  command not found` from the shell) lands on stderr.
- Wrapper parsing (mosh.pl:429-433), conch matches it:
  `^MOSH CONNECT (\d+?) ([A-Za-z0-9/+]{22})\s*$` — any other line is
  informational and must be shown/surfaced, not fatal, until the channel
  closes without a CONNECT line ("Did not find mosh server startup
  message").

The SSH session itself stays open after bootstrap (conch keeps tunnels and
SOCKS alive); mosh-server ignores the dying channel anyway (SIGHUP ignored
before the fork).

## 2. Crypto (per datagram)

Source of truth: RFC 7253 (OCB3) + mosh crypto.cc.

- **Key**: 16 random bytes. Printable form: standard-alphabet base64
  (`A-Za-z0-9+/`), 22 chars (the 24-char encoding without its `==` padding).
  Parsing appends `==` and must verify round-trip (crypto.cc:110-131).
- **Nonce** (12 bytes): `00 00 00 00 || u64_be(value)` (crypto.cc:175-198).
  The wire carries only the last 8 bytes; the receiver re-prefixes the zeros.
- **Direction**: bit 63 of the nonce value — `0` = client→server,
  `1` = server→client (network.cc:66-67). The low 63 bits are the packet
  sequence number, assigned from a monotonic process-local counter starting
  at 0, one per datagram sent (crypto.cc `unique()`, network.h Packet ctor).
  Both sides use the same key; the direction bit is what keeps nonces from
  colliding.
- **Datagram layout**: `nonce_suffix(8) || OCB3 ciphertext || tag(16)`.
  Plaintext is §3's packet. No AAD. Minimum datagram length 24 bytes;
  shorter is a decode error (crypto.cc:250-253).
- **Limits**: mosh aborts a session after 2^47 encrypted blocks per key
  (≈2 PB; crypto.cc:241-243 — 2^48 blocks is the RFC's per-key adversary
  ceiling and both directions share this key, hence 2^47). conch mirrors
  the check. Decryption failure (tag mismatch) drops the datagram — it is
  never fatal to the session.
- OCB3 itself comes from RustCrypto's `ocb3` crate (RFC 7253, the same
  RustCrypto trust family as the already-pinned `aes`/`aes-gcm`), exact-
  pinned like every conch dependency. The RFC's official vectors and the
  golden transcript (§10) are the acceptance oracles either way.

## 3. Packet layer

Source: network.cc `Packet::Packet(Message)` / `toMessage` (lines 69-97).

Plaintext after decryption:

```
u16_be timestamp         -- ms since local monotonic epoch, 0xFFFF = "none"
u16_be timestamp_reply   -- the other side's saved timestamp, corrected
bytes  fragment payload  -- §4
```

- **timestamp16()**: `ms % 65536`, and 0xFFFF maps to 0 (never send -1).
- Every outgoing packet stamps `timestamp`. A received packet's timestamp
  is saved **only if its seq ≥ expected_receiver_seq** (the replay gate),
  and is echoed in the next outgoing `timestamp_reply` — advanced by how
  long we held it — only if it is still less than 1000 ms old; the echo is
  one-shot (saved state cleared after use) (network.cc:99-115, 521-524).
- **RTT**: on receiving a `timestamp_reply` ≠ 0xFFFF, compute
  `R = timestamp_diff(timestamp16(), timestamp_reply)` (mod-2^16) and update
  `RTTVAR = (1-1/4)·RTTVAR + 1/4·|SRTT-R|`, `SRTT = (1-1/8)·SRTT + 1/8·R`
  (first sample: SRTT=R, RTTVAR=R/2), ignoring R ≥ 5000 ms
  (network.cc:535-552). `RTO = SRTT + 4·RTTVAR` clamped to [50, 1000] ms.
- **Replay / reflection protection**: decrypt yields direction + seq.
  Stock mosh `dos_assert`s on a wrong direction (process abort); conch
  deliberately drops the datagram instead — a hardening difference. The
  seq gate: `expected_receiver_seq` only advances forward; packets with
  `seq < expected_receiver_seq` are still delivered but excluded from
  timestamp/RTT/targeting updates (network.cc:513-519). Sequence numbers
  are u63 (direction bit stripped).
- Initial SRTT/RTTVAR: 1000/500 ms (network.cc constructors).
- ECN: mosh sets IP_TOS 0x02 and honors CE by penalizing the echoed
  timestamp by 500 ms (network.cc:521-533). conch skips ECN (no socket
  option, no penalty) — legal; CE handling is an optimization.
- Timestamps are only ever compared within a side's local monotonic clock
  (CLOCK_MONOTONIC_RAW on Apple); the u16 wraps and all uses are mod-2^16
  diffs (timestamp_diff, network.cc:610-621).

## 4. Fragmentation + zlib

Source: transportfragment.cc.

The §3 payload bytes are a **fragment**:

```
u64_be id               -- instruction id (see bump rule below)
u16_be flags_num        -- bit 15: final fragment; bits 0-14: fragment index
bytes   contents        -- a slice of the zlib-compressed Instruction
```

- **MTU accounting** (transportsender-impl.h:336-338): fragments are cut to
  `MTU − Connection::ADDED_BYTES(12) − Crypto::Session::ADDED_BYTES(16)`
  where the 12 = 8 nonce + 4 timestamps and the 16 = OCB tag, and MTU =
  1280 − (20+8) for IPv4 / 1280 − (40+16+8) for IPv6 (network.h:108-131),
  minus the 10-byte fragment header inside `make_fragments`. A datagram
  that hits EMSGSIZE drops the connection MTU to 500 (network.cc:412-414).
- **Framing** (make_fragments, transportfragment.cc:157-199): the
  serialized `Instruction` is zlib-compressed whole (`compress()`:
  zlib header + adler32, default level — flate2 `ZlibEncoder` equivalent),
  then sliced into ≤MTU fragments; the last carries the final bit.
- **Instruction-id bump rule**: the id increments only when
  `old_num`, `new_num`, `ack_num`, `throwaway_num`, `chaff`, or
  `protocol_version` changed since the last send (or the MTU changed).
  Re-transmitting the identical instruction reuses the id — that is how
  the receiver dedupes retransmitted fragments.
- **Reassembly** (FragmentAssembly): fragments for a new id reset the
  buffer; duplicates must be byte-identical; total is learned from the
  final fragment; completion concatenates contents **in index order**,
  zlib-decompresses, and parses an `Instruction`. Decompression of
  untrusted input must be capped (mosh uses a fixed 4 MiB buffer —
  `2048*2048`, compressor.h:41 — and asserts; conch errors instead of
  aborting).

## 5. `TransportBuffers.Instruction` (proto2)

Verbatim from src/protobufs/transportinstruction.proto:

```proto
message Instruction {
  optional uint32 protocol_version = 1;  // must equal 2 on both sides
  optional uint64 old_num = 2;
  optional uint64 new_num = 3;
  optional uint64 ack_num = 4;
  optional uint64 throwaway_num = 5;
  optional bytes  diff = 6;
  optional bytes  chaff = 7;
}
```

Unknown fields are skipped (standard proto2). `chaff` is random padding —
generated 0-16 bytes per send by stock mosh, semantically ignored by the
receiver except that a change re-ids the instruction (§4).

## 6. State synchronization (SSP)

Source: transportsender-impl.h + networktransport-impl.h. Each side keeps:

- `current_state` — its own newest state (client: §7.1 UserStream).
- `sent_states` — a list of `{timestamp, num, state}` it has sent;
  `num` counts states, 0 = initial empty state. Capped at 32 entries
  (drop from the middle, keeping both ends — transportsender-impl.h:228-236).
- `assumed_receiver_state` — newest sent state the peer probably has.
- On the receive side: `received_states` (capped at 1024, §6.3).

### 6.1 Sending (tick / send path)

- `send_interval` = clamp(ceil(SRTT/2), 20, 250) ms — aim for ~2 frames
  per RTT. The client sets its minimum send delay to 1 ms
  (`set_send_delay(1)`, stmclient.cc:257) for snappy keystrokes.
- `next_send_time` logic (calculate_timers): if `current_state` changed →
  send after `mindelay_clock + SEND_MINDELAY` (client: 1 ms) but not more
  often than `send_interval`; else if it differs from the *assumed* receiver
  state and the peer was heard from within ACTIVE_RETRY_TIMEOUT (10 s) →
  resend at `send_interval` cadence; else if it differs even from the
  *known* receiver state (`sent_states.front()`) and the peer was heard
  from → resend at `RTO + ACK_DELAY` cadence; otherwise nothing to send.
- `next_ack_time`: empty acks every ACK_INTERVAL (3000 ms); a data-carrying
  receive schedules a delayed ack within ACK_DELAY (100 ms).
- A send emits `Instruction{protocol_version:2, old_num:
  assumed_receiver_state.num, new_num, ack_num, throwaway_num:
  sent_states.front().num, diff: current.diff_from(assumed), chaff}` —
  fragmented per §4, one datagram per fragment.
- **Shutdown special-case**: while shutting down, `new_num = u64::MAX`
  (0xFFFF…FF) on every send; each such send counts toward SHUTDOWN_RETRIES
  (16).
- **Prospective resend optimization**: if diffing against the *known*
  receiver state (`sent_states.front()`) is not bigger than the assumed
  diff (+100 bytes slack under 1000), resend from the known state instead
  (transportsender-impl.h:407-425). Optional to implement; it's a
  bandwidth optimization, not a correctness requirement.
- **rationalize/subtract**: states may be shrunk by dropping the common
  prefix everyone has acked (`state.subtract(front)`); for the client's
  UserStream subtract pops acked prefix events.

### 6.2 Receiving an Instruction

networktransport-impl.h:70-167, in order:

1. `protocol_version != 2` → protocol error (session-fatal).
2. `ack_num` → `process_acknowledgment_through`: drop `sent_states` with
   `num < ack_num` (ignored entirely if `ack_num` names a state we no
   longer hold). Feeds round-trip-success for roaming (§8).
3. If `new_num` already in `received_states` → done (idempotent).
4. If `old_num` not in `received_states` → **drop** (state we discarded or
   never had; security-sensitive idempotency).
5. `throwaway_num` → drop `received_states` with `num < throwaway_num`.
6. Queue cap: once `received_states` exceeds 1024 entries, one new state
   is admitted per 15 s window and the rest dropped
   (receiver_quench_timer, networktransport-impl.h:120-131).
7. Apply `diff` to the found `old_num` state → insert result sorted by
   `num`. **Only the append path** (newest state) updates our outbound
   `ack_num`, marks the peer heard and notes a data ack; an out-of-order
   insert returns immediately after inserting
   (networktransport-impl.h:143-165).

## 7. The two states

### 7.1 Client → server: `ClientBuffers.UserStream`

A pure append-only event log. Events: user bytes and resizes.
Wire form (proto2, src/protobufs/userinput.proto):

```proto
message UserMessage { repeated Instruction instruction = 1; }
message Instruction { extensions 2 to max; }  // keystroke=2, resize=3
message Keystroke { optional bytes keys = 4; }
message ResizeMessage { optional int32 width = 5; optional int32 height = 6; }
```

- `diff_from` (user.cc:61-106): the not-yet-known suffix; **consecutive
  user bytes coalesce into one Keystroke instruction's `keys`**; each
  Resize gets its own instruction. `subtract` pops the acked prefix.
- Client sends an initial `Resize(cols, rows)` immediately after connect
  (stmclient.cc:260) — the server's emulator starts at 80×24 and this is
  how it learns the real size.

### 7.2 Server → client: host `Complete`

The server's synchronized state = its terminal emulator + an echo-ack
counter. Wire form (proto2, src/protobufs/hostinput.proto):

```proto
message HostMessage { repeated Instruction instruction = 1; }
message Instruction { extensions 2 to max; }  // hostbytes=2, resize=3, echoack=7
message HostBytes   { optional bytes hoststring = 4; }
message ResizeMessage { optional int32 width = 5; optional int32 height = 6; }
message EchoAck     { optional uint64 echo_ack_num = 8; }
```

- **`hostbytes`**: escape-sequence bytes the client must feed its local
  terminal emulator (the server renders its own frame transitions into
  xterm-ish output — this is the 1.4 model: the client keeps its own
  emulator, so conch feeds these bytes into the same alacritty engine
  the SSH path uses). Server-side resize emits a `resize` instruction
  first, then a repaint in `hostbytes`.
- **`echoack`**: the server's `Complete.echo_ack` — how far through the
  user stream the server had actually *echoed* when it sent the frame,
  used to retire client-side predictions (it lags `ack_num` by up to
  ECHO_TIMEOUT = 50 ms deliberately; see completeterminal.cc:130-160).
  Monotonically non-decreasing.
- The client's copy of the state applies instructions in order:
  hostbytes → emulator; resize → emulator resize; echoack → prediction
  engine.

## 8. Session semantics

- **Ports**: mosh-server binds a UDP port scanning 60001-60999
  (network.h:136-137; the docs round this to "60000-61000"). The client
  binds an ephemeral port and sends to server:port from §1.
- **Heartbeat**: there is no dedicated heartbeat frame — empty acks
  (§6.1, every 3 s) plus retransmits serve as keepalive.
- **Roaming** (client): keep up to 10 bound sockets; when
  `now − last_port_choice > 10 s` **and** `now − last_roundtrip_success >
  10 s`, open a new socket and send from it (network.cc:117-149, 423-428).
  The server re-targets its replies to whatever source an authenticated
  datagram last came from (network.cc:558-572). Old sockets are pruned
  60 s after the last port choice (`MAX_OLD_SOCKET_AGE`, measured from
  `last_port_choice`). `last_roundtrip_success` advances when an ack
  covers a state we sent recently (§6.2 step 2).
- **Server detach**: 40 s without any authenticated datagram and the
  server forgets the client (re-attaches on the next authenticated
  packet) (network.h:139, network.cc:417-422).
- **Shutdown handshake**: the quitting side sends instructions with
  `new_num = u64::MAX` (§6.1). The peer, on seeing new_num = u64::MAX,
  acks it and starts its own shutdown; each side gives up after
  SHUTDOWN_RETRIES (16) tries or ACTIVE_RETRY_TIMEOUT (10 s) of trying,
  after which the session is over regardless. A client that never
  completed the handshake warns that mosh-server may still be running.
- **Connection-death UX**: "still connecting" = no remote state number
  yet (nothing heard); mosh surfaces "Nothing received from server on UDP
  port N" and, on quit without a successful round trip, the canonical
  firewall hint (stmclient.cc:196-225).

## 9. Interop edge cases conch must handle

- **Protocol floor**: `protocol_version` must equal 2 in both directions.
  The byte-stream model and every proto schema here are unchanged since
  mosh 1.3.2 (verified against that tag's proto files), so v2 covers
  every server shipped since 2017 — including distro mosh 1.3.2 (Ubuntu
  20.04). A `protocol_version ≠ 2` instruction ends the session with
  "server mosh is too old (or too new) for this client". The pre-2017
  cell-state protocol predates these proto files entirely; it is not
  separately detectable and does not need to be.
- **Fragment dedup assert**: a retransmitted fragment differing in bytes
  from the one held is a protocol violation — mosh asserts; conch drops
  the fragment (defensive, never abort).
- **Chaff**: 0-16 random bytes on stock sends; decode ignores it. conch
  may send none (empty) — receivers don't care. (Sending none leaks
  slightly more timing metadata; acceptable for v1.)
- **Diff empty vs state change**: an instruction may carry `new_num >
  old_num` with an empty diff (empty ack); also `new_num == old_num` is
  legal (pure retransmit marker).
- **u64::MAX = 0xFFFF…FF** is reserved as the shutdown new_num; real
  state numbers never reach it.

## 10. Golden transcript

`tests/fixtures/mosh/` (this repo's test tree) holds a recorded session:

- `transcript.json` — every datagram both directions (dir, epoch-ms,
  hex payload) plus `client_log_hex` (what the stock client itself
  rendered), captured through a recording UDP proxy between stock
  mosh-client 1.4.0 and mosh-server 1.4.0 on localhost, driven by an
  expect-like pty script (typed `echo` line, resize, clean Ctrl-^. quit).
- `key.txt` — the 22-char session key printed by `MOSH CONNECT`.

Regenerate with conch's
`shared/conch-core/scripts/capture-mosh-transcript.py` (needs
`brew install mosh`; never a build dependency — the fixture is
committed). Decode-path
tests replay the datagrams through conch's crypto/wire/SSP stack and
assert the emulator converges on the same screen the stock client showed.
