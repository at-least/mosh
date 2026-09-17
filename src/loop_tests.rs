//! S2 acceptance: two full SSP endpoints (fragmenter + assembly +
//! sender + receiver) exchanging through a seeded lossy/reordering/
//! duplicating in-memory channel, driven by a manual clock. Everything
//! must converge — typed bytes delivered exactly once, acks trimming
//! the sender queues, and the shutdown handshake completing — with no
//! sockets in sight (those are S3).

use super::fragment::{Fragment, FragmentAssembly, Fragmenter};
use super::ssp::{
    HostEvent, HostStreamState, RecvOutcome, SspReceivedState, SspReceiver, SspSender,
    SspSentState, UserStream,
};
use super::wire::{HostInstruction, HostMessage, TransportInstruction, MOSH_PROTOCOL_VERSION};

const MTU: usize = 1200;
const RTO: u64 = 120;
const SEND_INTERVAL: u64 = 20;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

/// One in-flight datagram: raw fragment bytes, deliverable at `due`.
struct InFlight {
    due: u64,
    bytes: Vec<u8>,
}

struct Channel {
    rng: Rng,
    /// datagrams in flight per direction (c2s = index 0): a datagram
    /// from one endpoint is only ever delivered to the other — the real
    /// wire's direction bit, simplified.
    in_flight: [Vec<InFlight>; 2],
    dropped: usize,
    duplicated: usize,
    delayed: usize,
}

impl Channel {
    fn new(seed: u64) -> Self {
        Channel {
            rng: Rng(seed | 1),
            in_flight: [Vec::new(), Vec::new()],
            dropped: 0,
            duplicated: 0,
            delayed: 0,
        }
    }

    fn send(&mut self, from_client: bool, frag: &Fragment, now: u64) {
        if self.rng.chance(15) {
            self.dropped += 1;
            return;
        }
        // index 0 is client-to-server, matching the deliver tuple order
        let queue = &mut self.in_flight[usize::from(!from_client)];
        let bytes = frag.tostring();
        queue.push(InFlight {
            due: now,
            bytes: bytes.clone(),
        });
        if self.rng.chance(10) {
            queue.push(InFlight { due: now, bytes });
            self.duplicated += 1;
        }
        if self.rng.chance(25) {
            // hold one packet back to reorder it behind its successor
            let last = queue.len() - 1;
            queue[last].due += 3;
            self.delayed += 1;
        }
    }

    fn deliver_due(&mut self, now: u64) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let mut due = [Vec::new(), Vec::new()];
        for (direction, queue) in self.in_flight.iter_mut().enumerate() {
            let mut i = 0;
            while i < queue.len() {
                if queue[i].due <= now {
                    due[direction].push(queue.remove(i).bytes);
                } else {
                    i += 1;
                }
            }
        }
        (due[0].clone(), due[1].clone())
    }
}

/// The server-side state for the test: an append-only log of host
/// instructions (the mirror of the real server's Terminal::Complete).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
struct HostLog {
    instructions: Vec<HostInstruction>,
}

impl SspSentState for HostLog {
    fn diff_from(&self, existing: &Self) -> Vec<u8> {
        let from = existing.instructions.len();
        HostMessage {
            instructions: self.instructions[from..].to_vec(),
        }
        .encode()
    }
    fn subtract(&mut self, known: &Self) {
        let n = known.instructions.len().min(self.instructions.len());
        self.instructions.drain(..n);
    }
}

struct Endpoint<S: SspSentState, R: SspReceivedState> {
    sender: SspSender<S>,
    receiver: SspReceiver<R>,
    fragmenter: Fragmenter,
    assembly: FragmentAssembly,
    bad_diffs: usize,
}

impl<S: SspSentState, R: SspReceivedState> Endpoint<S, R> {
    fn tick_into(&mut self, now: u64, from_client: bool, channel: &mut Channel) {
        let mut frags = Vec::new();
        self.sender
            .tick(
                now,
                RTO,
                SEND_INTERVAL,
                MTU,
                &mut self.fragmenter,
                &mut frags,
            )
            .expect("tick");
        for frag in &frags {
            channel.send(from_client, frag, now);
        }
    }

    fn receive(&mut self, bytes: &[u8], now: u64) {
        let Ok(frag) = Fragment::parse(bytes) else {
            return;
        };
        let Some(inst) = self.assembly.add_fragment(frag) else {
            return;
        };
        self.handle_instruction(&inst, now);
    }

    fn handle_instruction(&mut self, inst: &TransportInstruction, now: u64) {
        self.sender.process_acknowledgment_through(inst.ack_num);
        match self.receiver.process_instruction(inst, now) {
            Ok(RecvOutcome::Latest {
                num,
                had_diff,
                state: _,
            }) => {
                self.sender.set_ack_num(num);
                self.sender.remote_heard(now);
                if had_diff {
                    self.sender.set_data_ack();
                }
            }
            Ok(RecvOutcome::OutOfOrder { .. }) => {
                self.sender.remote_heard(now);
            }
            Ok(_) => {}
            Err(_) => self.bad_diffs += 1,
        }
    }
}

fn run_session(
    seed: u64,
) -> (
    Endpoint<HostLog, UserStream>,
    Endpoint<UserStream, HostStreamState>,
) {
    let mut server = Endpoint {
        sender: SspSender::new(HostLog::default(), 0, 8),
        receiver: SspReceiver::new(UserStream::new(), 0),
        fragmenter: Fragmenter::default(),
        assembly: FragmentAssembly::new(),
        bad_diffs: 0,
    };
    let mut client = Endpoint {
        sender: SspSender::new(UserStream::new(), 0, 1),
        receiver: SspReceiver::new(HostStreamState::new(), 0),
        fragmenter: Fragmenter::default(),
        assembly: FragmentAssembly::new(),
        bad_diffs: 0,
    };

    // script: what each side emits and when
    let mut emitted: Vec<u8> = Vec::new();
    let mut resizes: Vec<(i32, i32)> = Vec::new();
    let mut channel = Channel::new(seed);
    let shutdown_at: u64 = 900;
    let end_at: u64 = 2600;

    for now in 0..end_at {
        match now {
            50 => {
                client.sender.current_state().push_resize(100, 30);
                client.sender.current_state().push_bytes(b"echo golden\r");
            }
            200 => {
                let paint = b"\x1b[H\x1b[2Jgolden$ ".to_vec();
                emitted.extend_from_slice(&paint);
                server
                    .sender
                    .current_state()
                    .instructions
                    .push(HostInstruction::HostBytes(paint));
            }
            260 => {
                let paint = b"echo golden\r".to_vec();
                emitted.extend_from_slice(&paint);
                server
                    .sender
                    .current_state()
                    .instructions
                    .push(HostInstruction::HostBytes(paint));
            }
            300 => {
                server
                    .sender
                    .current_state()
                    .instructions
                    .push(HostInstruction::EchoAck(4));
            }
            420 => {
                resizes.push((100, 30));
                server
                    .sender
                    .current_state()
                    .instructions
                    .push(HostInstruction::Resize {
                        width: 100,
                        height: 30,
                    });
                let paint = vec![b'x'; 4000]; // forces multi-fragment diffs
                emitted.extend_from_slice(&paint);
                server
                    .sender
                    .current_state()
                    .instructions
                    .push(HostInstruction::HostBytes(paint));
            }
            600 => {
                let paint = b"\r\ngolden$ exit\r\n".to_vec();
                emitted.extend_from_slice(&paint);
                server
                    .sender
                    .current_state()
                    .instructions
                    .push(HostInstruction::HostBytes(paint));
            }
            _ => {}
        }
        if now == shutdown_at {
            client.sender.start_shutdown(now);
        }

        client.tick_into(now, true, &mut channel);
        server.tick_into(now, false, &mut channel);

        let (c2s, s2c) = channel.deliver_due(now);
        for bytes in &s2c {
            client.receive(bytes, now);
        }
        for bytes in &c2s {
            server.receive(bytes, now);
        }
        // both sides re-tick after receiving so acks go out promptly
        if now % 5 == 0 {
            client.tick_into(now, true, &mut channel);
            server.tick_into(now, false, &mut channel);
            let (c2s, s2c) = channel.deliver_due(now);
            for bytes in &s2c {
                client.receive(bytes, now);
            }
            for bytes in &c2s {
                server.receive(bytes, now);
            }
        }
    }

    // drain the tail: keep ticking past end_at until quiet or bounded
    for now in end_at..end_at + 4000 {
        client.tick_into(now, true, &mut channel);
        server.tick_into(now, false, &mut channel);
        let (c2s, s2c) = channel.deliver_due(now);
        for bytes in &s2c {
            client.receive(bytes, now);
        }
        for bytes in &c2s {
            server.receive(bytes, now);
        }
        if client.sender.shutdown_acknowledged()
            && channel.in_flight[0].is_empty()
            && channel.in_flight[1].is_empty()
        {
            break;
        }
    }

    let state = client.receiver.latest_state();
    let events = state.log.iter();
    let fed: Vec<u8> = events
        .iter()
        .flat_map(|e| match e {
            HostEvent::Bytes(b) => b.clone(),
            HostEvent::Resize { .. } => Vec::new(),
        })
        .collect();
    let got_resizes: Vec<(i32, i32)> = events
        .iter()
        .filter_map(|e| match e {
            HostEvent::Resize { width, height } => Some((*width, *height)),
            _ => None,
        })
        .collect();
    assert_eq!(
        fed, emitted,
        "client must have received every host byte exactly once, in order"
    );
    assert_eq!(got_resizes, resizes);
    assert_eq!(state.echo_ack, 4);
    assert_eq!(
        server.receiver.latest_state(),
        &{
            let mut expected = UserStream::new();
            expected.push_resize(100, 30);
            expected.push_bytes(b"echo golden\r");
            expected
        },
        "server must hold exactly the user's stream"
    );
    assert_eq!(client.bad_diffs, 0, "no protocol errors from the peer");
    assert_eq!(server.bad_diffs, 0);
    assert!(
        channel.dropped > 10 && channel.duplicated > 5 && channel.delayed > 10,
        "the channel must actually be nasty (dropped={}, dup={}, delayed={})",
        channel.dropped,
        channel.duplicated,
        channel.delayed
    );
    assert!(
        client.sender.shutdown_acknowledged(),
        "shutdown must complete under loss (tries so far: acked at drain end)"
    );
    assert_eq!(
        server.receiver.latest().num,
        u64::MAX,
        "server saw the shutdown state"
    );
    assert!(
        server
            .sender
            .counterparty_shutdown_acknowledged(&server.fragmenter),
        "server must have acked the client's shutdown"
    );
    (server, client)
}

#[test]
fn lossy_loopback_converges_and_shuts_down() {
    for seed in [0x1234_5678, 0xdead_beef, 42, 7] {
        run_session(seed);
    }
}

#[test]
fn protocol_version_mismatch_is_fatal() {
    let mut client_receiver = SspReceiver::new(UserStream::new(), 0);
    let inst = TransportInstruction {
        protocol_version: MOSH_PROTOCOL_VERSION + 1,
        ..Default::default()
    };
    assert!(client_receiver.process_instruction(&inst, 1).is_err());
}
