//! S3 acceptance: a real-UDP loopback — [`MoshSession`] as the client,
//! a mirror stack (our own S1+S2 pieces with swapped directions) as the
//! test "server" — covering input both ways, host bytes to the display
//! slot, roaming port-hops on a silent link, and a clean shutdown
//! handshake.

use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::crypto::{Base64Key, Direction, MoshOpener, MoshSealer, PacketHeader};
use super::fragment::{Fragment, FragmentAssembly, Fragmenter};
use super::session::{MoshDisplay, MoshSession, SessionEvent};
use super::ssp::{RecvOutcome, SspReceiver, SspSender, SspSentState, UserEvent, UserStream};
use super::wire::{HostInstruction, HostMessage, SHUTDOWN_NUM};

/// The server-side sent state: an append-only host-instruction log.
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

struct ServerHandles {
    addr: std::net::SocketAddr,
    /// host instructions the test wants the server to send
    outbox: Arc<Mutex<Vec<HostInstruction>>>,
    go_silent: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    /// every user byte the server has received (latest full stream)
    received: Arc<Mutex<Vec<u8>>>,
    saw_shutdown: Arc<AtomicBool>,
}

/// A capture display: records fed bytes + resizes at a fixed size.
#[derive(Clone, Default)]
struct TestDisplay {
    state: Arc<Mutex<TestState>>,
    cols: usize,
    rows: usize,
}

#[derive(Clone, Default)]
struct TestState {
    fed: Vec<u8>,
    resizes: Vec<(usize, usize)>,
}
impl TestDisplay {
    fn new(cols: usize, rows: usize) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(TestDisplay {
            state: Arc::new(Mutex::new(TestState::default())),
            cols,
            rows,
        }))
    }
    fn snapshot(&self) -> TestState {
        self.state.lock().unwrap().clone()
    }
}
impl MoshDisplay for TestDisplay {
    fn new_blank(cols: usize, rows: usize) -> Self {
        TestDisplay {
            state: Arc::new(Mutex::new(TestState::default())),
            cols,
            rows,
        }
    }
    fn feed(&mut self, bytes: &[u8]) {
        self.state.lock().unwrap().fed.extend_from_slice(bytes);
    }
    fn resize(&mut self, cols: usize, rows: usize) {
        self.cols = cols;
        self.state.lock().unwrap().resizes.push((cols, rows));
    }
    fn cols(&self) -> usize {
        self.cols
    }
    fn rows(&self) -> usize {
        self.rows
    }
    fn cursor(&self) -> (i32, i32, bool) {
        (0, 0, true)
    }
}

fn spawn_test_server(key: Base64Key) -> ServerHandles {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("bind");
    let addr = socket.local_addr().expect("addr");
    let outbox = Arc::new(Mutex::new(Vec::new()));
    let go_silent = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let received = Arc::new(Mutex::new(Vec::new()));
    let saw_shutdown = Arc::new(AtomicBool::new(false));

    let outbox_move = Arc::clone(&outbox);
    let silent_move = Arc::clone(&go_silent);
    let stop_move = Arc::clone(&stop);
    let received_move = Arc::clone(&received);
    let shutdown_move = Arc::clone(&saw_shutdown);
    std::thread::spawn(move || {
        let mut sealer = MoshSealer::new(&key, Direction::ToClient);
        let opener = MoshOpener::new(&key, Direction::ToServer);
        let mut sender: SspSender<HostLog> = SspSender::new(HostLog::default(), 0, 8);
        let mut receiver = SspReceiver::new(UserStream::new(), 0);
        let mut fragmenter = Fragmenter::default();
        let mut assembly = FragmentAssembly::new();
        let mut peer: Option<std::net::SocketAddr> = None;
        let origin = Instant::now();
        let now = || origin.elapsed().as_millis() as u64;

        socket.set_read_timeout(Some(Duration::from_millis(5))).ok();
        let mut buf = [0u8; 2048];
        loop {
            if stop_move.load(Ordering::Relaxed) {
                return;
            }
            let t = now();
            let silent = silent_move.load(Ordering::Relaxed);

            // adopt any scripted emissions
            for instruction in outbox_move.lock().unwrap().drain(..) {
                sender.current_state().instructions.push(instruction);
            }

            if !silent {
                let mut frags = Vec::new();
                sender.tick(t, 120, 20, 1200 - 12 - 16, &mut fragmenter, &mut frags);
                if let Some(peer_addr) = peer {
                    for frag in &frags {
                        let header = PacketHeader {
                            timestamp: (t % 65_536) as u16,
                            timestamp_reply: u16::MAX,
                        };
                        if let Ok(datagram) = sealer.seal(&header, &frag.tostring()) {
                            let _ = socket.send_to(&datagram, peer_addr);
                        }
                    }
                }
            }

            if let Ok((len, src)) = socket.recv_from(&mut buf) {
                {
                    peer = Some(src);
                    if silent {
                        continue; // swallow traffic, never answer
                    }
                    if let Ok((_, _header, fragment)) = opener.open(&buf[..len]) {
                        if let Ok(fragment) = Fragment::parse(&fragment) {
                            if let Some(inst) = assembly.add_fragment(fragment) {
                                sender.process_acknowledgment_through(inst.ack_num);
                                match receiver.process_instruction(&inst, t) {
                                    Ok(RecvOutcome::Latest { num, had_diff, .. }) => {
                                        sender.set_ack_num(num);
                                        sender.remote_heard(t);
                                        if had_diff {
                                            sender.set_data_ack();
                                        }
                                        let mut log = received_move.lock().unwrap();
                                        log.clear();
                                        for event in receiver.latest_state().events() {
                                            if let UserEvent::Byte(b) = event {
                                                log.push(*b);
                                            }
                                        }
                                        if num == SHUTDOWN_NUM {
                                            shutdown_move.store(true, Ordering::Relaxed);
                                            // keep ticking until an ack carrying MAX has
                                            // actually gone out, then stop
                                            let deadline =
                                                Instant::now() + Duration::from_millis(1500);
                                            while Instant::now() < deadline {
                                                let t2 = now();
                                                let mut frags = Vec::new();
                                                sender.tick(
                                                    t2,
                                                    120,
                                                    20,
                                                    1200 - 12 - 16,
                                                    &mut fragmenter,
                                                    &mut frags,
                                                );
                                                if let Some(peer_addr) = peer {
                                                    for frag in &frags {
                                                        let header = PacketHeader {
                                                            timestamp: (t2 % 65_536) as u16,
                                                            timestamp_reply: u16::MAX,
                                                        };
                                                        if let Ok(datagram) =
                                                            sealer.seal(&header, &frag.tostring())
                                                        {
                                                            let _ = socket
                                                                .send_to(&datagram, peer_addr);
                                                        }
                                                    }
                                                }
                                                if sender
                                                    .counterparty_shutdown_acknowledged(&fragmenter)
                                                {
                                                    break;
                                                }
                                                std::thread::sleep(Duration::from_millis(5));
                                            }
                                            stop_move.store(true, Ordering::Relaxed);
                                            return;
                                        }
                                    }
                                    Ok(RecvOutcome::OutOfOrder { .. }) => {
                                        // out-of-order inserts never refresh
                                        // the retry window (upstream returns
                                        // right after inserting)
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    ServerHandles {
        addr,
        outbox,
        go_silent,
        stop,
        received,
        saw_shutdown,
    }
}

fn wait_until(deadline_ms: u64, check: impl Fn() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed().as_millis() < deadline_ms as u128 {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

/// The display's fed bytes as text (the loopback marker assertions).
fn fed_text(display: &Arc<Mutex<TestDisplay>>) -> String {
    String::from_utf8_lossy(&display.lock().unwrap().snapshot().fed).into_owned()
}

#[test]
fn udp_loopback_input_hostbytes_and_clean_shutdown() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let server = spawn_test_server(key.clone());

    let events: Arc<Mutex<Vec<SessionEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let event_log = Arc::clone(&events);
    let display = TestDisplay::new(80, 24);
    let client = MoshSession::connect(
        Arc::clone(&display),
        "127.0.0.1",
        server.addr.port(),
        &key,
        move |event| event_log.lock().unwrap().push(event),
        80,
        24,
        false, // prediction off in these protocol tests
    )
    .expect("connect");

    // the server's acks reach us (initial resize + association)
    assert!(
        wait_until(3000, || !client.link_health().never_heard),
        "client must hear the server"
    );

    // keyboard input flows client -> server
    client.send_input(b"hi mosh\r");
    assert!(
        wait_until(3000, || {
            server.received.lock().unwrap().ends_with(b"hi mosh\r")
        }),
        "server must receive the typed bytes"
    );

    // host bytes flow server -> client display engine
    server
        .outbox
        .lock()
        .unwrap()
        .push(HostInstruction::HostBytes(
            b"\x1b[H\x1b[2Jgolden screen".to_vec(),
        ));
    assert!(
        wait_until(4000, || fed_text(&display).contains("golden screen")),
        "client display must contain the server's paint"
    );

    // a host resize instruction reflows the in-core engine
    server.outbox.lock().unwrap().push(HostInstruction::Resize {
        width: 100,
        height: 30,
    });
    assert!(
        wait_until(3000, || {
            display
                .lock()
                .unwrap()
                .snapshot()
                .resizes
                .contains(&(100, 30))
        }),
        "the host resize must reach the display"
    );

    // clean shutdown handshake both ways
    client.start_shutdown();
    assert!(
        wait_until(5000, || server.saw_shutdown.load(Ordering::Relaxed)),
        "server must see the shutdown state"
    );
    assert!(
        wait_until(5000, || {
            events
                .lock()
                .unwrap()
                .iter()
                .any(|e| matches!(e, SessionEvent::Ended { clean: true, .. }))
        }),
        "client must end cleanly"
    );
    client.join();
}

#[test]
fn roaming_hops_ports_when_the_link_goes_silent() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let server = spawn_test_server(key.clone());

    let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("bind");
    let display = TestDisplay::new(80, 24);
    let client = MoshSession::connect_on(
        display,
        socket,
        server.addr,
        &key,
        |_| {},
        80,
        24,
        200, // tiny hop interval for the test
        false,
    )
    .expect("connect");

    // associate first, then silence the server
    client.send_input(b"x");
    assert!(
        wait_until(3000, || !client.link_health().never_heard),
        "associate before going silent"
    );
    server.go_silent.store(true, Ordering::Relaxed);

    // with no round trips, the client must rotate source ports
    assert!(
        wait_until(6000, || client.ports_opened() >= 3),
        "expected at least 3 ports (2 hops) after the link went silent, got {}",
        client.ports_opened()
    );
    server.stop.store(true, Ordering::Relaxed);
    client.terminate();
}

#[test]
fn terminate_stops_the_loop_without_handshake() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let server = spawn_test_server(key.clone());
    let client = MoshSession::connect(
        TestDisplay::new(80, 24),
        "127.0.0.1",
        server.addr.port(),
        &key,
        |_| {},
        80,
        24,
        false,
    )
    .expect("connect");
    client.terminate(); // must return promptly, no hang
    server.stop.store(true, Ordering::Relaxed);
}

/// B4 regression: upstream refreshes `last_heard` on every packet that
/// decrypts with a fresh sequence number (network.cc:556), whether or
/// not its fragment assembles into an instruction — a stream of torn
/// fragments is still proof the link is alive. But `still_connecting`
/// upstream means "no appended remote state yet", so the connecting
/// flag must NOT clear on torn fragments alone.
#[test]
fn torn_fragments_refresh_heard_but_not_the_connecting_flag() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("bind");
    let server_addr = socket.local_addr().expect("addr");
    let stop = Arc::new(AtomicBool::new(false));
    let stop_move = Arc::clone(&stop);

    // one instruction, deliberately incompressible so it fragments
    let mut mix: u64 = 0x243F_6A88_85A3_08D3;
    let big_diff: Vec<u8> = (0..3000)
        .map(|_| {
            mix = mix
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (mix >> 56) as u8
        })
        .collect();
    let inst = super::wire::TransportInstruction {
        protocol_version: 2,
        old_num: 0,
        new_num: 1,
        ack_num: 0,
        throwaway_num: 0,
        diff: big_diff,
        chaff: Vec::new(),
    };
    let mut fragmenter = Fragmenter::default();
    let mut frags = fragmenter
        .make_fragments(&inst, 1200 - 12 - 16)
        .expect("fragments");
    assert!(
        frags.len() >= 2,
        "instruction must split so we can send a torn piece"
    );
    let torn = frags.remove(0); // fragment 0, final=false — never assembles

    let thread_key = key.clone();
    std::thread::spawn(move || {
        let mut sealer = MoshSealer::new(&thread_key, Direction::ToClient);
        let mut buf = [0u8; 2048];
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .ok();
        let mut peer: Option<std::net::SocketAddr> = None;
        loop {
            if stop_move.load(Ordering::Relaxed) {
                return;
            }
            // adopt the client as peer whenever it talks to us
            if let Ok((_, src)) = socket.recv_from(&mut buf) {
                peer = Some(src);
            }
            if let Some(client_addr) = peer {
                let header = PacketHeader {
                    timestamp: 0,
                    timestamp_reply: u16::MAX,
                };
                if let Ok(datagram) = sealer.seal(&header, &torn.tostring()) {
                    let _ = socket.send_to(&datagram, client_addr);
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });

    let display = TestDisplay::new(80, 24);
    let client = MoshSession::connect(
        display,
        "127.0.0.1",
        server_addr.port(),
        &key,
        |_| {},
        80,
        24,
        false,
    )
    .expect("connect");

    // let the torn fragments flow for a while: if they refresh "heard",
    // the metric stays small; if not, it grows with the clock
    std::thread::sleep(Duration::from_millis(1500));
    assert!(
        client.link_health().since_heard_ms < 250,
        "every decrypted datagram must refresh last_heard, got since_heard_ms={}",
        client.link_health().since_heard_ms
    );
    // ... but no instruction ever completed, so we are still connecting
    assert!(
        client.link_health().never_heard,
        "the connecting flag must not clear without an appended state"
    );
    stop.store(true, Ordering::Relaxed);
    client.terminate();
}

/// P6 regression: the server's echo-ack retires predictions on EVERY
/// appended state — an echoack-only instruction (no host bytes) is
/// enough upstream (completeterminal.cc:130-160); the guesses must not
/// linger until the next paint.
#[test]
fn echoack_only_state_retires_predictions() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let server = spawn_test_server(key.clone());

    let client = MoshSession::connect(
        TestDisplay::new(20, 4),
        "127.0.0.1",
        server.addr.port(),
        &key,
        |_| {},
        20,
        4,
        true, // prediction ON
    )
    .expect("connect");

    // associate, then silence so only predictions can paint
    client.send_input(b"x");
    assert!(
        wait_until(3000, || !client.link_health().never_heard),
        "associate first"
    );
    server.go_silent.store(true, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(300));

    client.send_input(b"hi");
    assert!(
        wait_until(1000, || !client.prediction_overlay().is_empty()),
        "predictions must appear first"
    );

    // the server answers with an ECHOACK ONLY — no host bytes, no paint
    server.go_silent.store(false, Ordering::Relaxed);
    server
        .outbox
        .lock()
        .unwrap()
        .push(HostInstruction::EchoAck(99));
    assert!(
        wait_until(4000, || client.prediction_overlay().is_empty()),
        "an echoack-only state must retire the guesses, got {:?}",
        client.prediction_overlay()
    );
    server.stop.store(true, Ordering::Relaxed);
    client.terminate();
}

/// Conservative local echo (the S5b layer): against a SILENT server,
/// typed printables appear on the core display at once (underlined —
/// the "this is a guess" mark); when the server finally paints and its
/// echo-ack covers the frame, the guesses retire; the never-toggle
/// shows nothing.
#[test]
fn prediction_appears_retires_and_toggles() {
    let key = Base64Key::parse("7l1cNvxYVkWP1j8zMC08Jg").unwrap();
    let server = spawn_test_server(key.clone());

    let events: Arc<Mutex<Vec<SessionEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let event_log = Arc::clone(&events);
    let client = MoshSession::connect(
        TestDisplay::new(20, 4),
        "127.0.0.1",
        server.addr.port(),
        &key,
        move |event| event_log.lock().unwrap().push(event),
        20,
        4,
        true, // prediction ON
    )
    .expect("connect");

    // associate, then silence the server so only predictions can paint
    client.send_input(b"x");
    assert!(
        wait_until(3000, || !client.link_health().never_heard),
        "associate first"
    );
    server.go_silent.store(true, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(300)); // let in-flight acks land

    // typing against the silent link produces the guessed cells at once
    client.send_input(b"hi");
    assert!(
        wait_until(1000, || {
            let overlay = client.prediction_overlay();
            overlay.iter().any(|c| c.ch == 'h') && overlay.iter().any(|c| c.ch == 'i')
        }),
        "predicted cells must appear while the link is silent"
    );

    // never-mode: cleared, and stays empty
    client.set_prediction(false);
    assert!(client.prediction_overlay().is_empty(), "toggle clears");
    client.send_input(b"zz");
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        client.prediction_overlay().is_empty(),
        "never-mode predicts nothing"
    );

    // back on: the guess reappears, then retires when the server
    // answers with the real echo + echo-ack
    client.set_prediction(true);
    client.send_input(b"ok");
    assert!(wait_until(1000, || !client.prediction_overlay().is_empty()));
    server.go_silent.store(false, Ordering::Relaxed);
    server
        .outbox
        .lock()
        .unwrap()
        .push(HostInstruction::HostBytes(b"ok".to_vec()));
    server
        .outbox
        .lock()
        .unwrap()
        .push(HostInstruction::EchoAck(99));
    assert!(
        wait_until(4000, || client.prediction_overlay().is_empty()),
        "the real echo must retire the guesses"
    );
    server.stop.store(true, Ordering::Relaxed);
    client.terminate();
}
