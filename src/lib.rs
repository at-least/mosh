//! A from-scratch, embeddable Rust client for the mosh mobile-shell
//! protocol — verified against stock mosh-server 1.4.0 (see SPEC.md).
//!
//! Layer map, bottom-up:
//! - [`crypto`] — AES-128-OCB3 datagram seal/open (RustCrypto `ocb3`),
//!   the 22-char key codec, the direction-bit nonce layout, the u16
//!   timestamp packet header, replay/direction gates.
//! - [`wire`] — a proto2-subset codec for mosh's three schemas (the
//!   field numbers ARE the spec). Total on hostile bytes.
//! - [`fragment`] — fragment framing + zlib over the transport diff,
//!   with mosh's instruction-id bump rule.
//! - [`ssp`] — the state-synchronization engine: sender timers,
//!   receiver idempotency rules, the two synchronized states (a
//!   user-stream out, a persistent event log in).
//! - [`bootstrap`] — the `mosh-server new` command builder and the
//!   `MOSH CONNECT` parser (pure; you run the SSH exec).
//! - [`session`] — the UDP session: sockets, timing, roaming, the
//!   shutdown handshake, driving YOUR display ([`MoshDisplay`]).
//!
//! Embedding shape: dial + bootstrap over your own SSH layer (parse
//! `MOSH CONNECT` with [`bootstrap::parse_mosh_bootstrap`]), build the
//! session deferred, and `start()` it from a plain synchronous context
//! once your FFI boundaries are quiet.

pub mod bootstrap;
pub mod crypto;
pub mod fragment;
#[cfg(test)]
mod loop_tests;
pub mod session;
#[cfg(test)]
mod session_tests;
pub mod ssp;
pub mod wire;

pub use bootstrap::{mosh_server_command, parse_mosh_bootstrap, MoshBootstrap, MoshBootstrapError};
pub use crypto::{
    Base64Key, Direction, MoshCryptoError, MoshOpener, MoshSealer, Nonce, PacketHeader,
};
pub use fragment::{Fragment, FragmentAssembly, FragmentError, Fragmenter};
pub use session::{
    LinkHealth, MoshDisplay, MoshSession, PredictedCell, SessionEvent, PASTE_THRESHOLD,
    PORT_HOP_INTERVAL_MS,
};
pub use ssp::{
    send_interval_ms, EventLog, HostEvent, HostStreamState, RecvOutcome, SspError,
    SspReceivedState, SspReceiver, SspSender, SspSentState, UserEvent, UserStream, ACK_DELAY_MS,
    ACK_INTERVAL_MS, ACTIVE_RETRY_TIMEOUT_MS, SEND_MINDELAY_CLIENT_MS, SEND_MINDELAY_DEFAULT_MS,
    SHUTDOWN_RETRIES,
};
pub use wire::{
    HostInstruction, HostMessage, TransportInstruction, UserInstruction, UserMessage, WireError,
    MOSH_PROTOCOL_VERSION, SHUTDOWN_NUM,
};
