/*
   OxiRush
   Copyright 2026 Valentin D'Emmanuele

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

//! A PFCP entity without I/O: datagrams and time go in; datagrams, events and the next
//! timer come out. An SMF, a UPF and a test tool share it, each with its own socket loop.
//!
//! - **Delivery (§6.4):** sequence numbers, retransmission after T1 up to N1 times,
//!   responses matched by sequence, peer and type, retransmitted requests answered again.
//! - **Heartbeat (§6.2.2):** answered from anyone, sent to the associated peers.
//! - **Associations (§6.2.6 to §6.2.8)** and **sessions**, kept in step with the
//!   procedures, a deletion with usage reports to follow until the last (§5.2.2.3.1).
//! - **Load and overload control (§6.2.3, §6.2.4)**, with the "Loss" throttling, and
//!   **message priority (§6.2.4.5)**.
//! - **Bundling (§6.5),** when both peers announced BUNDL.
//!
//! The node answers itself only what the clauses leave no choice in: a heartbeat, a
//! request that does not decode, one of a peer without an association or of a session
//! that the node does not have. What a peer does wrong is an [`Event::Violation`]. Every
//! other request is the caller's to answer with [`Node::respond`]: one that names a
//! session or an association that is not its sender's, as another SMF of a set sends
//! (§5.22), comes [`Inbound::stranger`].

mod controls;
mod delivery;
mod inbound;
mod peers;
mod sessions;
mod state;

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};
use core::time::Duration;

use crate::enums::{CauseValue, TimerUnit};
use crate::header::Header;
use crate::message::{
    Body, Message, datagram_parts, is_node_related, is_request, message_type_info,
};
use crate::registry::*;
use crate::values::*;
use crate::values_figures::*;

pub use controls::{LoadControl, OverloadControl};
use controls::{Overloads, Scope};
use delivery::{Change, Outstanding, Pending};
use inbound::Effect;
use peers::{Heartbeats, key_of, peer_key};
use state::{Answers, Digest, Features, Sessions, SetOf};
pub use state::{Association, Session};

/// The function of the node: it sets up sessions, or it has them set up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Function {
    /// A CP function: an SMF, an SGW-C, a PGW-C, a TDF-C.
    Cp,
    /// A UP function: a UPF, an SGW-U, a PGW-U, a TDF-U.
    Up,
}

/// What a node is.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Its Node ID, in the answers that the node writes itself.
    pub node_id: NodeId,
    /// Its function.
    pub function: Function,
    /// When it started, as the Recovery Time Stamp has it (§8.2.65).
    pub recovery_time_stamp: u32,
    /// T1, after which a request is sent again (§6.4): 1 ms at least.
    pub t1: Duration,
    /// N1, how many times a request is sent again (§6.4).
    pub n1: u8,
    /// How often each associated peer gets a Heartbeat Request: `None` for never, 1 ms
    /// at least.
    pub heartbeat: Option<Duration>,
    /// How long the node keeps an answer for its retransmissions, a request for the
    /// caller's answer, a finished request to tell a late response, and a deleted session
    /// for its last usage reports ([`Event::SessionEnded`]).
    pub keep: Duration,
    /// The priority of a request that has none (§6.2.4.5.2): 0 the highest, to 15.
    pub default_priority: u8,
    /// Throttle the session requests to an overloaded peer (§6.2.4.4).
    pub throttling: bool,
    /// The priorities, from 0 up to this one, of the requests that throttling spares
    /// while it can (§6.2.4.5.1): `None` for none.
    pub priority_up_to: Option<u8>,
    /// How many requests of the peers, and Recovery Time Stamps of hosts without an
    /// association, the node keeps: beyond, its own rejections go first, then the oldest
    /// answers, and a request that finds every place waiting is dropped
    /// ([`Node::counters`]).
    pub capacity: usize,
    /// The port of the node's own requests to a peer (§4.2.2): 8805, and a peer is its IP
    /// address. `None` for the port of the peer's request, as in a test: a peer is then
    /// its address and port.
    pub request_port: Option<u16>,
    /// How many requests of hosts without an association wait for their answer at once:
    /// beyond, one is dropped unread ([`Counters::refused`]). A session request from the
    /// address of its session's F-SEID, or from the peer of an adopted session, is not
    /// one of them.
    pub strangers: usize,
}

impl NodeConfig {
    /// A node of `node_id`: T1 of 3 s, N1 of 3, a heartbeat every 60 s, answers kept for
    /// 24 s, default priority 8, throttling on, no priority spared, room for 65,536
    /// requests of the peers and 16 of hosts without an association, and requests to port
    /// 8805.
    pub fn new(node_id: NodeId, function: Function, recovery_time_stamp: u32) -> Self {
        Self {
            node_id,
            function,
            recovery_time_stamp,
            t1: Duration::from_secs(3),
            n1: 3,
            heartbeat: Some(Duration::from_secs(60)),
            keep: Duration::from_secs(24),
            default_priority: 8,
            throttling: true,
            priority_up_to: None,
            capacity: 65_536,
            request_port: Some(PORT),
            strangers: 16,
        }
    }
}

/// The UDP port of PFCP (§4.2.2).
pub const PORT: u16 = 8805;

/// A datagram to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transmit {
    /// To whom.
    pub to: SocketAddr,
    /// Its priority: 0 the highest.
    pub priority: u8,
    /// The datagram.
    pub octets: Datagram,
}

/// The octets of a datagram or of a message: `Debug` prints their number alone, as they
/// may hold a key.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Datagram(pub Vec<u8>);

impl core::fmt::Debug for Datagram {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Datagram({} octets)", self.0.len())
    }
}

impl core::ops::Deref for Datagram {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl From<Vec<u8>> for Datagram {
    fn from(octets: Vec<u8>) -> Self {
        Self(octets)
    }
}

/// What the node dropped to bound what it keeps of its peers' requests (§6.4), since it
/// started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Counters {
    /// Answers that went before `keep`, for a new request that found the node full: a
    /// retransmission of their request comes again as a new request.
    pub evicted: u64,
    /// Requests dropped unanswered, for a node full of requests that wait for their
    /// answer: the peer sends them again.
    pub refused: u64,
}

/// A request that the node sends, until its response or its timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(pub u64);

/// A request that the node received, which [`Node::respond`] answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    /// From whom.
    pub from: SocketAddr,
    /// Its message type.
    pub message_type: u8,
    /// Its sequence number, which the response copies.
    pub sequence: u32,
    /// Its priority, or the default one (§6.2.4.5.2).
    pub priority: u8,
    /// Whether it said its priority, which the response then says too.
    pub prioritized: bool,
    /// The SEID of its header: the local SEID of its session when it came. Its answer goes
    /// to that session, wherever it moved since, while it lasts.
    pub seid: Option<u64>,
    /// The SEID of the peer's F-SEID, of an establishment.
    pub peer_seid: Option<u64>,
    /// The Node ID that it carries.
    pub node_id: Option<NodeId>,
    /// The mark of the session of `seid` when it came.
    pub(crate) mark: Option<u64>,
    /// What an answer that accepts it changes.
    pub(crate) effect: Effect,
    /// It names a session or an association that is not its sender's, as another SMF of a
    /// set does (§5.22): a modification or deletion of another peer's session, an update
    /// or release of another peer's association, or a report of SEID 0 that hands a
    /// session over ([`Node::adopt_session`]). The caller takes or rejects it; accepted, a
    /// modification gives the session to the sender's association.
    pub stranger: bool,
    /// The request, of all that the node gave the caller.
    pub(crate) id: u64,
}

impl Inbound {
    /// The request as one of the session of `local_seid`, which its answer goes to.
    pub(crate) fn of_session(&self, local_seid: u64) -> Self {
        Self {
            seid: Some(local_seid),
            mark: None,
            ..self.clone()
        }
    }
}

/// How a response goes, for a probe that breaks §6.4 on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Sent, and kept for the retransmissions of the request.
    Send,
    /// Kept for the retransmissions, and not sent: the first one is lost.
    CacheOnly,
    /// Neither sent nor kept, and without effect on the node: a responder that lost its
    /// state, which takes a retransmission of the request as a new request.
    Forget,
}

/// Why a request of the node ends without its response.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Failure {
    /// The peer answered with a Version Not Supported Response (§7.6.2), whose sequence
    /// number says nothing (§7.2.2.2): every request to the peer fails with it.
    VersionNotSupported,
    /// The response does not decode (§7.6.1, §7.6.3, §7.6.7): the node stops sending the
    /// request again, and the caller has the error.
    Malformed(crate::Error),
}

impl core::fmt::Display for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::VersionNotSupported => write!(
                f,
                "the peer does not support version 1 of PFCP (TS 29.244 7.6.2)"
            ),
            Self::Malformed(error) => write!(f, "the response does not decode: {error}"),
        }
    }
}

/// What a peer does that its clause does not let it, as the node sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ViolationKind {
    /// A response to a request that already had its response: discarded (§6.4).
    DuplicateResponse,
    /// A response to no request of the node: discarded (§6.4, §7.6.5).
    UnknownSequence,
    /// A response to a request that the node gave up: discarded.
    LateResponse,
    /// A response with the sequence number of a request to another peer: discarded.
    WrongPeer,
    /// A response of another type than the request's: discarded (§7.6.5).
    WrongResponseType,
    /// A request with the sequence number of one that is not answered yet, and other
    /// octets (§6.4): discarded.
    ChangedRetransmission,
    /// A message of a type that Table 7.3-1 does not have: discarded (§7.6.4).
    UnknownMessage,
    /// A request that the function of the node does not receive, as a CP function an
    /// establishment: discarded (§7.6.5).
    WrongDirection,
    /// A session or node request of a host without an association (§6.2.6), of no session
    /// of the node: answered "No established PFCP Association".
    SessionWithoutAssociation,
    /// A session request of a SEID that is of no established session of the peer:
    /// answered with "Session context not found" (§7.2.2.4.2).
    UnknownSeid,
    /// An association update or release of a Node ID of no association: answered "No
    /// established PFCP Association" (§6.2.7, §6.2.8).
    UnknownNode,
    /// Load control information of a sequence number that the node has, with other
    /// values, or of a new one with the same values (§6.2.3.3.2).
    LoadControlSequence,
    /// Overload control information of a sequence number that the node has, with other
    /// values (§6.2.4.3.2.1). A new number with the same values extends the period of
    /// validity, as NOTE 1 has it.
    OverloadControlSequence,
    /// A node related message bundled with others (§6.5): discarded.
    BundledNodeMessage,
    /// A session message bundled with those of another address of the node's F-SEIDs
    /// (§6.5): discarded.
    BundledPeers,
    /// Messages bundled by a host of no association, naming no session of one (§6.5):
    /// discarded.
    BundledWithoutAssociation,
    /// Messages bundled by a peer when it or the node did not announce BUNDL in their
    /// association messages (§6.5): discarded.
    BundlingNotAgreed,
    /// A peer's SEID of 0, which is of no session (§7.2.2.4.2): an establishment that gives
    /// it is answered "Mandatory IE incorrect", and nothing moves a session to it.
    SeidZero,
}

/// Whose load or overload control information the node keeps (§6.2.3.3.1, §6.2.4.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlScope {
    /// Of the Node ID of an association.
    Node(NodeId),
    /// Of the address of a UP F-SEID, on port 0 for a node of a
    /// [`NodeConfig::request_port`].
    Address(SocketAddr),
}

/// Something the caller is told.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// A request to answer with [`Node::respond`]: not a Heartbeat Request, which the
    /// node answers.
    Request {
        /// What to answer.
        request: Inbound,
        /// The request.
        message: Message,
    },
    /// The response to a request of the caller.
    Response {
        /// The request.
        request: RequestId,
        /// The response.
        message: Message,
    },
    /// A request of the caller without a response after N1 retransmissions (§6.4). An
    /// establishment that times out, fails or is cancelled takes its local SEID with it.
    Timeout {
        /// The request.
        request: RequestId,
        /// To whom it went.
        to: SocketAddr,
    },
    /// A request of the caller that ends without its response.
    Failed {
        /// The request.
        request: RequestId,
        /// To whom it went.
        to: SocketAddr,
        /// Why.
        failure: Failure,
    },
    /// An association, set up by a successful Association Setup.
    Associated {
        /// The peer.
        peer: SocketAddr,
        /// Its Node ID.
        node_id: NodeId,
        /// It replaces an association of the same Node ID (§6.2.6.2.2).
        replaced: bool,
        /// The local SEIDs of the sessions of the association that it replaces, which
        /// end with it on a UP function: those that the PFCP Session Retention Information
        /// of the request does not keep (§6.2.6.2.2).
        sessions: Vec<u64>,
    },
    /// An association ended by a successful Association Release, or by
    /// [`Node::end_association`], with its sessions.
    Released {
        /// The peer's Node ID.
        node_id: NodeId,
        /// The local SEIDs of the sessions that ended with it (§6.2.8).
        sessions: Vec<u64>,
        /// The local SEIDs of its sessions that its SMF set keeps, when both the node and
        /// the peer announced MPAS in their association messages (§6.2.8): on a UP function
        /// those that another association of the set takes, on a CP function all of them,
        /// which the caller ends unless another association of the set with the UP
        /// function remains.
        kept: Vec<u64>,
    },
    /// A peer whose Recovery Time Stamp changed: it restarted, and what the node kept of
    /// its load and overload is gone. Its sessions are the caller's to end
    /// ([`Node::end_sessions_of`]).
    PeerRestarted {
        /// The peer.
        peer: SocketAddr,
        /// Its new Recovery Time Stamp.
        recovery_time_stamp: u32,
    },
    /// A peer that answered none of N1 retransmissions of a Heartbeat Request.
    PeerDown {
        /// The peer.
        peer: SocketAddr,
    },
    /// An overload whose period of validity ended (§6.2.4.3.2).
    OverloadEnded {
        /// The peer that sent it.
        peer: SocketAddr,
    },
    /// A session whose deletion waited for the UP function's last usage reports
    /// (§5.2.2.3.1), which the node ended `keep` after the last message of it, without the
    /// report of PSDBU that ends it otherwise. The caller ends one sooner, when it has the
    /// number of reports that the Additional Usage Reports Information of the deletion's
    /// response said, with [`Node::end_session`].
    SessionEnded {
        /// Its local SEID.
        local_seid: u64,
    },
    /// A peer's retransmission of a request that the node holds (§6.4): one that waits
    /// for the caller's answer, which the node does not give the caller again, or one that
    /// has its answer, the caller's or a rejection of the node's own, which the node sent
    /// again. A Heartbeat Request is answered from the state, and held by nothing.
    Retransmission {
        /// The peer.
        from: SocketAddr,
        /// The sequence number of the request.
        sequence: u32,
        /// Whether the node sent the answer that it keeps.
        answered: bool,
    },
    /// What a peer did wrong, and its octets.
    Violation {
        /// The peer.
        from: SocketAddr,
        /// What.
        kind: ViolationKind,
        /// The message.
        octets: Datagram,
    },
    /// A message that does not decode, or of another version: the node answered a request
    /// that it could (§7.6.2, §7.6.3, §7.6.7), and a response ended its request with
    /// [`Event::Failed`].
    Malformed {
        /// The peer.
        from: SocketAddr,
        /// Why.
        error: crate::Error,
    },
}

/// Why the node does not send a request, or an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NodeError {
    /// A session request to a peer without an association (§6.2.6.2.1).
    NoAssociation,
    /// A session request to a session that the node does not have.
    NoSession,
    /// The "Loss" algorithm drops it, for the overload of the peer (§6.2.4.4).
    Throttled,
    /// It is no request.
    NotARequest,
    /// A request that the function of the node does not send, as a UP function an
    /// establishment (§7.6.5).
    WrongDirection,
    /// Every sequence number is outstanding, reserved or recent.
    NoSequence,
    /// An answer to a request that has one already (§6.4).
    Answered,
    /// An answer to a request that is no longer waiting: it expired past `keep`, or the
    /// caller forgot it.
    Forgotten,
    /// An answer of another type than the response of the request.
    WrongResponse,
    /// An establishment, or its answer, of a local SEID that another session or
    /// establishment has.
    SeidInUse,
    /// A local SEID of 0, which says that the peer's is not known (§7.2.2.4.2).
    SeidZero,
    /// It does not encode.
    Encode(crate::Error),
}

impl core::fmt::Display for NodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::NoAssociation => write!(
                f,
                "a session request to a peer without an association (TS 29.244 6.2.6.2.1)"
            ),
            Self::NoSession => write!(
                f,
                "a session request to a session that the node does not have"
            ),
            Self::Throttled => write!(
                f,
                "throttled for the overload of the peer (TS 29.244 6.2.4.4)"
            ),
            Self::NotARequest => write!(f, "the message is no request"),
            Self::WrongDirection => write!(
                f,
                "a request that the function of the node does not send (TS 29.244 7.6.5)"
            ),
            Self::NoSequence => write!(f, "no sequence number is free"),
            Self::Answered => write!(f, "the request has its answer (TS 29.244 6.4)"),
            Self::Forgotten => write!(
                f,
                "the request is no longer waiting for an answer (TS 29.244 6.4)"
            ),
            Self::WrongResponse => write!(f, "the answer is not the response of the request"),
            Self::SeidInUse => write!(f, "the local SEID is of another session"),
            Self::SeidZero => write!(f, "a SEID of 0 is of no session (TS 29.244 7.2.2.4.2)"),
            Self::Encode(error) => write!(f, "the message does not encode: {error}"),
        }
    }
}

impl core::error::Error for NodeError {}

impl From<crate::Error> for NodeError {
    fn from(error: crate::Error) -> Self {
        Self::Encode(error)
    }
}

/// Whether a function sends requests of `message_type` (§6.2, §6.3): heartbeats,
/// association setups and updates and session set deletions both ways, the rest one way.
fn sends(function: Function, message_type: u8) -> bool {
    match message_type {
        1 | 5 | 7 | 14 => true,
        3 | 9 | 16 | 50 | 52 | 54 => function == Function::Cp,
        12 | 56 => function == Function::Up,
        _ => false,
    }
}

/// The peer of `from` whose F-SEID has `fseid`: its address of the family of `from`, on
/// the port of `from` (§5.6.2).
fn fseid_peer(from: SocketAddr, fseid: &FSeid) -> SocketAddr {
    let address = fseid_address(from, fseid);
    SocketAddr::new(address.unwrap_or(from.ip()), from.port())
}

/// The address of `fseid` of the family of `peer`: where `peer` sends the messages of its
/// session.
fn fseid_address(peer: SocketAddr, fseid: &FSeid) -> Option<IpAddr> {
    match peer.ip() {
        IpAddr::V4(_) => fseid.ipv4.map(IpAddr::V4),
        IpAddr::V6(_) => fseid.ipv6.map(IpAddr::V6),
    }
}

/// A PFCP entity on one local endpoint.
#[derive(Debug)]
pub struct Node {
    config: NodeConfig,
    next_sequence: u32,
    next_request: u64,
    next_seid: u64,
    next_inbound: u64,
    next_mark: u64,
    reserved: BTreeSet<u32>,
    outstanding: BTreeMap<u32, Outstanding>,
    /// The sequence number of each outstanding request, and the peers that have a
    /// heartbeat of the node's outstanding.
    ids: BTreeMap<RequestId, u32>,
    beating: BTreeSet<SocketAddr>,
    /// The retransmissions, by when they are due.
    deadlines: BTreeSet<(Duration, u32)>,
    /// The requests that had their response, or that the node gave up, until `keep`:
    /// (sequence, peer) to (when they go, given up), and by when they go.
    finished: BTreeMap<(u32, SocketAddr), (Duration, bool)>,
    finishing: BTreeSet<(Duration, u32, SocketAddr)>,
    answers: Answers,
    associations: BTreeMap<Vec<u8>, Association>,
    /// The association of each peer, as [`Node::same_peer`] tells them apart.
    by_peer: BTreeMap<SocketAddr, Vec<u8>>,
    sessions: Sessions,
    /// The Recovery Time Stamp of each peer, as [`Node::same_peer`] tells them apart, and
    /// the turn in which the node last had it; and the peers with neither an association
    /// nor an adopted session by that turn, the first of which goes first.
    recovery: BTreeMap<SocketAddr, (u32, u64)>,
    aging: BTreeMap<u64, SocketAddr>,
    next_turn: u64,
    heartbeats: Heartbeats,
    load: BTreeMap<Scope, LoadControl>,
    overload: Overloads,
    /// The peers, as the node tells them apart, whose load and overload of their address
    /// go unless a session or an association of theirs remains.
    orphans: BTreeSet<SocketAddr>,
    /// The features of its function that the node last announced, in an association setup
    /// or update of its own: those that it bundles with the peers of adopted sessions by.
    features: Features,
    transmits: [VecDeque<Transmit>; 16],
    events: VecDeque<Event>,
}

impl Node {
    /// A node, with nothing outstanding.
    pub fn new(mut config: NodeConfig) -> Self {
        // A time of zero would send each retransmission, or heartbeat, at once.
        const LEAST: Duration = Duration::from_millis(1);
        config.t1 = config.t1.max(LEAST);
        config.heartbeat = config.heartbeat.map(|interval| interval.max(LEAST));
        let sessions = Sessions::new(config.request_port);
        Self {
            config,
            next_sequence: 1,
            next_request: 1,
            next_seid: 1,
            next_inbound: 1,
            next_mark: 1,
            reserved: BTreeSet::new(),
            outstanding: BTreeMap::new(),
            ids: BTreeMap::new(),
            beating: BTreeSet::new(),
            deadlines: BTreeSet::new(),
            finished: BTreeMap::new(),
            finishing: BTreeSet::new(),
            answers: Answers::default(),
            associations: BTreeMap::new(),
            by_peer: BTreeMap::new(),
            sessions,
            recovery: BTreeMap::new(),
            aging: BTreeMap::new(),
            next_turn: 0,
            heartbeats: Heartbeats::default(),
            load: BTreeMap::new(),
            overload: Overloads::default(),
            orphans: BTreeSet::new(),
            features: Features::default(),
            transmits: Default::default(),
            events: VecDeque::new(),
        }
    }

    /// What the node is.
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// A fresh mark for a session the node creates.
    fn mark(&mut self) -> u64 {
        let mark = self.next_mark;
        self.next_mark = self.next_mark.wrapping_add(1);
        mark
    }

    /// What the node dropped to bound what it keeps.
    pub fn counters(&self) -> Counters {
        Counters {
            evicted: self.answers.evicted,
            refused: self.answers.refused,
        }
    }

    /// The next datagram to send: those of the highest priority first.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.transmits.iter_mut().find_map(VecDeque::pop_front)
    }

    /// The next event.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// When [`handle_timeout`](Self::handle_timeout) is next due: a retransmission, a
    /// heartbeat, the end of an overload, or of a session whose deletion waits for its last
    /// usage reports.
    pub fn poll_timeout(&self) -> Option<Duration> {
        let retransmission = self.deadlines.first().map(|(deadline, _)| *deadline);
        let heartbeat = self.heartbeats.first();
        let overload = self.overload.first_end();
        let session = self.sessions.first_end();
        [retransmission, heartbeat, overload, session]
            .into_iter()
            .flatten()
            .min()
    }

    /// Do what is due at `now`.
    pub fn handle_timeout(&mut self, now: Duration) {
        self.prune(now);
        while let Some(&(deadline, sequence)) = self.deadlines.first()
            && deadline <= now
        {
            self.deadlines.pop_first();
            let Some(request) = self.outstanding.get_mut(&sequence) else {
                continue;
            };
            if request.attempts < self.config.n1 {
                request.attempts += 1;
                request.deadline = now.saturating_add(self.config.t1);
                self.deadlines.insert((request.deadline, sequence));
                let transmit = Transmit {
                    to: request.to,
                    priority: request.priority,
                    octets: request.octets.clone(),
                };
                self.queue(transmit);
                continue;
            }
            let request = self.take(sequence).expect("due");
            self.finish(now, sequence, request.to, true);
            match request.heartbeat {
                true => self.events.push_back(Event::PeerDown { peer: request.to }),
                false => {
                    self.abandon(&request);
                    self.events.push_back(Event::Timeout {
                        request: request.id,
                        to: request.to,
                    });
                }
            }
        }
        for peer in self.heartbeats.due(now) {
            // A peer without an association has no more heartbeats.
            if self.association_of(peer).is_none() {
                self.heartbeats.remove(&peer);
                continue;
            }
            let interval = self.config.heartbeat.unwrap_or(Duration::MAX);
            self.heartbeats.insert(peer, now.saturating_add(interval));
            if !self.beating.contains(&peer) {
                let request =
                    HeartbeatRequest::new(RecoveryTimeStamp::new(self.config.recovery_time_stamp));
                let message = Message {
                    header: Header::node(0),
                    body: request.into(),
                };
                let heartbeat = Pending {
                    heartbeat: true,
                    ..Pending::default()
                };
                let _ = self.send(now, peer, message, heartbeat);
            }
        }
        for scope in self.overload.ended(now) {
            if let Some(overload) = self.overload.remove(&scope) {
                self.events.push_back(Event::OverloadEnded {
                    peer: overload.peer,
                });
            }
        }
        self.prune_controls();
    }

    /// The association with a peer, of its address, or of its address and port without
    /// `request_port` (§4.2.2). A peer has one: a setup of another Node ID ends it.
    pub fn association(&self, peer: SocketAddr) -> Option<&Association> {
        self.association_of(peer)
    }

    /// The session of a local SEID.
    pub fn session(&self, local_seid: u64) -> Option<&Session> {
        self.sessions.get(&local_seid)
    }

    /// The sessions of the node, by their local SEIDs, in their order.
    pub fn sessions(&self) -> impl Iterator<Item = (u64, &Session)> + '_ {
        self.sessions.iter().map(|(seid, session)| (*seid, session))
    }

    /// The associations of the node.
    pub fn associations(&self) -> impl Iterator<Item = &Association> + '_ {
        self.associations.values()
    }

    /// Forget what has outlived `keep`.
    fn prune(&mut self, now: Duration) {
        while let Some(&(until, sequence, peer)) = self.finishing.first()
            && until <= now
        {
            self.finishing.pop_first();
            self.finished.remove(&(sequence, peer));
        }
        self.answers.prune(now);
        self.sessions.prune(now);
        for local_seid in self.sessions.ended(now) {
            self.events.push_back(Event::SessionEnded { local_seid });
        }
        self.prune_controls();
    }
}
