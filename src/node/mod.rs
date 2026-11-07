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

//! A PFCP entity on one local endpoint, without I/O: datagrams and time go in, and
//! datagrams to send, events and the next timer come out. An SMF, a UPF and a test tool
//! share it, each with its own socket loop.
//!
//! What it does for its caller:
//!
//! - **Reliable delivery (§6.4).** It gives each request a sequence number that no
//!   outstanding request of the endpoint has, and sends it again after T1 without a
//!   response, the same octets, up to N1 times. It matches each response by its sequence
//!   number, its peer and its type, and answers a retransmitted request with the response
//!   that it gave, byte for byte, telling its caller ([`Event::Retransmission`]).
//! - **Heartbeat (§6.2.2).** It answers each Heartbeat Request, even from an unknown
//!   peer, sends its own to the associated peers, and says when a peer stops answering
//!   or restarts.
//! - **Associations (§6.2.6 to §6.2.8).** It keeps the associations that a successful
//!   setup makes, an update changes and a release ends, with the sessions of each.
//! - **Sessions.** It gives the local SEIDs, keeps the peer's SEID of each session,
//!   answers a session that it does not have with "Session context not found", and a
//!   session without an association with "No established PFCP Association".
//! - **Load and overload control (§6.2.3, §6.2.4).** It keeps the latest information of
//!   each peer by its sequence number, ends an overload when its period of validity
//!   expires, and throttles the session requests to an overloaded peer with the "Loss"
//!   algorithm, sparing the priority ones.
//! - **Message priority (§6.2.4.5).** A response has the priority of its request, a
//!   request without one the default priority, and the highest priorities are sent first.
//! - **What a peer does wrong** is an [`Event::Violation`]: the node does what the clause
//!   says (discards a duplicate response, answers an unknown session), and reports it.
//!
//! What it answers itself is what the clauses leave no choice in: a heartbeat; a
//! request of the wrong direction, discarded; one that does not decode, "Invalid
//! length"; an establishment whose CP F-SEID has SEID 0, "Mandatory IE incorrect"; a
//! session or node request of a peer without an association, or of a session
//! that the peer does not have, as above; and, but with the [`SmfSet`] of the node, the
//! requests that §5.22 lets come from another SMF of a set, which it otherwise takes as
//! those of any peer. Every other request is its caller's to accept or reject, through
//! [`Node::respond`], and so is an association, and a session.

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
use crate::values_gen::*;

use state::{
    Answers, Change, Digest, Effect, Heartbeats, Outstanding, Overloads, Scope, Sessions, SetOf,
};
pub use state::{Association, LoadControl, OverloadControl, Session};

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
    /// T1, after which a request without a response is sent again (§6.4): at least a
    /// millisecond, which a shorter one is taken as.
    pub t1: Duration,
    /// N1, how many times a request is sent again (§6.4).
    pub n1: u8,
    /// How often a Heartbeat Request goes to each associated peer: `None` for never, and
    /// at least every millisecond, which a shorter interval is taken as.
    pub heartbeat: Option<Duration>,
    /// How long an answered request is kept, to answer its retransmissions, a request
    /// waits for the caller's answer, past which the node forgets it, and a finished
    /// request is kept, to tell a duplicate or late response. Its peer has given the
    /// request up after (N1 + 1) x T1 of its own.
    pub keep: Duration,
    /// The priority of a request that has none (§6.2.4.5.2): 0 the highest, to 15.
    pub default_priority: u8,
    /// Throttle the session requests to an overloaded peer (§6.2.4.4).
    pub throttling: bool,
    /// The priorities, from 0 up to this one, of the requests that throttling spares
    /// while it can (§6.2.4.5.1): `None` for none.
    pub priority_up_to: Option<u8>,
    /// How many requests of the peers the node keeps for their retransmissions, and how
    /// many Recovery Time Stamps of peers without an association, so that a flood of
    /// datagrams bounds what the node holds. A request that waits for its answer stays
    /// until the caller answers or forgets it ([`Node::forget`]), or `keep` has passed;
    /// beyond it, a rejection of
    /// the node's own goes first, then the oldest answer, and a request that finds every
    /// place waiting is dropped: [`Node::counters`] counts both. A Heartbeat Request is
    /// answered from the state, and not kept.
    pub capacity: usize,
    /// The UDP port of the requests that the node sends to a peer of its own accord, a
    /// heartbeat or a session request: 8805 (§4.2.2), whatever port the peer sends its
    /// requests from, and a peer is of its IP address. `None` for the port that the
    /// peer's request came from, for peers on ports of their own, as in a test: a peer is
    /// then of its address and its port. Its association, its sessions, its Recovery Time
    /// Stamp and its load and overload are of the peer so told apart.
    pub request_port: Option<u16>,
    /// How many requests of hosts without an association wait for their answer at once:
    /// Association Setup Requests, the session requests of a host of a session's F-SEID
    /// address, with SSET those of an SMF of the set, and on an SMF of SSET, or of MPAS
    /// and `other_entities`, a UP function's report of SEID 0 that hands a session over.
    /// Beyond, one is dropped before it is decoded, as [`Counters::refused`] counts, and
    /// its sender sends it again.
    pub strangers: usize,
    /// The SMF sets that the node takes part in, as its CP or UP Function Features say
    /// them (§8.2.25, §8.2.58), which the caller writes in its Association Setup
    /// messages too: without either, the node takes the requests of a set as those of
    /// any peer.
    pub smf_set: SmfSet,
    /// A CP function of several PFCP entities, each a node with associations of its own,
    /// of which this is one. With MPAS, a UP function hands a session over to another
    /// entity of the same SMF too (§5.22.3 bullets 5 and 6), which has not the
    /// association that the entity that set it up holds: its report of SEID 0 then goes
    /// to the caller from a host without an association with this node too, with
    /// [`Inbound::of_smf_set`], for the caller to take only from a UP function that has
    /// an association with an entity of its SMF. Without, the node answers it "No
    /// established PFCP Association".
    pub other_entities: bool,
}

/// The features of the SMF sets of §5.22 that a node takes part in, as the bits SSET and
/// MPAS of its CP or UP Function Features. The node delivers to its caller the requests
/// that a set lets come from another SMF of the set than a session's or an
/// association's, with [`Inbound::of_smf_set`], for the caller to take, redirect or
/// reject; and a release keeps the sessions that the set keeps.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SmfSet {
    /// SSET (§5.22.2): one association for the set, whose established sessions any SMF of
    /// the set may modify or delete, and which it may update or release, with an
    /// association of its own or not. An establishment needs an association.
    pub sset: bool,
    /// MPAS (§5.22.3): an association for each SMF of the set, of the same SMF Set ID,
    /// any of which may modify or delete the sessions of another, and whose sessions are
    /// kept while one of the set remains (§6.2.8). A UP function hands a session over to
    /// an SMF of the set that it has an association with, which a node of the SMF sees
    /// when it holds the association; an SMF of several PFCP entities, each a node, says
    /// so with [`NodeConfig::other_entities`].
    pub mpas: bool,
}

impl NodeConfig {
    /// A node of `node_id`: T1 of 3 s, N1 of 3, a heartbeat every 60 s, answers kept for
    /// 24 s, default priority 8, throttling on, no priority spared, room for 65,536
    /// requests of the peers and 16 of hosts without an association, requests to port
    /// 8805, no SMF set, and no other PFCP entity.
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
            smf_set: SmfSet::default(),
            other_entities: false,
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
    /// A request of another SMF of a set than the session's or the association's, which
    /// the node's [`SmfSet`] lets come (§5.22): a modification or deletion of a session
    /// from another association of the set (MPAS), a request of an SMF of the set without
    /// an association (SSET), or a UP function's request of SEID 0 with the CP F-SEID of
    /// the previous SMF, which hands a session over ([`Node::adopt_session`]). With
    /// [`NodeConfig::other_entities`], the UP function of such a handover may have no
    /// association with the node, and the caller takes the session only if it has one
    /// with another PFCP entity of the SMF.
    pub of_smf_set: bool,
    /// The request, of all that the node gave the caller.
    pub(crate) id: u64,
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
    /// A session request, or a node related request of a node, from a peer without an
    /// association, or that names the Node ID of another's (§6.2.6): answered with "No
    /// established PFCP Association". A host without an association is taken for the
    /// sessions whose F-SEID has its address, with SSET as an SMF of the set, and, by an
    /// SMF of SSET, for a report of SEID 0 that hands a session over (§5.22.2): with
    /// MPAS alone, the UP function that hands it over has an association (§5.22.3).
    SessionWithoutAssociation,
    /// A session request of a SEID that is of no established session of the peer:
    /// answered with "Session context not found" (§7.2.2.4.2).
    UnknownSeid,
    /// An association update or release of a Node ID that the node has no association
    /// with, or whose association is not the peer's: answered with "No established PFCP
    /// Association" (§6.2.7, §6.2.8).
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
    /// Session messages of different peers bundled together (§6.5): discarded.
    BundledPeers,
    /// Messages bundled by a peer without an association, which could not have agreed on
    /// bundling (§6.5): discarded.
    BundledWithoutAssociation,
    /// A peer's SEID of 0, which says that it is not known (§7.2.2.4.2): an
    /// establishment's response that gives it establishes no session, an establishment
    /// that gives it is answered "Mandatory IE incorrect", and a modification or a
    /// response that moves a session to it leaves the session's.
    SeidZero,
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
        /// The local SEIDs of its sessions that its SMF set keeps, with MPAS (§6.2.8): on a
        /// UP function those that another association of the set takes, on a CP function
        /// all of them when the UP function announced MPAS in its UP Function Features,
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
    let address = match from.ip() {
        IpAddr::V4(_) => fseid.ipv4.map(IpAddr::V4),
        IpAddr::V6(_) => fseid.ipv6.map(IpAddr::V6),
    };
    SocketAddr::new(address.unwrap_or(from.ip()), from.port())
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
    /// when the node last had it.
    recovery: BTreeMap<SocketAddr, (u32, Duration)>,
    heartbeats: Heartbeats,
    load: BTreeMap<Scope, LoadControl>,
    overload: Overloads,
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
            sessions: Sessions::default(),
            recovery: BTreeMap::new(),
            heartbeats: Heartbeats::default(),
            load: BTreeMap::new(),
            overload: Overloads::default(),
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
    /// heartbeat, or the end of an overload.
    pub fn poll_timeout(&self) -> Option<Duration> {
        let retransmission = self.deadlines.first().map(|(deadline, _)| *deadline);
        let heartbeat = self.heartbeats.first();
        let overload = self.overload.first_end();
        [retransmission, heartbeat, overload]
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
            let interval = self.config.heartbeat.unwrap_or(Duration::MAX);
            self.heartbeats.insert(peer, now.saturating_add(interval));
            if !self.beating.contains(&peer) {
                let request =
                    HeartbeatRequest::new(RecoveryTimeStamp::new(self.config.recovery_time_stamp));
                let message = Message {
                    header: Header::node(0),
                    body: request.into(),
                };
                let _ = self.send(now, peer, message, true, None, None, Change::Nothing);
            }
        }
        for scope in self.overload.ended(now) {
            if let Some(overload) = self.overload.remove(&scope) {
                self.events.push_back(Event::OverloadEnded {
                    peer: overload.peer,
                });
            }
        }
    }

    /// Send a request to `to`, with the next sequence number. A session request needs an
    /// association with the peer, but, with SSET, the modification or deletion of an
    /// established session (§5.22.2), and may be throttled for its overload. The SEID of the
    /// CP F-SEID of an establishment is the local SEID of its session, from
    /// [`new_session`](Self::new_session) or of the caller's own, which no other session
    /// then takes until the establishment ends.
    ///
    /// # Errors
    ///
    /// A session request without an association or throttled, a message that is no
    /// request or that the function of the node does not send, an establishment of a
    /// local SEID of 0 or that a session or another establishment has, or a modification
    /// to it, no free sequence number, and a message that does not encode.
    pub fn request(
        &mut self,
        now: Duration,
        to: SocketAddr,
        message: Message,
    ) -> Result<RequestId, NodeError> {
        let local_seid = match &message.body {
            Body::SessionEstablishmentRequest(request) => {
                request.cp_f_seid.as_ref().and_then(|f_seid| f_seid.seid)
            }
            // A request of SEID 0 to another SMF of a set, with the CP F-SEID of the
            // previous one, is of the session of that F-SEID (§5.22.2, bullet 4).
            Body::SessionReportRequest(request)
                if message.header.seid == Some(0) && request.old_cp_f_seid.is_some() =>
            {
                request.old_cp_f_seid.as_ref().and_then(|old| {
                    let address = [old.ipv4.map(IpAddr::V4), old.ipv6.map(IpAddr::V6)];
                    self.sessions.of_peer_seid(old.seid?).find(|local| {
                        self.sessions
                            .get(local)
                            .is_some_and(|session| address.contains(&Some(session.peer.ip())))
                    })
                })
            }
            _ => message
                .header
                .seid
                .and_then(|peer_seid| self.local_seid_of(to, peer_seid)),
        };
        self.request_of(now, to, message, local_seid)
    }

    fn request_of(
        &mut self,
        now: Duration,
        to: SocketAddr,
        message: Message,
        local_seid: Option<u64>,
    ) -> Result<RequestId, NodeError> {
        let message_type = message.body.message_type();
        if !is_request(message_type) {
            return Err(NodeError::NotARequest);
        }
        if !sends(self.config.function, message_type) {
            return Err(NodeError::WrongDirection);
        }
        let establishment = message_type == 50;
        if establishment && local_seid == Some(0) {
            return Err(NodeError::SeidZero);
        }
        if establishment && local_seid.is_some_and(|seid| self.in_use(seid)) {
            return Err(NodeError::SeidInUse);
        }
        let mut change = Change::Nothing;
        if !is_node_related(message_type) {
            // The association of the session, whose F-SEID may have another address; or,
            // with SSET, the modification or deletion of an established session of the
            // set, which the one association that a different SMF of the set holds lets
            // this SMF ask without one of its own (§5.22.2 bullet 3). An establishment
            // needs an association (§6.2.6.2.1).
            let session = local_seid.and_then(|seid| self.sessions.get(&seid));
            let of_session = session
                .is_some_and(|session| self.associations.contains_key(&session.node))
                || (self.config.smf_set.sset
                    && self.config.function == Function::Cp
                    && matches!(message_type, 52 | 54)
                    && session.is_some_and(|session| session.peer_seid.is_some()));
            if !of_session && self.association_of(to).is_none() {
                return Err(NodeError::NoAssociation);
            }
            let priority = message
                .header
                .priority
                .unwrap_or(self.config.default_priority);
            if self.throttle(to, local_seid, priority) {
                return Err(NodeError::Throttled);
            }
            change = match &message.body {
                Body::SessionDeletionRequest(_) => Change::Ends,
                Body::SessionReportRequest(request)
                    if request
                        .pfcpsrreq_flags
                        .as_ref()
                        .is_some_and(|flags| flags.psdbu) =>
                {
                    Change::Ends
                }
                Body::SessionModificationRequest(request) => {
                    match request.cp_f_seid.as_ref().and_then(|f_seid| f_seid.seid) {
                        Some(0) => return Err(NodeError::SeidZero),
                        // Not to the SEID of another session; to one of new_session, yes.
                        Some(seid) if self.in_use(seid) && Some(seid) != local_seid => {
                            return Err(NodeError::SeidInUse);
                        }
                        Some(seid) if Some(seid) != local_seid => Change::Moves(seid),
                        _ => Change::Nothing,
                    }
                }
                _ => Change::Nothing,
            };
        }
        // The SEID of an establishment, even one of the caller's own, and the new SEID of a
        // move, are theirs until they end.
        let held = match change {
            Change::Moves(new) => Some(new),
            _ => local_seid.filter(|_| establishment),
        };
        // The session that the request is of, which its response acts on: that of an
        // establishment is the one that it holds.
        let mark = match local_seid.and_then(|seid| self.sessions.get(&seid)) {
            Some(session) => Some(session.mark),
            None if establishment && local_seid.is_some() => Some(self.mark()),
            None => None,
        };
        let id = self.send(now, to, message, false, local_seid, mark, change)?;
        if let Some(seid) = held {
            if !self.sessions.contains_key(&seid) {
                let node = self
                    .association_of(to)
                    .map(|association| association.key.clone())
                    .unwrap_or_default();
                let mark = match establishment {
                    true => mark.expect("of the establishment"),
                    false => self.mark(),
                };
                let session = Session {
                    peer: to,
                    peer_seid: None,
                    node,
                    reserved: false,
                    mark,
                };
                self.sessions.insert(seid, session);
            }
            self.sessions.reserve(seid, true);
        }
        Ok(id)
    }

    /// Whether a local SEID is of a session, of an outstanding establishment or move, or
    /// the previous one of a session that moved.
    fn in_use(&self, seid: u64) -> bool {
        self.sessions
            .get(&seid)
            .is_some_and(|session| session.peer_seid.is_some() || session.reserved)
            || self.sessions.is_alias(seid)
    }

    /// The local SEID of the session that a request of the node is of, by its mark, while
    /// it lasts: wherever it moved since, and not a session that took its SEID after it
    /// ended (§6.3.3, Table 7.5.4.1-1 NOTE 2).
    fn session_of(&self, request: &Outstanding) -> Option<u64> {
        self.sessions.of_mark(request.mark?)
    }

    /// The local SEID of the session that a request of a peer is of, by its mark, while it
    /// lasts: wherever it moved since the request came, and not a session that took its SEID
    /// after it ended. A request that came of no session is of the one of its `seid`, which
    /// the caller sets to answer a handover ([`adopt_session`](Self::adopt_session)).
    fn answered_session(&self, request: &Inbound) -> Option<u64> {
        match request.mark {
            Some(mark) => self.sessions.of_mark(mark),
            None => self.sessions.resolve(request.seid?),
        }
    }

    /// A request that ends without its response, or with a rejection: an establishment
    /// leaves no session, and a move frees its new SEID.
    fn abandon(&mut self, request: &Outstanding) {
        let held = match request.change {
            Change::Moves(new) => Some(new),
            _ if request.message_type == 50 => self.session_of(request),
            _ => None,
        };
        if let Some(seid) = held
            && self
                .sessions
                .get(&seid)
                .is_some_and(|session| session.peer_seid.is_none())
        {
            self.sessions.remove(&seid);
        }
    }

    /// Send a session request to the peer of the session of `local_seid`, to its SEID.
    ///
    /// # Errors
    ///
    /// As [`request`](Self::request), and a session that the node does not have.
    pub fn session_request(
        &mut self,
        now: Duration,
        local_seid: u64,
        body: impl Into<Body>,
    ) -> Result<RequestId, NodeError> {
        let session = self.sessions.get(&local_seid).ok_or(NodeError::NoSession)?;
        let (peer, peer_seid) = (session.peer, session.peer_seid.unwrap_or(0));
        self.request_of(
            now,
            peer,
            Message {
                header: Header::session(peer_seid, 0),
                body: body.into(),
            },
            Some(local_seid),
        )
    }

    /// Stop sending a request again, and forget it: a response that comes after is late.
    /// `false` for a request that is not outstanding.
    pub fn cancel(&mut self, now: Duration, request: RequestId) -> bool {
        let Some(&sequence) = self.ids.get(&request) else {
            return false;
        };
        let outstanding = self.take(sequence).expect("outstanding");
        self.deadlines.remove(&(outstanding.deadline, sequence));
        self.finish(now, sequence, outstanding.to, true);
        self.abandon(&outstanding);
        true
    }

    /// A new local SEID, non-zero, of no session and given by no call before: the SEID of
    /// the F-SEID that the caller then sends. The node keeps nothing of it: the
    /// establishment that sends it, or the answer that accepts one, makes the session.
    pub fn new_session(&mut self) -> u64 {
        while self.next_seid == 0
            || self.sessions.contains_key(&self.next_seid)
            || self.sessions.is_alias(self.next_seid)
        {
            self.next_seid = self.next_seid.wrapping_add(1);
        }
        let seid = self.next_seid;
        self.next_seid = self.next_seid.wrapping_add(1);
        seid
    }

    /// A session that the node did not establish, of the caller's own: one that an SMF of
    /// a set takes over (§5.22), with the UP function at `peer` and its SEID. The node
    /// then takes its requests and sends the caller's. To answer the request that handed
    /// the session over to the session's SEID, the caller sets that request's
    /// [`Inbound::seid`] to the local SEID before [`respond`](Self::respond).
    ///
    /// # Errors
    ///
    /// A local or peer's SEID of 0, and a local SEID that another session has.
    pub fn adopt_session(
        &mut self,
        local_seid: u64,
        peer: SocketAddr,
        peer_seid: u64,
    ) -> Result<(), NodeError> {
        if local_seid == 0 || peer_seid == 0 {
            return Err(NodeError::SeidZero);
        }
        if self.in_use(local_seid) || self.sessions.contains_key(&local_seid) {
            return Err(NodeError::SeidInUse);
        }
        let node = self
            .association_of(peer)
            .map(|association| association.key.clone())
            .unwrap_or_default();
        let session = Session {
            peer,
            peer_seid: Some(peer_seid),
            node,
            reserved: false,
            mark: self.mark(),
        };
        self.sessions.insert(local_seid, session);
        Ok(())
    }

    /// End the session of `local_seid` without a procedure: one that a Session Set
    /// Deletion, a restart of the peer or the caller's own state ends.
    pub fn end_session(&mut self, local_seid: u64) -> Option<Session> {
        self.sessions.remove(&local_seid)
    }

    /// End every session with `peer`, as after its restart: those of its association,
    /// whatever the address of their F-SEIDs, and those of its address. Their local
    /// SEIDs.
    pub fn end_sessions_of(&mut self, peer: SocketAddr) -> Vec<u64> {
        let key = self
            .association_of(peer)
            .map(|association| association.key.clone());
        let ended: Vec<u64> = self
            .sessions
            .iter()
            .filter(|(_, session)| {
                self.same_peer(session.peer, peer) || key.as_ref() == Some(&session.node)
            })
            .map(|(seid, _)| *seid)
            .collect();
        for seid in &ended {
            self.sessions.remove(seid);
        }
        ended
    }

    /// End the association with `peer`, as [`association`](Self::association) finds it,
    /// without a procedure, with its
    /// sessions, as after [`Event::PeerDown`]: an [`Event::Released`] says what ended.
    /// `false` for a peer without an association.
    pub fn end_association(&mut self, peer: SocketAddr) -> bool {
        let Some(key) = self
            .association_of(peer)
            .map(|association| association.key.clone())
        else {
            return false;
        };
        self.release(&key);
        true
    }

    /// Answer a request with its response, with its sequence number and priority, to the
    /// SEID of its session; the answer is kept for the request's retransmissions.
    ///
    /// # Errors
    ///
    /// A body of another type than the response of the request, a request answered
    /// already or no longer waiting, an establishment's answer of a local SEID of 0 or of
    /// another session, and a body that does not encode.
    pub fn respond(
        &mut self,
        now: Duration,
        request: &Inbound,
        body: impl Into<Body>,
    ) -> Result<(), NodeError> {
        let body = body.into();
        if body.message_type() != request.message_type + 1 {
            return Err(NodeError::WrongResponse);
        }
        let key = (request.from, request.sequence);
        if self.answers.answered(&key, request.id) {
            return Err(NodeError::Answered);
        }
        if !self.answers.waits(&key, request.id) {
            return Err(NodeError::Forgotten);
        }
        if let Body::SessionEstablishmentResponse(response) = &body
            && let Some(seid) = response.up_f_seid.as_ref().and_then(|f_seid| f_seid.seid)
        {
            if seid == 0 {
                return Err(NodeError::SeidZero);
            }
            if self.in_use(seid) {
                return Err(NodeError::SeidInUse);
            }
        }
        self.respond_with(
            now,
            request,
            self.response_header(request),
            body,
            Delivery::Send,
        )
    }

    /// The header of the response to `request`: its sequence number, the peer's SEID of
    /// its session, and its priority.
    fn response_header(&self, request: &Inbound) -> Header {
        if is_node_related(request.message_type) {
            return Header::node(request.sequence);
        }
        let seid = match request.message_type {
            50 => request.peer_seid,
            _ => self
                .answered_session(request)
                .and_then(|local| self.sessions.get(&local))
                .and_then(|session| session.peer_seid),
        };
        let mut header = Header::session(seid.unwrap_or(0), request.sequence);
        if request.prioritized {
            header.priority = Some(request.priority);
        }
        header
    }

    /// Answer a request with a message as it is, delivered as `delivery` says: a probe,
    /// which may answer any number of times, and with anything. Its first answer of the
    /// type of the request's response alone changes the node, whenever the others come:
    /// the peer discards one of another type, and takes the next (§7.6.5). It does while
    /// the node keeps the request: an answer after [`Delivery::Forget`], which forgets it,
    /// or once the node forgot it, `keep` after it came, is sent and changes nothing. A
    /// later answer replaces the one kept for the retransmissions while the node keeps it.
    ///
    /// # Errors
    ///
    /// A message that does not encode.
    pub fn respond_message(
        &mut self,
        now: Duration,
        request: &Inbound,
        message: Message,
        delivery: Delivery,
    ) -> Result<(), NodeError> {
        self.respond_with(now, request, message.header, message.body, delivery)
    }

    /// Answer a request, and keep the answer for its retransmissions. Its first answer of
    /// the response's type alone, which the node knows by the request that it keeps,
    /// changes the node: a probe may answer again, and once the node no longer keeps the
    /// request, its answer changes nothing.
    fn respond_with(
        &mut self,
        now: Duration,
        request: &Inbound,
        header: Header,
        body: Body,
        delivery: Delivery,
    ) -> Result<(), NodeError> {
        let message = Message { header, body };
        let octets = message.encode()?;
        let key = (request.from, request.sequence);
        if delivery == Delivery::Forget {
            // A responder that lost its state: no answer kept, and nothing changed.
            self.answers.forget(&key, request.id);
            return Ok(());
        }
        let expires = now.saturating_add(self.config.keep);
        // One of another type the peer discards (§7.6.5): it changes nothing here either.
        let effective = message.body.message_type() == request.message_type + 1;
        if self
            .answers
            .answer(key, request.id, octets.clone(), expires, effective)
        {
            self.answered_effects(now, request, &message);
        }
        if delivery == Delivery::Send {
            self.queue(Transmit {
                to: request.from,
                priority: request.priority,
                octets: octets.into(),
            });
        }
        Ok(())
    }

    /// Forget a request that the caller does not answer, as one that it dropped: a
    /// retransmission of it comes again as a request.
    pub fn forget(&mut self, request: &Inbound) {
        let key = (request.from, request.sequence);
        if self.answers.waits(&key, request.id) {
            self.answers.forget(&key, request.id);
        }
    }

    /// A sequence number that the node will not give, for a probe that sends its own,
    /// until [`release_sequence`](Self::release_sequence) gives it back.
    ///
    /// # Errors
    ///
    /// Every sequence number is outstanding, reserved or recent.
    pub fn reserve_sequence(&mut self) -> Result<u32, NodeError> {
        let sequence = self.next_free_sequence()?;
        self.reserved.insert(sequence);
        Ok(sequence)
    }

    /// Give back a sequence number of [`reserve_sequence`](Self::reserve_sequence): the
    /// node gives it again. `false` for one that is not reserved.
    pub fn release_sequence(&mut self, sequence: u32) -> bool {
        self.reserved.remove(&sequence)
    }

    /// Send octets as they are: no sequence number, no retransmission, no matching. A
    /// response to a reserved sequence number is then a violation, as any unknown one.
    pub fn send_raw(&mut self, to: SocketAddr, priority: u8, octets: Vec<u8>) {
        self.queue(Transmit {
            to,
            priority,
            octets: octets.into(),
        });
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

    /// The latest load control information of a peer, by its Node ID (§6.2.3.3.1).
    pub fn load_control(&self, peer: SocketAddr) -> Option<LoadControl> {
        let node = self
            .association_of(peer)
            .map(|association| Scope::Node(association.key.clone()));
        node.and_then(|scope| self.load.get(&scope)).copied()
    }

    /// The overload control information that still holds for the requests to `peer`: of
    /// its address, as the UP F-SEID of a session has it, or of its Node ID (§6.2.4.3.1).
    pub fn overload_control(&self, peer: SocketAddr) -> Option<OverloadControl> {
        let node = self
            .association_of(peer)
            .map(|association| Scope::Node(association.key.clone()));
        self.overload
            .get(&Scope::Address(self.peer_key(peer)))
            .or_else(|| node.and_then(|scope| self.overload.get(&scope)))
            .copied()
    }

    /// Take a datagram that `from` sent: each of its messages, bundled with the FO flag,
    /// on its own (§6.5).
    pub fn handle_datagram(&mut self, now: Duration, from: SocketAddr, octets: &[u8]) {
        self.prune(now);
        let Some((header, message_type, _)) = Header::decode(octets) else {
            // Too short for a header: discarded (§7.6.3).
            self.events.push_back(Event::Malformed {
                from,
                error: crate::Error::TooShort {
                    octets: octets.len(),
                },
            });
            return;
        };
        if header.version != 1 {
            // Answered once, and the rest of the datagram, whose framing the node does
            // not know, discarded (§7.6.2).
            self.other_version(now, from, octets, header, message_type);
            return;
        }
        let parts = datagram_parts(octets);
        let bundled = parts.len() > 1;
        if bundled && self.association_of(from).is_none() {
            self.violation(from, ViolationKind::BundledWithoutAssociation, octets);
            return;
        }
        let mut peers = BTreeSet::new();
        for this in parts {
            let Some((header, message_type, _)) = Header::decode(this) else {
                let error = crate::Error::TooShort { octets: this.len() };
                self.malformed(now, from, error);
                continue;
            };
            if header.version != 1 {
                // As the first: answered, and the rest discarded (§7.6.2).
                self.other_version(now, from, this, header, message_type);
                return;
            }
            if bundled && is_node_related(message_type) {
                self.violation(from, ViolationKind::BundledNodeMessage, this);
                continue;
            }
            if bundled
                && let Some(session) = header
                    .seid
                    .and_then(|seid| self.sessions.resolve(seid))
                    .and_then(|seid| self.sessions.get(&seid))
            {
                peers.insert(self.peer_key(session.peer));
                if peers.len() > 1 {
                    self.violation(from, ViolationKind::BundledPeers, this);
                    continue;
                }
            }
            let Some(of_smf_set) = self.screen(now, from, this, header, message_type) else {
                continue;
            };
            match Message::decode(this) {
                Ok(message) => match is_request(message_type) {
                    true => self.handle_request(now, from, this, message, of_smf_set),
                    false => self.handle_response(now, from, this, message),
                },
                Err(error) => self.malformed(now, from, error),
            }
        }
    }

    /// What the node tells from the header of a message, and from the IEs that name the
    /// peer of a request, before it decodes the rest: a message that it discards or
    /// rejects costs it no more than its octets. `None` for a message that it handled, and
    /// whether a request is of another SMF of a set (§5.22) for one to decode.
    fn screen(
        &mut self,
        now: Duration,
        from: SocketAddr,
        octets: &[u8],
        header: Header,
        message_type: u8,
    ) -> Option<bool> {
        if message_type_info(message_type).is_none() {
            self.violation(from, ViolationKind::UnknownMessage, octets);
            return None;
        }
        let sequence = header.sequence;
        if !is_request(message_type) {
            if message_type == 11 {
                self.version_not_supported(now, from, octets);
                return None;
            }
            let kind = match self.outstanding.get(&sequence) {
                None => Some(match self.finished.get(&(sequence, from)) {
                    Some((_, true)) => ViolationKind::LateResponse,
                    Some((_, false)) => ViolationKind::DuplicateResponse,
                    None => ViolationKind::UnknownSequence,
                }),
                Some(request) if request.to != from => Some(ViolationKind::WrongPeer),
                Some(request) if message_type != request.message_type + 1 => {
                    Some(ViolationKind::WrongResponseType)
                }
                Some(_) => None,
            };
            if let Some(kind) = kind {
                self.violation(from, kind, octets);
                return None;
            }
            return Some(false);
        }
        if !self.peer_sends(message_type) {
            self.violation(from, ViolationKind::WrongDirection, octets);
            return None;
        }
        let priority = header.priority.unwrap_or(self.config.default_priority);
        if let Some(answered) = self.answers.get(&(from, sequence)) {
            match (answered.request == Digest::of(octets), &answered.response) {
                (true, response) => {
                    let answer = response.clone();
                    self.events.push_back(Event::Retransmission {
                        from,
                        sequence,
                        answered: answer.is_some(),
                    });
                    if let Some(answer) = answer {
                        self.queue(Transmit {
                            to: from,
                            priority,
                            octets: answer.into(),
                        });
                    }
                    return None;
                }
                (false, None) => {
                    self.violation(from, ViolationKind::ChangedRetransmission, octets);
                    return None;
                }
                // A new request of a number whose request had its response (§6.4): a
                // restarted peer numbers from the start again.
                (false, Some(_)) => {
                    self.answers.remove(&(from, sequence));
                }
            }
        }
        // What the node answers itself.
        let (node_id, peer_seid) = match message_type {
            7 | 9 | 12 | 14 | 16 | 50 | 56 => names(octets),
            _ => (None, None),
        };
        // Of the host's association: the Node ID that a request names is of it.
        let association = self
            .association_of(from)
            .map(|association| association.key.clone());
        let known_node = match &node_id {
            Some(node_id) => association.as_ref() == Some(&key_of(node_id)),
            None => association.is_some(),
        };
        // A session request is of an established session of the host: of its
        // association, or of the address of its F-SEID.
        let session = header
            .seid
            .and_then(|seid| self.sessions.resolve(seid))
            .and_then(|seid| self.sessions.get(&seid))
            .filter(|session| session.peer_seid.is_some());
        let of_host = session.is_some_and(|session| {
            self.same_peer(session.peer, from) || association.as_ref() == Some(&session.node)
        });
        // What a set lets come from another SMF of the set than the session's or the
        // association's, which the node gives its caller (§5.22.2, §5.22.3).
        let set = self.config.smf_set;
        let of = |key: &[u8]| {
            self.associations
                .get(key)
                .map(|association| &association.set)
        };
        let theirs = association.as_deref().and_then(of);
        let of_smf_set = match message_type {
            // An update or a release of the set's association, by an SMF of the set
            // without one of its own (SSET).
            7 | 9 => {
                let named = node_id.as_ref().and_then(|node_id| of(&key_of(node_id)));
                set.sset && association.is_none() && named.is_some_and(|named| named.sset)
            }
            // A modification or a deletion of a session of another association of the set
            // (MPAS), or by an SMF of the set without one (SSET).
            52 | 54 if !of_host => session.is_some_and(|session| {
                let owner = of(&session.node);
                let mpas = set.mpas
                    && owner.is_some_and(|owner| owner.mpas && owner.id.is_some())
                    && theirs.is_some_and(|theirs| {
                        theirs.mpas && theirs.id == owner.and_then(|owner| owner.id.clone())
                    });
                let sset =
                    set.sset && association.is_none() && owner.is_some_and(|owner| owner.sset);
                mpas || sset
            }),
            // A UP function's request of SEID 0 with the CP F-SEID of the previous SMF,
            // which hands the session over (§5.22.2 and §5.22.3, bullet 5). With SSET the
            // set has one association, which another SMF of the set holds, so the taking
            // SMF needs none of its own; with MPAS, the UP function hands it to an SMF of
            // the set that it has an association with (§5.22.3 bullet 6), which another
            // PFCP entity of the SMF may hold, for the caller to tell.
            56 => {
                (set.sset || set.mpas && (association.is_some() || self.config.other_entities))
                    && header.seid == Some(0)
                    && peer_seid.is_some()
            }
            _ => false,
        };
        let rejection = match message_type {
            _ if of_smf_set => None,
            7 | 9 if !known_node => Some((
                CauseValue::NoEstablishedPfcpAssociation,
                ViolationKind::UnknownNode,
            )),
            3 | 12 | 14 | 16 | 50 if !known_node => Some((
                CauseValue::NoEstablishedPfcpAssociation,
                ViolationKind::SessionWithoutAssociation,
            )),
            // A CP F-SEID of SEID 0 is of no session (§7.2.2.4.2).
            50 if peer_seid == Some(0) => {
                Some((CauseValue::MandatoryIeIncorrect, ViolationKind::SeidZero))
            }
            52 | 54 | 56 if association.is_none() && !of_host => Some((
                CauseValue::NoEstablishedPfcpAssociation,
                ViolationKind::SessionWithoutAssociation,
            )),
            52 | 54 | 56 if !of_host => Some((
                CauseValue::SessionContextNotFound,
                ViolationKind::UnknownSeid,
            )),
            _ => None,
        };
        let Some((cause, kind)) = rejection else {
            // A host without an association has only so many requests waiting; its
            // heartbeat, answered from the state, waits for nothing.
            if message_type != 1
                && association.is_none()
                && self.answers.strangers() >= self.config.strangers
            {
                self.answers.refuse();
                return None;
            }
            return Some(of_smf_set);
        };
        self.violation(from, kind, octets);
        let inbound = Inbound {
            from,
            message_type,
            sequence,
            priority,
            prioritized: header.priority.is_some(),
            seid: header.seid,
            peer_seid,
            node_id,
            mark: None,
            effect: Effect::Nothing,
            of_smf_set: false,
            id: 0,
        };
        let offending = (kind == ViolationKind::SeidZero).then_some(57);
        if let Some(body) = rejection_body(message_type, cause, offending, &self.config.node_id) {
            let mut header = self.response_header(&inbound);
            // The peer's SEID is not known: SEID 0 (§7.2.2.4.2), but that of the CP
            // F-SEID of an establishment without an association, which the SMF matches its
            // response by. A report of SEID 0 carries the previous SMF's SEID in its Old
            // CP F-SEID, not the peer's, so its rejection keeps SEID 0.
            if header.seid.is_some() {
                header.seid = Some(
                    if message_type == 50 && kind == ViolationKind::SessionWithoutAssociation {
                        inbound.peer_seid.unwrap_or(0)
                    } else {
                        0
                    },
                );
            }
            if let Ok(response) = (Message { header, body }).encode() {
                let expires = now.saturating_add(self.config.keep);
                let key = (from, sequence);
                let capacity = self.config.capacity;
                self.answers
                    .reject(key, Digest::of(octets), response.clone(), expires, capacity);
                self.queue(Transmit {
                    to: from,
                    priority,
                    octets: response.into(),
                });
            }
        }
        None
    }

    /// A message of another version than 1 (§7.6.2): a request is answered with a
    /// Version Not Supported Response, a Version Not Supported Response of any version
    /// ends the requests to the peer, and another response ends its request.
    fn other_version(
        &mut self,
        now: Duration,
        from: SocketAddr,
        octets: &[u8],
        header: Header,
        message_type: u8,
    ) {
        let error = crate::Error::Version {
            version: header.version,
        };
        if message_type == 11 {
            // Of the peer's highest version (§7.4.4.7): no fault of its own.
            self.version_not_supported(now, from, octets);
            return;
        }
        if is_request(message_type) {
            let message = Message {
                header: Header::node(header.sequence),
                body: VersionNotSupportedResponse::default().into(),
            };
            if let Ok(octets) = message.encode() {
                self.queue(Transmit {
                    to: from,
                    priority: 0,
                    octets: octets.into(),
                });
            }
        } else {
            self.fail(
                now,
                from,
                header.sequence,
                Failure::Malformed(error.clone()),
            );
        }
        self.events.push_back(Event::Malformed { from, error });
    }

    /// A message that does not decode: a request is answered with "Invalid length" when
    /// its header says what it is (§7.6.3, §7.6.7), and a response ends its request
    /// (§7.6.1).
    fn malformed(&mut self, now: Duration, from: SocketAddr, error: crate::Error) {
        let (header, message_type, offending) = match &error {
            crate::Error::MessageLength {
                header,
                message_type,
                ..
            } => (Some(*header), *message_type, None),
            crate::Error::Ies {
                header,
                message_type,
                fault,
            } => {
                let offending = match fault {
                    crate::IeFault::Length { ie_type, .. } => Some(*ie_type),
                    crate::IeFault::HeaderCut { .. } => None,
                };
                (Some(*header), *message_type, offending)
            }
            _ => (None, 0, None),
        };
        if let Some(header) = header {
            match is_request(message_type) {
                true => self.reject_malformed(from, &header, message_type, offending),
                false => self.fail(
                    now,
                    from,
                    header.sequence,
                    Failure::Malformed(error.clone()),
                ),
            }
        }
        self.events.push_back(Event::Malformed { from, error });
    }

    /// A Version Not Supported Response, whose sequence number says nothing (§7.2.2.2):
    /// every request to the peer fails.
    fn version_not_supported(&mut self, now: Duration, from: SocketAddr, octets: &[u8]) {
        let to_peer: Vec<u32> = self
            .outstanding
            .iter()
            .filter(|(_, request)| request.to == from)
            .map(|(sequence, _)| *sequence)
            .collect();
        if to_peer.is_empty() {
            self.violation(from, ViolationKind::UnknownSequence, octets);
        }
        for sequence in to_peer {
            self.fail(now, from, sequence, Failure::VersionNotSupported);
        }
    }

    /// End the request of `sequence` to `from` without its response.
    fn fail(&mut self, now: Duration, from: SocketAddr, sequence: u32, failure: Failure) {
        if self
            .outstanding
            .get(&sequence)
            .is_none_or(|request| request.to != from)
        {
            return;
        }
        let request = self.take(sequence).expect("outstanding");
        let (id, deadline, heartbeat) = (request.id, request.deadline, request.heartbeat);
        self.deadlines.remove(&(deadline, sequence));
        self.finish(now, sequence, from, false);
        self.abandon(&request);
        if !heartbeat {
            self.events.push_back(Event::Failed {
                request: id,
                to: from,
                failure,
            });
        }
    }

    /// A request that [`screen`](Self::screen) let through.
    fn handle_request(
        &mut self,
        now: Duration,
        from: SocketAddr,
        octets: &[u8],
        message: Message,
        of_smf_set: bool,
    ) {
        let sequence = message.header.sequence;
        let message_type = message.body.message_type();
        self.note_recovery(now, from, &message.body);
        let effect = match &message.body {
            // A PFCP Session Retention Information of a null length keeps every session.
            Body::AssociationSetupRequest(request)
                if request.pfcp_session_retention_information.is_none()
                    && request
                        .raw
                        .iter()
                        .any(|ie| ie.ie_type == 183 && ie.is_null()) =>
            {
                let set = self.set_of(
                    request.cp_function_features.as_ref(),
                    request.up_function_features.as_ref(),
                    request.smf_set_id.as_ref(),
                );
                Effect::Setup(Some(Vec::new()), set)
            }
            Body::AssociationSetupRequest(request) => {
                let set = self.set_of(
                    request.cp_function_features.as_ref(),
                    request.up_function_features.as_ref(),
                    request.smf_set_id.as_ref(),
                );
                let retained =
                    request
                        .pfcp_session_retention_information
                        .as_ref()
                        .map(|retention| {
                            let addresses = retention.cp_pfcp_entity_ip_address.iter();
                            addresses
                                .flat_map(|address| {
                                    [
                                        address.ipv4_address.map(IpAddr::V4),
                                        address.ipv6_address.map(IpAddr::V6),
                                    ]
                                    .into_iter()
                                    .flatten()
                                })
                                .collect()
                        });
                Effect::Setup(retained, set)
            }
            // The set features of the peer's function and the SMF Set ID that an update
            // carries (§5.22.3 bullet 1).
            Body::AssociationUpdateRequest(request) => {
                let features = self.features_of(
                    request.cp_function_features.as_ref(),
                    request.up_function_features.as_ref(),
                );
                match (features, request.smf_set_id.as_ref()) {
                    (None, None) => Effect::Nothing,
                    (features, id) => Effect::Update(features, id.map(|id| id.fqdn.0.clone())),
                }
            }
            Body::SessionEstablishmentRequest(request) => match request.cp_f_seid.as_ref() {
                Some(f_seid) => {
                    Effect::PeerFSeid(f_seid.seid.unwrap_or(0), fseid_peer(from, f_seid).ip())
                }
                None => Effect::Nothing,
            },
            // A new CP F-SEID of SEID 0 is of no session (§7.2.2.4.2): the session keeps
            // the peer's SEID that it has.
            Body::SessionModificationRequest(request) => match request.cp_f_seid.as_ref() {
                Some(f_seid) if f_seid.seid == Some(0) => {
                    self.violation(from, ViolationKind::SeidZero, octets);
                    Effect::Nothing
                }
                Some(f_seid) => {
                    Effect::PeerFSeid(f_seid.seid.unwrap_or(0), fseid_peer(from, f_seid).ip())
                }
                None => Effect::Nothing,
            },
            Body::SessionReportRequest(request)
                if request
                    .pfcpsrreq_flags
                    .as_ref()
                    .is_some_and(|flags| flags.psdbu) =>
            {
                Effect::Deleted
            }
            _ => Effect::Nothing,
        };
        // The session's, also by the SEID that it had before it moved.
        let seid = message
            .header
            .seid
            .map(|seid| self.sessions.resolve(seid).unwrap_or(seid));
        let inbound = Inbound {
            from,
            message_type,
            sequence,
            priority: message
                .header
                .priority
                .unwrap_or(self.config.default_priority),
            prioritized: message.header.priority.is_some(),
            seid,
            mark: seid
                .and_then(|seid| self.sessions.get(&seid))
                .map(|session| session.mark),
            peer_seid: match &message.body {
                Body::SessionEstablishmentRequest(request) => {
                    request.cp_f_seid.as_ref().and_then(|f_seid| f_seid.seid)
                }
                _ => None,
            },
            node_id: node_id_of(&message.body),
            effect,
            of_smf_set,
            id: self.next_inbound,
        };
        self.next_inbound += 1;
        if message_type == 1 {
            // Answered from the state, the same each time: not kept.
            let message = Message {
                header: self.response_header(&inbound),
                body: HeartbeatResponse::new(RecoveryTimeStamp::new(
                    self.config.recovery_time_stamp,
                ))
                .into(),
            };
            if let Ok(octets) = message.encode() {
                self.queue(Transmit {
                    to: from,
                    priority: inbound.priority,
                    octets: octets.into(),
                });
            }
            return;
        }
        let stranger = self.association_of(from).is_none();
        if !self.answers.wait(
            (from, sequence),
            Digest::of(octets),
            inbound.id,
            now.saturating_add(self.config.keep),
            self.config.capacity,
            stranger,
        ) {
            // Full of requests that wait for their answer: the peer sends it again.
            return;
        }
        self.note_controls(now, from, octets, &message.body, inbound.seid);
        self.events.push_back(Event::Request {
            request: inbound,
            message,
        });
    }

    /// A response that [`screen`](Self::screen) let through: of an outstanding request,
    /// from its peer, and of its type.
    fn handle_response(
        &mut self,
        now: Duration,
        from: SocketAddr,
        octets: &[u8],
        message: Message,
    ) {
        let sequence = message.header.sequence;
        let request = self.take(sequence).expect("outstanding");
        self.deadlines.remove(&(request.deadline, sequence));
        self.finish(now, sequence, from, false);
        self.note_recovery(now, from, &message.body);
        self.note_controls(now, from, octets, &message.body, request.local_seid);
        self.response_effects(now, from, octets, &request, &message);
        if !request.heartbeat {
            self.events.push_back(Event::Response {
                request: request.id,
                message,
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn send(
        &mut self,
        now: Duration,
        to: SocketAddr,
        mut message: Message,
        heartbeat: bool,
        local_seid: Option<u64>,
        mark: Option<u64>,
        change: Change,
    ) -> Result<RequestId, NodeError> {
        let sequence = self.next_free_sequence()?;
        message.header.sequence = sequence;
        let octets = message.encode()?;
        let id = RequestId(self.next_request);
        self.next_request += 1;
        let priority = message
            .header
            .priority
            .unwrap_or(self.config.default_priority);
        let message_type = message.body.message_type();
        let deadline = now.saturating_add(self.config.t1);
        self.deadlines.insert((deadline, sequence));
        self.ids.insert(id, sequence);
        if heartbeat {
            self.beating.insert(to);
        }
        self.outstanding.insert(
            sequence,
            Outstanding {
                id,
                to,
                message_type,
                octets: octets.clone().into(),
                deadline,
                attempts: 0,
                priority,
                heartbeat,
                local_seid,
                mark,
                change,
            },
        );
        self.queue(Transmit {
            to,
            priority,
            octets: octets.into(),
        });
        Ok(id)
    }

    /// The outstanding request of `sequence`, which is no longer.
    fn take(&mut self, sequence: u32) -> Option<Outstanding> {
        let request = self.outstanding.remove(&sequence)?;
        self.ids.remove(&request.id);
        if request.heartbeat {
            self.beating.remove(&request.to);
        }
        Some(request)
    }

    /// The next sequence number of no outstanding, reserved or recent request.
    fn next_free_sequence(&mut self) -> Result<u32, NodeError> {
        for _ in 0..=0x00ff_ffff {
            let sequence = self.next_sequence;
            self.next_sequence = (self.next_sequence + 1) & 0x00ff_ffff;
            let lowest = SocketAddr::new(IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED), 0);
            let recent = self
                .finished
                .range((sequence, lowest)..)
                .next()
                .is_some_and(|((finished, _), _)| *finished == sequence);
            if !self.outstanding.contains_key(&sequence)
                && !self.reserved.contains(&sequence)
                && !recent
            {
                return Ok(sequence);
            }
        }
        Err(NodeError::NoSequence)
    }

    /// Whether a peer of the node, of the other function, sends requests of
    /// `message_type`.
    fn peer_sends(&self, message_type: u8) -> bool {
        let peer = match self.config.function {
            Function::Cp => Function::Up,
            Function::Up => Function::Cp,
        };
        sends(peer, message_type)
    }

    /// The local SEID of the session whose peer's SEID is `peer_seid`, of `peer`: of its
    /// association, or of the address of its F-SEID (§7.2.2.4.1 NOTE).
    fn local_seid_of(&self, peer: SocketAddr, peer_seid: u64) -> Option<u64> {
        let node = self
            .association_of(peer)
            .map(|association| association.key.as_slice());
        self.sessions.of_peer_seid(peer_seid).find(|local| {
            self.sessions.get(local).is_some_and(|session| {
                self.same_peer(session.peer, peer) || node == Some(session.node.as_slice())
            })
        })
    }

    fn queue(&mut self, transmit: Transmit) {
        let priority = usize::from(transmit.priority.min(15));
        self.transmits[priority].push_back(transmit);
    }

    fn violation(&mut self, from: SocketAddr, kind: ViolationKind, octets: &[u8]) {
        self.events.push_back(Event::Violation {
            from,
            kind,
            octets: octets.to_vec().into(),
        });
    }

    /// A request that had its response, or that the node gave up, kept until `keep`.
    fn finish(&mut self, now: Duration, sequence: u32, peer: SocketAddr, given_up: bool) {
        let until = now.saturating_add(self.config.keep);
        if let Some((before, _)) = self.finished.insert((sequence, peer), (until, given_up)) {
            self.finishing.remove(&(before, sequence, peer));
        }
        self.finishing.insert((until, sequence, peer));
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
    }

    /// The association of `peer` (§4.2.2): of its address, or of its address and port for
    /// a node without `request_port`.
    fn association_of(&self, peer: SocketAddr) -> Option<&Association> {
        self.by_peer
            .get(&self.peer_key(peer))
            .and_then(|key| self.associations.get(key))
    }

    /// Whether two addresses are of one peer: of one IP address when the node sends its
    /// requests to port 8805, whatever port a peer sends from (§4.2.2), and of one address
    /// and port for a node without `request_port`, whose peers have ports of their own.
    fn same_peer(&self, one: SocketAddr, other: SocketAddr) -> bool {
        self.peer_key(one) == self.peer_key(other)
    }

    /// The address of a peer as [`same_peer`](Self::same_peer) tells them apart.
    fn peer_key(&self, peer: SocketAddr) -> SocketAddr {
        peer_key(self.config.request_port, peer)
    }

    /// Where the requests of the node to the peer of `from` go: to port 8805 (§4.2.2),
    /// or to the port of `from` for a node without `request_port`.
    fn request_address(&self, from: SocketAddr) -> SocketAddr {
        SocketAddr::new(from.ip(), self.config.request_port.unwrap_or(from.port()))
    }

    /// The SSET and MPAS that a peer says of itself: in its CP Function Features
    /// (§8.2.58) to a UP function, and in its UP Function Features (§8.2.25) to a CP
    /// function. `None` when it says none.
    fn features_of(
        &self,
        cp: Option<&crate::CpFunctionFeatures>,
        up: Option<&crate::UpFunctionFeatures>,
    ) -> Option<(bool, bool)> {
        match self.config.function {
            Function::Up => cp.map(|features| (features.sset, features.mpas)),
            Function::Cp => up.map(|features| (features.sset, features.mpas)),
        }
    }

    /// The SMF set that a peer says it is of in its Association Setup Request or Response.
    fn set_of(
        &self,
        cp: Option<&crate::CpFunctionFeatures>,
        up: Option<&crate::UpFunctionFeatures>,
        id: Option<&crate::SmfSetId>,
    ) -> SetOf {
        SetOf::new(self.features_of(cp, up), id)
    }

    /// Answer a request that does not decode, when its header says that it is one:
    /// "Invalid length" (§7.6.3, §7.6.7), with the IE when the node knows it. A header
    /// of the node's own, which copies none of the faults of the request's.
    fn reject_malformed(
        &mut self,
        from: SocketAddr,
        header: &Header,
        message_type: u8,
        offending: Option<u16>,
    ) {
        // Nor one that the peer does not send, which is discarded (§7.6.5).
        if !is_request(message_type) || message_type == 1 || !self.peer_sends(message_type) {
            return;
        }
        let Some(body) = rejection_body(
            message_type,
            CauseValue::InvalidLength,
            offending,
            &self.config.node_id,
        ) else {
            return;
        };
        let header = match is_node_related(message_type) {
            true => Header::node(header.sequence),
            false => Header {
                priority: header.priority.map(|priority| priority & 0x0f),
                ..Header::session(0, header.sequence)
            },
        };
        if let Ok(octets) = (Message { header, body }).encode() {
            self.queue(Transmit {
                to: from,
                priority: header.priority.unwrap_or(self.config.default_priority),
                octets: octets.into(),
            });
        }
    }

    /// The Recovery Time Stamp that a message carries: a change is a restart (§6.2.2).
    fn note_recovery(&mut self, now: Duration, from: SocketAddr, body: &Body) {
        let stamp = match body {
            Body::HeartbeatRequest(message) => message.recovery_time_stamp.as_ref(),
            Body::HeartbeatResponse(message) => message.recovery_time_stamp.as_ref(),
            Body::AssociationSetupRequest(message) => message.recovery_time_stamp.as_ref(),
            Body::AssociationSetupResponse(message) => message.recovery_time_stamp.as_ref(),
            _ => None,
        };
        let Some(stamp) = stamp.map(|stamp| stamp.value) else {
            return;
        };
        // The stamps of peers without an association are bounded, the oldest first.
        if !self.recovery.contains_key(&self.peer_key(from))
            && self.recovery.len() >= self.config.capacity.max(1)
        {
            let associated: BTreeSet<SocketAddr> = self
                .associations
                .values()
                .map(|association| self.peer_key(association.peer))
                .collect();
            let oldest = self
                .recovery
                .iter()
                .filter(|(peer, _)| !associated.contains(peer))
                .min_by_key(|(_, (_, seen))| *seen)
                .map(|(peer, _)| *peer);
            if let Some(oldest) = oldest {
                self.recovery.remove(&oldest);
            }
        }
        if let Some((known, _)) = self.recovery.insert(self.peer_key(from), (stamp, now))
            && known != stamp
        {
            // Load and overload of the peer start again (§6.2.3.3.2, §6.2.4.3.2).
            let node = self
                .association_of(from)
                .map(|association| Scope::Node(association.key.clone()));
            self.load.retain(|scope, _| Some(scope) != node.as_ref());
            let (peer, request_port) = (self.peer_key(from), self.config.request_port);
            self.overload.retain(|scope, overload| {
                peer_key(request_port, overload.peer) != peer && Some(scope) != node.as_ref()
            });
            self.events.push_back(Event::PeerRestarted {
                peer: from,
                recovery_time_stamp: stamp,
            });
        }
    }

    /// The load and overload control information that a message of the session of
    /// `local_seid` carries (§6.2.3.3.3, §6.2.4.3.3), from a peer with an association:
    /// the load of its Node ID, and the overload of the address of the UP F-SEID of the
    /// session, or of its Node ID (§6.2.4.3.1).
    fn note_controls(
        &mut self,
        now: Duration,
        from: SocketAddr,
        octets: &[u8],
        body: &Body,
        local_seid: Option<u64>,
    ) {
        let (load, overload) = match body {
            Body::SessionEstablishmentResponse(message) => (
                message.load_control_information.as_deref(),
                message.overload_control_information.as_deref(),
            ),
            Body::SessionModificationResponse(message) => (
                message.load_control_information.as_deref(),
                message.overload_control_information.as_deref(),
            ),
            Body::SessionDeletionResponse(message) => (
                message.load_control_information.as_deref(),
                message.overload_control_information.as_deref(),
            ),
            Body::SessionReportRequest(message) => (
                message.load_control_information.as_deref(),
                message.overload_control_information.as_deref(),
            ),
            _ => (None, None),
        };
        if load.is_none() && overload.is_none() {
            return;
        }
        // Of the association of the session, from its peer or the address of its F-SEID,
        // and of no other host, which would fill the maps or throttle a peer.
        let session = local_seid.and_then(|seid| self.sessions.get(&seid));
        let of_peer = |key: &[u8]| {
            session.is_some_and(|session| self.same_peer(session.peer, from))
                || self
                    .association_of(from)
                    .is_some_and(|association| association.key == key)
        };
        let node = match session.filter(|session| self.associations.contains_key(&session.node)) {
            Some(session) => Some(session.node.clone()).filter(|key| of_peer(key)),
            None => self
                .association_of(from)
                .map(|association| association.key.clone()),
        };
        let Some(node) = node.map(Scope::Node) else {
            return;
        };
        let address = match body {
            Body::SessionEstablishmentResponse(response) => response
                .up_f_seid
                .as_ref()
                .map(|f_seid| self.peer_key(fseid_peer(from, f_seid))),
            _ => session.map(|session| self.peer_key(session.peer)),
        };
        let address = Scope::Address(address.unwrap_or(self.peer_key(from)));
        if let Some(load) = load
            && let (Some(sequence), Some(metric)) =
                (&load.load_control_sequence_number, &load.load_metric)
        {
            let scope = node.clone();
            let new = LoadControl {
                sequence: sequence.value,
                metric: metric.value.effective(),
            };
            match self.load.get(&scope).copied() {
                Some(known) if known.sequence == new.sequence && known.metric != new.metric => {
                    self.violation(from, ViolationKind::LoadControlSequence, octets)
                }
                // The number goes up only with a change (§6.2.3.3.2.1).
                Some(known)
                    if known.sequence != new.sequence
                        && known.metric == new.metric
                        && newer(new.sequence, known.sequence) =>
                {
                    self.violation(from, ViolationKind::LoadControlSequence, octets);
                    self.load.insert(scope, new);
                }
                Some(known) if !newer(new.sequence, known.sequence) => {}
                _ => {
                    self.load.insert(scope, new);
                }
            }
        }
        if let Some(overload) = overload
            && let (Some(sequence), Some(metric), Some(validity)) = (
                &overload.overload_control_sequence_number,
                &overload.overload_reduction_metric,
                &overload.period_of_validity,
            )
        {
            let of_node = overload
                .overload_control_information_flags
                .as_ref()
                .is_some_and(|flags| flags.aoci);
            let scope = match of_node {
                true => node,
                false => address,
            };
            let validity = timer(validity);
            let until = validity.map(|period| now.saturating_add(period));
            let new = OverloadControl {
                peer: from,
                sequence: sequence.value,
                metric: metric.value.effective(),
                validity,
                until,
                credit: 0,
            };
            match self.overload.get(&scope).copied() {
                Some(known)
                    if known.sequence == new.sequence
                        && (known.metric, known.validity) != (new.metric, new.validity) =>
                {
                    self.violation(from, ViolationKind::OverloadControlSequence, octets)
                }
                Some(known) if !newer(new.sequence, known.sequence) => {}
                // A new number, even for the same information, restarts the period of
                // validity (§6.2.4.3.2.1 NOTE 1).
                Some(known) => {
                    self.overload.insert(
                        scope,
                        OverloadControl {
                            credit: known.credit,
                            ..new
                        },
                    );
                }
                None => {
                    self.overload.insert(scope, new);
                }
            }
        }
    }

    /// Whether the "Loss" algorithm drops a session request of `priority` to `to`
    /// (§6.2.4.4.2): of each 100 requests, as many as the Overload Reduction Metric,
    /// those of the priorities that the node spares last (§6.2.4.5.1).
    fn throttle(&mut self, to: SocketAddr, local_seid: Option<u64>, priority: u8) -> bool {
        if !self.config.throttling {
            return false;
        }
        // The address of the UP F-SEID of the session, and its association.
        let session = local_seid.and_then(|seid| self.sessions.get(&seid));
        let address = Scope::Address(self.peer_key(session.map_or(to, |session| session.peer)));
        let node = session
            .filter(|session| self.associations.contains_key(&session.node))
            .map(|session| session.node.clone())
            .or_else(|| {
                self.association_of(to)
                    .map(|association| association.key.clone())
            })
            .map(Scope::Node);
        let scope = match self.overload.contains_key(&address) {
            true => address,
            false => match node {
                Some(node) if self.overload.contains_key(&node) => node,
                _ => return false,
            },
        };
        let spared = self
            .config
            .priority_up_to
            .is_some_and(|up_to| priority <= up_to);
        let metric = self
            .overload
            .get(&scope)
            .map_or(0, |overload| overload.metric);
        let credit = self.overload.credit(&scope).expect("overload");
        *credit += u32::from(metric);
        // A spared request is dropped only when the others could not make the reduction.
        let owed = if spared { 200 } else { 100 };
        if *credit >= owed {
            *credit -= 100;
            return true;
        }
        false
    }

    /// What a response to a request of the node changes: the association, the session.
    fn response_effects(
        &mut self,
        now: Duration,
        from: SocketAddr,
        octets: &[u8],
        request: &Outstanding,
        message: &Message,
    ) {
        let accepted = accepts(&message.body);
        match &message.body {
            Body::AssociationSetupResponse(response) if accepted => {
                if let Some(node_id) = &response.node_id {
                    // The set that the peer answers with (§5.22): an SMF's CP Function
                    // Features and SMF Set ID to a UPF that sets the association up (§5.22.3
                    // bullet 1), a UPF's UP Function Features to an SMF, whose MPAS says
                    // whether a release keeps the sessions on the CP side (§6.2.8.2).
                    let set = self.set_of(
                        response.cp_function_features.as_ref(),
                        response.up_function_features.as_ref(),
                        response.smf_set_id.as_ref(),
                    );
                    self.associate(now, from, node_id.clone(), None, set);
                }
            }
            Body::AssociationReleaseResponse(_) if accepted => {
                if let Some(key) = self
                    .association_of(from)
                    .map(|association| association.key.clone())
                {
                    self.release(&key);
                }
            }
            // The set features of the peer's function that the answer to an update carries
            // (Table 7.4.4.4-1), as those of its request.
            Body::AssociationUpdateResponse(response) if accepted => {
                let features = self.features_of(
                    response.cp_function_features.as_ref(),
                    response.up_function_features.as_ref(),
                );
                if let Some(key) = self
                    .association_of(from)
                    .map(|association| association.key.clone())
                {
                    self.update_set(&key, features, None);
                }
            }
            Body::SessionEstablishmentResponse(response) => {
                if let Some(local) = self.session_of(request) {
                    match (accepted, response.up_f_seid.as_ref()) {
                        (true, Some(f_seid)) if f_seid.seid == Some(0) => {
                            self.violation(from, ViolationKind::SeidZero, octets);
                            self.abandon(request);
                        }
                        (true, Some(f_seid)) if f_seid.seid.is_some() => {
                            let node = self
                                .association_of(from)
                                .map(|association| association.key.clone())
                                .unwrap_or_default();
                            let mark = request.mark.expect("of the establishment");
                            self.sessions.insert(
                                local,
                                Session {
                                    peer: fseid_peer(from, f_seid),
                                    peer_seid: f_seid.seid,
                                    node,
                                    reserved: false,
                                    mark,
                                },
                            );
                        }
                        _ => self.abandon(request),
                    }
                }
            }
            // The session of the request, whatever SEID the header of the response has.
            _ if accepted && request.change == Change::Ends => {
                if let Some(local) = self.session_of(request) {
                    self.sessions.remove(&local);
                }
            }
            Body::SessionModificationResponse(_) if accepted => {
                let Change::Moves(new) = request.change else {
                    return;
                };
                let moved = self
                    .session_of(request)
                    .and_then(|local| self.sessions.remove(&local).map(|session| (local, session)));
                match moved {
                    Some((local, session)) => {
                        let mark = session.mark;
                        self.sessions.insert(new, session);
                        // The UP function may still send to the previous SEID, for longer
                        // than twice N1 x T1 (Table 7.5.4.1-1, NOTE 2).
                        let window = self
                            .config
                            .t1
                            .saturating_mul(2 * (u32::from(self.config.n1) + 1));
                        self.sessions.alias(local, mark, now.saturating_add(window));
                    }
                    // A move of no session, or of one that ended meanwhile, frees its SEID.
                    None => self.abandon(request),
                }
            }
            Body::SessionModificationResponse(_) => self.abandon(request),
            // A new CP F-SEID for the session, of another SMF (§5.22).
            Body::SessionReportResponse(response) if accepted => {
                if let (Some(f_seid), Some(local)) =
                    (response.cp_f_seid.as_ref(), self.session_of(request))
                    && let Some(session) = self.sessions.get(&local)
                {
                    // Not of SEID 0, which is of no session (§7.2.2.4.2).
                    let peer_seid = f_seid.seid.filter(|seid| *seid != 0).or(session.peer_seid);
                    if f_seid.seid == Some(0) {
                        self.violation(from, ViolationKind::SeidZero, octets);
                    }
                    self.sessions
                        .set_peer(local, fseid_peer(from, f_seid), peer_seid);
                    // Of the association of the SMF that took it, with MPAS.
                    if let Some(key) = self
                        .association_of(from)
                        .map(|association| association.key.clone())
                    {
                        self.sessions.set_node(local, key);
                    }
                }
            }
            _ => {}
        }
    }

    /// What an answer of the caller changes: the association, the session.
    fn answered_effects(&mut self, now: Duration, request: &Inbound, message: &Message) {
        let accepted = accepts(&message.body);
        if !accepted {
            return;
        }
        match (&message.body, request.effect.clone()) {
            (Body::AssociationSetupResponse(_), Effect::Setup(retained, set)) => {
                if let Some(node_id) = &request.node_id {
                    let peer = self.request_address(request.from);
                    // The retention of the sessions is the UP function's (§6.2.6.2.2): a
                    // CP function stores the Node ID (§6.2.6.3.2).
                    let retained = (self.config.function == Function::Up).then_some(retained);
                    self.associate(now, peer, node_id.clone(), retained, set);
                }
            }
            // The peer's new set features and SMF Set ID (§5.22.3, bullet 1).
            (Body::AssociationUpdateResponse(_), Effect::Update(features, id)) => {
                if let Some(node_id) = &request.node_id {
                    self.update_set(&key_of(node_id), features, id);
                }
            }
            (Body::AssociationReleaseResponse(_), _) => {
                // The association that the request names (§6.2.8).
                if let Some(node_id) = &request.node_id {
                    self.release(&key_of(node_id));
                }
            }
            (Body::SessionEstablishmentResponse(response), effect) => {
                // Not a SEID of another session, which a probe may answer with.
                if let Some(local) = response.up_f_seid.as_ref().and_then(|f_seid| f_seid.seid)
                    && local != 0
                    && !self.in_use(local)
                {
                    let node = self
                        .association_of(request.from)
                        .map(|association| association.key.clone())
                        .unwrap_or_default();
                    let peer = match effect {
                        Effect::PeerFSeid(_, address) => {
                            SocketAddr::new(address, request.from.port())
                        }
                        _ => request.from,
                    };
                    let peer = self.request_address(peer);
                    let mark = self.mark();
                    self.sessions.insert(
                        local,
                        Session {
                            peer,
                            peer_seid: request.peer_seid,
                            node,
                            reserved: false,
                            mark,
                        },
                    );
                }
            }
            (Body::SessionModificationResponse(_), effect) => {
                let session = self.answered_session(request);
                if let (Effect::PeerFSeid(seid, address), Some(local)) = (effect, session) {
                    let peer = self.request_address(SocketAddr::new(address, request.from.port()));
                    self.sessions.set_peer(local, peer, Some(seid));
                }
                // The SMF of the set that modifies a session controls it (§5.22.3, bullet 3).
                if request.of_smf_set
                    && let (Some(local), Some(key)) = (
                        session,
                        self.association_of(request.from)
                            .map(|association| association.key.clone()),
                    )
                {
                    self.sessions.set_node(local, key);
                }
            }
            (Body::SessionDeletionResponse(_), _)
            | (Body::SessionReportResponse(_), Effect::Deleted) => {
                if let Some(local) = self.answered_session(request) {
                    self.sessions.remove(&local);
                }
            }
            _ => {}
        }
    }

    /// The set of the association of `key` that an update changes (§5.22.3, bullet 1): the
    /// set features of the peer's function, and the FQDN of its SMF Set ID, each taken if
    /// the update carried it, and the rest kept.
    fn update_set(&mut self, key: &[u8], features: Option<(bool, bool)>, id: Option<Vec<u8>>) {
        let Some(association) = self.associations.get_mut(key) else {
            return;
        };
        if let Some((sset, mpas)) = features {
            association.set.sset = sset;
            association.set.mpas = mpas;
        }
        if let Some(id) = id {
            association.set.id = Some(id);
        }
    }

    /// An association with `peer` of `node_id`. As a UP function, `retained` says which
    /// sessions of an association of the same Node ID stay (§6.2.6.2.2): `Some(None)` for
    /// none, `Some(Some([]))` for all, and those of the addresses listed.
    fn associate(
        &mut self,
        now: Duration,
        peer: SocketAddr,
        node_id: NodeId,
        retained: Option<Option<Vec<IpAddr>>>,
        set: SetOf,
    ) {
        let key = key_of(&node_id);
        // A peer, as the node tells peers apart, has one association: that of another
        // Node ID ends.
        if let Some(other) = self
            .by_peer
            .get(&self.peer_key(peer))
            .filter(|other| **other != key)
            .cloned()
        {
            self.release(&other);
        }
        let replaced = self.associations.insert(
            key.clone(),
            Association {
                node_id: node_id.clone(),
                peer,
                key: key.clone(),
                set,
            },
        );
        if let Some(old) = &replaced
            && self.by_peer.get(&self.peer_key(old.peer)) == Some(&key)
        {
            self.by_peer.remove(&self.peer_key(old.peer));
        }
        self.by_peer.insert(self.peer_key(peer), key.clone());
        let mut ended = Vec::new();
        if let Some(old) = &replaced {
            if old.peer != peer && !self.by_peer.contains_key(&self.peer_key(old.peer)) {
                self.heartbeats.remove(&old.peer);
            }
            if let Some(retained) = retained {
                let keeps = |session: &Session| match &retained {
                    None => false,
                    Some(addresses) => {
                        addresses.is_empty() || addresses.contains(&session.peer.ip())
                    }
                };
                ended = self
                    .sessions
                    .iter()
                    .filter(|(_, session)| session.node == key && !keeps(session))
                    .map(|(seid, _)| *seid)
                    .collect();
                for seid in &ended {
                    self.sessions.remove(seid);
                }
            }
        }
        if let Some(interval) = self.config.heartbeat {
            self.heartbeats.insert(peer, now.saturating_add(interval));
        }
        self.events.push_back(Event::Associated {
            peer,
            node_id,
            replaced: replaced.is_some(),
            sessions: ended,
        });
    }

    fn release(&mut self, key: &[u8]) {
        let Some(association) = self.associations.remove(key) else {
            return;
        };
        let peer = association.peer;
        if self.by_peer.get(&self.peer_key(peer)).map(Vec::as_slice) == Some(key) {
            self.by_peer.remove(&self.peer_key(peer));
        }
        // The sessions of the association: those of its key, and those of its peer's
        // address that no live association owns. A session that another association took
        // over (its node is that of a live association) stays with it (§5.22.3 bullet 3).
        let of_it: Vec<u64> = self
            .sessions
            .iter()
            .filter(|(_, session)| {
                session.node == key
                    || (!self.associations.contains_key(&session.node)
                        && self.same_peer(session.peer, peer))
            })
            .map(|(seid, _)| *seid)
            .collect();
        // With MPAS, the set keeps the sessions while another of its associations remains
        // (§6.2.8, §5.22.3 bullet 1): on a UP function one of the same SMF Set ID, which
        // they go to; a CP function, which does not see the set's other associations,
        // keeps them all, for its caller to end when none remains.
        let mpas = self.config.smf_set.mpas;
        let heir = match self.config.function {
            Function::Up if mpas && association.set.mpas && association.set.id.is_some() => self
                .associations
                .values()
                .find(|other| other.set.mpas && other.set.id == association.set.id)
                .map(|other| other.key.clone()),
            _ => None,
        };
        // A CP function sees only its own association with the UPF, so it keeps the
        // sessions when both it and the UPF use MPAS, for its caller to end when no other
        // association of the set remains; a UPF that did not announce MPAS means no set.
        let keeps = heir.is_some()
            || (mpas && self.config.function == Function::Cp && association.set.mpas);
        let (kept, ended) = match keeps {
            true => (of_it, Vec::new()),
            false => (Vec::new(), of_it),
        };
        for seid in &ended {
            self.sessions.remove(seid);
        }
        if let Some(heir) = heir {
            for seid in &kept {
                self.sessions.set_node(*seid, heir.clone());
            }
        }
        if !self.by_peer.contains_key(&self.peer_key(peer)) {
            self.heartbeats.remove(&peer);
        }
        self.events.push_back(Event::Released {
            node_id: association.node_id,
            sessions: ended,
            kept,
        });
    }
}

/// Whether a response accepts its request: a Cause of acceptance, as read (Table
/// 8.2.1-1), and not the reserved 0, an invalid IE.
fn accepts(body: &Body) -> bool {
    body.cause()
        .is_some_and(|cause| (1..64).contains(&cause.effective().value()))
}

/// The address of a peer: of its IP address alone, port 0, for a node of a `request_port`.
fn peer_key(request_port: Option<u16>, peer: SocketAddr) -> SocketAddr {
    match request_port {
        Some(_) => SocketAddr::new(peer.ip(), 0),
        None => peer,
    }
}

/// Whether sequence number `new` comes after `known`, through a roll-over of 32 bits.
fn newer(new: u32, known: u32) -> bool {
    new != known && new.wrapping_sub(known) < 0x8000_0000
}

/// The Node ID as the key of its association: as its receiver takes it, without the
/// spare bits and the octets after its value.
fn key_of(node_id: &NodeId) -> Vec<u8> {
    let mut octets = Vec::new();
    let _ = crate::ie::Codec::encode(
        &node_id.effective().unwrap_or_else(|| node_id.clone()),
        &mut octets,
    );
    octets
}

/// The Node ID and the SEID of the CP F-SEID of a request, read from its IEs alone:
/// the first of each that decodes, as the decode of its table takes them.
fn names(octets: &[u8]) -> (Option<NodeId>, Option<u64>) {
    use crate::ie::Codec;
    let Ok((_, _, ies)) = crate::framing::message_ies(octets) else {
        return (None, None);
    };
    let (mut node_id, mut f_seid) = (None, None);
    for ie in ies.map_while(Result::ok) {
        match ie.ie_type {
            60 if node_id.is_none() => node_id = NodeId::decode(ie.value),
            57 if f_seid.is_none() => f_seid = FSeid::decode(ie.value),
            _ => {}
        }
    }
    (node_id, f_seid.and_then(|f_seid| f_seid.seid))
}

/// The Node ID that a node related request carries.
fn node_id_of(body: &Body) -> Option<NodeId> {
    let node_id = match body {
        Body::AssociationSetupRequest(message) => message.node_id.as_ref(),
        Body::AssociationUpdateRequest(message) => message.node_id.as_ref(),
        Body::AssociationReleaseRequest(message) => message.node_id.as_ref(),
        Body::NodeReportRequest(message) => message.node_id.as_ref(),
        Body::SessionSetDeletionRequest(message) => message.node_id.as_ref(),
        Body::SessionSetModificationRequest(message) => message.node_id.as_ref(),
        Body::SessionEstablishmentRequest(message) => message.node_id.as_ref(),
        _ => None,
    };
    node_id.cloned()
}

/// The period of a Timer (§8.2.35): `None` for an infinite one.
fn timer(timer: &Timer) -> Option<Duration> {
    let value = u64::from(timer.timer_value);
    let unit = match timer.timer_unit.effective() {
        TimerUnit::TwoSeconds => 2,
        TimerUnit::OneMinute => 60,
        TimerUnit::TenMinutes => 600,
        TimerUnit::OneHour => 3600,
        TimerUnit::TenHours => 36_000,
        TimerUnit::Infinite => return None,
        // effective() reads the others as minutes (Table 8.2.35.1).
        _ => 60,
    };
    Some(Duration::from_secs(value * unit))
}

/// The response that rejects a request of `message_type` with `cause`, with the node's
/// Node ID where the response has one, and the Offending IE.
fn rejection_body(
    message_type: u8,
    cause: CauseValue,
    offending: Option<u16>,
    node_id: &NodeId,
) -> Option<Body> {
    let cause = Some(Cause::new(cause));
    let node_id = Some(node_id.clone());
    let offending_ie = offending.map(OffendingIe::new);
    Some(match message_type {
        3 => PfdManagementResponse {
            cause,
            offending_ie,
            ..Default::default()
        }
        .into(),
        5 => AssociationSetupResponse {
            node_id,
            cause,
            ..Default::default()
        }
        .into(),
        7 => AssociationUpdateResponse {
            node_id,
            cause,
            ..Default::default()
        }
        .into(),
        9 => AssociationReleaseResponse {
            node_id,
            cause,
            ..Default::default()
        }
        .into(),
        12 => NodeReportResponse {
            node_id,
            cause,
            offending_ie,
            ..Default::default()
        }
        .into(),
        14 => SessionSetDeletionResponse {
            node_id,
            cause,
            offending_ie,
            ..Default::default()
        }
        .into(),
        16 => SessionSetModificationResponse {
            node_id,
            cause,
            offending_ie,
            ..Default::default()
        }
        .into(),
        50 => SessionEstablishmentResponse {
            node_id,
            cause,
            offending_ie,
            ..Default::default()
        }
        .into(),
        52 => SessionModificationResponse {
            cause,
            offending_ie,
            ..Default::default()
        }
        .into(),
        54 => SessionDeletionResponse {
            cause,
            offending_ie,
            ..Default::default()
        }
        .into(),
        56 => SessionReportResponse {
            cause,
            offending_ie,
            ..Default::default()
        }
        .into(),
        _ => return None,
    })
}
