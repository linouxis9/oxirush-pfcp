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
//!   that it gave, byte for byte.
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
//! It decides nothing for its caller: an association, a session and each answer are the
//! caller's, through [`Node::respond`].

mod state;

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;
use core::net::SocketAddr;
use core::time::Duration;

use crate::enums::{CauseValue, TimerUnit};
use crate::header::Header;
use crate::message::{Body, Message, is_node_related, is_request};
use crate::octets::IntoOwned;
use crate::registry::*;
use crate::values::*;
use crate::values_gen::*;

pub use state::{Association, LoadControl, OverloadControl, Session};
use state::{Answered, Outstanding, Scope};

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
    pub node_id: NodeId<'static>,
    /// Its function.
    pub function: Function,
    /// When it started, as the Recovery Time Stamp has it (§8.2.65).
    pub recovery_time_stamp: u32,
    /// T1, after which a request without a response is sent again (§6.4).
    pub t1: Duration,
    /// N1, how many times a request is sent again (§6.4).
    pub n1: u8,
    /// How often a Heartbeat Request goes to each associated peer: `None` for never.
    pub heartbeat: Option<Duration>,
    /// How long an answered request is kept, to answer its retransmissions, and a
    /// finished request, to tell a duplicate or late response.
    pub keep: Duration,
    /// The priority of a request that has none (§6.2.4.5.2): 0 the highest, to 15.
    pub default_priority: u8,
    /// Throttle the session requests to an overloaded peer (§6.2.4.4).
    pub throttling: bool,
    /// The priorities, from 0 up to this one, of the requests that throttling spares
    /// while it can (§6.2.4.5.1): `None` for none.
    pub priority_up_to: Option<u8>,
}

impl NodeConfig {
    /// A node of `node_id`: T1 of 3 s, N1 of 3, a heartbeat every 60 s, answers kept for
    /// 24 s, default priority 8, throttling on, and no priority spared.
    pub fn new(node_id: NodeId<'static>, function: Function, recovery_time_stamp: u32) -> Self {
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
        }
    }
}

/// A datagram to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transmit {
    /// To whom.
    pub to: SocketAddr,
    /// Its priority: 0 the highest.
    pub priority: u8,
    /// The datagram.
    pub octets: Vec<u8>,
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
    /// The SEID of its header: the local SEID of the session.
    pub seid: Option<u64>,
    /// The SEID of the peer's F-SEID, of an establishment.
    pub peer_seid: Option<u64>,
    /// The Node ID that it carries.
    pub node_id: Option<NodeId<'static>>,
}

/// How a response goes, for a probe that breaks §6.4 on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Sent, and kept for the retransmissions of the request.
    Send,
    /// Kept for the retransmissions, and not sent: the first one is lost.
    CacheOnly,
    /// Neither sent nor kept: a responder that lost its state.
    Forget,
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
    /// A request with the sequence number of an earlier one, and other octets (§6.4).
    ChangedRetransmission,
    /// A session request from a peer without an association (§6.2.6): answered with
    /// "No established PFCP Association".
    SessionWithoutAssociation,
    /// A session request of a SEID that the node does not have: answered with "Session
    /// context not found" (§7.2.2.4.2).
    UnknownSeid,
    /// An association update or release of a Node ID that the node has no association
    /// with: answered with "No established PFCP Association" (§6.2.7, §6.2.8).
    UnknownNode,
    /// Load control information of a sequence number that the node has, with other
    /// values, or of a new one with the same values (§6.2.3.3.2).
    LoadControlSequence,
    /// Overload control information of a sequence number that the node has, with other
    /// values, or of a new one with the same values (§6.2.4.3.2).
    OverloadControlSequence,
    /// A node related message bundled with others (§6.5).
    BundledNodeMessage,
    /// Session messages of different peers bundled together (§6.5).
    BundledPeers,
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
        message: Message<'static>,
    },
    /// The response to a request of the caller.
    Response {
        /// The request.
        request: RequestId,
        /// The response.
        message: Message<'static>,
    },
    /// A request of the caller without a response after N1 retransmissions (§6.4).
    Timeout {
        /// The request.
        request: RequestId,
        /// To whom it went.
        to: SocketAddr,
    },
    /// An association, set up by a successful Association Setup.
    Associated {
        /// The peer.
        peer: SocketAddr,
        /// Its Node ID.
        node_id: NodeId<'static>,
        /// It replaces an association of the same Node ID (§6.2.6.2.2).
        replaced: bool,
    },
    /// An association ended by a successful Association Release, with its sessions.
    Released {
        /// The peer's Node ID.
        node_id: NodeId<'static>,
        /// The local SEIDs of the sessions that ended with it (§6.2.8).
        sessions: Vec<u64>,
    },
    /// A peer whose Recovery Time Stamp changed: it restarted, and what the node kept of
    /// its load and overload is gone.
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
    /// What a peer did wrong, and its octets.
    Violation {
        /// The peer.
        from: SocketAddr,
        /// What.
        kind: ViolationKind,
        /// The message.
        octets: Vec<u8>,
    },
    /// A datagram that does not decode: the node answered a request that it could.
    Malformed {
        /// The peer.
        from: SocketAddr,
        /// Why.
        error: crate::Error,
    },
}

/// Why the node does not send a request.
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
    /// It does not encode.
    Encode(crate::Error),
}

impl From<crate::Error> for NodeError {
    fn from(error: crate::Error) -> Self {
        Self::Encode(error)
    }
}

/// A PFCP entity on one local endpoint.
#[derive(Debug)]
pub struct Node {
    config: NodeConfig,
    next_sequence: u32,
    next_request: u64,
    next_seid: u64,
    reserved: BTreeSet<u32>,
    outstanding: BTreeMap<u32, Outstanding>,
    /// The retransmissions, by when they are due.
    deadlines: BTreeSet<(Duration, u32)>,
    /// The requests that had their response, or that the node gave up, until `keep`:
    /// (sequence, peer) to (when they go, given up), and by when they go.
    finished: BTreeMap<(u32, SocketAddr), (Duration, bool)>,
    finishing: BTreeSet<(Duration, u32, SocketAddr)>,
    answering: BTreeSet<(Duration, SocketAddr, u32)>,
    answered: BTreeMap<(SocketAddr, u32), Answered>,
    associations: BTreeMap<Vec<u8>, Association>,
    sessions: BTreeMap<u64, Session>,
    recovery: BTreeMap<SocketAddr, u32>,
    heartbeats: BTreeMap<SocketAddr, Duration>,
    load: BTreeMap<Scope, LoadControl>,
    overload: BTreeMap<Scope, OverloadControl>,
    transmits: [VecDeque<Transmit>; 16],
    events: VecDeque<Event>,
}

impl Node {
    /// A node, with nothing outstanding.
    pub fn new(config: NodeConfig) -> Self {
        Self {
            config,
            next_sequence: 1,
            next_request: 1,
            next_seid: 1,
            reserved: BTreeSet::new(),
            outstanding: BTreeMap::new(),
            deadlines: BTreeSet::new(),
            finished: BTreeMap::new(),
            finishing: BTreeSet::new(),
            answering: BTreeSet::new(),
            answered: BTreeMap::new(),
            associations: BTreeMap::new(),
            sessions: BTreeMap::new(),
            recovery: BTreeMap::new(),
            heartbeats: BTreeMap::new(),
            load: BTreeMap::new(),
            overload: BTreeMap::new(),
            transmits: Default::default(),
            events: VecDeque::new(),
        }
    }

    /// What the node is.
    pub fn config(&self) -> &NodeConfig {
        &self.config
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
        let heartbeat = self.heartbeats.values().copied().min();
        let overload = self.overload.values().filter_map(|overload| overload.until).min();
        [retransmission, heartbeat, overload].into_iter().flatten().min()
    }

    /// Do what is due at `now`.
    pub fn handle_timeout(&mut self, now: Duration) {
        self.prune(now);
        while let Some(&(deadline, sequence)) = self.deadlines.first()
            && deadline <= now
        {
            self.deadlines.pop_first();
            let Some(request) = self.outstanding.get_mut(&sequence) else { continue };
            if request.attempts < self.config.n1 {
                request.attempts += 1;
                request.deadline = now + self.config.t1;
                self.deadlines.insert((request.deadline, sequence));
                let transmit = Transmit { to: request.to, priority: request.priority, octets: request.octets.clone() };
                self.queue(transmit);
                continue;
            }
            let request = self.outstanding.remove(&sequence).expect("due");
            self.finish(now, sequence, request.to, true);
            match request.heartbeat {
                true => self.events.push_back(Event::PeerDown { peer: request.to }),
                false => self.events.push_back(Event::Timeout { request: request.id, to: request.to }),
            }
        }
        let beats: Vec<SocketAddr> = self.heartbeats.iter().filter(|(_, at)| **at <= now).map(|(peer, _)| *peer).collect();
        for peer in beats {
            let interval = self.config.heartbeat.unwrap_or(Duration::MAX);
            self.heartbeats.insert(peer, now.saturating_add(interval));
            if !self.outstanding.values().any(|request| request.heartbeat && request.to == peer) {
                let request = HeartbeatRequest::new(RecoveryTimeStamp::new(self.config.recovery_time_stamp));
                let message = Message { header: Header::node(0), body: request.into() };
                let _ = self.send(now, peer, message, true, None);
            }
        }
        let ended: Vec<Scope> = self.overload.iter().filter(|(_, overload)| overload.until.is_some_and(|until| until <= now)).map(|(scope, _)| scope.clone()).collect();
        for scope in ended {
            if let Some(overload) = self.overload.remove(&scope) {
                self.events.push_back(Event::OverloadEnded { peer: overload.peer });
            }
        }
    }

    /// Send a request to `to`, with the next sequence number. A session request needs an
    /// association with the peer, and may be throttled for its overload.
    ///
    /// # Errors
    ///
    /// A session request without an association or throttled, a message that is no
    /// request, and one that does not encode.
    pub fn request(&mut self, now: Duration, to: SocketAddr, message: Message<'_>) -> Result<RequestId, NodeError> {
        let message_type = message.body.message_type();
        if !is_request(message_type) {
            return Err(NodeError::NotARequest);
        }
        let mut local_seid = None;
        if !is_node_related(message_type) {
            if self.association_of(to).is_none() {
                return Err(NodeError::NoAssociation);
            }
            if let Body::SessionEstablishmentRequest(request) = &message.body {
                local_seid = request.cp_f_seid.as_ref().and_then(|f_seid| f_seid.seid);
            }
            let priority = message.header.priority.unwrap_or(self.config.default_priority);
            if self.throttle(to, priority) {
                return Err(NodeError::Throttled);
            }
        }
        self.send(now, to, message, false, local_seid)
    }

    /// Send a session request to the peer of the session of `local_seid`, to its SEID.
    ///
    /// # Errors
    ///
    /// As [`request`](Self::request), and a session that the node does not have.
    pub fn session_request(&mut self, now: Duration, local_seid: u64, body: impl Into<Body<'static>>) -> Result<RequestId, NodeError> {
        let session = self.sessions.get(&local_seid).ok_or(NodeError::NoSession)?;
        let (peer, peer_seid) = (session.peer, session.peer_seid.unwrap_or(0));
        self.request(now, peer, Message { header: Header::session(peer_seid, 0), body: body.into() })
    }

    /// A new local SEID, non-zero and of no other session, for a session with `peer`:
    /// the SEID of the F-SEID that the caller then sends.
    pub fn new_session(&mut self, peer: SocketAddr) -> u64 {
        while self.next_seid == 0 || self.sessions.contains_key(&self.next_seid) {
            self.next_seid = self.next_seid.wrapping_add(1);
        }
        let seid = self.next_seid;
        self.next_seid = self.next_seid.wrapping_add(1);
        let node = self.association_of(peer).map(|association| association.key.clone()).unwrap_or_default();
        self.sessions.insert(seid, Session { peer, peer_seid: None, node });
        seid
    }

    /// Answer a request, with its sequence number and priority, to the SEID of its
    /// session; the answer is kept for the request's retransmissions.
    ///
    /// # Errors
    ///
    /// A body that does not encode.
    pub fn respond(&mut self, now: Duration, request: &Inbound, body: impl Into<Body<'static>>) -> Result<(), NodeError> {
        let body = body.into();
        let mut header = match is_node_related(request.message_type) {
            true => Header::node(request.sequence),
            false => {
                let seid = match request.message_type {
                    50 => request.peer_seid,
                    _ => request.seid.and_then(|seid| self.sessions.get(&seid)).and_then(|session| session.peer_seid),
                };
                Header::session(seid.unwrap_or(0), request.sequence)
            }
        };
        if request.prioritized {
            header.priority = Some(request.priority);
        }
        self.respond_with(now, request, Message { header, body }, Delivery::Send)
    }

    /// Answer a request with a message as it is, delivered as `delivery` says: a probe.
    ///
    /// # Errors
    ///
    /// A message that does not encode.
    pub fn respond_with(&mut self, now: Duration, request: &Inbound, message: Message<'static>, delivery: Delivery) -> Result<(), NodeError> {
        let octets = message.encode()?;
        self.answered_effects(now, request, &message);
        let key = (request.from, request.sequence);
        match delivery {
            Delivery::Forget => {
                self.answered.remove(&key);
            }
            _ => {
                let expires = now + self.config.keep;
                let entry = self.answered.entry(key).or_insert_with(|| Answered { request: Vec::new(), response: None, expires });
                entry.response = Some(octets.clone());
                entry.expires = expires;
                self.answering.insert((expires, key.0, key.1));
            }
        }
        if delivery == Delivery::Send {
            self.queue(Transmit { to: request.from, priority: request.priority, octets });
        }
        Ok(())
    }

    /// A sequence number that the node will not give, for a probe that sends its own.
    pub fn reserve_sequence(&mut self) -> u32 {
        let sequence = self.next_free_sequence();
        self.reserved.insert(sequence);
        sequence
    }

    /// Send octets as they are: no sequence number, no retransmission, no matching. A
    /// response to a reserved sequence number is then a violation, as any unknown one.
    pub fn send_raw(&mut self, to: SocketAddr, priority: u8, octets: Vec<u8>) {
        self.queue(Transmit { to, priority, octets });
    }

    /// The association with a peer.
    pub fn association(&self, peer: SocketAddr) -> Option<&Association> {
        self.association_of(peer)
    }

    /// The session of a local SEID.
    pub fn session(&self, local_seid: u64) -> Option<&Session> {
        self.sessions.get(&local_seid)
    }

    /// The latest load control information of a peer, by its Node ID (§6.2.3.3.1).
    pub fn load_control(&self, peer: SocketAddr) -> Option<LoadControl> {
        let node = self.association_of(peer).map(|association| Scope::Node(association.key.clone()));
        node.and_then(|scope| self.load.get(&scope)).or_else(|| self.load.get(&Scope::Address(peer.ip()))).copied()
    }

    /// The overload control information of a peer that still holds: of its address, or
    /// of its Node ID (§6.2.4.3.1).
    pub fn overload_control(&self, peer: SocketAddr) -> Option<OverloadControl> {
        let node = self.association_of(peer).map(|association| Scope::Node(association.key.clone()));
        self.overload.get(&Scope::Address(peer.ip())).or_else(|| node.and_then(|scope| self.overload.get(&scope))).copied()
    }

    /// Take a datagram that `from` sent: each of its messages, bundled with the FO flag.
    pub fn handle_datagram(&mut self, now: Duration, from: SocketAddr, octets: &[u8]) {
        self.prune(now);
        let mut rest = octets;
        let mut count = 0;
        let mut peers = BTreeSet::new();
        loop {
            let Some((header, message_type, length)) = Header::decode(rest) else {
                self.events.push_back(Event::Malformed { from, error: crate::Error::TooShort { octets: rest.len() } });
                return;
            };
            let end = 4 + usize::from(length);
            let bundled = count > 0 || (header.follow_on && end < rest.len());
            if header.version != 1 {
                if is_request(message_type) {
                    let message = Message { header: Header::node(header.sequence), body: VersionNotSupportedResponse::default().into() };
                    if let Ok(octets) = message.encode() {
                        self.queue(Transmit { to: from, priority: 0, octets });
                    }
                }
            } else if end > rest.len() || end < header.len() {
                let error = crate::Error::MessageLength { header, message_type, length, available: rest.len() - 4 };
                self.reject_malformed(from, &header, message_type, None);
                self.events.push_back(Event::Malformed { from, error });
                return;
            } else {
                let this = &rest[..end];
                if bundled && is_node_related(message_type) {
                    self.violation(from, ViolationKind::BundledNodeMessage, this);
                }
                if let Some(seid) = header.seid.filter(|_| bundled)
                    && let Some(session) = self.sessions.get(&seid)
                {
                    peers.insert(session.peer);
                    if peers.len() == 2 {
                        self.violation(from, ViolationKind::BundledPeers, this);
                    }
                }
                match Message::decode(this) {
                    Ok(message) => self.handle_message(now, from, this, message.into_owned()),
                    Err(error) => {
                        let offending = match &error {
                            crate::Error::Ies { fault: crate::IeFault::Length { ie_type, .. }, .. } => Some(*ie_type),
                            _ => None,
                        };
                        self.reject_malformed(from, &header, message_type, offending);
                        self.events.push_back(Event::Malformed { from, error });
                    }
                }
            }
            count += 1;
            rest = &rest[end.min(rest.len())..];
            if !header.follow_on || rest.is_empty() {
                return;
            }
        }
    }

    fn handle_message(&mut self, now: Duration, from: SocketAddr, octets: &[u8], message: Message<'static>) {
        let message_type = message.body.message_type();
        match is_request(message_type) {
            true => self.handle_request(now, from, octets, message),
            false => self.handle_response(now, from, octets, message),
        }
    }

    fn handle_request(&mut self, now: Duration, from: SocketAddr, octets: &[u8], message: Message<'static>) {
        let sequence = message.header.sequence;
        let message_type = message.body.message_type();
        if let Some(answered) = self.answered.get(&(from, sequence)) {
            match (answered.request == octets, &answered.response) {
                (true, Some(response)) => {
                    let transmit = Transmit { to: from, priority: message.header.priority.unwrap_or(self.config.default_priority), octets: response.clone() };
                    self.queue(transmit);
                }
                (true, None) => {}
                (false, _) => self.violation(from, ViolationKind::ChangedRetransmission, octets),
            }
            return;
        }
        self.note_recovery(from, &message.body);
        let inbound = Inbound {
            from,
            message_type,
            sequence,
            priority: message.header.priority.unwrap_or(self.config.default_priority),
            prioritized: message.header.priority.is_some(),
            seid: message.header.seid,
            peer_seid: match &message.body {
                Body::SessionEstablishmentRequest(request) => request.cp_f_seid.as_ref().and_then(|f_seid| f_seid.seid),
                _ => None,
            },
            node_id: node_id_of(&message.body),
        };
        self.answered.insert((from, sequence), Answered { request: octets.to_vec(), response: None, expires: now + self.config.keep });
        self.answering.insert((now + self.config.keep, from, sequence));
        // What the node answers itself.
        let rejection = match message_type {
            1 => {
                let response = HeartbeatResponse::new(RecoveryTimeStamp::new(self.config.recovery_time_stamp));
                let _ = self.respond(now, &inbound, response);
                return;
            }
            7 | 9 if inbound.node_id.as_ref().is_none_or(|node| !self.associations.contains_key(&key_of(node))) => {
                Some((CauseValue::NoEstablishedPfcpAssociation, ViolationKind::UnknownNode))
            }
            50 if self.config.function == Function::Up && self.association_of(from).is_none() => {
                Some((CauseValue::NoEstablishedPfcpAssociation, ViolationKind::SessionWithoutAssociation))
            }
            52 | 54 | 56 if inbound.seid.is_none_or(|seid| !self.sessions.contains_key(&seid)) => {
                Some((CauseValue::SessionContextNotFound, ViolationKind::UnknownSeid))
            }
            _ => None,
        };
        if let Some((cause, kind)) = rejection {
            self.violation(from, kind, octets);
            if let Some(body) = rejection_body(message_type, cause, None, &self.config.node_id) {
                let mut header = message.header;
                header.follow_on = false;
                if header.seid.is_some() {
                    header.seid = Some(if kind == ViolationKind::SessionWithoutAssociation { inbound.peer_seid.unwrap_or(0) } else { 0 });
                }
                let _ = self.respond_with(now, &inbound, Message { header, body }, Delivery::Send);
            }
            return;
        }
        self.note_controls(now, from, &message.body);
        self.events.push_back(Event::Request { request: inbound, message });
    }

    fn handle_response(&mut self, now: Duration, from: SocketAddr, octets: &[u8], message: Message<'static>) {
        let sequence = message.header.sequence;
        let message_type = message.body.message_type();
        let Some(request) = self.outstanding.get(&sequence) else {
            let kind = match self.finished.get(&(sequence, from)) {
                Some((_, true)) => ViolationKind::LateResponse,
                Some((_, false)) => ViolationKind::DuplicateResponse,
                None => ViolationKind::UnknownSequence,
            };
            self.violation(from, kind, octets);
            return;
        };
        if request.to != from {
            self.violation(from, ViolationKind::WrongPeer, octets);
            return;
        }
        if message_type != request.message_type + 1 && message_type != 11 {
            self.violation(from, ViolationKind::WrongResponseType, octets);
            return;
        }
        let request = self.outstanding.remove(&sequence).expect("outstanding");
        self.deadlines.remove(&(request.deadline, sequence));
        self.finish(now, sequence, from, false);
        self.note_recovery(from, &message.body);
        self.note_controls(now, from, &message.body);
        self.response_effects(now, from, &request, &message);
        if !request.heartbeat {
            self.events.push_back(Event::Response { request: request.id, message });
        }
    }

    fn send(&mut self, now: Duration, to: SocketAddr, mut message: Message<'_>, heartbeat: bool, local_seid: Option<u64>) -> Result<RequestId, NodeError> {
        let sequence = self.next_free_sequence();
        message.header.sequence = sequence;
        let octets = message.encode()?;
        let id = RequestId(self.next_request);
        self.next_request += 1;
        let priority = message.header.priority.unwrap_or(self.config.default_priority);
        let message_type = message.body.message_type();
        self.deadlines.insert((now + self.config.t1, sequence));
        self.outstanding.insert(
            sequence,
            Outstanding { id, to, message_type, octets: octets.clone(), deadline: now + self.config.t1, attempts: 0, priority, heartbeat, local_seid },
        );
        self.queue(Transmit { to, priority, octets });
        Ok(id)
    }

    /// The next sequence number of no outstanding, reserved or recent request.
    fn next_free_sequence(&mut self) -> u32 {
        loop {
            let sequence = self.next_sequence;
            self.next_sequence = (self.next_sequence + 1) & 0x00ff_ffff;
            let lowest = SocketAddr::new(core::net::IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED), 0);
            let recent = self.finished.range((sequence, lowest)..).next().is_some_and(|((finished, _), _)| *finished == sequence);
            if !self.outstanding.contains_key(&sequence) && !self.reserved.contains(&sequence) && !recent {
                return sequence;
            }
        }
    }

    fn queue(&mut self, transmit: Transmit) {
        let priority = usize::from(transmit.priority.min(15));
        self.transmits[priority].push_back(transmit);
    }

    fn violation(&mut self, from: SocketAddr, kind: ViolationKind, octets: &[u8]) {
        self.events.push_back(Event::Violation { from, kind, octets: octets.to_vec() });
    }

    /// A request that had its response, or that the node gave up, kept until `keep`.
    fn finish(&mut self, now: Duration, sequence: u32, peer: SocketAddr, given_up: bool) {
        let until = now + self.config.keep;
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
        while let Some(&(until, peer, sequence)) = self.answering.first()
            && until <= now
        {
            self.answering.pop_first();
            if self.answered.get(&(peer, sequence)).is_some_and(|answered| answered.expires <= now) {
                self.answered.remove(&(peer, sequence));
            }
        }
    }

    fn association_of(&self, peer: SocketAddr) -> Option<&Association> {
        self.associations.values().find(|association| association.peer == peer)
    }

    /// Answer a request that does not decode, when its header says that it is one:
    /// "Invalid length" (§7.6.3, §7.6.7), with the IE when the node knows it.
    fn reject_malformed(&mut self, from: SocketAddr, header: &Header, message_type: u8, offending: Option<u16>) {
        if !is_request(message_type) || message_type == 1 {
            return;
        }
        let Some(body) = rejection_body(message_type, CauseValue::InvalidLength, offending, &self.config.node_id) else { return };
        let mut header = *header;
        header.follow_on = false;
        header.length = None;
        if header.seid.is_some() {
            header.seid = Some(0);
        }
        if let Ok(octets) = (Message { header, body }).encode() {
            self.queue(Transmit { to: from, priority: header.priority.unwrap_or(self.config.default_priority), octets });
        }
    }

    /// The Recovery Time Stamp that a message carries: a change is a restart (§6.2.2).
    fn note_recovery(&mut self, from: SocketAddr, body: &Body<'_>) {
        let stamp = match body {
            Body::HeartbeatRequest(message) => message.recovery_time_stamp.as_ref(),
            Body::HeartbeatResponse(message) => message.recovery_time_stamp.as_ref(),
            Body::AssociationSetupRequest(message) => message.recovery_time_stamp.as_ref(),
            Body::AssociationSetupResponse(message) => message.recovery_time_stamp.as_ref(),
            _ => None,
        };
        let Some(stamp) = stamp.map(|stamp| stamp.value) else { return };
        if let Some(known) = self.recovery.insert(from, stamp)
            && known != stamp
        {
            // Load and overload of the peer start again (§6.2.3.3.2, §6.2.4.3.2).
            let node = self.association_of(from).map(|association| Scope::Node(association.key.clone()));
            self.load.retain(|scope, _| *scope != Scope::Address(from.ip()) && Some(scope) != node.as_ref());
            self.overload.retain(|scope, _| *scope != Scope::Address(from.ip()) && Some(scope) != node.as_ref());
            self.events.push_back(Event::PeerRestarted { peer: from, recovery_time_stamp: stamp });
        }
    }

    /// The load and overload control information that a message carries (§6.2.3.3.3,
    /// §6.2.4.3.3).
    fn note_controls(&mut self, now: Duration, from: SocketAddr, body: &Body<'_>) {
        let (load, overload) = match body {
            Body::SessionEstablishmentResponse(message) => (message.load_control_information.as_deref(), message.overload_control_information.as_deref()),
            Body::SessionModificationResponse(message) => (message.load_control_information.as_deref(), message.overload_control_information.as_deref()),
            Body::SessionDeletionResponse(message) => (message.load_control_information.as_deref(), message.overload_control_information.as_deref()),
            Body::SessionReportRequest(message) => (message.load_control_information.as_deref(), message.overload_control_information.as_deref()),
            _ => (None, None),
        };
        let node = self.association_of(from).map(|association| Scope::Node(association.key.clone()));
        if let Some(load) = load
            && let (Some(sequence), Some(metric)) = (&load.load_control_sequence_number, &load.load_metric)
        {
            let scope = node.clone().unwrap_or(Scope::Address(from.ip()));
            let new = LoadControl { sequence: sequence.value, metric: metric.value.0 };
            match self.load.get(&scope) {
                Some(known) if known.sequence == new.sequence && known.metric != new.metric => {
                    self.events.push_back(Event::Violation { from, kind: ViolationKind::LoadControlSequence, octets: Vec::new() })
                }
                Some(known) if known.sequence != new.sequence && known.metric == new.metric && newer(new.sequence, known.sequence) => {
                    self.events.push_back(Event::Violation { from, kind: ViolationKind::LoadControlSequence, octets: Vec::new() });
                    self.load.insert(scope, new);
                }
                Some(known) if !newer(new.sequence, known.sequence) => {}
                _ => {
                    self.load.insert(scope, new);
                }
            }
        }
        if let Some(overload) = overload
            && let (Some(sequence), Some(metric), Some(validity)) =
                (&overload.overload_control_sequence_number, &overload.overload_reduction_metric, &overload.period_of_validity)
        {
            let of_node = overload.overload_control_information_flags.as_ref().is_some_and(|flags| flags.aoci);
            let scope = match (of_node, node) {
                (true, Some(node)) => node,
                _ => Scope::Address(from.ip()),
            };
            let until = timer(validity).map(|period| now.saturating_add(period));
            let new = OverloadControl { peer: from, sequence: sequence.value, metric: metric.value.0.min(100), until, credit: 0 };
            match self.overload.get(&scope) {
                Some(known) if known.sequence == new.sequence && known.metric != new.metric => {
                    self.events.push_back(Event::Violation { from, kind: ViolationKind::OverloadControlSequence, octets: Vec::new() })
                }
                Some(known) if !newer(new.sequence, known.sequence) => {}
                Some(known) => {
                    if known.metric == new.metric {
                        self.events.push_back(Event::Violation { from, kind: ViolationKind::OverloadControlSequence, octets: Vec::new() });
                    }
                    self.overload.insert(scope, OverloadControl { credit: known.credit, ..new });
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
    fn throttle(&mut self, to: SocketAddr, priority: u8) -> bool {
        if !self.config.throttling {
            return false;
        }
        let node = self.association_of(to).map(|association| Scope::Node(association.key.clone()));
        let scope = match self.overload.contains_key(&Scope::Address(to.ip())) {
            true => Scope::Address(to.ip()),
            false => match node {
                Some(node) if self.overload.contains_key(&node) => node,
                _ => return false,
            },
        };
        let spared = self.config.priority_up_to.is_some_and(|up_to| priority <= up_to);
        let overload = self.overload.get_mut(&scope).expect("overload");
        overload.credit += u32::from(overload.metric);
        // A spared request is dropped only when the others could not make the reduction.
        let owed = if spared { 200 } else { 100 };
        if overload.credit >= owed {
            overload.credit -= 100;
            return true;
        }
        false
    }

    /// What a response to a request of the node changes: the association, the session.
    fn response_effects(&mut self, now: Duration, from: SocketAddr, request: &Outstanding, message: &Message<'_>) {
        let accepted = message.body.cause().is_some_and(|cause| cause.value() < 64);
        match &message.body {
            Body::AssociationSetupResponse(response) if accepted => {
                if let Some(node_id) = &response.node_id {
                    self.associate(now, from, node_id.clone().into_owned());
                }
            }
            Body::AssociationReleaseResponse(_) if accepted => self.release(from),
            Body::SessionEstablishmentResponse(response) => {
                if let Some(local) = request.local_seid {
                    match (accepted, response.up_f_seid.as_ref().and_then(|f_seid| f_seid.seid)) {
                        (true, Some(peer_seid)) => {
                            let node = self.association_of(from).map(|association| association.key.clone()).unwrap_or_default();
                            let session = self.sessions.entry(local).or_insert(Session { peer: from, peer_seid: None, node });
                            session.peer_seid = Some(peer_seid);
                        }
                        _ => {
                            self.sessions.remove(&local);
                        }
                    }
                }
            }
            // The peer writes the local SEID in the header of its response.
            Body::SessionDeletionResponse(_) if accepted => {
                if let Some(seid) = message.header.seid {
                    self.sessions.remove(&seid);
                }
            }
            _ => {}
        }
    }

    /// What an answer of the caller changes: the association, the session.
    fn answered_effects(&mut self, now: Duration, request: &Inbound, message: &Message<'_>) {
        let accepted = message.body.cause().is_some_and(|cause| cause.value() < 64);
        if !accepted {
            return;
        }
        match (&message.body, &request.node_id) {
            (Body::AssociationSetupResponse(_), Some(node_id)) => self.associate(now, request.from, node_id.clone()),
            (Body::AssociationReleaseResponse(_), _) => self.release(request.from),
            (Body::SessionEstablishmentResponse(response), _) => {
                if let Some(local) = response.up_f_seid.as_ref().and_then(|f_seid| f_seid.seid) {
                    let node = self.association_of(request.from).map(|association| association.key.clone()).unwrap_or_default();
                    self.sessions.insert(local, Session { peer: request.from, peer_seid: request.peer_seid, node });
                }
            }
            (Body::SessionDeletionResponse(_), _) => {
                if let Some(seid) = request.seid {
                    self.sessions.remove(&seid);
                }
            }
            _ => {}
        }
    }

    fn associate(&mut self, now: Duration, peer: SocketAddr, node_id: NodeId<'static>) {
        let key = key_of(&node_id);
        let replaced = self.associations.insert(key.clone(), Association { node_id: node_id.clone(), peer, key }).is_some();
        if let Some(interval) = self.config.heartbeat {
            self.heartbeats.insert(peer, now.saturating_add(interval));
        }
        self.events.push_back(Event::Associated { peer, node_id, replaced });
    }

    fn release(&mut self, peer: SocketAddr) {
        let Some(key) = self.association_of(peer).map(|association| association.key.clone()) else { return };
        let association = self.associations.remove(&key).expect("association");
        let ended: Vec<u64> = self.sessions.iter().filter(|(_, session)| session.node == key || session.peer == peer).map(|(seid, _)| *seid).collect();
        for seid in &ended {
            self.sessions.remove(seid);
        }
        self.heartbeats.remove(&peer);
        self.events.push_back(Event::Released { node_id: association.node_id, sessions: ended });
    }
}

/// Whether sequence number `new` comes after `known`, through a roll-over of 32 bits.
fn newer(new: u32, known: u32) -> bool {
    new != known && new.wrapping_sub(known) < 0x8000_0000
}

/// The Node ID as the key of its association.
fn key_of(node_id: &NodeId<'_>) -> Vec<u8> {
    let mut octets = Vec::new();
    let _ = crate::ie::Codec::encode(node_id, &mut octets);
    octets
}

/// The Node ID that a node related request carries.
fn node_id_of(body: &Body<'_>) -> Option<NodeId<'static>> {
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
    node_id.map(|node_id| node_id.clone().into_owned())
}

/// The period of a Timer (§8.2.35): `None` for an infinite one.
fn timer(timer: &Timer<'_>) -> Option<Duration> {
    let value = u64::from(timer.timer_value);
    let unit = match timer.timer_unit {
        TimerUnit::TwoSeconds => 2,
        TimerUnit::OneMinute => 60,
        TimerUnit::TenMinutes => 600,
        TimerUnit::OneHour => 3600,
        TimerUnit::TenHours => 36_000,
        TimerUnit::Infinite => return None,
        // Other values are taken as minutes (Table 8.2.35.1).
        _ => 60,
    };
    Some(Duration::from_secs(value * unit))
}

/// The response that rejects a request of `message_type` with `cause`, with the node's
/// Node ID where the response has one, and the Offending IE.
fn rejection_body(message_type: u8, cause: CauseValue, offending: Option<u16>, node_id: &NodeId<'static>) -> Option<Body<'static>> {
    let cause = Some(Cause::new(cause));
    let node_id = Some(node_id.clone());
    let offending_ie = offending.map(OffendingIe::new);
    Some(match message_type {
        3 => PfdManagementResponse { cause, offending_ie, ..Default::default() }.into(),
        5 => AssociationSetupResponse { node_id, cause, ..Default::default() }.into(),
        7 => AssociationUpdateResponse { node_id, cause, ..Default::default() }.into(),
        9 => AssociationReleaseResponse { node_id, cause, ..Default::default() }.into(),
        12 => NodeReportResponse { node_id, cause, offending_ie, ..Default::default() }.into(),
        14 => SessionSetDeletionResponse { node_id, cause, offending_ie, ..Default::default() }.into(),
        16 => SessionSetModificationResponse { node_id, cause, offending_ie, ..Default::default() }.into(),
        50 => SessionEstablishmentResponse { node_id, cause, offending_ie, ..Default::default() }.into(),
        52 => SessionModificationResponse { cause, offending_ie, ..Default::default() }.into(),
        54 => SessionDeletionResponse { cause, offending_ie, ..Default::default() }.into(),
        56 => SessionReportResponse { cause, offending_ie, ..Default::default() }.into(),
        _ => return None,
    })
}
