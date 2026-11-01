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

//! What a node keeps: its requests, its answers, its peers and their sessions.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};
use core::time::Duration;

use super::RequestId;
use crate::values::NodeId;

/// An association with a peer (§6.2.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Association {
    /// The peer's Node ID, which identifies the association.
    pub node_id: NodeId,
    /// Where the requests of the node go: the peer's address, on port 8805, or as
    /// `NodeConfig::request_port` has it (§4.2.2).
    pub peer: SocketAddr,
    pub(crate) key: Vec<u8>,
}

/// A session: the peer, and its SEID once the node knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// Where its messages go: the address of the peer's F-SEID (§5.6.2), on the port of
    /// the peer.
    pub peer: SocketAddr,
    /// The peer's SEID: the SEID of the header of what goes to it.
    pub peer_seid: Option<u64>,
    pub(crate) node: Vec<u8>,
    /// An establishment of the node's is outstanding for it.
    pub(crate) establishing: bool,
}

/// The load control information of a peer (§6.2.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadControl {
    /// Its Load Control Sequence Number.
    pub sequence: u32,
    /// Its Load Metric, a percentage: of 0 to 100, a value above read as 0 (§8.2.34).
    pub metric: u8,
}

/// The overload control information of a peer, while it holds (§6.2.4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverloadControl {
    /// The peer that sent it.
    pub peer: SocketAddr,
    /// Its Overload Control Sequence Number.
    pub sequence: u32,
    /// Its Overload Reduction Metric: the percentage of the requests to throttle, of 0 to
    /// 100, a value above read as 0 (§8.2.34).
    pub metric: u8,
    /// Its Period of Validity: `None` for an infinite one.
    pub validity: Option<Duration>,
    /// When its period of validity ends: `None` for never.
    pub until: Option<Duration>,
    /// What the "Loss" algorithm owes, in hundredths of a request.
    pub(crate) credit: u32,
}

/// Whose load or overload it is: of an address, or of a Node ID (§6.2.4.3.1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Scope {
    Address(IpAddr),
    Node(Vec<u8>),
}

/// What the response to a request of the node changes, besides the association.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Change {
    /// None.
    Nothing,
    /// The session of the request ends: a deletion, or a report of a session that the UP
    /// function deleted (PSDBU, §5.18).
    Ends,
    /// The session goes to another local SEID: a modification of the CP F-SEID.
    Moves(u64),
}

/// A request of the node, until its response or its last retransmission.
#[derive(Debug, Clone)]
pub(crate) struct Outstanding {
    pub(crate) id: RequestId,
    pub(crate) to: SocketAddr,
    pub(crate) message_type: u8,
    pub(crate) octets: Vec<u8>,
    pub(crate) deadline: Duration,
    pub(crate) attempts: u8,
    pub(crate) priority: u8,
    /// A heartbeat of the node's own, whose response goes to no event.
    pub(crate) heartbeat: bool,
    /// The local SEID of the session of a session request.
    pub(crate) local_seid: Option<u64>,
    pub(crate) change: Change,
}

/// What the answer to a request of a peer changes, once accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Effect {
    /// None besides what the answer itself says.
    Nothing,
    /// An association setup: the addresses of the CP PFCP entities whose sessions the old
    /// association of the Node ID keeps, `None` for no PFCP Session Retention
    /// Information, and an empty list for all of them (§6.2.6.2.2).
    Setup(Option<Vec<IpAddr>>),
    /// The peer's F-SEID of an establishment, or the new CP F-SEID of a modification.
    PeerFSeid(u64, IpAddr),
    /// A report of a session that the UP function deleted (PSDBU, §5.18).
    Deleted,
}

/// A request that the node received: its octets, its response once given, and when it
/// goes.
#[derive(Debug, Clone)]
pub(crate) struct Answered {
    pub(crate) request: Vec<u8>,
    pub(crate) response: Option<Vec<u8>>,
    expires: Duration,
    /// Its response is a rejection of the node's own.
    rejection: bool,
}

/// The requests of the peers that the node keeps for their retransmissions (§6.4), each
/// until `keep` after it came or had its answer, and at most `capacity` of them: those
/// that wait for their answer stay, the rejections of the node go first, then the
/// oldest answers.
#[derive(Debug, Default)]
pub(crate) struct Answers {
    entries: BTreeMap<(SocketAddr, u32), Answered>,
    /// By when they go: the requests that wait for their answer, the rejections of the
    /// node and the other answers.
    waiting: BTreeSet<(Duration, SocketAddr, u32)>,
    rejections: BTreeSet<(Duration, SocketAddr, u32)>,
    answers: BTreeSet<(Duration, SocketAddr, u32)>,
    pub(crate) evicted: u64,
    pub(crate) refused: u64,
}

impl Answers {
    pub(crate) fn get(&self, key: &(SocketAddr, u32)) -> Option<&Answered> {
        self.entries.get(key)
    }

    fn index(&mut self, entry: &Answered) -> &mut BTreeSet<(Duration, SocketAddr, u32)> {
        match (&entry.response, entry.rejection) {
            (None, _) => &mut self.waiting,
            (Some(_), true) => &mut self.rejections,
            (Some(_), false) => &mut self.answers,
        }
    }

    pub(crate) fn remove(&mut self, key: &(SocketAddr, u32)) -> Option<Answered> {
        let entry = self.entries.remove(key)?;
        self.index(&entry).remove(&(entry.expires, key.0, key.1));
        Some(entry)
    }

    fn insert(&mut self, key: (SocketAddr, u32), entry: Answered) {
        self.index(&entry).insert((entry.expires, key.0, key.1));
        self.entries.insert(key, entry);
    }

    /// Room for one more: a rejection goes, else the oldest answer. `false` when every
    /// request waits for its answer, or for a rejection when the node is full.
    fn room(&mut self, capacity: usize, rejection: bool) -> bool {
        while self.entries.len() >= capacity.max(1) {
            let first = match rejection {
                true => None,
                false => self.rejections.first().or(self.answers.first()).copied(),
            };
            let Some((_, peer, sequence)) = first else {
                return false;
            };
            if self
                .remove(&(peer, sequence))
                .is_some_and(|entry| !entry.rejection)
            {
                self.evicted += 1;
            }
        }
        true
    }

    /// Keep a request until its answer: `false`, and counted, when there is no room.
    pub(crate) fn wait(
        &mut self,
        key: (SocketAddr, u32),
        request: Vec<u8>,
        expires: Duration,
        capacity: usize,
    ) -> bool {
        self.remove(&key);
        if !self.room(capacity, false) {
            self.refused += 1;
            return false;
        }
        let entry = Answered {
            request,
            response: None,
            expires,
            rejection: false,
        };
        self.insert(key, entry);
        true
    }

    /// Keep the answer of a request until `expires`, when there is room: whether it is
    /// its first answer.
    pub(crate) fn answer(
        &mut self,
        key: (SocketAddr, u32),
        response: Vec<u8>,
        expires: Duration,
        capacity: usize,
        rejection: bool,
    ) -> bool {
        let (request, first) = match self.remove(&key) {
            Some(entry) => (entry.request, entry.response.is_none()),
            None => (Vec::new(), true),
        };
        if self.room(capacity, rejection) {
            let entry = Answered {
                request,
                response: Some(response),
                expires,
                rejection,
            };
            self.insert(key, entry);
        }
        first
    }

    /// Forget what has outlived `keep`.
    pub(crate) fn prune(&mut self, now: Duration) {
        let entries = &mut self.entries;
        for index in [&mut self.waiting, &mut self.rejections, &mut self.answers] {
            while let Some(&(until, peer, sequence)) = index.first()
                && until <= now
            {
                index.pop_first();
                entries.remove(&(peer, sequence));
            }
        }
    }
}
