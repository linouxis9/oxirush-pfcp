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
    /// An establishment of the node's, or a move of a session to it, is outstanding for
    /// it: no other may take it.
    pub(crate) reserved: bool,
}

/// The sessions of the node by their local SEIDs, with the peer's SEID of each and the
/// previous local SEIDs of the sessions that moved.
#[derive(Debug, Default)]
pub(crate) struct Sessions {
    by_local: BTreeMap<u64, Session>,
    /// (peer's SEID, local SEID) of each session that has a peer's SEID.
    by_peer: BTreeSet<(u64, u64)>,
    /// A previous local SEID of a session, after a change of its CP F-SEID: to the new
    /// one, until when.
    aliases: BTreeMap<u64, (u64, Duration)>,
    aliasing: BTreeSet<(Duration, u64)>,
}

impl Sessions {
    pub(crate) fn get(&self, local: &u64) -> Option<&Session> {
        self.by_local.get(local)
    }

    pub(crate) fn contains_key(&self, local: &u64) -> bool {
        self.by_local.contains_key(local)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&u64, &Session)> {
        self.by_local.iter()
    }

    pub(crate) fn insert(&mut self, local: u64, session: Session) {
        if let Some(seid) = session.peer_seid {
            self.by_peer.insert((seid, local));
        }
        if let Some(old) = self.by_local.insert(local, session)
            && let Some(seid) = old.peer_seid
            && self.by_local[&local].peer_seid != Some(seid)
        {
            self.by_peer.remove(&(seid, local));
        }
    }

    pub(crate) fn remove(&mut self, local: &u64) -> Option<Session> {
        let session = self.by_local.remove(local)?;
        if let Some(seid) = session.peer_seid {
            self.by_peer.remove(&(seid, *local));
        }
        Some(session)
    }

    /// Change where the messages of a session go, and the peer's SEID.
    pub(crate) fn set_peer(&mut self, local: u64, peer: SocketAddr, peer_seid: Option<u64>) {
        if let Some(mut session) = self.remove(&local) {
            session.peer = peer;
            session.peer_seid = peer_seid;
            self.insert(local, session);
        }
    }

    pub(crate) fn reserve(&mut self, local: u64, reserved: bool) {
        if let Some(session) = self.by_local.get_mut(&local) {
            session.reserved = reserved;
        }
    }

    /// The local SEIDs of the sessions whose peer's SEID is `peer_seid`.
    pub(crate) fn of_peer_seid(&self, peer_seid: u64) -> impl Iterator<Item = u64> + '_ {
        self.by_peer
            .range((peer_seid, 0)..=(peer_seid, u64::MAX))
            .map(|(_, local)| *local)
    }

    /// Keep `old` as a SEID of the session of `new` until `until`.
    pub(crate) fn alias(&mut self, old: u64, new: u64, until: Duration) {
        if let Some((_, before)) = self.aliases.insert(old, (new, until)) {
            self.aliasing.remove(&(before, old));
        }
        self.aliasing.insert((until, old));
    }

    pub(crate) fn is_alias(&self, seid: u64) -> bool {
        self.aliases.contains_key(&seid)
    }

    /// The local SEID of the session of a SEID that a header has: its own, or the one it
    /// moved to.
    pub(crate) fn resolve(&self, seid: u64) -> Option<u64> {
        match self.by_local.contains_key(&seid) {
            true => Some(seid),
            false => self
                .aliases
                .get(&seid)
                .map(|(new, _)| *new)
                .filter(|new| self.by_local.contains_key(new)),
        }
    }

    /// Forget the previous SEIDs that have outlived their time.
    pub(crate) fn prune(&mut self, now: Duration) {
        while let Some(&(until, old)) = self.aliasing.first()
            && until <= now
        {
            self.aliasing.pop_first();
            self.aliases.remove(&old);
        }
    }
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
    /// The peer of an address, as the node tells peers apart.
    Address(SocketAddr),
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
    pub(crate) octets: super::Datagram,
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

/// What tells a retransmission of a request from another request of its sequence number
/// (§6.4): its length and a hash of its octets, the FO flag aside, as a retransmission
/// need not be bundled as the first one was (§6.5 NOTE 3). A request kept for its
/// retransmissions costs no more than this, whatever its length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Digest {
    length: usize,
    hash: u64,
}

impl Digest {
    /// The digest of a request: FNV-1a of its octets.
    pub(crate) fn of(octets: &[u8]) -> Self {
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        for (at, octet) in octets.iter().enumerate() {
            let octet = if at == 0 { octet & !4 } else { *octet };
            hash = (hash ^ u64::from(octet)).wrapping_mul(0x0100_0000_01b3);
        }
        Self {
            length: octets.len(),
            hash,
        }
    }
}

/// A request that the node received: its digest, its response once given, and when the
/// response goes.
#[derive(Clone)]
pub(crate) struct Answered {
    pub(crate) request: Digest,
    pub(crate) response: Option<Vec<u8>>,
    /// The request, as the node gave it to the caller: an answer of another is not its.
    id: u64,
    expires: Duration,
    /// Its response is a rejection of the node's own.
    rejection: bool,
    /// Of a host without an association.
    stranger: bool,
}

impl core::fmt::Debug for Answered {
    /// Their lengths only: a request or its answer may hold a key.
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Answered")
            .field("request", &self.request)
            .field(
                "response",
                &self.response.as_ref().map(|response| response.len()),
            )
            .field("id", &self.id)
            .field("expires", &self.expires)
            .field("rejection", &self.rejection)
            .finish()
    }
}

/// The requests of the peers that the node keeps for their retransmissions (§6.4), at
/// most `capacity` of them: one that waits for its answer stays until the caller answers
/// or forgets it, or `keep` after it came, and an answer until `keep` after it was given;
/// a rejection of the node
/// goes first, then the oldest answer. The first answer of a request is the one of the
/// request that waits.
#[derive(Debug, Default)]
pub(crate) struct Answers {
    entries: BTreeMap<(SocketAddr, u32), Answered>,
    /// The requests that wait for their answer, the rejections of the node and the other
    /// answers, by when they go.
    waiting: BTreeSet<(Duration, SocketAddr, u32)>,
    rejections: BTreeSet<(Duration, SocketAddr, u32)>,
    answers: BTreeSet<(Duration, SocketAddr, u32)>,
    /// How many requests of hosts without an association wait for their answer.
    strangers: usize,
    pub(crate) evicted: u64,
    pub(crate) refused: u64,
}

impl Answers {
    pub(crate) fn get(&self, key: &(SocketAddr, u32)) -> Option<&Answered> {
        self.entries.get(key)
    }

    /// Whether the request `id` of `key` waits for its answer.
    pub(crate) fn waits(&self, key: &(SocketAddr, u32), id: u64) -> bool {
        self.entries
            .get(key)
            .is_some_and(|entry| entry.id == id && entry.response.is_none())
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
        if entry.stranger && entry.response.is_none() {
            self.strangers -= 1;
        }
        Some(entry)
    }

    fn insert(&mut self, key: (SocketAddr, u32), entry: Answered) {
        self.index(&entry).insert((entry.expires, key.0, key.1));
        if entry.stranger && entry.response.is_none() {
            self.strangers += 1;
        }
        self.entries.insert(key, entry);
    }

    /// How many requests of hosts without an association wait for their answer.
    pub(crate) fn strangers(&self) -> usize {
        self.strangers
    }

    /// A request dropped for a full node.
    pub(crate) fn refuse(&mut self) {
        self.refused += 1;
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

    /// Keep the request `id` until its answer or `expires`, of a `stranger` without an
    /// association or not: `false`, and counted, when there is no room.
    pub(crate) fn wait(
        &mut self,
        key: (SocketAddr, u32),
        request: Digest,
        id: u64,
        expires: Duration,
        capacity: usize,
        stranger: bool,
    ) -> bool {
        self.remove(&key);
        if !self.room(capacity, false) {
            self.refused += 1;
            return false;
        }
        let entry = Answered {
            request,
            response: None,
            id,
            expires,
            rejection: false,
            stranger,
        };
        self.insert(key, entry);
        true
    }

    /// Keep an answer of the request `id` until `expires`: whether it is its first, which
    /// the request that waits for it has. A later answer replaces the one kept, and one
    /// of a request that the node no longer keeps is not kept.
    pub(crate) fn answer(
        &mut self,
        key: (SocketAddr, u32),
        id: u64,
        response: Vec<u8>,
        expires: Duration,
    ) -> bool {
        let Some(entry) = self.entries.get(&key).filter(|entry| entry.id == id) else {
            return false;
        };
        let first = entry.response.is_none();
        let Some(mut entry) = self.remove(&key) else {
            return false;
        };
        entry.response = Some(response);
        entry.expires = expires;
        self.insert(key, entry);
        first
    }

    /// Keep a rejection of the node's own of `request`, when there is room.
    pub(crate) fn reject(
        &mut self,
        key: (SocketAddr, u32),
        request: Digest,
        response: Vec<u8>,
        expires: Duration,
        capacity: usize,
    ) {
        self.remove(&key);
        if self.room(capacity, true) {
            let entry = Answered {
                request,
                response: Some(response),
                id: 0,
                expires,
                rejection: true,
                stranger: false,
            };
            self.insert(key, entry);
        }
    }

    /// Forget the request `id` of `key`, answered or not.
    pub(crate) fn forget(&mut self, key: &(SocketAddr, u32), id: u64) {
        if self.entries.get(key).is_some_and(|entry| entry.id == id) {
            self.remove(key);
        }
    }

    /// Forget the answers that have outlived `keep`.
    pub(crate) fn prune(&mut self, now: Duration) {
        loop {
            let first = [&self.waiting, &self.rejections, &self.answers]
                .into_iter()
                .filter_map(|index| index.first().copied())
                .filter(|(until, ..)| *until <= now)
                .min();
            let Some((_, peer, sequence)) = first else {
                return;
            };
            self.remove(&(peer, sequence));
        }
    }
}
