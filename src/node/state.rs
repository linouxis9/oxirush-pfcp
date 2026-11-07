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
    /// The SMF set that the peer says it is of, as its setup has it (§5.22).
    pub(crate) set: SetOf,
}

/// What the node keeps of the features of a peer's function (§8.2.25, §8.2.58): SSET and
/// MPAS of the SMF sets (§5.22), and BUNDL (§6.5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Features {
    pub(crate) sset: bool,
    pub(crate) mpas: bool,
    pub(crate) bundl: bool,
}

/// What a peer says of itself in an Association Setup: of its SMF set (§5.22), the SSET
/// and MPAS of the features of its function and its SMF Set ID, and whether it bundles
/// (BUNDL, §6.5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SetOf {
    pub(crate) sset: bool,
    pub(crate) mpas: bool,
    pub(crate) bundl: bool,
    pub(crate) id: Option<Vec<u8>>,
}

impl SetOf {
    /// What a peer says: the features of its function, and the FQDN of its SMF Set ID.
    pub(crate) fn new(
        features: Option<Features>,
        id: Option<&crate::values_hand::SmfSetId>,
    ) -> Self {
        let Features { sset, mpas, bundl } = features.unwrap_or_default();
        Self {
            sset,
            mpas,
            bundl,
            id: id.map(|id| id.fqdn.0.to_vec()),
        }
    }
}

/// A session: the peer, and its SEID once the node knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// Where its messages go: the address of the peer's F-SEID (§5.6.2), on the port of
    /// the peer.
    pub peer: SocketAddr,
    /// The peer's SEID: the SEID of the header of what goes to it.
    pub peer_seid: Option<u64>,
    /// The address of the node's own F-SEID of the session, of the family of the peer:
    /// where the peer sends the messages of the session, which it bundles with those of
    /// sessions of the same address alone (§6.5). `None` while the node does not know it:
    /// a session adopted before the answer that gives its CP F-SEID.
    pub local_address: Option<IpAddr>,
    pub(crate) node: Vec<u8>,
    /// An establishment of the node's, or a move of a session to it, is outstanding for
    /// it: no other may take it.
    pub(crate) reserved: bool,
    /// Which session it is: a fresh value at each session created, kept through a move or
    /// a change of its peer. A request's outstanding carries the mark of its session, so
    /// its response acts on that session, not on another that reused its local SEID.
    pub(crate) mark: u64,
    /// The caller adopted it from a peer without an association with the node (§5.22),
    /// whose association another SMF of the set, or another PFCP entity of the SMF, holds:
    /// the node takes the session's requests from its peer as those of an association,
    /// sends the caller's, and heartbeats the peer while it has such a session.
    pub(crate) adopted: bool,
    /// Its deletion waits for the UP function's last usage reports (§5.2.2.3.1): the node
    /// ends it then, without them.
    pub(crate) until: Option<Duration>,
}

/// The sessions of the node by their local SEIDs, with the peer's SEID and the mark of
/// each, and the previous local SEIDs of the sessions that moved.
#[derive(Debug, Default)]
pub(crate) struct Sessions {
    by_local: BTreeMap<u64, Session>,
    /// (peer's SEID, local SEID) of each session that has a peer's SEID.
    by_peer: BTreeSet<(u64, u64)>,
    /// The local SEID of each session by its mark, wherever it moved.
    by_mark: BTreeMap<u64, u64>,
    /// The port of the node's requests, by which it tells its peers apart.
    request_port: Option<u16>,
    /// How many adopted sessions each peer has, as the node tells peers apart.
    adopted: BTreeMap<SocketAddr, usize>,
    /// How many sessions each peer has, as the node tells peers apart, and the peers whose
    /// last session ended since the node last took them.
    by_address: BTreeMap<SocketAddr, usize>,
    emptied: BTreeSet<SocketAddr>,
    /// The peers whose first adopted session began, or whose last ended, since the node
    /// last took them.
    flipped: BTreeSet<SocketAddr>,
    /// A previous local SEID of a session, after a change of its CP F-SEID: the mark of
    /// the session, until when.
    aliases: BTreeMap<u64, (u64, Duration)>,
    aliasing: BTreeSet<(Duration, u64)>,
    /// The sessions whose deletion waits for their last usage reports, by when the node
    /// ends them.
    ends: BTreeSet<(Duration, u64)>,
    /// The new local SEID of each outstanding move, which the UP function may send to
    /// before the response: the mark of the session that moves.
    moves: BTreeMap<u64, u64>,
}

impl Sessions {
    /// The sessions of a node of `request_port`.
    pub(crate) fn new(request_port: Option<u16>) -> Self {
        Self {
            request_port,
            ..Self::default()
        }
    }

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
        let mark = session.mark;
        *self
            .by_address
            .entry(super::peer_key(self.request_port, session.peer))
            .or_default() += 1;
        if session.adopted {
            let peer = super::peer_key(self.request_port, session.peer);
            let count = self.adopted.entry(peer).or_default();
            *count += 1;
            if *count == 1 {
                self.flipped.insert(peer);
            }
        }
        let until = session.until;
        self.moves.remove(&local);
        if let Some(old) = self.by_local.insert(local, session) {
            if let Some(seid) = old.peer_seid
                && self.by_local[&local].peer_seid != Some(seid)
            {
                self.by_peer.remove(&(seid, local));
            }
            if self.by_mark.get(&old.mark) == Some(&local) {
                self.by_mark.remove(&old.mark);
            }
            if let Some(until) = old.until {
                self.ends.remove(&(until, local));
            }
            self.unadopt(&old);
        }
        if let Some(until) = until {
            self.ends.insert((until, local));
        }
        self.by_mark.insert(mark, local);
    }

    /// Count a session that goes no more among the sessions of its peer, and its adopted
    /// sessions.
    fn unadopt(&mut self, session: &Session) {
        let peer = super::peer_key(self.request_port, session.peer);
        if let Some(count) = self.by_address.get_mut(&peer) {
            *count -= 1;
            if *count == 0 {
                self.by_address.remove(&peer);
                self.emptied.insert(peer);
            }
        }
        if session.adopted
            && let Some(count) = self.adopted.get_mut(&peer)
        {
            *count -= 1;
            if *count == 0 {
                self.adopted.remove(&peer);
                self.flipped.insert(peer);
            }
        }
    }

    /// Whether `peer`, as the node tells peers apart, has a session.
    pub(crate) fn has(&self, peer: SocketAddr) -> bool {
        self.by_address.contains_key(&peer)
    }

    /// The peers, as the node tells them apart, whose last session ended since the last
    /// call.
    pub(crate) fn emptied(&mut self) -> BTreeSet<SocketAddr> {
        core::mem::take(&mut self.emptied)
    }

    /// Whether `peer` has an adopted session.
    pub(crate) fn adopts(&self, peer: SocketAddr) -> bool {
        self.adopted
            .contains_key(&super::peer_key(self.request_port, peer))
    }

    /// The peers whose first adopted session began, or whose last ended, since the last
    /// call, as the node tells peers apart.
    pub(crate) fn flipped(&mut self) -> BTreeSet<SocketAddr> {
        core::mem::take(&mut self.flipped)
    }

    pub(crate) fn remove(&mut self, local: &u64) -> Option<Session> {
        let session = self.by_local.remove(local)?;
        self.moves.remove(local);
        if let Some(seid) = session.peer_seid {
            self.by_peer.remove(&(seid, *local));
        }
        if self.by_mark.get(&session.mark) == Some(local) {
            self.by_mark.remove(&session.mark);
        }
        if let Some(until) = session.until {
            self.ends.remove(&(until, *local));
        }
        self.unadopt(&session);
        Some(session)
    }

    /// End the session of `local` at `until`, unless something ends it before: its
    /// deletion waits for its last usage reports.
    pub(crate) fn end_at(&mut self, local: u64, until: Duration) {
        if let Some(mut session) = self.remove(&local) {
            session.until = Some(until);
            self.insert(local, session);
        }
    }

    /// When the first session whose deletion waits for its last usage reports ends.
    pub(crate) fn first_end(&self) -> Option<Duration> {
        self.ends.first().map(|(until, _)| *until)
    }

    /// End the sessions whose deletion waited for their last usage reports until `now`:
    /// their local SEIDs.
    pub(crate) fn ended(&mut self, now: Duration) -> Vec<u64> {
        let mut ended = Vec::new();
        while let Some(&(until, local)) = self.ends.first()
            && until <= now
        {
            self.ends.pop_first();
            self.remove(&local);
            ended.push(local);
        }
        ended
    }

    /// The local SEID of the session of `mark`, wherever it moved.
    pub(crate) fn of_mark(&self, mark: u64) -> Option<u64> {
        self.by_mark.get(&mark).copied()
    }

    /// The address of the node's own F-SEID of the session of `local`.
    pub(crate) fn set_local_address(&mut self, local: u64, address: IpAddr) {
        if let Some(session) = self.by_local.get_mut(&local) {
            session.local_address = Some(address);
        }
    }

    /// Change where the messages of a session go, and the peer's SEID.
    pub(crate) fn set_peer(&mut self, local: u64, peer: SocketAddr, peer_seid: Option<u64>) {
        if let Some(mut session) = self.remove(&local) {
            session.peer = peer;
            session.peer_seid = peer_seid;
            self.insert(local, session);
        }
    }

    /// Give a session to the association of `node`.
    pub(crate) fn set_node(&mut self, local: u64, node: Vec<u8>) {
        if let Some(session) = self.by_local.get_mut(&local) {
            session.node = node;
        }
    }

    pub(crate) fn reserve(&mut self, local: u64, reserved: bool) {
        if let Some(session) = self.by_local.get_mut(&local) {
            session.reserved = reserved;
        }
    }

    /// Take `new`, which an outstanding move of the session of `mark` holds, for that
    /// session, until the move ends and the session or nothing is there.
    pub(crate) fn hold_for(&mut self, new: u64, mark: u64) {
        if self.by_local.contains_key(&new) {
            self.moves.insert(new, mark);
        }
    }

    /// The local SEIDs of the sessions whose peer's SEID is `peer_seid`.
    pub(crate) fn of_peer_seid(&self, peer_seid: u64) -> impl Iterator<Item = u64> + '_ {
        self.by_peer
            .range((peer_seid, 0)..=(peer_seid, u64::MAX))
            .map(|(_, local)| *local)
    }

    /// Keep `old` as a SEID of the session of `mark` until `until`, wherever it moves.
    pub(crate) fn alias(&mut self, old: u64, mark: u64, until: Duration) {
        if let Some((_, before)) = self.aliases.insert(old, (mark, until)) {
            self.aliasing.remove(&(before, old));
        }
        self.aliasing.insert((until, old));
    }

    pub(crate) fn is_alias(&self, seid: u64) -> bool {
        self.aliases.contains_key(&seid)
    }

    /// The local SEID of the session of a SEID that a header has: its own, the one it
    /// moved to since, through any number of moves, or the one it moves from, of the new
    /// SEID of an outstanding move.
    pub(crate) fn resolve(&self, seid: u64) -> Option<u64> {
        if let Some(mark) = self.moves.get(&seid) {
            return self.of_mark(*mark);
        }
        match self.by_local.contains_key(&seid) {
            true => Some(seid),
            false => self
                .aliases
                .get(&seid)
                .and_then(|(mark, _)| self.of_mark(*mark)),
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
    /// The mark of the session when the request was sent, so its response acts on that
    /// session only.
    pub(crate) mark: Option<u64>,
    pub(crate) change: Change,
    /// The address of the node's F-SEID that the request gives the peer: of the CP F-SEID
    /// of an establishment or a modification, of the family of the peer.
    pub(crate) local_address: Option<IpAddr>,
}

/// What the answer to a request of a peer changes, once accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Effect {
    /// None besides what the answer itself says.
    Nothing,
    /// An association setup: the addresses of the CP PFCP entities whose sessions the old
    /// association of the Node ID keeps, `None` for no PFCP Session Retention
    /// Information, and an empty list for all of them (§6.2.6.2.2); and the SMF set that
    /// the CP function says.
    Setup(Option<Vec<IpAddr>>, SetOf),
    /// An association update (§5.22.3): the features of the peer's new function features,
    /// `None` for none in the update, and the FQDN of a new SMF Set ID, `None` for none.
    Update(Option<Features>, Option<Vec<u8>>),
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
    /// It had an answer of the type of its response, the one that changed the node.
    settled: bool,
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
            .field("settled", &self.settled)
            .field("expires", &self.expires)
            .field("rejection", &self.rejection)
            .finish()
    }
}

/// The requests of the peers that the node keeps for their retransmissions (§6.4), at
/// most `capacity` of them: one that waits for its answer stays until the caller answers
/// or forgets it, or `keep` after it came, and an answer until `keep` after it was given;
/// a rejection of the node
/// goes first, then the oldest answer. The answer of a request that changes the node is
/// its first of the type of its response.
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

    /// Whether the request `id` of `key` has its answer already.
    pub(crate) fn answered(&self, key: &(SocketAddr, u32), id: u64) -> bool {
        self.entries
            .get(key)
            .is_some_and(|entry| entry.id == id && entry.response.is_some())
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
            settled: false,
            expires,
            rejection: false,
            stranger,
        };
        self.insert(key, entry);
        true
    }

    /// Keep an answer of the request `id` until `expires`, `effective` for one of the type
    /// of its response: whether it is the first such, which changes the node. A later
    /// answer replaces the one kept, and one of a request that the node no longer keeps
    /// is not kept.
    pub(crate) fn answer(
        &mut self,
        key: (SocketAddr, u32),
        id: u64,
        response: Vec<u8>,
        expires: Duration,
        effective: bool,
    ) -> bool {
        if !self.entries.get(&key).is_some_and(|entry| entry.id == id) {
            return false;
        }
        let Some(mut entry) = self.remove(&key) else {
            return false;
        };
        let first = effective && !entry.settled;
        entry.settled |= effective;
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
                settled: true,
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

/// When each associated peer is due a heartbeat, and the peers by when.
#[derive(Debug, Default)]
pub(crate) struct Heartbeats {
    at: BTreeMap<SocketAddr, Duration>,
    due: BTreeSet<(Duration, SocketAddr)>,
}

impl Heartbeats {
    pub(crate) fn insert(&mut self, peer: SocketAddr, at: Duration) {
        if let Some(before) = self.at.insert(peer, at) {
            self.due.remove(&(before, peer));
        }
        self.due.insert((at, peer));
    }

    pub(crate) fn remove(&mut self, peer: &SocketAddr) {
        if let Some(before) = self.at.remove(peer) {
            self.due.remove(&(before, *peer));
        }
    }

    /// When the first is due.
    pub(crate) fn first(&self) -> Option<Duration> {
        self.due.first().map(|(at, _)| *at)
    }

    /// The peers due at `now`.
    pub(crate) fn due(&self, now: Duration) -> Vec<SocketAddr> {
        self.due
            .iter()
            .take_while(|(at, _)| *at <= now)
            .map(|(_, peer)| *peer)
            .collect()
    }
}

/// The overload control information of the peers, by its scope, and the scopes by when
/// their period of validity ends.
#[derive(Debug, Default)]
pub(crate) struct Overloads {
    by_scope: BTreeMap<Scope, OverloadControl>,
    ending: BTreeSet<(Duration, Scope)>,
}

impl Overloads {
    pub(crate) fn get(&self, scope: &Scope) -> Option<&OverloadControl> {
        self.by_scope.get(scope)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&Scope, &OverloadControl)> {
        self.by_scope.iter()
    }

    pub(crate) fn contains_key(&self, scope: &Scope) -> bool {
        self.by_scope.contains_key(scope)
    }

    /// What the "Loss" algorithm owes of a scope.
    pub(crate) fn credit(&mut self, scope: &Scope) -> Option<&mut u32> {
        self.by_scope
            .get_mut(scope)
            .map(|overload| &mut overload.credit)
    }

    pub(crate) fn insert(&mut self, scope: Scope, overload: OverloadControl) {
        self.remove(&scope);
        if let Some(until) = overload.until {
            self.ending.insert((until, scope.clone()));
        }
        self.by_scope.insert(scope, overload);
    }

    pub(crate) fn remove(&mut self, scope: &Scope) -> Option<OverloadControl> {
        let overload = self.by_scope.remove(scope)?;
        if let Some(until) = overload.until {
            self.ending.remove(&(until, scope.clone()));
        }
        Some(overload)
    }

    pub(crate) fn retain(&mut self, keep: impl Fn(&Scope, &OverloadControl) -> bool) {
        let gone: Vec<Scope> = self
            .by_scope
            .iter()
            .filter(|(scope, overload)| !keep(scope, overload))
            .map(|(scope, _)| scope.clone())
            .collect();
        for scope in gone {
            self.remove(&scope);
        }
    }

    /// When the first period of validity ends.
    pub(crate) fn first_end(&self) -> Option<Duration> {
        self.ending.first().map(|(until, _)| *until)
    }

    /// The scopes whose period of validity has ended at `now`.
    pub(crate) fn ended(&self, now: Duration) -> Vec<Scope> {
        self.ending
            .iter()
            .take_while(|(until, _)| *until <= now)
            .map(|(_, scope)| scope.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(mark: u64, adopted: bool) -> Session {
        Session {
            peer: SocketAddr::from(([10, 0, 0, 2], 8805)),
            peer_seid: Some(0x66),
            local_address: None,
            node: Vec::new(),
            reserved: false,
            mark,
            adopted,
            until: None,
        }
    }

    /// A session that another replaces at its local SEID takes its mark and its adoption
    /// with it; one removed leaves the mark that another session took.
    #[test]
    fn a_replaced_session_leaves_nothing_of_its_own() {
        let peer = session(0, false).peer;
        let mut sessions = Sessions::default();
        sessions.insert(1, session(7, true));
        assert!(sessions.adopts(peer));
        sessions.insert(1, session(8, false));
        assert!(!sessions.adopts(peer));
        assert_eq!(sessions.of_mark(7), None);
        assert_eq!(sessions.of_mark(8), Some(1));
        // A mark that another session took stays with it.
        sessions.insert(2, session(8, false));
        sessions.remove(&1);
        assert_eq!(sessions.of_mark(8), Some(2));
        sessions.insert(3, session(9, false));
        sessions.insert(2, session(9, false));
        assert_eq!(sessions.of_mark(9), Some(2));
        sessions.insert(3, session(10, false));
        assert_eq!(sessions.of_mark(9), Some(2));
    }

    /// The peers whose first adopted session begins or whose last ends are told once, as
    /// the node tells peers apart: of their addresses alone, with a port of the requests.
    #[test]
    fn the_peers_of_adopted_sessions_that_begin_or_end_are_told() {
        let mut sessions = Sessions::new(Some(8805));
        let key = SocketAddr::from(([10, 0, 0, 2], 0));
        sessions.insert(1, session(7, true));
        assert_eq!(sessions.flipped().into_iter().collect::<Vec<_>>(), [key]);
        sessions.insert(
            2,
            Session {
                peer: SocketAddr::from(([10, 0, 0, 2], 40000)),
                ..session(8, true)
            },
        );
        assert!(sessions.flipped().is_empty(), "the second is told nothing");
        assert!(sessions.adopts(SocketAddr::from(([10, 0, 0, 2], 1))));
        sessions.remove(&1);
        assert!(sessions.flipped().is_empty());
        sessions.remove(&2);
        assert_eq!(sessions.flipped().into_iter().collect::<Vec<_>>(), [key]);
        assert!(!sessions.adopts(key));
    }

    /// The peers whose last session ends are told once, whatever their sessions, and a peer
    /// has sessions while one remains, as the node tells peers apart.
    #[test]
    fn the_peers_whose_last_session_ends_are_told() {
        let mut sessions = Sessions::new(Some(8805));
        let key = SocketAddr::from(([10, 0, 0, 2], 0));
        sessions.insert(1, session(7, false));
        sessions.insert(2, session(8, true));
        assert!(sessions.has(key));
        sessions.remove(&1);
        assert!(sessions.emptied().is_empty() && sessions.has(key));
        sessions.insert(2, session(9, false));
        assert!(sessions.emptied().is_empty());
        sessions.remove(&2);
        assert_eq!(sessions.emptied().into_iter().collect::<Vec<_>>(), [key]);
        assert!(!sessions.has(key));
    }

    /// A session that another replaces at its local SEID leaves the peer's SEID of the new
    /// one: the same as before, or another.
    #[test]
    fn a_replaced_session_leaves_its_peer_seid() {
        let of_peer = |sessions: &Sessions, seid| sessions.of_peer_seid(seid).collect::<Vec<_>>();
        let mut sessions = Sessions::default();
        sessions.insert(1, session(7, false));
        sessions.insert(1, session(8, false));
        assert_eq!(of_peer(&sessions, 0x66), [1]);
        let other = Session {
            peer_seid: Some(0x67),
            ..session(9, false)
        };
        sessions.insert(1, other);
        assert_eq!(of_peer(&sessions, 0x66), Vec::<u64>::new());
        assert_eq!(of_peer(&sessions, 0x67), [1]);
    }
}
