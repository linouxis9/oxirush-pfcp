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

//! The peers: their associations (§6.2.6 to §6.2.8), Recovery Time Stamps and heartbeats
//! (§6.2.2), and what they announce of their functions.

use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};
use core::time::Duration;

use super::*;

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

impl Node {
    /// The association of `peer` (§4.2.2): of its address, or of its address and port for
    /// a node without `request_port`.
    pub(super) fn association_of(&self, peer: SocketAddr) -> Option<&Association> {
        self.by_peer
            .get(&self.peer_key(peer))
            .and_then(|key| self.associations.get(key))
    }

    /// Whether two addresses are of one peer: of one IP address when the node sends its
    /// requests to port 8805, whatever port a peer sends from (§4.2.2), and of one address
    /// and port for a node without `request_port`, whose peers have ports of their own.
    pub(super) fn same_peer(&self, one: SocketAddr, other: SocketAddr) -> bool {
        self.peer_key(one) == self.peer_key(other)
    }

    /// The address of a peer as [`same_peer`](Self::same_peer) tells them apart.
    pub(super) fn peer_key(&self, peer: SocketAddr) -> SocketAddr {
        peer_key(self.config.request_port, peer)
    }

    /// Where the requests of the node to the peer of `from` go: to port 8805 (§4.2.2),
    /// or to the port of `from` for a node without `request_port`.
    pub(super) fn request_address(&self, from: SocketAddr) -> SocketAddr {
        SocketAddr::new(from.ip(), self.config.request_port.unwrap_or(from.port()))
    }

    /// Whether a request of `message_type` of `from` to the SEID `seid`, which
    /// [`screen`](Self::screen) lets through, waits in the room of
    /// [`NodeConfig::strangers`]: from a host without an association, but for a session
    /// request of a session whose peer the host is, as the address of its F-SEID
    /// (§7.2.2.4.1 NOTE) or of a session adopted from it, which does not wait.
    pub(super) fn unassociated(
        &self,
        from: SocketAddr,
        message_type: u8,
        seid: Option<u64>,
    ) -> bool {
        let of_its_session = !is_node_related(message_type)
            && seid
                .and_then(|seid| self.sessions.resolve(seid))
                .and_then(|seid| self.sessions.get(&seid))
                .is_some_and(|session| self.same_peer(session.peer, from));
        self.association_of(from).is_none() && !of_its_session
    }

    /// Whether `from` may bundle the messages `parts` (§6.5): as the association of the
    /// host has it, when both it and the node announced BUNDL, or that of the session of the
    /// first of them that names one, whatever the host, whose messages are then taken as
    /// they would be alone: a host of the session's F-SEID address, another SMF of the set.
    /// The peer of a session adopted without an association, whose features the holder of
    /// its association knows, as the node last announced BUNDL. `None` for a host of
    /// neither.
    pub(super) fn bundling_with(&self, from: SocketAddr, parts: &[&[u8]]) -> Option<bool> {
        let agreed =
            |association: &Association| association.own.bundl && association.set.features.bundl;
        if let Some(association) = self.association_of(from) {
            return Some(agreed(association));
        }
        let session = parts.iter().find_map(|part| {
            let (header, ..) = Header::decode(part)?;
            let local = self.sessions.resolve(header.seid?)?;
            self.sessions.get(&local)
        })?;
        match self.associations.get(&session.node) {
            Some(association) => Some(agreed(association)),
            None if session.adopted && self.same_peer(session.peer, from) => {
                Some(self.features.bundl)
            }
            None => None,
        }
    }

    /// The MPAS and BUNDL that a peer says of itself: in its CP Function Features
    /// (§8.2.58) to a UP function, and in its UP Function Features (§8.2.25) to a CP
    /// function. `None` when it says none.
    pub(super) fn features_of(
        &self,
        cp: Option<&crate::CpFunctionFeatures>,
        up: Option<&crate::UpFunctionFeatures>,
    ) -> Option<Features> {
        features(self.config.function == Function::Up, cp, up)
    }

    /// What the node says of its function to the peer (§8.2.25, §8.2.58) in an association
    /// setup or update of its own, a request or an answer, which the caller writes.
    pub(super) fn announced(&self, body: &Body) -> Option<Features> {
        let (cp, up) = match body {
            Body::AssociationSetupRequest(message) => {
                (&message.cp_function_features, &message.up_function_features)
            }
            Body::AssociationUpdateRequest(message) => {
                (&message.cp_function_features, &message.up_function_features)
            }
            Body::AssociationSetupResponse(message) => {
                (&message.cp_function_features, &message.up_function_features)
            }
            Body::AssociationUpdateResponse(message) => {
                (&message.cp_function_features, &message.up_function_features)
            }
            _ => return None,
        };
        self.own_features(cp.as_ref(), up.as_ref())
    }

    /// The MPAS and BUNDL that the node says of itself, in the features of its own
    /// function, which the caller writes. `None` when it says none.
    pub(super) fn own_features(
        &self,
        cp: Option<&crate::CpFunctionFeatures>,
        up: Option<&crate::UpFunctionFeatures>,
    ) -> Option<Features> {
        features(self.config.function == Function::Cp, cp, up)
    }

    /// The SMF set that a peer says it is of in its Association Setup Request or Response.
    pub(super) fn set_of(
        &self,
        cp: Option<&crate::CpFunctionFeatures>,
        up: Option<&crate::UpFunctionFeatures>,
        id: Option<&crate::SmfSetId>,
    ) -> SetOf {
        SetOf::new(self.features_of(cp, up), id)
    }

    /// The Recovery Time Stamp that a message carries: a change is a restart (§6.2.2).
    pub(super) fn note_recovery(&mut self, from: SocketAddr, body: &Body) {
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
        // The stamps of peers without an association are bounded, the oldest first, which
        // their index gives at once.
        let key = self.peer_key(from);
        let turn = self.next_turn;
        self.next_turn += 1;
        let full = self.recovery.len() >= self.config.capacity.max(1);
        let known = self.recovery.insert(key, (stamp, turn));
        match known {
            Some((_, before)) => {
                self.aging.remove(&before);
            }
            None if full => {
                if let Some((_, oldest)) = self.aging.pop_first() {
                    self.recovery.remove(&oldest);
                }
            }
            None => {}
        }
        if !self.by_peer.contains_key(&key) {
            self.aging.insert(turn, key);
        }
        if let Some((known, _)) = known
            && known != stamp
        {
            // Load and overload of the peer start again (§6.2.3.3.2, §6.2.4.3.2).
            let node = self
                .association_of(from)
                .map(|association| Scope::Node(association.key.clone()));
            if let Some(node) = &node {
                self.load.remove(node);
            }
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

    /// Index the stamp of `peer`, as the node tells peers apart, among those that go first
    /// when the node is full, or not, as it has an association.
    pub(super) fn reage(&mut self, peer: SocketAddr) {
        if let Some(&(_, turn)) = self.recovery.get(&peer) {
            match self.by_peer.contains_key(&peer) {
                true => self.aging.remove(&turn),
                false => self.aging.insert(turn, peer),
            };
        }
    }

    /// An association with `peer` of `node_id`. As a UP function, `retained` says which
    /// sessions of an association of the same Node ID stay (§6.2.6.2.2): `Some(None)` for
    /// none, `Some(Some([]))` for all, and those of the addresses listed.
    pub(super) fn associate(
        &mut self,
        now: Duration,
        peer: SocketAddr,
        node_id: NodeId,
        retained: Option<Option<Vec<IpAddr>>>,
        set: SetOf,
        own: Features,
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
                own,
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
            // The heartbeats go to the new address, also of the same peer on another port.
            if old.peer != peer {
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
        self.reage(self.peer_key(peer));
        if let Some(old) = &replaced {
            self.reage(self.peer_key(old.peer));
        }
        self.events.push_back(Event::Associated {
            peer,
            node_id,
            replaced: replaced.is_some(),
            sessions: ended,
        });
    }

    pub(super) fn release(&mut self, key: &[u8]) {
        let Some(association) = self.associations.remove(key) else {
            return;
        };
        let peer = association.peer;
        if self.by_peer.get(&self.peer_key(peer)).map(Vec::as_slice) == Some(key) {
            self.by_peer.remove(&self.peer_key(peer));
        }
        // The load and overload of its Node ID go with it; those of its address with the
        // last session of the address.
        let node = Scope::Node(association.key.clone());
        self.load.remove(&node);
        self.overload.remove(&node);
        self.orphans.insert(self.peer_key(peer));
        self.reage(self.peer_key(peer));
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
        // With MPAS, which both the node and the peer announced, the set keeps the sessions
        // while another of its associations remains (§6.2.8, §5.22.3 bullet 1): on a UP
        // function one of the same SMF Set ID, which they go to; a CP function, which does
        // not see the set's other associations, keeps them all, for its caller to end when
        // none remains.
        let mpas = association.own.mpas && association.set.features.mpas;
        let heir = match self.config.function {
            Function::Up if mpas && association.set.id.is_some() => self
                .associations
                .values()
                .find(|other| {
                    other.own.mpas && other.set.features.mpas && other.set.id == association.set.id
                })
                .map(|other| other.key.clone()),
            _ => None,
        };
        let keeps = heir.is_some() || (mpas && self.config.function == Function::Cp);
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
        if self.association_of(peer).is_none() {
            self.heartbeats.remove(&peer);
        }
        self.events.push_back(Event::Released {
            node_id: association.node_id,
            sessions: ended,
            kept,
        });
    }

    /// What an update changes of the association of `key` (§5.22.3, bullet 1): the
    /// features of the peer's function, the FQDN of its SMF Set ID, and the features that
    /// the node announces, each taken if the update carried it, and the rest kept.
    pub(super) fn update_set(
        &mut self,
        key: &[u8],
        features: Option<Features>,
        id: Option<Vec<u8>>,
        own: Option<Features>,
    ) {
        let Some(association) = self.associations.get_mut(key) else {
            return;
        };
        if let Some(features) = features {
            association.set.features = features;
        }
        if let Some(id) = id {
            association.set.id = Some(id);
        }
        if let Some(own) = own {
            association.own = own;
        }
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
        self.prune_controls();
        true
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
        self.prune_controls();
        ended
    }
}

/// The MPAS and BUNDL of the CP Function Features, or of the UP Function Features.
pub(super) fn features(
    of_cp: bool,
    cp: Option<&crate::CpFunctionFeatures>,
    up: Option<&crate::UpFunctionFeatures>,
) -> Option<Features> {
    match of_cp {
        true => cp.map(|features| Features {
            mpas: features.mpas,
            bundl: features.bundl,
        }),
        false => up.map(|features| Features {
            mpas: features.mpas,
            bundl: features.bundl,
        }),
    }
}

/// The address of a peer: of its IP address alone, port 0, for a node of a `request_port`.
pub(super) fn peer_key(request_port: Option<u16>, peer: SocketAddr) -> SocketAddr {
    match request_port {
        Some(_) => SocketAddr::new(peer.ip(), 0),
        None => peer,
    }
}

/// The Node ID as the key of its association: as its receiver takes it, without the
/// spare bits and the octets after its value.
pub(super) fn key_of(node_id: &NodeId) -> Vec<u8> {
    let mut octets = Vec::new();
    let _ = crate::ie::Codec::encode(
        &node_id.effective().unwrap_or_else(|| node_id.clone()),
        &mut octets,
    );
    octets
}
