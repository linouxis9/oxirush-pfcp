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

//! Load and overload control (§6.2.3, §6.2.4): what the peers say of their load, and the
//! throttling of the requests to an overloaded one.

use alloc::vec::Vec;
use core::net::SocketAddr;
use core::time::Duration;

use super::*;

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

impl Node {
    /// The load control information that the node keeps, and whose.
    pub fn loads(&self) -> impl Iterator<Item = (ControlScope, LoadControl)> + '_ {
        self.load
            .iter()
            .map(|(scope, load)| (control_scope(scope), *load))
    }

    /// The overload control information that the node keeps, and whose, which
    /// [`overload_control`](Self::overload_control) gives of a peer.
    pub fn overloads(&self) -> impl Iterator<Item = (ControlScope, OverloadControl)> + '_ {
        self.overload
            .iter()
            .map(|(scope, overload)| (control_scope(scope), *overload))
    }

    /// The latest load control information of a peer, by the Node ID of its association
    /// (§6.2.3.3.1), kept while the association lasts.
    pub fn load_control(&self, peer: SocketAddr) -> Option<LoadControl> {
        let association = self.association_of(canonical(peer))?;
        self.load
            .get(&Scope::Node(association.key.clone()))
            .copied()
    }

    /// The overload control information that still holds for the requests to `peer`: of
    /// its address, as the UP F-SEID of a session has it, or of its Node ID (§6.2.4.3.1).
    /// The node keeps it while its period of validity lasts and a session of the address,
    /// or the association, remains: what the last of them takes with it ends without
    /// [`Event::OverloadEnded`].
    pub fn overload_control(&self, peer: SocketAddr) -> Option<OverloadControl> {
        let peer = canonical(peer);
        let node = self
            .association_of(peer)
            .map(|association| Scope::Node(association.key.clone()));
        self.overload
            .get(&Scope::Address(self.peer_key(peer)))
            .or_else(|| node.and_then(|scope| self.overload.get(&scope)))
            .copied()
    }

    /// The load and overload control information that a message of the session of
    /// `local_seid` carries (§6.2.3.3.3, §6.2.4.3.3), from a peer with an association:
    /// the load of its Node ID, and the overload of the address of the UP F-SEID of the
    /// session, or of its Node ID (§6.2.4.3.1).
    pub(super) fn note_controls(
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
        let Some((node, address)) = self.control_scopes(from, body, local_seid) else {
            return;
        };
        if let Some(load) = load {
            self.note_load(from, octets, node.clone(), load);
        }
        if let Some(overload) = overload {
            let of_node = overload
                .overload_control_information_flags
                .as_ref()
                .is_some_and(|flags| flags.aoci);
            let scope = if of_node { node } else { address };
            self.note_overload(now, from, octets, scope, overload);
        }
    }

    /// Whose controls a message of the session of `local_seid` from `from` carries: the
    /// Node ID of the association of the session, from its peer or the address of its
    /// F-SEID, and of no other host, which would fill the maps or throttle a peer; and the
    /// address of its UP F-SEID. `None` for a host of no association.
    fn control_scopes(
        &self,
        from: SocketAddr,
        body: &Body,
        local_seid: Option<u64>,
    ) -> Option<(Scope, Scope)> {
        let session = local_seid.and_then(|seid| self.sessions.get(&seid));
        let of_peer = |key: &[u8]| {
            session.is_some_and(|session| self.same_peer(session.peer, from))
                || self
                    .association_of(from)
                    .is_some_and(|association| association.key == key)
        };
        let node = match session.filter(|session| self.associations.contains_key(&session.node)) {
            Some(session) => Some(session.node.clone())
                .filter(|key| of_peer(key))
                .map(Scope::Node),
            None => self
                .association_of(from)
                .map(|association| Scope::Node(association.key.clone())),
        }?;
        let address = match body {
            Body::SessionEstablishmentResponse(response) => response
                .up_f_seid
                .as_ref()
                .map(|f_seid| self.peer_key(fseid_peer(from, f_seid))),
            _ => session.map(|session| self.peer_key(session.peer)),
        };
        Some((node, Scope::Address(address.unwrap_or(self.peer_key(from)))))
    }

    /// Load control information of `scope`, kept by its sequence number (§6.2.3.3.2).
    fn note_load(
        &mut self,
        from: SocketAddr,
        octets: &[u8],
        scope: Scope,
        load: &crate::LoadControlInformation,
    ) {
        let (Some(sequence), Some(metric)) =
            (&load.load_control_sequence_number, &load.load_metric)
        else {
            return;
        };
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

    /// Overload control information of `scope`, kept by its sequence number while its
    /// period of validity lasts (§6.2.4.3.2).
    fn note_overload(
        &mut self,
        now: Duration,
        from: SocketAddr,
        octets: &[u8],
        scope: Scope,
        overload: &crate::OverloadControlInformation,
    ) {
        let (Some(sequence), Some(metric), Some(validity)) = (
            &overload.overload_control_sequence_number,
            &overload.overload_reduction_metric,
            &overload.period_of_validity,
        ) else {
            return;
        };
        if let Scope::Address(peer) = scope {
            self.orphans.insert(peer);
        }
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
                let kept = OverloadControl {
                    credit: known.credit,
                    ..new
                };
                self.overload.insert(scope, kept);
            }
            None => {
                self.overload.insert(scope, new);
            }
        }
    }

    /// Whether the "Loss" algorithm drops a session request of `priority` to `to`
    /// (§6.2.4.4.2): of each 100 requests, as many as the Overload Reduction Metric,
    /// those of the priorities that the node spares last (§6.2.4.5.1).
    pub(super) fn throttle(
        &mut self,
        to: SocketAddr,
        local_seid: Option<u64>,
        priority: u8,
    ) -> bool {
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

    /// Forget the overload of the addresses that no session or association has any more,
    /// whose information goes with what set it.
    pub(super) fn prune_controls(&mut self) {
        let mut orphans = core::mem::take(&mut self.orphans);
        orphans.append(&mut self.sessions.emptied());
        for peer in orphans {
            if !self.sessions.has(peer) && !self.by_peer.contains_key(&peer) {
                self.overload.remove(&Scope::Address(peer));
            }
        }
    }
}

/// The public form of the scope of a load or an overload: the Node ID that its key
/// encodes.
pub(super) fn control_scope(scope: &Scope) -> ControlScope {
    match scope {
        Scope::Address(peer) => ControlScope::Address(*peer),
        Scope::Node(key) => ControlScope::Node(
            <NodeId as crate::ie::Codec>::decode(key)
                .unwrap_or_else(|| NodeId::Fqdn(crate::octets::Octets::copied(key))),
        ),
    }
}

/// Whether sequence number `new` comes after `known`, through a roll-over of 32 bits.
pub(super) fn newer(new: u32, known: u32) -> bool {
    new != known && new.wrapping_sub(known) < 0x8000_0000
}

/// The period of a Timer (§8.2.35): `None` for an infinite one.
pub(super) fn timer(timer: &Timer) -> Option<Duration> {
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
