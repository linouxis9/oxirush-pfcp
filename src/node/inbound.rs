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

//! The peers' requests: screened from their headers, rejected or held until the caller
//! answers them (§6.4, §7.6).

use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};
use core::time::Duration;

use super::*;

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

impl Node {
    /// Take a datagram that `from` sent: each of its messages, bundled with the FO flag,
    /// on its own (§6.5).
    pub fn handle_datagram(&mut self, now: Duration, from: SocketAddr, octets: &[u8]) {
        let from = canonical(from);
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
        if bundled {
            let refused = match self.bundling_with(from, &parts) {
                Some(true) => None,
                Some(false) => Some(ViolationKind::BundlingNotAgreed),
                None => Some(ViolationKind::BundledWithoutAssociation),
            };
            if let Some(kind) = refused {
                self.violation(from, kind, octets);
                return;
            }
        }
        // The address of the node's F-SEIDs of the sessions of the bundle, of the first
        // whose session it knows (§6.5).
        let mut local = None;
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
                && let Some(address) = header
                    .seid
                    .and_then(|seid| self.sessions.resolve(seid))
                    .and_then(|seid| self.sessions.get(&seid))
                    .and_then(|session| session.local_address)
                && *local.get_or_insert(address) != address
            {
                self.violation(from, ViolationKind::BundledPeers, this);
                continue;
            }
            let Some(stranger) = self.screen(now, from, this, header, message_type) else {
                continue;
            };
            match Message::decode(this) {
                Ok(message) => match is_request(message_type) {
                    true => self.handle_request(now, from, this, message, stranger),
                    false => self.handle_response(now, from, this, message),
                },
                Err(error) => self.malformed(now, from, error),
            }
        }
        self.prune_controls();
    }

    /// What the node tells from the header of a message, and from the IEs that name the
    /// peer of a request, before it decodes the rest: a message that it discards or
    /// rejects costs it no more than its octets. `None` for a message that it handled, and
    /// whether a request is a stranger's ([`Inbound::stranger`]) for one to decode.
    pub(super) fn screen(
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
        if !is_request(message_type) {
            return self.screen_response(now, from, octets, header.sequence, message_type);
        }
        if !self.peer_sends(message_type) {
            self.violation(from, ViolationKind::WrongDirection, octets);
            return None;
        }
        let priority = header.priority.unwrap_or(self.config.default_priority);
        if self.held(from, header.sequence, priority, octets) {
            return None;
        }
        // What the node answers itself.
        let (node_id, peer_seid) = match message_type {
            7 | 9 | 12 | 14 | 16 | 50 | 56 => names(octets),
            _ => (None, None),
        };
        let (stranger, rejection) =
            self.judge(from, &header, message_type, node_id.as_ref(), peer_seid);
        let Some((cause, kind)) = rejection else {
            // A host without an association has only so many requests waiting; its
            // heartbeat, answered from the state, waits for nothing.
            if message_type != 1
                && self.unassociated(from, message_type, header.seid)
                && self.answers.strangers() >= self.config.strangers
            {
                self.answers.refuse();
                return None;
            }
            return Some(stranger);
        };
        self.violation(from, kind, octets);
        let inbound = Inbound {
            from,
            message_type,
            sequence: header.sequence,
            priority,
            prioritized: header.priority.is_some(),
            seid: header.seid,
            peer_seid,
            node_id,
            mark: None,
            effect: Effect::Nothing,
            stranger: false,
            id: 0,
        };
        self.reject(now, octets, &inbound, cause, kind);
        None
    }

    /// A response, of an outstanding request, from its peer and of its type: `Some(false)`,
    /// to decode. Another is a violation, discarded (§6.4, §7.6.5), and a Version Not
    /// Supported Response ends the requests to its peer.
    fn screen_response(
        &mut self,
        now: Duration,
        from: SocketAddr,
        octets: &[u8],
        sequence: u32,
        message_type: u8,
    ) -> Option<bool> {
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
        match kind {
            Some(kind) => {
                self.violation(from, kind, octets);
                None
            }
            None => Some(false),
        }
    }

    /// Whether the node holds a request of `sequence` from `from` already (§6.4): a
    /// retransmission, told and answered again if it has its answer, or one of other
    /// octets, discarded while it waits for its answer. A new request of a number whose
    /// request had its response is not held: a restarted peer numbers from the start again.
    fn held(&mut self, from: SocketAddr, sequence: u32, priority: u8, octets: &[u8]) -> bool {
        let Some(answered) = self.answers.get(&(from, sequence)) else {
            return false;
        };
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
                true
            }
            (false, None) => {
                self.violation(from, ViolationKind::ChangedRetransmission, octets);
                true
            }
            (false, Some(_)) => {
                self.answers.remove(&(from, sequence));
                false
            }
        }
    }

    /// Whether a request of `message_type` that names `node_id` and the peer's SEID
    /// `peer_seid` is a stranger's ([`Inbound::stranger`]), and how the node rejects it,
    /// if it does: a request of a node or a session of a host without an association, or
    /// of a session that the host does not have (§6.2.6, §7.2.2.4.2).
    fn judge(
        &self,
        from: SocketAddr,
        header: &Header,
        message_type: u8,
        node_id: Option<&NodeId>,
        peer_seid: Option<u64>,
    ) -> (bool, Option<(CauseValue, ViolationKind)>) {
        // Of the host's association: the Node ID that a request names is of it.
        let association = self
            .association_of(from)
            .map(|association| association.key.clone());
        let known_node = match node_id {
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
        // What another SMF of a set sends (§5.22), the caller's to take: an update or a
        // release of an association of the node that is not the host's, a modification or
        // a deletion of a session that is not the host's, and a UP function's report of
        // SEID 0 with the CP F-SEID of the previous SMF, which hands a session over.
        let stranger = match message_type {
            7 | 9 => {
                !known_node
                    && node_id
                        .is_some_and(|node_id| self.associations.contains_key(&key_of(node_id)))
            }
            52 | 54 => session.is_some() && !of_host,
            56 => header.seid == Some(0) && peer_seid.is_some(),
            _ => false,
        };
        let rejection = match message_type {
            _ if stranger => None,
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
        (stranger, rejection)
    }

    /// Reject a request with `cause`, and keep the rejection for its retransmissions.
    fn reject(
        &mut self,
        now: Duration,
        octets: &[u8],
        inbound: &Inbound,
        cause: CauseValue,
        kind: ViolationKind,
    ) {
        let message_type = inbound.message_type;
        let offending = (kind == ViolationKind::SeidZero).then_some(57);
        let Some(body) = rejection_body(message_type, cause, offending, &self.config.node_id)
        else {
            return;
        };
        let mut header = self.response_header(inbound);
        // The peer's SEID is not known: SEID 0 (§7.2.2.4.2), but that of the CP F-SEID of
        // an establishment without an association, which the SMF matches its response by.
        // A report of SEID 0 carries the previous SMF's SEID in its Old CP F-SEID, not the
        // peer's, so its rejection keeps SEID 0.
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
            let key = (inbound.from, inbound.sequence);
            let capacity = self.config.capacity;
            self.answers
                .reject(key, Digest::of(octets), response.clone(), expires, capacity);
            self.queue(Transmit {
                to: inbound.from,
                priority: inbound.priority,
                octets: response.into(),
            });
        }
    }

    /// A message of another version than 1 (§7.6.2): a request is answered with a
    /// Version Not Supported Response, a Version Not Supported Response of any version
    /// ends the requests to the peer, and another response ends its request.
    pub(super) fn other_version(
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
    pub(super) fn malformed(&mut self, now: Duration, from: SocketAddr, error: crate::Error) {
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

    /// Answer a request that does not decode, when its header says that it is one:
    /// "Invalid length" (§7.6.3, §7.6.7), with the IE when the node knows it. A header
    /// of the node's own, which copies none of the faults of the request's.
    pub(super) fn reject_malformed(
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

    /// A request that [`screen`](Self::screen) let through.
    pub(super) fn handle_request(
        &mut self,
        now: Duration,
        from: SocketAddr,
        octets: &[u8],
        message: Message,
        stranger: bool,
    ) {
        let sequence = message.header.sequence;
        let message_type = message.body.message_type();
        self.note_recovery(from, &message.body);
        let effect = self.effect_of(from, octets, &message.body);
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
            stranger,
            id: self.next_inbound,
        };
        self.next_inbound += 1;
        if message_type == 1 {
            // Answered from the state, the same each time: not kept.
            let stamp = RecoveryTimeStamp::new(self.config.recovery_time_stamp);
            let message = Message {
                header: self.response_header(&inbound),
                body: HeartbeatResponse::new(stamp).into(),
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
        let unassociated = self.unassociated(from, message_type, message.header.seid);
        if !self.answers.wait(
            (from, sequence),
            Digest::of(octets),
            inbound.id,
            now.saturating_add(self.config.keep),
            self.config.capacity,
            unassociated,
        ) {
            // Full of requests that wait for their answer: the peer sends it again.
            return;
        }
        self.put_off(now, inbound.seid);
        self.note_controls(now, from, octets, &message.body, inbound.seid);
        self.events.push_back(Event::Request {
            request: inbound,
            message,
        });
    }

    /// What an answer that accepts a request of `from` changes, besides what the answer says.
    fn effect_of(&mut self, from: SocketAddr, octets: &[u8], body: &Body) -> Effect {
        match body {
            Body::AssociationSetupRequest(request) => {
                let set = self.set_of(
                    request.cp_function_features.as_ref(),
                    request.up_function_features.as_ref(),
                    request.smf_set_id.as_ref(),
                );
                Effect::Setup(retained(request), set)
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
                    (features, id) => Effect::Update(features, id.map(|id| id.fqdn.0.to_vec())),
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
        }
    }

    /// The local SEID of the session that a request of a peer is of, by its mark, while it
    /// lasts: wherever it moved since the request came, and not a session that took its SEID
    /// after it ended. A request that came of no session is of the one of its `seid`, which
    /// [`respond_as`](Self::respond_as) gives it.
    pub(super) fn answered_session(&self, request: &Inbound) -> Option<u64> {
        match request.mark {
            Some(mark) => self.sessions.of_mark(mark),
            None => self.sessions.resolve(request.seid?),
        }
    }

    /// Whether a peer of the node, of the other function, sends requests of
    /// `message_type`.
    pub(super) fn peer_sends(&self, message_type: u8) -> bool {
        let peer = match self.config.function {
            Function::Cp => Function::Up,
            Function::Up => Function::Cp,
        };
        sends(peer, message_type)
    }

    /// The local SEID of the session whose peer's SEID is `peer_seid`, of `peer`: of its
    /// association, or of the address of its F-SEID (§7.2.2.4.1 NOTE).
    pub(super) fn local_seid_of(&self, peer: SocketAddr, peer_seid: u64) -> Option<u64> {
        let node = self
            .association_of(peer)
            .map(|association| association.key.as_slice());
        self.sessions.of_peer_seid(peer_seid).find(|local| {
            self.sessions.get(local).is_some_and(|session| {
                self.same_peer(session.peer, peer) || node == Some(session.node.as_slice())
            })
        })
    }
}

/// The addresses of the CP PFCP entities whose sessions a setup keeps of the old
/// association of its Node ID (§6.2.6.2.2): `None` for no PFCP Session Retention
/// Information, and none for one of a null length, which keeps every session.
fn retained(request: &AssociationSetupRequest) -> Option<Vec<IpAddr>> {
    let null = request
        .raw
        .iter()
        .any(|ie| ie.ie_type == 183 && ie.is_null());
    let Some(retention) = &request.pfcp_session_retention_information else {
        return null.then(Vec::new);
    };
    let addresses = retention.cp_pfcp_entity_ip_address.iter();
    let addresses = addresses.flat_map(|address| {
        [
            address.ipv4_address.map(IpAddr::V4),
            address.ipv6_address.map(IpAddr::V6),
        ]
        .into_iter()
        .flatten()
    });
    Some(addresses.collect())
}

/// The response that rejects a request of `message_type` with `cause`, with the node's
/// Node ID where the response has one, and the Offending IE.
pub(super) fn rejection_body(
    message_type: u8,
    cause: CauseValue,
    offending: Option<u16>,
    node_id: &NodeId,
) -> Option<Body> {
    let cause = Some(Cause::new(cause));
    let node_id = Some(node_id.clone());
    let offending_ie = offending.map(OffendingIe::new);
    // The response of the type, with the Cause and the fields named.
    macro_rules! answer {
        ($response:ident $(, $field:ident)*) => {
            $response { cause, $($field,)* ..Default::default() }.into()
        };
    }
    Some(match message_type {
        3 => answer!(PfdManagementResponse, offending_ie),
        5 => answer!(AssociationSetupResponse, node_id),
        7 => answer!(AssociationUpdateResponse, node_id),
        9 => answer!(AssociationReleaseResponse, node_id),
        12 => answer!(NodeReportResponse, node_id, offending_ie),
        14 => answer!(SessionSetDeletionResponse, node_id, offending_ie),
        16 => answer!(SessionSetModificationResponse, node_id, offending_ie),
        50 => answer!(SessionEstablishmentResponse, node_id, offending_ie),
        52 => answer!(SessionModificationResponse, offending_ie),
        54 => answer!(SessionDeletionResponse, offending_ie),
        56 => answer!(SessionReportResponse, offending_ie),
        _ => return None,
    })
}

/// The Node ID and the SEID of the CP F-SEID of a request, read from its IEs alone, as
/// the decode of its table takes them: the first IE of each type, `None` for one of a null
/// length or that does not decode, and not the IEs of its type after it (§7.6.10).
pub(super) fn names(octets: &[u8]) -> (Option<NodeId>, Option<u64>) {
    use crate::ie::Codec;
    let Ok((_, _, ies)) = crate::framing::message_ies(octets) else {
        return (None, None);
    };
    let (mut node_id, mut f_seid) = (None, None);
    for ie in ies.map_while(Result::ok) {
        match ie.ie_type {
            60 if node_id.is_none() => node_id = Some(NodeId::decode(ie.value)),
            57 if f_seid.is_none() => f_seid = Some(FSeid::decode(ie.value)),
            _ => {}
        }
    }
    let f_seid = f_seid.flatten().and_then(|f_seid| f_seid.seid);
    (node_id.flatten(), f_seid)
}

/// The Node ID that a node related request carries.
pub(super) fn node_id_of(body: &Body) -> Option<NodeId> {
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
