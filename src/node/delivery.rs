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

//! The node's requests, their retransmissions and responses, and its answers to the peers'
//! requests, kept for their retransmissions (§6.4).

use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};
use core::time::Duration;

use super::*;

/// What the response to a request of the node changes, besides the association.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Change {
    /// None.
    #[default]
    Nothing,
    /// The session of the request ends: a deletion, or a report of a session that the UP
    /// function deleted (PSDBU, §5.18).
    Ends,
    /// The session goes to another local SEID: a modification of the CP F-SEID.
    Moves(u64),
}

/// What the node keeps of a request that it sends, besides its message.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Pending {
    /// A heartbeat of the node's own, whose response goes to no event.
    pub(crate) heartbeat: bool,
    /// The local SEID of the session of a session request.
    pub(crate) local_seid: Option<u64>,
    /// The mark of the session when the request is sent.
    pub(crate) mark: Option<u64>,
    pub(crate) change: Change,
    /// The address of the node's F-SEID that the request gives the peer.
    pub(crate) local_address: Option<IpAddr>,
    /// The features of the node's function that an association setup or update announces.
    pub(crate) features: Option<Features>,
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
    /// The features of the node's function that an association setup or update announces.
    pub(crate) features: Option<Features>,
}

impl Node {
    /// Send a request to `to`, with the next sequence number. A session request needs an
    /// association with the peer, but that of a session adopted without one (§5.22.2,
    /// §5.22.3), and may be throttled for its overload. The SEID of the
    /// CP F-SEID of an establishment is the local SEID of its session, from
    /// [`new_session`](Self::new_session) or of the caller's own, which no other session
    /// then takes until the establishment ends. The new SEID of a modification that changes
    /// the CP F-SEID is the session's from when it is sent: the UP function's requests to
    /// it before the response are of the session (Table 7.5.4.1-1, CP F-SEID).
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

    pub(super) fn request_of(
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
        let change = match is_node_related(message_type) {
            true => Change::Nothing,
            false => self.session_change(to, &message, local_seid)?,
        };
        // The SEID of an establishment, even one of the caller's own, and the new SEID of a
        // move, are theirs until they end: a session of a fresh mark, made once the request
        // is sent, where none is.
        let held = match change {
            Change::Moves(new) => Some(new),
            _ => local_seid.filter(|_| establishment),
        };
        let made = held
            .filter(|seid| !self.sessions.contains_key(seid))
            .map(|seid| (seid, self.mark()));
        // The session that the request is of, which its response acts on: that of an
        // establishment is the one that it holds.
        let mark = match local_seid.and_then(|seid| self.sessions.get(&seid)) {
            Some(session) => Some(session.mark),
            None => made.filter(|_| establishment).map(|(_, mark)| mark),
        };
        // Where the peer sends the messages of the session: the CP F-SEID that the request
        // gives it (§6.5).
        let local_address = match &message.body {
            Body::SessionEstablishmentRequest(request) => request.cp_f_seid.as_ref(),
            Body::SessionModificationRequest(request) => request.cp_f_seid.as_ref(),
            _ => None,
        }
        .and_then(|f_seid| fseid_address(to, f_seid));
        let features = self.announced(&message.body);
        let pending = Pending {
            heartbeat: false,
            local_seid,
            mark,
            change,
            local_address,
            features,
        };
        let id = self.send(now, to, message, pending)?;
        if let Some(features) = features {
            self.features = features;
        }
        self.put_off(now, local_seid);
        self.hold(to, made, held, change, mark, local_address);
        Ok(id)
    }

    /// What a request holds once it is sent: the session of `made`, where none is, the SEID
    /// of an establishment or the new SEID of a move, `held`, and that new SEID for the
    /// session of `mark`, as the UP function may send to it before the response (Table
    /// 7.5.4.1-1, CP F-SEID).
    fn hold(
        &mut self,
        to: SocketAddr,
        made: Option<(u64, u64)>,
        held: Option<u64>,
        change: Change,
        mark: Option<u64>,
        local_address: Option<IpAddr>,
    ) {
        if let Some((seid, mark)) = made {
            let node = self
                .association_of(to)
                .map(|association| association.key.clone())
                .unwrap_or_default();
            let session = Session {
                peer: to,
                peer_seid: None,
                local_address,
                node,
                reserved: false,
                mark,
                adopted: false,
                until: None,
            };
            self.sessions.insert(seid, session);
        }
        if let Some(seid) = held {
            self.sessions.reserve(seid, true);
        }
        if let (Change::Moves(new), Some(mark)) = (change, mark) {
            self.sessions.hold_for(new, mark);
        }
    }

    /// What the response to a session request changes of its session, which needs an
    /// association with the peer, but that of a session adopted from a peer whose
    /// association another SMF of the set holds (§5.22), and which throttling may drop. An
    /// establishment needs an association (§6.2.6.2.1).
    fn session_change(
        &mut self,
        to: SocketAddr,
        message: &Message,
        local_seid: Option<u64>,
    ) -> Result<Change, NodeError> {
        let session = local_seid.and_then(|seid| self.sessions.get(&seid));
        let of_session = session.is_some_and(|session| {
            session.adopted || self.associations.contains_key(&session.node)
        });
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
        Ok(match &message.body {
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
        })
    }

    /// Whether a local SEID is of a session, of an outstanding establishment or move, or
    /// the previous one of a session that moved.
    pub(super) fn in_use(&self, seid: u64) -> bool {
        self.sessions
            .get(&seid)
            .is_some_and(|session| session.peer_seid.is_some() || session.reserved)
            || self.sessions.is_alias(seid)
    }

    /// The local SEID of the session that a request of the node is of, by its mark, while
    /// it lasts: wherever it moved since, and not a session that took its SEID after it
    /// ended (§6.3.3, Table 7.5.4.1-1 NOTE 2).
    pub(super) fn session_of(&self, request: &Outstanding) -> Option<u64> {
        self.sessions.of_mark(request.mark?)
    }

    /// A request that ends without its response, or with a rejection: an establishment
    /// leaves no session, and a move frees its new SEID.
    pub(super) fn abandon(&mut self, request: &Outstanding) {
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
        self.prune_controls();
        true
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

    /// A response that [`screen`](Self::screen) let through: of an outstanding request,
    /// from its peer, and of its type.
    pub(super) fn handle_response(
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
        self.note_recovery(from, &message.body);
        self.note_controls(now, from, octets, &message.body, request.local_seid);
        self.response_effects(now, from, octets, &request, &message);
        if !request.heartbeat {
            self.events.push_back(Event::Response {
                request: request.id,
                message,
            });
        }
    }

    /// Send a request with the next sequence number, and keep it until its response.
    pub(super) fn send(
        &mut self,
        now: Duration,
        to: SocketAddr,
        mut message: Message,
        pending: Pending,
    ) -> Result<RequestId, NodeError> {
        let Pending {
            heartbeat,
            local_seid,
            mark,
            change,
            local_address,
            features,
        } = pending;
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
                local_address,
                features,
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
    pub(super) fn take(&mut self, sequence: u32) -> Option<Outstanding> {
        let request = self.outstanding.remove(&sequence)?;
        self.ids.remove(&request.id);
        if request.heartbeat {
            self.beating.remove(&request.to);
        }
        Some(request)
    }

    /// The next sequence number of no outstanding, reserved or recent request.
    pub(super) fn next_free_sequence(&mut self) -> Result<u32, NodeError> {
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

    /// End the request of `sequence` to `from` without its response.
    pub(super) fn fail(
        &mut self,
        now: Duration,
        from: SocketAddr,
        sequence: u32,
        failure: Failure,
    ) {
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

    /// A Version Not Supported Response, whose sequence number says nothing (§7.2.2.2):
    /// every request to the peer fails.
    pub(super) fn version_not_supported(&mut self, now: Duration, from: SocketAddr, octets: &[u8]) {
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

    /// A request that had its response, or that the node gave up, kept until `keep`.
    pub(super) fn finish(
        &mut self,
        now: Duration,
        sequence: u32,
        peer: SocketAddr,
        given_up: bool,
    ) {
        let until = now.saturating_add(self.config.keep);
        if let Some((before, _)) = self.finished.insert((sequence, peer), (until, given_up)) {
            self.finishing.remove(&(before, sequence, peer));
        }
        self.finishing.insert((until, sequence, peer));
    }

    pub(super) fn queue(&mut self, transmit: Transmit) {
        let priority = usize::from(transmit.priority.min(15));
        self.transmits[priority].push_back(transmit);
    }

    pub(super) fn violation(&mut self, from: SocketAddr, kind: ViolationKind, octets: &[u8]) {
        self.events.push_back(Event::Violation {
            from,
            kind,
            octets: octets.to_vec().into(),
        });
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

    /// [`respond`](Self::respond) to a request as one of the session of `local_seid`, to
    /// the peer's SEID of that session: the request of SEID 0 that hands a session over
    /// (§5.22.2), whose session the caller adopted ([`adopt_session`](Self::adopt_session)).
    ///
    /// # Errors
    ///
    /// Those of [`respond`](Self::respond).
    pub fn respond_as(
        &mut self,
        now: Duration,
        request: &Inbound,
        local_seid: u64,
        body: impl Into<Body>,
    ) -> Result<(), NodeError> {
        self.respond(now, &request.of_session(local_seid), body)
    }

    /// The header of the response to `request`: its sequence number, the peer's SEID of
    /// its session, and its priority.
    pub(super) fn response_header(&self, request: &Inbound) -> Header {
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
    pub(super) fn respond_with(
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
            self.prune_controls();
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
}
