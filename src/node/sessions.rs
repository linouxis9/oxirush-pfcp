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

//! What the responses and the answers change of the associations and the sessions, and the
//! sessions that the caller adopts from another SMF of its set (§5.22).

use core::net::SocketAddr;
use core::time::Duration;

use super::*;

impl Node {
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
    /// then takes its requests and sends the caller's, to port 8805 of `peer` (§4.2.2), as
    /// [`NodeConfig::request_port`] has it, whatever port the request that handed the
    /// session over came from, which [`respond_as`](Self::respond_as) answers to the
    /// session's SEID.
    ///
    /// A `peer` without an association with the node is one whose association another
    /// SMF of the set holds, as the caller knows (§5.22): the node routes the session, as
    /// it takes the session's requests from the peer, outside the room of
    /// [`NodeConfig::strangers`], and sends the caller's modifications and deletions to
    /// it. The holder of the association heartbeats the peer.
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
        let peer = self.request_address(canonical(peer));
        let node = self
            .association_of(peer)
            .map(|association| association.key.clone());
        let adopted = node.is_none();
        let session = Session {
            peer,
            peer_seid: Some(peer_seid),
            local_address: None,
            node: node.unwrap_or_default(),
            reserved: false,
            mark: self.mark(),
            adopted,
            until: None,
        };
        self.sessions.insert(local_seid, session);
        Ok(())
    }

    /// End the session of `local_seid` without a procedure: one that a Session Set
    /// Deletion, a restart of the peer or the caller's own state ends.
    pub fn end_session(&mut self, local_seid: u64) -> Option<Session> {
        let session = self.sessions.remove(&local_seid);
        self.prune_controls();
        session
    }

    /// What a response to a request of the node changes: the association, the session.
    pub(super) fn response_effects(
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
                    let own = request.features.unwrap_or_default();
                    self.associate(now, from, node_id.clone(), None, set, own);
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
                    self.update_set(&key, features, None, request.features);
                }
            }
            Body::SessionEstablishmentResponse(response) => {
                self.established(from, octets, request, response, accepted);
            }
            // The session of the request, whatever SEID the header of the response has. A
            // deletion answered "More Usage Report to send", or with PURU, keeps it for the
            // UP function's last usage reports (§5.2.2.3.1).
            _ if accepted && request.change == Change::Ends => {
                if let Some(local) = self.session_of(request) {
                    match reports_follow(&message.body, true) {
                        true => self
                            .sessions
                            .end_at(local, now.saturating_add(self.config.keep)),
                        false => {
                            self.sessions.remove(&local);
                        }
                    }
                }
            }
            Body::SessionModificationResponse(_) if accepted => self.modified(now, request),
            Body::SessionModificationResponse(_) => self.abandon(request),
            Body::SessionReportResponse(response) if accepted => {
                self.taken_over(from, octets, request, response);
            }
            _ => {}
        }
    }

    /// The session that an establishment's response establishes, of the UP F-SEID that an
    /// acceptance gives, but of SEID 0, which is of no session (§7.2.2.4.2).
    fn established(
        &mut self,
        from: SocketAddr,
        octets: &[u8],
        request: &Outstanding,
        response: &SessionEstablishmentResponse,
        accepted: bool,
    ) {
        let Some(local) = self.session_of(request) else {
            return;
        };
        match (accepted, response.up_f_seid.as_ref()) {
            (true, Some(f_seid)) if f_seid.seid == Some(0) => {
                self.violation(from, ViolationKind::SeidZero, octets);
                self.abandon(request);
            }
            // A decoded F-SEID has its SEID, of no flag.
            (true, Some(f_seid)) => {
                let node = self
                    .association_of(from)
                    .map(|association| association.key.clone())
                    .unwrap_or_default();
                let session = Session {
                    peer: fseid_peer(from, f_seid),
                    peer_seid: f_seid.seid,
                    local_address: request.local_address,
                    node,
                    reserved: false,
                    mark: request.mark.expect("of the establishment"),
                    adopted: false,
                    until: None,
                };
                self.sessions.insert(local, session);
            }
            _ => self.abandon(request),
        }
    }

    /// What an accepted modification changes: the address of the new CP F-SEID, where the
    /// peer sends, and the local SEID of a move.
    fn modified(&mut self, now: Duration, request: &Outstanding) {
        if let (Some(address), Some(local)) = (request.local_address, self.session_of(request)) {
            self.sessions.set_local_address(local, address);
        }
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
                // The UP function may still send to the previous SEID, for longer than
                // twice N1 x T1 (Table 7.5.4.1-1, NOTE 2).
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

    /// A new CP F-SEID for the session, of another SMF that took it over (§5.22): not of
    /// SEID 0, which is of no session (§7.2.2.4.2).
    fn taken_over(
        &mut self,
        from: SocketAddr,
        octets: &[u8],
        request: &Outstanding,
        response: &SessionReportResponse,
    ) {
        let (Some(f_seid), Some(local)) = (response.cp_f_seid.as_ref(), self.session_of(request))
        else {
            return;
        };
        let Some(session) = self.sessions.get(&local) else {
            return;
        };
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

    /// What an answer of the caller changes: the association, the session.
    pub(super) fn answered_effects(&mut self, now: Duration, request: &Inbound, message: &Message) {
        if !accepts(&message.body) {
            return;
        }
        // The CP F-SEID of the SMF that takes a session over (§5.22), where the UP function
        // sends its messages from then on.
        if let Body::SessionReportResponse(response) = &message.body
            && let Some(address) = response
                .cp_f_seid
                .as_ref()
                .and_then(|f_seid| fseid_address(request.from, f_seid))
            && let Some(local) = self.answered_session(request)
        {
            self.sessions.set_local_address(local, address);
        }
        match (&message.body, request.effect.clone()) {
            (
                Body::AssociationSetupResponse(_)
                | Body::AssociationUpdateResponse(_)
                | Body::AssociationReleaseResponse(_),
                effect,
            ) => self.answered_association(now, request, &message.body, effect),
            (Body::SessionEstablishmentResponse(response), effect) => {
                self.answered_establishment(request, response, effect);
            }
            (Body::SessionModificationResponse(_), effect) => {
                let session = self.answered_session(request);
                if let (Effect::PeerFSeid(seid, address), Some(local)) = (effect, session) {
                    let peer = self.request_address(SocketAddr::new(address, request.from.port()));
                    self.sessions.set_peer(local, peer, Some(seid));
                }
                // The SMF of the set that modifies a session controls it (§5.22.3, bullet 3).
                if request.stranger
                    && let (Some(local), Some(key)) = (
                        session,
                        self.association_of(request.from)
                            .map(|association| association.key.clone()),
                    )
                {
                    self.sessions.set_node(local, key);
                }
            }
            // A deletion answered "More Usage Report to send" keeps the session for the
            // reports that the caller sends, the last with PSDBU (§5.2.2.3.1); one answered
            // with PURU alone does not, as its pending reports are the node's requests.
            (Body::SessionDeletionResponse(_), _) if reports_follow(&message.body, false) => {
                if let Some(local) = self.answered_session(request) {
                    self.sessions
                        .end_at(local, now.saturating_add(self.config.keep));
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

    /// What the caller's acceptance of an association setup, update or release changes,
    /// with the features that the node announces in it (§8.2.25, §8.2.58).
    fn answered_association(
        &mut self,
        now: Duration,
        request: &Inbound,
        body: &Body,
        effect: Effect,
    ) {
        let own = self.announced(body);
        if let Some(own) = own {
            self.features = own;
        }
        let Some(node_id) = &request.node_id else {
            return;
        };
        match (body, effect) {
            (Body::AssociationSetupResponse(_), Effect::Setup(retained, set)) => {
                let peer = self.request_address(request.from);
                // The retention of the sessions is the UP function's (§6.2.6.2.2): a CP
                // function stores the Node ID (§6.2.6.3.2).
                let retained = (self.config.function == Function::Up).then_some(retained);
                let own = own.unwrap_or_default();
                self.associate(now, peer, node_id.clone(), retained, set, own);
            }
            // The peer's new set features and SMF Set ID (§5.22.3, bullet 1), and the node's.
            (Body::AssociationUpdateResponse(_), Effect::Update(features, id)) => {
                self.update_set(&key_of(node_id), features, id, own);
            }
            (Body::AssociationUpdateResponse(_), _) => {
                self.update_set(&key_of(node_id), None, None, own);
            }
            // The association that the request names (§6.2.8).
            (Body::AssociationReleaseResponse(_), _) => self.release(&key_of(node_id)),
            _ => {}
        }
    }

    /// The session that the caller's acceptance of an establishment makes, of the local
    /// SEID of its UP F-SEID: not a SEID of another session, which a probe may answer with.
    fn answered_establishment(
        &mut self,
        request: &Inbound,
        response: &SessionEstablishmentResponse,
        effect: Effect,
    ) {
        let Some(local) = response.up_f_seid.as_ref().and_then(|f_seid| f_seid.seid) else {
            return;
        };
        if local == 0 || self.in_use(local) {
            return;
        }
        let node = self
            .association_of(request.from)
            .map(|association| association.key.clone())
            .unwrap_or_default();
        let peer = match effect {
            Effect::PeerFSeid(_, address) => SocketAddr::new(address, request.from.port()),
            _ => request.from,
        };
        let session = Session {
            peer: self.request_address(peer),
            peer_seid: request.peer_seid,
            local_address: response
                .up_f_seid
                .as_ref()
                .and_then(|f_seid| fseid_address(request.from, f_seid)),
            node,
            reserved: false,
            mark: self.mark(),
            adopted: false,
            until: None,
        };
        self.sessions.insert(local, session);
    }

    /// Put off the end of a session whose deletion waits for its last usage reports to
    /// `keep` after a message of it (§5.2.2.3.1).
    pub(super) fn put_off(&mut self, now: Duration, local_seid: Option<u64>) {
        if let Some(local) = local_seid
            && self
                .sessions
                .get(&local)
                .is_some_and(|session| session.until.is_some())
        {
            self.sessions
                .end_at(local, now.saturating_add(self.config.keep));
        }
    }
}

/// Whether a response accepts its request: a Cause of acceptance, as read (Table
/// 8.2.1-1), and not the reserved 0, an invalid IE.
pub(super) fn accepts(body: &Body) -> bool {
    body.cause().is_some_and(CauseValue::accepts)
}

/// Whether the response to a deletion says that the UP function's usage reports of the
/// session follow it (§5.2.2.3.1): "More Usage Report to send", and, with `pending`, the
/// PURU flag of reports that the CP function has not acknowledged.
pub(super) fn reports_follow(body: &Body, pending: bool) -> bool {
    let Body::SessionDeletionResponse(response) = body else {
        return false;
    };
    let more = response
        .cause
        .as_ref()
        .is_some_and(|cause| cause.value.effective() == CauseValue::MoreUsageReportToSend);
    let puru = response
        .pfcpsdrsp_flags
        .as_ref()
        .is_some_and(|flags| flags.puru);
    more || pending && puru
}
