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

//! The session related procedures (§6.3): establishment, modification, deletion and
//! report, the SEIDs of a session (§7.2.2.4), its F-SEIDs (§5.6.2, §5.18), and the SMF
//! sets (§5.22).

use super::*;

/// §6.5: a modification that changes the CP F-SEID, to another SEID or to another address
/// of the same, gives the session the address where the UP function then sends its
/// messages, once it is accepted.
#[test]
fn a_new_cp_f_seid_gives_its_session_its_address() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    let local = |smf: &Node, seid| smf.session(seid).and_then(|session| session.local_address);
    assert_eq!(local(&smf, cp_seid), Some(SMF.ip()));
    let f_seid = |seid, last| FSeid::ipv4(seid, Ipv4Addr::new(10, 0, 0, last));
    let new = smf.new_session();
    for (seid, last, now) in [(new, 11, 1), (new, 12, 2)] {
        let modification = SessionModificationRequest::default().with_cp_f_seid(f_seid(seid, last));
        let at_seid = if now == 1 { cp_seid } else { new };
        smf.session_request(at(now), at_seid, modification).unwrap();
        pass(&mut smf, &mut upf, UPF, at(now));
        let (received, _) = request(&mut upf);
        upf.respond(
            at(now),
            &received,
            SessionModificationResponse::new(accepted()),
        )
        .unwrap();
        pass(&mut upf, &mut smf, SMF, at(now));
        assert_eq!(
            local(&smf, seid),
            Some(Ipv4Addr::new(10, 0, 0, last).into()),
            "at {now} s"
        );
    }
}

// ── Sessions ────────────────────────────────────────────────────────────────

#[test]
fn session_establishment_seids() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
    assert_ne!(cp_seid, 0);
    assert_ne!(smf.new_session(), cp_seid, "a SEID of no other session");
    assert_eq!(
        smf.session(cp_seid).and_then(|session| session.peer_seid),
        Some(up_seid)
    );
    assert_eq!(
        upf.session(up_seid).and_then(|session| session.peer_seid),
        Some(cp_seid)
    );
}

#[test]
fn session_messages_carry_peer_seid() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
    smf.session_request(at(1), cp_seid, SessionModificationRequest::default())
        .unwrap();
    assert_eq!(decoded(&sent(&mut smf)[0]).header.seid, Some(up_seid));
    upf.session_request(
        at(1),
        up_seid,
        SessionReportRequest::new(ReportType::default()),
    )
    .unwrap();
    assert_eq!(decoded(&sent(&mut upf)[0]).header.seid, Some(cp_seid));
}

#[test]
fn unknown_seid_answered() {
    let (_, mut upf) = associated(at(0));
    let modification = Message::session(0xdead, 12, SessionModificationRequest::default());
    upf.handle_datagram(at(1), SMF, &modification.encode().unwrap());
    assert_eq!(violations(&mut upf), [ViolationKind::UnknownSeid]);
    let answer = decoded(&sent(&mut upf)[0]);
    assert_eq!(
        answer.body.cause(),
        Some(CauseValue::SessionContextNotFound)
    );
    assert_eq!((answer.header.seid, answer.header.sequence), (Some(0), 12));
    assert!(
        answer.check(Interfaces::N4).is_empty(),
        "{:?}",
        answer.check(Interfaces::N4)
    );
}

#[test]
fn session_deletion_ends_session() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
    smf.session_request(at(1), cp_seid, SessionDeletionRequest::default())
        .unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (received, _) = request(&mut upf);
    upf.respond(at(1), &received, SessionDeletionResponse::new(accepted()))
        .unwrap();
    assert!(upf.session(up_seid).is_none());
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(smf.session(cp_seid).is_none());
}

/// A deletion ends the session that it deletes, whatever SEID the header of its response
/// has.
#[test]
fn a_deletion_ends_the_session_that_it_deletes() {
    let (mut smf, mut upf) = associated(at(0));
    let (first, _) = established(&mut smf, &mut upf, at(0));
    let (second, _) = established(&mut smf, &mut upf, at(0));
    smf.session_request(at(1), first, SessionDeletionRequest::default())
        .unwrap();
    let request = decoded(&sent(&mut smf)[0]);
    let response = Message::session(
        second,
        request.header.sequence,
        SessionDeletionResponse::new(accepted()),
    );
    smf.handle_datagram(at(1), UPF, &response.encode().unwrap());
    assert!(smf.session(first).is_none());
    assert!(smf.session(second).is_some());
}

/// §5.6.2: the messages of a session go to the address of the peer's F-SEID; §5.22: a
/// modification that changes the CP F-SEID moves the session; §5.18: a report of a
/// session that the UP function deleted (PSDBU) ends it.
#[test]
fn a_session_follows_its_f_seids() {
    let (mut smf, mut upf) = associated(at(0));
    let cp_seid = smf.new_session();
    let f_seid = FSeid::ipv4(cp_seid, Ipv4Addr::new(10, 0, 0, 1));
    let pdr = CreatePdr::new_n4(
        PdrId::new(1),
        Precedence::new(1),
        Pdi::new(SourceInterface::new(SourceInterfaceValue::Access)),
    );
    let far = CreateFar::new(
        FarId::new(1),
        ApplyAction {
            drop: true,
            ..Default::default()
        },
    );
    let establishment = SessionEstablishmentRequest::new_n4(node_id(SMF), f_seid, pdr, far);
    smf.request(at(0), UPF, Message::session(0, 0, establishment))
        .unwrap();
    pass(&mut smf, &mut upf, UPF, at(0));
    let (received, _) = request(&mut upf);
    let up_seid = upf.new_session();
    // The UPF's F-SEID has another address than its socket
    let up_f_seid = FSeid::ipv4(up_seid, Ipv4Addr::new(10, 0, 0, 22));
    upf.respond(
        at(0),
        &received,
        SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(up_f_seid),
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(0));
    assert_eq!(
        smf.session(cp_seid).map(|session| session.peer.ip()),
        Some(Ipv4Addr::new(10, 0, 0, 22).into())
    );
    // The SMF moves the session to a new SEID of its own
    let moved = smf.new_session();
    smf.end_session(moved);
    let f_seid = FSeid::ipv4(moved, Ipv4Addr::new(10, 0, 0, 1));
    let id = smf
        .session_request(
            at(1),
            cp_seid,
            SessionModificationRequest::default().with_cp_f_seid(f_seid),
        )
        .unwrap();
    let request = decoded(&sent(&mut smf)[0]);
    upf.handle_datagram(at(1), SMF, &request.encode().unwrap());
    let (received, _) = self::request(&mut upf);
    upf.respond(
        at(1),
        &received,
        SessionModificationResponse::new(accepted()),
    )
    .unwrap();
    assert_eq!(
        upf.session(up_seid).and_then(|session| session.peer_seid),
        Some(moved)
    );
    // The response goes to the SEID of the request; what follows, to the new one
    let response = decoded(&sent(&mut upf)[0]);
    assert_eq!(response.header.seid, Some(cp_seid));
    smf.handle_datagram(
        at(1),
        Ipv4Addr::new(10, 0, 0, 22).into_socket(UPF.port()),
        &response.encode().unwrap(),
    );
    assert!(
        events(&mut smf)
            .iter()
            .any(|event| matches!(event, Event::Response { request, .. } if *request == id))
    );
    assert!(smf.session(cp_seid).is_none() && smf.session(moved).is_some());
    // The UPF deletes the session, and says so in a report
    let report = SessionReportRequest::new(ReportType {
        upir: true,
        ..Default::default()
    })
    .with_pfcpsrreq_flags(PFCPSRReqFlags {
        psdbu: true,
        ..Default::default()
    });
    upf.session_request(at(2), up_seid, report).unwrap();
    let request = decoded(&sent(&mut upf)[0]);
    smf.handle_datagram(at(2), UPF, &request.encode().unwrap());
    let (received, _) = self::request(&mut smf);
    smf.respond(at(2), &received, SessionReportResponse::new(accepted()))
        .unwrap();
    assert!(smf.session(moved).is_none());
    upf.handle_datagram(at(2), SMF, &sent(&mut smf)[0].octets);
    assert!(upf.session(up_seid).is_none());
}

/// An establishment that times out leaves no session; the caller ends the sessions of a
/// peer that restarted, and an association that went down.
#[test]
fn sessions_that_end_without_a_procedure() {
    let (mut smf, mut upf) = associated(at(0));
    let pending = smf.new_session();
    let f_seid = FSeid::ipv4(pending, Ipv4Addr::new(10, 0, 0, 1));
    let pdr = CreatePdr::new_n4(
        PdrId::new(1),
        Precedence::new(1),
        Pdi::new(SourceInterface::new(SourceInterfaceValue::Access)),
    );
    let far = CreateFar::new(
        FarId::new(1),
        ApplyAction {
            drop: true,
            ..Default::default()
        },
    );
    smf.request(
        at(0),
        UPF,
        Message::session(
            0,
            0,
            SessionEstablishmentRequest::new_n4(node_id(SMF), f_seid, pdr, far),
        ),
    )
    .unwrap();
    for attempt in 1..=4 {
        smf.handle_timeout(T1 * attempt);
    }
    assert!(smf.session(pending).is_none());
    sent(&mut smf);
    events(&mut smf);
    let (first, _) = established(&mut smf, &mut upf, at(20));
    let (second, _) = established(&mut smf, &mut upf, at(20));
    assert_eq!(smf.end_sessions_of(UPF), [first, second]);
    let (third, _) = established(&mut smf, &mut upf, at(21));
    assert!(smf.end_association(UPF));
    assert!(smf.association(UPF).is_none() && smf.session(third).is_none());
    assert!(events(&mut smf).contains(&Event::Released {
        node_id: node_id(UPF),
        sessions: vec![third],
        kept: vec![]
    }));
}

/// A session request is of a session of the host's, which is established: one of a
/// session of another, of a host with an association or without, is a stranger's, which
/// the caller takes or rejects, and one of a session not established yet is answered
/// "Session context not found".
#[test]
fn a_session_request_of_a_session_of_the_host() {
    let (mut smf, mut upf) = associated(at(0));
    let (_, up_seid) = established(&mut smf, &mut upf, at(0));
    let deletion = |seid| {
        Message::session(seid, 9, SessionDeletionRequest::default())
            .encode()
            .unwrap()
    };
    let stranger: SocketAddr = "10.0.0.66:8805".parse().unwrap();
    upf.handle_datagram(at(1), stranger, &deletion(up_seid));
    let (received, _) = request(&mut upf);
    assert!(received.stranger);
    let allocated = upf.new_session();
    upf.handle_datagram(at(1), SMF, &deletion(allocated));
    assert_eq!(violations(&mut upf), [ViolationKind::UnknownSeid]);
    upf.handle_datagram(at(1), OTHER, &setup_of(OTHER, 1, 1000));
    let (received, _) = request(&mut upf);
    upf.respond(at(1), &received, setup_answer()).unwrap();
    sent(&mut upf);
    upf.handle_datagram(at(2), OTHER, &deletion(up_seid));
    let (received, _) = request(&mut upf);
    assert!(received.stranger);
    assert!(upf.session(up_seid).is_some());
}

/// An establishment of a local SEID that a session or another establishment has is
/// not sent, and a rejected establishment leaves the other sessions alone.
#[test]
fn an_establishment_of_a_seid_in_use_is_refused() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    assert_eq!(
        smf.request(at(1), UPF, establishment(cp_seid)),
        Err(NodeError::SeidInUse)
    );
    // A SEID of the caller's own is the establishment's until it ends
    let own = 0x1001;
    smf.request(at(1), UPF, establishment(own)).unwrap();
    assert_eq!(
        smf.request(at(1), UPF, establishment(own)),
        Err(NodeError::SeidInUse)
    );
    for _ in 0..0x1001 {
        assert_ne!(smf.new_session(), own);
    }
    pass(&mut smf, &mut upf, UPF, at(1));
    let (received, _) = request(&mut upf);
    let rejected =
        SessionEstablishmentResponse::new(node_id(UPF), Cause::new(CauseValue::RequestRejected));
    upf.respond(at(1), &received, rejected).unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(smf.session(own).is_none());
    assert!(smf.session(cp_seid).is_some());
    // Nor does a session move to the SEID of another
    let (other, _) = established(&mut smf, &mut upf, at(2));
    let moved = FSeid::ipv4(other, Ipv4Addr::new(10, 0, 0, 1));
    let modification = SessionModificationRequest::default().with_cp_f_seid(moved);
    assert_eq!(
        smf.session_request(at(2), cp_seid, modification),
        Err(NodeError::SeidInUse)
    );
    // But to one that new_session gave for it
    let fresh = smf.new_session();
    let moved = FSeid::ipv4(fresh, Ipv4Addr::new(10, 0, 0, 1));
    let modification = SessionModificationRequest::default().with_cp_f_seid(moved);
    smf.session_request(at(2), cp_seid, modification).unwrap();
    pass(&mut smf, &mut upf, UPF, at(2));
    let (received, _) = request(&mut upf);
    upf.respond(
        at(2),
        &received,
        SessionModificationResponse::new(accepted()),
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(2));
    assert!(smf.session(cp_seid).is_none());
    assert!(
        smf.session(fresh)
            .is_some_and(|session| session.peer_seid.is_some())
    );
}

/// A move of a session holds its new SEID until it ends: another move or an
/// establishment to it is refused, and a rejected move frees it.
#[test]
fn a_move_holds_its_new_seid() {
    let (mut smf, mut upf) = associated(at(0));
    let (first, _) = established(&mut smf, &mut upf, at(0));
    let (second, _) = established(&mut smf, &mut upf, at(0));
    let target = 0x9999;
    let to_target = || {
        let moved = FSeid::ipv4(target, Ipv4Addr::new(10, 0, 0, 1));
        SessionModificationRequest::default().with_cp_f_seid(moved)
    };
    smf.session_request(at(1), first, to_target()).unwrap();
    assert_eq!(
        smf.session_request(at(1), second, to_target()),
        Err(NodeError::SeidInUse)
    );
    assert_eq!(
        smf.request(at(1), UPF, establishment(target)),
        Err(NodeError::SeidInUse)
    );
    pass(&mut smf, &mut upf, UPF, at(1));
    let (received, _) = request(&mut upf);
    let rejected = SessionModificationResponse::new(Cause::new(CauseValue::RequestRejected));
    upf.respond(at(1), &received, rejected).unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(smf.session(first).is_some() && smf.session(target).is_none());
    smf.session_request(at(2), second, to_target()).unwrap();
    pass(&mut smf, &mut upf, UPF, at(2));
    let (received, _) = request(&mut upf);
    upf.respond(
        at(2),
        &received,
        SessionModificationResponse::new(accepted()),
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(2));
    assert!(smf.session(first).is_some() && smf.session(target).is_some());
    assert!(smf.session(second).is_none());
}

/// A move that is accepted when its session has ended, or of a session that the node
/// does not know, frees its new SEID.
#[test]
fn a_move_of_no_session_frees_its_new_seid() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
    let to = |seid| {
        let moved = FSeid::ipv4(seid, Ipv4Addr::new(10, 0, 0, 1));
        SessionModificationRequest::default().with_cp_f_seid(moved)
    };
    let new = smf.new_session();
    smf.session_request(at(1), cp_seid, to(new)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (received, _) = request(&mut upf);
    smf.end_session(cp_seid);
    upf.respond(
        at(1),
        &received,
        SessionModificationResponse::new(accepted()),
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(smf.session(new).is_none());
    // A modification that request() sends with the SEID of no session of the node
    let modification = Message::session(up_seid + 1000, 0, to(0x4242));
    smf.request(at(2), UPF, modification).unwrap();
    let sequence = decoded(&sent(&mut smf)[0]).header.sequence;
    let response = Message::session(1, sequence, SessionModificationResponse::new(accepted()));
    smf.handle_datagram(at(2), UPF, &response.encode().unwrap());
    assert!(smf.session(0x4242).is_none());
}

/// Table 7.5.4.1-1 NOTE 2: after a change of its CP F-SEID, the CP function takes the
/// session messages of the UP function to the previous SEID for longer than twice N1 x
/// T1, as of the session.
#[test]
fn the_previous_seid_of_a_moved_session() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    let fresh = smf.new_session();
    let moved = FSeid::ipv4(fresh, Ipv4Addr::new(10, 0, 0, 1));
    let modification = SessionModificationRequest::default().with_cp_f_seid(moved);
    smf.session_request(at(1), cp_seid, modification).unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (received, _) = request(&mut upf);
    upf.respond(
        at(1),
        &received,
        SessionModificationResponse::new(accepted()),
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    events(&mut smf);
    let report = |sequence| {
        Message::session(
            cp_seid,
            sequence,
            SessionReportRequest::new(ReportType {
                upir: true,
                ..Default::default()
            }),
        )
    };
    // 2 x N1 x T1 is 18 s: at 20 s, the previous SEID is of the session still
    smf.handle_datagram(at(20), UPF, &report(900).encode().unwrap());
    let (received, _) = request(&mut smf);
    assert_eq!(received.seid, Some(fresh));
    assert_eq!(
        smf.request(at(20), UPF, establishment(cp_seid)),
        Err(NodeError::SeidInUse)
    );
    smf.handle_datagram(at(60), UPF, &report(901).encode().unwrap());
    assert_eq!(violations(&mut smf), [ViolationKind::UnknownSeid]);
}

/// §7.2.2.4.1 NOTE: a session request is of the session of its SEID, sent to the address
/// of the association or to that of the session's F-SEID.
#[test]
fn a_session_request_by_its_seid_whatever_its_address() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, up_seid) = established_on(&mut smf, &mut upf, at(0), Ipv4Addr::new(10, 0, 0, 22));
    let deletion = Message::session(up_seid, 0, SessionDeletionRequest::default());
    smf.request(at(1), UPF, deletion).unwrap();
    for transmit in sent(&mut smf) {
        upf.handle_datagram(at(1), SMF, &transmit.octets);
    }
    let (received, _) = request(&mut upf);
    upf.respond(at(1), &received, SessionDeletionResponse::new(accepted()))
        .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(smf.session(cp_seid).is_none());
}

/// §7.2.2.4.2: a SEID of 0 says that the peer's is not known: it is no local SEID, and an
/// answer that gives it as the peer's establishes nothing.
#[test]
fn a_seid_of_zero_is_of_no_session() {
    // A modification of the node to a CP F-SEID of SEID 0, or of the session's own SEID
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    let to = |seid| {
        SessionModificationRequest::default()
            .with_cp_f_seid(FSeid::ipv4(seid, Ipv4Addr::new(10, 0, 0, 11)))
    };
    assert_eq!(
        smf.session_request(at(1), cp_seid, to(0)),
        Err(NodeError::SeidZero)
    );
    assert!(smf.session_request(at(1), cp_seid, to(cp_seid)).is_ok());
    // That one moves nothing: its SEID is free for another session once the session ends
    pass(&mut smf, &mut upf, UPF, at(1));
    let (received, _) = request(&mut upf);
    upf.respond(
        at(1),
        &received,
        SessionModificationResponse::new(accepted()),
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    smf.session_request(at(2), cp_seid, SessionDeletionRequest::default())
        .unwrap();
    pass(&mut smf, &mut upf, UPF, at(2));
    let (received, _) = request(&mut upf);
    upf.respond(at(2), &received, SessionDeletionResponse::new(accepted()))
        .unwrap();
    pass(&mut upf, &mut smf, SMF, at(2));
    assert!(smf.session(cp_seid).is_none());
    let f_seid = FSeid::ipv4(cp_seid, Ipv4Addr::new(10, 0, 0, 1));
    let pdr = CreatePdr::new_n4(
        PdrId::new(1),
        Precedence::new(1),
        Pdi::new(SourceInterface::new(SourceInterfaceValue::Access)),
    );
    let far = CreateFar::new(
        FarId::new(1),
        ApplyAction {
            forw: true,
            ..Default::default()
        },
    );
    let again = Message::session(
        0,
        0,
        SessionEstablishmentRequest::new_n4(node_id(SMF), f_seid, pdr, far),
    );
    assert!(smf.request(at(3), UPF, again).is_ok());
    let (mut smf, mut upf) = associated(at(0));
    assert_eq!(
        smf.request(at(1), UPF, establishment(0)),
        Err(NodeError::SeidZero)
    );
    let cp_seid = smf.new_session();
    smf.request(at(1), UPF, establishment(cp_seid)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (received, _) = request(&mut upf);
    let zero = FSeid::ipv4(0, Ipv4Addr::new(10, 0, 0, 2));
    let response = SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(zero);
    assert_eq!(
        upf.respond(at(1), &received, response.clone()),
        Err(NodeError::SeidZero)
    );
    // A probe's answer with it: no session 0 on either side
    let message = Message::session(cp_seid, received.sequence, response);
    upf.respond_message(at(1), &received, message, Delivery::Send)
        .unwrap();
    assert!(upf.session(0).is_none());
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(smf.session(cp_seid).is_none());
    assert_eq!(violations(&mut smf), [ViolationKind::SeidZero]);
    let modification = Message::session(0, 77, SessionModificationRequest::default());
    upf.handle_datagram(at(2), SMF, &modification.encode().unwrap());
    assert_eq!(violations(&mut upf), [ViolationKind::UnknownSeid]);
}

/// §7.2.2.4.2 on the UP side: a CP F-SEID of SEID 0 is of no session. An establishment
/// of it is answered "Mandatory IE incorrect", and a modification or a report's response
/// that gives it changes no peer's SEID.
#[test]
fn a_peer_seid_of_zero_is_kept_by_no_session() {
    let (mut smf, mut upf) = associated(at(0));
    let zero = FSeid::ipv4(0, Ipv4Addr::new(10, 0, 0, 1));
    let pdr = CreatePdr::new_n4(
        PdrId::new(1),
        Precedence::new(1),
        Pdi::new(SourceInterface::new(SourceInterfaceValue::Access)),
    );
    let far = CreateFar::new(
        FarId::new(1),
        ApplyAction {
            forw: true,
            ..Default::default()
        },
    );
    let establishment = Message::session(
        0,
        40,
        SessionEstablishmentRequest::new_n4(node_id(SMF), zero.clone(), pdr, far),
    );
    upf.handle_datagram(at(1), SMF, &establishment.encode().unwrap());
    assert_eq!(violations(&mut upf), [ViolationKind::SeidZero]);
    let Body::SessionEstablishmentResponse(answer) = decoded(&sent(&mut upf)[0]).body else {
        panic!()
    };
    assert_eq!(
        (
            answer.cause.map(|cause| cause.value),
            answer.offending_ie.map(|ie| ie.value)
        ),
        (Some(CauseValue::MandatoryIeIncorrect), Some(57))
    );
    // A modification that moves the session to SEID 0
    let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(2));
    let modification = Message::session(
        up_seid,
        41,
        SessionModificationRequest::default().with_cp_f_seid(zero),
    );
    upf.handle_datagram(at(3), SMF, &modification.encode().unwrap());
    let got = events(&mut upf);
    assert!(
        got.iter().any(|event| matches!(
            event,
            Event::Violation {
                kind: ViolationKind::SeidZero,
                ..
            }
        )),
        "{got:?}"
    );
    let received = got
        .into_iter()
        .find_map(|event| match event {
            Event::Request { request, .. } => Some(request),
            _ => None,
        })
        .unwrap();
    upf.respond(
        at(3),
        &received,
        SessionModificationResponse::new(accepted()),
    )
    .unwrap();
    assert_eq!(
        upf.session(up_seid).and_then(|session| session.peer_seid),
        Some(cp_seid)
    );
}

/// The UP function's answer that gives the local SEID of another session is not sent.
#[test]
fn an_answer_of_a_seid_in_use_is_refused() {
    let (mut smf, mut upf) = associated(at(0));
    let (_, up_seid) = established(&mut smf, &mut upf, at(0));
    let other = smf.new_session();
    smf.request(at(1), UPF, establishment(other)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (received, _) = request(&mut upf);
    let up_f_seid = FSeid::ipv4(up_seid, Ipv4Addr::new(10, 0, 0, 2));
    let response =
        SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(up_f_seid);
    assert_eq!(
        upf.respond(at(1), &received, response),
        Err(NodeError::SeidInUse)
    );
    assert_eq!(
        upf.session(up_seid).and_then(|session| session.peer_seid),
        Some(1)
    );
}

// ── SMF sets (§5.22) ─────────────────────────────────────────────────────────

/// An Association Setup Request of an SMF of `node_id` from `from`, with the features of
/// an SMF set and its SMF Set ID.
fn setup_of_set(node_id: NodeId, features: CpFunctionFeatures, set: Option<&str>) -> Vec<u8> {
    let mut request = AssociationSetupRequest::new(node_id, RecoveryTimeStamp::new(1000))
        .with_cp_function_features(features);
    if let Some(set) = set {
        request = request.with_smf_set_id(SmfSetId {
            fqdn: Fqdn::new(set).unwrap(),
            ..Default::default()
        });
    }
    Message::node(1, request).encode().unwrap()
}

/// A UPF associated with an SMF at each of `smfs`, which gives its Node ID, its features and
/// its set, and which answers each with MPAS in its UP Function Features or not; and a
/// session of the first.
fn upf_of_set(
    mpas: bool,
    smfs: &[(SocketAddr, NodeId, CpFunctionFeatures, Option<&str>)],
) -> (Node, u64) {
    let mut upf = node(UPF, Function::Up);
    for (from, node_id, features, set) in smfs {
        upf.handle_datagram(
            at(0),
            *from,
            &setup_of_set(node_id.clone(), features.clone(), *set),
        );
        let (received, _) = request(&mut upf);
        let answer = setup_answer().with_up_function_features(UpFunctionFeatures {
            mpas,
            ..Default::default()
        });
        upf.respond(at(0), &received, answer).unwrap();
    }
    let (from, node_id, ..) = &smfs[0];
    let f_seid = FSeid::ipv4(0x51, Ipv4Addr::new(10, 0, 0, 1));
    let pdr = CreatePdr::new_n4(
        PdrId::new(1),
        Precedence::new(1),
        Pdi::new(SourceInterface::new(SourceInterfaceValue::Access)),
    );
    let far = CreateFar::new(
        FarId::new(1),
        ApplyAction {
            forw: true,
            ..Default::default()
        },
    );
    let establishment = Message::session(
        0,
        2,
        SessionEstablishmentRequest::new_n4(node_id.clone(), f_seid, pdr, far),
    );
    upf.handle_datagram(at(0), *from, &establishment.encode().unwrap());
    let (received, _) = request(&mut upf);
    let up_seid = upf.new_session();
    let up_f_seid = FSeid::ipv4(up_seid, Ipv4Addr::new(10, 0, 0, 2));
    let response =
        SessionEstablishmentResponse::new(node_id_of_upf(), accepted()).with_up_f_seid(up_f_seid);
    upf.respond(at(0), &received, response).unwrap();
    sent(&mut upf);
    events(&mut upf);
    (upf, up_seid)
}

fn node_id_of_upf() -> NodeId {
    node_id(UPF)
}

/// The CP Function Features of an SMF of a set, of MPAS or of SSET.
fn mpas() -> CpFunctionFeatures {
    CpFunctionFeatures {
        mpas: true,
        ..Default::default()
    }
}

fn sset_features() -> CpFunctionFeatures {
    CpFunctionFeatures {
        sset: true,
        ..Default::default()
    }
}

/// §5.22.3 bullet 3, §5.22.2 bullet 3: another SMF of a set modifies or deletes a session,
/// and updates or releases the association, with an association of its own or none: the
/// UPF gives its caller each request that names a session or an association that is not
/// its sender's as a stranger's, for the caller to take or reject; accepted, a
/// modification gives the session to the sender's association. What names none of the
/// node's is answered as before.
#[test]
fn a_request_of_another_peers_session_is_a_strangers() {
    let smf_b = Ipv4Addr::new(10, 0, 0, 5).into_socket(8805);
    let smf_c: SocketAddr = Ipv4Addr::new(10, 0, 0, 7).into_socket(8805);
    let smfs = [
        (SMF, node_id(SMF), mpas(), Some("set")),
        (smf_b, node_id(smf_b), mpas(), Some("set")),
    ];
    let modification =
        |seid, sequence| Message::session(seid, sequence, SessionModificationRequest::default());
    let deletion = |seid| Message::session(seid, 5, SessionDeletionRequest::default());
    let (mut upf, up_seid) = upf_of_set(false, &smfs);
    // Of a session that is not theirs: B with an association, C without
    assert_eq!(taken(&mut upf, smf_c, modification(up_seid, 6)), Ok(true));
    assert_eq!(taken(&mut upf, smf_c, deletion(up_seid)), Ok(true));
    assert_eq!(taken(&mut upf, SMF, modification(up_seid, 6)), Ok(false));
    upf.handle_datagram(at(1), smf_b, &modification(up_seid, 7).encode().unwrap());
    let (received, _) = request(&mut upf);
    assert!(received.stranger);
    upf.respond(
        at(1),
        &received,
        SessionModificationResponse::new(accepted()),
    )
    .unwrap();
    // The session is of B's association now
    assert_eq!(taken(&mut upf, smf_b, modification(up_seid, 8)), Ok(false));
    // Of no session, as before
    assert_eq!(
        taken(&mut upf, smf_c, modification(0x999, 10)),
        Err(vec![ViolationKind::SessionWithoutAssociation])
    );
    assert_eq!(
        taken(&mut upf, smf_b, modification(0x999, 11)),
        Err(vec![ViolationKind::UnknownSeid])
    );
    // An update or a release of the association of another SMF, and of none
    let update = |node_id| AssociationUpdateRequest::new(node_id);
    let release = |node_id| AssociationReleaseRequest::new(node_id);
    assert_eq!(
        taken(&mut upf, smf_c, Message::node(12, update(node_id(SMF)))),
        Ok(true)
    );
    assert_eq!(
        taken(&mut upf, smf_b, Message::node(13, release(node_id(SMF)))),
        Ok(true)
    );
    assert_eq!(
        taken(&mut upf, SMF, Message::node(14, update(node_id(SMF)))),
        Ok(false)
    );
    assert_eq!(
        taken(&mut upf, smf_c, Message::node(15, update(node_id(smf_c)))),
        Err(vec![ViolationKind::UnknownNode])
    );
    // An establishment needs an association (§6.2.6.2.1)
    assert_eq!(
        taken(&mut upf, smf_c, establishment(0x61)),
        Err(vec![ViolationKind::SessionWithoutAssociation])
    );
}

/// §6.2.8 with MPAS, which the SMFs and the UPF announced in their association messages:
/// the release of an association keeps its sessions while another of the SMF set remains,
/// of which they are then; that of the last ends them.
#[test]
fn mpas_a_release_keeps_the_sessions_of_the_set() {
    let smf_b = Ipv4Addr::new(10, 0, 0, 5).into_socket(8805);
    let smfs = [
        (SMF, node_id(SMF), mpas(), Some("set")),
        (smf_b, node_id(smf_b), mpas(), Some("set")),
    ];
    let (mut upf, up_seid) = upf_of_set(true, &smfs);
    let release =
        |from: SocketAddr| Message::node(9, AssociationReleaseRequest::new(node_id(from)));
    for (from, kept) in [(SMF, true), (smf_b, false)] {
        upf.handle_datagram(at(2), from, &release(from).encode().unwrap());
        let (received, _) = request(&mut upf);
        upf.respond(
            at(2),
            &received,
            AssociationReleaseResponse::new(node_id(UPF), accepted()),
        )
        .unwrap();
        let released = events(&mut upf)
            .into_iter()
            .find_map(|event| match event {
                Event::Released { sessions, kept, .. } => Some((sessions, kept)),
                _ => None,
            })
            .unwrap();
        match kept {
            true => assert_eq!(released, (vec![], vec![up_seid])),
            false => assert_eq!(released, (vec![up_seid], vec![])),
        }
        assert_eq!(upf.session(up_seid).is_some(), kept);
    }
    // An association of the set of which the UPF or the SMF did not announce MPAS takes
    // nothing: the sessions of the released one end
    for (upf_announces, smf_announces) in [(false, true), (true, false)] {
        let (mut upf, up_seid) = upf_of_set(true, &smfs[..1]);
        let features = if smf_announces { mpas() } else { cp_features() };
        upf.handle_datagram(
            at(1),
            smf_b,
            &setup_of_set(node_id(smf_b), features, Some("set")),
        );
        let (received, _) = request(&mut upf);
        let up = UpFunctionFeatures {
            mpas: upf_announces,
            ..up_features()
        };
        let mut answer = setup_answer();
        if upf_announces {
            answer = answer.with_up_function_features(up);
        }
        upf.respond(at(1), &received, answer).unwrap();
        events(&mut upf);
        assert!(upf.end_association(SMF));
        let released = events(&mut upf).into_iter().find_map(|event| match event {
            Event::Released { sessions, kept, .. } => Some((sessions, kept)),
            _ => None,
        });
        assert_eq!(
            released,
            Some((vec![up_seid], vec![])),
            "{upf_announces} {smf_announces}"
        );
    }
}

/// §5.22.2 and §5.22.3, bullet 5: a UP function hands a session over to an SMF of the set
/// with a request of SEID 0 and the CP F-SEID of the previous SMF, whether the SMF holds the
/// association or another SMF of the set does: the SMF gives it its caller as a
/// stranger's, which takes the session over by adopting it, and answers it to the UP
/// function's SEID. The adopted session is then routed: its reports, its modifications. A
/// report of SEID 0 without the previous CP F-SEID is of no session.
#[test]
fn a_session_handed_over_to_an_smf_of_the_set() {
    for associated_upf in [true, false] {
        let mut smf = match associated_upf {
            true => associated(at(0)).0,
            false => node(SMF, Function::Cp),
        };
        smf.handle_datagram(at(1), UPF, &handover_report().encode().unwrap());
        let (received, _) = request(&mut smf);
        assert!(received.stranger);
        // The caller takes the session over, of the UPF's SEID that the set knows
        let local = smf.new_session();
        smf.adopt_session(local, UPF, 0x77).unwrap();
        assert_eq!(
            smf.adopt_session(local, UPF, 0x77),
            Err(NodeError::SeidInUse)
        );
        smf.respond_as(
            at(1),
            &received,
            local,
            SessionReportResponse::new(accepted()),
        )
        .unwrap();
        assert_eq!(decoded(&sent(&mut smf)[0]).header.seid, Some(0x77));
        // A report of the session that it took over is of its own
        let report = Message::session(
            local,
            10,
            SessionReportRequest::new(ReportType {
                upir: true,
                ..Default::default()
            }),
        );
        assert_eq!(taken(&mut smf, UPF, report), Ok(false));
        // Its modifications go to the UPF's SEID
        smf.session_request(at(2), local, SessionModificationRequest::default())
            .unwrap();
        assert_eq!(decoded(&sent(&mut smf)[0]).header.seid, Some(0x77));
        let mut lone = handover_report();
        let Body::SessionReportRequest(report) = &mut lone.body else {
            panic!()
        };
        report.old_cp_f_seid = None;
        let refused = match associated_upf {
            true => ViolationKind::UnknownSeid,
            false => ViolationKind::SessionWithoutAssociation,
        };
        assert_eq!(taken(&mut smf, UPF, lone), Err(vec![refused]));
    }
}

/// §5.22.2 bullet 4: a UP function sends a session's request to another SMF of the set,
/// one without an association too, of SEID 0 with the CP F-SEID of the previous SMF; the
/// answer's CP F-SEID is where the session's requests go after (§5.22.2 bullet 5).
#[test]
fn a_session_moved_to_another_smf_of_the_set() {
    let set = fqdn("set.example");
    let other: SocketAddr = Ipv4Addr::new(10, 0, 0, 7).into_socket(8805);
    let (mut upf, up_seid) = upf_of_set(false, &[(SMF, set, sset_features(), None)]);
    let old = FSeid::ipv4(0x51, Ipv4Addr::new(10, 0, 0, 1));
    let report = SessionReportRequest::new(ReportType {
        uisr: true,
        ..Default::default()
    })
    .with_old_cp_f_seid(old);
    upf.request(at(1), other, Message::session(0, 0, report))
        .unwrap();
    let sequence = decoded(&sent(&mut upf)[0]).header.sequence;
    let new = FSeid::ipv4(0x99, Ipv4Addr::new(10, 0, 0, 7));
    let response = Message::session(
        up_seid,
        sequence,
        SessionReportResponse::new(accepted()).with_cp_f_seid(new),
    );
    upf.handle_datagram(at(1), other, &response.encode().unwrap());
    let session = upf.session(up_seid).unwrap();
    assert_eq!((session.peer, session.peer_seid), (other, Some(0x99)));
    assert_eq!(
        violations(&mut upf),
        [],
        "a CP F-SEID of a SEID other than 0"
    );
}

/// Table 7.5.4.1-1 NOTE 2, §6.3.3: the accepted response to a session's outstanding
/// request acts on that session, not on a new one that reused its local SEID. A move is
/// outstanding for a session; the caller ends it and establishes a new session of the
/// same SEID; the move's response must not move the new session.
#[test]
fn an_outstanding_move_does_not_take_a_reused_seid() {
    let (mut smf, mut upf) = associated(at(0));
    let l = 0x10;
    let n = 0x20;
    let up = |seid| FSeid::ipv4(seid, Ipv4Addr::new(10, 0, 0, 2));
    // Establish session L, UP SEID 1.
    smf.request(at(0), UPF, establishment(l)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(0));
    let (received, _) = request(&mut upf);
    upf.respond(
        at(0),
        &received,
        SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(up(1)),
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(0));
    events(&mut smf);
    // A move of L to N is outstanding; keep its datagram for later.
    let moved = FSeid::ipv4(n, Ipv4Addr::new(10, 0, 0, 1));
    smf.session_request(
        at(1),
        l,
        SessionModificationRequest::default().with_cp_f_seid(moved),
    )
    .unwrap();
    let move_datagram = sent(&mut smf);
    // The caller ends L and establishes a new session of the same SEID; UP SEID 2.
    smf.end_session(l);
    smf.request(at(1), UPF, establishment(l)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (received, _) = request(&mut upf);
    upf.respond(
        at(1),
        &received,
        SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(up(2)),
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    events(&mut smf);
    // The old move's response arrives.
    for transmit in &move_datagram {
        upf.handle_datagram(at(1), SMF, &transmit.octets);
    }
    let (received, _) = request(&mut upf);
    upf.respond(
        at(1),
        &received,
        SessionModificationResponse::new(accepted()),
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    events(&mut smf);
    // L is still the new session (UP SEID 2); N holds no session.
    assert_eq!(
        smf.session(l).and_then(|session| session.peer_seid),
        Some(2)
    );
    assert!(smf.session(n).is_none());
}

/// Table 7.4.4.3-1, §5.22.3: an Association Update carries the supported features, which
/// the node must take, not only a new SMF Set ID. An SMF that turns MPAS off in an update
/// no longer shares its sessions with the set: its release ends them.
#[test]
fn an_association_update_changes_the_set_features() {
    let smf_b = Ipv4Addr::new(10, 0, 0, 5).into_socket(8805);
    let smfs = [
        (SMF, node_id(SMF), mpas(), Some("set")),
        (smf_b, node_id(smf_b), mpas(), Some("set")),
    ];
    let (mut upf, up_seid) = upf_of_set(true, &smfs);
    // A turns MPAS off in an Association Update, with no new SMF Set ID.
    let update = Message::node(
        8,
        AssociationUpdateRequest::new(node_id(SMF))
            .with_cp_function_features(CpFunctionFeatures::default()),
    );
    upf.handle_datagram(at(2), SMF, &update.encode().unwrap());
    let (received, _) = request(&mut upf);
    upf.respond(
        at(2),
        &received,
        AssociationUpdateResponse::new(node_id(UPF), accepted()),
    )
    .unwrap();
    assert!(upf.end_association(SMF));
    let released = events(&mut upf).into_iter().find_map(|event| match event {
        Event::Released { sessions, kept, .. } => Some((sessions, kept)),
        _ => None,
    });
    assert_eq!(released, Some((vec![up_seid], vec![])));
}

/// The same of a UPF's Association Update to an SMF: the SMF takes the MPAS of the UPF's
/// new UP Function Features, kept or withdrawn, for a release.
#[test]
fn a_cp_takes_the_mpas_of_a_upf_update() {
    assert!(cp_keeps_with_a_upf_that_sets_up(Some(true)));
    assert!(!cp_keeps_with_a_upf_that_sets_up(Some(false)));
}

/// §6.2.8.2: a CP function keeps the sessions of a released association only when the
/// MPAS feature is used, which both announce: the CP its own in the CP Function Features
/// of its Association Setup Request, the UPF in the UP Function Features of its response.
/// Without either, the CP ends the sessions on release.
#[test]
fn a_cp_keeps_released_sessions_only_with_an_mpas_upf() {
    let outcome = |cp_mpas: bool, up_mpas: bool| {
        let (mut smf, mut upf) = (node(SMF, Function::Cp), node(UPF, Function::Up));
        let cp = CpFunctionFeatures {
            mpas: cp_mpas,
            ..cp_features()
        };
        let up = UpFunctionFeatures {
            mpas: up_mpas,
            ..up_features()
        };
        set_up(&mut smf, &mut upf, at(0), cp, up);
        events(&mut smf);
        let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
        assert!(smf.end_association(UPF));
        let released = events(&mut smf)
            .into_iter()
            .find_map(|event| match event {
                Event::Released { sessions, kept, .. } => Some((sessions, kept)),
                _ => None,
            })
            .unwrap();
        (released, smf.session(cp_seid).is_some())
    };
    // A UPF, or an SMF, that did not announce MPAS: the CP ends the sessions.
    for (cp_mpas, up_mpas) in [(true, false), (false, true)] {
        let ((sessions, kept), still) = outcome(cp_mpas, up_mpas);
        assert!(!still);
        assert_eq!(kept, Vec::<u64>::new());
        assert!(!sessions.is_empty());
    }
    // Both announced MPAS: the CP keeps them for its caller to decide.
    let ((sessions, kept), still) = outcome(true, true);
    assert!(still);
    assert_eq!(sessions, Vec::<u64>::new());
    assert!(!kept.is_empty());
}

/// §5.22.3 bullet 1, §6.2.6.3: a UPF may set the associations up itself, with MPAS in its
/// requests; each SMF of the set then says its MPAS and its SMF Set ID in its Association
/// Setup Response, which the UPF takes: a release leaves a session to another SMF of the
/// set.
#[test]
fn mpas_of_associations_that_the_upf_sets_up() {
    let smf_b = Ipv4Addr::new(10, 0, 0, 5).into_socket(8805);
    let mut upf = node(UPF, Function::Up);
    for smf in [SMF, smf_b] {
        let setup = AssociationSetupRequest::new(node_id(UPF), RecoveryTimeStamp::new(1000))
            .with_up_function_features(UpFunctionFeatures {
                mpas: true,
                ..Default::default()
            });
        upf.request(at(0), smf, Message::node(0, setup)).unwrap();
        let sequence = decoded(&sent(&mut upf)[0]).header.sequence;
        let response =
            AssociationSetupResponse::new(node_id(smf), accepted(), RecoveryTimeStamp::new(1000))
                .with_cp_function_features(mpas())
                .with_smf_set_id(SmfSetId {
                    fqdn: Fqdn::new("set").unwrap(),
                    ..Default::default()
                });
        let response = Message::node(sequence, response);
        upf.handle_datagram(at(0), smf, &response.encode().unwrap());
    }
    events(&mut upf);
    upf.handle_datagram(at(0), SMF, &establishment(0x51).encode().unwrap());
    let (received, _) = request(&mut upf);
    let up_seid = upf.new_session();
    let up_f_seid = FSeid::ipv4(up_seid, Ipv4Addr::new(10, 0, 0, 2));
    upf.respond(
        at(0),
        &received,
        SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(up_f_seid),
    )
    .unwrap();
    sent(&mut upf);
    events(&mut upf);
    assert!(upf.end_association(SMF));
    let released = events(&mut upf).into_iter().find_map(|event| match event {
        Event::Released { sessions, kept, .. } => Some((sessions, kept)),
        _ => None,
    });
    assert_eq!(released, Some((vec![], vec![up_seid])));
}

/// A CP function of MPAS that a UPF sets an association up with, announcing MPAS, then
/// updating its UP Function Features to `update`; whether a release then keeps a session.
fn cp_keeps_with_a_upf_that_sets_up(update: Option<bool>) -> bool {
    let mut smf = node(SMF, Function::Cp);
    let mut upf = node(UPF, Function::Up);
    let up_mpas = |mpas| UpFunctionFeatures {
        mpas,
        ..Default::default()
    };
    let setup = AssociationSetupRequest::new(node_id(UPF), RecoveryTimeStamp::new(1000))
        .with_up_function_features(up_mpas(true));
    upf.request(at(0), SMF, Message::node(0, setup)).unwrap();
    pass(&mut upf, &mut smf, SMF, at(0));
    let (received, _) = request(&mut smf);
    let answer =
        AssociationSetupResponse::new(node_id(SMF), accepted(), RecoveryTimeStamp::new(1000))
            .with_cp_function_features(mpas());
    smf.respond(at(0), &received, answer).unwrap();
    pass(&mut smf, &mut upf, UPF, at(0));
    events(&mut upf);
    events(&mut smf);
    if let Some(mpas) = update {
        let update =
            AssociationUpdateRequest::new(node_id(UPF)).with_up_function_features(up_mpas(mpas));
        upf.request(at(0), SMF, Message::node(0, update)).unwrap();
        pass(&mut upf, &mut smf, SMF, at(0));
        let (received, _) = request(&mut smf);
        smf.respond(
            at(0),
            &received,
            AssociationUpdateResponse::new(node_id(SMF), accepted()),
        )
        .unwrap();
        pass(&mut smf, &mut upf, UPF, at(0));
        events(&mut upf);
    }
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    assert!(smf.end_association(UPF));
    events(&mut smf)
        .into_iter()
        .any(|event| matches!(event, Event::Released { ref kept, .. } if kept == &[cp_seid]))
}

/// §6.2.6.3, §6.2.8.2: a CP function that a UPF sets an association up with takes the
/// UPF's MPAS from the UP Function Features of its request: a release keeps the sessions.
#[test]
fn a_cp_takes_the_mpas_of_a_upf_that_sets_up() {
    assert!(cp_keeps_with_a_upf_that_sets_up(None));
}

/// §5.22.3 bullets 1 and 3: with MPAS, a session that another SMF of the set took over
/// (a modification with its Node ID) is that SMF's. The release of the association that
/// no longer controls the session must leave it with its SMF, not hand it to a third SMF
/// of the set because that one's Node ID sorts first.
#[test]
fn mpas_a_release_leaves_a_taken_over_session_with_its_smf() {
    let a = SMF;
    let b: SocketAddr = Ipv4Addr::new(10, 0, 0, 30).into_socket(8805);
    let c: SocketAddr = Ipv4Addr::new(10, 0, 0, 10).into_socket(8805);
    let smfs = [
        (a, node_id(a), mpas(), Some("set")),
        (b, node_id(b), mpas(), Some("set")),
        (c, node_id(c), mpas(), Some("set")),
    ];
    let (mut upf, up_seid) = upf_of_set(true, &smfs);
    // B takes the session over, with its Node ID and no new CP F-SEID.
    let takeover = Message::session(
        up_seid,
        7,
        SessionModificationRequest::default().with_node_id(node_id(b)),
    );
    upf.handle_datagram(at(1), b, &takeover.encode().unwrap());
    let (received, _) = request(&mut upf);
    assert!(received.stranger);
    upf.respond(
        at(1),
        &received,
        SessionModificationResponse::new(accepted()),
    )
    .unwrap();
    let bs = |seq| Message::session(up_seid, seq, SessionModificationRequest::default());
    // The session is B's now: B's own modification is not a stranger's.
    assert_eq!(taken(&mut upf, b, bs(8)), Ok(false));
    // A releases its association.
    let release = Message::node(9, AssociationReleaseRequest::new(node_id(a)));
    upf.handle_datagram(at(2), a, &release.encode().unwrap());
    let (received, _) = request(&mut upf);
    upf.respond(
        at(2),
        &received,
        AssociationReleaseResponse::new(node_id(UPF), accepted()),
    )
    .unwrap();
    events(&mut upf);
    // The session stays B's: it is kept, and still not a stranger's for B.
    assert!(upf.session(up_seid).is_some());
    assert_eq!(taken(&mut upf, b, bs(10)), Ok(false));
}

/// §7.2.2.4.2 bullet 3: the response to a request of header SEID 0 has SEID 0. A UPF
/// without an association sends a Session Report Request of SEID 0 with the Old CP F-SEID
/// of a previous SMF, which the caller rejects: the rejection does not carry that
/// SMF-assigned SEID in its header.
#[test]
fn a_seid_zero_report_is_rejected_with_seid_zero() {
    let mut smf = node(SMF, Function::Cp);
    smf.handle_datagram(at(1), UPF, &handover_report().encode().unwrap());
    let (received, _) = request(&mut smf);
    let rejection = Cause::new(CauseValue::NoEstablishedPfcpAssociation);
    smf.respond(at(1), &received, SessionReportResponse::new(rejection))
        .unwrap();
    assert_eq!(decoded(&sent(&mut smf)[0]).header.seid, Some(0));
    // The node's rejection of a report of a session that it does not have, from a host
    // without an association: SEID 0, not that of its Old CP F-SEID
    let mut report = handover_report();
    report.header.seid = Some(0x999);
    smf.handle_datagram(at(2), UPF, &report.encode().unwrap());
    assert_eq!(
        violations(&mut smf),
        [ViolationKind::SessionWithoutAssociation]
    );
    assert_eq!(decoded(&sent(&mut smf)[0]).header.seid, Some(0));
}

/// The accepted responses of the node's requests in the order the peer took them
/// (§6.3.3).
fn answer_all(upf: &mut Node, now: Duration) {
    let requests: Vec<(Received, Message)> = events(upf)
        .into_iter()
        .filter_map(|event| match event {
            Event::Request { request, message } => Some((request, message)),
            _ => None,
        })
        .collect();
    for (received, message) in requests {
        let body: Body = match message.body {
            Body::SessionModificationRequest(_) => {
                SessionModificationResponse::new(accepted()).into()
            }
            Body::SessionDeletionRequest(_) => SessionDeletionResponse::new(accepted()).into(),
            other => panic!("{other:?}"),
        };
        upf.respond(now, &received, body).unwrap();
    }
}

/// §6.3.3: a deletion of a session that a move outstanding with it moved first ends the
/// session where it went. The UPF accepts the move, then the deletion, and has no session;
/// the SMF has none either, by its old SEID or its new one.
#[test]
fn a_deletion_after_a_move_ends_the_moved_session() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
    let new = 0x77;
    let moved = FSeid::ipv4(new, Ipv4Addr::new(10, 0, 0, 1));
    smf.session_request(
        at(1),
        cp_seid,
        SessionModificationRequest::default().with_cp_f_seid(moved),
    )
    .unwrap();
    smf.session_request(at(1), cp_seid, SessionDeletionRequest::default())
        .unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    answer_all(&mut upf, at(1));
    pass(&mut upf, &mut smf, SMF, at(1));
    let responses = events(&mut smf)
        .iter()
        .filter(|event| matches!(event, Event::Response { .. }))
        .count();
    assert_eq!(responses, 2);
    assert!(upf.session(up_seid).is_none());
    assert!(smf.session(cp_seid).is_none());
    assert!(
        smf.session(new).is_none(),
        "the deleted session stays at its new SEID"
    );
}

/// A UPF's report of a session that it deleted (PSDBU, §5.18).
fn deleted_report() -> SessionReportRequest {
    SessionReportRequest::new(ReportType {
        upir: true,
        ..Default::default()
    })
    .with_pfcpsrreq_flags(PFCPSRReqFlags {
        psdbu: true,
        ..Default::default()
    })
}

/// §7.2.2.4.2 and §5.18: the answer to a peer's request goes to the session that the
/// request is of, where it moved since the request came. The UPF reports a session that
/// it deleted while the SMF's move of it is outstanding, and the SMF answers the report
/// once the move is accepted: to the UPF's SEID, and the session ends at its new SEID.
#[test]
fn an_answer_after_a_move_goes_to_the_moved_session() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
    let new = 0x77;
    let moved = FSeid::ipv4(new, Ipv4Addr::new(10, 0, 0, 1));
    smf.session_request(
        at(1),
        cp_seid,
        SessionModificationRequest::default().with_cp_f_seid(moved),
    )
    .unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (modification, _) = request(&mut upf);
    upf.session_request(at(1), up_seid, deleted_report())
        .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    let (report, _) = request(&mut smf);
    upf.respond(
        at(1),
        &modification,
        SessionModificationResponse::new(accepted()),
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(smf.session(new).is_some());
    smf.respond(at(1), &report, SessionReportResponse::new(accepted()))
        .unwrap();
    assert_eq!(decoded(&sent(&mut smf)[0]).header.seid, Some(up_seid));
    assert!(
        smf.session(new).is_none(),
        "the session that the UPF deleted stays at its new SEID"
    );
}

/// §6.3.3: the answer to a peer's request acts on the session that the request is of, not
/// on a new one that took its local SEID after it ended: the SMF answers a UPF's report of
/// a deleted session after its caller ended the session and established a new one of the
/// same SEID, which stays, and the answer has SEID 0, as the session's peer SEID is gone.
#[test]
fn an_answer_does_not_act_on_a_reused_seid() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
    upf.session_request(at(1), up_seid, deleted_report())
        .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    let (report, _) = request(&mut smf);
    // The caller ends the session, and establishes a new one of the same SEID.
    smf.end_session(cp_seid);
    smf.request(at(1), UPF, establishment(cp_seid)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (received, _) = request(&mut upf);
    let up_f_seid = FSeid::ipv4(0x99, Ipv4Addr::new(10, 0, 0, 2));
    upf.respond(
        at(1),
        &received,
        SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(up_f_seid),
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    let peer_seid = |smf: &Node| smf.session(cp_seid).and_then(|session| session.peer_seid);
    assert_eq!(peer_seid(&smf), Some(0x99));
    smf.respond(at(1), &report, SessionReportResponse::new(accepted()))
        .unwrap();
    assert_eq!(decoded(&sent(&mut smf)[0]).header.seid, Some(0));
    assert_eq!(
        peer_seid(&smf),
        Some(0x99),
        "the new session of the SEID ends"
    );
}

/// §6.3.3: the accepted response to a deletion ends the session that it deleted, not a
/// new one that took its local SEID meanwhile.
#[test]
fn an_outstanding_deletion_does_not_end_a_reused_seid() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    smf.session_request(at(1), cp_seid, SessionDeletionRequest::default())
        .unwrap();
    let deletion = sent(&mut smf);
    // The caller ends the session, and establishes a new one of the same SEID.
    smf.end_session(cp_seid);
    smf.request(at(1), UPF, establishment(cp_seid)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (received, _) = request(&mut upf);
    let up_f_seid = FSeid::ipv4(0x99, Ipv4Addr::new(10, 0, 0, 2));
    upf.respond(
        at(1),
        &received,
        SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(up_f_seid),
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    events(&mut smf);
    // The old deletion's accepted response arrives.
    for transmit in &deletion {
        upf.handle_datagram(at(1), SMF, &transmit.octets);
    }
    answer_all(&mut upf, at(1));
    pass(&mut upf, &mut smf, SMF, at(1));
    events(&mut smf);
    assert_eq!(
        smf.session(cp_seid).and_then(|session| session.peer_seid),
        Some(0x99)
    );
}

/// §6.3.3, §5.22: the CP F-SEID of an accepted Session Report Response moves the session
/// that the report was of, not a new one that took its local SEID while the report was
/// outstanding.
#[test]
fn a_report_response_does_not_move_a_reused_seid() {
    let (mut smf, mut upf) = associated(at(0));
    let (_, up_seid) = established(&mut smf, &mut upf, at(0));
    upf.session_request(
        at(1),
        up_seid,
        SessionReportRequest::new(ReportType {
            upir: true,
            ..Default::default()
        }),
    )
    .unwrap();
    let report = sent(&mut upf);
    // The UPF's caller ends the session, and gives a new one the same UP SEID.
    upf.end_session(up_seid);
    smf.request(at(1), UPF, establishment(0x4242)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (received, _) = request(&mut upf);
    let up_f_seid = FSeid::ipv4(up_seid, Ipv4Addr::new(10, 0, 0, 2));
    upf.respond(
        at(1),
        &received,
        SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(up_f_seid),
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    events(&mut smf);
    // The old report reaches the SMF, which answers with the CP F-SEID of another SMF.
    for transmit in &report {
        smf.handle_datagram(at(1), UPF, &transmit.octets);
    }
    let (received, _) = request(&mut smf);
    let other = FSeid::ipv4(0xbeef, Ipv4Addr::new(10, 0, 0, 7));
    smf.respond(
        at(1),
        &received,
        SessionReportResponse::new(accepted()).with_cp_f_seid(other),
    )
    .unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let session = upf.session(up_seid).unwrap();
    assert_eq!(session.peer_seid, Some(0x4242));
    assert_eq!(session.peer.ip(), SMF.ip());
}

/// A UPF's report of SEID 0 that hands over the session of the Old CP F-SEID 0x1234 of
/// 10.0.0.9 (§5.22.2, §5.22.3 bullet 6).
fn handover_report() -> Message {
    Message::session(
        0,
        9,
        SessionReportRequest::new(ReportType {
            uisr: true,
            ..Default::default()
        })
        .with_old_cp_f_seid(FSeid::ipv4(0x1234, Ipv4Addr::new(10, 0, 0, 9))),
    )
}

/// Table 7.4.4.4-1: the Association Update Response carries the responder's function
/// features too. A CP function of MPAS sets an association up with a UPF of MPAS `before`,
/// sends it an update, which the UPF answers with `cause` and its UP Function Features of
/// MPAS `after`; whether a release then keeps a session.
fn cp_keeps_after_an_update_answered_with(before: bool, after: bool, cause: CauseValue) -> bool {
    let (mut smf, mut upf) = (node(SMF, Function::Cp), node(UPF, Function::Up));
    let up_mpas = |mpas| UpFunctionFeatures {
        mpas,
        ..up_features()
    };
    set_up(&mut smf, &mut upf, at(0), mpas(), up_mpas(before));
    events(&mut smf);
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    smf.request(
        at(1),
        UPF,
        Message::node(0, AssociationUpdateRequest::new(node_id(SMF))),
    )
    .unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (received, _) = request(&mut upf);
    upf.respond(
        at(1),
        &received,
        AssociationUpdateResponse::new(node_id(UPF), Cause::new(cause))
            .with_up_function_features(up_mpas(after)),
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    events(&mut smf);
    assert!(smf.end_association(UPF));
    events(&mut smf)
        .into_iter()
        .any(|event| matches!(event, Event::Released { ref kept, .. } if kept == &[cp_seid]))
}

/// §6.2.8.2, Table 7.4.4.4-1: the node takes the set features of the peer's function from
/// an Association Update Response as from a request: a UPF that withdraws MPAS in its
/// answer leaves the CP nothing to keep on a release, and one that announces it there,
/// its sessions. An answer that rejects the update changes nothing.
#[test]
fn an_association_update_response_changes_the_set_features() {
    let accepted = CauseValue::RequestAccepted;
    assert!(cp_keeps_after_an_update_answered_with(true, true, accepted));
    assert!(!cp_keeps_after_an_update_answered_with(
        true, false, accepted
    ));
    assert!(cp_keeps_after_an_update_answered_with(
        false, true, accepted
    ));
    let rejected = CauseValue::RequestRejected;
    assert!(cp_keeps_after_an_update_answered_with(
        true, false, rejected
    ));
    assert!(!cp_keeps_after_an_update_answered_with(
        false, true, rejected
    ));
}

/// An establishment that does not go, or that its peer rejects, takes its local SEID
/// with it: new_session() gives a SEID, and the node keeps nothing of it until an
/// establishment holds it. However many establishments request() refuses, and whatever
/// the UPF's caller rejects, no session stays.
#[test]
fn a_refused_establishment_leaves_no_session() {
    let mut smf = node(SMF, Function::Cp);
    for _ in 0..1000 {
        let seid = smf.new_session();
        assert_eq!(
            smf.request(at(0), UPF, establishment(seid)),
            Err(NodeError::NoAssociation)
        );
        assert!(smf.session(seid).is_none());
    }
    let (mut smf, mut upf) = associated(at(0));
    let cp_seid = smf.new_session();
    assert_ne!(smf.new_session(), cp_seid);
    smf.request(at(0), UPF, establishment(cp_seid)).unwrap();
    assert!(smf.session(cp_seid).is_some(), "held by its establishment");
    pass(&mut smf, &mut upf, UPF, at(0));
    let (received, _) = request(&mut upf);
    let up_seid = upf.new_session();
    upf.respond(
        at(0),
        &received,
        SessionEstablishmentResponse::new(
            node_id(UPF),
            Cause::new(CauseValue::NoResourcesAvailable),
        ),
    )
    .unwrap();
    assert!(upf.session(up_seid).is_none());
    pass(&mut upf, &mut smf, SMF, at(0));
    assert!(smf.session(cp_seid).is_none());
}

/// Move the SMF's session of `from` to the local SEID `to`, a move that the UPF accepts.
fn move_session(smf: &mut Node, upf: &mut Node, from: u64, to: u64, now: Duration) {
    let moved = FSeid::ipv4(to, Ipv4Addr::new(10, 0, 0, 1));
    smf.session_request(
        now,
        from,
        SessionModificationRequest::default().with_cp_f_seid(moved),
    )
    .unwrap();
    pass(smf, upf, UPF, now);
    answer_all(upf, now);
    pass(upf, smf, SMF, now);
    events(smf);
    assert!(smf.session(to).is_some(), "the session moved to {to:#x}");
}

/// §5.18 and §7.2.2.4.2: the answer to a peer's request goes to its session for as long as
/// the node keeps the request, also once the previous SEID of a move is forgotten. The SMF
/// keeps requests for 60 s, longer than the 24 s of the previous SEID of a move; the UPF
/// reports a session that it deleted, the session moves, and the SMF answers 30 s later: to
/// the UPF's SEID, and the session ends where it went.
#[test]
fn an_answer_after_the_previous_seid_is_forgotten_goes_to_its_session() {
    let smf_config = NodeConfig {
        keep: Duration::from_secs(60),
        ..config(SMF, Function::Cp)
    };
    let (mut smf, mut upf) = associated_as(smf_config, at(0));
    let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
    upf.session_request(at(1), up_seid, deleted_report())
        .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    let (report, _) = request(&mut smf);
    move_session(&mut smf, &mut upf, cp_seid, 0x77, at(1));
    smf.handle_timeout(at(30));
    smf.respond(at(30), &report, SessionReportResponse::new(accepted()))
        .unwrap();
    assert_eq!(decoded(&sent(&mut smf)[0]).header.seid, Some(up_seid));
    assert!(
        smf.session(0x77).is_none(),
        "the session that the UPF deleted stays at its new SEID"
    );
}

/// Table 7.5.4.1-1 NOTE 2: the session of a request is the same through any number of
/// moves. The UPF reports a session that it deleted, and the session moves twice before
/// the SMF answers: the answer goes to the UPF's SEID, and the session ends. A request of
/// the UPF to the first SEID, within the time of the first move, is of the session too.
#[test]
fn an_answer_after_two_moves_goes_to_its_session() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
    upf.session_request(at(1), up_seid, deleted_report())
        .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    let (report, _) = request(&mut smf);
    move_session(&mut smf, &mut upf, cp_seid, 0x77, at(1));
    move_session(&mut smf, &mut upf, 0x77, 0x88, at(1));
    // The UPF still sends to the first SEID (NOTE 2)
    let earlier = Message::session(
        cp_seid,
        77,
        SessionReportRequest::new(ReportType {
            dldr: true,
            ..Default::default()
        }),
    );
    smf.handle_datagram(at(2), UPF, &earlier.encode().unwrap());
    let (received, _) = request(&mut smf);
    assert_eq!(received.seid, Some(0x88));
    smf.respond(at(2), &report, SessionReportResponse::new(accepted()))
        .unwrap();
    assert_eq!(decoded(&sent(&mut smf)[0]).header.seid, Some(up_seid));
    assert!(
        smf.session(0x88).is_none(),
        "the session that the UPF deleted stays at its last SEID"
    );
}

/// `respond_as` answers the request of SEID 0 that hands a session over, and no other: a
/// report of a session, answered as one of another, would give that session what the
/// answer says.
#[test]
fn respond_as_answers_a_handover_alone() {
    let (mut smf, mut upf) = associated(at(0));
    let (first, _) = established(&mut smf, &mut upf, at(0));
    let (second, _) = established(&mut smf, &mut upf, at(0));
    let report = Message::session(
        first,
        10,
        SessionReportRequest::new(ReportType {
            upir: true,
            ..Default::default()
        }),
    );
    smf.handle_datagram(at(1), UPF, &report.encode().unwrap());
    let (received, _) = request(&mut smf);
    assert_eq!(received.seid, Some(first));
    let answer = SessionReportResponse::new(accepted());
    assert_eq!(
        smf.respond_as(at(1), &received, second, answer.clone()),
        Err(NodeError::NotAHandover)
    );
    assert!(sent(&mut smf).is_empty());
    smf.respond(at(1), &received, answer).unwrap();
    assert_eq!(sent(&mut smf).len(), 1);
}

/// §6.3.3: the accepted response to a request of the node acts on its session through any
/// number of moves: a deletion outstanding while the session moves twice ends it where it
/// went.
#[test]
fn a_response_after_two_moves_acts_on_its_session() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    smf.session_request(at(1), cp_seid, SessionDeletionRequest::default())
        .unwrap();
    let deletion = sent(&mut smf);
    move_session(&mut smf, &mut upf, cp_seid, 0x77, at(1));
    move_session(&mut smf, &mut upf, 0x77, 0x88, at(1));
    for transmit in &deletion {
        upf.handle_datagram(at(1), SMF, &transmit.octets);
    }
    answer_all(&mut upf, at(1));
    pass(&mut upf, &mut smf, SMF, at(1));
    let responses = events(&mut smf)
        .into_iter()
        .filter(|event| matches!(event, Event::Response { .. }))
        .count();
    assert_eq!(responses, 1);
    assert!(
        smf.session(0x88).is_none(),
        "the deleted session stays at its last SEID"
    );
}

/// §5.22.3 bullets 3 and 5: the PFCP entity of an SMF that takes a session over controls
/// it, also one without the association, which another entity of the SMF holds. A node of
/// MPAS and `other_entities` adopts a session that a UPF hands over to it: it then sends
/// its modifications and deletions to the UPF, takes the UPF's requests of the session
/// beyond the room of hosts without an association, and heartbeats the UPF while it has
/// the session, so that it sees the UPF restart (§6.2.2.2).
#[test]
fn mpas_an_entity_controls_the_session_that_it_takes_over() {
    let mut other = Node::new(NodeConfig {
        strangers: 2,
        heartbeat: Some(Duration::from_secs(60)),
        ..config(OTHER, Function::Cp)
    });
    other.handle_datagram(at(1), UPF, &handover_report().encode().unwrap());
    let (received, _) = request(&mut other);
    other.adopt_session(0x55, UPF, 0x66).unwrap();
    let cp_f_seid = FSeid::ipv4(0x55, Ipv4Addr::new(10, 0, 0, 3));
    let answer = SessionReportResponse::new(accepted()).with_cp_f_seid(cp_f_seid);
    other.respond_as(at(1), &received, 0x55, answer).unwrap();
    sent(&mut other);
    // Its modifications go to the UPF's SEID
    other
        .session_request(at(2), 0x55, SessionModificationRequest::default())
        .unwrap();
    let transmits = sent(&mut other);
    assert_eq!(transmits.len(), 1);
    assert_eq!(transmits[0].to, UPF);
    let modification = decoded(&transmits[0]);
    assert_eq!(modification.header.seid, Some(0x66));
    let response = Message::session(
        0x55,
        modification.header.sequence,
        SessionModificationResponse::new(accepted()),
    );
    other.handle_datagram(at(2), UPF, &response.encode().unwrap());
    assert!(matches!(&events(&mut other)[..], [Event::Response { .. }]));
    // The UPF's requests of the session, beyond the room of strangers
    for sequence in 10..20 {
        let report = Message::session(
            0x55,
            sequence,
            SessionReportRequest::new(ReportType {
                dldr: true,
                ..Default::default()
            }),
        );
        other.handle_datagram(at(3), UPF, &report.encode().unwrap());
    }
    assert_eq!(requests_of(&events(&mut other)), 10);
    assert_eq!(other.counters().refused, 0);
    // No heartbeat to the UPF, whose association another entity holds
    other.handle_timeout(at(63));
    assert!(sent(&mut other).is_empty());
    // Its deletion ends it
    other
        .session_request(at(64), 0x55, SessionDeletionRequest::default())
        .unwrap();
    let deletion = decoded(&sent(&mut other)[0]);
    let response = Message::session(
        0x55,
        deletion.header.sequence,
        SessionDeletionResponse::new(accepted()),
    );
    other.handle_datagram(at(64), UPF, &response.encode().unwrap());
    assert!(other.session(0x55).is_none());
    assert_eq!(other.poll_timeout(), None);
}

/// A UPF sends the requests of a session from the address of its UP F-SEID, which may
/// differ from its own (§7.2.2.4.1 NOTE): they are of the session's peer, and take no
/// place of the room of `NodeConfig::strangers`, which the hosts without an association
/// share.
#[test]
fn the_requests_of_the_host_of_an_f_seid_are_no_strangers() {
    let (mut smf, mut upf) = associated_as(
        NodeConfig {
            strangers: 1,
            ..config(SMF, Function::Cp)
        },
        at(0),
    );
    let (cp_seid, _) = established_on(&mut smf, &mut upf, at(0), Ipv4Addr::new(10, 0, 0, 12));
    let host = Ipv4Addr::new(10, 0, 0, 12).into_socket(8805);
    for sequence in [10, 11, 12] {
        let report = Message::session(
            cp_seid,
            sequence,
            SessionReportRequest::new(ReportType {
                dldr: true,
                ..Default::default()
            }),
        );
        smf.handle_datagram(at(1), host, &report.encode().unwrap());
    }
    assert_eq!(requests_of(&events(&mut smf)), 3);
    assert_eq!(smf.counters().refused, 0);
    // A host without an association still waits for the one place
    for from in [OTHER, Ipv4Addr::new(10, 0, 0, 4).into_socket(8805)] {
        smf.handle_datagram(at(1), from, &setup_of(from, 1, 1000));
    }
    assert_eq!(requests_of(&events(&mut smf)), 1);
    assert_eq!(smf.counters().refused, 1);
}

/// §4.3.2, §5.6.2, §6.5: a socket of both families gives an IPv4 peer as its IPv4-mapped
/// IPv6 address, which the node takes as the IPv4 address. The session goes to the
/// address of the UP F-SEID, the node keeps the address of its own F-SEID, a report from
/// the address of the UP F-SEID is taken (§7.2.2.4.1 NOTE), and the node sends to the
/// IPv4 addresses, as on sockets of IPv4.
#[test]
fn a_peer_at_its_ipv4_mapped_address_is_its_ipv4_address() {
    let mapped = |address: SocketAddr| match address.ip() {
        std::net::IpAddr::V4(ip) => SocketAddr::new(ip.to_ipv6_mapped().into(), address.port()),
        std::net::IpAddr::V6(_) => address,
    };
    let (mut smf, mut upf) = (node(SMF, Function::Cp), node(UPF, Function::Up));
    let carry = |from: &mut Node, to: &mut Node, address: SocketAddr, seen_as: SocketAddr| {
        for transmit in sent(from) {
            assert_eq!(transmit.to, address);
            to.handle_datagram(at(0), mapped(seen_as), &transmit.octets);
        }
    };
    let setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000));
    let setup = Message::node(0, setup);
    smf.request(at(0), mapped(UPF), setup).unwrap();
    carry(&mut smf, &mut upf, UPF, SMF);
    let (received, _) = request(&mut upf);
    assert_eq!(received.from, SMF);
    upf.respond(at(0), &received, setup_answer()).unwrap();
    carry(&mut upf, &mut smf, SMF, UPF);
    assert!(smf.association(mapped(UPF)).is_some());
    assert_eq!(
        smf.association(UPF).map(|association| association.peer),
        Some(UPF)
    );
    events(&mut smf);
    let cp_seid = smf.new_session();
    let cp_f_seid = FSeid::ipv4(cp_seid, Ipv4Addr::new(10, 0, 0, 1));
    let pdr = CreatePdr::new_n4(
        PdrId::new(1),
        Precedence::new(1),
        Pdi::new(SourceInterface::new(SourceInterfaceValue::Access)),
    );
    let far = CreateFar::new(FarId::new(1), ApplyAction::default());
    let establishment = SessionEstablishmentRequest::new_n4(node_id(SMF), cp_f_seid, pdr, far);
    let establishment = Message::session(0, 0, establishment);
    smf.request(at(0), mapped(UPF), establishment).unwrap();
    carry(&mut smf, &mut upf, UPF, SMF);
    let (received, _) = request(&mut upf);
    let up_seid = upf.new_session();
    let f_seid_address = Ipv4Addr::new(10, 0, 0, 7);
    let up_f_seid = FSeid::ipv4(up_seid, f_seid_address);
    let response =
        SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(up_f_seid);
    upf.respond(at(0), &received, response).unwrap();
    carry(&mut upf, &mut smf, SMF, UPF);
    events(&mut smf);
    let session = smf.session(cp_seid).unwrap();
    assert_eq!(session.peer, f_seid_address.into_socket(8805));
    assert_eq!(
        session.local_address,
        Some(Ipv4Addr::new(10, 0, 0, 1).into())
    );
    let session = upf.session(up_seid).unwrap();
    assert_eq!(session.peer, SMF);
    assert_eq!(session.local_address, Some(f_seid_address.into()));
    // The UPF reports from the address of its F-SEID
    let report = SessionReportRequest::new(ReportType {
        dldr: true,
        ..Default::default()
    });
    upf.session_request(at(0), up_seid, report).unwrap();
    let f_seid_peer = f_seid_address.into_socket(8805);
    carry(&mut upf, &mut smf, SMF, f_seid_peer);
    let (received, _) = request(&mut smf);
    assert_eq!((received.from, received.stranger), (f_seid_peer, false));
    // The session's modification goes to the address of the UP F-SEID
    let modification = SessionModificationRequest::default();
    smf.session_request(at(0), cp_seid, modification).unwrap();
    assert_eq!(
        sent(&mut smf).last().map(|transmit| transmit.to),
        Some(f_seid_peer)
    );
}

/// §5.22.3 bullet 6, and 4119cdf: an adoption gives no more to a host that it does not
/// name. A host without an association with the node, of another address than the
/// adopted session's UPF, has its requests of that session rejected, and its handover
/// reports, of no session, wait in the room of strangers.
#[test]
fn mpas_an_adopted_session_is_none_of_a_strangers() {
    let mut other = Node::new(NodeConfig {
        strangers: 1,
        ..config(OTHER, Function::Cp)
    });
    other.adopt_session(0x55, UPF, 0x66).unwrap();
    let stranger = Ipv4Addr::new(10, 0, 0, 8).into_socket(8805);
    let report = Message::session(
        0x55,
        10,
        SessionReportRequest::new(ReportType {
            dldr: true,
            ..Default::default()
        }),
    );
    assert_eq!(
        taken(&mut other, stranger, report),
        Err(vec![ViolationKind::SessionWithoutAssociation])
    );
    assert_eq!(taken(&mut other, stranger, handover_report()), Ok(true));
    let another = Ipv4Addr::new(10, 0, 0, 9).into_socket(8805);
    other.handle_datagram(at(1), another, &handover_report().encode().unwrap());
    assert_eq!(requests_of(&events(&mut other)), 0);
    assert_eq!(other.counters().refused, 1);
}

/// `NodeConfig::strangers`: an adopted session spares the room of hosts without an
/// association to the session requests of its peer alone. Hosts without an association
/// that send Association Setup Requests with the S flag and the session's SEID wait in it
/// as any, and so does the peer's own, which is no session request.
#[test]
fn an_adopted_seid_spares_the_room_of_strangers_to_its_peer_alone() {
    let mut other = Node::new(NodeConfig {
        strangers: 1,
        ..config(OTHER, Function::Cp)
    });
    other.adopt_session(1, UPF, 0x66).unwrap();
    let setup = |from: SocketAddr, sequence: u32| {
        let header = Header {
            seid: Some(1),
            ..Header::node(sequence)
        };
        let body = AssociationSetupRequest::new(node_id(from), RecoveryTimeStamp::new(1000));
        Message {
            header,
            body: body.into(),
        }
        .encode()
        .unwrap()
    };
    for host in 10..20 {
        let from = Ipv4Addr::new(10, 0, 1, host).into_socket(8805);
        other.handle_datagram(at(1), from, &setup(from, host.into()));
    }
    assert_eq!(requests_of(&events(&mut other)), 1);
    assert_eq!(other.counters().refused, 9);
    other.handle_datagram(at(1), UPF, &setup(UPF, 30));
    assert_eq!(requests_of(&events(&mut other)), 0);
    assert_eq!(other.counters().refused, 10);
    // The session's report, from its peer, does not wait
    let report = Message::session(
        1,
        31,
        SessionReportRequest::new(ReportType {
            dldr: true,
            ..Default::default()
        }),
    );
    other.handle_datagram(at(1), UPF, &report.encode().unwrap());
    assert_eq!(requests_of(&events(&mut other)), 1);
}

/// §4.2.2: the node sends its requests to a peer of a session that it adopts at port
/// 8805, whatever port the request that handed the session over came from, as it does to
/// a peer of an association or of an established session; without `request_port`, to the
/// port of the peer. Its modifications go there.
#[test]
fn an_adopted_session_takes_the_port_of_the_requests() {
    for request_port in [Some(PORT), None] {
        let mut other = Node::new(NodeConfig {
            request_port,
            ..config(OTHER, Function::Cp)
        });
        let from = SocketAddr::new(UPF.ip(), 40000);
        let to = SocketAddr::new(UPF.ip(), request_port.unwrap_or(40000));
        other.handle_datagram(at(1), from, &handover_report().encode().unwrap());
        let (received, _) = request(&mut other);
        other.adopt_session(0x55, received.from, 0x66).unwrap();
        assert_eq!(other.session(0x55).map(|session| session.peer), Some(to));
        other
            .respond_as(
                at(1),
                &received,
                0x55,
                SessionReportResponse::new(accepted()),
            )
            .unwrap();
        assert_eq!(
            sent(&mut other)[0].to,
            from,
            "the answer to the request's port"
        );
        other
            .session_request(at(2), 0x55, SessionModificationRequest::default())
            .unwrap();
        let requests: Vec<(SocketAddr, u8)> = sent(&mut other)
            .iter()
            .map(|transmit| (transmit.to, decoded(transmit).body.message_type()))
            .collect();
        assert_eq!(requests, [(to, 52)]);
    }
}

/// An establishment holds its session from when it is sent: another request of the
/// session that ends without its response, cancelled here, leaves it, and the
/// establishment's accepted response establishes it.
#[test]
fn a_request_that_ends_leaves_an_establishment_its_session() {
    let (mut smf, mut upf) = associated(at(0));
    let cp_seid = smf.new_session();
    smf.request(at(0), UPF, establishment(cp_seid)).unwrap();
    let modification = smf
        .session_request(at(0), cp_seid, SessionModificationRequest::default())
        .unwrap();
    assert!(smf.cancel(at(0), modification));
    let transmits = sent(&mut smf);
    upf.handle_datagram(at(0), SMF, &transmits[0].octets);
    let (received, _) = request(&mut upf);
    let up_f_seid = FSeid::ipv4(0x99, Ipv4Addr::new(10, 0, 0, 2));
    upf.respond(
        at(0),
        &received,
        SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(up_f_seid),
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(0));
    assert_eq!(
        smf.session(cp_seid).and_then(|session| session.peer_seid),
        Some(0x99)
    );
}

/// Table 7.5.4.1-1, CP F-SEID: "The UP function shall use the new CP F-SEID for subsequent
/// PFCP Session related messages", from when it accepts the change, and §7.2.2.4.2: the
/// new SEID is the SMF's while its move is outstanding. A report of the UPF to it that
/// comes before the move's response, lost or overtaken, is of the session: it reaches the
/// SMF's caller, of the session's SEID then, and its answer goes to the UPF's SEID. The
/// session then moves with the response, or stays where it was with a rejection, which a
/// request to the new SEID before it does not change.
#[test]
fn a_request_to_the_new_seid_of_a_move_before_its_response() {
    for accept in [true, false] {
        let (mut smf, mut upf) = associated(at(0));
        let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
        let new = smf.new_session();
        let moved = FSeid::ipv4(new, Ipv4Addr::new(10, 0, 0, 1));
        smf.session_request(
            at(1),
            cp_seid,
            SessionModificationRequest::default().with_cp_f_seid(moved),
        )
        .unwrap();
        pass(&mut smf, &mut upf, UPF, at(1));
        let (received, _) = request(&mut upf);
        let cause = match accept {
            true => accepted(),
            false => Cause::new(CauseValue::RequestRejected),
        };
        upf.respond(at(1), &received, SessionModificationResponse::new(cause))
            .unwrap();
        let response = sent(&mut upf);
        let report = SessionReportRequest::new(ReportType {
            dldr: true,
            ..Default::default()
        });
        // To the new SEID, which the UPF takes with its acceptance
        let peer_seid = upf.session(up_seid).and_then(|session| session.peer_seid);
        assert_eq!(peer_seid == Some(new), accept);
        let header = Header::session(new, 0);
        upf.request(
            at(1),
            SMF,
            Message {
                header,
                body: report.into(),
            },
        )
        .unwrap();
        pass(&mut upf, &mut smf, SMF, at(1));
        let (received, _) = request(&mut smf);
        assert_eq!(received.seid, Some(cp_seid));
        smf.respond(at(1), &received, SessionReportResponse::new(accepted()))
            .unwrap();
        let answer = decoded(&sent(&mut smf)[0]);
        assert_eq!(answer.header.seid, Some(up_seid));
        assert_eq!(answer.body.cause(), Some(CauseValue::RequestAccepted));
        for transmit in response {
            smf.handle_datagram(at(1), UPF, &transmit.octets);
        }
        assert!(violations(&mut smf).is_empty());
        let at_new = smf.session(new).and_then(|session| session.peer_seid);
        let at_old = smf.session(cp_seid).and_then(|session| session.peer_seid);
        assert_eq!((at_new.is_some(), at_old.is_some()), (accept, !accept));
    }
}

// ── §5.2.2.3.1: the usage reports that follow a deletion ────────────────────

/// A UPF's report of the usage of a session that the SMF deletes: the last with PSDBU.
fn usage_report(last: bool) -> SessionReportRequest {
    let report = SessionReportRequest::new(ReportType {
        usar: true,
        ..Default::default()
    });
    match last {
        true => report.with_pfcpsrreq_flags(PFCPSRReqFlags {
            psdbu: true,
            ..Default::default()
        }),
        false => report,
    }
}

/// An SMF and a UPF whose session the SMF deletes at 1 s, which the UPF's caller answers
/// with `answer`: their SEIDs.
fn deleted_with(answer: SessionDeletionResponse) -> (Node, Node, u64, u64) {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
    smf.session_request(at(1), cp_seid, SessionDeletionRequest::default())
        .unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (received, _) = request(&mut upf);
    upf.respond(at(1), &received, answer).unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(matches!(&events(&mut smf)[..], [Event::Response { .. }]));
    (smf, upf, cp_seid, up_seid)
}

/// The UPF reports the usage of its session to the SMF, whose caller has the report and
/// accepts it, and the UPF has the response.
fn usage_reported(smf: &mut Node, upf: &mut Node, seids: (u64, u64), last: bool, now: Duration) {
    let (cp_seid, up_seid) = seids;
    upf.session_request(now, up_seid, usage_report(last))
        .unwrap();
    pass(upf, smf, SMF, now);
    let (received, message) = request(smf);
    assert_eq!(received.seid, Some(cp_seid));
    assert!(matches!(message.body, Body::SessionReportRequest(_)));
    smf.respond(now, &received, SessionReportResponse::new(accepted()))
        .unwrap();
    pass(smf, upf, UPF, now);
    assert!(matches!(&events(upf)[..], [Event::Response { .. }]));
}

/// §5.2.2.3.1: a UP function with more usage reports of a session that the CP function
/// deletes answers the deletion "More Usage Report to send", then sends them in Session
/// Report Requests, the last with PSDBU, and the CP function deletes the session only
/// then. Both nodes keep the session: each report in between reaches the SMF's caller and
/// has its answer, and the last ends the session on both, with nothing left due.
#[test]
fn more_usage_reports_keep_the_session_until_the_last() {
    let more = SessionDeletionResponse::new(Cause::new(CauseValue::MoreUsageReportToSend))
        .with_additional_usage_reports_information(AdditionalUsageReportsInformation {
            auri: true,
            ..Default::default()
        });
    let (mut smf, mut upf, cp_seid, up_seid) = deleted_with(more);
    assert!(smf.session(cp_seid).is_some());
    assert!(upf.session(up_seid).is_some());
    for (now, last) in [(2, false), (3, false), (4, true)] {
        usage_reported(&mut smf, &mut upf, (cp_seid, up_seid), last, at(now));
        assert_eq!(smf.session(cp_seid).is_some(), !last, "at {now} s");
        assert_eq!(upf.session(up_seid).is_some(), !last, "at {now} s");
    }
    assert_eq!(smf.poll_timeout(), None);
    assert_eq!(upf.poll_timeout(), None);
    assert!(events(&mut smf).is_empty());
}

/// §5.2.2.3.1: a UP function that has reports of a session not yet acknowledged when it
/// answers the session's deletion sets PURU, and the CP function waits before it deletes
/// the session. The SMF keeps the session: the UPF's pending report, sent again, reaches
/// its caller, and the session ends `keep` after the last report of it, as an event says.
/// The UPF keeps none, as its pending report is a request of its own.
#[test]
fn pending_usage_reports_keep_the_session_a_while() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
    // A report of the UPF, lost
    upf.session_request(at(1), up_seid, usage_report(false))
        .unwrap();
    sent(&mut upf);
    smf.session_request(at(1), cp_seid, SessionDeletionRequest::default())
        .unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (received, _) = request(&mut upf);
    let pending = SessionDeletionResponse::new(accepted()).with_pfcpsdrsp_flags(PFCPSDRspFlags {
        puru: true,
        ..Default::default()
    });
    upf.respond(at(1), &received, pending).unwrap();
    assert!(upf.session(up_seid).is_none());
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(matches!(&events(&mut smf)[..], [Event::Response { .. }]));
    assert!(smf.session(cp_seid).is_some());
    // The report again, after T1
    upf.handle_timeout(at(1) + T1);
    pass(&mut upf, &mut smf, SMF, at(4));
    let (received, _) = request(&mut smf);
    smf.respond(at(4), &received, SessionReportResponse::new(accepted()))
        .unwrap();
    pass(&mut smf, &mut upf, UPF, at(4));
    assert!(matches!(&events(&mut upf)[..], [Event::Response { .. }]));
    let keep = config(SMF, Function::Cp).keep;
    assert_eq!(smf.poll_timeout(), Some(at(4) + keep));
    smf.handle_timeout(at(4) + keep - Duration::from_millis(1));
    assert!(smf.session(cp_seid).is_some());
    smf.handle_timeout(at(4) + keep);
    assert!(smf.session(cp_seid).is_none());
    assert_eq!(
        events(&mut smf),
        [Event::SessionEnded {
            local_seid: cp_seid
        }]
    );
    assert_eq!(smf.poll_timeout(), None);
}

/// §5.2.2.3.1: a session whose deletion waits for its last usage reports, which do not
/// come, ends on each node `keep` after the last message of it: on the SMF after the
/// deletion's response or the last report that it took, on the UPF after its answer or
/// the last report that it sent, as an event says on each.
#[test]
fn a_session_without_its_last_usage_report_ends_after_keep() {
    let more = SessionDeletionResponse::new(Cause::new(CauseValue::MoreUsageReportToSend));
    let (mut smf, mut upf, cp_seid, up_seid) = deleted_with(more);
    let keep = config(SMF, Function::Cp).keep;
    assert_eq!(smf.poll_timeout(), Some(at(1) + keep));
    assert_eq!(upf.poll_timeout(), Some(at(1) + keep));
    usage_reported(&mut smf, &mut upf, (cp_seid, up_seid), false, at(5));
    for (node, local_seid) in [(&mut smf, cp_seid), (&mut upf, up_seid)] {
        assert_eq!(node.poll_timeout(), Some(at(5) + keep));
        node.handle_timeout(at(1) + keep);
        assert!(node.session(local_seid).is_some());
        assert!(events(node).is_empty());
        node.handle_timeout(at(5) + keep);
        assert!(node.session(local_seid).is_none());
        assert_eq!(events(node), [Event::SessionEnded { local_seid }]);
        assert_eq!(node.poll_timeout(), None);
    }
}
