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

//! The delivery of the messages (§6.4): sequence numbers, retransmissions, the answers
//! kept for the retransmissions of a request, and the messages and datagrams that a node
//! discards or answers with an error (§7.6).

use super::*;

// ── §6.4: reliable delivery ─────────────────────────────────────────────────

#[test]
fn queue_per_peer() {
    let mut smf = node(SMF, Function::Cp);
    let first = smf.request(at(0), UPF, heartbeat()).unwrap();
    let second = smf.request(at(0), OTHER, heartbeat()).unwrap();
    let datagrams = sent(&mut smf);
    assert_eq!([datagrams[0].to, datagrams[1].to], [UPF, OTHER]);
    // A response from the other peer, with the sequence number of the request to UPF
    let to_upf = decoded(&datagrams[0]);
    let response = Message::node(
        to_upf.header.sequence,
        HeartbeatResponse::new(RecoveryTimeStamp::new(1)),
    );
    smf.handle_datagram(at(1), OTHER, &response.encode().unwrap());
    assert_eq!(violations(&mut smf), [ViolationKind::WrongPeer]);
    smf.handle_datagram(at(1), UPF, &response.encode().unwrap());
    assert!(
        matches!(&events(&mut smf)[..], [Event::Response { request, .. }] if *request == first)
    );
    // The request to the other peer still waits, and is sent again alone
    smf.handle_timeout(at(3));
    let again = sent(&mut smf);
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].to, OTHER);
    assert_ne!(first, second);
}

#[test]
fn retransmit_until_response() {
    let mut smf = node(SMF, Function::Cp);
    smf.request(at(0), UPF, heartbeat()).unwrap();
    let original = sent(&mut smf).remove(0);
    assert_eq!(smf.poll_timeout(), Some(T1));
    smf.handle_timeout(at(2));
    assert!(sent(&mut smf).is_empty(), "not before T1");
    smf.handle_timeout(T1);
    assert_eq!(sent(&mut smf), std::slice::from_ref(&original));
    let response = Message::node(
        decoded(&original).header.sequence,
        HeartbeatResponse::new(RecoveryTimeStamp::new(1)),
    );
    smf.handle_datagram(at(4), UPF, &response.encode().unwrap());
    smf.handle_timeout(at(60));
    assert!(sent(&mut smf).is_empty(), "nothing after the response");
    assert_eq!(smf.poll_timeout(), None);
}

#[test]
fn sequence_unique() {
    let mut smf = node(SMF, Function::Cp);
    let reserved = smf.reserve_sequence().unwrap();
    for _ in 0..1000 {
        smf.request(at(0), UPF, heartbeat()).unwrap();
    }
    let mut sequences: Vec<u32> = sent(&mut smf)
        .iter()
        .map(|transmit| decoded(transmit).header.sequence)
        .collect();
    assert!(!sequences.contains(&reserved));
    sequences.sort_unstable();
    sequences.dedup();
    assert_eq!(sequences.len(), 1000);
    assert!(sequences.iter().all(|sequence| *sequence <= 0x00ff_ffff));
}

#[test]
fn timeout_after_n1() {
    let mut smf = node(SMF, Function::Cp);
    let id = smf.request(at(0), UPF, heartbeat()).unwrap();
    sent(&mut smf);
    for attempt in 1..=3 {
        smf.handle_timeout(T1 * attempt);
        assert_eq!(sent(&mut smf).len(), 1, "retransmission {attempt}");
        assert!(events(&mut smf).is_empty());
    }
    smf.handle_timeout(T1 * 4);
    assert!(sent(&mut smf).is_empty());
    assert_eq!(
        events(&mut smf),
        [Event::Failed {
            request: id,
            to: UPF,
            failure: Failure::Timeout
        }]
    );
}

/// Each failure and each error of the node says what it is, apart from the others, and
/// one that carries an error of the codec says it too.
#[test]
fn a_failure_and_an_error_say_what_they_are() {
    let codec = Message::decode(&[0x20]).unwrap_err();
    let failures = [
        Failure::Timeout,
        Failure::VersionNotSupported,
        Failure::Malformed(codec.clone()),
    ];
    let errors = [
        NodeError::NoAssociation,
        NodeError::NoSession,
        NodeError::Throttled,
        NodeError::NotARequest,
        NodeError::WrongDirection,
        NodeError::NoSequence,
        NodeError::Answered,
        NodeError::Forgotten,
        NodeError::WrongResponse,
        NodeError::SeidInUse,
        NodeError::SeidZero,
        NodeError::NotAHandover,
        NodeError::Encode(codec.clone()),
    ];
    let failures = failures.iter().map(ToString::to_string);
    let texts: Vec<String> = failures
        .chain(errors.iter().map(ToString::to_string))
        .collect();
    let distinct: std::collections::BTreeSet<&str> = texts.iter().map(String::as_str).collect();
    assert_eq!(distinct.len(), texts.len(), "{texts:?}");
    let carrying = [&texts[2], &texts[texts.len() - 1]];
    assert!(
        carrying
            .iter()
            .all(|text| text.contains(&codec.to_string())),
        "{texts:?}"
    );
}

#[test]
fn retransmission_identical() {
    let mut smf = node(SMF, Function::Cp);
    smf.request(at(0), UPF, of_priority(3, heartbeat()))
        .unwrap();
    let original = sent(&mut smf).remove(0);
    smf.handle_timeout(T1);
    let again = sent(&mut smf).remove(0);
    assert_eq!(again, original, "the same octets, header and peer");
}

#[test]
fn response_copies_sequence() {
    let (_, mut upf) = associated(at(0));
    let update = AssociationUpdateRequest::new(node_id(SMF));
    let octets = Message::node(0x1234, update).encode().unwrap();
    upf.handle_datagram(at(1), SMF, &octets);
    let (received, _) = request(&mut upf);
    upf.respond(
        at(1),
        &received,
        AssociationUpdateResponse::new(node_id(UPF), accepted()),
    )
    .unwrap();
    assert_eq!(decoded(&sent(&mut upf)[0]).header.sequence, 0x1234);
}

#[test]
fn retransmitted_request_answered_from_cache() {
    let (_, mut upf) = associated(at(0));
    let update = AssociationUpdateRequest::new(node_id(SMF));
    let octets = Message::node(77, update).encode().unwrap();
    upf.handle_datagram(at(1), SMF, &octets);
    let (received, _) = request(&mut upf);
    // A retransmission before the answer is not a second request, and the number of a
    // request that has no answer yet is not another's
    upf.handle_datagram(at(2), SMF, &octets);
    assert_eq!(
        events(&mut upf),
        [Event::Retransmission {
            from: SMF,
            sequence: 77,
            answered: false
        }]
    );
    let changed = Message::node(
        77,
        AssociationUpdateRequest::new(node_id(SMF))
            .with_graceful_release_period(GracefulReleasePeriod::default()),
    );
    upf.handle_datagram(at(2), SMF, &changed.encode().unwrap());
    assert_eq!(violations(&mut upf), [ViolationKind::ChangedRetransmission]);
    upf.respond(
        at(2),
        &received,
        AssociationUpdateResponse::new(node_id(UPF), accepted()),
    )
    .unwrap();
    let answer = sent(&mut upf).remove(0);
    // One after it gets the same answer, byte for byte
    upf.handle_datagram(at(4), SMF, &octets);
    assert_eq!(
        events(&mut upf),
        [Event::Retransmission {
            from: SMF,
            sequence: 77,
            answered: true
        }]
    );
    assert_eq!(sent(&mut upf), [answer]);
    // Once answered, the number may be another request's (§6.4)
    upf.handle_datagram(at(5), SMF, &changed.encode().unwrap());
    let (_, message) = request(&mut upf);
    assert!(
        matches!(message.body, Body::AssociationUpdateRequest(update) if update.graceful_release_period.is_some())
    );
}

#[test]
fn duplicate_response_discarded() {
    let mut smf = node(SMF, Function::Cp);
    smf.request(at(0), UPF, heartbeat()).unwrap();
    let header = decoded(&sent(&mut smf)[0]).header;
    let response = Message {
        header,
        body: HeartbeatResponse::new(RecoveryTimeStamp::new(1)).into(),
    }
    .encode()
    .unwrap();
    smf.handle_datagram(at(1), UPF, &response);
    assert_eq!(events(&mut smf).len(), 1);
    smf.handle_datagram(at(1), UPF, &response);
    assert_eq!(violations(&mut smf), [ViolationKind::DuplicateResponse]);
}

#[test]
fn unknown_response_discarded() {
    let mut smf = node(SMF, Function::Cp);
    let response = Message::node(4242, HeartbeatResponse::new(RecoveryTimeStamp::new(1)));
    smf.handle_datagram(at(0), UPF, &response.encode().unwrap());
    assert_eq!(violations(&mut smf), [ViolationKind::UnknownSequence]);
    // A response to a request that the node gave up is late
    smf.request(at(0), UPF, heartbeat()).unwrap();
    let header = decoded(&sent(&mut smf)[0]).header;
    for attempt in 1..=4 {
        smf.handle_timeout(T1 * attempt);
    }
    events(&mut smf);
    let late = Message {
        header,
        body: HeartbeatResponse::new(RecoveryTimeStamp::new(1)).into(),
    };
    smf.handle_datagram(at(13), UPF, &late.encode().unwrap());
    assert_eq!(violations(&mut smf), [ViolationKind::LateResponse]);
}

/// What a node keeps is listed: its sessions, with the address of the node's F-SEID of
/// each, its associations, and its loads and overloads with whose they are.
#[test]
fn the_state_of_a_node_is_listed() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
    let sessions: Vec<(u64, Option<std::net::IpAddr>)> = smf
        .sessions()
        .map(|(seid, session)| (seid, session.local_address))
        .collect();
    assert_eq!(sessions, [(cp_seid, Some(SMF.ip()))]);
    let sessions: Vec<(u64, Option<std::net::IpAddr>)> = upf
        .sessions()
        .map(|(seid, session)| (seid, session.local_address))
        .collect();
    assert_eq!(sessions, [(up_seid, Some(UPF.ip()))]);
    let peers: Vec<NodeId> = smf
        .associations()
        .map(|association| association.node_id.clone())
        .collect();
    assert_eq!(peers, [node_id(UPF)]);
    let response = with_load(1, 40);
    modified(&mut smf, &mut upf, cp_seid, at(1), response);
    modified(
        &mut smf,
        &mut upf,
        cp_seid,
        at(2),
        with_overload(1, 50, 30, false),
    );
    modified(
        &mut smf,
        &mut upf,
        cp_seid,
        at(3),
        with_overload(1, 60, 30, true),
    );
    let loads: Vec<(ControlScope, u8)> = smf
        .loads()
        .map(|(scope, load)| (scope, load.metric))
        .collect();
    assert_eq!(loads, [(ControlScope::Node(node_id(UPF)), 40)]);
    let overloads: Vec<(ControlScope, u8)> = smf
        .overloads()
        .map(|(scope, overload)| (scope, overload.metric))
        .collect();
    let address = Ipv4Addr::new(10, 0, 0, 2).into_socket(0);
    assert_eq!(
        overloads,
        [
            (ControlScope::Address(address), 50),
            (ControlScope::Node(node_id(UPF)), 60)
        ]
    );
}

#[test]
fn version_not_supported() {
    let mut upf = node(UPF, Function::Up);
    let mut octets = Message::node(8, HeartbeatRequest::new(RecoveryTimeStamp::new(1000)))
        .encode()
        .unwrap();
    octets[0] = (octets[0] & 0x1f) | 2 << 5;
    upf.handle_datagram(at(0), SMF, &octets);
    let answer = decoded(&sent(&mut upf)[0]);
    assert_eq!(answer.body.message_type(), 11);
    assert_eq!(answer.header.sequence, 8);
    assert_eq!(
        events(&mut upf),
        [Event::Malformed {
            from: SMF,
            error: Error::Version { version: 2 }
        }],
        "the request is discarded"
    );
}

/// §7.6.3: a request in a datagram longer than its Message Length is answered "Invalid
/// Length", and is no request for the caller.
#[test]
fn a_request_of_a_false_length_is_answered_invalid_length() {
    let (mut smf, mut upf) = associated(at(0));
    let (_, up_seid) = established(&mut smf, &mut upf, at(0));
    events(&mut upf);
    let mut octets = Message::node(9, AssociationUpdateRequest::new(node_id(SMF)))
        .encode()
        .unwrap();
    octets.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 1, 2, 3]);
    upf.handle_datagram(at(1), SMF, &octets);
    let got = events(&mut upf);
    assert_eq!(requests_of(&got), 0);
    assert!(
        matches!(
            &got[..],
            [Event::Malformed {
                error: Error::MessageLength { .. },
                ..
            }]
        ),
        "{got:?}"
    );
    let answer = decoded(&sent(&mut upf)[0]);
    assert_eq!(
        (answer.header.sequence, answer.body.cause()),
        (9, Some(CauseValue::InvalidLength))
    );
    assert!(
        answer.check(Interfaces::N4).is_empty(),
        "{:?}",
        answer.check(Interfaces::N4)
    );
    // An IE that runs past its message is named in the answer (§7.6.7): of a session
    // that the node has, as a session that it does not have is answered so first. The
    // answer says the priority that the request says.
    let modification = SessionModificationRequest::default()
        .with_cp_f_seid(FSeid::ipv4(1, Ipv4Addr::new(10, 0, 0, 1)));
    let mut octets = of_priority(3, Message::session(up_seid, 10, modification))
        .encode()
        .unwrap();
    octets[19] = 99;
    upf.handle_datagram(at(1), SMF, &octets);
    let answer = decoded(&sent(&mut upf)[0]);
    assert_eq!(answer.header.priority, Some(3));
    let Body::SessionModificationResponse(response) = answer.body else {
        panic!()
    };
    assert_eq!(response.offending_ie.map(|ie| ie.value), Some(57));
    // One that the peer does not send is discarded, and not answered (§7.6.5)
    let report = SessionReportRequest::new(ReportType::default());
    let mut octets = Message::session(up_seid, 11, report).encode().unwrap();
    octets.extend_from_slice(&[0, 1]);
    let length = (octets.len() - 4) as u16;
    octets[2..4].copy_from_slice(&length.to_be_bytes());
    upf.handle_datagram(at(1), SMF, &octets);
    assert!(sent(&mut upf).is_empty());
}

/// §7.6.3, §7.6.7: a request of each type that the UP function takes, whose IEs run past
/// it, is answered with its response, "Invalid length"; one of a session that the node
/// does not have, "Session context not found" first; one of a session, of SEID 0, as the
/// node knows no session of it.
#[test]
fn a_request_of_each_type_that_does_not_decode_is_answered_invalid_length() {
    let (_, mut upf) = associated(at(0));
    for message_type in [3, 5, 7, 9, 16, 50, 52, 54] {
        let session = message_type >= 50;
        let mut octets = vec![0x20 | u8::from(session), message_type, 0, 0];
        if session {
            octets.extend(1u64.to_be_bytes());
        }
        octets.extend([0, 0, 9, 0]);
        octets.extend([0, 60, 0, 9, 0]);
        let length = (octets.len() - 4) as u16;
        octets[2..4].copy_from_slice(&length.to_be_bytes());
        upf.handle_datagram(at(1), SMF, &octets);
        let answer = decoded(&sent(&mut upf)[0]);
        assert_eq!(
            answer.body.message_type(),
            message_type + 1,
            "{message_type}"
        );
        let cause = match message_type {
            52 | 54 => CauseValue::SessionContextNotFound,
            _ => CauseValue::InvalidLength,
        };
        assert_eq!(answer.body.cause(), Some(cause), "{message_type}");
        assert_eq!(answer.header.seid, session.then_some(0), "{message_type}");
    }
}

/// §7.6.1, §7.6.3: a response that does not decode, or of another version, ends its
/// request: no more retransmissions, and the caller has why.
#[test]
fn an_erroneous_response_ends_its_request() {
    let mut smf = node(SMF, Function::Cp);
    let id = smf.request(at(0), UPF, heartbeat()).unwrap();
    let request = decoded(&sent(&mut smf)[0]);
    let mut reply = Message::node(
        request.header.sequence,
        HeartbeatResponse::new(RecoveryTimeStamp::new(1)),
    )
    .encode()
    .unwrap();
    reply[3] += 1;
    smf.handle_datagram(at(1), UPF, &reply);
    let got = events(&mut smf);
    assert!(got.iter().any(|event| matches!(event, Event::Failed { request, to: UPF, failure: Failure::Malformed(Error::MessageLength { .. }) } if *request == id)), "{got:?}");
    for attempt in 1..=4 {
        smf.handle_timeout(T1 * attempt);
    }
    assert!(sent(&mut smf).is_empty() && events(&mut smf).is_empty());
    // A response of version 2
    let id = smf.request(at(20), UPF, heartbeat()).unwrap();
    let mut reply = Message {
        header: decoded(&sent(&mut smf)[0]).header,
        body: HeartbeatResponse::new(RecoveryTimeStamp::new(1)).into(),
    }
    .encode()
    .unwrap();
    reply[0] = (reply[0] & 0x1f) | 2 << 5;
    smf.handle_datagram(at(21), UPF, &reply);
    let got = events(&mut smf);
    assert!(got.iter().any(|event| matches!(event, Event::Failed { request, failure: Failure::Malformed(Error::Version { version: 2 }), .. } if *request == id)), "{got:?}");
}

/// §7.2.2.2: the sequence number of a Version Not Supported Response says nothing: each
/// request to the peer ends with it.
#[test]
fn version_not_supported_ends_the_requests_to_the_peer() {
    // Its version is the highest of the peer (§7.4.4.7): 1 is as good as any other.
    for version in [2, 1, 7] {
        let mut smf = node(SMF, Function::Cp);
        let first = smf.request(at(0), UPF, heartbeat()).unwrap();
        let second = smf.request(at(0), UPF, heartbeat()).unwrap();
        smf.request(at(0), OTHER, heartbeat()).unwrap();
        sent(&mut smf);
        let answer = Message::node(0x777, VersionNotSupportedResponse::default());
        let mut octets = answer.encode().unwrap();
        octets[0] = (octets[0] & 0x1f) | version << 5;
        smf.handle_datagram(at(1), UPF, &octets);
        let got = events(&mut smf);
        assert!(
            !got.iter()
                .any(|event| matches!(event, Event::Malformed { .. }))
        );
        let failed: Vec<RequestId> = got
            .into_iter()
            .filter_map(|event| match event {
                Event::Failed {
                    request,
                    failure: Failure::VersionNotSupported,
                    ..
                } => Some(request),
                _ => None,
            })
            .collect();
        assert_eq!(failed, [first, second], "version {version}");
        smf.handle_timeout(T1);
        assert_eq!(
            sent(&mut smf)
                .iter()
                .map(|transmit| transmit.to)
                .collect::<Vec<_>>(),
            [OTHER]
        );
    }
}

/// Table 8.2.1-1: a Cause of 0 is an invalid IE, and accepts nothing.
#[test]
fn a_cause_of_zero_accepts_nothing() {
    let (mut smf, mut upf) = (node(SMF, Function::Cp), node(UPF, Function::Up));
    let setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000));
    smf.request(at(0), UPF, Message::node(0, setup)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(0));
    let (received, _) = request(&mut upf);
    let zero = Cause::new(CauseValue::from_value(0));
    let answer = AssociationSetupResponse::new(node_id(UPF), zero, RecoveryTimeStamp::new(1000));
    upf.respond(at(0), &received, answer).unwrap();
    pass(&mut upf, &mut smf, SMF, at(0));
    assert!(upf.association(SMF).is_none());
    assert!(smf.association(UPF).is_none());
}

/// §7.6.2: a datagram of another version is answered once: the node does not follow
/// the framing of a version that it does not know.
#[test]
fn a_datagram_of_another_version_is_answered_once() {
    let mut upf = node(UPF, Function::Up);
    let mut datagram = Vec::new();
    for _ in 0..16_000 {
        datagram.extend_from_slice(&[0x44, 0x01, 0x00, 0x00]);
    }
    upf.handle_datagram(at(0), OTHER, &datagram);
    assert_eq!(sent(&mut upf).len(), 1);
    assert_eq!(events(&mut upf).len(), 1);
}

/// §7.6.4: a message of a type that Table 7.3-1 does not have is discarded.
#[test]
fn a_message_of_no_type_is_discarded() {
    let mut upf = node(UPF, Function::Up);
    for (message_type, seid) in [(100u8, Some(0u64)), (19, None), (0, Some(0))] {
        let header = match seid {
            Some(seid) => Header::session(seid, 9),
            None => Header::node(9),
        };
        let mut octets = Message {
            header,
            body: HeartbeatRequest::default().into(),
        }
        .encode()
        .unwrap();
        octets[1] = message_type;
        upf.handle_datagram(at(0), SMF, &octets);
    }
    let got = events(&mut upf);
    assert_eq!(kinds_of(&got), [ViolationKind::UnknownMessage; 3]);
    assert!(sent(&mut upf).is_empty());
}

/// §7.6.5: a request that the function of the node does not receive is discarded, and
/// a node does not send one; a node related request of a peer without an association
/// is answered "No established PFCP Association".
#[test]
fn a_request_of_the_wrong_direction_is_discarded() {
    let mut smf = node(SMF, Function::Cp);
    let pfd = Message::node(4, PfdManagementRequest::default());
    smf.handle_datagram(at(0), OTHER, &pfd.encode().unwrap());
    assert_eq!(kinds_of(&events(&mut smf)), [ViolationKind::WrongDirection]);
    assert!(sent(&mut smf).is_empty());
    // Not answered either when it does not decode
    let mut octets = pfd.encode().unwrap();
    octets.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 1, 2, 3]);
    smf.handle_datagram(at(0), OTHER, &octets);
    assert!(sent(&mut smf).is_empty());
    events(&mut smf);
    let mut upf = node(UPF, Function::Up);
    assert_eq!(
        upf.request(at(0), SMF, pfd.clone()),
        Err(NodeError::WrongDirection)
    );
    let report = Message::node(
        5,
        NodeReportRequest::new(
            node_id(OTHER),
            NodeReportType {
                uprr: true,
                ..Default::default()
            },
        ),
    );
    smf.handle_datagram(at(0), OTHER, &report.encode().unwrap());
    assert_eq!(
        kinds_of(&events(&mut smf)),
        [ViolationKind::SessionWithoutAssociation]
    );
    assert_eq!(
        decoded(&sent(&mut smf)[0]).body.cause(),
        Some(CauseValue::NoEstablishedPfcpAssociation)
    );
}

/// §7.2.2: the answers that the node writes have a header of their own, which copies
/// none of the faults of the request's.
#[test]
fn a_rejection_has_a_header_of_its_own() {
    let mut upf = node(UPF, Function::Up);
    let header = Header {
        spare: 3,
        spare_last: 0x0f,
        priority: Some(5),
        ..Header::node(3)
    };
    let update = Message {
        header,
        body: AssociationUpdateRequest::new(node_id(SMF)).into(),
    };
    upf.handle_datagram(at(0), SMF, &update.encode().unwrap());
    let answer = decoded(&sent(&mut upf)[0]);
    assert_eq!(answer.header, Header::node(3));
    assert!(
        answer.check(Interfaces::N4).is_empty(),
        "{:?}",
        answer.check(Interfaces::N4)
    );
}

// ── §6.4: what a request may repeat ─────────────────────────────────────────

/// §6.4: a sequence number is unique among outstanding requests only: once answered, a
/// restarted peer that numbers from 1 again sends a new request.
#[test]
fn a_sequence_number_again_after_its_answer() {
    let mut upf = node(UPF, Function::Up);
    let first = Message::node(
        1,
        AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000)),
    );
    upf.handle_datagram(at(0), SMF, &first.encode().unwrap());
    let (received, _) = request(&mut upf);
    upf.respond(
        at(0),
        &received,
        AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(1000)),
    )
    .unwrap();
    sent(&mut upf);
    let again = Message::node(
        1,
        AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(2000)),
    );
    upf.handle_datagram(at(5), SMF, &again.encode().unwrap());
    let got = events(&mut upf);
    assert_eq!(requests_of(&got), 1, "{got:?}");
    assert!(got.contains(&Event::PeerRestarted {
        peer: SMF,
        recovery_time_stamp: 2000
    }));
    let heartbeat = Message::node(2, HeartbeatRequest::new(RecoveryTimeStamp::new(2000)));
    upf.handle_datagram(at(6), SMF, &heartbeat.encode().unwrap());
    assert_eq!(
        sent(&mut upf).len(),
        1,
        "a heartbeat of the restarted peer is answered"
    );
}

/// §6.4: one answer to a request; and an answer of its response's type.
#[test]
fn a_request_is_answered_once_by_its_response() {
    let (_, mut upf) = associated(at(0));
    events(&mut upf);
    let update = Message::node(7, AssociationUpdateRequest::new(node_id(SMF)));
    upf.handle_datagram(at(1), SMF, &update.encode().unwrap());
    let (received, _) = request(&mut upf);
    assert_eq!(
        upf.respond(
            at(1),
            &received,
            HeartbeatResponse::new(RecoveryTimeStamp::new(1))
        ),
        Err(NodeError::WrongResponse)
    );
    upf.respond(
        at(1),
        &received,
        AssociationUpdateResponse::new(node_id(UPF), accepted()),
    )
    .unwrap();
    assert_eq!(
        upf.respond(
            at(1),
            &received,
            AssociationUpdateResponse::new(node_id(UPF), accepted())
        ),
        Err(NodeError::Answered)
    );
    assert_eq!(sent(&mut upf).len(), 1);
}

/// A request that the caller cancels is sent no more, and its response is late.
#[test]
fn a_cancelled_request_is_sent_no_more() {
    let mut smf = node(SMF, Function::Cp);
    let id = smf.request(at(0), UPF, heartbeat()).unwrap();
    let header = decoded(&sent(&mut smf)[0]).header;
    assert!(smf.cancel(at(1), id));
    assert!(!smf.cancel(at(1), id));
    for attempt in 1..=4 {
        smf.handle_timeout(T1 * attempt);
    }
    assert!(sent(&mut smf).is_empty() && events(&mut smf).is_empty());
    smf.handle_datagram(
        at(13),
        UPF,
        &Message {
            header,
            body: HeartbeatResponse::new(RecoveryTimeStamp::new(1)).into(),
        }
        .encode()
        .unwrap(),
    );
    assert_eq!(violations(&mut smf), [ViolationKind::LateResponse]);
}

/// A response of another type than the request's is discarded, and the request waits.
#[test]
fn a_response_of_another_type_is_discarded() {
    let mut smf = node(SMF, Function::Cp);
    smf.request(at(0), UPF, heartbeat()).unwrap();
    let header = decoded(&sent(&mut smf)[0]).header;
    let wrong = Message {
        header,
        body: AssociationUpdateResponse::new(node_id(UPF), accepted()).into(),
    };
    smf.handle_datagram(at(1), UPF, &wrong.encode().unwrap());
    assert_eq!(violations(&mut smf), [ViolationKind::WrongResponseType]);
    smf.handle_timeout(T1);
    assert_eq!(sent(&mut smf).len(), 1, "still sent again");
}

/// The probes of `Delivery`: CacheOnly keeps the answer for the retransmission and sends
/// it then; Forget keeps nothing and changes nothing, as a responder that lost its state.
#[test]
fn cache_only_and_forget() {
    let mut upf = node(UPF, Function::Up);
    let setup = Message::node(
        3,
        AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000)),
    );
    let octets = setup.encode().unwrap();
    upf.handle_datagram(at(0), SMF, &octets);
    let (received, _) = request(&mut upf);
    let answer = Message::node(
        3,
        AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(1000)),
    );
    upf.respond_message(at(0), &received, answer.clone(), Delivery::Forget)
        .unwrap();
    assert!(sent(&mut upf).is_empty());
    assert!(upf.association(SMF).is_none(), "nothing changed");
    upf.handle_datagram(at(3), SMF, &octets);
    let (received, _) = request(&mut upf);
    upf.respond_message(at(3), &received, answer, Delivery::CacheOnly)
        .unwrap();
    assert!(sent(&mut upf).is_empty());
    assert!(upf.association(SMF).is_some());
    upf.handle_datagram(at(6), SMF, &octets);
    assert!(
        events(&mut upf)
            .iter()
            .all(|event| !matches!(event, Event::Request { .. }))
    );
    assert_eq!(sent(&mut upf).len(), 1, "the kept answer");
}

/// A probe's answer changes the node while the node keeps the request: once a probe has
/// answered with Forget, or `keep` has passed since the request came, an accepted answer
/// is sent, and changes nothing.
#[test]
fn a_probe_answer_to_a_request_forgotten_changes_nothing() {
    let mut upf = node(UPF, Function::Up);
    let setup = |sequence| {
        Message::node(
            sequence,
            AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000)),
        )
    };
    let answer = |sequence| {
        Message::node(
            sequence,
            AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(1000)),
        )
    };
    upf.handle_datagram(at(0), SMF, &setup(3).encode().unwrap());
    let (received, _) = request(&mut upf);
    upf.respond_message(at(0), &received, answer(3), Delivery::Forget)
        .unwrap();
    upf.respond_message(at(0), &received, answer(3), Delivery::Send)
        .unwrap();
    assert_eq!(sent(&mut upf).len(), 1);
    assert!(upf.association(SMF).is_none(), "after Forget");
    upf.handle_datagram(at(1), SMF, &setup(4).encode().unwrap());
    let (received, _) = request(&mut upf);
    let past = at(1) + upf.config().keep;
    upf.handle_timeout(past);
    upf.respond_message(past, &received, answer(4), Delivery::Send)
        .unwrap();
    assert_eq!(sent(&mut upf).len(), 1);
    assert!(upf.association(SMF).is_none(), "past keep");
}

/// Durations at their limits do not overflow: a request kept, sent again or beating for
/// ever.
#[test]
fn durations_at_their_limits() {
    let mut upf = Node::new(NodeConfig {
        keep: Duration::MAX,
        ..config(UPF, Function::Up)
    });
    upf.handle_datagram(at(1), OTHER, &heartbeat().encode().unwrap());
    let mut smf = Node::new(NodeConfig {
        t1: Duration::MAX,
        heartbeat: Some(Duration::MAX),
        ..config(SMF, Function::Cp)
    });
    smf.request(at(1), UPF, heartbeat()).unwrap();
    smf.handle_timeout(Duration::MAX);
}

/// A T1 or a heartbeat interval of zero is one of a millisecond: a node does not send
/// every retransmission at once, nor spin on its heartbeats.
#[test]
fn durations_of_zero() {
    let mut smf = Node::new(NodeConfig {
        t1: Duration::ZERO,
        heartbeat: Some(Duration::ZERO),
        ..config(SMF, Function::Cp)
    });
    smf.request(at(0), UPF, heartbeat()).unwrap();
    smf.handle_timeout(at(0));
    assert_eq!(sent(&mut smf).len(), 1);
    let (mut smf, _) = associated_as(
        NodeConfig {
            heartbeat: Some(Duration::ZERO),
            ..config(SMF, Function::Cp)
        },
        at(0),
    );
    smf.handle_timeout(at(1));
    assert!(smf.poll_timeout().is_some_and(|next| next > at(1)));
}

/// What the node keeps of peers that send without an association is bounded by
/// `capacity`: the oldest go first.
#[test]
fn what_the_node_keeps_is_bounded() {
    let mut upf = Node::new(NodeConfig {
        capacity: 100,
        ..config(UPF, Function::Up)
    });
    for port in 1..=2_000u16 {
        let from = SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::new(10, 9, (port >> 8) as u8, port as u8)),
            port,
        );
        upf.handle_datagram(at(0), from, &heartbeat().encode().unwrap());
    }
    sent(&mut upf);
    let kept = format!("{upf:?}");
    // The Recovery Time Stamps, the answers and their deadlines: each of at most 100
    assert!(
        kept.matches("10.9.").count() <= 3 * 100,
        "{}",
        kept.matches("10.9.").count()
    );
}

/// Every sequence number reserved: a request has none, and says so; one given back is
/// the next request's. CI runs it, with `--ignored`.
#[test]
#[ignore = "reserves 2^24 numbers: run with --release"]
fn no_sequence_number_left() {
    let mut smf = node(SMF, Function::Cp);
    let reserved: Vec<u32> = (0..0x0100_0000u32)
        .map(|_| smf.reserve_sequence().unwrap())
        .collect();
    assert_eq!(
        smf.request(at(0), UPF, heartbeat()),
        Err(NodeError::NoSequence)
    );
    let given_back = reserved[1000];
    assert!(smf.release_sequence(given_back));
    assert!(!smf.release_sequence(given_back), "once");
    smf.request(at(0), UPF, heartbeat()).unwrap();
    assert_eq!(decoded(&sent(&mut smf)[0]).header.sequence, given_back);
}

/// A sequence number reserved and given back is free again; one that was not reserved is
/// not given back.
#[test]
fn a_reserved_sequence_number_given_back() {
    let mut smf = node(SMF, Function::Cp);
    let sequence = smf.reserve_sequence().unwrap();
    assert!(smf.release_sequence(sequence));
    assert!(!smf.release_sequence(sequence));
    assert!(!smf.release_sequence(sequence + 1));
}

/// §6.4: a request that waits for the caller's answer stays, whatever comes meanwhile:
/// the answer has its effect, and answers the retransmission.
#[test]
fn a_request_waits_for_its_answer_through_a_flood() {
    let mut upf = Node::new(NodeConfig {
        capacity: 4,
        ..config(UPF, Function::Up)
    });
    let setup = setup_of(SMF, 1, 1000);
    upf.handle_datagram(at(0), SMF, &setup);
    let (received, _) = request(&mut upf);
    for i in 0..8u8 {
        let from = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 9, 9, i)), 8805);
        upf.handle_datagram(at(0), from, &heartbeat().encode().unwrap());
    }
    assert_eq!(sent(&mut upf).len(), 8, "each heartbeat answered");
    events(&mut upf);
    upf.respond(at(1), &received, setup_answer()).unwrap();
    assert!(upf.association(SMF).is_some());
    assert!(matches!(events(&mut upf)[..], [Event::Associated { .. }]));
    sent(&mut upf);
    upf.handle_datagram(at(2), SMF, &setup);
    assert_eq!(
        events(&mut upf),
        [Event::Retransmission {
            from: SMF,
            sequence: 1,
            answered: true
        }],
        "no new request"
    );
    assert_eq!(sent(&mut upf).len(), 1, "the kept answer");
    assert_eq!(upf.counters(), Counters::default());
}

/// Beyond `capacity`, the oldest answer goes for a new request, and a request that
/// finds every place waiting for an answer is dropped: both are counted.
#[test]
fn what_a_full_node_drops_is_counted() {
    let mut upf = Node::new(NodeConfig {
        capacity: 2,
        ..config(UPF, Function::Up)
    });
    let peers: Vec<SocketAddr> = (1..=3u8)
        .map(|i| SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 9, 0, i)), 8805))
        .collect();
    let mut waiting = Vec::new();
    for peer in &peers[..2] {
        upf.handle_datagram(at(0), *peer, &setup_of(*peer, 1, 1000));
        waiting.push(request(&mut upf).0);
    }
    upf.handle_datagram(at(0), peers[2], &setup_of(peers[2], 1, 1000));
    assert_eq!(requests_of(&events(&mut upf)), 0, "dropped");
    assert_eq!(upf.counters().refused, 1);
    for received in &waiting {
        upf.respond(at(1), received, setup_answer()).unwrap();
    }
    sent(&mut upf);
    events(&mut upf);
    upf.handle_datagram(at(2), peers[2], &setup_of(peers[2], 1, 1000));
    assert_eq!(requests_of(&events(&mut upf)), 1);
    let counters = upf.counters();
    assert_eq!((counters.evicted, counters.refused), (1, 1));
}

/// A peer that changes the request of an answered sequence number again and again
/// leaves behind no more than one request (§6.4).
#[test]
fn a_number_used_again_and_again_is_kept_once() {
    let mut upf = Node::new(NodeConfig {
        capacity: 16,
        ..config(UPF, Function::Up)
    });
    let from: SocketAddr = "10.0.0.9:8805".parse().unwrap();
    for i in 0..1_000u32 {
        let now = Duration::from_millis(u64::from(i));
        upf.handle_datagram(now, from, &setup_of(from, 1, i % 2));
        let (received, _) = request(&mut upf);
        upf.respond(now, &received, setup_answer()).unwrap();
        sent(&mut upf);
    }
    let kept = format!("{upf:?}");
    assert!(kept.matches("10.0.0.9").count() <= 8, "{kept}");
}

/// A probe that answers again changes nothing more: the first answer had the effects.
#[test]
fn a_second_answer_has_no_effect() {
    let mut upf = node(UPF, Function::Up);
    let mut smf = node(SMF, Function::Cp);
    let setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000));
    smf.request(at(0), UPF, Message::node(0, setup)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(0));
    let (received, _) = request(&mut upf);
    upf.respond(at(0), &received, setup_answer()).unwrap();
    pass(&mut upf, &mut smf, SMF, at(0));
    events(&mut smf);
    events(&mut upf);
    let (_, up_seid) = established(&mut smf, &mut upf, at(1));
    let again = Message::node(received.sequence, setup_answer());
    upf.respond_message(at(2), &received, again, Delivery::CacheOnly)
        .unwrap();
    assert!(events(&mut upf).is_empty());
    assert!(upf.session(up_seid).is_some());
}

/// A probe's later answers change nothing, also once the first has left the node, past
/// `keep` or evicted: the first answer of a request is a fact that the node keeps.
#[test]
fn a_later_answer_has_no_effect_after_keep_or_eviction() {
    for evicted in [false, true] {
        let mut upf = Node::new(NodeConfig {
            capacity: 3,
            ..config(UPF, Function::Up)
        });
        let mut smf = node(SMF, Function::Cp);
        let setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000));
        smf.request(at(0), UPF, Message::node(0, setup)).unwrap();
        pass(&mut smf, &mut upf, UPF, at(0));
        let (received, _) = request(&mut upf);
        upf.respond(at(0), &received, setup_answer()).unwrap();
        pass(&mut upf, &mut smf, SMF, at(0));
        events(&mut smf);
        events(&mut upf);
        let (_, up_seid) = established(&mut smf, &mut upf, at(1));
        let now = match evicted {
            // Requests of others take the place of the answer
            true => {
                for i in 1..=3u8 {
                    let from = SocketAddr::new(Ipv4Addr::new(10, 9, 0, i).into(), 8805);
                    upf.handle_datagram(at(2), from, &setup_of(from, 1, 1000));
                    let (other, _) = request(&mut upf);
                    upf.respond(at(2), &other, setup_answer()).unwrap();
                }
                assert!(upf.counters().evicted > 0);
                at(2)
            }
            false => at(30),
        };
        upf.handle_timeout(now);
        events(&mut upf);
        let again = Message::node(received.sequence, setup_answer());
        upf.respond_message(now, &received, again, Delivery::CacheOnly)
            .unwrap();
        assert!(events(&mut upf).is_empty(), "evicted {evicted}");
        assert!(upf.session(up_seid).is_some(), "evicted {evicted}");
        assert_eq!(
            upf.respond(now, &received, setup_answer()),
            Err(NodeError::Forgotten)
        );
    }
}

/// A request that waits for its answer more than `keep` is forgotten, by when its peer
/// has given it up: its retransmission comes again as a new request, the late answer of
/// the first is refused and has no effect, and the place of a host without an
/// association is free again.
#[test]
fn a_request_that_waits_past_keep_is_forgotten() {
    let mut upf = Node::new(NodeConfig {
        keep: Duration::from_secs(5),
        strangers: 1,
        ..config(UPF, Function::Up)
    });
    let setup = setup_of(SMF, 1, 1000);
    upf.handle_datagram(at(0), SMF, &setup);
    let (first, _) = request(&mut upf);
    upf.handle_datagram(at(1), OTHER, &setup_of(OTHER, 1, 1000));
    assert_eq!(requests_of(&events(&mut upf)), 0, "no place for another");
    upf.handle_datagram(at(6), SMF, &setup);
    let (again, _) = request(&mut upf);
    assert_eq!(
        upf.respond(at(7), &first, setup_answer()),
        Err(NodeError::Forgotten)
    );
    assert!(upf.association(SMF).is_none());
    upf.respond(at(7), &again, setup_answer()).unwrap();
    assert!(upf.association(SMF).is_some());
    upf.handle_datagram(at(7), OTHER, &setup_of(OTHER, 2, 1000));
    assert_eq!(requests_of(&events(&mut upf)), 1, "the place is free again");
}

/// The node judges a request by the IEs that it decodes: the first Node ID or CP F-SEID,
/// and not another after a first one of a null length, which the receiver ignores
/// (§7.6.10). A release of a null Node ID and of another association's is no stranger's,
/// nor one of a null Node ID and of one of no association rejected; an establishment of a
/// null CP F-SEID and of one of SEID 0 is not rejected for that SEID, and a report of SEID
/// 0 whose first Old CP F-SEID is null is of no session.
#[test]
fn a_request_is_judged_by_the_first_ie_of_each_type() {
    let (mut smf, mut upf) = associated(at(0));
    upf.handle_datagram(at(0), OTHER, &setup_of(OTHER, 1, 1000));
    let (received, _) = request(&mut upf);
    upf.respond(at(0), &received, setup_answer()).unwrap();
    sent(&mut upf);
    let release = |second: [u8; 4]| {
        let mut release = AssociationReleaseRequest::default();
        release.raw.push(RawIe::new(60, Vec::new()));
        release
            .raw
            .push(RawIe::new(60, [&[0], &second[..]].concat()));
        Message::node(5, release)
    };
    for second in [[10, 0, 0, 3], [10, 0, 0, 7]] {
        upf.handle_datagram(at(1), SMF, &release(second).encode().unwrap());
        let (received, message) = request(&mut upf);
        assert!(!received.stranger);
        assert_eq!(received.node_id, None);
        let Body::AssociationReleaseRequest(body) = &message.body else {
            panic!("{message}")
        };
        assert_eq!(body.node_id, None);
        upf.forget(&received);
    }
    let Body::SessionEstablishmentRequest(mut body) = establishment(9).body else {
        panic!("an establishment")
    };
    body.cp_f_seid = None;
    body.raw.push(RawIe::new(57, Vec::new()));
    body.raw
        .push(RawIe::new(57, [2, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1]));
    let null_first = Message::session(0, 6, Body::SessionEstablishmentRequest(body));
    assert_eq!(taken(&mut upf, SMF, null_first), Ok(false));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    let mut report = SessionReportRequest::new(ReportType {
        dldr: true,
        ..Default::default()
    });
    report.raw.push(RawIe::new(57, Vec::new()));
    let old = [&[2u8][..], &cp_seid.to_be_bytes(), &[10, 0, 0, 1]].concat();
    report.raw.push(RawIe::new(57, old));
    let report = Message::session(0, 7, report);
    assert_eq!(
        taken(&mut smf, UPF, report),
        Err(vec![ViolationKind::UnknownSeid])
    );
}

/// The requests of hosts without an association that wait for their answer are at most
/// `strangers`: beyond, one is dropped before it is decoded, and counted.
#[test]
fn the_requests_of_strangers_are_bounded() {
    let mut upf = Node::new(NodeConfig {
        strangers: 2,
        ..config(UPF, Function::Up)
    });
    for i in 1..=3u8 {
        let from = SocketAddr::new(Ipv4Addr::new(10, 9, 1, i).into(), 8805);
        upf.handle_datagram(at(0), from, &setup_of(from, 1, 1000));
    }
    assert_eq!(requests_of(&events(&mut upf)), 2);
    assert_eq!(upf.counters().refused, 1);
}

/// What the node keeps and gives, printed by Debug, prints no key: the octets of a
/// message as their number, and an IE kept as octets that may hold a key as its length.
#[test]
fn debug_prints_no_key() {
    assert_eq!(
        format!("{:?}", Datagram(vec![1, 2, 3])),
        "Datagram(3 octets)"
    );
    let (mut smf, mut upf) = associated(at(0));
    let password: String = b"hunter2"
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let printed = |text: &str| text.contains(&password) || text.contains("68756e74657232");
    // An unknown session's modification, with a Tunnel Password kept as an IE
    let mut modification = Message::session(0x777, 5, SessionModificationRequest::default());
    if let Body::SessionModificationRequest(request) = &mut modification.body {
        request.raw.push(RawIe::new(313, b"hunter2".to_vec()));
    }
    upf.handle_datagram(at(1), SMF, &modification.encode().unwrap());
    let got = format!("{:?}", events(&mut upf));
    assert!(!printed(&got), "{got}");
    assert!(!printed(&format!("{:?}", sent(&mut upf))));
    // A request that waits, the node's own outstanding one, and an L2TP Tunnel
    // Information that did not decode, with the password in it
    let mut establishment = establishment(smf.new_session());
    if let Body::SessionEstablishmentRequest(request) = &mut establishment.body {
        let tunnel = [&[1, 57][..], &(7u16).to_be_bytes(), b"hunter2"].concat();
        request.raw.push(RawIe::new(276, tunnel));
    }
    smf.request(at(2), UPF, establishment).unwrap();
    assert!(!printed(&format!("{smf:?}")));
    let tunnel = [&[1, 57][..], &(7u16).to_be_bytes(), b"hunter2"].concat();
    assert!(!printed(&format!("{:?}", RawIe::new(276, tunnel))));
    pass(&mut smf, &mut upf, UPF, at(2));
    assert!(!printed(&format!("{upf:?}")));
    let got = format!("{:?}", events(&mut upf));
    assert!(!printed(&got), "{got}");
    // The requests that it keeps are there, by their lengths: the rejection of the
    // modification, and the establishment that waits
    let kept = format!("{upf:?}");
    assert!(kept.contains("rejection: true"), "{kept}");
    assert!(kept.contains("response: None"), "{kept}");
}

// ── §4.2.2: the port of the requests ───────────────────────────────────────

/// §4.2.2: a request goes to port 8805, whatever port the peer sends its own from, and
/// the association is of the peer's address, whatever its port.
#[test]
fn requests_go_to_port_8805() {
    let ephemeral: SocketAddr = "10.0.0.1:40000".parse().unwrap();
    let mut upf = Node::new(NodeConfig {
        heartbeat: Some(Duration::from_secs(10)),
        ..config(UPF, Function::Up)
    });
    upf.handle_datagram(at(0), ephemeral, &setup_of(SMF, 1, 1000));
    let (received, _) = request(&mut upf);
    upf.respond(at(0), &received, setup_answer()).unwrap();
    assert_eq!(
        sent(&mut upf)[0].to,
        ephemeral,
        "a response to the source port"
    );
    assert_eq!(
        upf.association(SMF).map(|association| association.peer),
        Some(SMF)
    );
    assert!(upf.association(ephemeral).is_some());
    events(&mut upf);
    upf.handle_timeout(at(10));
    assert_eq!(sent(&mut upf)[0].to, SMF, "the heartbeat");
    let f_seid = FSeid::ipv4(77, Ipv4Addr::new(10, 0, 0, 1));
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
        SessionEstablishmentRequest::new_n4(node_id(SMF), f_seid, pdr, far),
    );
    upf.handle_datagram(at(11), ephemeral, &establishment.encode().unwrap());
    let (received, _) = request(&mut upf);
    let up_seid = upf.new_session();
    let up_f_seid = FSeid::ipv4(up_seid, Ipv4Addr::new(10, 0, 0, 2));
    let response =
        SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(up_f_seid);
    upf.respond(at(11), &received, response).unwrap();
    sent(&mut upf);
    let report = SessionReportRequest::new(ReportType {
        upir: true,
        ..Default::default()
    });
    upf.session_request(at(12), up_seid, report).unwrap();
    assert_eq!(sent(&mut upf)[0].to, SMF, "the report");
    let pfd = Message::node(3, PfdManagementRequest::default());
    upf.handle_datagram(at(13), SMF, &pfd.encode().unwrap());
    assert_eq!(requests_of(&events(&mut upf)), 1, "of the association");
}

/// A node of `request_port` `None` sends its requests to the port that the peer sent
/// from, for peers on other ports, as in a test.
#[test]
fn requests_to_the_port_of_the_peer() {
    let ephemeral: SocketAddr = "10.0.0.1:40000".parse().unwrap();
    let mut upf = Node::new(NodeConfig {
        heartbeat: Some(Duration::from_secs(10)),
        request_port: None,
        ..config(UPF, Function::Up)
    });
    upf.handle_datagram(at(0), ephemeral, &setup_of(SMF, 1, 1000));
    let (received, _) = request(&mut upf);
    upf.respond(at(0), &received, setup_answer()).unwrap();
    sent(&mut upf);
    upf.handle_timeout(at(10));
    assert_eq!(sent(&mut upf)[0].to, ephemeral);
}

/// A probe may answer with anything, but a response of another type than the request's
/// changes nothing: the peer discards such a response (§7.6.5), so the two sides agree. A
/// modification answered with a deletion response does not end the session, and a setup
/// answered with a release response does not release the association.
#[test]
fn a_probe_answer_of_another_type_changes_nothing() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
    smf.session_request(at(1), cp_seid, SessionModificationRequest::default())
        .unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (received, _) = request(&mut upf);
    let wrong = Message::session(
        cp_seid,
        received.sequence,
        SessionDeletionResponse::new(accepted()),
    );
    upf.respond_message(at(1), &received, wrong, Delivery::Send)
        .unwrap();
    assert!(upf.session(up_seid).is_some());

    // A setup answered with a release response: the association is not formed.
    let mut fresh = node(UPF, Function::Up);
    let setup = Message::node(
        1,
        AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000)),
    );
    fresh.handle_datagram(at(0), SMF, &setup.encode().unwrap());
    let (received, _) = request(&mut fresh);
    let wrong = Message::node(
        received.sequence,
        AssociationReleaseResponse::new(node_id(UPF), accepted()),
    );
    fresh
        .respond_message(at(0), &received, wrong, Delivery::Send)
        .unwrap();
    assert!(fresh.association(SMF).is_none());
}

/// §6.4: an answer to a request that is no longer waiting, because it expired past keep
/// or the caller forgot it, says it is no longer waiting, not that it has its answer
/// (which it does not).
#[test]
fn an_answer_to_a_request_no_longer_waiting_says_so() {
    let answer =
        || AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(1000));
    let setup = || {
        Message::node(
            1,
            AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000)),
        )
    };
    // Forgotten by the caller.
    let mut upf = node(UPF, Function::Up);
    upf.handle_datagram(at(0), SMF, &setup().encode().unwrap());
    let (received, _) = request(&mut upf);
    upf.forget(&received);
    assert_eq!(
        upf.respond(at(0), &received, answer()),
        Err(NodeError::Forgotten)
    );
    // Expired past keep (24 s).
    let mut upf = node(UPF, Function::Up);
    upf.handle_datagram(at(0), SMF, &setup().encode().unwrap());
    let (received, _) = request(&mut upf);
    upf.handle_timeout(at(25));
    assert_eq!(
        upf.respond(at(25), &received, answer()),
        Err(NodeError::Forgotten)
    );
    // Answered already stays Answered.
    let mut upf = node(UPF, Function::Up);
    upf.handle_datagram(at(0), SMF, &setup().encode().unwrap());
    let (received, _) = request(&mut upf);
    upf.respond(at(0), &received, answer()).unwrap();
    assert_eq!(
        upf.respond(at(0), &received, answer()),
        Err(NodeError::Answered)
    );
}

/// §7.6.5: the peer discards a response of another type than its request's, and takes
/// the next one of the right type. A probe that answers an establishment first with a
/// Heartbeat Response, then with an accepted establishment response, leaves both sides
/// with the session: the first answer of the response's type is the one that changes the
/// node.
#[test]
fn a_probe_answer_of_another_type_leaves_the_next_one_its_effect() {
    let (mut smf, mut upf) = associated(at(0));
    let cp_seid = smf.new_session();
    smf.request(at(0), UPF, establishment(cp_seid)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(0));
    let (received, _) = request(&mut upf);
    let wrong = Message::session(
        cp_seid,
        received.sequence,
        HeartbeatResponse::new(RecoveryTimeStamp::new(1000)),
    );
    upf.respond_message(at(0), &received, wrong, Delivery::Send)
        .unwrap();
    let up_seid = 0x5151;
    let right = Message::session(
        cp_seid,
        received.sequence,
        SessionEstablishmentResponse::new(node_id(UPF), accepted())
            .with_up_f_seid(FSeid::ipv4(up_seid, Ipv4Addr::new(10, 0, 0, 2))),
    );
    upf.respond_message(at(0), &received, right, Delivery::Send)
        .unwrap();
    pass(&mut upf, &mut smf, SMF, at(0));
    let got = events(&mut smf);
    assert!(got.iter().any(|event| matches!(
        event,
        Event::Violation {
            kind: ViolationKind::WrongResponseType,
            ..
        }
    )));
    assert_eq!(smf.session(cp_seid).unwrap().peer_seid, Some(up_seid));
    assert_eq!(upf.session(up_seid).unwrap().peer_seid, Some(cp_seid));
    // The SMF's next modification reaches the UPF's caller.
    smf.session_request(at(1), cp_seid, SessionModificationRequest::default())
        .unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (received, _) = request(&mut upf);
    assert_eq!(received.seid, Some(up_seid));
}

/// §6.4, §7.6.5: the peer takes a response by its sequence number, and discards one of
/// another. A probe that answers a setup with an acceptance of the next sequence number,
/// then with a rejection of the request's, leaves both sides without the association: the
/// first answer that the peer takes is the one that changes the node.
#[test]
fn a_probe_answer_of_another_sequence_number_changes_nothing() {
    let mut smf = node(SMF, Function::Cp);
    let mut upf = node(UPF, Function::Up);
    let setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000));
    smf.request(at(0), UPF, Message::node(0, setup)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(0));
    let (received, _) = request(&mut upf);
    let answer = |sequence: u32, cause: CauseValue| {
        Message::node(
            sequence,
            AssociationSetupResponse::new(
                node_id(UPF),
                Cause::new(cause),
                RecoveryTimeStamp::new(2000),
            ),
        )
    };
    let wrong = answer(received.sequence + 1, CauseValue::RequestAccepted);
    upf.respond_message(at(0), &received, wrong, Delivery::Send)
        .unwrap();
    assert!(upf.association(SMF).is_none());
    pass(&mut upf, &mut smf, SMF, at(0));
    assert_eq!(violations(&mut smf), [ViolationKind::UnknownSequence]);
    let right = answer(received.sequence, CauseValue::RequestRejected);
    upf.respond_message(at(0), &received, right, Delivery::Send)
        .unwrap();
    pass(&mut upf, &mut smf, SMF, at(0));
    assert!(smf.association(UPF).is_none());
    assert!(upf.association(SMF).is_none());
}

/// §7.6.1-§7.6.3: the peer reads an answer from its octets, and ends its request on one
/// that it cannot read, of another version, of a false Message Length, or of an IE whose
/// length runs past the message: such an answer changes neither the peer nor the node,
/// nor does a later one, which the peer, its request ended, discards. One of a type of no
/// table the peer discards, and the request waits for the next.
#[test]
fn a_probe_answer_that_the_peer_cannot_read_changes_nothing() {
    let answer = |sequence: u32| {
        let answer =
            AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(2000));
        Message::node(sequence, answer)
    };
    let false_ie = RawIe {
        ie_type: 3000,
        enterprise_id: None,
        length: Some(200),
        octets: vec![1, 2].into(),
    };
    let unread: [&dyn Fn(&mut Message); 3] = [
        &|message| message.header.version = 2,
        &|message| message.header.length = Some(3),
        &|message| {
            let Body::AssociationSetupResponse(response) = &mut message.body else {
                panic!()
            };
            response.raw.push(false_ie.clone());
        },
    ];
    for (at_case, change) in unread.into_iter().enumerate() {
        let mut smf = node(SMF, Function::Cp);
        let mut upf = node(UPF, Function::Up);
        let setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000));
        smf.request(at(0), UPF, Message::node(0, setup)).unwrap();
        pass(&mut smf, &mut upf, UPF, at(0));
        let (received, _) = request(&mut upf);
        let mut first = answer(received.sequence);
        change(&mut first);
        upf.respond_message(at(0), &received, first, Delivery::Send)
            .unwrap();
        assert!(upf.association(SMF).is_none(), "{at_case}");
        pass(&mut upf, &mut smf, SMF, at(0));
        let failed = events(&mut smf)
            .into_iter()
            .any(|event| matches!(event, Event::Failed { .. }));
        assert!(failed && smf.association(UPF).is_none(), "{at_case}");
        upf.respond_message(at(0), &received, answer(received.sequence), Delivery::Send)
            .unwrap();
        assert!(upf.association(SMF).is_none(), "{at_case}");
        pass(&mut upf, &mut smf, SMF, at(0));
        assert!(smf.association(UPF).is_none(), "{at_case}");
    }
    // A Version Not Supported Response ends the peer's request unread, as one of another
    // version of the request's sequence number; one of another version and sequence
    // number, or a request, the peer discards
    let answer_by = |change: &dyn Fn(&mut Message), body: Option<Body>| {
        let mut smf = node(SMF, Function::Cp);
        let mut upf = node(UPF, Function::Up);
        let setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000));
        smf.request(at(0), UPF, Message::node(0, setup)).unwrap();
        pass(&mut smf, &mut upf, UPF, at(0));
        let (received, _) = request(&mut upf);
        let mut first = answer(received.sequence);
        if let Some(body) = body {
            first.body = body;
        }
        change(&mut first);
        upf.respond_message(at(0), &received, first, Delivery::Send)
            .unwrap();
        upf.respond_message(at(0), &received, answer(received.sequence), Delivery::Send)
            .unwrap();
        upf.association(SMF).is_some()
    };
    let unsupported = Some(VersionNotSupportedResponse::default().into());
    assert!(!answer_by(&|_| {}, unsupported));
    assert!(!answer_by(&|message| message.header.version = 2, None));
    let other = |message: &mut Message| {
        message.header.version = 2;
        message.header.sequence += 1;
    };
    assert!(answer_by(&other, None));
    let heartbeat = Some(HeartbeatRequest::new(RecoveryTimeStamp::new(5)).into());
    assert!(answer_by(&|_| {}, heartbeat));
    // A message type of no table is discarded, and the answer after it taken
    let mut smf = node(SMF, Function::Cp);
    let mut upf = node(UPF, Function::Up);
    let setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000));
    smf.request(at(0), UPF, Message::node(0, setup)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(0));
    let (received, _) = request(&mut upf);
    let other = Message::node(
        received.sequence,
        Body::Other {
            message_type: 99,
            octets: vec![].into(),
        },
    );
    upf.respond_message(at(0), &received, other, Delivery::Send)
        .unwrap();
    assert!(upf.association(SMF).is_none());
    pass(&mut upf, &mut smf, SMF, at(0));
    assert_eq!(violations(&mut smf), [ViolationKind::UnknownMessage]);
    upf.respond_message(at(0), &received, answer(received.sequence), Delivery::Send)
        .unwrap();
    pass(&mut upf, &mut smf, SMF, at(0));
    assert!(upf.association(SMF).is_some() && smf.association(UPF).is_some());
}

/// §7.2.1A, §7.6.2: a Version Not Supported Response ends every request of the peer to
/// the node, whichever request it answers: the node's answers to them after change
/// nothing, as the peer discards them.
#[test]
fn a_version_not_supported_answer_ends_every_request_of_the_peer() {
    let (mut smf, mut upf) = associated(at(0));
    let cp_seids = [smf.new_session(), smf.new_session()];
    for cp_seid in cp_seids {
        smf.request(at(1), UPF, establishment(cp_seid)).unwrap();
    }
    pass(&mut smf, &mut upf, UPF, at(1));
    let received: Vec<Received> = events(&mut upf)
        .into_iter()
        .filter_map(|event| match event {
            Event::Request { request, .. } => Some(request),
            _ => None,
        })
        .collect();
    let unsupported = Message::node(received[0].sequence, VersionNotSupportedResponse::default());
    upf.respond_message(at(1), &received[0], unsupported, Delivery::Send)
        .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    let failed = events(&mut smf).into_iter().filter(|event| {
        matches!(
            event,
            Event::Failed {
                failure: Failure::VersionNotSupported,
                ..
            }
        )
    });
    assert_eq!(failed.count(), 2);
    let up_seid = upf.new_session();
    let f_seid = FSeid::ipv4(up_seid, Ipv4Addr::new(10, 0, 0, 2));
    let response =
        SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(f_seid);
    upf.respond(at(2), &received[1], response).unwrap();
    assert!(upf.session(up_seid).is_none());
    pass(&mut upf, &mut smf, SMF, at(2));
    assert_eq!(violations(&mut smf), [ViolationKind::DuplicateResponse]);
    assert!(smf.sessions().next().is_none());
}

/// §6.4: a peer's retransmission of a request that the node holds is an event, which a
/// probe of the peer's retransmissions sees without forgetting the request: one that waits
/// for the caller's answer, unanswered, and one answered from the cache, the caller's
/// answer or a rejection of the node's own, with the response sent again. A Heartbeat
/// Request is answered from the state, and held by nothing.
#[test]
fn a_retransmission_of_a_held_request_is_an_event() {
    let retransmission = |sequence, answered| Event::Retransmission {
        from: SMF,
        sequence,
        answered,
    };
    let mut upf = node(UPF, Function::Up);
    let setup = setup_of(SMF, 5, 1000);
    upf.handle_datagram(at(0), SMF, &setup);
    let (received, _) = request(&mut upf);
    upf.handle_datagram(at(1), SMF, &setup);
    assert_eq!(events(&mut upf), [retransmission(5, false)]);
    assert!(sent(&mut upf).is_empty());
    upf.respond(at(1), &received, setup_answer()).unwrap();
    let answer = sent(&mut upf);
    events(&mut upf);
    upf.handle_datagram(at(2), SMF, &setup);
    assert_eq!(events(&mut upf), [retransmission(5, true)]);
    assert_eq!(sent(&mut upf), answer);
    // A session request of a host without an association, which the node rejects itself
    let modification = Message::session(0x10, 6, SessionModificationRequest::default())
        .encode()
        .unwrap();
    let mut upf = node(UPF, Function::Up);
    upf.handle_datagram(at(0), SMF, &modification);
    assert_eq!(
        violations(&mut upf),
        [ViolationKind::SessionWithoutAssociation]
    );
    let rejection = sent(&mut upf);
    upf.handle_datagram(at(1), SMF, &modification);
    assert_eq!(events(&mut upf), [retransmission(6, true)]);
    assert_eq!(sent(&mut upf), rejection);
    // A heartbeat, again
    let heartbeat = Message::node(7, HeartbeatRequest::new(RecoveryTimeStamp::new(1000)))
        .encode()
        .unwrap();
    for _ in 0..2 {
        upf.handle_datagram(at(2), SMF, &heartbeat);
        assert_eq!(sent(&mut upf).len(), 1);
    }
    assert!(events(&mut upf).is_empty());
}
