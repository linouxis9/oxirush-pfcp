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

//! PFCP messages bundled in one datagram (§6.5).

use super::*;

fn bundle(messages: &[Message]) -> Vec<u8> {
    let mut octets = Vec::new();
    for (rank, message) in messages.iter().enumerate() {
        let mut message = message.clone();
        message.header.follow_on = rank + 1 < messages.len();
        octets.extend(message.encode().unwrap());
    }
    octets
}

/// An SMF and a UPF associated, which announce BUNDL in their CP and UP Function
/// Features (§8.2.25, §8.2.58).
fn bundling(now: Duration) -> (Node, Node) {
    let (mut smf, mut upf) = (node(SMF, Function::Cp), node(UPF, Function::Up));
    let cp = CpFunctionFeatures {
        bundl: true,
        ..cp_features()
    };
    let up = UpFunctionFeatures {
        bundl: true,
        ..up_features()
    };
    set_up(&mut smf, &mut upf, now, cp, up);
    events(&mut smf);
    events(&mut upf);
    (smf, upf)
}

#[test]
fn bundled_datagram_each_message() {
    let (mut smf, mut upf) = bundling(at(0));
    let (_, up_seid) = established(&mut smf, &mut upf, at(0));
    let modification =
        |sequence| Message::session(up_seid, sequence, SessionModificationRequest::default());
    upf.handle_datagram(at(1), SMF, &bundle(&[modification(20), modification(21)]));
    assert_eq!(sequences(&mut upf), [20, 21]);
}

/// §6.5: bundling "may be used if both the CP function and the UP function have
/// indicated support of the corresponding feature ... during the PFCP Association Setup or
/// Update procedure": the node takes what a peer bundles when both announced BUNDL in the
/// features of their function, in their association messages, and discards it otherwise.
#[test]
fn bundling_needs_both_to_announce_it() {
    let modifications = |up_seid, first: u32| {
        let modification =
            |sequence| Message::session(up_seid, sequence, SessionModificationRequest::default());
        bundle(&[modification(first), modification(first + 1)])
    };
    let refused = [ViolationKind::BundlingNotAgreed];
    // Each of the four: neither, the SMF alone, the UPF alone, both
    for (smf_bundles, upf_bundles) in [(false, false), (true, false), (false, true), (true, true)] {
        let (mut smf, mut upf) = (node(SMF, Function::Cp), node(UPF, Function::Up));
        let cp = CpFunctionFeatures {
            bundl: smf_bundles,
            ..cp_features()
        };
        let up = UpFunctionFeatures {
            bundl: upf_bundles,
            ..up_features()
        };
        set_up(&mut smf, &mut upf, at(0), cp, up);
        let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
        upf.handle_datagram(at(1), SMF, &modifications(up_seid, 20));
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
        smf.handle_datagram(at(1), UPF, &bundle(&[report(30), report(31)]));
        match smf_bundles && upf_bundles {
            true => {
                assert_eq!(sequences(&mut upf), [20, 21]);
                assert_eq!(sequences(&mut smf), [30, 31]);
            }
            false => {
                assert_eq!(violations(&mut upf), refused);
                assert_eq!(violations(&mut smf), refused);
            }
        }
    }
    // Both did, then the SMF's update takes BUNDL back
    let (mut smf, mut upf) = bundling(at(0));
    let (_, up_seid) = established(&mut smf, &mut upf, at(0));
    upf.handle_datagram(at(1), SMF, &modifications(up_seid, 20));
    assert_eq!(sequences(&mut upf), [20, 21]);
    let update = AssociationUpdateRequest::new(node_id(SMF))
        .with_cp_function_features(CpFunctionFeatures::default());
    smf.request(at(2), UPF, Message::node(0, update)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(2));
    let (received, _) = request(&mut upf);
    upf.respond(
        at(2),
        &received,
        AssociationUpdateResponse::new(node_id(UPF), accepted()),
    )
    .unwrap();
    upf.handle_datagram(at(3), SMF, &modifications(up_seid, 30));
    assert_eq!(violations(&mut upf), refused);
    // Both did, then an update of the SMF, with its features or not, which the UPF
    // answers taking BUNDL back: its own, and the SMF's own when it updates
    for with_features in [false, true] {
        let (mut smf, mut upf) = bundling(at(0));
        let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
        let mut update = AssociationUpdateRequest::new(node_id(SMF));
        if with_features {
            let cp = CpFunctionFeatures {
                bundl: true,
                ..cp_features()
            };
            update = update.with_cp_function_features(cp);
        }
        let message = Message::node(0, update);
        smf.request(at(2), UPF, message).unwrap();
        pass(&mut smf, &mut upf, UPF, at(2));
        let (received, _) = request(&mut upf);
        let answer = AssociationUpdateResponse::new(node_id(UPF), accepted())
            .with_up_function_features(up_features());
        upf.respond(at(2), &received, answer).unwrap();
        pass(&mut upf, &mut smf, SMF, at(2));
        upf.handle_datagram(at(3), SMF, &modifications(up_seid, 40));
        assert_eq!(violations(&mut upf), refused, "the UPF's own");
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
        smf.handle_datagram(at(3), UPF, &bundle(&[report(50), report(51)]));
        assert_eq!(
            violations(&mut smf),
            refused,
            "the UPF's, as the SMF has it"
        );
    }
    // The SMF's update takes its own BUNDL back, which the UPF accepts
    let (mut smf, mut upf) = bundling(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    let update =
        AssociationUpdateRequest::new(node_id(SMF)).with_cp_function_features(cp_features());
    let message = Message::node(0, update);
    smf.request(at(2), UPF, message).unwrap();
    pass(&mut smf, &mut upf, UPF, at(2));
    let (received, _) = request(&mut upf);
    let answer = AssociationUpdateResponse::new(node_id(UPF), accepted());
    upf.respond(at(2), &received, answer).unwrap();
    pass(&mut upf, &mut smf, SMF, at(2));
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
    smf.handle_datagram(at(3), UPF, &bundle(&[report(60), report(61)]));
    assert_eq!(violations(&mut smf), refused, "the SMF's own");
}

/// §7.6.2: a bundled message of another version is answered, and what follows it, whose
/// framing the node does not know, is discarded.
#[test]
fn bundled_message_of_another_version() {
    let (mut smf, mut upf) = bundling(at(0));
    let (_, up_seid) = established(&mut smf, &mut upf, at(0));
    let modification =
        |sequence| Message::session(up_seid, sequence, SessionModificationRequest::default());
    let mut octets = bundle(&[modification(20), modification(21), modification(22)]);
    let second = octets.len() / 3;
    octets[second] = (octets[second] & 0x1f) | 2 << 5;
    upf.handle_datagram(at(1), SMF, &octets);
    assert_eq!(requests_of(&events(&mut upf)), 1);
    let answers: Vec<Message> = sent(&mut upf).iter().map(decoded).collect();
    assert!(
        matches!(
            &answers[..],
            [Message {
                body: Body::VersionNotSupportedResponse(_),
                ..
            }]
        ),
        "{answers:?}"
    );
}

/// §6.5: the messages of a bundle are of sessions "with the peer's F-SEID having the same
/// IP address ... when being sent to that peer PFCP entity": of one address of the
/// receiver's F-SEIDs, whatever the addresses of the sender's. A UPF of two addresses
/// bundles the reports of its sessions of each to the SMF's one address, which takes them;
/// an SMF that bundles modifications of sessions of the UPF's two addresses breaks the
/// rule, and the UPF discards the second.
#[test]
fn bundled_messages_of_one_peer() {
    let (mut smf, mut upf) = bundling(at(0));
    let (cp_first, up_first) =
        established_on(&mut smf, &mut upf, at(0), Ipv4Addr::new(10, 0, 0, 2));
    let (cp_second, up_second) =
        established_on(&mut smf, &mut upf, at(0), Ipv4Addr::new(10, 0, 0, 22));
    let report = |seid, sequence| {
        Message::session(
            seid,
            sequence,
            SessionReportRequest::new(ReportType {
                upir: true,
                ..Default::default()
            }),
        )
    };
    smf.handle_datagram(
        at(1),
        UPF,
        &bundle(&[report(cp_first, 100), report(cp_second, 101)]),
    );
    assert_eq!(sequences(&mut smf), [100, 101]);
    let modification =
        |seid, sequence| Message::session(seid, sequence, SessionModificationRequest::default());
    upf.handle_datagram(
        at(1),
        SMF,
        &bundle(&[modification(up_first, 20), modification(up_second, 21)]),
    );
    let events = events(&mut upf);
    assert_eq!(requests_of(&events), 1);
    assert_eq!(kinds_of(&events), [ViolationKind::BundledPeers]);
}

/// §6.5: "the procedures ... shall apply for each PFCP message that is bundled ... as if
/// the PFCP message was sent in its own individual UDP/IP packet": a bundle of a peer that
/// sends from the address of an F-SEID of its sessions, not that of its association, is
/// taken as its messages alone are, by the agreement of the association of the sessions:
/// the UPF's reports from its UP F-SEID address, the SMF's modifications from its CP
/// F-SEID address; and an SMF of an SSET set without an association of its own bundles
/// what it sends alone, by the agreement of the set's association.
#[test]
fn a_bundle_of_an_f_seid_address_is_taken_as_its_messages_alone() {
    let (mut smf, mut upf) = bundling(at(0));
    let up_address = Ipv4Addr::new(10, 0, 0, 22);
    let (cp_first, up_first) = established_on(&mut smf, &mut upf, at(0), up_address);
    let (cp_second, up_second) = established_on(&mut smf, &mut upf, at(0), up_address);
    let report = |seid, sequence| {
        Message::session(
            seid,
            sequence,
            SessionReportRequest::new(ReportType {
                upir: true,
                ..Default::default()
            }),
        )
    };
    let from = up_address.into_socket(8805);
    smf.handle_datagram(at(1), from, &report(cp_first, 99).encode().unwrap());
    assert_eq!(sequences(&mut smf), [99]);
    smf.handle_datagram(
        at(1),
        from,
        &bundle(&[report(cp_first, 100), report(cp_second, 101)]),
    );
    assert_eq!(sequences(&mut smf), [100, 101]);
    let _ = (up_first, up_second);
    // The SMF from the address of its CP F-SEIDs, 10.0.0.11, not its association's
    let cp_address = Ipv4Addr::new(10, 0, 0, 11);
    let up_seids: Vec<u64> = (0..2)
        .map(|_| {
            let f_seid = FSeid::ipv4(smf.new_session(), cp_address);
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
            let establishment = SessionEstablishmentRequest::new_n4(node_id(SMF), f_seid, pdr, far);
            let message = Message::session(0, 0, establishment);
            smf.request(at(1), UPF, message).unwrap();
            pass(&mut smf, &mut upf, UPF, at(1));
            let (received, _) = request(&mut upf);
            let up_seid = upf.new_session();
            let up_f_seid = FSeid::ipv4(up_seid, Ipv4Addr::new(10, 0, 0, 2));
            let response = SessionEstablishmentResponse::new(node_id(UPF), accepted())
                .with_up_f_seid(up_f_seid);
            upf.respond(at(1), &received, response).unwrap();
            up_seid
        })
        .collect();
    events(&mut upf);
    let modification =
        |seid, sequence| Message::session(seid, sequence, SessionModificationRequest::default());
    let from = cp_address.into_socket(8805);
    // The UPF's session is of the CP F-SEID's address, which its requests come from
    assert_eq!(
        upf.session(up_seids[0]).map(|session| session.peer),
        Some(from)
    );
    upf.handle_datagram(
        at(2),
        from,
        &modification(up_seids[0], 20).encode().unwrap(),
    );
    assert_eq!(sequences(&mut upf), [20]);
    upf.handle_datagram(
        at(2),
        from,
        &bundle(&[modification(up_seids[0], 21), modification(up_seids[1], 22)]),
    );
    assert_eq!(sequences(&mut upf), [21, 22]);
    // Another SMF of the set, without an association of its own: its requests, as alone,
    // are a stranger's
    upf.handle_datagram(
        at(3),
        OTHER,
        &bundle(&[modification(up_seids[0], 40), modification(up_seids[1], 41)]),
    );
    let strangers: Vec<bool> = events(&mut upf)
        .into_iter()
        .filter_map(|event| match event {
            Event::Request { request, .. } => Some(request.stranger),
            _ => None,
        })
        .collect();
    assert_eq!(strangers, [true, true]);
}

/// §6.5 and §5.22: the peer of a session that the node adopted without an association, whose
/// association another SMF of the set holds, bundles its messages as an associated peer
/// does: the node takes them when it last announced BUNDL, in an association message of
/// its own. A host of neither has not agreed on bundling.
#[test]
fn an_adopted_peer_bundles_as_an_associated_one() {
    let entity = |bundling| {
        let mut entity = node(OTHER, Function::Cp);
        let features = CpFunctionFeatures {
            bundl: bundling,
            ..Default::default()
        };
        let setup = AssociationSetupRequest::new(node_id(OTHER), RecoveryTimeStamp::new(1000))
            .with_cp_function_features(features);
        let elsewhere = Ipv4Addr::new(10, 0, 0, 12).into_socket(8805);
        let message = Message::node(0, setup);
        entity.request(at(0), elsewhere, message).unwrap();
        sent(&mut entity);
        entity.adopt_session(0x55, UPF, 0x66).unwrap();
        events(&mut entity);
        entity
    };
    let report = |sequence| {
        Message::session(
            0x55,
            sequence,
            SessionReportRequest::new(ReportType {
                dldr: true,
                ..Default::default()
            }),
        )
    };
    let reports = bundle(&[report(10), report(11)]);
    let mut taking = entity(true);
    taking.handle_datagram(at(1), UPF, &reports);
    assert_eq!(sequences(&mut taking), [10, 11]);
    let mut refusing = entity(false);
    refusing.handle_datagram(at(1), UPF, &reports);
    assert_eq!(
        violations(&mut refusing),
        [ViolationKind::BundlingNotAgreed]
    );
    let stranger = Ipv4Addr::new(10, 0, 0, 8).into_socket(8805);
    taking.handle_datagram(at(1), stranger, &reports);
    assert_eq!(
        violations(&mut taking),
        [ViolationKind::BundledWithoutAssociation]
    );
}

/// §7.2.1A: the FO flag of a message that ends its datagram follows on to nothing: the
/// message is one on its own, which the node takes whether bundling was agreed or not,
/// and a stranger's Heartbeat Request is answered.
#[test]
fn a_lone_message_with_the_fo_flag_is_one_message() {
    let lone = |message: Message| {
        let mut message = message;
        message.header.follow_on = true;
        message.encode().unwrap()
    };
    for agreed in [true, false] {
        let (mut smf, mut upf) = if agreed {
            bundling(at(0))
        } else {
            associated(at(0))
        };
        let (_, up_seid) = established(&mut smf, &mut upf, at(0));
        let modification = Message::session(up_seid, 20, SessionModificationRequest::default());
        upf.handle_datagram(at(1), SMF, &lone(modification));
        let events = events(&mut upf);
        assert_eq!(requests_of(&events), 1, "{events:?}");
        assert_eq!(events.len(), 1, "{events:?}");
    }
    let mut upf = node(UPF, Function::Up);
    upf.handle_datagram(at(0), OTHER, &lone(heartbeat()));
    assert!(events(&mut upf).is_empty());
    let answers: Vec<Message> = sent(&mut upf).iter().map(decoded).collect();
    assert!(
        matches!(
            &answers[..],
            [Message {
                body: Body::HeartbeatResponse(_),
                ..
            }]
        ),
        "{answers:?}"
    );
}

/// §6.5: node related messages are not bundled, and a peer without an association has
/// not agreed on bundling: what they bundle is discarded, and answered not at all.
#[test]
fn bundled_node_message_reported() {
    let heartbeats = bundle(&[
        Message::node(1, HeartbeatRequest::new(RecoveryTimeStamp::new(1000))),
        Message::node(2, HeartbeatRequest::new(RecoveryTimeStamp::new(1000))),
    ]);
    let mut lone = node(UPF, Function::Up);
    lone.handle_datagram(at(0), OTHER, &heartbeats);
    assert_eq!(
        violations(&mut lone),
        [ViolationKind::BundledWithoutAssociation]
    );
    assert!(sent(&mut lone).is_empty());
    let (_, mut upf) = bundling(at(0));
    upf.handle_datagram(at(0), SMF, &heartbeats);
    assert_eq!(
        violations(&mut upf),
        [
            ViolationKind::BundledNodeMessage,
            ViolationKind::BundledNodeMessage
        ]
    );
    assert!(sent(&mut upf).is_empty(), "none is answered");
}

/// §6.5 NOTE 3: a request sent bundled and retransmitted alone is the same request,
/// answered from the cache.
#[test]
fn a_retransmission_alone_of_a_bundled_request() {
    let (mut smf, mut upf) = bundling(at(0));
    let (_, up_seid) = established(&mut smf, &mut upf, at(0));
    let modification = |sequence: u32, follow_on: bool| {
        let header = Header {
            follow_on,
            ..Header::session(up_seid, sequence)
        };
        Message {
            header,
            body: SessionModificationRequest::default().into(),
        }
        .encode()
        .unwrap()
    };
    upf.handle_datagram(
        at(1),
        SMF,
        &[modification(20, true), modification(21, false)].concat(),
    );
    for event in events(&mut upf) {
        if let Event::Request { request, .. } = event {
            upf.respond(
                at(1),
                &request,
                SessionModificationResponse::new(accepted()),
            )
            .unwrap();
        }
    }
    let answers = sent(&mut upf);
    upf.handle_datagram(at(4), SMF, &modification(20, false));
    assert_eq!(
        events(&mut upf),
        [Event::Retransmission {
            from: SMF,
            sequence: 20,
            answered: true
        }]
    );
    assert_eq!(sent(&mut upf), answers[..1]);
}

/// `answer` with the FO flag, and a Message Length that ends it `cut` octets before its
/// end: the peer reads the octets after as another message (§7.2.1A).
fn cut_short(mut answer: Message, cut: u16) -> Message {
    let length = answer.encode().unwrap().len() as u16 - 4;
    answer.header.follow_on = true;
    answer.header.length = Some(length - cut);
    answer
}

/// A raw IE of 4 octets that a Length of 4 says, then `after`, which its IE does not count.
fn followed_by(after: &[u8]) -> RawIe {
    RawIe {
        ie_type: 3000,
        enterprise_id: None,
        length: Some(4),
        octets: [&[0; 4][..], after].concat().into(),
    }
}

/// A probe's answer changes the node as its peer reads the datagram that it is (§6.5,
/// §7.2.1A): a peer without an association takes no bundle, and its request waits for
/// the next answer; one that agreed on bundling takes the first message of a session
/// answer; one that did not discards it whole.
#[test]
fn an_answer_changes_the_node_as_its_peer_reads_its_bundle() {
    // A setup answered with the FO flag and a Message Length short of its last IE
    let mut smf = node(SMF, Function::Cp);
    let mut upf = node(UPF, Function::Up);
    let setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000));
    smf.request(at(0), UPF, Message::node(0, setup)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(0));
    let (received, _) = request(&mut upf);
    let answer = Message::node(received.sequence, setup_answer());
    let bundled = cut_short(answer.clone(), 8);
    upf.respond_message(at(0), &received, bundled, Delivery::Send)
        .unwrap();
    assert!(upf.association(SMF).is_none());
    pass(&mut upf, &mut smf, SMF, at(0));
    assert_eq!(
        violations(&mut smf),
        [ViolationKind::BundledWithoutAssociation]
    );
    upf.respond_message(at(0), &received, answer, Delivery::Send)
        .unwrap();
    pass(&mut upf, &mut smf, SMF, at(0));
    assert!(upf.association(SMF).is_some() && smf.association(UPF).is_some());
    // A deletion answered so, with BUNDL on both sides, on neither, and on one alone
    for (smf_bundles, upf_bundles) in [(true, true), (false, false), (true, false), (false, true)] {
        let agreed = smf_bundles && upf_bundles;
        let (mut smf, mut upf) = (node(SMF, Function::Cp), node(UPF, Function::Up));
        let cp = CpFunctionFeatures {
            bundl: smf_bundles,
            ..cp_features()
        };
        let up = UpFunctionFeatures {
            bundl: upf_bundles,
            ..up_features()
        };
        set_up(&mut smf, &mut upf, at(0), cp, up);
        events(&mut smf);
        events(&mut upf);
        let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
        smf.session_request(at(1), cp_seid, SessionDeletionRequest::default())
            .unwrap();
        pass(&mut smf, &mut upf, UPF, at(1));
        let (received, _) = request(&mut upf);
        let mut deletion = SessionDeletionResponse::new(accepted());
        deletion.raw.push(followed_by(&[0x20, 0, 0, 4, 0, 0, 0, 0]));
        let answer = Message::session(cp_seid, received.sequence, deletion);
        upf.respond_message(at(1), &received, cut_short(answer, 8), Delivery::Send)
            .unwrap();
        assert_eq!(upf.session(up_seid).is_none(), agreed, "{agreed}");
        pass(&mut upf, &mut smf, SMF, at(1));
        assert_eq!(smf.session(cp_seid).is_none(), agreed, "{agreed}");
        let discarded = match agreed {
            true => ViolationKind::UnknownMessage,
            false => ViolationKind::BundlingNotAgreed,
        };
        assert_eq!(violations(&mut smf), [discarded]);
    }
}

/// The message after the first of an answer that the peer takes as the response of
/// another of its requests answers that request: the node changes as the peer does.
#[test]
fn an_answer_that_bundles_the_response_of_another_request_answers_it() {
    let (mut smf, mut upf) = bundling(at(0));
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
    let response = |up_seid: u64| {
        let f_seid = FSeid::ipv4(up_seid, Ipv4Addr::new(10, 0, 0, 2));
        SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(f_seid)
    };
    let up_seids = [upf.new_session(), upf.new_session()];
    let second = Message::session(cp_seids[1], received[1].sequence, response(up_seids[1]));
    let second = second.encode().unwrap();
    let mut first = response(up_seids[0]);
    first.raw.push(followed_by(&second));
    let first = Message::session(cp_seids[0], received[0].sequence, first);
    let cut = second.len() as u16;
    upf.respond_message(at(1), &received[0], cut_short(first, cut), Delivery::Send)
        .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    for (cp_seid, up_seid) in cp_seids.into_iter().zip(up_seids) {
        assert_eq!(upf.session(up_seid).unwrap().peer_seid, Some(cp_seid));
        assert_eq!(smf.session(cp_seid).unwrap().peer_seid, Some(up_seid));
    }
    // The second has its answer: its own after is the error of a request answered
    // already, and sends nothing
    let third = upf.new_session();
    assert_eq!(
        upf.respond(at(1), &received[1], response(third)),
        Err(NodeError::Answered)
    );
    assert!(upf.session(third).is_none());
    pass(&mut upf, &mut smf, SMF, at(1));
    assert_eq!(violations(&mut smf), []);
}
