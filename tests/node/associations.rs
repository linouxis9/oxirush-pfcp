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

//! The node related procedures (§6.2): heartbeat (§6.2.2), PFCP association setup, update
//! and release (§6.2.6 to §6.2.8), node report (§6.2.9), and the recovery time stamps of
//! the peers.

use super::*;

// ── §6.2.2: heartbeat ───────────────────────────────────────────────────────

#[test]
fn heartbeat_answered_from_unknown_peer() {
    let mut upf = node(UPF, Function::Up);
    upf.handle_datagram(
        at(0),
        OTHER,
        &Message::node(5, HeartbeatRequest::new(RecoveryTimeStamp::new(1000)))
            .encode()
            .unwrap(),
    );
    assert!(events(&mut upf).is_empty(), "the node answers it");
    let answer = decoded(&sent(&mut upf)[0]);
    assert_eq!(answer.header.sequence, 5);
    let Body::HeartbeatResponse(response) = &answer.body else {
        panic!("{answer:?}")
    };
    assert_eq!(
        response
            .recovery_time_stamp
            .as_ref()
            .map(|stamp| stamp.value),
        Some(1000)
    );
}

// ── §6.2.6 to §6.2.8: associations ──────────────────────────────────────────

#[test]
fn association_setup_by_cp() {
    let (mut smf, mut upf) = (node(SMF, Function::Cp), node(UPF, Function::Up));
    let setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000));
    smf.request(at(0), UPF, Message::node(0, setup)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(0));
    let (received, _) = request(&mut upf);
    assert_eq!(received.node_id, Some(node_id(SMF)));
    assert!(upf.association(SMF).is_none(), "the UPF's caller decides");
    upf.respond(
        at(0),
        &received,
        AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(1000)),
    )
    .unwrap();
    assert_eq!(
        upf.association(SMF)
            .map(|association| association.node_id.clone()),
        Some(node_id(SMF))
    );
    pass(&mut upf, &mut smf, SMF, at(0));
    let associated = events(&mut smf);
    assert!(associated.contains(&Event::Associated {
        peer: UPF,
        node_id: node_id(UPF),
        replaced: false,
        sessions: vec![]
    }));
}

#[test]
fn association_setup_by_up() {
    let (mut smf, mut upf) = (node(SMF, Function::Cp), node(UPF, Function::Up));
    let setup = AssociationSetupRequest::new(node_id(UPF), RecoveryTimeStamp::new(1000));
    upf.request(at(0), SMF, Message::node(0, setup)).unwrap();
    pass(&mut upf, &mut smf, SMF, at(0));
    let (received, _) = request(&mut smf);
    smf.respond(
        at(0),
        &received,
        AssociationSetupResponse::new(node_id(SMF), accepted(), RecoveryTimeStamp::new(1000)),
    )
    .unwrap();
    assert!(smf.association(UPF).is_some());
    pass(&mut smf, &mut upf, UPF, at(0));
    assert!(upf.association(SMF).is_some());
    // A rejection makes none
    let mut other = node(OTHER, Function::Up);
    let setup = AssociationSetupRequest::new(node_id(OTHER), RecoveryTimeStamp::new(1));
    other.request(at(0), SMF, Message::node(0, setup)).unwrap();
    for transmit in sent(&mut other) {
        smf.handle_datagram(at(0), OTHER, &transmit.octets);
    }
    let (received, _) = request(&mut smf);
    let rejection = AssociationSetupResponse::new(
        node_id(SMF),
        Cause::new(CauseValue::RequestRejected),
        RecoveryTimeStamp::new(1000),
    );
    smf.respond(at(0), &received, rejection).unwrap();
    assert!(smf.association(OTHER).is_none());
}

#[test]
fn association_setup_again() {
    let (mut smf, mut upf) = associated(at(0));
    let setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000));
    smf.request(at(5), UPF, Message::node(0, setup)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(5));
    let (received, _) = request(&mut upf);
    upf.respond(
        at(5),
        &received,
        AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(1000)),
    )
    .unwrap();
    assert!(events(&mut upf).contains(&Event::Associated {
        peer: SMF,
        node_id: node_id(SMF),
        replaced: true,
        sessions: vec![]
    }));
}

#[test]
fn association_update() {
    let (mut smf, mut upf) = associated(at(0));
    let features = CpFunctionFeatures {
        load: true,
        ovrl: true,
        ..Default::default()
    };
    let update = AssociationUpdateRequest::new(node_id(SMF)).with_cp_function_features(features);
    smf.request(at(1), UPF, Message::node(0, update)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (received, message) = request(&mut upf);
    let Body::AssociationUpdateRequest(update) = &message.body else {
        panic!()
    };
    assert!(
        update
            .cp_function_features
            .as_ref()
            .is_some_and(|features| features.ovrl)
    );
    upf.respond(
        at(1),
        &received,
        AssociationUpdateResponse::new(node_id(UPF), accepted()),
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(
        smf.association(UPF).is_some() && upf.association(SMF).is_some(),
        "it stays until a release"
    );
}

#[test]
fn association_update_unknown_node() {
    let mut upf = node(UPF, Function::Up);
    let update = Message::node(3, AssociationUpdateRequest::new(node_id(SMF)));
    upf.handle_datagram(at(0), SMF, &update.encode().unwrap());
    assert_eq!(violations(&mut upf), [ViolationKind::UnknownNode]);
    let answer = decoded(&sent(&mut upf)[0]);
    assert_eq!(
        answer.body.cause(),
        Some(CauseValue::NoEstablishedPfcpAssociation)
    );
    assert_eq!(answer.header.sequence, 3);
}

#[test]
fn association_release() {
    let (mut smf, mut upf) = associated(at(0));
    let release = AssociationReleaseRequest::new(node_id(SMF));
    smf.request(at(1), UPF, Message::node(0, release)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (received, _) = request(&mut upf);
    upf.respond(
        at(1),
        &received,
        AssociationReleaseResponse::new(node_id(UPF), accepted()),
    )
    .unwrap();
    assert!(upf.association(SMF).is_none());
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(smf.association(UPF).is_none());
    assert!(events(&mut smf).contains(&Event::Released {
        node_id: node_id(UPF),
        sessions: vec![],
        kept: vec![]
    }));
}

#[test]
fn association_release_ends_sessions() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
    let release = AssociationReleaseRequest::new(node_id(SMF));
    smf.request(at(1), UPF, Message::node(0, release)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (received, _) = request(&mut upf);
    upf.respond(
        at(1),
        &received,
        AssociationReleaseResponse::new(node_id(UPF), accepted()),
    )
    .unwrap();
    assert!(upf.session(up_seid).is_none());
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(events(&mut smf).contains(&Event::Released {
        node_id: node_id(UPF),
        sessions: vec![cp_seid],
        kept: vec![]
    }));
    assert!(smf.session(cp_seid).is_none());
}

#[test]
fn session_needs_association() {
    let (mut smf, mut upf) = (node(SMF, Function::Cp), node(UPF, Function::Up));
    let seid = smf.new_session();
    assert_eq!(
        smf.request(at(0), UPF, establishment(seid)),
        Err(NodeError::NoAssociation)
    );
    // A UPF answers a session from a peer without an association
    let f_seid = FSeid {
        v4: true,
        seid: 0x55,
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
        ..Default::default()
    };
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
        6,
        SessionEstablishmentRequest::new_n4(node_id(SMF), f_seid, pdr, far),
    );
    upf.handle_datagram(at(0), SMF, &establishment.encode().unwrap());
    assert_eq!(
        violations(&mut upf),
        [ViolationKind::SessionWithoutAssociation]
    );
    let answer = decoded(&sent(&mut upf)[0]);
    assert_eq!(
        answer.body.cause(),
        Some(CauseValue::NoEstablishedPfcpAssociation)
    );
    assert_eq!(answer.header.seid, Some(0x55), "to the SMF's SEID");
    assert!(
        answer.check(Interfaces::N4).is_empty(),
        "{:?}",
        answer.check(Interfaces::N4)
    );
}

/// §6.2.9: a node report, and the session set procedures, run as the other requests:
/// Table 7.3-1 makes 12, 14 and 16 requests, and 13, 15 and 17 their responses.
#[test]
fn node_report_and_session_sets() {
    let (mut smf, mut upf) = associated(at(0));
    events(&mut upf);
    let change = PfcpSessionChangeInfo::new(AlternativeSmfIpAddress {
        v4: true,
        ipv4_address: Some(Ipv4Addr::new(10, 0, 0, 9)),
        ..Default::default()
    });
    let exchanges: [(bool, Body, Body); 3] = [
        (
            false,
            NodeReportRequest::new(
                node_id(UPF),
                NodeReportType {
                    uprr: true,
                    ..Default::default()
                },
            )
            .into(),
            NodeReportResponse::new(node_id(SMF), accepted()).into(),
        ),
        (
            false,
            SessionSetDeletionRequest::new(node_id(UPF)).into(),
            SessionSetDeletionResponse::new(node_id(SMF), accepted()).into(),
        ),
        (
            true,
            SessionSetModificationRequest::new(node_id(SMF), change).into(),
            SessionSetModificationResponse::new(node_id(UPF), accepted()).into(),
        ),
    ];
    for (from_smf, body, answer) in exchanges {
        let message_type = body.message_type();
        let (sender, receiver, to, back) = match from_smf {
            true => (&mut smf, &mut upf, UPF, SMF),
            false => (&mut upf, &mut smf, SMF, UPF),
        };
        let id = sender.request(at(1), to, Message::node(0, body)).unwrap();
        pass(sender, receiver, to, at(1));
        let (received, message) = request(receiver);
        assert_eq!(message.body.message_type(), message_type);
        receiver.respond(at(1), &received, answer).unwrap();
        pass(receiver, sender, back, at(1));
        let got = events(sender);
        assert!(
            matches!(&got[..], [Event::Response { request, message }] if *request == id && message.body.message_type() == message_type + 1),
            "{got:?}"
        );
    }
}

/// A node sends a Heartbeat Request to each associated peer every interval, says when a
/// peer answers none of N1 retransmissions, and when its Recovery Time Stamp changes.
#[test]
fn heartbeat_toward_associated_peers() {
    let config = NodeConfig {
        heartbeat: Some(Duration::from_secs(60)),
        ..config(SMF, Function::Cp)
    };
    let (mut smf, mut upf) = associated_as(config, at(0));
    assert_eq!(smf.poll_timeout(), Some(at(60)));
    smf.handle_timeout(at(60));
    pass(&mut smf, &mut upf, UPF, at(60));
    pass(&mut upf, &mut smf, SMF, at(60));
    assert!(
        events(&mut smf).is_empty(),
        "an answered heartbeat is no event"
    );
    // The UPF restarts: its answer has another Recovery Time Stamp
    smf.handle_timeout(at(120));
    let request = decoded(&sent(&mut smf)[0]);
    let restarted = Message::node(
        request.header.sequence,
        HeartbeatResponse::new(RecoveryTimeStamp::new(4000)),
    );
    smf.handle_datagram(at(121), UPF, &restarted.encode().unwrap());
    assert_eq!(
        events(&mut smf),
        [Event::PeerRestarted {
            peer: UPF,
            recovery_time_stamp: 4000
        }]
    );
    // Then it answers no more
    smf.handle_timeout(at(180));
    for attempt in 1..=3 {
        smf.handle_timeout(at(180) + T1 * attempt);
    }
    smf.handle_timeout(at(180) + T1 * 4);
    assert!(events(&mut smf).contains(&Event::PeerDown { peer: UPF }));
}

/// §6.2.2.2 and `NodeConfig::capacity`: a heartbeat of a new host, which the node answers
/// from anyone, costs about the same once the Recovery Time Stamps of the hosts without an
/// association fill the node as before, though each then evicts the oldest: not a walk of
/// them all, nor of the peers that the node keeps the stamps of. Of the batches of a
/// thousand new hosts before and after, the quickest of each. CI runs it, with `--ignored`.
#[test]
#[ignore = "times 70,000 heartbeats: run with --release"]
fn a_new_host_costs_the_same_once_the_stamps_fill_the_node() {
    let mut upf = Node::new(NodeConfig {
        heartbeat: None,
        ..NodeConfig::new(node_id(UPF), Function::Up, 1000)
    });
    let capacity = upf.config().capacity as u32;
    let address = |n: u32| SocketAddr::new(Ipv4Addr::from(0x0b00_0000 + n).into(), 8805);
    let beat = heartbeat().encode().unwrap();
    let mut hosts = 0..;
    let mut batch = |upf: &mut Node| {
        let start = std::time::Instant::now();
        for n in hosts.by_ref().take(1000) {
            upf.handle_datagram(at(1), address(n), &beat);
            while upf.poll_transmit().is_some() {}
            while upf.poll_event().is_some() {}
        }
        start.elapsed()
    };
    for _ in 0..capacity / 1000 - 5 {
        batch(&mut upf);
    }
    let before = (0..5).map(|_| batch(&mut upf)).min().unwrap();
    let after = (0..5).map(|_| batch(&mut upf)).min().unwrap();
    assert!(
        after < before * 10,
        "a thousand new hosts: {before:?} before the stamps fill the node, {after:?} after"
    );
}

// ── Associations and sessions, kept in step with the procedures ─────────────

/// §6.2.6.3.2: a CP function that accepts the setup of a UP function that it has an
/// association with keeps its sessions: the retention of §6.2.6.2.2 is the UP
/// function's.
#[test]
fn a_cp_function_keeps_its_sessions_on_a_new_setup() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    let setup = AssociationSetupRequest::new(node_id(UPF), RecoveryTimeStamp::new(1000));
    upf.request(at(1), SMF, Message::node(0, setup)).unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    let (received, _) = request(&mut smf);
    let answer =
        AssociationSetupResponse::new(node_id(SMF), accepted(), RecoveryTimeStamp::new(1000));
    smf.respond(at(1), &received, answer).unwrap();
    assert!(smf.session(cp_seid).is_some());
    assert!(matches!(
        &events(&mut smf)[..],
        [Event::Associated { replaced: true, sessions, .. }] if sessions.is_empty()
    ));
}

/// §6.2.6.2.2: a new association of a Node ID that has one ends the sessions of the old,
/// but those that the PFCP Session Retention Information keeps.
#[test]
fn reassociation_ends_the_old_sessions() {
    // Without the PFCP Session Retention Information, also beside an IE of another type of
    // a null length, and with it
    let retentions = [
        (None, false),
        (Some(PfcpSessionRetentionInformation::default()), false),
        (None, true),
    ];
    for (retention, null) in retentions {
        let (mut smf, mut upf) = associated(at(0));
        let (_, up_seid) = established(&mut smf, &mut upf, at(0));
        let mut setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(2000));
        setup.pfcp_session_retention_information = retention.clone().map(Box::new);
        if null {
            setup.raw.push(RawIe::new(116, Vec::new()));
        }
        upf.handle_datagram(at(10), SMF, &Message::node(500, setup).encode().unwrap());
        let (received, _) = request(&mut upf);
        upf.respond(
            at(10),
            &received,
            AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(1000)),
        )
        .unwrap();
        let got = events(&mut upf);
        let ended = match retention {
            None => vec![up_seid],
            Some(_) => vec![],
        };
        assert!(
            got.contains(&Event::Associated {
                peer: SMF,
                node_id: node_id(SMF),
                replaced: true,
                sessions: ended.clone()
            }),
            "{got:?}"
        );
        assert_eq!(upf.session(up_seid).is_none(), !ended.is_empty());
        let modification = Message::session(up_seid, 501, SessionModificationRequest::default());
        upf.handle_datagram(at(11), SMF, &modification.encode().unwrap());
        let got = events(&mut upf);
        assert_eq!(
            kinds_of(&got).contains(&ViolationKind::UnknownSeid),
            !ended.is_empty(),
            "{got:?}"
        );
    }
}

/// A replaced association heartbeats its new address, and the old no more.
#[test]
fn a_replaced_association_heartbeats_its_new_address() {
    let mut smf = Node::new(NodeConfig {
        heartbeat: Some(Duration::from_secs(60)),
        ..config(SMF, Function::Cp)
    });
    for (from, sequence) in [(UPF, 1u32), (OTHER, 2)] {
        let setup = Message::node(
            sequence,
            AssociationSetupRequest::new(node_id(UPF), RecoveryTimeStamp::new(5)),
        );
        smf.handle_datagram(at(0), from, &setup.encode().unwrap());
        let (received, _) = request(&mut smf);
        smf.respond(
            at(0),
            &received,
            AssociationSetupResponse::new(node_id(SMF), accepted(), RecoveryTimeStamp::new(1000)),
        )
        .unwrap();
        sent(&mut smf);
    }
    smf.handle_timeout(at(60));
    assert_eq!(
        sent(&mut smf)
            .iter()
            .map(|transmit| transmit.to)
            .collect::<Vec<_>>(),
        [OTHER]
    );
}

/// §6.2.8: a release ends the association between its sender and the node, which it
/// names: one that names the association of another is a stranger's, which the caller
/// takes or rejects.
#[test]
fn a_release_ends_the_association_that_it_names() {
    let mut upf = node(UPF, Function::Up);
    for (from, sequence) in [(SMF, 1u32), (OTHER, 2)] {
        let setup = Message::node(
            sequence,
            AssociationSetupRequest::new(node_id(from), RecoveryTimeStamp::new(5)),
        );
        upf.handle_datagram(at(0), from, &setup.encode().unwrap());
        let (received, _) = request(&mut upf);
        upf.respond(
            at(0),
            &received,
            AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(1000)),
        )
        .unwrap();
        sent(&mut upf);
    }
    let release = Message::node(3, AssociationReleaseRequest::new(node_id(SMF)));
    upf.handle_datagram(at(1), OTHER, &release.encode().unwrap());
    let (received, _) = request(&mut upf);
    assert!(received.stranger);
    let rejection = Cause::new(CauseValue::RequestRejected);
    upf.respond(
        at(1),
        &received,
        AssociationReleaseResponse::new(node_id(UPF), rejection),
    )
    .unwrap();
    assert!(upf.association(SMF).is_some());
    upf.handle_datagram(at(1), SMF, &release.encode().unwrap());
    let (received, _) = request(&mut upf);
    upf.respond(
        at(1),
        &received,
        AssociationReleaseResponse::new(node_id(UPF), accepted()),
    )
    .unwrap();
    assert!(upf.association(SMF).is_none());
    assert!(upf.association(OTHER).is_some());
}

/// A request of a host is of an association that is the host's: a host that names the
/// Node ID of another's in an establishment is answered "No established PFCP Association",
/// and its release of another's association is a stranger's.
#[test]
fn a_request_of_another_peers_node_id() {
    let (_, mut upf) = associated(at(0));
    upf.handle_datagram(at(1), OTHER, &establishment(9).encode().unwrap());
    assert_eq!(
        violations(&mut upf),
        [ViolationKind::SessionWithoutAssociation]
    );
    let release = Message::node(4, AssociationReleaseRequest::new(node_id(SMF)));
    assert_eq!(taken(&mut upf, OTHER, release), Ok(true));
    assert!(upf.association(SMF).is_some());
}

/// The sessions of a peer that restarted end by its association, whatever address
/// their UP F-SEIDs have.
#[test]
fn the_sessions_of_a_peer_end_by_its_association() {
    let (mut smf, mut upf) = associated(at(0));
    let (first, _) = established(&mut smf, &mut upf, at(0));
    let (second, _) = established_on(&mut smf, &mut upf, at(0), Ipv4Addr::new(10, 0, 0, 22));
    assert_eq!(smf.end_sessions_of(UPF), [first, second]);
}

/// A peer is of an address and a port without `request_port`, as two SMFs on one host
/// of a test, and of an address with it: its association, its sessions and its Recovery
/// Time Stamp are its own.
#[test]
fn peers_on_one_address() {
    let smf1: SocketAddr = "127.0.0.1:20001".parse().unwrap();
    let smf2: SocketAddr = "127.0.0.1:20002".parse().unwrap();
    for request_port in [None, Some(8805)] {
        let mut upf = Node::new(NodeConfig {
            request_port,
            ..NodeConfig::new(fqdn("upf"), Function::Up, 1000)
        });
        let mut seids = Vec::new();
        for (peer, name, stamp) in [(smf1, "smf1", 1001), (smf2, "smf2", 1002)] {
            let setup = Message::node(
                1,
                AssociationSetupRequest::new(fqdn(name), RecoveryTimeStamp::new(stamp)),
            );
            upf.handle_datagram(at(0), peer, &setup.encode().unwrap());
            let (received, _) = request(&mut upf);
            let answer =
                AssociationSetupResponse::new(fqdn("upf"), accepted(), RecoveryTimeStamp::new(1));
            upf.respond(at(0), &received, answer).unwrap();
            let f_seid = FSeid {
                v4: true,
                seid: 0x10,
                ipv4: Some(Ipv4Addr::LOCALHOST),
                ..Default::default()
            };
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
                SessionEstablishmentRequest::new_n4(fqdn(name), f_seid, pdr, far),
            );
            upf.handle_datagram(at(1), peer, &establishment.encode().unwrap());
            let (received, _) = request(&mut upf);
            let up_seid = upf.new_session();
            let up_f_seid = FSeid {
                v4: true,
                seid: up_seid,
                ipv4: Some(Ipv4Addr::LOCALHOST),
                ..Default::default()
            };
            let response = SessionEstablishmentResponse::new(fqdn("upf"), accepted())
                .with_up_f_seid(up_f_seid);
            upf.respond(at(1), &received, response).unwrap();
            seids.push(up_seid);
        }
        sent(&mut upf);
        events(&mut upf);
        if request_port.is_some() {
            // One peer, of one association: the second Node ID replaced the first, with
            // its session
            assert_eq!(
                upf.association(smf1)
                    .map(|association| &association.node_id),
                Some(&fqdn("smf2"))
            );
            assert!(upf.session(seids[0]).is_none() && upf.session(seids[1]).is_some());
            continue;
        }
        assert_eq!(
            upf.association(smf2)
                .map(|association| &association.node_id),
            Some(&fqdn("smf2"))
        );
        // Their heartbeats, each with its stamp: no restart
        for i in 0..4 {
            for (peer, stamp) in [(smf1, 1001), (smf2, 1002)] {
                let heartbeat =
                    Message::node(10 + i, HeartbeatRequest::new(RecoveryTimeStamp::new(stamp)));
                upf.handle_datagram(at(2), peer, &heartbeat.encode().unwrap());
            }
        }
        assert!(
            !events(&mut upf)
                .iter()
                .any(|event| matches!(event, Event::PeerRestarted { .. }))
        );
        // The release of the first ends its sessions alone
        let release = Message::node(3, AssociationReleaseRequest::new(fqdn("smf1")));
        upf.handle_datagram(at(3), smf1, &release.encode().unwrap());
        let (received, _) = request(&mut upf);
        upf.respond(
            at(3),
            &received,
            AssociationReleaseResponse::new(fqdn("upf"), accepted()),
        )
        .unwrap();
        assert!(upf.session(seids[0]).is_none());
        assert!(upf.session(seids[1]).is_some());
        assert!(upf.association(smf2).is_some());
        assert_eq!(upf.end_sessions_of(smf2), [seids[1]]);
    }
}

/// `NodeConfig::capacity`: the Recovery Time Stamps that a flood of hosts without an
/// association pushes out are not those of the associated peers: the restart of one is
/// told after a flood, while its association lasts, and that of an adopted session's peer,
/// whose association another entity holds, is not kept through one.
#[test]
fn the_stamps_that_a_flood_spares_follow_the_associations() {
    let (mut smf, _) = associated_as(
        NodeConfig {
            capacity: 2,
            ..config(SMF, Function::Cp)
        },
        at(0),
    );
    smf.adopt_session(0x55, OTHER, 0x66).unwrap();
    let beat = |smf: &mut Node, from: SocketAddr, stamp: u32| {
        let request = Message::node(7, HeartbeatRequest::new(RecoveryTimeStamp::new(stamp)));
        smf.handle_datagram(at(1), from, &request.encode().unwrap());
        sent(smf);
        events(smf)
            .iter()
            .any(|event| matches!(event, Event::PeerRestarted { peer, .. } if *peer == from))
    };
    let mut hosts = (10..).map(|host| Ipv4Addr::new(10, 0, 1, host).into_socket(8805));
    let mut flood = |smf: &mut Node| {
        for host in hosts.by_ref().take(4) {
            beat(smf, host, 1000);
        }
    };
    assert!(!beat(&mut smf, OTHER, 1000));
    flood(&mut smf);
    assert!(beat(&mut smf, UPF, 2000));
    assert!(!beat(&mut smf, OTHER, 2000));
    assert!(smf.end_association(UPF));
    flood(&mut smf);
    assert!(!beat(&mut smf, UPF, 3000));
}

/// §6.2.6.2.2: an association that a setup from another address replaces leaves the old
/// address, which has nothing else of the node, without heartbeats: the next is due to
/// the new address.
#[test]
fn a_replaced_association_stops_the_heartbeats_of_its_old_address() {
    let mut smf = Node::new(NodeConfig {
        heartbeat: Some(Duration::from_secs(60)),
        ..config(SMF, Function::Cp)
    });
    let setup = |sequence: u32| {
        let request =
            AssociationSetupRequest::new(fqdn("upf.example"), RecoveryTimeStamp::new(1000));
        Message::node(sequence, request).encode().unwrap()
    };
    let elsewhere = Ipv4Addr::new(10, 0, 0, 7).into_socket(8805);
    for (now, from) in [(0, UPF), (10, elsewhere)] {
        smf.handle_datagram(at(now), from, &setup(now as u32 + 1));
        let (received, _) = request(&mut smf);
        let answer =
            AssociationSetupResponse::new(node_id(SMF), accepted(), RecoveryTimeStamp::new(1000));
        smf.respond(at(now), &received, answer).unwrap();
        sent(&mut smf);
        events(&mut smf);
    }
    assert_eq!(smf.poll_timeout(), Some(at(70)));
    assert!(smf.association(UPF).is_none(), "the old address has none");
    assert!(smf.association(elsewhere).is_some());
    // An SMF that sets its association up again with the UPF on another port: the
    // heartbeats go there alone
    let mut smf = Node::new(NodeConfig {
        heartbeat: Some(Duration::from_secs(60)),
        ..config(SMF, Function::Cp)
    });
    let mut upf = node(UPF, Function::Up);
    set_up(&mut smf, &mut upf, at(0), cp_features(), up_features());
    let other_port = SocketAddr::new(UPF.ip(), 9000);
    let setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000));
    let message = Message::node(0, setup);
    smf.request(at(10), other_port, message).unwrap();
    pass(&mut smf, &mut upf, other_port, at(10));
    let (received, _) = request(&mut upf);
    let answer = setup_answer();
    let response = Message::node(received.sequence, answer);
    smf.handle_datagram(at(10), other_port, &response.encode().unwrap());
    events(&mut smf);
    smf.handle_timeout(at(70));
    let beats: Vec<SocketAddr> = sent(&mut smf).iter().map(|transmit| transmit.to).collect();
    assert_eq!(beats, [other_port]);
}

/// The Recovery Time Stamps of hosts without an association go, the oldest first, only
/// once the node holds `capacity` of them: before, the restart of each is told.
#[test]
fn the_stamps_of_hosts_go_only_once_the_node_is_full() {
    let mut upf = Node::new(NodeConfig {
        capacity: 3,
        ..config(UPF, Function::Up)
    });
    let heartbeat = |stamp| {
        Message::node(1, HeartbeatRequest::new(RecoveryTimeStamp::new(stamp)))
            .encode()
            .unwrap()
    };
    let hosts = [3, 4, 5, 6].map(|last| Ipv4Addr::new(10, 0, 0, last).into_socket(8805));
    let restarted = |upf: &mut Node, host| {
        events(upf).contains(&Event::PeerRestarted {
            peer: host,
            recovery_time_stamp: 2000,
        })
    };
    for host in &hosts[..3] {
        upf.handle_datagram(at(0), *host, &heartbeat(1000));
    }
    events(&mut upf);
    upf.handle_datagram(at(1), hosts[0], &heartbeat(2000));
    assert!(restarted(&mut upf, hosts[0]), "the first, of three stamps");
    // A fourth host takes the place of the oldest, now the second
    upf.handle_datagram(at(2), hosts[3], &heartbeat(1000));
    upf.handle_datagram(at(3), hosts[1], &heartbeat(2000));
    assert!(!restarted(&mut upf, hosts[1]), "the second, forgotten");
    upf.handle_datagram(at(4), hosts[3], &heartbeat(2000));
    assert!(restarted(&mut upf, hosts[3]), "the fourth, kept");
}
