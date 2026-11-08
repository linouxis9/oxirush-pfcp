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

//! Load control and overload control (§6.2.3, §6.2.4): the information that a node keeps
//! of its peers, and the throttling of its requests by message priority.

use super::*;

#[test]
fn load_control_kept_by_sequence() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    modified(&mut smf, &mut upf, cp_seid, at(1), with_load(5, 40));
    assert_eq!(
        smf.load_control(UPF),
        Some(LoadControl {
            sequence: 5,
            metric: 40
        })
    );
    // An older one, out of order, changes nothing; a newer one replaces it
    modified(&mut smf, &mut upf, cp_seid, at(2), with_load(4, 90));
    assert_eq!(smf.load_control(UPF).map(|load| load.metric), Some(40));
    modified(&mut smf, &mut upf, cp_seid, at(3), with_load(6, 70));
    assert_eq!(
        smf.load_control(UPF),
        Some(LoadControl {
            sequence: 6,
            metric: 70
        })
    );
    assert_eq!(violations(&mut smf), [], "a new number for a new metric");
}

#[test]
fn load_control_per_node_id() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    modified(&mut smf, &mut upf, cp_seid, at(1), with_load(1, 25));
    let association = smf.association(UPF).unwrap();
    assert_eq!(association.node_id, node_id(UPF));
    assert_eq!(smf.load_control(UPF).map(|load| load.metric), Some(25));
    assert_eq!(smf.load_control(OTHER), None);
}

#[test]
fn load_control_reset_on_peer_restart() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    modified(&mut smf, &mut upf, cp_seid, at(1), with_load(900, 30));
    // The UPF restarts: its heartbeat says another Recovery Time Stamp
    let restarted = Message::node(9, HeartbeatRequest::new(RecoveryTimeStamp::new(3000)));
    smf.handle_datagram(at(2), UPF, &restarted.encode().unwrap());
    assert!(events(&mut smf).contains(&Event::PeerRestarted {
        peer: UPF,
        recovery_time_stamp: 3000
    }));
    assert_eq!(smf.load_control(UPF), None);
    modified(&mut smf, &mut upf, cp_seid, at(3), with_load(1, 60));
    assert_eq!(
        smf.load_control(UPF),
        Some(LoadControl {
            sequence: 1,
            metric: 60
        })
    );
}

#[test]
fn load_control_sequence_violation() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    modified(&mut smf, &mut upf, cp_seid, at(1), with_load(5, 40));
    events(&mut smf);
    modified(&mut smf, &mut upf, cp_seid, at(2), with_load(5, 41));
    assert_eq!(
        violations(&mut smf),
        [ViolationKind::LoadControlSequence],
        "the same number, other values"
    );
    modified(&mut smf, &mut upf, cp_seid, at(3), with_load(6, 40));
    assert_eq!(
        violations(&mut smf),
        [ViolationKind::LoadControlSequence],
        "a new number, the same values"
    );
}

#[test]
fn load_control_from_any_message() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
    // In a Session Report Request of the UPF
    let load = LoadControlInformation::new(SequenceNumber::new(3), Metric::new(Percent(55)));
    let report =
        SessionReportRequest::new(ReportType::default()).with_load_control_information(load);
    upf.session_request(at(1), up_seid, report).unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    let (received, _) = request(&mut smf);
    assert_eq!(received.seid, Some(cp_seid));
    assert_eq!(smf.load_control(UPF).map(|load| load.metric), Some(55));
}

#[test]
fn overload_control_kept_by_sequence() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    modified(
        &mut smf,
        &mut upf,
        cp_seid,
        at(1),
        with_overload(7, 20, 10, false),
    );
    modified(
        &mut smf,
        &mut upf,
        cp_seid,
        at(2),
        with_overload(6, 90, 10, false),
    );
    assert_eq!(
        smf.overload_control(UPF).map(|overload| overload.metric),
        Some(20)
    );
    modified(
        &mut smf,
        &mut upf,
        cp_seid,
        at(3),
        with_overload(8, 50, 10, false),
    );
    assert_eq!(
        smf.overload_control(UPF)
            .map(|overload| (overload.sequence, overload.metric)),
        Some((8, 50))
    );
}

#[test]
fn overload_control_reset_on_peer_restart() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    modified(
        &mut smf,
        &mut upf,
        cp_seid,
        at(1),
        with_overload(500, 20, 10, false),
    );
    let restarted = Message::node(9, HeartbeatRequest::new(RecoveryTimeStamp::new(3000)));
    smf.handle_datagram(at(2), UPF, &restarted.encode().unwrap());
    assert_eq!(smf.overload_control(UPF), None);
    modified(
        &mut smf,
        &mut upf,
        cp_seid,
        at(3),
        with_overload(1, 30, 10, false),
    );
    assert_eq!(
        smf.overload_control(UPF).map(|overload| overload.sequence),
        Some(1)
    );
}

#[test]
fn overload_control_sequence_violation() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    modified(
        &mut smf,
        &mut upf,
        cp_seid,
        at(1),
        with_overload(5, 20, 10, false),
    );
    events(&mut smf);
    modified(
        &mut smf,
        &mut upf,
        cp_seid,
        at(2),
        with_overload(5, 30, 10, false),
    );
    assert_eq!(
        violations(&mut smf),
        [ViolationKind::OverloadControlSequence]
    );
}

/// §6.2.4.3.2.1 NOTE 1: a new number with the same information extends its period of
/// validity, and is no violation.
#[test]
fn overload_control_extended_by_a_new_number() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    modified(
        &mut smf,
        &mut upf,
        cp_seid,
        at(1),
        with_overload(5, 30, 5, false),
    );
    modified(
        &mut smf,
        &mut upf,
        cp_seid,
        at(2),
        with_overload(6, 30, 5, false),
    );
    assert!(violations(&mut smf).is_empty());
    let overload = smf.overload_control(UPF).unwrap();
    assert_eq!((overload.sequence, overload.until), (6, Some(at(2 + 300))));
}

#[test]
fn overload_control_scope() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    // By default, of the address of the peer
    modified(
        &mut smf,
        &mut upf,
        cp_seid,
        at(1),
        with_overload(1, 20, 10, false),
    );
    assert_eq!(
        smf.overload_control(UPF).map(|overload| overload.metric),
        Some(20)
    );
    // Of the Node ID, with AOCI: it holds for the association, apart from the address
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    modified(
        &mut smf,
        &mut upf,
        cp_seid,
        at(1),
        with_overload(1, 35, 10, true),
    );
    assert_eq!(
        smf.overload_control(UPF).map(|overload| overload.metric),
        Some(35)
    );
}

#[test]
fn overload_control_validity_expires() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    modified(
        &mut smf,
        &mut upf,
        cp_seid,
        at(10),
        with_overload(1, 20, 1, false),
    );
    assert_eq!(
        smf.overload_control(UPF)
            .and_then(|overload| overload.until),
        Some(at(70))
    );
    // A new set restarts the period
    modified(
        &mut smf,
        &mut upf,
        cp_seid,
        at(40),
        with_overload(2, 25, 1, false),
    );
    events(&mut smf);
    smf.handle_timeout(at(70));
    assert!(smf.overload_control(UPF).is_some());
    smf.handle_timeout(at(100));
    assert_eq!(smf.overload_control(UPF), None);
    assert!(events(&mut smf).contains(&Event::OverloadEnded { peer: UPF }));
}

#[test]
fn overload_control_from_any_message() {
    let (mut smf, mut upf) = associated(at(0));
    let (_, up_seid) = established(&mut smf, &mut upf, at(0));
    let timer = Timer {
        timer_unit: TimerUnit::OneMinute,
        timer_value: 5,
        ..Default::default()
    };
    let overload =
        OverloadControlInformation::new(SequenceNumber::new(4), Metric::new(Percent(15)), timer);
    let report = SessionReportRequest::new(ReportType::default())
        .with_overload_control_information(overload);
    upf.session_request(at(1), up_seid, report).unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    assert_eq!(
        smf.overload_control(UPF).map(|overload| overload.metric),
        Some(15)
    );
}

// ── §6.2.4.4, §6.2.4.5: throttling and priority ──────────────────────────────

/// An SMF of `smf` with a session on a UPF that asks for a reduction of `metric`%.
fn overloaded(smf: NodeConfig, metric: u8) -> (Node, u64) {
    let (mut smf, mut upf) = associated_as(smf, at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    modified(
        &mut smf,
        &mut upf,
        cp_seid,
        at(1),
        with_overload(1, metric, 30, false),
    );
    (smf, cp_seid)
}

/// §6.2.4.3.1: the overload of a session is of the address of its UP F-SEID, which the
/// requests of the session go to, whatever address of the UP function sent it.
#[test]
fn overload_of_the_address_of_the_up_f_seid() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, up_seid) = established_on(&mut smf, &mut upf, at(0), Ipv4Addr::new(10, 0, 0, 22));
    let timer = Timer {
        timer_unit: TimerUnit::OneMinute,
        timer_value: 30,
        ..Default::default()
    };
    let report = SessionReportRequest::new(ReportType {
        upir: true,
        ..Default::default()
    })
    .with_overload_control_information(OverloadControlInformation::new(
        SequenceNumber::new(1),
        Metric::new(Percent(100)),
        timer,
    ));
    upf.session_request(at(1), up_seid, report).unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    let (received, _) = request(&mut smf);
    smf.respond(at(1), &received, SessionReportResponse::new(accepted()))
        .unwrap();
    let f_seid_address = Ipv4Addr::new(10, 0, 0, 22).into_socket(8805);
    assert!(smf.overload_control(f_seid_address).is_some());
    assert_eq!(
        smf.session_request(at(2), cp_seid, SessionModificationRequest::default()),
        Err(NodeError::Throttled)
    );
    // The establishment's own response: of the address of the UP F-SEID that it gives
    let (mut smf, mut upf) = associated(at(0));
    let cp_seid = smf.new_session();
    let f_seid = FSeid {
        v4: true,
        seid: Some(cp_seid),
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
    let establishment = SessionEstablishmentRequest::new_n4(node_id(SMF), f_seid, pdr, far);
    let message = Message::session(0, 0, establishment);
    smf.request(at(1), UPF, message).unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (received, _) = request(&mut upf);
    let up_f_seid = FSeid {
        v4: true,
        seid: Some(upf.new_session()),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 22)),
        ..Default::default()
    };
    let overload = *with_overload(1, 100, 30, false)
        .overload_control_information
        .unwrap();
    let response = SessionEstablishmentResponse::new(node_id(UPF), accepted())
        .with_up_f_seid(up_f_seid)
        .with_overload_control_information(overload);
    upf.respond(at(1), &received, response).unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(smf.overload_control(f_seid_address).is_some());
    assert!(
        smf.overload_control(UPF).is_none(),
        "not of the association's address"
    );
}

/// The load and overload of a peer without an association are not kept: a host that
/// sends a session request of a SEID that it guessed throttles nothing, and leaves
/// nothing behind.
#[test]
fn controls_of_a_peer_without_an_association_are_not_kept() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    let timer = Timer {
        timer_unit: TimerUnit::OneMinute,
        timer_value: 30,
        ..Default::default()
    };
    for i in 0..100u8 {
        let from = Ipv4Addr::new(10, 7, 0, i).into_socket(8805);
        let report = SessionReportRequest::new(ReportType {
            upir: true,
            ..Default::default()
        })
        .with_load_control_information(LoadControlInformation::new(
            SequenceNumber::new(1),
            Metric::new(Percent(10)),
        ))
        .with_overload_control_information(OverloadControlInformation::new(
            SequenceNumber::new(1),
            Metric::new(Percent(100)),
            timer.clone(),
        ));
        let message = Message::session(cp_seid, u32::from(i) + 1, report);
        smf.handle_datagram(at(1), from, &message.encode().unwrap());
        assert!(smf.load_control(from).is_none() && smf.overload_control(from).is_none());
    }
    assert!(smf.overload_control(UPF).is_none());
    smf.session_request(at(2), cp_seid, SessionModificationRequest::default())
        .unwrap();
}

/// What the node keeps of the load and overload of its peers is bounded by their sessions
/// and associations: the overload of the address of a UP F-SEID goes with the last session
/// of that address, even of an infinite Period of Validity, and the load and overload of a
/// Node ID with its association.
#[test]
fn controls_go_with_the_sessions_and_the_association_that_set_them() {
    let (mut smf, mut upf) = associated(at(0));
    let infinite = Timer {
        timer_unit: TimerUnit::Infinite,
        timer_value: 1,
        ..Default::default()
    };
    let overload = |aoci| {
        let overload = OverloadControlInformation::new(
            SequenceNumber::new(1),
            Metric::new(Percent(50)),
            infinite.clone(),
        );
        match aoci {
            false => overload,
            true => overload.with_overload_control_information_flags(OciFlags {
                aoci: true,
                ..Default::default()
            }),
        }
    };
    let addresses = [21, 22, 23].map(|last| Ipv4Addr::new(10, 0, 0, last));
    let mut sessions = Vec::new();
    for address in addresses {
        let (cp_seid, up_seid) = established_on(&mut smf, &mut upf, at(0), address);
        let report = SessionReportRequest::new(ReportType {
            upir: true,
            ..Default::default()
        })
        .with_overload_control_information(overload(false));
        upf.session_request(at(1), up_seid, report).unwrap();
        pass(&mut upf, &mut smf, SMF, at(1));
        let (received, _) = request(&mut smf);
        smf.respond(at(1), &received, SessionReportResponse::new(accepted()))
            .unwrap();
        sessions.push(cp_seid);
    }
    let kept = |smf: &Node| {
        addresses
            .iter()
            .filter(|address| smf.overload_control(address.into_socket(8805)).is_some())
            .count()
    };
    assert_eq!(kept(&smf), 3);
    smf.end_session(sessions[0]);
    assert_eq!(kept(&smf), 2);
    smf.end_sessions_of(addresses[1].into_socket(8805));
    smf.handle_timeout(at(2));
    assert_eq!(kept(&smf), 1);
    // The load and overload of the Node ID of the association
    let (cp_seid, _) = established(&mut smf, &mut upf, at(2));
    let response = with_load(1, 40).with_overload_control_information(overload(true));
    modified(&mut smf, &mut upf, cp_seid, at(3), response);
    assert!(smf.load_control(UPF).is_some() && smf.overload_control(UPF).is_some());
    smf.end_association(UPF);
    assert_eq!(kept(&smf), 0);
    assert_eq!(
        (smf.load_control(UPF), smf.overload_control(UPF)),
        (None, None)
    );
    // A new association of the same Node ID starts without them
    set_up(&mut smf, &mut upf, at(4), cp_features(), up_features());
    assert_eq!(
        (smf.load_control(UPF), smf.overload_control(UPF)),
        (None, None)
    );
}

/// §8.2.34: a Metric above 100 is read as 0: an Overload Reduction Metric of 200 throttles
/// nothing, and a Load Metric of 250 is a load of 0.
#[test]
fn a_metric_above_100_is_read_as_0() {
    let (mut smf, cp_seid) = overloaded(config(SMF, Function::Cp), 200);
    assert_eq!(
        smf.overload_control(UPF).map(|overload| overload.metric),
        Some(0)
    );
    for _ in 0..100 {
        smf.session_request(at(2), cp_seid, SessionModificationRequest::default())
            .unwrap();
    }
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    modified(&mut smf, &mut upf, cp_seid, at(1), with_load(1, 250));
    assert_eq!(smf.load_control(UPF).map(|load| load.metric), Some(0));
}

#[test]
fn throttling_loss_algorithm() {
    let (mut smf, cp_seid) = overloaded(config(SMF, Function::Cp), 30);
    let throttled = (0..100)
        .filter(|_| {
            smf.session_request(at(2), cp_seid, SessionModificationRequest::default())
                == Err(NodeError::Throttled)
        })
        .count();
    assert_eq!(throttled, 30, "30% of the requests");
    // A new number of the same overload keeps what the algorithm owes: 40 + 40, then
    // past 100 at the third request
    let (mut smf, cp_seid) = overloaded(config(SMF, Function::Cp), 40);
    let modify =
        |smf: &mut Node| smf.session_request(at(2), cp_seid, SessionModificationRequest::default());
    assert!(modify(&mut smf).is_ok());
    let overload = *with_overload(2, 40, 30, false)
        .overload_control_information
        .unwrap();
    let report = Message::session(
        cp_seid,
        70,
        SessionReportRequest::new(ReportType {
            upir: true,
            ..Default::default()
        })
        .with_overload_control_information(overload),
    );
    smf.handle_datagram(at(2), UPF, &report.encode().unwrap());
    assert_eq!(
        smf.overload_control(UPF).map(|overload| overload.sequence),
        Some(2)
    );
    assert!(modify(&mut smf).is_ok());
    assert_eq!(modify(&mut smf), Err(NodeError::Throttled));
}

#[test]
fn throttling_never_responses() {
    let (mut smf, cp_seid) = overloaded(config(SMF, Function::Cp), 100);
    assert_eq!(
        smf.session_request(at(2), cp_seid, SessionModificationRequest::default()),
        Err(NodeError::Throttled)
    );
    // Node related requests, and responses, go
    assert!(smf.request(at(2), UPF, heartbeat()).is_ok());
    let report = Message::session(
        cp_seid,
        31,
        SessionReportRequest::new(ReportType::default()),
    );
    smf.handle_datagram(at(3), UPF, &report.encode().unwrap());
    let (received, _) = request(&mut smf);
    sent(&mut smf);
    smf.respond(at(3), &received, SessionReportResponse::new(accepted()))
        .unwrap();
    assert_eq!(sent(&mut smf).len(), 1);
}

#[test]
fn throttling_spares_priority() {
    // An SMF that spares the priorities 0 to 2, and a UPF that asks for 50%
    let (mut smf, _) = overloaded(
        NodeConfig {
            priority_up_to: Some(2),
            ..config(SMF, Function::Cp)
        },
        50,
    );
    let send = |smf: &mut Node, priority: u8| {
        let message = Message {
            header: Header {
                priority: Some(priority),
                ..Header::session(1, 0)
            },
            body: SessionModificationRequest::default().into(),
        };
        smf.request(at(2), UPF, message)
    };
    // Mixed with as many others, no priority request is dropped
    let mut dropped = [0, 0];
    for _ in 0..50 {
        for (rank, priority) in [1, 9].into_iter().enumerate() {
            if send(&mut smf, priority) == Err(NodeError::Throttled) {
                dropped[rank] += 1;
            }
        }
    }
    assert_eq!(dropped, [0, 50]);
    // Alone, they are dropped too, once the reduction cannot be met otherwise
    let alone = (0..100)
        .filter(|_| send(&mut smf, 1) == Err(NodeError::Throttled))
        .count();
    assert!(alone > 0 && alone <= 50, "{alone}");
}

#[test]
fn message_priority_default() {
    let (_, mut upf) = associated(at(0));
    let without = Message::node(100, AssociationUpdateRequest::new(node_id(SMF)));
    upf.handle_datagram(at(1), SMF, &without.encode().unwrap());
    let (received, _) = request(&mut upf);
    assert_eq!(received.priority, None);
    let answer = AssociationUpdateResponse::new(node_id(UPF), accepted());
    upf.respond(at(1), &received, answer).unwrap();
    let answer = sent(&mut upf).remove(0);
    assert_eq!(
        (answer.priority, decoded(&answer).header.priority),
        (8, None)
    );
    // The highest priority goes out first
    upf.send_raw(OTHER, 9, vec![9]);
    upf.send_raw(OTHER, 0, vec![0]);
    assert_eq!(
        sent(&mut upf)
            .iter()
            .map(|transmit| transmit.octets[0])
            .collect::<Vec<_>>(),
        [0, 9]
    );
}

#[test]
fn response_copies_priority() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    let message = Message {
        header: Header {
            priority: Some(2),
            ..Header::session(0, 0)
        },
        body: SessionModificationRequest::default().into(),
    };
    let peer_seid = smf.session(cp_seid).unwrap().peer_seid.unwrap();
    smf.request(
        at(1),
        UPF,
        Message {
            header: Header {
                seid: Some(peer_seid),
                ..message.header
            },
            ..message
        },
    )
    .unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (received, _) = request(&mut upf);
    assert_eq!(received.priority, Some(2));
    upf.respond(
        at(1),
        &received,
        SessionModificationResponse::new(accepted()),
    )
    .unwrap();
    let answer = sent(&mut upf).remove(0);
    assert_eq!(answer.priority, 2);
    assert_eq!(decoded(&answer).header.priority, Some(2));
}

/// §6.2.4.3.2.1: a new Overload Control Sequence Number for a new period of validity is
/// no violation; the violations of control information carry their message.
#[test]
fn overload_control_of_a_new_period() {
    let (mut smf, mut upf) = associated_as(
        NodeConfig {
            throttling: false,
            ..config(SMF, Function::Cp)
        },
        at(0),
    );
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    modified(
        &mut smf,
        &mut upf,
        cp_seid,
        at(1),
        with_overload(1, 50, 1, false),
    );
    modified(
        &mut smf,
        &mut upf,
        cp_seid,
        at(2),
        with_overload(2, 50, 10, false),
    );
    assert!(violations(&mut smf).is_empty());
    modified(
        &mut smf,
        &mut upf,
        cp_seid,
        at(3),
        with_overload(2, 60, 10, false),
    );
    let got = events(&mut smf);
    assert!(got.iter().any(|event| matches!(event, Event::Violation { kind: ViolationKind::OverloadControlSequence, octets, .. } if !octets.is_empty())), "{got:?}");
}

/// §6.2.3.3.1, §6.2.4.3.1: the load and overload of a session of an association, which
/// the UP function sends from the address of its UP F-SEID, are of the Node ID of the
/// association, not of that address: the peer of an adopted session alone has them by
/// its address.
#[test]
fn the_controls_of_a_session_from_its_f_seid_address_are_of_its_association() {
    let (mut smf, mut upf) = associated(at(0));
    let f_seid_address = Ipv4Addr::new(10, 0, 0, 22);
    let (_, up_seid) = established_on(&mut smf, &mut upf, at(0), f_seid_address);
    let timer = Timer::new(TimerUnit::OneMinute, 30);
    let overload =
        OverloadControlInformation::new(SequenceNumber::new(1), Metric::new(Percent(50)), timer)
            .with_overload_control_information_flags(OciFlags {
                aoci: true,
                ..Default::default()
            });
    let report = SessionReportRequest::new(ReportType {
        upir: true,
        ..Default::default()
    })
    .with_load_control_information(LoadControlInformation::new(
        SequenceNumber::new(1),
        Metric::new(Percent(40)),
    ))
    .with_overload_control_information(overload);
    upf.session_request(at(1), up_seid, report).unwrap();
    let from = f_seid_address.into_socket(8805);
    for transmit in sent(&mut upf) {
        smf.handle_datagram(at(1), from, &transmit.octets);
    }
    let (received, _) = request(&mut smf);
    smf.respond(at(1), &received, SessionReportResponse::new(accepted()))
        .unwrap();
    assert_eq!(smf.load_control(UPF).map(|load| load.metric), Some(40));
    assert_eq!(
        smf.overload_control(UPF).map(|overload| overload.metric),
        Some(50)
    );
    let scopes: Vec<ControlScope> = smf.loads().map(|(scope, _)| scope).collect();
    assert_eq!(scopes, [ControlScope::Node(node_id(UPF))]);
}
