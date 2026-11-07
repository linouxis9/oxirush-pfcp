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

//! The node layer against the requirements of clause 6 that `tests/spec/requirements.tsv`
//! gives it: each test is named there. An SMF and a UPF exchange their datagrams by hand.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use oxirush_pfcp::node::*;
use oxirush_pfcp::*;

const SMF: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8805);
const UPF: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8805);
const OTHER: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 8805);
const T1: Duration = Duration::from_secs(3);

fn node_id(address: SocketAddr) -> NodeId {
    match address.ip() {
        std::net::IpAddr::V4(ip) => NodeId::Ipv4(ip),
        std::net::IpAddr::V6(ip) => NodeId::Ipv6(ip),
    }
}

fn config(address: SocketAddr, function: Function) -> NodeConfig {
    NodeConfig {
        heartbeat: None,
        ..NodeConfig::new(node_id(address), function, 1000)
    }
}

fn node(address: SocketAddr, function: Function) -> Node {
    Node::new(config(address, function))
}

fn at(seconds: u64) -> Duration {
    Duration::from_secs(seconds)
}

/// What a node sends.
fn sent(node: &mut Node) -> Vec<Transmit> {
    std::iter::from_fn(|| node.poll_transmit()).collect()
}

fn events(node: &mut Node) -> Vec<Event> {
    std::iter::from_fn(|| node.poll_event()).collect()
}

/// Give `to` what `from` sends to it.
fn pass(from: &mut Node, to: &mut Node, address: SocketAddr, now: Duration) {
    let from_address = match from.config().function {
        Function::Cp => SMF,
        Function::Up => UPF,
    };
    for transmit in sent(from) {
        if transmit.to == address {
            to.handle_datagram(now, from_address, &transmit.octets);
        }
    }
}

/// The one request event of a node.
fn request(node: &mut Node) -> (Inbound, Message) {
    let mut requests = events(node).into_iter().filter_map(|event| match event {
        Event::Request { request, message } => Some((request, message)),
        _ => None,
    });
    let first = requests.next().expect("a request");
    assert!(requests.next().is_none());
    first
}

fn violations(node: &mut Node) -> Vec<ViolationKind> {
    events(node)
        .into_iter()
        .filter_map(|event| match event {
            Event::Violation { kind, .. } => Some(kind),
            _ => None,
        })
        .collect()
}

fn accepted() -> Cause {
    Cause::new(CauseValue::RequestAccepted)
}

/// An SMF associated with a UPF.
fn associated(now: Duration) -> (Node, Node) {
    associated_as(config(SMF, Function::Cp), now)
}

/// An SMF of `smf` associated with a UPF.
fn associated_as(smf: NodeConfig, now: Duration) -> (Node, Node) {
    let (mut smf, mut upf) = (Node::new(smf), node(UPF, Function::Up));
    let setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000));
    smf.request(
        now,
        UPF,
        Message {
            header: Header::node(0),
            body: setup.into(),
        },
    )
    .unwrap();
    pass(&mut smf, &mut upf, UPF, now);
    let (inbound, _) = request(&mut upf);
    upf.respond(
        now,
        &inbound,
        AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(1000)),
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, now);
    events(&mut smf);
    (smf, upf)
}

/// A session between them: the SMF's SEID and the UPF's.
fn established(smf: &mut Node, upf: &mut Node, now: Duration) -> (u64, u64) {
    established_on(smf, upf, now, Ipv4Addr::new(10, 0, 0, 2))
}

/// A session between them, of a UP F-SEID of `address`.
fn established_on(smf: &mut Node, upf: &mut Node, now: Duration, address: Ipv4Addr) -> (u64, u64) {
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
    smf.request(
        now,
        UPF,
        Message {
            header: Header::session(0, 0),
            body: establishment.into(),
        },
    )
    .unwrap();
    pass(smf, upf, UPF, now);
    let (inbound, _) = request(upf);
    let up_seid = upf.new_session();
    let up_f_seid = FSeid {
        v4: true,
        seid: Some(up_seid),
        ipv4: Some(address),
        ..Default::default()
    };
    let response =
        SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(up_f_seid);
    upf.respond(now, &inbound, response).unwrap();
    pass(upf, smf, SMF, now);
    events(smf);
    (cp_seid, up_seid)
}

fn decoded(transmit: &Transmit) -> Message {
    Message::decode(&transmit.octets).unwrap()
}

fn heartbeat() -> Message {
    Message {
        header: Header::node(0),
        body: HeartbeatRequest::new(RecoveryTimeStamp::new(1000)).into(),
    }
}

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
    let response = Message {
        header: to_upf.header,
        body: HeartbeatResponse::new(RecoveryTimeStamp::new(1)).into(),
    };
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
    let response = Message {
        header: decoded(&original).header,
        body: HeartbeatResponse::new(RecoveryTimeStamp::new(1)).into(),
    };
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
        [Event::Timeout {
            request: id,
            to: UPF
        }]
    );
}

#[test]
fn retransmission_identical() {
    let mut smf = node(SMF, Function::Cp);
    let message = Message {
        header: Header {
            priority: Some(3),
            ..Header::node(0)
        },
        body: HeartbeatRequest::new(RecoveryTimeStamp::new(1000)).into(),
    };
    smf.request(at(0), UPF, message).unwrap();
    let original = sent(&mut smf).remove(0);
    smf.handle_timeout(T1);
    let again = sent(&mut smf).remove(0);
    assert_eq!(again, original, "the same octets, header and peer");
}

#[test]
fn response_copies_sequence() {
    let (_, mut upf) = associated(at(0));
    let update = AssociationUpdateRequest::new(node_id(SMF));
    let octets = Message {
        header: Header::node(0x1234),
        body: update.into(),
    }
    .encode()
    .unwrap();
    upf.handle_datagram(at(1), SMF, &octets);
    let (inbound, _) = request(&mut upf);
    upf.respond(
        at(1),
        &inbound,
        AssociationUpdateResponse::new(node_id(UPF), accepted()),
    )
    .unwrap();
    assert_eq!(decoded(&sent(&mut upf)[0]).header.sequence, 0x1234);
}

#[test]
fn retransmitted_request_answered_from_cache() {
    let (_, mut upf) = associated(at(0));
    let update = AssociationUpdateRequest::new(node_id(SMF));
    let octets = Message {
        header: Header::node(77),
        body: update.into(),
    }
    .encode()
    .unwrap();
    upf.handle_datagram(at(1), SMF, &octets);
    let (inbound, _) = request(&mut upf);
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
    let changed = Message {
        header: Header::node(77),
        body: AssociationUpdateRequest::new(node_id(SMF))
            .with_graceful_release_period(GracefulReleasePeriod::default())
            .into(),
    };
    upf.handle_datagram(at(2), SMF, &changed.encode().unwrap());
    assert_eq!(violations(&mut upf), [ViolationKind::ChangedRetransmission]);
    upf.respond(
        at(2),
        &inbound,
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
    let response = Message {
        header: Header::node(4242),
        body: HeartbeatResponse::new(RecoveryTimeStamp::new(1)).into(),
    };
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

// ── §6.2.2: heartbeat ───────────────────────────────────────────────────────

#[test]
fn heartbeat_answered_from_unknown_peer() {
    let mut upf = node(UPF, Function::Up);
    upf.handle_datagram(
        at(0),
        OTHER,
        &Message {
            header: Header::node(5),
            ..heartbeat()
        }
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

// ── §6.2.3, §6.2.4: load and overload control ───────────────────────────────

fn with_load(sequence: u32, metric: u8) -> SessionModificationResponse {
    SessionModificationResponse::new(accepted()).with_load_control_information(
        LoadControlInformation::new(SequenceNumber::new(sequence), Metric::new(Percent(metric))),
    )
}

fn with_overload(
    sequence: u32,
    metric: u8,
    minutes: u8,
    of_node: bool,
) -> SessionModificationResponse {
    let timer = Timer {
        timer_unit: TimerUnit::OneMinute,
        timer_value: minutes,
        ..Default::default()
    };
    let mut overload = OverloadControlInformation::new(
        SequenceNumber::new(sequence),
        Metric::new(Percent(metric)),
        timer,
    );
    if of_node {
        overload = overload.with_overload_control_information_flags(OciFlags {
            aoci: true,
            ..Default::default()
        });
    }
    SessionModificationResponse::new(accepted()).with_overload_control_information(overload)
}

/// The UPF answers a modification of the session with `response`.
fn modified(
    smf: &mut Node,
    upf: &mut Node,
    cp_seid: u64,
    now: Duration,
    response: SessionModificationResponse,
) {
    smf.session_request(now, cp_seid, SessionModificationRequest::default())
        .unwrap();
    pass(smf, upf, UPF, now);
    let (inbound, _) = request(upf);
    upf.respond(now, &inbound, response).unwrap();
    pass(upf, smf, SMF, now);
}

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
    let restarted = Message {
        header: Header::node(9),
        body: HeartbeatRequest::new(RecoveryTimeStamp::new(3000)).into(),
    };
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
    let (inbound, _) = request(&mut smf);
    assert_eq!(inbound.seid, Some(cp_seid));
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
    let restarted = Message {
        header: Header::node(9),
        body: HeartbeatRequest::new(RecoveryTimeStamp::new(3000)).into(),
    };
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
    let (inbound, _) = request(&mut smf);
    smf.respond(at(1), &inbound, SessionReportResponse::new(accepted()))
        .unwrap();
    let f_seid_address = Ipv4Addr::new(10, 0, 0, 22).into_socket(8805);
    assert!(smf.overload_control(f_seid_address).is_some());
    assert_eq!(
        smf.session_request(at(2), cp_seid, SessionModificationRequest::default()),
        Err(NodeError::Throttled)
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
        let message = Message {
            header: Header::session(cp_seid, u32::from(i) + 1),
            body: report.into(),
        };
        smf.handle_datagram(at(1), from, &message.encode().unwrap());
        assert!(smf.load_control(from).is_none() && smf.overload_control(from).is_none());
    }
    assert!(smf.overload_control(UPF).is_none());
    smf.session_request(at(2), cp_seid, SessionModificationRequest::default())
        .unwrap();
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
    let report = Message {
        header: Header::session(cp_seid, 31),
        body: SessionReportRequest::new(ReportType::default()).into(),
    };
    smf.handle_datagram(at(3), UPF, &report.encode().unwrap());
    let (inbound, _) = request(&mut smf);
    sent(&mut smf);
    smf.respond(at(3), &inbound, SessionReportResponse::new(accepted()))
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
    let without = Message {
        header: Header::node(100),
        body: AssociationUpdateRequest::new(node_id(SMF)).into(),
    };
    upf.handle_datagram(at(1), SMF, &without.encode().unwrap());
    let (inbound, _) = request(&mut upf);
    assert_eq!((inbound.priority, inbound.prioritized), (8, false));
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
    let (inbound, _) = request(&mut upf);
    assert_eq!((inbound.priority, inbound.prioritized), (2, true));
    upf.respond(
        at(1),
        &inbound,
        SessionModificationResponse::new(accepted()),
    )
    .unwrap();
    let answer = sent(&mut upf).remove(0);
    assert_eq!(answer.priority, 2);
    assert_eq!(decoded(&answer).header.priority, Some(2));
}

// ── §6.2.6 to §6.2.8: associations ──────────────────────────────────────────

#[test]
fn association_setup_by_cp() {
    let (mut smf, mut upf) = (node(SMF, Function::Cp), node(UPF, Function::Up));
    let setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000));
    smf.request(
        at(0),
        UPF,
        Message {
            header: Header::node(0),
            body: setup.into(),
        },
    )
    .unwrap();
    pass(&mut smf, &mut upf, UPF, at(0));
    let (inbound, _) = request(&mut upf);
    assert_eq!(inbound.node_id, Some(node_id(SMF)));
    assert!(upf.association(SMF).is_none(), "the UPF's caller decides");
    upf.respond(
        at(0),
        &inbound,
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
    upf.request(
        at(0),
        SMF,
        Message {
            header: Header::node(0),
            body: setup.into(),
        },
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(0));
    let (inbound, _) = request(&mut smf);
    smf.respond(
        at(0),
        &inbound,
        AssociationSetupResponse::new(node_id(SMF), accepted(), RecoveryTimeStamp::new(1000)),
    )
    .unwrap();
    assert!(smf.association(UPF).is_some());
    pass(&mut smf, &mut upf, UPF, at(0));
    assert!(upf.association(SMF).is_some());
    // A rejection makes none
    let mut other = node(OTHER, Function::Up);
    let setup = AssociationSetupRequest::new(node_id(OTHER), RecoveryTimeStamp::new(1));
    other
        .request(
            at(0),
            SMF,
            Message {
                header: Header::node(0),
                body: setup.into(),
            },
        )
        .unwrap();
    for transmit in sent(&mut other) {
        smf.handle_datagram(at(0), OTHER, &transmit.octets);
    }
    let (inbound, _) = request(&mut smf);
    let rejection = AssociationSetupResponse::new(
        node_id(SMF),
        Cause::new(CauseValue::RequestRejected),
        RecoveryTimeStamp::new(1000),
    );
    smf.respond(at(0), &inbound, rejection).unwrap();
    assert!(smf.association(OTHER).is_none());
}

#[test]
fn association_setup_again() {
    let (mut smf, mut upf) = associated(at(0));
    let setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000));
    smf.request(
        at(5),
        UPF,
        Message {
            header: Header::node(0),
            body: setup.into(),
        },
    )
    .unwrap();
    pass(&mut smf, &mut upf, UPF, at(5));
    let (inbound, _) = request(&mut upf);
    upf.respond(
        at(5),
        &inbound,
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
    smf.request(
        at(1),
        UPF,
        Message {
            header: Header::node(0),
            body: update.into(),
        },
    )
    .unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (inbound, message) = request(&mut upf);
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
        &inbound,
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
    let update = Message {
        header: Header::node(3),
        body: AssociationUpdateRequest::new(node_id(SMF)).into(),
    };
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
    smf.request(
        at(1),
        UPF,
        Message {
            header: Header::node(0),
            body: release.into(),
        },
    )
    .unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (inbound, _) = request(&mut upf);
    upf.respond(
        at(1),
        &inbound,
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
    smf.request(
        at(1),
        UPF,
        Message {
            header: Header::node(0),
            body: release.into(),
        },
    )
    .unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (inbound, _) = request(&mut upf);
    upf.respond(
        at(1),
        &inbound,
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
        seid: Some(0x55),
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
    let establishment = Message {
        header: Header::session(0, 6),
        body: SessionEstablishmentRequest::new_n4(node_id(SMF), f_seid, pdr, far).into(),
    };
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

#[test]
fn version_not_supported() {
    let mut upf = node(UPF, Function::Up);
    let mut octets = Message {
        header: Header::node(8),
        ..heartbeat()
    }
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
        let id = sender
            .request(
                at(1),
                to,
                Message {
                    header: Header::node(0),
                    body,
                },
            )
            .unwrap();
        pass(sender, receiver, to, at(1));
        let (inbound, message) = request(receiver);
        assert_eq!(message.body.message_type(), message_type);
        receiver.respond(at(1), &inbound, answer).unwrap();
        pass(receiver, sender, back, at(1));
        let got = events(sender);
        assert!(
            matches!(&got[..], [Event::Response { request, message }] if *request == id && message.body.message_type() == message_type + 1),
            "{got:?}"
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
    let modification = Message {
        header: Header::session(0xdead, 12),
        body: SessionModificationRequest::default().into(),
    };
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
    let (inbound, _) = request(&mut upf);
    upf.respond(at(1), &inbound, SessionDeletionResponse::new(accepted()))
        .unwrap();
    assert!(upf.session(up_seid).is_none());
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(smf.session(cp_seid).is_none());
}

// ── §6.5: bundling ──────────────────────────────────────────────────────────

fn bundle(messages: &[Message]) -> Vec<u8> {
    let mut octets = Vec::new();
    for (rank, message) in messages.iter().enumerate() {
        let mut message = message.clone();
        message.header.follow_on = rank + 1 < messages.len();
        octets.extend(message.encode().unwrap());
    }
    octets
}

#[test]
fn bundled_datagram_each_message() {
    let (mut smf, mut upf) = associated(at(0));
    let (_, up_seid) = established(&mut smf, &mut upf, at(0));
    let modification = |sequence| Message {
        header: Header::session(up_seid, sequence),
        body: SessionModificationRequest::default().into(),
    };
    upf.handle_datagram(at(1), SMF, &bundle(&[modification(20), modification(21)]));
    let requests: Vec<u32> = events(&mut upf)
        .into_iter()
        .filter_map(|event| match event {
            Event::Request { request, .. } => Some(request.sequence),
            _ => None,
        })
        .collect();
    assert_eq!(requests, [20, 21]);
}

/// §7.6.2: a bundled message of another version is answered, and what follows it, whose
/// framing the node does not know, is discarded.
#[test]
fn bundled_message_of_another_version() {
    let (mut smf, mut upf) = associated(at(0));
    let (_, up_seid) = established(&mut smf, &mut upf, at(0));
    let modification = |sequence| Message {
        header: Header::session(up_seid, sequence),
        body: SessionModificationRequest::default().into(),
    };
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

#[test]
fn bundled_messages_of_one_peer() {
    let (mut smf, mut upf) = associated(at(0));
    let (_, up_seid) = established(&mut smf, &mut upf, at(0));
    let other_seid = 0x900;
    upf.adopt_session(other_seid, OTHER, 0x99).unwrap();
    let modification = |seid, sequence| Message {
        header: Header::session(seid, sequence),
        body: SessionModificationRequest::default().into(),
    };
    upf.handle_datagram(
        at(1),
        SMF,
        &bundle(&[modification(up_seid, 20), modification(other_seid, 21)]),
    );
    assert_eq!(violations(&mut upf), [ViolationKind::BundledPeers]);
}

/// §6.5: node related messages are not bundled, and a peer without an association has
/// not agreed on bundling: what they bundle is discarded, and answered not at all.
#[test]
fn bundled_node_message_reported() {
    let heartbeats = bundle(&[
        Message {
            header: Header::node(1),
            ..heartbeat()
        },
        Message {
            header: Header::node(2),
            ..heartbeat()
        },
    ]);
    let mut lone = node(UPF, Function::Up);
    lone.handle_datagram(at(0), OTHER, &heartbeats);
    assert_eq!(
        violations(&mut lone),
        [ViolationKind::BundledWithoutAssociation]
    );
    assert!(sent(&mut lone).is_empty());
    let (_, mut upf) = associated(at(0));
    events(&mut upf);
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
    let restarted = Message {
        header: request.header,
        body: HeartbeatResponse::new(RecoveryTimeStamp::new(4000)).into(),
    };
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

// ── §7.6: messages that do not decode, of another version or of no type ──────

fn requests_of(events: &[Event]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event, Event::Request { .. }))
        .count()
}

fn kinds_of(events: &[Event]) -> Vec<ViolationKind> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Violation { kind, .. } => Some(*kind),
            _ => None,
        })
        .collect()
}

/// §7.6.3: a request in a datagram longer than its Message Length is answered "Invalid
/// Length", and is no request for the caller.
#[test]
fn a_request_of_a_false_length_is_answered_invalid_length() {
    let (mut smf, mut upf) = associated(at(0));
    let (_, up_seid) = established(&mut smf, &mut upf, at(0));
    events(&mut upf);
    let mut octets = Message {
        header: Header::node(9),
        body: AssociationUpdateRequest::new(node_id(SMF)).into(),
    }
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
    // that the node has, as a session that it does not have is answered so first
    let modification = SessionModificationRequest::default().with_cp_f_seid(FSeid {
        v4: true,
        seid: Some(1),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
        ..Default::default()
    });
    let mut octets = Message {
        header: Header::session(up_seid, 10),
        body: modification.into(),
    }
    .encode()
    .unwrap();
    octets[19] = 99;
    upf.handle_datagram(at(1), SMF, &octets);
    let Body::SessionModificationResponse(response) = decoded(&sent(&mut upf)[0]).body else {
        panic!()
    };
    assert_eq!(response.offending_ie.map(|ie| ie.value), Some(57));
}

/// §7.6.1, §7.6.3: a response that does not decode, or of another version, ends its
/// request: no more retransmissions, and the caller has why.
#[test]
fn an_erroneous_response_ends_its_request() {
    let mut smf = node(SMF, Function::Cp);
    let id = smf.request(at(0), UPF, heartbeat()).unwrap();
    let request = decoded(&sent(&mut smf)[0]);
    let mut reply = Message {
        header: request.header,
        body: HeartbeatResponse::new(RecoveryTimeStamp::new(1)).into(),
    }
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
        let answer = Message {
            header: Header::node(0x777),
            body: VersionNotSupportedResponse::default().into(),
        };
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
    smf.request(
        at(0),
        UPF,
        Message {
            header: Header::node(0),
            body: setup.into(),
        },
    )
    .unwrap();
    pass(&mut smf, &mut upf, UPF, at(0));
    let (inbound, _) = request(&mut upf);
    let zero = Cause::new(CauseValue::from_value(0));
    let answer = AssociationSetupResponse::new(node_id(UPF), zero, RecoveryTimeStamp::new(1000));
    upf.respond(at(0), &inbound, answer).unwrap();
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
    let pfd = Message {
        header: Header::node(4),
        body: PfdManagementRequest::default().into(),
    };
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
    let report = Message {
        header: Header::node(5),
        body: NodeReportRequest::new(
            node_id(OTHER),
            NodeReportType {
                uprr: true,
                ..Default::default()
            },
        )
        .into(),
    };
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
    let first = Message {
        header: Header::node(1),
        body: AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000)).into(),
    };
    upf.handle_datagram(at(0), SMF, &first.encode().unwrap());
    let (inbound, _) = request(&mut upf);
    upf.respond(
        at(0),
        &inbound,
        AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(1000)),
    )
    .unwrap();
    sent(&mut upf);
    let again = Message {
        header: Header::node(1),
        body: AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(2000)).into(),
    };
    upf.handle_datagram(at(5), SMF, &again.encode().unwrap());
    let got = events(&mut upf);
    assert_eq!(requests_of(&got), 1, "{got:?}");
    assert!(got.contains(&Event::PeerRestarted {
        peer: SMF,
        recovery_time_stamp: 2000
    }));
    let heartbeat = Message {
        header: Header::node(2),
        body: HeartbeatRequest::new(RecoveryTimeStamp::new(2000)).into(),
    };
    upf.handle_datagram(at(6), SMF, &heartbeat.encode().unwrap());
    assert_eq!(
        sent(&mut upf).len(),
        1,
        "a heartbeat of the restarted peer is answered"
    );
}

/// §6.5 NOTE 3: a request sent bundled and retransmitted alone is the same request,
/// answered from the cache.
#[test]
fn a_retransmission_alone_of_a_bundled_request() {
    let (mut smf, mut upf) = associated(at(0));
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

/// §6.4: one answer to a request; and an answer of its response's type.
#[test]
fn a_request_is_answered_once_by_its_response() {
    let (_, mut upf) = associated(at(0));
    events(&mut upf);
    let update = Message {
        header: Header::node(7),
        body: AssociationUpdateRequest::new(node_id(SMF)).into(),
    };
    upf.handle_datagram(at(1), SMF, &update.encode().unwrap());
    let (inbound, _) = request(&mut upf);
    assert_eq!(
        upf.respond(
            at(1),
            &inbound,
            HeartbeatResponse::new(RecoveryTimeStamp::new(1))
        ),
        Err(NodeError::WrongResponse)
    );
    upf.respond(
        at(1),
        &inbound,
        AssociationUpdateResponse::new(node_id(UPF), accepted()),
    )
    .unwrap();
    assert_eq!(
        upf.respond(
            at(1),
            &inbound,
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
    let setup = Message {
        header: Header::node(3),
        body: AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000)).into(),
    };
    let octets = setup.encode().unwrap();
    upf.handle_datagram(at(0), SMF, &octets);
    let (inbound, _) = request(&mut upf);
    let answer = Message {
        header: Header::node(3),
        body: AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(1000))
            .into(),
    };
    upf.respond_message(at(0), &inbound, answer.clone(), Delivery::Forget)
        .unwrap();
    assert!(sent(&mut upf).is_empty());
    assert!(upf.association(SMF).is_none(), "nothing changed");
    upf.handle_datagram(at(3), SMF, &octets);
    let (inbound, _) = request(&mut upf);
    upf.respond_message(at(3), &inbound, answer, Delivery::CacheOnly)
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
    let setup = |sequence| Message {
        header: Header::node(sequence),
        body: AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000)).into(),
    };
    let answer = |sequence| Message {
        header: Header::node(sequence),
        body: AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(1000))
            .into(),
    };
    upf.handle_datagram(at(0), SMF, &setup(3).encode().unwrap());
    let (inbound, _) = request(&mut upf);
    upf.respond_message(at(0), &inbound, answer(3), Delivery::Forget)
        .unwrap();
    upf.respond_message(at(0), &inbound, answer(3), Delivery::Send)
        .unwrap();
    assert_eq!(sent(&mut upf).len(), 1);
    assert!(upf.association(SMF).is_none(), "after Forget");
    upf.handle_datagram(at(1), SMF, &setup(4).encode().unwrap());
    let (inbound, _) = request(&mut upf);
    let past = at(1) + upf.config().keep;
    upf.handle_timeout(past);
    upf.respond_message(past, &inbound, answer(4), Delivery::Send)
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
    for n in 0..1000 {
        upf.adopt_session(u64::from(n) + 1, address(capacity * 2 + n), 0x66)
            .unwrap();
    }
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

// ── Associations and sessions, kept in step with the procedures ─────────────

/// §6.2.6.3.2: a CP function that accepts the setup of a UP function that it has an
/// association with keeps its sessions: the retention of §6.2.6.2.2 is the UP
/// function's.
#[test]
fn a_cp_function_keeps_its_sessions_on_a_new_setup() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    let setup = AssociationSetupRequest::new(node_id(UPF), RecoveryTimeStamp::new(1000));
    upf.request(
        at(1),
        SMF,
        Message {
            header: Header::node(0),
            body: setup.into(),
        },
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    let (inbound, _) = request(&mut smf);
    let answer =
        AssociationSetupResponse::new(node_id(SMF), accepted(), RecoveryTimeStamp::new(1000));
    smf.respond(at(1), &inbound, answer).unwrap();
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
    for retention in [None, Some(PfcpSessionRetentionInformation::default())] {
        let (mut smf, mut upf) = associated(at(0));
        let (_, up_seid) = established(&mut smf, &mut upf, at(0));
        let mut setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(2000));
        setup.pfcp_session_retention_information = retention.clone().map(Box::new);
        upf.handle_datagram(
            at(10),
            SMF,
            &Message {
                header: Header::node(500),
                body: setup.into(),
            }
            .encode()
            .unwrap(),
        );
        let (inbound, _) = request(&mut upf);
        upf.respond(
            at(10),
            &inbound,
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
        let modification = Message {
            header: Header::session(up_seid, 501),
            body: SessionModificationRequest::default().into(),
        };
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
        let setup = Message {
            header: Header::node(sequence),
            body: AssociationSetupRequest::new(node_id(UPF), RecoveryTimeStamp::new(5)).into(),
        };
        smf.handle_datagram(at(0), from, &setup.encode().unwrap());
        let (inbound, _) = request(&mut smf);
        smf.respond(
            at(0),
            &inbound,
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
/// names: one that names the association of another is answered "No established PFCP
/// Association".
#[test]
fn a_release_ends_the_association_that_it_names() {
    let mut upf = node(UPF, Function::Up);
    for (from, sequence) in [(SMF, 1u32), (OTHER, 2)] {
        let setup = Message {
            header: Header::node(sequence),
            body: AssociationSetupRequest::new(node_id(from), RecoveryTimeStamp::new(5)).into(),
        };
        upf.handle_datagram(at(0), from, &setup.encode().unwrap());
        let (inbound, _) = request(&mut upf);
        upf.respond(
            at(0),
            &inbound,
            AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(1000)),
        )
        .unwrap();
        sent(&mut upf);
    }
    let release = Message {
        header: Header::node(3),
        body: AssociationReleaseRequest::new(node_id(SMF)).into(),
    };
    upf.handle_datagram(at(1), OTHER, &release.encode().unwrap());
    assert_eq!(violations(&mut upf), [ViolationKind::UnknownNode]);
    upf.handle_datagram(at(1), SMF, &release.encode().unwrap());
    let (inbound, _) = request(&mut upf);
    upf.respond(
        at(1),
        &inbound,
        AssociationReleaseResponse::new(node_id(UPF), accepted()),
    )
    .unwrap();
    assert!(upf.association(SMF).is_none());
    assert!(upf.association(OTHER).is_some());
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
    let response = Message {
        header: Header::session(second, request.header.sequence),
        body: SessionDeletionResponse::new(accepted()).into(),
    };
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
            drop: true,
            ..Default::default()
        },
    );
    let establishment = SessionEstablishmentRequest::new_n4(node_id(SMF), f_seid, pdr, far);
    smf.request(
        at(0),
        UPF,
        Message {
            header: Header::session(0, 0),
            body: establishment.into(),
        },
    )
    .unwrap();
    pass(&mut smf, &mut upf, UPF, at(0));
    let (inbound, _) = request(&mut upf);
    let up_seid = upf.new_session();
    // The UPF's F-SEID has another address than its socket
    let up_f_seid = FSeid {
        v4: true,
        seid: Some(up_seid),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 22)),
        ..Default::default()
    };
    upf.respond(
        at(0),
        &inbound,
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
    let f_seid = FSeid {
        v4: true,
        seid: Some(moved),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
        ..Default::default()
    };
    let id = smf
        .session_request(
            at(1),
            cp_seid,
            SessionModificationRequest::default().with_cp_f_seid(f_seid),
        )
        .unwrap();
    let request = decoded(&sent(&mut smf)[0]);
    upf.handle_datagram(at(1), SMF, &request.encode().unwrap());
    let (inbound, _) = self::request(&mut upf);
    upf.respond(
        at(1),
        &inbound,
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
    let (inbound, _) = self::request(&mut smf);
    smf.respond(at(2), &inbound, SessionReportResponse::new(accepted()))
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
    let f_seid = FSeid {
        v4: true,
        seid: Some(pending),
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
            drop: true,
            ..Default::default()
        },
    );
    smf.request(
        at(0),
        UPF,
        Message {
            header: Header::session(0, 0),
            body: SessionEstablishmentRequest::new_n4(node_id(SMF), f_seid, pdr, far).into(),
        },
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

// ── What the node keeps for the retransmissions, under load ────────────────

/// An Association Setup Request of `from`, of sequence number `sequence`.
fn setup_of(from: SocketAddr, sequence: u32, stamp: u32) -> Vec<u8> {
    Message {
        header: Header::node(sequence),
        body: AssociationSetupRequest::new(node_id(from), RecoveryTimeStamp::new(stamp)).into(),
    }
    .encode()
    .unwrap()
}

fn setup_answer() -> AssociationSetupResponse {
    AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(1000))
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
    let (inbound, _) = request(&mut upf);
    for i in 0..8u8 {
        let from = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 9, 9, i)), 8805);
        upf.handle_datagram(at(0), from, &heartbeat().encode().unwrap());
    }
    assert_eq!(sent(&mut upf).len(), 8, "each heartbeat answered");
    events(&mut upf);
    upf.respond(at(1), &inbound, setup_answer()).unwrap();
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
    for inbound in &waiting {
        upf.respond(at(1), inbound, setup_answer()).unwrap();
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
        let (inbound, _) = request(&mut upf);
        upf.respond(now, &inbound, setup_answer()).unwrap();
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
    smf.request(
        at(0),
        UPF,
        Message {
            header: Header::node(0),
            body: setup.into(),
        },
    )
    .unwrap();
    pass(&mut smf, &mut upf, UPF, at(0));
    let (inbound, _) = request(&mut upf);
    upf.respond(at(0), &inbound, setup_answer()).unwrap();
    pass(&mut upf, &mut smf, SMF, at(0));
    events(&mut smf);
    events(&mut upf);
    let (_, up_seid) = established(&mut smf, &mut upf, at(1));
    let again = Message {
        header: Header::node(inbound.sequence),
        body: setup_answer().into(),
    };
    upf.respond_message(at(2), &inbound, again, Delivery::CacheOnly)
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
        smf.request(
            at(0),
            UPF,
            Message {
                header: Header::node(0),
                body: setup.into(),
            },
        )
        .unwrap();
        pass(&mut smf, &mut upf, UPF, at(0));
        let (inbound, _) = request(&mut upf);
        upf.respond(at(0), &inbound, setup_answer()).unwrap();
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
        let again = Message {
            header: Header::node(inbound.sequence),
            body: setup_answer().into(),
        };
        upf.respond_message(now, &inbound, again, Delivery::CacheOnly)
            .unwrap();
        assert!(events(&mut upf).is_empty(), "evicted {evicted}");
        assert!(upf.session(up_seid).is_some(), "evicted {evicted}");
        assert_eq!(
            upf.respond(now, &inbound, setup_answer()),
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

/// A request of a host is of an association that is the host's: a host that names the
/// Node ID of another's is answered "No established PFCP Association".
#[test]
fn a_request_of_another_peers_node_id() {
    let (_, mut upf) = associated(at(0));
    upf.handle_datagram(at(1), OTHER, &establishment(9).encode().unwrap());
    assert_eq!(
        violations(&mut upf),
        [ViolationKind::SessionWithoutAssociation]
    );
    let release = Message {
        header: Header::node(4),
        body: AssociationReleaseRequest::new(node_id(SMF)).into(),
    };
    upf.handle_datagram(at(1), OTHER, &release.encode().unwrap());
    assert_eq!(violations(&mut upf), [ViolationKind::UnknownNode]);
    assert!(upf.association(SMF).is_some());
}

/// A session request is of a session of the host's, which is established: one of a host
/// without an association is answered "No established PFCP Association", and one of a
/// session of another or of one not established yet "Session context not found".
#[test]
fn a_session_request_of_a_session_of_the_host() {
    let (mut smf, mut upf) = associated(at(0));
    let (_, up_seid) = established(&mut smf, &mut upf, at(0));
    let deletion = |seid| {
        Message {
            header: Header::session(seid, 9),
            body: SessionDeletionRequest::default().into(),
        }
        .encode()
        .unwrap()
    };
    let stranger: SocketAddr = "10.0.0.66:8805".parse().unwrap();
    upf.handle_datagram(at(1), stranger, &deletion(up_seid));
    assert_eq!(
        violations(&mut upf),
        [ViolationKind::SessionWithoutAssociation]
    );
    assert_eq!(
        decoded(&sent(&mut upf)[0]).body.cause(),
        Some(CauseValue::NoEstablishedPfcpAssociation)
    );
    let allocated = upf.new_session();
    upf.handle_datagram(at(1), SMF, &deletion(allocated));
    assert_eq!(violations(&mut upf), [ViolationKind::UnknownSeid]);
    upf.handle_datagram(at(1), OTHER, &setup_of(OTHER, 1, 1000));
    let (inbound, _) = request(&mut upf);
    upf.respond(at(1), &inbound, setup_answer()).unwrap();
    sent(&mut upf);
    upf.handle_datagram(at(2), OTHER, &deletion(up_seid));
    assert_eq!(violations(&mut upf), [ViolationKind::UnknownSeid]);
    assert!(upf.session(up_seid).is_some());
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
    let (mut smf, mut upf) = associated(at(0));
    let password: String = b"hunter2"
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let printed = |text: &str| text.contains(&password) || text.contains("68756e74657232");
    // An unknown session's modification, with a Tunnel Password kept as an IE
    let mut modification = Message {
        header: Header::session(0x777, 5),
        body: SessionModificationRequest::default().into(),
    };
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
    let (inbound, _) = request(&mut upf);
    upf.respond(at(0), &inbound, setup_answer()).unwrap();
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
    let f_seid = FSeid {
        v4: true,
        seid: Some(77),
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
    let establishment = Message {
        header: Header::session(0, 2),
        body: SessionEstablishmentRequest::new_n4(node_id(SMF), f_seid, pdr, far).into(),
    };
    upf.handle_datagram(at(11), ephemeral, &establishment.encode().unwrap());
    let (inbound, _) = request(&mut upf);
    let up_seid = upf.new_session();
    let up_f_seid = FSeid {
        v4: true,
        seid: Some(up_seid),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 2)),
        ..Default::default()
    };
    let response =
        SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(up_f_seid);
    upf.respond(at(11), &inbound, response).unwrap();
    sent(&mut upf);
    let report = SessionReportRequest::new(ReportType {
        upir: true,
        ..Default::default()
    });
    upf.session_request(at(12), up_seid, report).unwrap();
    assert_eq!(sent(&mut upf)[0].to, SMF, "the report");
    let pfd = Message {
        header: Header::node(3),
        body: PfdManagementRequest::default().into(),
    };
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
    let (inbound, _) = request(&mut upf);
    upf.respond(at(0), &inbound, setup_answer()).unwrap();
    sent(&mut upf);
    upf.handle_timeout(at(10));
    assert_eq!(sent(&mut upf)[0].to, ephemeral);
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

/// The FQDN Node ID of `name`.
fn fqdn(name: &str) -> NodeId {
    let mut octets = Vec::new();
    for label in name.split('.') {
        octets.push(label.len() as u8);
        octets.extend_from_slice(label.as_bytes());
    }
    NodeId::Fqdn(octets.into())
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
            let setup = Message {
                header: Header::node(1),
                body: AssociationSetupRequest::new(fqdn(name), RecoveryTimeStamp::new(stamp))
                    .into(),
            };
            upf.handle_datagram(at(0), peer, &setup.encode().unwrap());
            let (inbound, _) = request(&mut upf);
            let answer =
                AssociationSetupResponse::new(fqdn("upf"), accepted(), RecoveryTimeStamp::new(1));
            upf.respond(at(0), &inbound, answer).unwrap();
            let f_seid = FSeid {
                v4: true,
                seid: Some(0x10),
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
            let establishment = Message {
                header: Header::session(0, 2),
                body: SessionEstablishmentRequest::new_n4(fqdn(name), f_seid, pdr, far).into(),
            };
            upf.handle_datagram(at(1), peer, &establishment.encode().unwrap());
            let (inbound, _) = request(&mut upf);
            let up_seid = upf.new_session();
            let up_f_seid = FSeid {
                v4: true,
                seid: Some(up_seid),
                ipv4: Some(Ipv4Addr::LOCALHOST),
                ..Default::default()
            };
            let response = SessionEstablishmentResponse::new(fqdn("upf"), accepted())
                .with_up_f_seid(up_f_seid);
            upf.respond(at(1), &inbound, response).unwrap();
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
                let heartbeat = Message {
                    header: Header::node(10 + i),
                    body: HeartbeatRequest::new(RecoveryTimeStamp::new(stamp)).into(),
                };
                upf.handle_datagram(at(2), peer, &heartbeat.encode().unwrap());
            }
        }
        assert!(
            !events(&mut upf)
                .iter()
                .any(|event| matches!(event, Event::PeerRestarted { .. }))
        );
        // The release of the first ends its sessions alone
        let release = Message {
            header: Header::node(3),
            body: AssociationReleaseRequest::new(fqdn("smf1")).into(),
        };
        upf.handle_datagram(at(3), smf1, &release.encode().unwrap());
        let (inbound, _) = request(&mut upf);
        upf.respond(
            at(3),
            &inbound,
            AssociationReleaseResponse::new(fqdn("upf"), accepted()),
        )
        .unwrap();
        assert!(upf.session(seids[0]).is_none());
        assert!(upf.session(seids[1]).is_some());
        assert!(upf.association(smf2).is_some());
        assert_eq!(upf.end_sessions_of(smf2), [seids[1]]);
    }
}

// ── Local SEIDs, one session each ──────────────────────────────────────────

/// An establishment of the SMF with `cp_seid` in its CP F-SEID.
fn establishment(cp_seid: u64) -> Message {
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
    Message {
        header: Header::session(0, 0),
        body: SessionEstablishmentRequest::new_n4(node_id(SMF), f_seid, pdr, far).into(),
    }
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
    let (inbound, _) = request(&mut upf);
    let rejected =
        SessionEstablishmentResponse::new(node_id(UPF), Cause::new(CauseValue::RequestRejected));
    upf.respond(at(1), &inbound, rejected).unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(smf.session(own).is_none());
    assert!(smf.session(cp_seid).is_some());
    // Nor does a session move to the SEID of another
    let (other, _) = established(&mut smf, &mut upf, at(2));
    let moved = FSeid {
        v4: true,
        seid: Some(other),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
        ..Default::default()
    };
    let modification = SessionModificationRequest::default().with_cp_f_seid(moved);
    assert_eq!(
        smf.session_request(at(2), cp_seid, modification),
        Err(NodeError::SeidInUse)
    );
    // But to one that new_session gave for it
    let fresh = smf.new_session();
    let moved = FSeid {
        v4: true,
        seid: Some(fresh),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
        ..Default::default()
    };
    let modification = SessionModificationRequest::default().with_cp_f_seid(moved);
    smf.session_request(at(2), cp_seid, modification).unwrap();
    pass(&mut smf, &mut upf, UPF, at(2));
    let (inbound, _) = request(&mut upf);
    upf.respond(
        at(2),
        &inbound,
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
        let moved = FSeid {
            v4: true,
            seid: Some(target),
            ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
            ..Default::default()
        };
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
    let (inbound, _) = request(&mut upf);
    let rejected = SessionModificationResponse::new(Cause::new(CauseValue::RequestRejected));
    upf.respond(at(1), &inbound, rejected).unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(smf.session(first).is_some() && smf.session(target).is_none());
    smf.session_request(at(2), second, to_target()).unwrap();
    pass(&mut smf, &mut upf, UPF, at(2));
    let (inbound, _) = request(&mut upf);
    upf.respond(
        at(2),
        &inbound,
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
        let moved = FSeid {
            v4: true,
            seid: Some(seid),
            ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
            ..Default::default()
        };
        SessionModificationRequest::default().with_cp_f_seid(moved)
    };
    let new = smf.new_session();
    smf.session_request(at(1), cp_seid, to(new)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (inbound, _) = request(&mut upf);
    smf.end_session(cp_seid);
    upf.respond(
        at(1),
        &inbound,
        SessionModificationResponse::new(accepted()),
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(smf.session(new).is_none());
    // A modification that request() sends with the SEID of no session of the node
    let modification = Message {
        header: Header::session(up_seid + 1000, 0),
        body: to(0x4242).into(),
    };
    smf.request(at(2), UPF, modification).unwrap();
    let sequence = decoded(&sent(&mut smf)[0]).header.sequence;
    let response = Message {
        header: Header::session(1, sequence),
        body: SessionModificationResponse::new(accepted()).into(),
    };
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
    let moved = FSeid {
        v4: true,
        seid: Some(fresh),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
        ..Default::default()
    };
    let modification = SessionModificationRequest::default().with_cp_f_seid(moved);
    smf.session_request(at(1), cp_seid, modification).unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (inbound, _) = request(&mut upf);
    upf.respond(
        at(1),
        &inbound,
        SessionModificationResponse::new(accepted()),
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    events(&mut smf);
    let report = |sequence| Message {
        header: Header::session(cp_seid, sequence),
        body: SessionReportRequest::new(ReportType {
            upir: true,
            ..Default::default()
        })
        .into(),
    };
    // 2 x N1 x T1 is 18 s: at 20 s, the previous SEID is of the session still
    smf.handle_datagram(at(20), UPF, &report(900).encode().unwrap());
    let (inbound, _) = request(&mut smf);
    assert_eq!(inbound.seid, Some(fresh));
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
    let deletion = Message {
        header: Header::session(up_seid, 0),
        body: SessionDeletionRequest::default().into(),
    };
    smf.request(at(1), UPF, deletion).unwrap();
    for transmit in sent(&mut smf) {
        upf.handle_datagram(at(1), SMF, &transmit.octets);
    }
    let (inbound, _) = request(&mut upf);
    upf.respond(at(1), &inbound, SessionDeletionResponse::new(accepted()))
        .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(smf.session(cp_seid).is_none());
}

/// §7.2.2.4.2: a SEID of 0 says that the peer's is not known: it is no local SEID, and an
/// answer that gives it as the peer's establishes nothing.
#[test]
fn a_seid_of_zero_is_of_no_session() {
    let (mut smf, mut upf) = associated(at(0));
    assert_eq!(
        smf.request(at(1), UPF, establishment(0)),
        Err(NodeError::SeidZero)
    );
    let cp_seid = smf.new_session();
    smf.request(at(1), UPF, establishment(cp_seid)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (inbound, _) = request(&mut upf);
    let zero = FSeid {
        v4: true,
        seid: Some(0),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 2)),
        ..Default::default()
    };
    let response = SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(zero);
    assert_eq!(
        upf.respond(at(1), &inbound, response.clone()),
        Err(NodeError::SeidZero)
    );
    // A probe's answer with it: no session 0 on either side
    let message = Message {
        header: Header::session(cp_seid, inbound.sequence),
        body: response.into(),
    };
    upf.respond_message(at(1), &inbound, message, Delivery::Send)
        .unwrap();
    assert!(upf.session(0).is_none());
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(smf.session(cp_seid).is_none());
    assert_eq!(violations(&mut smf), [ViolationKind::SeidZero]);
    let modification = Message {
        header: Header::session(0, 77),
        body: SessionModificationRequest::default().into(),
    };
    upf.handle_datagram(at(2), SMF, &modification.encode().unwrap());
    assert_eq!(violations(&mut upf), [ViolationKind::UnknownSeid]);
}

/// §7.2.2.4.2 on the UP side: a CP F-SEID of SEID 0 is of no session. An establishment
/// of it is answered "Mandatory IE incorrect", and a modification or a report's response
/// that gives it changes no peer's SEID.
#[test]
fn a_peer_seid_of_zero_is_kept_by_no_session() {
    let (mut smf, mut upf) = associated(at(0));
    let zero = FSeid {
        v4: true,
        seid: Some(0),
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
    let establishment = Message {
        header: Header::session(0, 40),
        body: SessionEstablishmentRequest::new_n4(node_id(SMF), zero.clone(), pdr, far).into(),
    };
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
    let modification = Message {
        header: Header::session(up_seid, 41),
        body: SessionModificationRequest::default()
            .with_cp_f_seid(zero)
            .into(),
    };
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
    let inbound = got
        .into_iter()
        .find_map(|event| match event {
            Event::Request { request, .. } => Some(request),
            _ => None,
        })
        .unwrap();
    upf.respond(
        at(3),
        &inbound,
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
    let (inbound, _) = request(&mut upf);
    let up_f_seid = FSeid {
        v4: true,
        seid: Some(up_seid),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 2)),
        ..Default::default()
    };
    let response =
        SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(up_f_seid);
    assert_eq!(
        upf.respond(at(1), &inbound, response),
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
            fqdn: Rest(set.as_bytes().to_vec()),
            ..Default::default()
        });
    }
    Message {
        header: Header::node(1),
        body: request.into(),
    }
    .encode()
    .unwrap()
}

/// A UPF of `smf_set`, associated with an SMF of the set at each of `smfs`, which gives
/// its Node ID, its features and its set; and a session of the first.
fn upf_of_set(
    smf_set: SmfSet,
    smfs: &[(SocketAddr, NodeId, CpFunctionFeatures, Option<&str>)],
) -> (Node, u64) {
    let mut upf = Node::new(NodeConfig {
        smf_set,
        ..config(UPF, Function::Up)
    });
    for (from, node_id, features, set) in smfs {
        upf.handle_datagram(
            at(0),
            *from,
            &setup_of_set(node_id.clone(), features.clone(), *set),
        );
        let (inbound, _) = request(&mut upf);
        upf.respond(at(0), &inbound, setup_answer()).unwrap();
    }
    let (from, node_id, ..) = &smfs[0];
    let f_seid = FSeid {
        v4: true,
        seid: Some(0x51),
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
    let establishment = Message {
        header: Header::session(0, 2),
        body: SessionEstablishmentRequest::new_n4(node_id.clone(), f_seid, pdr, far).into(),
    };
    upf.handle_datagram(at(0), *from, &establishment.encode().unwrap());
    let (inbound, _) = request(&mut upf);
    let up_seid = upf.new_session();
    let up_f_seid = FSeid {
        v4: true,
        seid: Some(up_seid),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 2)),
        ..Default::default()
    };
    let response =
        SessionEstablishmentResponse::new(node_id_of_upf(), accepted()).with_up_f_seid(up_f_seid);
    upf.respond(at(0), &inbound, response).unwrap();
    sent(&mut upf);
    events(&mut upf);
    (upf, up_seid)
}

fn node_id_of_upf() -> NodeId {
    node_id(UPF)
}

/// What the node gives of the datagram that `from` sends: whether a request, and of the
/// set, or the violations.
fn taken(upf: &mut Node, from: SocketAddr, message: Message) -> Result<bool, Vec<ViolationKind>> {
    upf.handle_datagram(at(1), from, &message.encode().unwrap());
    let got = events(upf);
    let request = got.iter().find_map(|event| match event {
        Event::Request { request, .. } => Some(request.of_smf_set),
        _ => None,
    });
    match request {
        Some(of_smf_set) => Ok(of_smf_set),
        None => Err(got
            .into_iter()
            .filter_map(|event| match event {
                Event::Violation { kind, .. } => Some(kind),
                _ => None,
            })
            .collect()),
    }
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

/// §5.22.3 bullet 3: with MPAS, the UPF takes a modification or a deletion of a session
/// from another association of the SMF set, of the same SMF Set ID, for its caller, and
/// the session is then of that association. Without MPAS, or from an SMF of another set,
/// it is answered "Session context not found".
#[test]
fn mpas_a_session_request_of_another_smf_of_the_set() {
    let smf_b = Ipv4Addr::new(10, 0, 0, 5).into_socket(8805);
    let smf_c = Ipv4Addr::new(10, 0, 0, 6).into_socket(8805);
    let smfs = [
        (SMF, node_id(SMF), mpas(), Some("set")),
        (smf_b, node_id(smf_b), mpas(), Some("set")),
        (smf_c, node_id(smf_c), mpas(), Some("other")),
    ];
    let modification = |seid| Message {
        header: Header::session(seid, 7),
        body: SessionModificationRequest::default().into(),
    };
    let (mut upf, up_seid) = upf_of_set(SmfSet::default(), &smfs);
    assert_eq!(
        taken(&mut upf, smf_b, modification(up_seid)),
        Err(vec![ViolationKind::UnknownSeid])
    );
    let mpas = SmfSet {
        mpas: true,
        ..SmfSet::default()
    };
    let (mut upf, up_seid) = upf_of_set(mpas, &smfs);
    assert_eq!(
        taken(&mut upf, smf_c, modification(up_seid)),
        Err(vec![ViolationKind::UnknownSeid])
    );
    upf.handle_datagram(at(1), smf_b, &modification(up_seid).encode().unwrap());
    let (inbound, _) = request(&mut upf);
    assert!(inbound.of_smf_set);
    upf.respond(
        at(1),
        &inbound,
        SessionModificationResponse::new(accepted()),
    )
    .unwrap();
    // The session is of B's association now
    let again = Message {
        header: Header::session(up_seid, 8),
        body: SessionModificationRequest::default().into(),
    };
    assert_eq!(taken(&mut upf, smf_b, again), Ok(false));
}

/// §5.22.2 bullet 3: with SSET, any SMF of the set may modify or delete a session, or
/// update or release the association, which is of the set: the UPF takes those of an SMF
/// without an association of its own for its caller. Without SSET it answers "No
/// established PFCP Association".
#[test]
fn sset_requests_of_an_smf_without_an_association() {
    let set = fqdn("set.example");
    let other: SocketAddr = Ipv4Addr::new(10, 0, 0, 7).into_socket(8805);
    let smfs = [(SMF, set.clone(), sset_features(), None)];
    let modification = |seid| Message {
        header: Header::session(seid, 7),
        body: SessionModificationRequest::default().into(),
    };
    let update = Message {
        header: Header::node(8),
        body: AssociationUpdateRequest::new(set.clone()).into(),
    };
    let (mut upf, up_seid) = upf_of_set(SmfSet::default(), &smfs);
    assert_eq!(
        taken(&mut upf, other, modification(up_seid)),
        Err(vec![ViolationKind::SessionWithoutAssociation])
    );
    assert_eq!(
        taken(&mut upf, other, update.clone()),
        Err(vec![ViolationKind::UnknownNode])
    );
    let sset = SmfSet {
        sset: true,
        ..SmfSet::default()
    };
    let (mut upf, up_seid) = upf_of_set(sset, &smfs);
    assert_eq!(taken(&mut upf, other, modification(up_seid)), Ok(true));
    assert_eq!(taken(&mut upf, other, update), Ok(true));
}

/// §6.2.8 with MPAS: the release of an association keeps its sessions while another of
/// the SMF set remains, of which they are then; that of the last ends them.
#[test]
fn mpas_a_release_keeps_the_sessions_of_the_set() {
    let smf_b = Ipv4Addr::new(10, 0, 0, 5).into_socket(8805);
    let smfs = [
        (SMF, node_id(SMF), mpas(), Some("set")),
        (smf_b, node_id(smf_b), mpas(), Some("set")),
    ];
    let mpas = SmfSet {
        mpas: true,
        ..SmfSet::default()
    };
    let (mut upf, up_seid) = upf_of_set(mpas, &smfs);
    let release = |from: SocketAddr| Message {
        header: Header::node(9),
        body: AssociationReleaseRequest::new(node_id(from)).into(),
    };
    for (from, kept) in [(SMF, true), (smf_b, false)] {
        upf.handle_datagram(at(2), from, &release(from).encode().unwrap());
        let (inbound, _) = request(&mut upf);
        upf.respond(
            at(2),
            &inbound,
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
}

/// §5.22.2 and §5.22.3 bullet 5: an SMF of a set takes the UPF's request of SEID 0 with
/// the CP F-SEID of the previous SMF for its caller, which takes the session over; without
/// the features of a set, it is a session that it does not have.
#[test]
fn a_session_handed_over_to_an_smf_of_the_set() {
    let report = || {
        let old = FSeid {
            v4: true,
            seid: Some(0x1234),
            ipv4: Some(Ipv4Addr::new(10, 0, 0, 9)),
            ..Default::default()
        };
        let report = SessionReportRequest::new(ReportType {
            uisr: true,
            ..Default::default()
        })
        .with_old_cp_f_seid(old);
        Message {
            header: Header::session(0, 9),
            body: report.into(),
        }
    };
    let (mut smf, _) = associated(at(0));
    assert_eq!(
        taken(&mut smf, UPF, report()),
        Err(vec![ViolationKind::UnknownSeid])
    );
    let (mut smf, _) = associated_as(
        NodeConfig {
            smf_set: SmfSet {
                mpas: true,
                ..SmfSet::default()
            },
            ..config(SMF, Function::Cp)
        },
        at(0),
    );
    smf.handle_datagram(at(1), UPF, &report().encode().unwrap());
    let (mut inbound, _) = request(&mut smf);
    assert!(inbound.of_smf_set);
    // The caller takes the session over, of the UPF's SEID that the set knows
    let local = smf.new_session();
    smf.end_session(local);
    smf.adopt_session(local, UPF, 0x77).unwrap();
    assert_eq!(
        smf.adopt_session(local, UPF, 0x77),
        Err(NodeError::SeidInUse)
    );
    inbound.seid = Some(local);
    smf.respond(at(1), &inbound, SessionReportResponse::new(accepted()))
        .unwrap();
    assert_eq!(decoded(&sent(&mut smf)[0]).header.seid, Some(0x77));
    // A report of the session that it took over is of its own
    let report = Message {
        header: Header::session(local, 10),
        body: SessionReportRequest::new(ReportType {
            upir: true,
            ..Default::default()
        })
        .into(),
    };
    assert_eq!(taken(&mut smf, UPF, report), Ok(false));
}

/// §5.22.2 bullet 4: a UP function sends a session's request to another SMF of the set,
/// one without an association too, of SEID 0 with the CP F-SEID of the previous SMF; the
/// answer's CP F-SEID is where the session's requests go after (§5.22.2 bullet 5).
#[test]
fn a_session_moved_to_another_smf_of_the_set() {
    let set = fqdn("set.example");
    let other: SocketAddr = Ipv4Addr::new(10, 0, 0, 7).into_socket(8805);
    let sset = SmfSet {
        sset: true,
        ..SmfSet::default()
    };
    let (mut upf, up_seid) = upf_of_set(sset, &[(SMF, set, sset_features(), None)]);
    let old = FSeid {
        v4: true,
        seid: Some(0x51),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
        ..Default::default()
    };
    let report = SessionReportRequest::new(ReportType {
        uisr: true,
        ..Default::default()
    })
    .with_old_cp_f_seid(old);
    upf.request(
        at(1),
        other,
        Message {
            header: Header::session(0, 0),
            body: report.into(),
        },
    )
    .unwrap();
    let sequence = decoded(&sent(&mut upf)[0]).header.sequence;
    let new = FSeid {
        v4: true,
        seid: Some(0x99),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 7)),
        ..Default::default()
    };
    let response = Message {
        header: Header::session(up_seid, sequence),
        body: SessionReportResponse::new(accepted())
            .with_cp_f_seid(new)
            .into(),
    };
    upf.handle_datagram(at(1), other, &response.encode().unwrap());
    let session = upf.session(up_seid).unwrap();
    assert_eq!((session.peer, session.peer_seid), (other, Some(0x99)));
}

/// §5.22.2 bullets 3-5: with SSET the set has one association, held by one SMF. Another
/// SMF of the set, with no association of its own, still takes the UPF's SEID-0 handover
/// report (header SEID 0, Old CP F-SEID of the previous SMF) for its caller, adopts the
/// session, and may modify it: any SMF of the set controls the session, with or without
/// an association of its own.
#[test]
fn sset_an_smf_without_the_association_controls_a_session() {
    let mut smf = Node::new(NodeConfig {
        smf_set: SmfSet {
            sset: true,
            ..SmfSet::default()
        },
        ..config(SMF, Function::Cp)
    });
    let old = FSeid {
        v4: true,
        seid: Some(0x1234),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 9)),
        ..Default::default()
    };
    let report = Message {
        header: Header::session(0, 9),
        body: SessionReportRequest::new(ReportType {
            uisr: true,
            ..Default::default()
        })
        .with_old_cp_f_seid(old)
        .into(),
    };
    smf.handle_datagram(at(1), UPF, &report.encode().unwrap());
    let (mut inbound, _) = request(&mut smf);
    assert!(inbound.of_smf_set);
    // The caller takes the session over, of the UPF's SEID that the set knows, and
    // answers the report.
    let local = smf.new_session();
    smf.end_session(local);
    smf.adopt_session(local, UPF, 0x77).unwrap();
    inbound.seid = Some(local);
    smf.respond(at(1), &inbound, SessionReportResponse::new(accepted()))
        .unwrap();
    assert_eq!(decoded(&sent(&mut smf)[0]).header.seid, Some(0x77));
    // Any SMF of the set may modify the session, with no association of its own.
    smf.session_request(at(2), local, SessionModificationRequest::default())
        .unwrap();
    assert_eq!(decoded(&sent(&mut smf)[0]).header.seid, Some(0x77));
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
    let up = |seid| FSeid {
        v4: true,
        seid: Some(seid),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 2)),
        ..Default::default()
    };
    // Establish session L, UP SEID 1.
    smf.request(at(0), UPF, establishment(l)).unwrap();
    pass(&mut smf, &mut upf, UPF, at(0));
    let (inbound, _) = request(&mut upf);
    upf.respond(
        at(0),
        &inbound,
        SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(up(1)),
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(0));
    events(&mut smf);
    // A move of L to N is outstanding; keep its datagram for later.
    let moved = FSeid {
        v4: true,
        seid: Some(n),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
        ..Default::default()
    };
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
    let (inbound, _) = request(&mut upf);
    upf.respond(
        at(1),
        &inbound,
        SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(up(2)),
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    events(&mut smf);
    // The old move's response arrives.
    for transmit in &move_datagram {
        upf.handle_datagram(at(1), SMF, &transmit.octets);
    }
    let (inbound, _) = request(&mut upf);
    upf.respond(
        at(1),
        &inbound,
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
    let (inbound, _) = request(&mut upf);
    let wrong = Message {
        header: Header::session(cp_seid, inbound.sequence),
        body: SessionDeletionResponse::new(accepted()).into(),
    };
    upf.respond_message(at(1), &inbound, wrong, Delivery::Send)
        .unwrap();
    assert!(upf.session(up_seid).is_some());

    // A setup answered with a release response: the association is not formed.
    let mut fresh = node(UPF, Function::Up);
    let setup = Message {
        header: Header::node(1),
        body: AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000)).into(),
    };
    fresh.handle_datagram(at(0), SMF, &setup.encode().unwrap());
    let (inbound, _) = request(&mut fresh);
    let wrong = Message {
        header: Header::node(inbound.sequence),
        body: AssociationReleaseResponse::new(node_id(UPF), accepted()).into(),
    };
    fresh
        .respond_message(at(0), &inbound, wrong, Delivery::Send)
        .unwrap();
    assert!(fresh.association(SMF).is_none());
}

/// Table 7.4.4.3-1, §5.22.3: an Association Update carries the supported features, which
/// the node must take, not only a new SMF Set ID. An SMF that turns MPAS off in an update
/// no longer shares its sessions with the set.
#[test]
fn an_association_update_changes_the_set_features() {
    let smf_b = Ipv4Addr::new(10, 0, 0, 5).into_socket(8805);
    let smfs = [
        (SMF, node_id(SMF), mpas(), Some("set")),
        (smf_b, node_id(smf_b), mpas(), Some("set")),
    ];
    let mpas = SmfSet {
        mpas: true,
        ..SmfSet::default()
    };
    let (mut upf, up_seid) = upf_of_set(mpas, &smfs);
    let modification = |seq| Message {
        header: Header::session(up_seid, seq),
        body: SessionModificationRequest::default().into(),
    };
    // Before: B may take A's session over by MPAS.
    assert_eq!(taken(&mut upf, smf_b, modification(7)), Ok(true));
    // A turns MPAS off in an Association Update, with no new SMF Set ID.
    let update = Message {
        header: Header::node(8),
        body: AssociationUpdateRequest::new(node_id(SMF))
            .with_cp_function_features(CpFunctionFeatures::default())
            .into(),
    };
    upf.handle_datagram(at(2), SMF, &update.encode().unwrap());
    let (inbound, _) = request(&mut upf);
    upf.respond(
        at(2),
        &inbound,
        AssociationUpdateResponse::new(node_id(UPF), accepted()),
    )
    .unwrap();
    // After: A no longer shares the session, so B's modification is not of the set.
    assert_eq!(
        taken(&mut upf, smf_b, modification(9)),
        Err(vec![ViolationKind::UnknownSeid])
    );
}

/// The same of a UPF's Association Update to an SMF: the SMF takes the MPAS of the UPF's
/// new UP Function Features, kept or withdrawn, for a release.
#[test]
fn a_cp_takes_the_mpas_of_a_upf_update() {
    assert!(cp_keeps_with_a_upf_that_sets_up(Some(true)));
    assert!(!cp_keeps_with_a_upf_that_sets_up(Some(false)));
}

/// §6.2.8.2: a CP function keeps the sessions of a released association only when the
/// MPAS feature is used, which the UPF must support too. The CP reads the UPF's MPAS from
/// the UP Function Features of the Association Setup Response; a UPF that did not announce
/// it means the CP ends the sessions on release.
#[test]
fn a_cp_keeps_released_sessions_only_with_an_mpas_upf() {
    let outcome = |up_mpas: bool| {
        let mut smf = Node::new(NodeConfig {
            smf_set: SmfSet {
                mpas: true,
                ..SmfSet::default()
            },
            ..config(SMF, Function::Cp)
        });
        let mut upf = node(UPF, Function::Up);
        smf.request(
            at(0),
            UPF,
            Message {
                header: Header::node(0),
                body: AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000))
                    .into(),
            },
        )
        .unwrap();
        pass(&mut smf, &mut upf, UPF, at(0));
        let (inbound, _) = request(&mut upf);
        let mut answer =
            AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(1000));
        if up_mpas {
            answer = answer.with_up_function_features(UpFunctionFeatures {
                mpas: true,
                ..Default::default()
            });
        }
        upf.respond(at(0), &inbound, answer).unwrap();
        pass(&mut upf, &mut smf, SMF, at(0));
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
    // A UPF that did not announce MPAS: the CP ends the sessions.
    let ((sessions, kept), still) = outcome(false);
    assert!(!still);
    assert_eq!(kept, Vec::<u64>::new());
    assert!(!sessions.is_empty());
    // A UPF that announced MPAS: the CP keeps them for its caller to decide.
    let ((sessions, kept), still) = outcome(true);
    assert!(still);
    assert_eq!(sessions, Vec::<u64>::new());
    assert!(!kept.is_empty());
}

/// §5.22.3 bullet 1, §6.2.6.3: a UPF may set the associations up itself; each SMF of the
/// set then says its MPAS and its SMF Set ID in its Association Setup Response, which the
/// UPF takes, so another SMF of the set may modify a session.
#[test]
fn mpas_of_associations_that_the_upf_sets_up() {
    let smf_b = Ipv4Addr::new(10, 0, 0, 5).into_socket(8805);
    let mut upf = Node::new(NodeConfig {
        smf_set: SmfSet {
            mpas: true,
            ..SmfSet::default()
        },
        ..config(UPF, Function::Up)
    });
    for smf in [SMF, smf_b] {
        let setup = AssociationSetupRequest::new(node_id(UPF), RecoveryTimeStamp::new(1000));
        upf.request(
            at(0),
            smf,
            Message {
                header: Header::node(0),
                body: setup.into(),
            },
        )
        .unwrap();
        let sequence = decoded(&sent(&mut upf)[0]).header.sequence;
        let response =
            AssociationSetupResponse::new(node_id(smf), accepted(), RecoveryTimeStamp::new(1000))
                .with_cp_function_features(mpas())
                .with_smf_set_id(SmfSetId {
                    fqdn: Rest(b"set".to_vec()),
                    ..Default::default()
                });
        let response = Message {
            header: Header::node(sequence),
            body: response.into(),
        };
        upf.handle_datagram(at(0), smf, &response.encode().unwrap());
    }
    events(&mut upf);
    upf.handle_datagram(at(0), SMF, &establishment(0x51).encode().unwrap());
    let (inbound, _) = request(&mut upf);
    let up_seid = upf.new_session();
    let up_f_seid = FSeid {
        v4: true,
        seid: Some(up_seid),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 2)),
        ..Default::default()
    };
    upf.respond(
        at(0),
        &inbound,
        SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(up_f_seid),
    )
    .unwrap();
    sent(&mut upf);
    let modification = Message {
        header: Header::session(up_seid, 7),
        body: SessionModificationRequest::default().into(),
    };
    assert_eq!(taken(&mut upf, smf_b, modification), Ok(true));
}

/// A CP function of MPAS that a UPF sets an association up with, announcing MPAS, then
/// updating its UP Function Features to `update`; whether a release then keeps a session.
fn cp_keeps_with_a_upf_that_sets_up(update: Option<bool>) -> bool {
    let mut smf = Node::new(NodeConfig {
        smf_set: SmfSet {
            mpas: true,
            ..SmfSet::default()
        },
        ..config(SMF, Function::Cp)
    });
    let mut upf = node(UPF, Function::Up);
    let up_mpas = |mpas| UpFunctionFeatures {
        mpas,
        ..Default::default()
    };
    let setup = AssociationSetupRequest::new(node_id(UPF), RecoveryTimeStamp::new(1000))
        .with_up_function_features(up_mpas(true));
    upf.request(
        at(0),
        SMF,
        Message {
            header: Header::node(0),
            body: setup.into(),
        },
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(0));
    let (inbound, _) = request(&mut smf);
    let answer =
        AssociationSetupResponse::new(node_id(SMF), accepted(), RecoveryTimeStamp::new(1000))
            .with_cp_function_features(mpas());
    smf.respond(at(0), &inbound, answer).unwrap();
    pass(&mut smf, &mut upf, UPF, at(0));
    events(&mut upf);
    events(&mut smf);
    if let Some(mpas) = update {
        let update =
            AssociationUpdateRequest::new(node_id(UPF)).with_up_function_features(up_mpas(mpas));
        upf.request(
            at(0),
            SMF,
            Message {
                header: Header::node(0),
                body: update.into(),
            },
        )
        .unwrap();
        pass(&mut upf, &mut smf, SMF, at(0));
        let (inbound, _) = request(&mut smf);
        smf.respond(
            at(0),
            &inbound,
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
    let mpas = SmfSet {
        mpas: true,
        ..SmfSet::default()
    };
    let (mut upf, up_seid) = upf_of_set(mpas, &smfs);
    // B takes the session over, with its Node ID and no new CP F-SEID.
    let takeover = Message {
        header: Header::session(up_seid, 7),
        body: SessionModificationRequest::default()
            .with_node_id(node_id(b))
            .into(),
    };
    upf.handle_datagram(at(1), b, &takeover.encode().unwrap());
    let (inbound, _) = request(&mut upf);
    assert!(inbound.of_smf_set);
    upf.respond(
        at(1),
        &inbound,
        SessionModificationResponse::new(accepted()),
    )
    .unwrap();
    let bs = |seq| Message {
        header: Header::session(up_seid, seq),
        body: SessionModificationRequest::default().into(),
    };
    // The session is B's now: B's own modification is not of the set.
    assert_eq!(taken(&mut upf, b, bs(8)), Ok(false));
    // A releases its association.
    let release = Message {
        header: Header::node(9),
        body: AssociationReleaseRequest::new(node_id(a)).into(),
    };
    upf.handle_datagram(at(2), a, &release.encode().unwrap());
    let (inbound, _) = request(&mut upf);
    upf.respond(
        at(2),
        &inbound,
        AssociationReleaseResponse::new(node_id(UPF), accepted()),
    )
    .unwrap();
    events(&mut upf);
    // The session stays B's: it is kept, and still not of the set for B.
    assert!(upf.session(up_seid).is_some());
    assert_eq!(taken(&mut upf, b, bs(10)), Ok(false));
}

/// §6.4: an answer to a request that is no longer waiting, because it expired past keep
/// or the caller forgot it, says it is no longer waiting, not that it has its answer
/// (which it does not).
#[test]
fn an_answer_to_a_request_no_longer_waiting_says_so() {
    let answer =
        || AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(1000));
    let setup = || Message {
        header: Header::node(1),
        body: AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000)).into(),
    };
    // Forgotten by the caller.
    let mut upf = node(UPF, Function::Up);
    upf.handle_datagram(at(0), SMF, &setup().encode().unwrap());
    let (inbound, _) = request(&mut upf);
    upf.forget(&inbound);
    assert_eq!(
        upf.respond(at(0), &inbound, answer()),
        Err(NodeError::Forgotten)
    );
    // Expired past keep (24 s).
    let mut upf = node(UPF, Function::Up);
    upf.handle_datagram(at(0), SMF, &setup().encode().unwrap());
    let (inbound, _) = request(&mut upf);
    upf.handle_timeout(at(25));
    assert_eq!(
        upf.respond(at(25), &inbound, answer()),
        Err(NodeError::Forgotten)
    );
    // Answered already stays Answered.
    let mut upf = node(UPF, Function::Up);
    upf.handle_datagram(at(0), SMF, &setup().encode().unwrap());
    let (inbound, _) = request(&mut upf);
    upf.respond(at(0), &inbound, answer()).unwrap();
    assert_eq!(
        upf.respond(at(0), &inbound, answer()),
        Err(NodeError::Answered)
    );
}

/// §7.2.2.4.2 bullet 3: the response to a request of header SEID 0 has SEID 0. A UPF
/// without an association sends a Session Report Request of SEID 0 with the Old CP F-SEID
/// of a previous SMF; the rejection must not carry that SMF-assigned SEID in its header.
#[test]
fn a_seid_zero_report_is_rejected_with_seid_zero() {
    let mut smf = node(SMF, Function::Cp);
    let old = FSeid {
        v4: true,
        seid: Some(0x1234),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 9)),
        ..Default::default()
    };
    let report = Message {
        header: Header::session(0, 9),
        body: SessionReportRequest::new(ReportType {
            uisr: true,
            ..Default::default()
        })
        .with_old_cp_f_seid(old)
        .into(),
    };
    smf.handle_datagram(at(1), UPF, &report.encode().unwrap());
    assert_eq!(decoded(&sent(&mut smf)[0]).header.seid, Some(0));
}

/// §5.22.2 bullet 3, §6.2.6.2.1: with SSET, an SMF without the set's association may
/// modify or delete an established session of the set, and nothing more. An establishment
/// needs an association, whatever its SEID, and so does a request of a session that is
/// not established.
#[test]
fn sset_an_smf_without_the_association_establishes_nothing() {
    let mut smf = Node::new(NodeConfig {
        smf_set: SmfSet {
            sset: true,
            ..SmfSet::default()
        },
        ..config(SMF, Function::Cp)
    });
    // An establishment of a SEID of new_session, or of the caller's own: refused alike.
    let seid = smf.new_session();
    assert_eq!(
        smf.request(at(0), UPF, establishment(seid)),
        Err(NodeError::NoAssociation)
    );
    assert_eq!(
        smf.request(at(0), UPF, establishment(0x99)),
        Err(NodeError::NoAssociation)
    );
    assert!(sent(&mut smf).is_empty());
    // An established session of the set, adopted, is modified and deleted.
    smf.adopt_session(0x42, UPF, 0x77).unwrap();
    smf.session_request(at(0), 0x42, SessionModificationRequest::default())
        .unwrap();
    smf.session_request(at(0), 0x42, SessionDeletionRequest::default())
        .unwrap();
    assert_eq!(sent(&mut smf).len(), 2);
    // It moves to a new SEID, which is no established session while the move waits.
    let moved = FSeid {
        v4: true,
        seid: Some(0x43),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
        ..Default::default()
    };
    smf.session_request(
        at(0),
        0x42,
        SessionModificationRequest::default().with_cp_f_seid(moved),
    )
    .unwrap();
    assert_eq!(
        smf.session_request(at(0), 0x43, SessionDeletionRequest::default()),
        Err(NodeError::NoAssociation)
    );
}

/// The accepted responses of the node's requests in the order the peer took them
/// (§6.3.3).
fn answer_all(upf: &mut Node, now: Duration) {
    let requests: Vec<(Inbound, Message)> = events(upf)
        .into_iter()
        .filter_map(|event| match event {
            Event::Request { request, message } => Some((request, message)),
            _ => None,
        })
        .collect();
    for (inbound, message) in requests {
        let body: Body = match message.body {
            Body::SessionModificationRequest(_) => {
                SessionModificationResponse::new(accepted()).into()
            }
            Body::SessionDeletionRequest(_) => SessionDeletionResponse::new(accepted()).into(),
            other => panic!("{other:?}"),
        };
        upf.respond(now, &inbound, body).unwrap();
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
    let moved = FSeid {
        v4: true,
        seid: Some(new),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
        ..Default::default()
    };
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
    let moved = FSeid {
        v4: true,
        seid: Some(new),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
        ..Default::default()
    };
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
    let (inbound, _) = request(&mut upf);
    let up_f_seid = FSeid {
        v4: true,
        seid: Some(0x99),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 2)),
        ..Default::default()
    };
    upf.respond(
        at(1),
        &inbound,
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
    let (inbound, _) = request(&mut upf);
    let up_f_seid = FSeid {
        v4: true,
        seid: Some(0x99),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 2)),
        ..Default::default()
    };
    upf.respond(
        at(1),
        &inbound,
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
    let (inbound, _) = request(&mut upf);
    let up_f_seid = FSeid {
        v4: true,
        seid: Some(up_seid),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 2)),
        ..Default::default()
    };
    upf.respond(
        at(1),
        &inbound,
        SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(up_f_seid),
    )
    .unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    events(&mut smf);
    // The old report reaches the SMF, which answers with the CP F-SEID of another SMF.
    for transmit in &report {
        smf.handle_datagram(at(1), UPF, &transmit.octets);
    }
    let (inbound, _) = request(&mut smf);
    let other = FSeid {
        v4: true,
        seid: Some(0xbeef),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 7)),
        ..Default::default()
    };
    smf.respond(
        at(1),
        &inbound,
        SessionReportResponse::new(accepted()).with_cp_f_seid(other),
    )
    .unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let session = upf.session(up_seid).unwrap();
    assert_eq!(session.peer_seid, Some(0x4242));
    assert_eq!(session.peer.ip(), SMF.ip());
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
    let (inbound, _) = request(&mut upf);
    let wrong = Message {
        header: Header::session(cp_seid, inbound.sequence),
        body: HeartbeatResponse::new(RecoveryTimeStamp::new(1000)).into(),
    };
    upf.respond_message(at(0), &inbound, wrong, Delivery::Send)
        .unwrap();
    let up_seid = 0x5151;
    let right = Message {
        header: Header::session(cp_seid, inbound.sequence),
        body: SessionEstablishmentResponse::new(node_id(UPF), accepted())
            .with_up_f_seid(FSeid {
                v4: true,
                seid: Some(up_seid),
                ipv4: Some(Ipv4Addr::new(10, 0, 0, 2)),
                ..Default::default()
            })
            .into(),
    };
    upf.respond_message(at(0), &inbound, right, Delivery::Send)
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
    let (inbound, _) = request(&mut upf);
    assert_eq!(inbound.seid, Some(up_seid));
}

/// A UPF's report of SEID 0 that hands over the session of the Old CP F-SEID 0x1234 of
/// 10.0.0.9 (§5.22.2, §5.22.3 bullet 6).
fn handover_report() -> Message {
    Message {
        header: Header::session(0, 9),
        body: SessionReportRequest::new(ReportType {
            uisr: true,
            ..Default::default()
        })
        .with_old_cp_f_seid(FSeid {
            v4: true,
            seid: Some(0x1234),
            ipv4: Some(Ipv4Addr::new(10, 0, 0, 9)),
            ..Default::default()
        })
        .into(),
    }
}

/// §5.22.3 bullet 6: with MPAS, a UPF hands a session over to an SMF of the set with which
/// it has an association. An SMF of MPAS alone answers a report of SEID 0 of a UPF without
/// one with "No established PFCP Association"; only SSET lets the taking SMF have none,
/// and, with `other_entities`, another PFCP entity of the same SMF
/// (`mpas_a_handover_report_to_another_entity_of_the_smf`).
#[test]
fn mpas_a_handover_report_needs_an_association() {
    let report = handover_report;
    let of = |mpas, sset| {
        Node::new(NodeConfig {
            smf_set: SmfSet { sset, mpas },
            ..config(SMF, Function::Cp)
        })
    };
    let mut smf = of(true, false);
    assert_eq!(
        taken(&mut smf, UPF, report()),
        Err(vec![ViolationKind::SessionWithoutAssociation])
    );
    let rejection = decoded(&sent(&mut smf)[0]);
    assert_eq!(
        rejection.body.cause(),
        Some(CauseValue::NoEstablishedPfcpAssociation)
    );
    assert_eq!(taken(&mut of(false, true), UPF, report()), Ok(true));
    assert_eq!(taken(&mut of(true, true), UPF, report()), Ok(true));
}

/// §5.22.3 bullets 5 and 6: with MPAS, a UPF hands a session over to another PFCP entity of
/// the same SMF too, a node of its own, which has not the association that another entity
/// of the SMF holds. A node of `other_entities` gives its caller the report of a host
/// without an association with it, as of the set, and answers nothing itself: its caller
/// takes the session only from a UPF that has an association with an entity of its SMF,
/// here by adopting it, and answers to the UPF's SEID. Without MPAS, a node of
/// `other_entities` rejects it.
#[test]
fn mpas_a_handover_report_to_another_entity_of_the_smf() {
    let entity = |mpas| {
        Node::new(NodeConfig {
            smf_set: SmfSet {
                mpas,
                ..SmfSet::default()
            },
            other_entities: true,
            ..config(OTHER, Function::Cp)
        })
    };
    let mut other = entity(true);
    other.handle_datagram(at(1), UPF, &handover_report().encode().unwrap());
    let (mut inbound, _) = request(&mut other);
    assert!(inbound.of_smf_set);
    assert!(sent(&mut other).is_empty());
    // The caller takes the session over, with the UPF's SEID that the SMF knows.
    other.adopt_session(0x55, UPF, 0x66).unwrap();
    inbound.seid = Some(0x55);
    let cp_f_seid = FSeid {
        v4: true,
        seid: Some(0x55),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 3)),
        ..Default::default()
    };
    let response = SessionReportResponse::new(accepted()).with_cp_f_seid(cp_f_seid);
    other.respond(at(1), &inbound, response).unwrap();
    assert_eq!(decoded(&sent(&mut other)[0]).header.seid, Some(0x66));
    assert_eq!(
        taken(&mut entity(false), UPF, handover_report()),
        Err(vec![ViolationKind::SessionWithoutAssociation])
    );
}

/// Table 7.4.4.4-1: the Association Update Response carries the responder's function
/// features too. A CP function of MPAS sets an association up with a UPF of MPAS `before`,
/// sends it an update, which the UPF answers with `cause` and its UP Function Features of
/// MPAS `after`; whether a release then keeps a session.
fn cp_keeps_after_an_update_answered_with(before: bool, after: bool, cause: CauseValue) -> bool {
    let mut smf = Node::new(NodeConfig {
        smf_set: SmfSet {
            mpas: true,
            ..SmfSet::default()
        },
        ..config(SMF, Function::Cp)
    });
    let mut upf = node(UPF, Function::Up);
    let up_mpas = |mpas| UpFunctionFeatures {
        mpas,
        ..Default::default()
    };
    let setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000));
    smf.request(
        at(0),
        UPF,
        Message {
            header: Header::node(0),
            body: setup.into(),
        },
    )
    .unwrap();
    pass(&mut smf, &mut upf, UPF, at(0));
    let (inbound, _) = request(&mut upf);
    let answer =
        AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(1000))
            .with_up_function_features(up_mpas(before));
    upf.respond(at(0), &inbound, answer).unwrap();
    pass(&mut upf, &mut smf, SMF, at(0));
    events(&mut smf);
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    smf.request(
        at(1),
        UPF,
        Message {
            header: Header::node(0),
            body: AssociationUpdateRequest::new(node_id(SMF)).into(),
        },
    )
    .unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (inbound, _) = request(&mut upf);
    upf.respond(
        at(1),
        &inbound,
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
    let (inbound, _) = request(&mut upf);
    let up_seid = upf.new_session();
    upf.respond(
        at(0),
        &inbound,
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

/// §5.22.2, Table 7.4.4.3-1: an Association Update that turns SSET off or on changes
/// what an SMF of the set without an association may ask. Once the holder of the set's
/// association withdraws SSET, another SMF's modification is answered "No established
/// PFCP Association"; once it announces SSET, the modification goes to the caller.
#[test]
fn an_association_update_changes_the_sset_of_the_set() {
    let set = fqdn("set.example");
    let other: SocketAddr = Ipv4Addr::new(10, 0, 0, 7).into_socket(8805);
    let sset = SmfSet {
        sset: true,
        ..SmfSet::default()
    };
    let modification = |seid, sequence| Message {
        header: Header::session(seid, sequence),
        body: SessionModificationRequest::default().into(),
    };
    let update = |sset| Message {
        header: Header::node(8),
        body: AssociationUpdateRequest::new(fqdn("set.example"))
            .with_cp_function_features(CpFunctionFeatures {
                sset,
                ..Default::default()
            })
            .into(),
    };
    let updated = |upf: &mut Node, sset| {
        upf.handle_datagram(at(2), SMF, &update(sset).encode().unwrap());
        let (inbound, _) = request(upf);
        upf.respond(
            at(2),
            &inbound,
            AssociationUpdateResponse::new(node_id(UPF), accepted()),
        )
        .unwrap();
    };
    let smfs = [(SMF, set.clone(), sset_features(), None)];
    let (mut upf, up_seid) = upf_of_set(sset, &smfs);
    assert_eq!(taken(&mut upf, other, modification(up_seid, 7)), Ok(true));
    updated(&mut upf, false);
    assert_eq!(
        taken(&mut upf, other, modification(up_seid, 9)),
        Err(vec![ViolationKind::SessionWithoutAssociation])
    );
    let smfs = [(SMF, set, CpFunctionFeatures::default(), None)];
    let (mut upf, up_seid) = upf_of_set(sset, &smfs);
    assert_eq!(
        taken(&mut upf, other, modification(up_seid, 7)),
        Err(vec![ViolationKind::SessionWithoutAssociation])
    );
    updated(&mut upf, true);
    assert_eq!(taken(&mut upf, other, modification(up_seid, 9)), Ok(true));
}

/// §5.22.2 bullet 3: an SMF without an association updates or releases the set's
/// association only when that association is of SSET. A UPF of SSET with an association
/// whose SMF did not announce SSET answers another host's update or release of it with
/// "No established PFCP Association".
#[test]
fn sset_an_update_of_an_association_not_of_sset_is_refused() {
    let set = fqdn("set.example");
    let other: SocketAddr = Ipv4Addr::new(10, 0, 0, 7).into_socket(8805);
    let sset = SmfSet {
        sset: true,
        ..SmfSet::default()
    };
    let update = Message {
        header: Header::node(8),
        body: AssociationUpdateRequest::new(set.clone()).into(),
    };
    let release = Message {
        header: Header::node(9),
        body: AssociationReleaseRequest::new(set.clone()).into(),
    };
    let smfs = [(SMF, set.clone(), CpFunctionFeatures::default(), None)];
    let (mut upf, _) = upf_of_set(sset, &smfs);
    assert_eq!(
        taken(&mut upf, other, update.clone()),
        Err(vec![ViolationKind::UnknownNode])
    );
    assert_eq!(
        taken(&mut upf, other, release.clone()),
        Err(vec![ViolationKind::UnknownNode])
    );
    let smfs = [(SMF, set, sset_features(), None)];
    let (mut upf, _) = upf_of_set(sset, &smfs);
    assert_eq!(taken(&mut upf, other, update), Ok(true));
    assert_eq!(taken(&mut upf, other, release), Ok(true));
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
    let (inbound, _) = request(&mut upf);
    upf.handle_datagram(at(1), SMF, &setup);
    assert_eq!(events(&mut upf), [retransmission(5, false)]);
    assert!(sent(&mut upf).is_empty());
    upf.respond(at(1), &inbound, setup_answer()).unwrap();
    let answer = sent(&mut upf);
    events(&mut upf);
    upf.handle_datagram(at(2), SMF, &setup);
    assert_eq!(events(&mut upf), [retransmission(5, true)]);
    assert_eq!(sent(&mut upf), answer);
    // A session request of a host without an association, which the node rejects itself
    let modification = Message {
        header: Header::session(0x10, 6),
        body: SessionModificationRequest::default().into(),
    }
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
    let heartbeat = Message {
        header: Header::node(7),
        ..heartbeat()
    }
    .encode()
    .unwrap();
    for _ in 0..2 {
        upf.handle_datagram(at(2), SMF, &heartbeat);
        assert_eq!(sent(&mut upf).len(), 1);
    }
    assert!(events(&mut upf).is_empty());
}

/// Move the SMF's session of `from` to the local SEID `to`, a move that the UPF accepts.
fn move_session(smf: &mut Node, upf: &mut Node, from: u64, to: u64, now: Duration) {
    let moved = FSeid {
        v4: true,
        seid: Some(to),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
        ..Default::default()
    };
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
    let earlier = Message {
        header: Header::session(cp_seid, 77),
        body: SessionReportRequest::new(ReportType {
            dldr: true,
            ..Default::default()
        })
        .into(),
    };
    smf.handle_datagram(at(2), UPF, &earlier.encode().unwrap());
    let (inbound, _) = request(&mut smf);
    assert_eq!(inbound.seid, Some(0x88));
    smf.respond(at(2), &report, SessionReportResponse::new(accepted()))
        .unwrap();
    assert_eq!(decoded(&sent(&mut smf)[0]).header.seid, Some(up_seid));
    assert!(
        smf.session(0x88).is_none(),
        "the session that the UPF deleted stays at its last SEID"
    );
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
        smf_set: SmfSet {
            mpas: true,
            ..SmfSet::default()
        },
        other_entities: true,
        strangers: 2,
        heartbeat: Some(Duration::from_secs(60)),
        ..config(OTHER, Function::Cp)
    });
    other.handle_datagram(at(1), UPF, &handover_report().encode().unwrap());
    let (mut inbound, _) = request(&mut other);
    other.adopt_session(0x55, UPF, 0x66).unwrap();
    inbound.seid = Some(0x55);
    let cp_f_seid = FSeid {
        v4: true,
        seid: Some(0x55),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 3)),
        ..Default::default()
    };
    other
        .respond(
            at(1),
            &inbound,
            SessionReportResponse::new(accepted()).with_cp_f_seid(cp_f_seid),
        )
        .unwrap();
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
    let response = Message {
        header: Header::session(0x55, modification.header.sequence),
        body: SessionModificationResponse::new(accepted()).into(),
    };
    other.handle_datagram(at(2), UPF, &response.encode().unwrap());
    assert!(matches!(&events(&mut other)[..], [Event::Response { .. }]));
    // The UPF's requests of the session, beyond the room of strangers
    for sequence in 10..20 {
        let report = Message {
            header: Header::session(0x55, sequence),
            body: SessionReportRequest::new(ReportType {
                dldr: true,
                ..Default::default()
            })
            .into(),
        };
        other.handle_datagram(at(3), UPF, &report.encode().unwrap());
    }
    assert_eq!(requests_of(&events(&mut other)), 10);
    assert_eq!(other.counters().refused, 0);
    // A heartbeat to the UPF, which tells its Recovery Time Stamp, and then its restart
    let beat = |other: &mut Node, now: Duration, stamp: u32| {
        assert!(other.poll_timeout().is_some_and(|due| due <= now));
        other.handle_timeout(now);
        let heartbeats: Vec<Message> = sent(other)
            .iter()
            .filter(|transmit| transmit.to == UPF)
            .map(decoded)
            .filter(|message| matches!(message.body, Body::HeartbeatRequest(_)))
            .collect();
        assert_eq!(heartbeats.len(), 1, "a heartbeat to the UPF at {now:?}");
        let response = Message {
            header: Header::node(heartbeats[0].header.sequence),
            body: HeartbeatResponse::new(RecoveryTimeStamp::new(stamp)).into(),
        };
        other.handle_datagram(now, UPF, &response.encode().unwrap());
        events(other)
    };
    assert!(
        !beat(&mut other, at(3), 1000)
            .iter()
            .any(|event| matches!(event, Event::PeerRestarted { .. }))
    );
    let restarted = beat(&mut other, at(63), 2000);
    assert!(restarted.iter().any(|event| matches!(
        event,
        Event::PeerRestarted {
            peer: UPF,
            recovery_time_stamp: 2000
        }
    )));
    // Its deletion ends it, and the heartbeats with it
    other
        .session_request(at(64), 0x55, SessionDeletionRequest::default())
        .unwrap();
    let deletion = decoded(&sent(&mut other)[0]);
    let response = Message {
        header: Header::session(0x55, deletion.header.sequence),
        body: SessionDeletionResponse::new(accepted()).into(),
    };
    other.handle_datagram(at(64), UPF, &response.encode().unwrap());
    assert!(other.session(0x55).is_none());
    other.handle_timeout(at(123));
    assert!(sent(&mut other).is_empty());
    assert_eq!(other.poll_timeout(), None);
}

/// §6.2.2.2: a node heartbeats the peer of a session adopted without an association for
/// as long as such a session lasts, also through an association with the peer that ends
/// and leaves the session to the set (§6.2.8, MPAS); without one, a released association
/// has no more heartbeats.
#[test]
fn an_adopted_session_keeps_the_heartbeats_of_its_peer_through_a_release() {
    let released = |adopt: bool| {
        let mut smf = Node::new(NodeConfig {
            smf_set: SmfSet {
                mpas: true,
                ..SmfSet::default()
            },
            heartbeat: Some(Duration::from_secs(60)),
            ..config(SMF, Function::Cp)
        });
        if adopt {
            smf.adopt_session(0x55, UPF, 0x66).unwrap();
        }
        let mut upf = node(UPF, Function::Up);
        let setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000));
        smf.request(
            at(0),
            UPF,
            Message {
                header: Header::node(0),
                body: setup.into(),
            },
        )
        .unwrap();
        pass(&mut smf, &mut upf, UPF, at(0));
        let (inbound, _) = request(&mut upf);
        let answer =
            AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(1000))
                .with_up_function_features(UpFunctionFeatures {
                    mpas: true,
                    ..Default::default()
                });
        upf.respond(at(0), &inbound, answer).unwrap();
        pass(&mut upf, &mut smf, SMF, at(0));
        assert!(smf.end_association(UPF));
        smf
    };
    let mut smf = released(true);
    assert!(smf.session(0x55).is_some());
    let due = smf.poll_timeout().expect("a heartbeat");
    smf.handle_timeout(due);
    assert!(sent(&mut smf).iter().any(|transmit| transmit.to == UPF
        && matches!(decoded(transmit).body, Body::HeartbeatRequest(_))));
    assert_eq!(released(false).poll_timeout(), None);
}

/// The requests of a host without an association, of the address of a session's F-SEID,
/// wait in the room of hosts without an association, as `NodeConfig::strangers` says: only
/// a session that the caller adopted makes its peer's requests those of an association.
#[test]
fn the_requests_of_the_host_of_an_f_seid_wait_as_a_strangers() {
    let (mut smf, mut upf) = associated_as(
        NodeConfig {
            strangers: 1,
            ..config(SMF, Function::Cp)
        },
        at(0),
    );
    let (cp_seid, _) = established_on(&mut smf, &mut upf, at(0), Ipv4Addr::new(10, 0, 0, 12));
    let host = Ipv4Addr::new(10, 0, 0, 12).into_socket(8805);
    for sequence in [10, 11] {
        let report = Message {
            header: Header::session(cp_seid, sequence),
            body: SessionReportRequest::new(ReportType {
                dldr: true,
                ..Default::default()
            })
            .into(),
        };
        smf.handle_datagram(at(1), host, &report.encode().unwrap());
    }
    assert_eq!(requests_of(&events(&mut smf)), 1);
    assert_eq!(smf.counters().refused, 1);
}

/// A node heartbeats the peer of its adopted sessions from the first adoption: those
/// after change nothing, nor does an adoption from a peer of an association, which has
/// the heartbeats of one, nor one on a node of no heartbeat.
#[test]
fn adoptions_start_the_heartbeats_of_their_peer_once() {
    let (mut smf, _) = associated_as(
        NodeConfig {
            heartbeat: Some(Duration::from_secs(60)),
            ..config(SMF, Function::Cp)
        },
        at(0),
    );
    assert_eq!(smf.poll_timeout(), Some(at(60)));
    smf.adopt_session(0x55, UPF, 0x66).unwrap();
    assert_eq!(smf.poll_timeout(), Some(at(60)));
    let mut smf = Node::new(NodeConfig {
        heartbeat: Some(Duration::from_secs(60)),
        ..config(SMF, Function::Cp)
    });
    smf.adopt_session(0x55, UPF, 0x66).unwrap();
    assert_eq!(smf.poll_timeout(), Some(at(0)));
    smf.handle_timeout(at(0));
    let request = decoded(&sent(&mut smf)[0]);
    let response = Message {
        header: Header::node(request.header.sequence),
        body: HeartbeatResponse::new(RecoveryTimeStamp::new(1000)).into(),
    };
    smf.handle_datagram(at(0), UPF, &response.encode().unwrap());
    smf.adopt_session(0x56, UPF, 0x67).unwrap();
    assert_eq!(smf.poll_timeout(), Some(at(60)));
    // A node of no heartbeat beats none
    let mut smf = node(SMF, Function::Cp);
    smf.adopt_session(0x55, UPF, 0x66).unwrap();
    assert_eq!(smf.poll_timeout(), None);
}

/// A node keeps the Recovery Time Stamp of the peer of an adopted session through a flood
/// of hosts without an association, as it keeps those of its associations: their
/// heartbeats do not make it miss the peer's restart.
#[test]
fn an_adopted_peer_keeps_its_recovery_time_stamp() {
    let mut smf = Node::new(NodeConfig {
        capacity: 2,
        heartbeat: Some(Duration::from_secs(60)),
        ..config(SMF, Function::Cp)
    });
    smf.adopt_session(0x55, UPF, 0x66).unwrap();
    let beat = |smf: &mut Node, now: Duration, stamp: u32| {
        smf.handle_timeout(now);
        let request = decoded(&sent(smf)[0]);
        let response = Message {
            header: Header::node(request.header.sequence),
            body: HeartbeatResponse::new(RecoveryTimeStamp::new(stamp)).into(),
        };
        smf.handle_datagram(now, UPF, &response.encode().unwrap());
        events(smf)
    };
    beat(&mut smf, at(0), 1000);
    for host in 10..14 {
        let stranger = Ipv4Addr::new(10, 0, 0, host).into_socket(8805);
        smf.handle_datagram(at(1), stranger, &heartbeat().encode().unwrap());
    }
    sent(&mut smf);
    assert!(
        beat(&mut smf, at(60), 2000)
            .iter()
            .any(|event| matches!(event, Event::PeerRestarted { peer: UPF, .. }))
    );
}

/// The Recovery Time Stamps that a flood of hosts without an association spares are
/// those of the peers of an association or of an adopted session while they last: once
/// the association is released, or the adopted session ends, the peer's stamp goes before
/// the others, and a new one of it is no restart.
#[test]
fn the_stamps_that_a_flood_spares_follow_the_associations_and_adoptions() {
    let (mut smf, _) = associated_as(
        NodeConfig {
            capacity: 2,
            ..config(SMF, Function::Cp)
        },
        at(0),
    );
    smf.adopt_session(0x55, OTHER, 0x66).unwrap();
    let beat = |smf: &mut Node, from: SocketAddr, stamp: u32| {
        let request = Message {
            header: Header::node(7),
            body: HeartbeatRequest::new(RecoveryTimeStamp::new(stamp)).into(),
        };
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
    assert!(beat(&mut smf, OTHER, 2000));
    assert!(smf.end_association(UPF));
    assert!(smf.end_session(0x55).is_some());
    flood(&mut smf);
    assert!(!beat(&mut smf, UPF, 3000));
    assert!(!beat(&mut smf, OTHER, 3000));
}

/// §5.22.3 bullet 6, and 4119cdf: an adoption gives no more to a host that it does not
/// name. A host without an association with the node, of another address than the
/// adopted session's UPF, has its requests of that session rejected, and its handover
/// reports, of no session, wait in the room of strangers.
#[test]
fn mpas_an_adopted_session_is_none_of_a_strangers() {
    let mut other = Node::new(NodeConfig {
        smf_set: SmfSet {
            mpas: true,
            ..SmfSet::default()
        },
        other_entities: true,
        strangers: 1,
        ..config(OTHER, Function::Cp)
    });
    other.adopt_session(0x55, UPF, 0x66).unwrap();
    let stranger = Ipv4Addr::new(10, 0, 0, 8).into_socket(8805);
    let report = Message {
        header: Header::session(0x55, 10),
        body: SessionReportRequest::new(ReportType {
            dldr: true,
            ..Default::default()
        })
        .into(),
    };
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
        smf_set: SmfSet {
            mpas: true,
            ..SmfSet::default()
        },
        other_entities: true,
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
    let report = Message {
        header: Header::session(1, 31),
        body: SessionReportRequest::new(ReportType {
            dldr: true,
            ..Default::default()
        })
        .into(),
    };
    other.handle_datagram(at(1), UPF, &report.encode().unwrap());
    assert_eq!(requests_of(&events(&mut other)), 1);
}

/// §6.2.3.3.1, §6.2.4.3.1 and §6.2.4.4.1: the load and overload control information of
/// the peer of an adopted session, without an association, applies to that peer, which
/// the node knows by its address alone, with AOCI or not: kept, the overload throttles
/// the session's requests, and a restart of the peer ends both.
#[test]
fn the_controls_of_an_adopted_peer_apply_to_it() {
    for of_node in [false, true] {
        let mut other = Node::new(NodeConfig {
            smf_set: SmfSet {
                mpas: true,
                ..SmfSet::default()
            },
            other_entities: true,
            ..config(OTHER, Function::Cp)
        });
        other.adopt_session(0x55, UPF, 0x66).unwrap();
        let controls = with_overload(1, 100, 30, of_node);
        let report = SessionReportRequest::new(ReportType {
            upir: true,
            ..Default::default()
        })
        .with_load_control_information(LoadControlInformation::new(
            SequenceNumber::new(1),
            Metric::new(Percent(50)),
        ))
        .with_overload_control_information(*controls.overload_control_information.unwrap());
        let message = Message {
            header: Header::session(0x55, 10),
            body: report.into(),
        };
        other.handle_datagram(at(1), UPF, &message.encode().unwrap());
        assert_eq!(requests_of(&events(&mut other)), 1);
        assert_eq!(other.load_control(UPF).map(|load| load.metric), Some(50));
        assert_eq!(
            other.overload_control(UPF).map(|overload| overload.metric),
            Some(100)
        );
        for second in 2..5 {
            assert_eq!(
                other.session_request(at(second), 0x55, SessionModificationRequest::default()),
                Err(NodeError::Throttled)
            );
        }
        // The UPF restarts
        let restart = Message {
            header: Header::node(11),
            body: HeartbeatRequest::new(RecoveryTimeStamp::new(1000)).into(),
        };
        other.handle_datagram(at(5), UPF, &restart.encode().unwrap());
        let restart = Message {
            header: Header::node(12),
            body: HeartbeatRequest::new(RecoveryTimeStamp::new(2000)).into(),
        };
        other.handle_datagram(at(5), UPF, &restart.encode().unwrap());
        assert!(other.load_control(UPF).is_none() && other.overload_control(UPF).is_none());
    }
}

/// §4.2.2: the node sends its requests to a peer of a session that it adopts at port
/// 8805, whatever port the request that handed the session over came from, as it does to
/// a peer of an association or of an established session; without `request_port`, to the
/// port of the peer. Its modifications and its heartbeats go there.
#[test]
fn an_adopted_session_takes_the_port_of_the_requests() {
    for request_port in [Some(PORT), None] {
        let mut other = Node::new(NodeConfig {
            smf_set: SmfSet {
                mpas: true,
                ..SmfSet::default()
            },
            other_entities: true,
            heartbeat: Some(Duration::from_secs(60)),
            request_port,
            ..config(OTHER, Function::Cp)
        });
        let from = SocketAddr::new(UPF.ip(), 40000);
        let to = SocketAddr::new(UPF.ip(), request_port.unwrap_or(40000));
        other.handle_datagram(at(1), from, &handover_report().encode().unwrap());
        let (mut inbound, _) = request(&mut other);
        other.adopt_session(0x55, inbound.from, 0x66).unwrap();
        assert_eq!(other.session(0x55).map(|session| session.peer), Some(to));
        inbound.seid = Some(0x55);
        other
            .respond(at(1), &inbound, SessionReportResponse::new(accepted()))
            .unwrap();
        assert_eq!(
            sent(&mut other)[0].to,
            from,
            "the answer to the request's port"
        );
        other
            .session_request(at(2), 0x55, SessionModificationRequest::default())
            .unwrap();
        other.handle_timeout(at(2));
        let requests: Vec<(SocketAddr, u8)> = sent(&mut other)
            .iter()
            .map(|transmit| (transmit.to, decoded(transmit).body.message_type()))
            .collect();
        assert_eq!(requests, [(to, 52), (to, 1)]);
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
    let (inbound, _) = request(&mut upf);
    let up_f_seid = FSeid {
        v4: true,
        seid: Some(0x99),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 2)),
        ..Default::default()
    };
    upf.respond(
        at(0),
        &inbound,
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
        let moved = FSeid {
            v4: true,
            seid: Some(new),
            ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
            ..Default::default()
        };
        smf.session_request(
            at(1),
            cp_seid,
            SessionModificationRequest::default().with_cp_f_seid(moved),
        )
        .unwrap();
        pass(&mut smf, &mut upf, UPF, at(1));
        let (inbound, _) = request(&mut upf);
        let cause = match accept {
            true => accepted(),
            false => Cause::new(CauseValue::RequestRejected),
        };
        upf.respond(at(1), &inbound, SessionModificationResponse::new(cause))
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
        let (inbound, _) = request(&mut smf);
        assert_eq!(inbound.seid, Some(cp_seid));
        smf.respond(at(1), &inbound, SessionReportResponse::new(accepted()))
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
    let (inbound, _) = request(&mut upf);
    upf.respond(at(1), &inbound, answer).unwrap();
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
    let (inbound, message) = request(smf);
    assert_eq!(inbound.seid, Some(cp_seid));
    assert!(matches!(message.body, Body::SessionReportRequest(_)));
    smf.respond(now, &inbound, SessionReportResponse::new(accepted()))
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
    let (inbound, _) = request(&mut upf);
    let pending = SessionDeletionResponse::new(accepted()).with_pfcpsdrsp_flags(PFCPSDRspFlags {
        puru: true,
        ..Default::default()
    });
    upf.respond(at(1), &inbound, pending).unwrap();
    assert!(upf.session(up_seid).is_none());
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(matches!(&events(&mut smf)[..], [Event::Response { .. }]));
    assert!(smf.session(cp_seid).is_some());
    // The report again, after T1
    upf.handle_timeout(at(1) + T1);
    pass(&mut upf, &mut smf, SMF, at(4));
    let (inbound, _) = request(&mut smf);
    smf.respond(at(4), &inbound, SessionReportResponse::new(accepted()))
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

trait IntoSocket {
    fn into_socket(self, port: u16) -> SocketAddr;
}

impl IntoSocket for Ipv4Addr {
    fn into_socket(self, port: u16) -> SocketAddr {
        SocketAddr::new(self.into(), port)
    }
}
