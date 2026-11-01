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
    let cp_seid = smf.new_session(UPF);
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
    let up_seid = upf.new_session(SMF);
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
    assert!(events(&mut upf).is_empty());
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
    assert!(events(&mut upf).is_empty());
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
        sessions: vec![]
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
        sessions: vec![cp_seid]
    }));
    assert!(smf.session(cp_seid).is_none());
}

#[test]
fn session_needs_association() {
    let (mut smf, mut upf) = (node(SMF, Function::Cp), node(UPF, Function::Up));
    let seid = smf.new_session(UPF);
    assert_eq!(
        smf.session_request(at(0), seid, SessionDeletionRequest::default()),
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
    assert_ne!(smf.new_session(UPF), cp_seid, "a SEID of no other session");
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
    let other_seid = upf.new_session(OTHER);
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
    assert!(events(&mut upf).is_empty());
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

/// Every sequence number reserved: a request has none, and says so.
#[test]
#[ignore = "reserves 2^24 numbers"]
fn no_sequence_number_left() {
    let mut smf = node(SMF, Function::Cp);
    for _ in 0..0x0100_0000u32 {
        smf.reserve_sequence().unwrap();
    }
    assert_eq!(
        smf.request(at(0), UPF, heartbeat()),
        Err(NodeError::NoSequence)
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

/// §6.2.8: a release ends the association that it names, whoever sends it.
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
    let cp_seid = smf.new_session(UPF);
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
    let up_seid = upf.new_session(SMF);
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
    let moved = smf.new_session(UPF);
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
    let pending = smf.new_session(UPF);
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
        sessions: vec![third]
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
    assert!(events(&mut upf).is_empty(), "no new request");
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
            Err(NodeError::Answered)
        );
    }
}

/// A request that waits for its answer stays past `keep`: its retransmission is no new
/// request, and the late answer has its effect.
#[test]
fn a_request_waits_past_keep() {
    let mut upf = Node::new(NodeConfig {
        keep: Duration::from_secs(5),
        ..config(UPF, Function::Up)
    });
    let setup = setup_of(SMF, 1, 1000);
    upf.handle_datagram(at(0), SMF, &setup);
    let (inbound, _) = request(&mut upf);
    upf.handle_datagram(at(6), SMF, &setup);
    assert_eq!(requests_of(&events(&mut upf)), 0);
    upf.respond(at(7), &inbound, setup_answer()).unwrap();
    assert!(upf.association(SMF).is_some());
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
    let up_seid = upf.new_session(ephemeral);
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
            let up_seid = upf.new_session(peer);
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
        assert_ne!(smf.new_session(UPF), own);
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
    let fresh = smf.new_session(UPF);
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

/// Table 7.5.4.1-1 NOTE 2: after a change of its CP F-SEID, the CP function takes the
/// session messages of the UP function to the previous SEID for longer than twice N1 x
/// T1, as of the session.
#[test]
fn the_previous_seid_of_a_moved_session() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    let fresh = smf.new_session(UPF);
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

/// The UP function's answer that gives the local SEID of another session is not sent.
#[test]
fn an_answer_of_a_seid_in_use_is_refused() {
    let (mut smf, mut upf) = associated(at(0));
    let (_, up_seid) = established(&mut smf, &mut upf, at(0));
    let other = smf.new_session(UPF);
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

trait IntoSocket {
    fn into_socket(self, port: u16) -> SocketAddr;
}

impl IntoSocket for Ipv4Addr {
    fn into_socket(self, port: u16) -> SocketAddr {
        SocketAddr::new(self.into(), port)
    }
}
