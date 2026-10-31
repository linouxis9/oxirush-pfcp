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
    NodeConfig { heartbeat: None, ..NodeConfig::new(node_id(address), function, 1000) }
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
    smf.request(now, UPF, Message { header: Header::node(0), body: setup.into() }).unwrap();
    pass(&mut smf, &mut upf, UPF, now);
    let (inbound, _) = request(&mut upf);
    upf.respond(now, &inbound, AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(1000))).unwrap();
    pass(&mut upf, &mut smf, SMF, now);
    events(&mut smf);
    (smf, upf)
}

/// A session between them: the SMF's SEID and the UPF's.
fn established(smf: &mut Node, upf: &mut Node, now: Duration) -> (u64, u64) {
    let cp_seid = smf.new_session(UPF);
    let f_seid = FSeid { v4: true, seid: Some(cp_seid), ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)), ..Default::default() };
    let pdr = CreatePdr::new(PdrId::new(1), Precedence::new(1), Pdi::new(SourceInterface::new(SourceInterfaceValue::Access)));
    let far = CreateFar::new(FarId::new(1), ApplyAction { forw: true, ..Default::default() });
    let establishment = SessionEstablishmentRequest::new(node_id(SMF), f_seid, pdr, far);
    smf.request(now, UPF, Message { header: Header::session(0, 0), body: establishment.into() }).unwrap();
    pass(smf, upf, UPF, now);
    let (inbound, _) = request(upf);
    let up_seid = upf.new_session(SMF);
    let up_f_seid = FSeid { v4: true, seid: Some(up_seid), ipv4: Some(Ipv4Addr::new(10, 0, 0, 2)), ..Default::default() };
    let response = SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(up_f_seid);
    upf.respond(now, &inbound, response).unwrap();
    pass(upf, smf, SMF, now);
    events(smf);
    (cp_seid, up_seid)
}

fn decoded(transmit: &Transmit) -> Message {
    Message::decode(&transmit.octets).unwrap()
}

fn heartbeat() -> Message {
    Message { header: Header::node(0), body: HeartbeatRequest::new(RecoveryTimeStamp::new(1000)).into() }
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
    let response = Message { header: to_upf.header, body: HeartbeatResponse::new(RecoveryTimeStamp::new(1)).into() };
    smf.handle_datagram(at(1), OTHER, &response.encode().unwrap());
    assert_eq!(violations(&mut smf), [ViolationKind::WrongPeer]);
    smf.handle_datagram(at(1), UPF, &response.encode().unwrap());
    assert!(matches!(&events(&mut smf)[..], [Event::Response { request, .. }] if *request == first));
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
    let response = Message { header: decoded(&original).header, body: HeartbeatResponse::new(RecoveryTimeStamp::new(1)).into() };
    smf.handle_datagram(at(4), UPF, &response.encode().unwrap());
    smf.handle_timeout(at(60));
    assert!(sent(&mut smf).is_empty(), "nothing after the response");
    assert_eq!(smf.poll_timeout(), None);
}

#[test]
fn sequence_unique() {
    let mut smf = node(SMF, Function::Cp);
    let reserved = smf.reserve_sequence();
    for _ in 0..1000 {
        smf.request(at(0), UPF, heartbeat()).unwrap();
    }
    let mut sequences: Vec<u32> = sent(&mut smf).iter().map(|transmit| decoded(transmit).header.sequence).collect();
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
    assert_eq!(events(&mut smf), [Event::Timeout { request: id, to: UPF }]);
}

#[test]
fn retransmission_identical() {
    let mut smf = node(SMF, Function::Cp);
    let message = Message { header: Header { priority: Some(3), ..Header::node(0) }, body: HeartbeatRequest::new(RecoveryTimeStamp::new(1000)).into() };
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
    let octets = Message { header: Header::node(0x1234), body: update.into() }.encode().unwrap();
    upf.handle_datagram(at(1), SMF, &octets);
    let (inbound, _) = request(&mut upf);
    upf.respond(at(1), &inbound, AssociationUpdateResponse::new(node_id(UPF), accepted())).unwrap();
    assert_eq!(decoded(&sent(&mut upf)[0]).header.sequence, 0x1234);
}

#[test]
fn retransmitted_request_answered_from_cache() {
    let (_, mut upf) = associated(at(0));
    let update = AssociationUpdateRequest::new(node_id(SMF));
    let octets = Message { header: Header::node(77), body: update.into() }.encode().unwrap();
    upf.handle_datagram(at(1), SMF, &octets);
    let (inbound, _) = request(&mut upf);
    // A retransmission before the answer is not a second request
    upf.handle_datagram(at(2), SMF, &octets);
    assert!(events(&mut upf).is_empty());
    upf.respond(at(2), &inbound, AssociationUpdateResponse::new(node_id(UPF), accepted())).unwrap();
    let answer = sent(&mut upf).remove(0);
    // One after it gets the same answer, byte for byte
    upf.handle_datagram(at(4), SMF, &octets);
    assert!(events(&mut upf).is_empty());
    assert_eq!(sent(&mut upf), [answer]);
    // The same sequence number with other octets
    let changed = Message { header: Header::node(77), body: AssociationUpdateRequest::new(node_id(OTHER)).into() };
    upf.handle_datagram(at(5), SMF, &changed.encode().unwrap());
    assert_eq!(violations(&mut upf), [ViolationKind::ChangedRetransmission]);
}

#[test]
fn duplicate_response_discarded() {
    let mut smf = node(SMF, Function::Cp);
    smf.request(at(0), UPF, heartbeat()).unwrap();
    let header = decoded(&sent(&mut smf)[0]).header;
    let response = Message { header, body: HeartbeatResponse::new(RecoveryTimeStamp::new(1)).into() }.encode().unwrap();
    smf.handle_datagram(at(1), UPF, &response);
    assert_eq!(events(&mut smf).len(), 1);
    smf.handle_datagram(at(1), UPF, &response);
    assert_eq!(violations(&mut smf), [ViolationKind::DuplicateResponse]);
}

#[test]
fn unknown_response_discarded() {
    let mut smf = node(SMF, Function::Cp);
    let response = Message { header: Header::node(4242), body: HeartbeatResponse::new(RecoveryTimeStamp::new(1)).into() };
    smf.handle_datagram(at(0), UPF, &response.encode().unwrap());
    assert_eq!(violations(&mut smf), [ViolationKind::UnknownSequence]);
    // A response to a request that the node gave up is late
    smf.request(at(0), UPF, heartbeat()).unwrap();
    let header = decoded(&sent(&mut smf)[0]).header;
    for attempt in 1..=4 {
        smf.handle_timeout(T1 * attempt);
    }
    events(&mut smf);
    let late = Message { header, body: HeartbeatResponse::new(RecoveryTimeStamp::new(1)).into() };
    smf.handle_datagram(at(13), UPF, &late.encode().unwrap());
    assert_eq!(violations(&mut smf), [ViolationKind::LateResponse]);
}

// ── §6.2.2: heartbeat ───────────────────────────────────────────────────────

#[test]
fn heartbeat_answered_from_unknown_peer() {
    let mut upf = node(UPF, Function::Up);
    upf.handle_datagram(at(0), OTHER, &Message { header: Header::node(5), ..heartbeat() }.encode().unwrap());
    assert!(events(&mut upf).is_empty(), "the node answers it");
    let answer = decoded(&sent(&mut upf)[0]);
    assert_eq!(answer.header.sequence, 5);
    let Body::HeartbeatResponse(response) = &answer.body else { panic!("{answer:?}") };
    assert_eq!(response.recovery_time_stamp.as_ref().map(|stamp| stamp.value), Some(1000));
}

// ── §6.2.3, §6.2.4: load and overload control ───────────────────────────────

fn with_load(sequence: u32, metric: u8) -> SessionModificationResponse {
    SessionModificationResponse::new(accepted()).with_load_control_information(LoadControlInformation::new(SequenceNumber::new(sequence), Metric::new(Percent(metric))))
}

fn with_overload(sequence: u32, metric: u8, minutes: u8, of_node: bool) -> SessionModificationResponse {
    let timer = Timer { timer_unit: TimerUnit::OneMinute, timer_value: minutes, ..Default::default() };
    let mut overload = OverloadControlInformation::new(SequenceNumber::new(sequence), Metric::new(Percent(metric)), timer);
    if of_node {
        overload = overload.with_overload_control_information_flags(OciFlags { aoci: true, ..Default::default() });
    }
    SessionModificationResponse::new(accepted()).with_overload_control_information(overload)
}

/// The UPF answers a modification of the session with `response`.
fn modified(smf: &mut Node, upf: &mut Node, cp_seid: u64, now: Duration, response: SessionModificationResponse) {
    smf.session_request(now, cp_seid, SessionModificationRequest::default()).unwrap();
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
    assert_eq!(smf.load_control(UPF), Some(LoadControl { sequence: 5, metric: 40 }));
    // An older one, out of order, changes nothing; a newer one replaces it
    modified(&mut smf, &mut upf, cp_seid, at(2), with_load(4, 90));
    assert_eq!(smf.load_control(UPF).map(|load| load.metric), Some(40));
    modified(&mut smf, &mut upf, cp_seid, at(3), with_load(6, 70));
    assert_eq!(smf.load_control(UPF), Some(LoadControl { sequence: 6, metric: 70 }));
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
    let restarted = Message { header: Header::node(9), body: HeartbeatRequest::new(RecoveryTimeStamp::new(3000)).into() };
    smf.handle_datagram(at(2), UPF, &restarted.encode().unwrap());
    assert!(events(&mut smf).contains(&Event::PeerRestarted { peer: UPF, recovery_time_stamp: 3000 }));
    assert_eq!(smf.load_control(UPF), None);
    modified(&mut smf, &mut upf, cp_seid, at(3), with_load(1, 60));
    assert_eq!(smf.load_control(UPF), Some(LoadControl { sequence: 1, metric: 60 }));
}

#[test]
fn load_control_sequence_violation() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    modified(&mut smf, &mut upf, cp_seid, at(1), with_load(5, 40));
    events(&mut smf);
    modified(&mut smf, &mut upf, cp_seid, at(2), with_load(5, 41));
    assert_eq!(violations(&mut smf), [ViolationKind::LoadControlSequence], "the same number, other values");
    modified(&mut smf, &mut upf, cp_seid, at(3), with_load(6, 40));
    assert_eq!(violations(&mut smf), [ViolationKind::LoadControlSequence], "a new number, the same values");
}

#[test]
fn load_control_from_any_message() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
    // In a Session Report Request of the UPF
    let load = LoadControlInformation::new(SequenceNumber::new(3), Metric::new(Percent(55)));
    let report = SessionReportRequest::new(ReportType::default()).with_load_control_information(load);
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
    modified(&mut smf, &mut upf, cp_seid, at(1), with_overload(7, 20, 10, false));
    modified(&mut smf, &mut upf, cp_seid, at(2), with_overload(6, 90, 10, false));
    assert_eq!(smf.overload_control(UPF).map(|overload| overload.metric), Some(20));
    modified(&mut smf, &mut upf, cp_seid, at(3), with_overload(8, 50, 10, false));
    assert_eq!(smf.overload_control(UPF).map(|overload| (overload.sequence, overload.metric)), Some((8, 50)));
}

#[test]
fn overload_control_reset_on_peer_restart() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    modified(&mut smf, &mut upf, cp_seid, at(1), with_overload(500, 20, 10, false));
    let restarted = Message { header: Header::node(9), body: HeartbeatRequest::new(RecoveryTimeStamp::new(3000)).into() };
    smf.handle_datagram(at(2), UPF, &restarted.encode().unwrap());
    assert_eq!(smf.overload_control(UPF), None);
    modified(&mut smf, &mut upf, cp_seid, at(3), with_overload(1, 30, 10, false));
    assert_eq!(smf.overload_control(UPF).map(|overload| overload.sequence), Some(1));
}

#[test]
fn overload_control_sequence_violation() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    modified(&mut smf, &mut upf, cp_seid, at(1), with_overload(5, 20, 10, false));
    events(&mut smf);
    modified(&mut smf, &mut upf, cp_seid, at(2), with_overload(5, 30, 10, false));
    assert_eq!(violations(&mut smf), [ViolationKind::OverloadControlSequence]);
}

#[test]
fn overload_control_scope() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    // By default, of the address of the peer
    modified(&mut smf, &mut upf, cp_seid, at(1), with_overload(1, 20, 10, false));
    assert_eq!(smf.overload_control(UPF).map(|overload| overload.metric), Some(20));
    // Of the Node ID, with AOCI: it holds for the association, apart from the address
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    modified(&mut smf, &mut upf, cp_seid, at(1), with_overload(1, 35, 10, true));
    assert_eq!(smf.overload_control(UPF).map(|overload| overload.metric), Some(35));
}

#[test]
fn overload_control_validity_expires() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    modified(&mut smf, &mut upf, cp_seid, at(10), with_overload(1, 20, 1, false));
    assert_eq!(smf.overload_control(UPF).and_then(|overload| overload.until), Some(at(70)));
    // A new set restarts the period
    modified(&mut smf, &mut upf, cp_seid, at(40), with_overload(2, 25, 1, false));
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
    let timer = Timer { timer_unit: TimerUnit::OneMinute, timer_value: 5, ..Default::default() };
    let overload = OverloadControlInformation::new(SequenceNumber::new(4), Metric::new(Percent(15)), timer);
    let report = SessionReportRequest::new(ReportType::default()).with_overload_control_information(overload);
    upf.session_request(at(1), up_seid, report).unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    assert_eq!(smf.overload_control(UPF).map(|overload| overload.metric), Some(15));
}

// ── §6.2.4.4, §6.2.4.5: throttling and priority ──────────────────────────────

/// An SMF of `smf` with a session on a UPF that asks for a reduction of `metric`%.
fn overloaded(smf: NodeConfig, metric: u8) -> (Node, u64) {
    let (mut smf, mut upf) = associated_as(smf, at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    modified(&mut smf, &mut upf, cp_seid, at(1), with_overload(1, metric, 30, false));
    (smf, cp_seid)
}

#[test]
fn throttling_loss_algorithm() {
    let (mut smf, cp_seid) = overloaded(config(SMF, Function::Cp), 30);
    let throttled = (0..100)
        .filter(|_| smf.session_request(at(2), cp_seid, SessionModificationRequest::default()) == Err(NodeError::Throttled))
        .count();
    assert_eq!(throttled, 30, "30% of the requests");
}

#[test]
fn throttling_never_responses() {
    let (mut smf, cp_seid) = overloaded(config(SMF, Function::Cp), 100);
    assert_eq!(smf.session_request(at(2), cp_seid, SessionModificationRequest::default()), Err(NodeError::Throttled));
    // Node related requests, and responses, go
    assert!(smf.request(at(2), UPF, heartbeat()).is_ok());
    let report = Message { header: Header::session(cp_seid, 31), body: SessionReportRequest::new(ReportType::default()).into() };
    smf.handle_datagram(at(3), UPF, &report.encode().unwrap());
    let (inbound, _) = request(&mut smf);
    sent(&mut smf);
    smf.respond(at(3), &inbound, SessionReportResponse::new(accepted())).unwrap();
    assert_eq!(sent(&mut smf).len(), 1);
}

#[test]
fn throttling_spares_priority() {
    // An SMF that spares the priorities 0 to 2, and a UPF that asks for 50%
    let (mut smf, _) = overloaded(NodeConfig { priority_up_to: Some(2), ..config(SMF, Function::Cp) }, 50);
    let send = |smf: &mut Node, priority: u8| {
        let message = Message { header: Header { priority: Some(priority), ..Header::session(1, 0) }, body: SessionModificationRequest::default().into() };
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
    let alone = (0..100).filter(|_| send(&mut smf, 1) == Err(NodeError::Throttled)).count();
    assert!(alone > 0 && alone <= 50, "{alone}");
}

#[test]
fn message_priority_default() {
    let (_, mut upf) = associated(at(0));
    let without = Message { header: Header::node(100), body: AssociationUpdateRequest::new(node_id(SMF)).into() };
    upf.handle_datagram(at(1), SMF, &without.encode().unwrap());
    let (inbound, _) = request(&mut upf);
    assert_eq!((inbound.priority, inbound.prioritized), (8, false));
    // The highest priority goes out first
    upf.send_raw(OTHER, 9, vec![9]);
    upf.send_raw(OTHER, 0, vec![0]);
    assert_eq!(sent(&mut upf).iter().map(|transmit| transmit.octets[0]).collect::<Vec<_>>(), [0, 9]);
}

#[test]
fn response_copies_priority() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, _) = established(&mut smf, &mut upf, at(0));
    let message = Message { header: Header { priority: Some(2), ..Header::session(0, 0) }, body: SessionModificationRequest::default().into() };
    let peer_seid = smf.session(cp_seid).unwrap().peer_seid.unwrap();
    smf.request(at(1), UPF, Message { header: Header { seid: Some(peer_seid), ..message.header }, ..message }).unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (inbound, _) = request(&mut upf);
    assert_eq!((inbound.priority, inbound.prioritized), (2, true));
    upf.respond(at(1), &inbound, SessionModificationResponse::new(accepted())).unwrap();
    let answer = sent(&mut upf).remove(0);
    assert_eq!(answer.priority, 2);
    assert_eq!(decoded(&answer).header.priority, Some(2));
}

// ── §6.2.6 to §6.2.8: associations ──────────────────────────────────────────

#[test]
fn association_setup_by_cp() {
    let (mut smf, mut upf) = (node(SMF, Function::Cp), node(UPF, Function::Up));
    let setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000));
    smf.request(at(0), UPF, Message { header: Header::node(0), body: setup.into() }).unwrap();
    pass(&mut smf, &mut upf, UPF, at(0));
    let (inbound, _) = request(&mut upf);
    assert_eq!(inbound.node_id, Some(node_id(SMF)));
    assert!(upf.association(SMF).is_none(), "the UPF's caller decides");
    upf.respond(at(0), &inbound, AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(1000))).unwrap();
    assert_eq!(upf.association(SMF).map(|association| association.node_id.clone()), Some(node_id(SMF)));
    pass(&mut upf, &mut smf, SMF, at(0));
    let associated = events(&mut smf);
    assert!(associated.contains(&Event::Associated { peer: UPF, node_id: node_id(UPF), replaced: false }));
}

#[test]
fn association_setup_by_up() {
    let (mut smf, mut upf) = (node(SMF, Function::Cp), node(UPF, Function::Up));
    let setup = AssociationSetupRequest::new(node_id(UPF), RecoveryTimeStamp::new(1000));
    upf.request(at(0), SMF, Message { header: Header::node(0), body: setup.into() }).unwrap();
    pass(&mut upf, &mut smf, SMF, at(0));
    let (inbound, _) = request(&mut smf);
    smf.respond(at(0), &inbound, AssociationSetupResponse::new(node_id(SMF), accepted(), RecoveryTimeStamp::new(1000))).unwrap();
    assert!(smf.association(UPF).is_some());
    pass(&mut smf, &mut upf, UPF, at(0));
    assert!(upf.association(SMF).is_some());
    // A rejection makes none
    let mut other = node(OTHER, Function::Up);
    let setup = AssociationSetupRequest::new(node_id(OTHER), RecoveryTimeStamp::new(1));
    other.request(at(0), SMF, Message { header: Header::node(0), body: setup.into() }).unwrap();
    for transmit in sent(&mut other) {
        smf.handle_datagram(at(0), OTHER, &transmit.octets);
    }
    let (inbound, _) = request(&mut smf);
    let rejection = AssociationSetupResponse::new(node_id(SMF), Cause::new(CauseValue::RequestRejected), RecoveryTimeStamp::new(1000));
    smf.respond(at(0), &inbound, rejection).unwrap();
    assert!(smf.association(OTHER).is_none());
}

#[test]
fn association_setup_again() {
    let (mut smf, mut upf) = associated(at(0));
    let setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000));
    smf.request(at(5), UPF, Message { header: Header::node(0), body: setup.into() }).unwrap();
    pass(&mut smf, &mut upf, UPF, at(5));
    let (inbound, _) = request(&mut upf);
    upf.respond(at(5), &inbound, AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(1000))).unwrap();
    assert!(events(&mut upf).contains(&Event::Associated { peer: SMF, node_id: node_id(SMF), replaced: true }));
}

#[test]
fn association_update() {
    let (mut smf, mut upf) = associated(at(0));
    let features = CpFunctionFeatures { load: true, ovrl: true, ..Default::default() };
    let update = AssociationUpdateRequest::new(node_id(SMF)).with_cp_function_features(features);
    smf.request(at(1), UPF, Message { header: Header::node(0), body: update.into() }).unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (inbound, message) = request(&mut upf);
    let Body::AssociationUpdateRequest(update) = &message.body else { panic!() };
    assert!(update.cp_function_features.as_ref().is_some_and(|features| features.ovrl));
    upf.respond(at(1), &inbound, AssociationUpdateResponse::new(node_id(UPF), accepted())).unwrap();
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(smf.association(UPF).is_some() && upf.association(SMF).is_some(), "it stays until a release");
}

#[test]
fn association_update_unknown_node() {
    let mut upf = node(UPF, Function::Up);
    let update = Message { header: Header::node(3), body: AssociationUpdateRequest::new(node_id(SMF)).into() };
    upf.handle_datagram(at(0), SMF, &update.encode().unwrap());
    assert_eq!(violations(&mut upf), [ViolationKind::UnknownNode]);
    let answer = decoded(&sent(&mut upf)[0]);
    assert_eq!(answer.body.cause(), Some(CauseValue::NoEstablishedPfcpAssociation));
    assert_eq!(answer.header.sequence, 3);
}

#[test]
fn association_release() {
    let (mut smf, mut upf) = associated(at(0));
    let release = AssociationReleaseRequest::new(node_id(SMF));
    smf.request(at(1), UPF, Message { header: Header::node(0), body: release.into() }).unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (inbound, _) = request(&mut upf);
    upf.respond(at(1), &inbound, AssociationReleaseResponse::new(node_id(UPF), accepted())).unwrap();
    assert!(upf.association(SMF).is_none());
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(smf.association(UPF).is_none());
    assert!(events(&mut smf).contains(&Event::Released { node_id: node_id(UPF), sessions: vec![] }));
}

#[test]
fn association_release_ends_sessions() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
    let release = AssociationReleaseRequest::new(node_id(SMF));
    smf.request(at(1), UPF, Message { header: Header::node(0), body: release.into() }).unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (inbound, _) = request(&mut upf);
    upf.respond(at(1), &inbound, AssociationReleaseResponse::new(node_id(UPF), accepted())).unwrap();
    assert!(upf.session(up_seid).is_none());
    pass(&mut upf, &mut smf, SMF, at(1));
    assert!(events(&mut smf).contains(&Event::Released { node_id: node_id(UPF), sessions: vec![cp_seid] }));
    assert!(smf.session(cp_seid).is_none());
}

#[test]
fn session_needs_association() {
    let (mut smf, mut upf) = (node(SMF, Function::Cp), node(UPF, Function::Up));
    let seid = smf.new_session(UPF);
    assert_eq!(smf.session_request(at(0), seid, SessionDeletionRequest::default()), Err(NodeError::NoAssociation));
    // A UPF answers a session from a peer without an association
    let f_seid = FSeid { v4: true, seid: Some(0x55), ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)), ..Default::default() };
    let pdr = CreatePdr::new(PdrId::new(1), Precedence::new(1), Pdi::new(SourceInterface::new(SourceInterfaceValue::Access)));
    let far = CreateFar::new(FarId::new(1), ApplyAction { forw: true, ..Default::default() });
    let establishment = Message { header: Header::session(0, 6), body: SessionEstablishmentRequest::new(node_id(SMF), f_seid, pdr, far).into() };
    upf.handle_datagram(at(0), SMF, &establishment.encode().unwrap());
    assert_eq!(violations(&mut upf), [ViolationKind::SessionWithoutAssociation]);
    let answer = decoded(&sent(&mut upf)[0]);
    assert_eq!(answer.body.cause(), Some(CauseValue::NoEstablishedPfcpAssociation));
    assert_eq!(answer.header.seid, Some(0x55), "to the SMF's SEID");
    assert!(answer.check().is_empty(), "{:?}", answer.check());
}

#[test]
fn version_not_supported() {
    let mut upf = node(UPF, Function::Up);
    let mut octets = Message { header: Header::node(8), ..heartbeat() }.encode().unwrap();
    octets[0] = (octets[0] & 0x1f) | 2 << 5;
    upf.handle_datagram(at(0), SMF, &octets);
    let answer = decoded(&sent(&mut upf)[0]);
    assert_eq!(answer.body.message_type(), 11);
    assert_eq!(answer.header.sequence, 8);
    assert!(events(&mut upf).is_empty(), "the request is discarded");
}

/// §6.2.9: a node report, and the session set procedures, run as the other requests:
/// Table 7.3-1 makes 12, 14 and 16 requests, and 13, 15 and 17 their responses.
#[test]
fn node_report_and_session_sets() {
    let (mut smf, mut upf) = associated(at(0));
    events(&mut upf);
    let change = PfcpSessionChangeInfo::new(AlternativeSmfIpAddress { v4: true, ipv4_address: Some(Ipv4Addr::new(10, 0, 0, 9)), ..Default::default() });
    let exchanges: [(bool, Body, Body); 3] = [
        (false, NodeReportRequest::new(node_id(UPF), NodeReportType { uprr: true, ..Default::default() }).into(), NodeReportResponse::new(node_id(SMF), accepted()).into()),
        (false, SessionSetDeletionRequest::new(node_id(UPF)).into(), SessionSetDeletionResponse::new(node_id(SMF), accepted()).into()),
        (true, SessionSetModificationRequest::new(node_id(SMF), change).into(), SessionSetModificationResponse::new(node_id(UPF), accepted()).into()),
    ];
    for (from_smf, body, answer) in exchanges {
        let message_type = body.message_type();
        let (sender, receiver, to, back) = match from_smf {
            true => (&mut smf, &mut upf, UPF, SMF),
            false => (&mut upf, &mut smf, SMF, UPF),
        };
        let id = sender.request(at(1), to, Message { header: Header::node(0), body }).unwrap();
        pass(sender, receiver, to, at(1));
        let (inbound, message) = request(receiver);
        assert_eq!(message.body.message_type(), message_type);
        receiver.respond(at(1), &inbound, answer).unwrap();
        pass(receiver, sender, back, at(1));
        let got = events(sender);
        assert!(matches!(&got[..], [Event::Response { request, message }] if *request == id && message.body.message_type() == message_type + 1), "{got:?}");
    }
}

// ── Sessions ────────────────────────────────────────────────────────────────

#[test]
fn session_establishment_seids() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
    assert_ne!(cp_seid, 0);
    assert_ne!(smf.new_session(UPF), cp_seid, "a SEID of no other session");
    assert_eq!(smf.session(cp_seid).and_then(|session| session.peer_seid), Some(up_seid));
    assert_eq!(upf.session(up_seid).and_then(|session| session.peer_seid), Some(cp_seid));
}

#[test]
fn session_messages_carry_peer_seid() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
    smf.session_request(at(1), cp_seid, SessionModificationRequest::default()).unwrap();
    assert_eq!(decoded(&sent(&mut smf)[0]).header.seid, Some(up_seid));
    upf.session_request(at(1), up_seid, SessionReportRequest::new(ReportType::default())).unwrap();
    assert_eq!(decoded(&sent(&mut upf)[0]).header.seid, Some(cp_seid));
}

#[test]
fn unknown_seid_answered() {
    let (_, mut upf) = associated(at(0));
    let modification = Message { header: Header::session(0xdead, 12), body: SessionModificationRequest::default().into() };
    upf.handle_datagram(at(1), SMF, &modification.encode().unwrap());
    assert_eq!(violations(&mut upf), [ViolationKind::UnknownSeid]);
    let answer = decoded(&sent(&mut upf)[0]);
    assert_eq!(answer.body.cause(), Some(CauseValue::SessionContextNotFound));
    assert_eq!((answer.header.seid, answer.header.sequence), (Some(0), 12));
    assert!(answer.check().is_empty(), "{:?}", answer.check());
}

#[test]
fn session_deletion_ends_session() {
    let (mut smf, mut upf) = associated(at(0));
    let (cp_seid, up_seid) = established(&mut smf, &mut upf, at(0));
    smf.session_request(at(1), cp_seid, SessionDeletionRequest::default()).unwrap();
    pass(&mut smf, &mut upf, UPF, at(1));
    let (inbound, _) = request(&mut upf);
    upf.respond(at(1), &inbound, SessionDeletionResponse::new(accepted())).unwrap();
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
    let modification = |sequence| Message { header: Header::session(up_seid, sequence), body: SessionModificationRequest::default().into() };
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

#[test]
fn bundled_messages_of_one_peer() {
    let (mut smf, mut upf) = associated(at(0));
    let (_, up_seid) = established(&mut smf, &mut upf, at(0));
    let other_seid = upf.new_session(OTHER);
    let modification = |seid, sequence| Message { header: Header::session(seid, sequence), body: SessionModificationRequest::default().into() };
    upf.handle_datagram(at(1), SMF, &bundle(&[modification(up_seid, 20), modification(other_seid, 21)]));
    assert_eq!(violations(&mut upf), [ViolationKind::BundledPeers]);
}

#[test]
fn bundled_node_message_reported() {
    let mut upf = node(UPF, Function::Up);
    upf.handle_datagram(at(0), SMF, &bundle(&[Message { header: Header::node(1), ..heartbeat() }, Message { header: Header::node(2), ..heartbeat() }]));
    assert_eq!(violations(&mut upf), [ViolationKind::BundledNodeMessage, ViolationKind::BundledNodeMessage]);
    assert_eq!(sent(&mut upf).len(), 2, "each is still answered");
}

/// A node sends a Heartbeat Request to each associated peer every interval, says when a
/// peer answers none of N1 retransmissions, and when its Recovery Time Stamp changes.
#[test]
fn heartbeat_toward_associated_peers() {
    let config = NodeConfig { heartbeat: Some(Duration::from_secs(60)), ..config(SMF, Function::Cp) };
    let (mut smf, mut upf) = associated_as(config, at(0));
    assert_eq!(smf.poll_timeout(), Some(at(60)));
    smf.handle_timeout(at(60));
    pass(&mut smf, &mut upf, UPF, at(60));
    pass(&mut upf, &mut smf, SMF, at(60));
    assert!(events(&mut smf).is_empty(), "an answered heartbeat is no event");
    // The UPF restarts: its answer has another Recovery Time Stamp
    smf.handle_timeout(at(120));
    let request = decoded(&sent(&mut smf)[0]);
    let restarted = Message { header: request.header, body: HeartbeatResponse::new(RecoveryTimeStamp::new(4000)).into() };
    smf.handle_datagram(at(121), UPF, &restarted.encode().unwrap());
    assert_eq!(events(&mut smf), [Event::PeerRestarted { peer: UPF, recovery_time_stamp: 4000 }]);
    // Then it answers no more
    smf.handle_timeout(at(180));
    for attempt in 1..=3 {
        smf.handle_timeout(at(180) + T1 * attempt);
    }
    smf.handle_timeout(at(180) + T1 * 4);
    assert!(events(&mut smf).contains(&Event::PeerDown { peer: UPF }));
}
