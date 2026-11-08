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
//! A module has the tests of a clause, and this one the helpers that they share.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use oxirush_pfcp::node::*;
use oxirush_pfcp::*;

mod associations;
mod bundles;
mod controls;
mod delivery;
mod sessions;

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
fn request(node: &mut Node) -> (Received, Message) {
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
    set_up(&mut smf, &mut upf, now, cp_features(), up_features());
    events(&mut smf);
    (smf, upf)
}

/// The SMF sets up its association with the UPF at `now`, with `cp` in its CP Function
/// Features, and the UPF accepts it, with `up` in its UP Function Features: those of no
/// feature are not written.
fn set_up(
    smf: &mut Node,
    upf: &mut Node,
    now: Duration,
    cp: CpFunctionFeatures,
    up: UpFunctionFeatures,
) {
    let mut setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1000));
    if cp != cp_features() {
        setup = setup.with_cp_function_features(cp);
    }
    let message = Message::node(0, setup);
    smf.request(now, UPF, message).unwrap();
    pass(smf, upf, UPF, now);
    let (received, _) = request(upf);
    let mut answer = setup_answer();
    if up != up_features() {
        answer = answer.with_up_function_features(up);
    }
    upf.respond(now, &received, answer).unwrap();
    pass(upf, smf, SMF, now);
}

/// CP and UP Function Features of none.
fn cp_features() -> CpFunctionFeatures {
    CpFunctionFeatures::default()
}

fn up_features() -> UpFunctionFeatures {
    UpFunctionFeatures::default()
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
    smf.request(now, UPF, Message::session(0, 0, establishment))
        .unwrap();
    pass(smf, upf, UPF, now);
    let (received, _) = request(upf);
    let up_seid = upf.new_session();
    let up_f_seid = FSeid {
        v4: true,
        seid: Some(up_seid),
        ipv4: Some(address),
        ..Default::default()
    };
    let response =
        SessionEstablishmentResponse::new(node_id(UPF), accepted()).with_up_f_seid(up_f_seid);
    upf.respond(now, &received, response).unwrap();
    pass(upf, smf, SMF, now);
    events(smf);
    (cp_seid, up_seid)
}

fn decoded(transmit: &Transmit) -> Message {
    Message::decode(&transmit.octets).unwrap()
}

fn heartbeat() -> Message {
    Message::node(0, HeartbeatRequest::new(RecoveryTimeStamp::new(1000)))
}

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
    let (received, _) = request(upf);
    upf.respond(now, &received, response).unwrap();
    pass(upf, smf, SMF, now);
}

/// The sequence numbers of the requests that a node gives its caller.
fn sequences(node: &mut Node) -> Vec<u32> {
    events(node)
        .into_iter()
        .filter_map(|event| match event {
            Event::Request { request, .. } => Some(request.sequence),
            _ => None,
        })
        .collect()
}

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

/// An Association Setup Request of `from`, of sequence number `sequence`.
fn setup_of(from: SocketAddr, sequence: u32, stamp: u32) -> Vec<u8> {
    Message::node(
        sequence,
        AssociationSetupRequest::new(node_id(from), RecoveryTimeStamp::new(stamp)),
    )
    .encode()
    .unwrap()
}

fn setup_answer() -> AssociationSetupResponse {
    AssociationSetupResponse::new(node_id(UPF), accepted(), RecoveryTimeStamp::new(1000))
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
    Message::session(
        0,
        0,
        SessionEstablishmentRequest::new_n4(node_id(SMF), f_seid, pdr, far),
    )
}

/// What the node gives of the datagram that `from` sends: whether a request, and a
/// stranger's, or the violations.
fn taken(upf: &mut Node, from: SocketAddr, message: Message) -> Result<bool, Vec<ViolationKind>> {
    upf.handle_datagram(at(1), from, &message.encode().unwrap());
    let got = events(upf);
    let request = got.iter().find_map(|event| match event {
        Event::Request { request, .. } => Some(request.stranger),
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

trait IntoSocket {
    fn into_socket(self, port: u16) -> SocketAddr;
}

impl IntoSocket for Ipv4Addr {
    fn into_socket(self, port: u16) -> SocketAddr {
        SocketAddr::new(self.into(), port)
    }
}
