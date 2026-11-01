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

//! An SMF and a UPF, associated, with a session, take any datagram from any peer, and
//! their timers. The first octet of each piece of the input picks the node, the peer and
//! how far the time moves; the rest is the datagram, or, with the high bit, a request or
//! an answer of the caller. What they send decodes and encodes back to its octets; a
//! datagram gets at most one answer for each of its messages; a timer that is due moves
//! on; nothing panics.
#![no_main]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use oxirush_pfcp::node::{Event, Function, Node, NodeConfig};
use oxirush_pfcp::*;

const SMF: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8805);
const UPF: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8805);

fn node_id(address: SocketAddr) -> NodeId {
    match address.ip() {
        std::net::IpAddr::V4(ip) => NodeId::Ipv4(ip),
        std::net::IpAddr::V6(ip) => NodeId::Ipv6(ip),
    }
}

/// What a node sends, checked: it decodes, and encodes back to its octets.
fn drain(node: &mut Node) -> Vec<(SocketAddr, Vec<u8>)> {
    let mut sent = Vec::new();
    while let Some(transmit) = node.poll_transmit() {
        let message = Message::decode(&transmit.octets).expect("what a node sends decodes");
        assert_eq!(message.encode().expect("and encodes"), *transmit.octets);
        sent.push((transmit.to, transmit.octets.0));
    }
    sent
}

/// Answer each request of a node with an accepting response, as its caller would.
fn answer(node: &mut Node, now: Duration, accepting: bool) {
    let cause = Cause::new(if accepting { CauseValue::RequestAccepted } else { CauseValue::RequestRejected });
    let own = node_id(if node.config().function == Function::Cp { SMF } else { UPF });
    while let Some(event) = node.poll_event() {
        let Event::Request { request, message } = event else { continue };
        let body: Body = match message.body {
            Body::AssociationSetupRequest(_) => AssociationSetupResponse::new(own.clone(), cause.clone(), RecoveryTimeStamp::new(1)).into(),
            Body::AssociationUpdateRequest(_) => AssociationUpdateResponse::new(own.clone(), cause.clone()).into(),
            Body::AssociationReleaseRequest(_) => AssociationReleaseResponse::new(own.clone(), cause.clone()).into(),
            Body::SessionModificationRequest(_) => SessionModificationResponse::new(cause.clone()).into(),
            Body::SessionDeletionRequest(_) => SessionDeletionResponse::new(cause.clone()).into(),
            Body::SessionReportRequest(_) => SessionReportResponse::new(cause.clone()).into(),
            _ => continue,
        };
        let _ = node.respond(now, &request, body);
    }
}

fuzz_target!(|octets: &[u8]| {
    let config = |address, function| NodeConfig { capacity: 64, ..NodeConfig::new(node_id(address), function, 1) };
    let mut smf = Node::new(config(SMF, Function::Cp));
    let mut upf = Node::new(config(UPF, Function::Up));
    let mut now = Duration::ZERO;
    // The association and a session
    let setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1));
    smf.request(now, UPF, Message { header: Header::node(0), body: setup.into() }).unwrap();
    for (_, datagram) in drain(&mut smf) {
        upf.handle_datagram(now, SMF, &datagram);
    }
    answer(&mut upf, now, true);
    for (_, datagram) in drain(&mut upf) {
        smf.handle_datagram(now, UPF, &datagram);
    }
    while smf.poll_event().is_some() {}
    let seid = upf.new_session(SMF);
    for piece in octets.split(|octet| *octet == 0xa5) {
        let Some((&first, datagram)) = piece.split_first() else { continue };
        now += Duration::from_millis(u64::from(first >> 3 & 0x0f) * 700);
        let (node, from) = match first & 1 {
            0 => (&mut smf, UPF),
            _ => (&mut upf, SMF),
        };
        let from = if first & 2 == 0 { from } else { SocketAddr::new(Ipv4Addr::new(10, 0, 0, 9).into(), 8805) };
        if first & 0x80 == 0 {
            let messages = Message::decode_datagram(datagram).len();
            node.handle_datagram(now, from, datagram);
            let answers = drain(node).iter().filter(|(to, _)| *to == from).count();
            assert!(answers <= messages, "{answers} answers to {messages} messages");
        } else if first & 4 == 0 {
            let _ = node.session_request(now, seid, SessionReportRequest::new(ReportType { upir: true, ..Default::default() }));
            let _ = node.request(now, from, Message { header: Header::node(0), body: HeartbeatRequest::new(RecoveryTimeStamp::new(1)).into() });
        }
        answer(node, now, first & 4 == 0);
        if let Some(due) = node.poll_timeout()
            && due <= now
        {
            node.handle_timeout(now);
            assert!(node.poll_timeout().is_none_or(|next| next > now), "a timer that is due moves on");
        }
        drain(node);
        while node.poll_event().is_some() {}
    }
});
