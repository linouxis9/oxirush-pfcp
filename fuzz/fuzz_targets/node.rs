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
//! their timers. The first octet of the input picks the SMF sets of the nodes; the first
//! octet of each piece of it picks the node, the peer and how far the time moves; the
//! rest is the datagram, or, with the high bit, an operation of the caller that its next
//! octet picks: requests, a move of a session, a probe's answers of each delivery, a
//! forget, a cancel, the setups of strangers, a sequence number reserved and given back.
//! What they send decodes and encodes back to its octets; a datagram gets at most one
//! answer for each of its messages; a timer that is due moves on; nothing panics.
#![no_main]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use oxirush_pfcp::node::{Delivery, Event, Function, Inbound, Node, NodeConfig, RequestId, SmfSet};
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

/// Answer each request of a node with an accepting response, or a rejecting one, as its
/// caller would; with `delivery`, as a probe, twice.
fn answer(node: &mut Node, now: Duration, accepting: bool, delivery: Option<Delivery>, kept: &mut Vec<Inbound>) {
    let cause = Cause::new(if accepting { CauseValue::RequestAccepted } else { CauseValue::RequestRejected });
    let own = node_id(if node.config().function == Function::Cp { SMF } else { UPF });
    while let Some(event) = node.poll_event() {
        let Event::Request { request, message } = event else { continue };
        kept.push(request.clone());
        kept.truncate(16);
        let body: Body = match message.body {
            Body::AssociationSetupRequest(_) => AssociationSetupResponse::new(own.clone(), cause.clone(), RecoveryTimeStamp::new(1)).into(),
            Body::AssociationUpdateRequest(_) => AssociationUpdateResponse::new(own.clone(), cause.clone()).into(),
            Body::AssociationReleaseRequest(_) => AssociationReleaseResponse::new(own.clone(), cause.clone()).into(),
            Body::SessionModificationRequest(_) => SessionModificationResponse::new(cause.clone()).into(),
            Body::SessionDeletionRequest(_) => SessionDeletionResponse::new(cause.clone()).into(),
            Body::SessionReportRequest(_) => SessionReportResponse::new(cause.clone()).into(),
            _ => continue,
        };
        match delivery {
            Some(delivery) => {
                let header = match message.header.seid {
                    Some(seid) => Header::session(seid, request.sequence),
                    None => Header::node(request.sequence),
                };
                let response = Message { header, body };
                let _ = node.respond_message(now, &request, response.clone(), delivery);
                let _ = node.respond_message(now, &request, response, Delivery::Send);
            }
            None => {
                let _ = node.respond(now, &request, body);
            }
        }
    }
}

fuzz_target!(|octets: &[u8]| {
    let sets = octets.first().copied().unwrap_or(0);
    let smf_set = SmfSet { sset: sets & 0x20 != 0, mpas: sets & 0x40 != 0 };
    let config = |address, function| NodeConfig { capacity: 64, strangers: 4, smf_set, ..NodeConfig::new(node_id(address), function, 1) };
    let mut smf = Node::new(config(SMF, Function::Cp));
    let mut upf = Node::new(config(UPF, Function::Up));
    let mut now = Duration::ZERO;
    // The association and a session
    let setup = AssociationSetupRequest::new(node_id(SMF), RecoveryTimeStamp::new(1));
    smf.request(now, UPF, Message { header: Header::node(0), body: setup.into() }).unwrap();
    for (_, datagram) in drain(&mut smf) {
        upf.handle_datagram(now, SMF, &datagram);
    }
    let mut kept = Vec::new();
    let mut sent: Vec<RequestId> = Vec::new();
    answer(&mut upf, now, true, None, &mut kept);
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
        } else {
            let op = datagram.first().copied().unwrap_or(0);
            let arg = u64::from(datagram.get(1).copied().unwrap_or(0));
            match op % 8 {
                0 => {
                    sent.extend(node.session_request(now, seid, SessionReportRequest::new(ReportType { upir: true, ..Default::default() })));
                    sent.extend(node.request(now, from, Message { header: Header::node(0), body: HeartbeatRequest::new(RecoveryTimeStamp::new(1)).into() }));
                }
                // A move of a session to a new SEID, or to one of the arguments
                1 => {
                    let new = match arg % 2 { 0 => node.new_session(UPF), _ => arg };
                    let f_seid = FSeid { v4: true, seid: Some(new), ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)), ..Default::default() };
                    let local = 1 + arg % 4;
                    sent.extend(node.session_request(now, local, SessionModificationRequest::default().with_cp_f_seid(f_seid)));
                }
                2 => {
                    let delivery = [Delivery::Send, Delivery::CacheOnly, Delivery::Forget][(arg % 3) as usize];
                    answer(node, now, op & 8 == 0, Some(delivery), &mut kept);
                    // A later answer of a request answered already
                    if let Some(old) = kept.first().cloned() {
                        let _ = node.respond_message(now, &old, Message { header: Header::node(old.sequence), body: HeartbeatResponse::new(RecoveryTimeStamp::new(1)).into() }, delivery);
                    }
                }
                3 => {
                    while let Some(event) = node.poll_event() {
                        if let Event::Request { request, .. } = event {
                            node.forget(&request);
                        }
                    }
                }
                4 => {
                    if let Some(id) = sent.get(arg as usize % sent.len().max(1)).copied() {
                        node.cancel(now, id);
                    }
                }
                // The setups of strangers, of their own ports
                5 => {
                    for port in 0..(arg % 8) as u16 {
                        let stranger = SocketAddr::new(Ipv4Addr::new(10, 9, 9, port as u8).into(), 8805 + port);
                        let setup = AssociationSetupRequest::new(node_id(stranger), RecoveryTimeStamp::new(1));
                        if let Ok(octets) = (Message { header: Header::node(u32::from(port) + 1), body: setup.into() }).encode() {
                            node.handle_datagram(now, stranger, &octets);
                        }
                    }
                }
                6 => {
                    if let Ok(sequence) = node.reserve_sequence() {
                        if arg % 2 == 0 {
                            assert!(node.release_sequence(sequence));
                        }
                    }
                }
                _ => {
                    let local = node.new_session(UPF);
                    let f_seid = FSeid { v4: true, seid: Some(if arg % 2 == 0 { local } else { arg }), ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)), ..Default::default() };
                    let pdr = CreatePdr::new_n4(PdrId::new(1), Precedence::new(1), Pdi::new(SourceInterface::new(SourceInterfaceValue::Access)));
                    let far = CreateFar::new(FarId::new(1), ApplyAction { forw: true, ..Default::default() });
                    let request = SessionEstablishmentRequest::new_n4(node_id(SMF), f_seid, pdr, far);
                    sent.extend(node.request(now, UPF, Message { header: Header::session(0, 0), body: request.into() }));
                }
            }
            sent.truncate(64);
        }
        answer(node, now, first & 4 == 0, None, &mut kept);
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
