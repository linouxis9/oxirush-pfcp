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

//! A UPF and an SMF, which announce the features of an SMF set and the bundling that the
//! first octet of the input picks, with a real session between them; two more SMFs of the
//! set are associated with the UPF. Each
//! piece of the rest of the input, split at 0xa5, is a datagram to one of the nodes from
//! one of its peers or from a stranger, or, with the high bit of its first octet, an
//! operation that its next octets pick: an SMF of the set sets up, establishes, modifies
//! (taking a session over), deletes, updates or releases; the UPF hands a session over
//! with a report of SEID 0, which the SMF may adopt, as a stranger's request may have its
//! session adopted first; a session moves to a new SEID; a
//! request is forgotten, cancelled, or answered late; a sequence number is reserved and
//! given back. Answers accept or reject, through `respond` or as a probe's message of any
//! type and delivery, and a deletion's may say that usage reports follow. What the nodes send each other is delivered. What a node sends
//! decodes and encodes back to its octets; a datagram gets at most one answer for each of
//! its messages; a timer that is due moves on; the load and overload that a node keeps are
//! of its sessions and associations; nothing panics.
#![no_main]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use oxirush_pfcp::node::{
    ControlScope, Delivery, Event, Function, Received, Node, NodeConfig, RequestId,
};
use oxirush_pfcp::*;

const UPF: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8805);
/// The SMFs of the set: the first is the SMF node, the others are addresses only.
const SMFS: [SocketAddr; 3] = [
    SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8805),
    SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 30)), 8805),
    SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)), 8805),
];
const STRANGER: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 8805);

fn node_id(address: SocketAddr) -> NodeId {
    match address.ip() {
        std::net::IpAddr::V4(ip) => NodeId::Ipv4(ip),
        std::net::IpAddr::V6(ip) => NodeId::Ipv6(ip),
    }
}

fn ipv4(address: SocketAddr) -> Ipv4Addr {
    match address.ip() {
        std::net::IpAddr::V4(ip) => ip,
        std::net::IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
    }
}

fn encode(header: Header, body: impl Into<Body>) -> Vec<u8> {
    Message {
        header,
        body: body.into(),
    }
    .encode()
    .unwrap()
}

/// The CP Function Features and the SMF Set ID that `features` and `set` pick.
fn of_set(features: u8) -> (CpFunctionFeatures, SmfSetId) {
    let cp = CpFunctionFeatures {
        sset: features & 1 != 0,
        mpas: features & 2 != 0,
        bundl: features & 8 != 0,
        ..Default::default()
    };
    let id = SmfSetId {
        fqdn: Fqdn(vec![1, b's', b'0' + (features >> 2) % 2].into()),
        ..Default::default()
    };
    (cp, id)
}

fn setup(from: SocketAddr, features: u8) -> Message {
    let (cp, id) = of_set(features);
    let request = AssociationSetupRequest::new(node_id(from), RecoveryTimeStamp::new(1))
        .with_cp_function_features(cp)
        .with_smf_set_id(id);
    Message::node(0, request)
}

fn establishment(from: SocketAddr, cp_seid: u64) -> Message {
    let f_seid = FSeid {
        v4: true,
        seid: cp_seid,
        ipv4: Some(ipv4(from)),
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
    Message::session(0, 0, SessionEstablishmentRequest::new_n4(node_id(from), f_seid, pdr, far))
}

/// What a node keeps of the load and overload of its peers, checked: each is of a session
/// or an association of its address, or of the association of its Node ID.
fn held(node: &Node) {
    let scopes = node.loads().map(|(scope, _)| scope);
    for scope in scopes.chain(node.overloads().map(|(scope, _)| scope)) {
        let held = match &scope {
            ControlScope::Address(address) => {
                node.sessions()
                    .any(|(_, session)| session.peer.ip() == address.ip())
                    || node
                        .associations()
                        .any(|association| association.peer.ip() == address.ip())
            }
            ControlScope::Node(id) => node
                .associations()
                .any(|association| association.node_id.effective().as_ref() == Some(id)),
        };
        assert!(held, "{scope:?} outlives what set it");
    }
}

/// What a node sends, checked: each datagram decodes and encodes back to its octets.
fn pump(node: &mut Node) -> Vec<(SocketAddr, Vec<u8>)> {
    let mut sent = Vec::new();
    while let Some(transmit) = node.poll_transmit() {
        let message = Message::decode(&transmit.octets).expect("what a node sends decodes");
        assert_eq!(message.encode().expect("and encodes"), *transmit.octets);
        sent.push((transmit.to, transmit.octets.0));
    }
    sent
}

/// Deliver to the other node what each node sent to it: the UPF's to the SMF node, the
/// SMF's to the UPF. What goes to the other SMFs of the set, or to a stranger, is lost.
fn deliver(
    upf: &mut Node,
    smf: &mut Node,
    now: Duration,
    sent: Vec<(SocketAddr, Vec<u8>)>,
    by_upf: bool,
) {
    for (to, datagram) in sent {
        match by_upf {
            true if to == SMFS[0] => smf.handle_datagram(now, UPF, &datagram),
            false if to == UPF => upf.handle_datagram(now, SMFS[0], &datagram),
            _ => {}
        }
    }
}

/// Answer each request of a node, accepting or not as `how` says, with `respond` or, as a
/// probe, a message of another type and each delivery. An establishment gets a UP F-SEID,
/// a setup the UP Function Features of a set; a stranger's request may have its session
/// adopted first.
fn answer(node: &mut Node, now: Duration, how: u8, kept: &mut Vec<Received>) {
    let cause = Cause::new(if how & 1 == 0 {
        CauseValue::RequestAccepted
    } else {
        CauseValue::RequestRejected
    });
    let up = node.config().function == Function::Up;
    let own = node_id(if up { UPF } else { SMFS[0] });
    while let Some(event) = node.poll_event() {
        let Event::Request { request, message } = event else {
            continue;
        };
        kept.push(request.clone());
        kept.truncate(16);
        // A stranger's session that the caller takes over, which its answer goes to
        let mut adopted = None;
        if request.stranger && how & 8 != 0 {
            let local = node.new_session();
            node.end_session(local);
            if node.adopt_session(local, request.from, 0x77).is_ok() {
                adopted = Some(local);
            }
        }
        let body: Body = match message.body {
            Body::AssociationSetupRequest(_) => {
                AssociationSetupResponse::new(own.clone(), cause.clone(), RecoveryTimeStamp::new(1))
                    .with_up_function_features(UpFunctionFeatures {
                        sset: how & 2 != 0,
                        mpas: how & 4 != 0,
                        bundl: true,
                        ..Default::default()
                    })
                    .into()
            }
            Body::AssociationUpdateRequest(_) => {
                AssociationUpdateResponse::new(own.clone(), cause.clone()).into()
            }
            Body::AssociationReleaseRequest(_) => {
                AssociationReleaseResponse::new(own.clone(), cause.clone()).into()
            }
            Body::SessionEstablishmentRequest(_) => {
                let seid = node.new_session();
                SessionEstablishmentResponse::new(own.clone(), cause.clone())
                    .with_up_f_seid(FSeid {
                        v4: true,
                        seid,
                        ipv4: Some(ipv4(UPF)),
                        ..Default::default()
                    })
                    .into()
            }
            Body::SessionModificationRequest(_) => {
                SessionModificationResponse::new(cause.clone()).into()
            }
            // Usage reports that follow the deletion (§5.2.2.3.1)
            Body::SessionDeletionRequest(_) => {
                let more = Cause::new(CauseValue::MoreUsageReportToSend);
                let deleted =
                    SessionDeletionResponse::new(if how & 2 != 0 { more } else { cause.clone() });
                match how & 4 {
                    0 => deleted.into(),
                    _ => deleted
                        .with_pfcpsdrsp_flags(PFCPSDRspFlags {
                            puru: true,
                            ..Default::default()
                        })
                        .into(),
                }
            }
            Body::SessionReportRequest(_) => SessionReportResponse::new(cause.clone()).into(),
            _ => continue,
        };
        if how & 0x10 == 0 {
            let _ = match adopted {
                Some(local) => node.respond_as(now, &request, local, body),
                None => node.respond(now, &request, body),
            };
            continue;
        }
        let other: Body = match how >> 5 & 3 {
            0 => body,
            1 => SessionDeletionResponse::new(cause.clone()).into(),
            2 => AssociationReleaseResponse::new(own.clone(), cause.clone()).into(),
            _ => HeartbeatResponse::new(RecoveryTimeStamp::new(1)).into(),
        };
        let header = match message.header.seid {
            Some(seid) => Header::session(seid, request.sequence),
            None => Header::node(request.sequence),
        };
        let delivery =
            [Delivery::Send, Delivery::CacheOnly, Delivery::Forget][usize::from(how >> 6) % 3];
        let response = Message {
            header,
            body: other,
        };
        let _ = node.respond_message(now, &request, response.clone(), delivery);
        // A probe answers again.
        let _ = node.respond_message(now, &request, response, Delivery::Send);
    }
}

/// Answer both nodes, and deliver what they send each other until it settles, twice at
/// most.
fn settle(upf: &mut Node, smf: &mut Node, now: Duration, how: u8, kept: &mut Vec<Received>) {
    for _ in 0..2 {
        answer(upf, now, how, kept);
        answer(smf, now, how, kept);
        let (by_upf, by_smf) = (pump(upf), pump(smf));
        if by_upf.is_empty() && by_smf.is_empty() {
            return;
        }
        deliver(upf, smf, now, by_upf, true);
        deliver(upf, smf, now, by_smf, false);
    }
    answer(upf, now, how, kept);
    answer(smf, now, how, kept);
    pump(upf);
    pump(smf);
}

fuzz_target!(|octets: &[u8]| {
    let sets = octets.first().copied().unwrap_or(0);
    let config = |address, function| NodeConfig {
        capacity: 64,
        strangers: 4,
        keep: Duration::from_secs(5),
        ..NodeConfig::new(node_id(address), function, 1)
    };
    let mut upf = Node::new(config(UPF, Function::Up));
    let mut smf = Node::new(config(SMFS[0], Function::Cp));
    let mut now = Duration::ZERO;
    let mut kept: Vec<Received> = Vec::new();
    let mut sent: Vec<RequestId> = Vec::new();
    // The SMF node sets up its association and establishes a session; the other SMFs of
    // the set set up theirs, with the features of the set.
    // Accepted, through `respond`, with the UP Function Features that the octet picks.
    let features = sets >> 2;
    let accepting = sets & 0x0e;
    let _ = smf.request(now, UPF, setup(SMFS[0], features));
    settle(&mut upf, &mut smf, now, accepting, &mut kept);
    for from in &SMFS[1..] {
        if let Ok(octets) = setup(*from, features).encode() {
            upf.handle_datagram(now, *from, &octets);
        }
    }
    settle(&mut upf, &mut smf, now, accepting, &mut kept);
    let cp_seid = smf.new_session();
    let _ = smf.request(now, UPF, establishment(SMFS[0], cp_seid));
    settle(&mut upf, &mut smf, now, accepting, &mut kept);
    for node in [&mut upf, &mut smf] {
        while node.poll_event().is_some() {}
    }

    for piece in octets.get(1..).unwrap_or(&[]).split(|octet| *octet == 0xa5) {
        let Some((&first, rest)) = piece.split_first() else {
            continue;
        };
        now += Duration::from_millis(u64::from(first >> 3 & 0x0f) * 700);
        let [arg, how, extra] = [0, 1, 2].map(|at| rest.get(at).copied().unwrap_or(0));
        // To the UPF from an SMF of the set or a stranger; to the SMF from the UPF or a
        // stranger.
        let to_upf = first & 1 == 1;
        let from = match (to_upf, first >> 1 & 3) {
            (true, 3) | (false, 2 | 3) => STRANGER,
            (true, which) => SMFS[usize::from(which)],
            (false, _) => UPF,
        };
        if first & 0x80 == 0 {
            let node = if to_upf { &mut upf } else { &mut smf };
            let messages = Message::decode_datagram(rest).len();
            node.handle_datagram(now, from, rest);
            let answers = pump(node);
            let to_peer = answers.iter().filter(|(to, _)| *to == from).count();
            assert!(
                to_peer <= messages,
                "{to_peer} answers to {messages} messages"
            );
            deliver(&mut upf, &mut smf, now, answers, to_upf);
        } else {
            // The op is the high nibble; the low bits pick a session: the sessions of
            // the UPF are 1 and up, and 0 is of none.
            let session = u64::from(arg & 3);
            match arg >> 4 & 0x0f {
                0 => {
                    let octets = setup(from, extra).encode().unwrap();
                    upf.handle_datagram(now, from, &octets);
                }
                1 => {
                    let mut message = establishment(from, u64::from(extra) + 1);
                    message.header.sequence = u32::from(extra) + 1;
                    upf.handle_datagram(now, from, &message.encode().unwrap());
                }
                // A modification from an SMF of the set: with its Node ID, it takes the
                // session over; with a CP F-SEID, it moves it.
                2 => {
                    let mut request = SessionModificationRequest::default();
                    if extra & 1 != 0 {
                        request = request.with_node_id(node_id(from));
                    }
                    if extra & 2 != 0 {
                        request = request.with_cp_f_seid(FSeid {
                            v4: true,
                            seid: u64::from(extra >> 2),
                            ipv4: Some(ipv4(from)),
                            ..Default::default()
                        });
                    }
                    let octets = encode(Header::session(session, u32::from(extra) + 1), request);
                    upf.handle_datagram(now, from, &octets);
                }
                3 => {
                    let octets = encode(
                        Header::session(session, u32::from(extra) + 1),
                        SessionDeletionRequest::default(),
                    );
                    upf.handle_datagram(now, from, &octets);
                }
                4 => {
                    let released = SMFS[usize::from(extra) % 3];
                    let octets = encode(
                        Header::node(u32::from(extra) + 1),
                        AssociationReleaseRequest::new(node_id(released)),
                    );
                    upf.handle_datagram(now, from, &octets);
                }
                5 => {
                    let (cp, id) = of_set(extra);
                    let mut request = AssociationUpdateRequest::new(node_id(from));
                    if extra & 0x10 != 0 {
                        request = request.with_cp_function_features(cp);
                    }
                    if extra & 0x20 != 0 {
                        request = request.with_smf_set_id(id);
                    }
                    let octets = encode(Header::node(u32::from(extra) + 1), request);
                    upf.handle_datagram(now, from, &octets);
                }
                // The UPF hands a session over to the SMF node: SEID 0, with the Old CP
                // F-SEID of the previous SMF.
                6 => {
                    let old = FSeid {
                        v4: true,
                        seid: u64::from(extra),
                        ipv4: Some(ipv4(SMFS[usize::from(extra) % 3])),
                        ..Default::default()
                    };
                    let report = SessionReportRequest::new(ReportType {
                        uisr: true,
                        ..Default::default()
                    })
                    .with_old_cp_f_seid(old);
                    let message = Message::session(0, 0, report);
                    sent.extend(upf.request(now, SMFS[0], message));
                }
                // The UPF reports on a session, as one it deleted or not.
                7 => {
                    let report = SessionReportRequest::new(ReportType {
                        upir: true,
                        ..Default::default()
                    })
                    .with_pfcpsrreq_flags(PFCPSRReqFlags {
                        psdbu: extra & 1 != 0,
                        ..Default::default()
                    });
                    sent.extend(upf.session_request(now, session, report));
                }
                // The SMF moves its session to a new SEID, or to one of the arguments.
                8 => {
                    let new = match extra & 1 {
                        0 => smf.new_session(),
                        _ => u64::from(extra >> 1),
                    };
                    let f_seid = FSeid {
                        v4: true,
                        seid: new,
                        ipv4: Some(ipv4(SMFS[0])),
                        ..Default::default()
                    };
                    let request = SessionModificationRequest::default().with_cp_f_seid(f_seid);
                    sent.extend(smf.session_request(now, 1 + session % 4, request));
                }
                9 => {
                    sent.extend(smf.session_request(
                        now,
                        1 + session % 4,
                        SessionDeletionRequest::default(),
                    ));
                }
                10 => {
                    let _ = upf.end_association(from);
                    if extra & 1 != 0 {
                        let _ = smf.end_association(UPF);
                    }
                }
                11 => {
                    if let Some(old) = kept.get(usize::from(extra) % kept.len().max(1)).cloned() {
                        let node = if old.from == UPF { &mut smf } else { &mut upf };
                        match extra >> 4 & 3 {
                            0 => node.forget(&old),
                            1 => {
                                let _ = node.respond(
                                    now,
                                    &old,
                                    SessionDeletionResponse::new(Cause::new(
                                        CauseValue::RequestAccepted,
                                    )),
                                );
                            }
                            _ => {
                                let late = Message::node(old.sequence, HeartbeatResponse::new(RecoveryTimeStamp::new(1)));
                                let _ = node.respond_message(now, &old, late, Delivery::Send);
                            }
                        }
                    }
                }
                12 => {
                    if let Some(id) = sent.get(usize::from(extra) % sent.len().max(1)).copied() {
                        upf.cancel(now, id);
                        smf.cancel(now, id);
                    }
                }
                13 => {
                    for node in [&mut upf, &mut smf] {
                        if let Ok(sequence) = node.reserve_sequence()
                            && extra & 1 == 0
                        {
                            assert!(node.release_sequence(sequence));
                        }
                    }
                }
                _ => {
                    let due = [upf.poll_timeout(), smf.poll_timeout()]
                        .into_iter()
                        .flatten()
                        .min();
                    if let Some(due) = due {
                        now = now.max(due);
                    }
                }
            }
            sent.truncate(64);
        }
        for node in [&mut upf, &mut smf] {
            if let Some(due) = node.poll_timeout()
                && due <= now
            {
                node.handle_timeout(now);
                assert!(
                    node.poll_timeout().is_none_or(|next| next > now),
                    "a timer that is due moves on"
                );
            }
        }
        settle(&mut upf, &mut smf, now, how, &mut kept);
        for node in [&mut upf, &mut smf] {
            while node.poll_event().is_some() {}
            held(node);
        }
    }
});
