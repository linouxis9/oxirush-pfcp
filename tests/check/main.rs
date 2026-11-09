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

//! What `check()` and `check_on()` find, with the clause and the Cause of each. A module has the
//! tests of a subject, and this one the helpers that they share.

use std::net::Ipv4Addr;

use oxirush_pfcp::*;

mod conditions;
mod header;
mod interfaces;
mod reading;
mod rejections;
mod tables;
mod values;

const SMF: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

fn pdr(id: u16) -> CreatePdr {
    CreatePdr::new_n4(
        PdrId::new(id),
        Precedence::new(255),
        Pdi::new(SourceInterface::new(SourceInterfaceValue::Access)),
    )
    .with_far_id(FarId::new(1))
}

fn far(id: u32) -> CreateFar {
    let forwarding =
        ForwardingParameters::new(DestinationInterface::new(DestinationInterfaceValue::Core));
    CreateFar::new(
        FarId::new(id),
        ApplyAction {
            forw: true,
            ..Default::default()
        },
    )
    .with_forwarding_parameters(forwarding)
}

fn establishment() -> Message {
    let seid = FSeid::ipv4(0x1001, SMF);
    let request = SessionEstablishmentRequest::new_n4(NodeId::Ipv4(SMF), seid, pdr(1), far(1));
    Message::session(0, 7, request)
}

fn kinds(message: &Message, interface: Interfaces) -> Vec<DeviationKind> {
    message
        .check(interface)
        .into_iter()
        .map(|deviation| deviation.kind)
        .collect()
}

#[test]
fn a_built_establishment_has_no_deviation() {
    let found = establishment().check(Interfaces::N4);
    assert!(found.is_empty(), "{found:?}");
}

fn request_with(message: &mut Message, change: impl FnOnce(&mut SessionEstablishmentRequest)) {
    let Body::SessionEstablishmentRequest(request) = &mut message.body else {
        panic!()
    };
    change(request);
}

/// An IE of `ie_type` and `content`.
fn ie(ie_type: u16, content: &[u8]) -> Vec<u8> {
    [
        &ie_type.to_be_bytes()[..],
        &(content.len() as u16).to_be_bytes(),
        content,
    ]
    .concat()
}

/// A node related message of `message_type` and its IEs.
fn node_message(message_type: u8, ies: &[Vec<u8>]) -> Vec<u8> {
    let body = ies.concat();
    [
        &[0x20, message_type][..],
        &((4 + body.len()) as u16).to_be_bytes(),
        &[0, 0, 1, 0],
        &body,
    ]
    .concat()
}

/// A session related message of `message_type` and its IEs.
fn session_message(message_type: u8, seid: u64, ies: &[Vec<u8>]) -> Vec<u8> {
    let body = ies.concat();
    [
        &[0x21, message_type][..],
        &((12 + body.len()) as u16).to_be_bytes(),
        &seid.to_be_bytes(),
        &[0, 0, 7, 0],
        &body,
    ]
    .concat()
}

/// The deviations of `octets`, with their Causes and Offending IEs.
fn found(octets: &[u8]) -> Vec<(DeviationKind, Option<CauseValue>, Option<u16>)> {
    let message = Message::decode(octets).unwrap();
    assert_eq!(message.encode().unwrap(), octets, "byte for byte");
    message
        .check(Interfaces::N4)
        .into_iter()
        .map(|deviation| {
            (
                deviation.kind.clone(),
                deviation.cause,
                deviation.offending_ie(),
            )
        })
        .collect()
}

const RTS: [u8; 4] = [0xe8, 0x00, 0x00, 0x00];

/// The IEs of an establishment after its Node ID and CP F-SEID: a Create PDR and a
/// Create FAR.
fn rules() -> [Vec<u8>; 2] {
    let pdr = ie(
        1,
        &[
            ie(56, &[0, 1]),
            ie(29, &[0, 0, 0, 255]),
            ie(2, &ie(20, &[0])),
            ie(108, &[0, 0, 0, 1]),
        ]
        .concat(),
    );
    let far = ie(3, &[ie(108, &[0, 0, 0, 1]), ie(44, &[1, 0])].concat());
    [pdr, far]
}
