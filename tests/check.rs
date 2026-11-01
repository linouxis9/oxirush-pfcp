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

//! What `check()` and `check_on()` find, with the clause and the Cause of each.

use std::net::Ipv4Addr;

use oxirush_pfcp::*;

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
    let seid = FSeid {
        v4: true,
        seid: Some(0x1001),
        ipv4: Some(SMF),
        ..Default::default()
    };
    let request = SessionEstablishmentRequest::new_n4(NodeId::Ipv4(SMF), seid, pdr(1), far(1));
    Message {
        header: Header::session(0, 7),
        body: request.into(),
    }
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

/// Precedence is mandatory in Create PDR on N4 and not on Sxa, which has no row for it.
#[test]
fn check_on_takes_the_rows_of_the_interface() {
    let mut message = establishment();
    let Body::SessionEstablishmentRequest(request) = &mut message.body else {
        panic!()
    };
    request.create_pdr[0].precedence = None;
    let on_n4 = message.check(Interfaces::N4);
    assert_eq!(on_n4.len(), 1, "{on_n4:?}");
    assert_eq!(
        on_n4[0].kind,
        DeviationKind::MandatoryMissing { ie_type: 29 }
    );
    assert_eq!(on_n4[0].path, "/pfcp/Create PDR/0/Precedence");
    assert!(kinds(&message, Interfaces::SXA).is_empty());
    // An IE that the interface does not have.
    request_with(&mut message, |request| {
        request.create_pdr[0].precedence = Some(Precedence::new(1))
    });
    assert_eq!(
        kinds(&message, Interfaces::SXA),
        [DeviationKind::NotOnInterface { ie_type: 29 }]
    );
}

/// The check of a grouped IE on its own is on the interfaces of its table: the IEs that
/// each of them needs are missing from an empty one.
#[test]
fn a_grouped_ie_on_its_own_needs_what_its_interfaces_need() {
    let mut found = Vec::new();
    Check::check(&CreateMar::default(), &Path::Root("/mar"), &mut found);
    let missing: Vec<DeviationKind> = found.into_iter().map(|deviation| deviation.kind).collect();
    assert_eq!(
        missing,
        [
            DeviationKind::MandatoryMissing { ie_type: 170 },
            DeviationKind::MandatoryMissing { ie_type: 171 },
            DeviationKind::MandatoryMissing { ie_type: 172 },
        ]
    );
}

/// A field that rows of several presences share is of the strongest, and on an
/// interface of the presence of its row there: the Source IP Address of an IP Multicast
/// Addressing Info is O on N4 and M on N4mb (Table 7.5.2.2-4), the weakest on both.
#[test]
fn a_shared_field_has_the_presence_of_its_row_on_the_interface() {
    let row = IpMulticastAddressingInfo::table().row_of(192).unwrap();
    assert_eq!(row.presence, Presence::Mandatory);
    assert_eq!(row.presence_on(Interfaces::N4), Presence::Optional);
    assert_eq!(row.presence_on(Interfaces::N4MB), Presence::Mandatory);
    assert_eq!(
        row.presence_on(Interfaces::N4 | Interfaces::N4MB),
        Presence::Optional
    );
    let pdr_id = CreatePdr::table().row_of(56).unwrap();
    assert_eq!(pdr_id.presence_on(Interfaces::N4), pdr_id.presence);
}

/// A set of interfaces is of the bits of the constants, and not empty.
#[test]
fn interfaces_of_their_bits() {
    assert_eq!(Interfaces::from_bits(8), Some(Interfaces::N4));
    assert_eq!(
        Interfaces::from_bits(3),
        Some(Interfaces::SXA | Interfaces::SXB)
    );
    assert_eq!(Interfaces::from_bits(0), None);
    assert_eq!(Interfaces::from_bits(32), None);
    assert_eq!(Interfaces::ALL.bits(), 31);
}

fn request_with(message: &mut Message, change: impl FnOnce(&mut SessionEstablishmentRequest)) {
    let Body::SessionEstablishmentRequest(request) = &mut message.body else {
        panic!()
    };
    change(request);
}

/// §7.2.3.2: the mandatory IE of a mandatory grouped IE is answered with "Mandatory IE
/// missing", that of a conditional one with "Conditional IE missing", and that of an
/// optional one not at all; nor is any of a response.
#[test]
fn the_cause_follows_the_presence_of_the_grouped_ie() {
    let mut message = establishment();
    request_with(&mut message, |request| {
        request.create_pdr[0].pdi.as_mut().unwrap().source_interface = None
    });
    let found = message.check(Interfaces::N4);
    assert_eq!(
        found[0].cause(),
        Some(CauseValue::MandatoryIeMissing),
        "{found:?}"
    );
    assert_eq!(found[0].offending_ie(), Some(20));

    let mut modification = SessionModificationRequest::default().with_create_pdr(pdr(1));
    modification.create_pdr[0].pdr_id = None;
    let message = Message {
        header: Header::session(0x2002, 8),
        body: modification.into(),
    };
    let found = message.check(Interfaces::N4);
    assert_eq!(
        found[0].kind,
        DeviationKind::MandatoryMissing { ie_type: 56 },
        "{found:?}"
    );
    assert_eq!(found[0].cause(), Some(CauseValue::ConditionalIeMissing));

    let mut establishment = establishment();
    request_with(&mut establishment, |request| {
        request.create_bar = Some(Box::default());
    });
    let found = establishment.check(Interfaces::N4);
    assert_eq!(
        found[0].kind,
        DeviationKind::MandatoryMissing { ie_type: 88 },
        "{found:?}"
    );
    assert_eq!(found[0].cause(), None, "an optional grouped IE");

    let response = SessionEstablishmentResponse::default();
    let message = Message {
        header: Header::session(0x1001, 7),
        body: response.into(),
    };
    assert!(
        message
            .check(Interfaces::N4)
            .iter()
            .all(|deviation| deviation.cause().is_none())
    );
}

/// §7.2.3.2: a rejection carries the Cause, the Node ID, the Offending IE, the Load and
/// Overload Control Information and the Failed Rule ID, and lacks the other mandatory IEs.
#[test]
fn a_rejection_carries_only_what_it_may() {
    let response = SessionEstablishmentResponse {
        node_id: Some(NodeId::Ipv4(SMF)),
        cause: Some(Cause::new(CauseValue::MandatoryIeMissing)),
        offending_ie: Some(OffendingIe::new(96)),
        ..Default::default()
    };
    let mut message = Message {
        header: Header::session(0x1001, 7),
        body: response.into(),
    };
    assert!(
        message.check(Interfaces::N4).is_empty(),
        "{:?}",
        message.check(Interfaces::N4)
    );
    let Body::SessionEstablishmentResponse(response) = &mut message.body else {
        panic!()
    };
    response.up_f_seid = Some(FSeid {
        v4: true,
        seid: Some(1),
        ipv4: Some(SMF),
        ..Default::default()
    });
    assert_eq!(
        kinds(&message, Interfaces::N4),
        [DeviationKind::WithRejection { ie_type: 57 }]
    );
}

/// §7.2.2.4.2: SEID 0 in an establishment, or in an answer that rejects; not in a
/// modification, nor in an answer that accepts.
#[test]
fn seid_0_only_where_the_peer_seid_is_not_known() {
    let establishment = establishment();
    assert!(establishment.check(Interfaces::N4).is_empty());
    let modification = Message {
        header: Header::session(0, 8),
        body: SessionModificationRequest::default().into(),
    };
    assert!(
        modification
            .check(Interfaces::N4)
            .iter()
            .any(|deviation| deviation.clause == "7.2.2.4.2")
    );
    let response = SessionModificationResponse {
        cause: Some(Cause::new(CauseValue::SessionContextNotFound)),
        ..Default::default()
    };
    let mut message = Message {
        header: Header::session(0, 8),
        body: response.into(),
    };
    assert!(
        message.check(Interfaces::N4).is_empty(),
        "{:?}",
        message.check(Interfaces::N4)
    );
    let Body::SessionModificationResponse(response) = &mut message.body else {
        panic!()
    };
    response.cause = Some(Cause::new(CauseValue::RequestAccepted));
    assert!(
        message
            .check(Interfaces::N4)
            .iter()
            .any(|deviation| deviation.clause == "7.2.2.4.2")
    );
}

/// Table 7.3-1: PFD management is not on Sxa; a message type of no table is reported.
#[test]
fn a_message_type_of_the_interface() {
    let request = PfdManagementRequest::default();
    let message = Message {
        header: Header::node(3),
        body: request.into(),
    };
    assert!(kinds(&message, Interfaces::N4).is_empty());
    assert_eq!(
        kinds(&message, Interfaces::SXA),
        [DeviationKind::MessageNotOnInterface { message_type: 3 }]
    );
    let other = Message {
        header: Header::node(3),
        body: Body::Other {
            message_type: 99,
            octets: Octets::new(),
        },
    };
    assert_eq!(
        kinds(&other, Interfaces::N4),
        [DeviationKind::UnknownMessage { message_type: 99 }]
    );
}

/// §6.3.3.2: one message does not create, update or remove one rule twice.
#[test]
fn check_one_change_per_rule() {
    let modification = SessionModificationRequest::default()
        .with_create_pdr(pdr(3))
        .with_remove_pdr(RemovePdr::new(PdrId::new(3)))
        .with_create_far(far(4))
        .with_update_far(UpdateFar::new(FarId::new(5)));
    let message = Message {
        header: Header::session(0x2002, 8),
        body: modification.into(),
    };
    assert_eq!(
        kinds(&message, Interfaces::N4),
        [DeviationKind::RuleChangedTwice { rule: "PDR", id: 3 }]
    );
    let mut establishment = establishment();
    request_with(&mut establishment, |request| {
        request.create_far.push(far(1))
    });
    let found = establishment.check(Interfaces::N4);
    assert_eq!(
        found
            .iter()
            .map(|deviation| (deviation.kind.clone(), deviation.clause))
            .collect::<Vec<_>>(),
        [(
            DeviationKind::RuleChangedTwice { rule: "FAR", id: 1 },
            "5.2.1"
        )]
    );
}

/// §8.2.34: a Metric is a percentage, and a receiver takes another value as 0.
#[test]
fn check_overload_reduction_metric() {
    let overload = OverloadControlInformation::new(
        SequenceNumber::new(1),
        Metric::new(Percent(101)),
        Timer {
            timer_unit: TimerUnit::OneMinute,
            timer_value: 1,
            ..Default::default()
        },
    );
    let response = SessionEstablishmentResponse {
        node_id: Some(NodeId::Ipv4(SMF)),
        cause: Some(Cause::new(CauseValue::RequestAccepted)),
        up_f_seid: Some(FSeid {
            v4: true,
            seid: Some(1),
            ipv4: Some(SMF),
            ..Default::default()
        }),
        overload_control_information: Some(Box::new(overload)),
        ..Default::default()
    };
    let message = Message {
        header: Header::session(0x1001, 7),
        body: response.into(),
    };
    assert_eq!(
        kinds(&message, Interfaces::N4),
        [DeviationKind::ReadAs {
            value: 101,
            read: 0
        }]
    );
}

/// §7.6.8: a reserved value is an incorrect IE, a spare one is ignored; Table 8.1.2-1: an
/// IE of a fixed length has that length.
#[test]
fn reserved_values_and_fixed_lengths() {
    let mut message = establishment();
    request_with(&mut message, |request| {
        request.rat_type = Some(RatType::new(RatTypeValue::from_value(0)))
    });
    assert_eq!(
        kinds(&message, Interfaces::N4),
        [DeviationKind::ReservedValue { value: 0 }]
    );
    request_with(&mut message, |request| {
        request.rat_type = Some(RatType::new(RatTypeValue::from_value(200)))
    });
    assert_eq!(
        kinds(&message, Interfaces::N4),
        [DeviationKind::SpareValue { value: 200 }]
    );
    request_with(&mut message, |request| {
        request.rat_type = None;
        request.s_nssai = SNssai::decode(&[1, 0, 0, 1, 9]);
    });
    let found = message.check(Interfaces::N4);
    assert_eq!(
        found[0].kind,
        DeviationKind::FixedLength {
            ie_type: 257,
            length: 5
        },
        "{found:?}"
    );
    assert_eq!(found[0].cause(), None, "an optional IE");
}

/// Table 7.3-1: after 11, Version Not Supported Response, a request has an even type: 12
/// Node Report, 14 Session Set Deletion and 16 Session Set Modification.
#[test]
fn a_request_by_the_name_of_its_type() {
    for info in MESSAGE_TYPES {
        assert_eq!(
            is_request(info.message_type),
            info.name().ends_with(" Request"),
            "{}",
            info.name()
        );
    }
    for message_type in (0..=255).filter(|&message_type| message_type_info(message_type).is_none())
    {
        assert!(!is_request(message_type), "{message_type}");
    }
    let request = Message {
        header: Header::node(1),
        body: NodeReportRequest::default().into(),
    };
    let causes: Vec<_> = request
        .check(Interfaces::N4)
        .iter()
        .map(Deviation::cause)
        .collect();
    assert_eq!(causes, [Some(CauseValue::MandatoryIeMissing); 2]);
    let response = Message {
        header: Header::node(1),
        body: NodeReportResponse::default().into(),
    };
    assert!(
        response
            .check(Interfaces::N4)
            .iter()
            .all(|deviation| deviation.cause().is_none())
    );
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
                deviation.cause(),
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

/// §7.6.10: of an IE that its table has once, the first is handled and the others are
/// ignored; when the first does not decode, the second is not taken in its place.
#[test]
fn the_first_of_a_repeated_ie_is_the_one_handled() {
    // A Node ID shorter than its type, then one that is not
    let octets = node_message(
        5,
        &[ie(60, &[0, 10, 0]), ie(60, &[0, 10, 0, 0, 9]), ie(96, &RTS)],
    );
    let Body::AssociationSetupRequest(request) = Message::decode(&octets).unwrap().body else {
        panic!()
    };
    assert_eq!(
        request.node_id.and_then(|node_id| node_id.effective()),
        None
    );
    assert_eq!(
        found(&octets),
        [
            (DeviationKind::Repeated { ie_type: 60 }, None, None),
            (
                DeviationKind::Rule("a Node ID value shorter than its type"),
                Some(CauseValue::MandatoryIeIncorrect),
                Some(60)
            ),
        ]
    );
    let cut = [2, 0, 0, 0, 0, 0, 0, 0x10, 0x01, 10];
    let whole = [2, 0, 0, 0, 0, 0, 0, 0x10, 0x01, 10, 0, 0, 1];
    let [pdr, far] = rules();
    let octets = session_message(
        50,
        0,
        &[
            ie(60, &[0, 10, 0, 0, 1]),
            ie(57, &cut),
            ie(57, &whole),
            pdr,
            far,
        ],
    );
    assert_eq!(
        found(&octets)[0],
        (
            DeviationKind::MandatoryIncorrect { ie_type: 57 },
            Some(CauseValue::MandatoryIeIncorrect),
            Some(57)
        )
    );
    // An optional IE: the first, which does not decode, is taken as absent
    let octets = node_message(1, &[ie(96, &RTS), ie(96, &RTS[..2]), ie(96, &RTS)]);
    assert_eq!(
        found(&octets),
        [(DeviationKind::Repeated { ie_type: 96 }, None, None); 1]
    );
    let octets = node_message(
        5,
        &[
            ie(60, &[0, 10, 0, 0, 9]),
            ie(96, &RTS),
            ie(107, &[1]),
            ie(107, &[0, 0]),
        ],
    );
    let Body::AssociationSetupRequest(request) = Message::decode(&octets).unwrap().body else {
        panic!()
    };
    assert_eq!(request.up_function_features, None);
}

/// §7.6.8: a mandatory IE whose value is semantically invalid is answered "Mandatory IE
/// incorrect", with its type: a Node ID of a length that its type does not have, an empty
/// FQDN, a spare Node ID Type, an F-SEID with no address.
#[test]
fn a_semantically_invalid_mandatory_ie_is_incorrect() {
    for node_id in [&[0, 10, 0][..], &[2], &[5, 1, 2, 3, 4], &[2, 3, b'u', b'p']] {
        let octets = node_message(5, &[ie(60, node_id), ie(96, &RTS)]);
        let found = found(&octets);
        assert_eq!(found.len(), 1, "{node_id:?}: {found:?}");
        assert_eq!(
            (found[0].1, found[0].2),
            (Some(CauseValue::MandatoryIeIncorrect), Some(60)),
            "{node_id:?}: {found:?}"
        );
    }
    let [pdr, far] = rules();
    let octets = session_message(
        50,
        0,
        &[
            ie(60, &[0, 10, 0, 0, 1]),
            ie(57, &[0, 0, 0, 0, 0, 0, 0, 0x10, 0x01]),
            pdr,
            far,
        ],
    );
    let found = found(&octets);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        (found[0].1, found[0].2),
        (Some(CauseValue::MandatoryIeIncorrect), Some(57)),
        "{found:?}"
    );
    // In a response, no Cause
    let octets = node_message(6, &[ie(60, &[2]), ie(19, &[1]), ie(96, &RTS)]);
    assert!(
        Message::decode(&octets)
            .unwrap()
            .check(Interfaces::N4)
            .iter()
            .all(|deviation| deviation.cause().is_none())
    );
}

/// §7.6.8: an optional IE of a mandatory grouped IE, whose value is reserved, is taken as
/// absent, and the request is answered for what else it has; a conditional one, which the
/// receiver verifies, is answered "Mandatory IE incorrect" with its type.
#[test]
fn a_reserved_value_follows_the_presence_of_its_own_row() {
    let mut message = establishment();
    request_with(&mut message, |request| {
        request.create_pdr[0].rat_type = Some(RatType::new(RatTypeValue::from_value(0)))
    });
    let found = message.check(Interfaces::N4);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        (
            found[0].kind.clone(),
            found[0].cause(),
            found[0].offending_ie()
        ),
        (DeviationKind::ReservedValue { value: 0 }, None, None)
    );
    let mut message = establishment();
    let forwarding = |request: &mut SessionEstablishmentRequest| {
        request.create_far[0]
            .forwarding_parameters
            .as_mut()
            .unwrap()
            .outer_header_creation = Some(OuterHeaderCreation::default())
    };
    request_with(&mut message, forwarding);
    let found = message.check(Interfaces::N4);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        found[0].path,
        "/pfcp/Create FAR/0/Forwarding Parameters/Outer Header Creation"
    );
    assert_eq!(
        (found[0].cause(), found[0].offending_ie()),
        (Some(CauseValue::MandatoryIeIncorrect), Some(84)),
        "{found:?}"
    );
    // An optional IE whose value breaks a rule of its clause is taken as absent too
    let f_teid = FTeid {
        chid: true,
        choose_id: Some(1),
        ..FTeid::ipv4(1, SMF)
    };
    let mut message = establishment();
    request_with(&mut message, |request| {
        request.create_pdr[0].pdi.as_mut().unwrap().local_f_teid = Some(f_teid)
    });
    assert_eq!(
        message
            .check(Interfaces::N4)
            .iter()
            .map(Deviation::cause)
            .collect::<Vec<_>>(),
        [None]
    );
}

/// §8.1.2: an IE of a null length is no error, and a mandatory one is there.
#[test]
fn a_mandatory_ie_of_a_null_length_is_there() {
    assert_eq!(found(&node_message(5, &[ie(60, &[]), ie(96, &RTS)])), []);
    // After a value, it is a repetition, ignored
    assert_eq!(
        found(&node_message(
            5,
            &[ie(60, &[0, 10, 0, 0, 1]), ie(96, &RTS), ie(60, &[])]
        )),
        [(DeviationKind::Repeated { ie_type: 60 }, None, None)]
    );
}

/// §7.6.6: the conditions of the C rows that the message alone shows: in a request,
/// answered with "Conditional IE missing" and the type of the IE; in a response, without
/// a Cause.
#[test]
fn the_conditions_that_a_message_shows() {
    let node = NodeId::Ipv4(SMF);
    let missing = |message: Message, ie_type: u16, cause: Option<CauseValue>| {
        let found = message.check(Interfaces::N4);
        assert_eq!(found.len(), 1, "{message}: {found:?}");
        assert_eq!(
            found[0].kind,
            DeviationKind::ConditionalMissing { ie_type },
            "{message}: {found:?}"
        );
        assert_eq!(
            (found[0].cause(), found[0].offending_ie()),
            (cause, cause.map(|_| ie_type)),
            "{message}: {found:?}"
        );
    };
    // An accepted establishment has the UP F-SEID
    let response =
        SessionEstablishmentResponse::new(node.clone(), Cause::new(CauseValue::RequestAccepted));
    missing(
        Message {
            header: Header::session(0x1001, 7),
            body: response.into(),
        },
        57,
        None,
    );
    // A rejection for a missing or incorrect IE names it
    for cause in [
        CauseValue::MandatoryIeMissing,
        CauseValue::ConditionalIeMissing,
        CauseValue::MandatoryIeIncorrect,
    ] {
        let response = SessionModificationResponse::new(Cause::new(cause));
        missing(
            Message {
                header: Header::session(0x1001, 7),
                body: response.into(),
            },
            40,
            None,
        );
    }
    let response =
        SessionModificationResponse::new(Cause::new(CauseValue::RuleCreationModificationFailure));
    missing(
        Message {
            header: Header::session(0x1001, 7),
            body: response.into(),
        },
        114,
        None,
    );
    let response =
        SessionModificationResponse::new(Cause::new(CauseValue::RequestPartiallyAccepted));
    missing(
        Message {
            header: Header::session(0x1001, 7),
            body: response.into(),
        },
        272,
        None,
    );
    // A report has what its type says
    let report = NodeReportRequest::new(
        node.clone(),
        NodeReportType {
            upfr: true,
            ..Default::default()
        },
    );
    missing(
        Message {
            header: Header::node(1),
            body: report.into(),
        },
        102,
        Some(CauseValue::ConditionalIeMissing),
    );
    let report = SessionReportRequest::new(ReportType {
        dldr: true,
        ..Default::default()
    });
    missing(
        Message {
            header: Header::session(0x1001, 7),
            body: report.into(),
        },
        83,
        Some(CauseValue::ConditionalIeMissing),
    );
    // A FAR that forwards has its Forwarding Parameters, here in a mandatory Create FAR
    let mut message = establishment();
    request_with(&mut message, |request| {
        request.create_far[0].forwarding_parameters = None
    });
    missing(message, 4, Some(CauseValue::ConditionalIeMissing));
    // A URR that reports on a volume threshold has its Volume Threshold
    let urr = CreateUrr::new(
        UrrId::new(1),
        MeasurementMethod {
            volum: true,
            ..Default::default()
        },
        ReportingTriggers {
            volth: true,
            ..Default::default()
        },
    );
    let mut message = establishment();
    request_with(&mut message, |request| request.create_urr.push(urr));
    missing(message, 31, Some(CauseValue::ConditionalIeMissing));
}

/// The rows whose condition `check()` checks are those that say so.
#[test]
fn the_rows_whose_condition_is_checked() {
    let checked: Vec<(&str, &str)> = MESSAGE_TYPES
        .iter()
        .map(|info| info.table)
        .chain(IE_TYPES.iter().flat_map(|info| info.tables.iter().copied()))
        .flat_map(|table| {
            table
                .rows
                .iter()
                .filter(|row| row.checked)
                .map(move |row| (table.id, row.name))
        })
        .collect();
    assert!(checked.contains(&("7.5.3.1-1", "UP F-SEID")), "{checked:?}");
    assert!(checked.iter().all(|(_, name)| !name.is_empty()));
    for info in MESSAGE_TYPES {
        for row in info.table.rows.iter().filter(|row| row.checked) {
            assert_eq!(
                row.presence,
                Presence::Conditional,
                "{} {}",
                info.name(),
                row.name
            );
        }
    }
}

/// EPS CUPS: an SGW-U checks an SGW-C's message on Sxa, a combined SGW/PGW-U on both
/// Sxa and Sxb (§5.2.6), where a message may have the IEs of either and needs those that
/// both need; each interface has its constructor where their mandatory IEs differ.
#[test]
fn eps_cups_on_its_interfaces() {
    let smf = NodeId::Ipv4(SMF);
    let seid = FSeid {
        v4: true,
        seid: Some(0x1001),
        ipv4: Some(SMF),
        ..Default::default()
    };
    let pdi = || Pdi::new(SourceInterface::new(SourceInterfaceValue::Access));
    let buffering = CreateFar::new(
        FarId::new(1),
        ApplyAction {
            buff: true,
            ..Default::default()
        },
    )
    .with_bar_id(BarId::new(1));
    // An SGW-C's establishment: no Precedence, a BAR
    let sxa = SessionEstablishmentRequest::new_sxa(
        smf.clone(),
        seid.clone(),
        CreatePdr::new_sxa(PdrId::new(1), pdi()).with_far_id(FarId::new(1)),
        buffering.clone(),
    )
    .with_create_bar(CreateBar::new(BarId::new(1)));
    let sxa = Message {
        header: Header::session(0, 1),
        body: sxa.into(),
    };
    assert!(
        sxa.check(Interfaces::SXA).is_empty(),
        "{:?}",
        sxa.check(Interfaces::SXA)
    );
    assert!(
        sxa.check(Interfaces::SXA_SXB).is_empty(),
        "{:?}",
        sxa.check(Interfaces::SXA_SXB)
    );
    assert!(
        sxa.check(Interfaces::SXB)
            .iter()
            .any(|deviation| deviation.kind == DeviationKind::MandatoryMissing { ie_type: 29 })
    );
    // A PGW-C's: Precedence, and Aggregated URRs, of Sxb only
    let aggregated = AggregatedURRs::new(
        AggregatedUrrId::new(7),
        Multiplier {
            value_digits: 1,
            exponent: 0,
            extra: Octets::new(),
        },
    );
    let urr = CreateUrr::new(
        UrrId::new(1),
        MeasurementMethod {
            volum: true,
            ..Default::default()
        },
        ReportingTriggers::default(),
    )
    .with_aggregated_urrs(aggregated);
    let forward = CreateFar::new(
        FarId::new(2),
        ApplyAction {
            forw: true,
            ..Default::default()
        },
    )
    .with_forwarding_parameters(ForwardingParameters::new(DestinationInterface::new(
        DestinationInterfaceValue::Core,
    )));
    let sxb = SessionEstablishmentRequest::new_sxb(
        smf.clone(),
        seid.clone(),
        CreatePdr::new_sxb(PdrId::new(2), Precedence::new(1), pdi()).with_far_id(FarId::new(2)),
        forward.clone(),
    )
    .with_create_urr(urr);
    let sxb = Message {
        header: Header::session(0, 2),
        body: sxb.into(),
    };
    assert!(
        sxb.check(Interfaces::SXB).is_empty(),
        "{:?}",
        sxb.check(Interfaces::SXB)
    );
    assert!(
        sxb.check(Interfaces::SXA_SXB).is_empty(),
        "{:?}",
        sxb.check(Interfaces::SXA_SXB)
    );
    assert!(
        sxb.check(Interfaces::SXA)
            .iter()
            .any(|deviation| matches!(deviation.kind, DeviationKind::NotOnInterface { .. }))
    );
    // A combined one: the PDRs and FARs of both, duplicated packets of Sxa and Sxb
    let duplicating = DuplicatingParameters::new(DestinationInterface::new(
        DestinationInterfaceValue::LiFunction,
    ));
    let both = SessionEstablishmentRequest::new_sxa(
        smf,
        seid,
        CreatePdr::new_sxa(PdrId::new(1), pdi()).with_far_id(FarId::new(1)),
        buffering,
    )
    .with_create_pdr(
        CreatePdr::new_sxb(PdrId::new(2), Precedence::new(1), pdi()).with_far_id(FarId::new(2)),
    )
    .with_create_far(
        forward
            .with_apply_action(ApplyAction {
                forw: true,
                dupl: true,
                ..Default::default()
            })
            .with_duplicating_parameters(duplicating),
    )
    .with_create_bar(CreateBar::new(BarId::new(1)));
    let both = Message {
        header: Header::session(0, 3),
        body: both.into(),
    };
    assert!(
        both.check(Interfaces::SXA_SXB).is_empty(),
        "{:?}",
        both.check(Interfaces::SXA_SXB)
    );
    assert!(!both.check(Interfaces::N4).is_empty());
}

/// Messages of each interface and procedure, built, decoded back and checked where they
/// are and where they are not: Sxb modification and report, association update and
/// release, PFD management on Sxb and Sxc, session set deletion with the FQ-CSIDs of
/// its roles, a TDF's establishment on Sxc, an MB-SMF's on N4mb.
#[test]
fn messages_of_each_interface() {
    let node = NodeId::Ipv4(SMF);
    let fq_csid = |node_id_type_address: [u8; 4], csid: u16| FqCsid {
        node_id_type: 0,
        node_address: node_id_type_address.to_vec(),
        csids: vec![csid],
        node_type: None,
        extra: Octets::new(),
    };
    let seid = FSeid {
        v4: true,
        seid: Some(0x1001),
        ipv4: Some(SMF),
        ..Default::default()
    };
    let pdi = || Pdi::new(SourceInterface::new(SourceInterfaceValue::Core));
    let urr = UsageReport::new(
        UrrId::new(1),
        UrSeqn::new(0),
        UsageReportTrigger {
            perio: true,
            ..Default::default()
        },
    );
    let pfd = PfdContents {
        fd: true,
        spare_octet: Some(Spare(0)),
        flow_description: Some(Lv16(b"permit out ip from any to any".to_vec())),
        ..Default::default()
    };
    let cases: Vec<(Message, Interfaces, Option<Interfaces>)> = vec![
        (
            Message {
                header: Header::session(0x2001, 1),
                body: SessionModificationRequest::default()
                    .with_update_far(
                        UpdateFar::new(FarId::new(1)).with_apply_action(ApplyAction {
                            drop: true,
                            ..Default::default()
                        }),
                    )
                    .with_remove_qer(RemoveQer::new(QerId::new(1)))
                    .into(),
            },
            Interfaces::SXB,
            Some(Interfaces::SXA),
        ),
        (
            Message {
                header: Header::session(0x2001, 2),
                body: SessionReportRequest::new(ReportType {
                    usar: true,
                    ..Default::default()
                })
                .with_usage_report(urr)
                .into(),
            },
            Interfaces::SXB,
            None,
        ),
        (
            Message {
                header: Header::node(3),
                body: AssociationUpdateRequest::new(node.clone()).into(),
            },
            Interfaces::SXA,
            None,
        ),
        (
            Message {
                header: Header::node(4),
                body: AssociationReleaseRequest::new(node.clone()).into(),
            },
            Interfaces::SXB,
            None,
        ),
        (
            Message {
                header: Header::node(5),
                body: PfdManagementRequest::default()
                    .with_application_ids_pfds(
                        ApplicationIDsPFDs::new(ApplicationId(b"app".to_vec().into()))
                            .with_pfd_context(PfdContext::new(pfd)),
                    )
                    .into(),
            },
            Interfaces::SXC,
            Some(Interfaces::SXA),
        ),
        (
            Message {
                header: Header::node(6),
                body: SessionSetDeletionRequest::new(node.clone())
                    .with_fq_csid(fq_csid([10, 0, 0, 1], 1))
                    .with_fq_csid(fq_csid([10, 0, 0, 5], 2))
                    .into(),
            },
            Interfaces::SXA,
            Some(Interfaces::SXC),
        ),
        (
            Message {
                header: Header::session(0, 7),
                body: SessionEstablishmentRequest::new_sxc(
                    node.clone(),
                    seid.clone(),
                    CreatePdr::new_sxc(
                        PdrId::new(1),
                        Precedence::new(1),
                        pdi().with_application_id(ApplicationId(b"app".to_vec().into())),
                    ),
                    CreateFar::new(
                        FarId::new(1),
                        ApplyAction {
                            drop: true,
                            ..Default::default()
                        },
                    ),
                )
                .into(),
            },
            Interfaces::SXC,
            Some(Interfaces::SXA),
        ),
        (
            Message {
                header: Header::session(0, 8),
                body: SessionEstablishmentRequest::new_n4mb(
                    node.clone(),
                    seid,
                    CreatePdr::new_n4mb(PdrId::new(1), Precedence::new(1), pdi()),
                    CreateFar::new(
                        FarId::new(1),
                        ApplyAction {
                            drop: true,
                            ..Default::default()
                        },
                    ),
                    MbsSessionN4mbControlInformation::new(MbsSessionIdentifier {
                        tmgi: true,
                        tmgi_field: Some([1, 2, 3, 4, 5, 6]),
                        ..Default::default()
                    }),
                )
                .into(),
            },
            Interfaces::N4MB,
            Some(Interfaces::SXA),
        ),
    ];
    for (message, on, off) in cases {
        let octets = message.encode().unwrap();
        assert_eq!(Message::decode(&octets).unwrap(), message);
        let found = message.check(on);
        assert!(found.is_empty(), "{message} on {on:?}: {found:?}");
        if let Some(off) = off {
            assert!(!message.check(off).is_empty(), "{message} on {off:?}");
        }
    }
    // The FQ-CSIDs of Session Set Deletion: one of each role on the interface
    let mut deletion = SessionSetDeletionRequest::new(node);
    for csid in 0..3 {
        deletion = deletion.with_fq_csid(fq_csid([10, 0, 0, 1], csid));
    }
    let deletion = Message {
        header: Header::node(9),
        body: deletion.into(),
    };
    assert!(deletion.check(Interfaces::SXA).is_empty());
    assert_eq!(
        deletion
            .check(Interfaces::N4)
            .iter()
            .map(|deviation| deviation.kind.clone())
            .collect::<Vec<_>>(),
        [DeviationKind::Repeated { ie_type: 65 }]
    );
}
