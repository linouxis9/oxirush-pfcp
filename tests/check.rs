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

/// §7.2.2.4.2 bullet 4, §5.22.2 bullet 4, Table 7.5.8.1-1: a Session Report Request of
/// SEID 0 moves the session to another SMF of the set and carries the Old CP F-SEID of
/// the previous one; one of a known SEID has none.
#[test]
fn a_report_of_seid_0_carries_the_old_cp_f_seid() {
    let old = FSeid {
        v4: true,
        seid: Some(0x1234),
        ipv4: Some(SMF),
        ..Default::default()
    };
    let report = |seid, with_old| {
        let mut body = SessionReportRequest::new(ReportType {
            uisr: true,
            ..Default::default()
        });
        if with_old {
            body = body.with_old_cp_f_seid(old.clone());
        }
        Message {
            header: Header::session(seid, 9),
            body: body.into(),
        }
    };
    // A report of SEID 0 with the Old CP F-SEID, and one of a known SEID without it: fine.
    assert!(report(0, true).check(Interfaces::N4).is_empty());
    assert!(report(0x1001, false).check(Interfaces::N4).is_empty());
    // SEID 0 without the Old CP F-SEID: a deviation.
    assert!(
        report(0, false)
            .check(Interfaces::N4)
            .iter()
            .any(|deviation| deviation.clause == "7.2.2.4.2")
    );
    // A known SEID with the Old CP F-SEID: a deviation.
    assert!(
        report(0x1001, true)
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
/// FQDN, one of more than 255 octets with the trailing zero byte (RFC 1035 §2.3.4), a
/// spare Node ID Type, an F-SEID with no address.
#[test]
fn a_semantically_invalid_mandatory_ie_is_incorrect() {
    let label = [&[63][..], &[b'a'; 63]].concat();
    let long = [&[2][..], &label, &label, &label, &label].concat();
    let fits = [&long[..193], &[61], &[b'a'; 61]].concat();
    assert_eq!(found(&node_message(5, &[ie(60, &fits), ie(96, &RTS)])), []);
    let too_long = [&long[..193], &[62], &[b'a'; 62]].concat();
    for node_id in [
        &[0, 10, 0][..],
        &[2],
        &[5, 1, 2, 3, 4],
        &[2, 3, b'u', b'p'],
        &too_long,
    ] {
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

/// §8.2.43: "Other values of Node-Address Type are reserved", which §7.6.8 makes an
/// incorrect value: a conditional FQ-CSID of one, which only a built value has, is
/// answered "Mandatory IE incorrect".
#[test]
fn a_reserved_node_id_type_of_an_fq_csid_is_incorrect() {
    let mut message = establishment();
    request_with(&mut message, |request| {
        request.fq_csid.push(FqCsid {
            node_id_type: 3,
            node_address: vec![10, 0, 0, 1],
            csids: vec![1],
            node_type: None,
            extra: Octets::new(),
        })
    });
    let found = message.check(Interfaces::N4);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        (
            found[0].kind.clone(),
            found[0].cause(),
            found[0].offending_ie()
        ),
        (
            DeviationKind::ReservedValue { value: 3 },
            Some(CauseValue::MandatoryIeIncorrect),
            Some(65)
        ),
        "{found:?}"
    );
    // It encodes, for a test tool to send, and its receiver keeps it as octets: a
    // conditional IE that does not decode, incorrect all the same
    let octets = message.encode().unwrap();
    let received = Message::decode(&octets).unwrap();
    assert_eq!(received.encode().unwrap(), octets);
    let found: Vec<_> = received
        .check(Interfaces::N4)
        .into_iter()
        .map(|deviation| (deviation.kind, deviation.cause))
        .collect();
    assert_eq!(
        found,
        [(
            DeviationKind::ConditionalIncorrect { ie_type: 65 },
            Some(CauseValue::MandatoryIeIncorrect)
        )]
    );
}

/// §8.2.131: the FQDN of an SMF Set ID is labels as RFC 1035 writes them, without the
/// trailing zero byte, and of 255 octets at most with it: dotted text is none, nor are
/// labels that run past their end or are too many.
#[test]
fn the_fqdn_of_an_smf_set_id_is_labels() {
    let setup = |fqdn: Fqdn| Message {
        header: Header::node(1),
        body: AssociationSetupRequest::new(NodeId::Ipv4(SMF), RecoveryTimeStamp::new(1))
            .with_cp_function_features(CpFunctionFeatures {
                mpas: true,
                ..Default::default()
            })
            .with_smf_set_id(SmfSetId {
                fqdn,
                ..Default::default()
            })
            .into(),
    };
    let label = |length: u8| [&[length][..], &vec![b'a'; usize::from(length)]].concat();
    let labels = |last| [label(63), label(63), label(63), label(last)].concat();
    for (fqdn, broken) in [
        (Fqdn::new("smf.set").unwrap(), false),
        (Fqdn(b"smf.set".to_vec().into()), true),
        (Fqdn(b"\x09set".to_vec().into()), true),
        (Fqdn(Octets::new()), true),
        (Fqdn(labels(61).into()), false),
        (Fqdn(labels(62).into()), true),
    ] {
        let found: Vec<_> = setup(fqdn.clone())
            .check(Interfaces::N4)
            .into_iter()
            .map(|deviation| (deviation.path, deviation.clause, deviation.cause))
            .collect();
        let expected = match broken {
            true => vec![(
                "/pfcp/SMF Set ID".to_string(),
                "8.2.131",
                Some(CauseValue::MandatoryIeIncorrect),
            )],
            false => vec![],
        };
        assert_eq!(found, expected, "{fqdn:?}");
    }
}

/// §7.6.8: a verifiable conditional IE that does not decode is semantically invalid, as one
/// that decodes and breaks a rule of its clause: in a request, "Mandatory IE incorrect"
/// with its type, and so is one of a mandatory list beyond those that it needs. Only an
/// optional IE is taken as absent. Without a Cause in a response, and in an optional
/// grouped IE, whose IEs the receiver takes as optional (§7.2.3.2).
#[test]
fn a_conditional_ie_that_does_not_decode_is_incorrect() {
    let cut = |ie_type, octets: &[u8]| RawIe {
        ie_type,
        enterprise_id: None,
        length: None,
        octets: octets.to_vec().into(),
    };
    let checked = |message: &Message| {
        Message::decode(&message.encode().unwrap())
            .unwrap()
            .check(Interfaces::N4)
            .into_iter()
            .map(|found| {
                let offending = found.offending_ie();
                (found.path, found.kind, found.cause, offending)
            })
            .collect::<Vec<_>>()
    };
    // An Outer Header Creation of GTP-U/UDP/IPv4 cut after its TEID
    let mut message = establishment();
    request_with(&mut message, |request| {
        let forwarding = request.create_far[0]
            .forwarding_parameters
            .as_mut()
            .unwrap();
        forwarding.raw.push(cut(84, &[1, 0, 0, 0, 0, 1]));
    });
    assert_eq!(
        checked(&message),
        [(
            "/pfcp/Create FAR/0/Forwarding Parameters/Outer Header Creation".to_string(),
            DeviationKind::ConditionalIncorrect { ie_type: 84 },
            Some(CauseValue::MandatoryIeIncorrect),
            Some(84)
        )]
    );
    // A mandatory IE that does not decode, alone: the row of the table says it, once
    let mut message = establishment();
    request_with(&mut message, |request| {
        request.cp_f_seid = None;
        request
            .raw
            .push(cut(57, &[2, 0, 0, 0, 0, 0, 0, 0x10, 0x01]));
    });
    assert_eq!(
        checked(&message),
        [(
            "/pfcp/CP F-SEID".to_string(),
            DeviationKind::MandatoryIncorrect { ie_type: 57 },
            Some(CauseValue::MandatoryIeIncorrect),
            Some(57)
        )]
    );
    // A second Create PDR, whose IEs do not frame
    let mut message = establishment();
    request_with(&mut message, |request| {
        request.raw.push(cut(1, &[0, 56, 0, 9]));
    });
    assert_eq!(
        checked(&message),
        [(
            "/pfcp/Create PDR".to_string(),
            DeviationKind::MandatoryIncorrect { ie_type: 1 },
            Some(CauseValue::MandatoryIeIncorrect),
            Some(1)
        )]
    );
    // In an optional Ethernet Packet Filter, an Ethernet Filter ID of two octets
    let mut message = establishment();
    request_with(&mut message, |request| {
        let mut filter = EthernetPacketFilter::default();
        filter.raw.push(cut(138, &[0, 1]));
        let pdi = request.create_pdr[0].pdi.as_mut().unwrap();
        pdi.ethernet_packet_filter.push(filter);
    });
    assert_eq!(
        checked(&message),
        [(
            "/pfcp/Create PDR/0/PDI/Ethernet Packet Filter/0/Ethernet Filter ID".to_string(),
            DeviationKind::ConditionalIncorrect { ie_type: 138 },
            None,
            None
        )]
    );
    // An optional IE is taken as absent: the Ethertype of the filter
    let mut message = establishment();
    request_with(&mut message, |request| {
        let mut filter = EthernetPacketFilter::default();
        filter.raw.push(cut(136, &[8]));
        let pdi = request.create_pdr[0].pdi.as_mut().unwrap();
        pdi.ethernet_packet_filter.push(filter);
    });
    assert_eq!(
        checked(&message),
        [(
            "/pfcp/Create PDR/0/PDI/Ethernet Packet Filter/0/Ethertype".to_string(),
            DeviationKind::Incorrect { ie_type: 136 },
            None,
            None
        )]
    );
    // In a response, a Local F-TEID of Created PDR without its TEID
    let mut created = CreatedPdr::new(PdrId::new(1));
    created.raw.push(cut(21, &[1]));
    let response = Message {
        header: Header::session(0x1001, 7),
        body: SessionEstablishmentResponse::new(
            NodeId::Ipv4(SMF),
            Cause::new(CauseValue::RequestAccepted),
        )
        .with_up_f_seid(FSeid {
            v4: true,
            seid: Some(0x2001),
            ipv4: Some(SMF),
            ..Default::default()
        })
        .with_created_pdr(created)
        .into(),
    };
    assert_eq!(
        checked(&response),
        [(
            "/pfcp/Created PDR/0/F-TEID".to_string(),
            DeviationKind::ConditionalIncorrect { ie_type: 21 },
            None,
            None
        )]
    );
}

/// §8.1.2, §5.6.3: a null length removes an IE that an update provisioned, and its
/// receiver does not treat it as an error. A mandatory IE of a null length, or a
/// conditional one where its condition holds, lacks its value: the sender's deviation,
/// without a Cause. One after a value is a repetition.
#[test]
fn a_needed_ie_of_a_null_length_is_the_senders_deviation() {
    let null = |ie_type| (DeviationKind::NullLength { ie_type }, None, None);
    assert_eq!(
        found(&node_message(5, &[ie(60, &[]), ie(96, &RTS)])),
        [null(60)]
    );
    assert_eq!(found(&node_message(1, &[ie(96, &[])])), [null(96)]);
    assert_eq!(
        found(&node_message(
            5,
            &[ie(60, &[0, 10, 0, 0, 1]), ie(96, &RTS), ie(60, &[])]
        )),
        [(DeviationKind::Repeated { ie_type: 60 }, None, None)]
    );
    let node = ie(60, &[0, 10, 0, 0, 1]);
    let f_seid = ie(57, &[2, 0, 0, 0, 0, 0, 0, 0x10, 0x01, 10, 0, 0, 1]);
    let [pdr, far] = rules();
    assert_eq!(
        found(&session_message(
            50,
            0,
            &[ie(60, &[]), f_seid.clone(), pdr.clone(), far.clone()]
        )),
        [null(60)]
    );
    assert_eq!(
        found(&session_message(
            50,
            0,
            &[node.clone(), ie(57, &[]), pdr, far.clone()]
        )),
        [null(57)]
    );
    let pdr = ie(
        1,
        &[
            ie(56, &[]),
            ie(29, &[0, 0, 0, 255]),
            ie(2, &ie(20, &[0])),
            ie(108, &[0, 0, 0, 1]),
        ]
        .concat(),
    );
    let deviations = Message::decode(&session_message(50, 0, &[node.clone(), f_seid, pdr, far]))
        .unwrap()
        .check(Interfaces::N4);
    let at: Vec<_> = deviations
        .iter()
        .map(|deviation| {
            (
                deviation.path.as_str(),
                deviation.kind.clone(),
                deviation.cause,
            )
        })
        .collect();
    assert_eq!(
        at,
        [(
            "/pfcp/Create PDR/0/PDR ID",
            DeviationKind::NullLength { ie_type: 56 },
            None
        )]
    );
    // A response: its Cause, and the UP F-SEID of an acceptance
    assert_eq!(
        found(&session_message(51, 1, &[node.clone(), ie(19, &[])])),
        [null(19)]
    );
    assert_eq!(
        found(&session_message(51, 1, &[node, ie(19, &[1]), ie(57, &[])])),
        [null(57)]
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

/// The rows of a grouped IE, checked on its own, that are missing where their condition
/// holds.
fn missing_where_shown(value: &impl Check) -> Vec<String> {
    let mut found = Vec::new();
    Check::check(value, &Path::Root(""), &mut found);
    found
        .into_iter()
        .filter(|deviation| matches!(deviation.kind, DeviationKind::ConditionalMissing { .. }))
        .map(|deviation| deviation.path.trim_start_matches('/').to_string())
        .collect()
}

/// The rows that a value has where the conditions of its table have them absent.
fn excluded(value: &impl Check) -> Vec<String> {
    let mut found = Vec::new();
    Check::check(value, &Path::Root(""), &mut found);
    found
        .into_iter()
        .filter(|deviation| matches!(deviation.kind, DeviationKind::Excluded { .. }))
        .map(|deviation| deviation.path.trim_start_matches('/').to_string())
        .collect()
}

/// The absence rules that the IEs beside a row show: "shall not be present if", "shall
/// be absent", "shall not be present together", "exclusive from each other", each where
/// it holds and where it does not, without a Cause (§7.6 has none for them).
#[test]
fn the_absence_rules_that_their_scope_shows() {
    let pdi = || Pdi::new(SourceInterface::new(SourceInterfaceValue::Access));
    let endpoint = TrafficEndpointId::new(1);
    let ue = UeIpAddress {
        v4: true,
        ipv4: Some(SMF),
        ..Default::default()
    };
    let chosen = UeIpAddress {
        chv4: true,
        ..Default::default()
    };
    let instance = NetworkInstance(b"internet".to_vec().into());
    let filter = SdfFilter::default();
    let ethernet = EthernetPacketFilter::default();
    let forwarding =
        || ForwardingParameters::new(DestinationInterface::new(DestinationInterfaceValue::Core));
    let marking = || TransportLevelMarking::new(0x00fc);
    let mar = |functionality| {
        CreateMar::new(
            MarId::new(1),
            SteeringFunctionality::new(functionality),
            SteeringMode::new(SteeringModeValue::ActiveStandby),
        )
    };
    let mode = || TransportMode::new(TransportModeValue::DatagramMode1);
    let cases: Vec<(Vec<String>, &[&str])> =
        vec![
            // Table 7.5.2.2-2: of a Traffic Endpoint ID, none of the four
            (
                excluded(&pdi().with_traffic_endpoint_id(endpoint.clone())),
                &[],
            ),
            (
                excluded(&pdi().with_local_f_teid(FTeid::choose_ipv4())),
                &[],
            ),
            (
                excluded(
                    &pdi()
                        .with_local_f_teid(FTeid::choose_ipv4())
                        .with_local_ingress_tunnel(LocalIngressTunnel::default())
                        .with_network_instance(instance.clone())
                        .with_ue_ip_address(ue.clone())
                        .with_traffic_endpoint_id(endpoint.clone()),
                ),
                &[
                    "Local F-TEID",
                    "Local Ingress Tunnel",
                    "Network Instance",
                    "UE IP address",
                ],
            ),
            // NOTE 3: no SDF Filter beside an Ethernet Packet Filter
            (excluded(&pdi().with_sdf_filter(filter.clone())), &[]),
            (
                excluded(
                    &pdi()
                        .with_sdf_filter(filter)
                        .with_ethernet_packet_filter(ethernet),
                ),
                &["SDF Filter"],
            ),
            // Table 7.5.2.3-2: no Transport Level Marking beside an Extended one
            (
                excluded(&forwarding().with_transport_level_marking(marking())),
                &[],
            ),
            (
                excluded(
                    &forwarding()
                        .with_transport_level_marking(marking())
                        .with_extended_transport_level_marking(
                            ExtendedTransportLevelMarking::default(),
                        ),
                ),
                &["Transport Level Marking"],
            ),
            // Table 7.5.2.8-1: a Transport Mode of MPQUIC alone, and NOTE 2
            (
                excluded(&mar(SteeringFunctionalityValue::MpquicUdp).with_transport_mode(mode())),
                &[],
            ),
            (
                excluded(&mar(SteeringFunctionalityValue::AtsssLl).with_transport_mode(mode())),
                &["Transport Mode"],
            ),
            (
                excluded(
                    &mar(SteeringFunctionalityValue::AtsssLl)
                        .with_threshold_values(Thresholds::default())
                        .with_steering_mode_indicator(SteeringModeIndicator::default()),
                ),
                &["Threshold Values", "Steering Mode Indicator"],
            ),
        ];
    for (found, expected) in cases {
        assert_eq!(found, expected);
    }
    // The Network Instance of a UE IP address that the UP function allocates, without a
    // Traffic Endpoint ID
    assert_eq!(
        missing_where_shown(&pdi().with_ue_ip_address(chosen.clone())),
        ["Network Instance"]
    );
    for present in [
        pdi()
            .with_ue_ip_address(ue)
            .with_ue_ip_address(chosen.clone())
            .with_network_instance(instance),
        pdi()
            .with_ue_ip_address(chosen)
            .with_traffic_endpoint_id(endpoint),
    ] {
        assert!(missing_where_shown(&present).is_empty(), "{present:?}");
    }
    // Table 7.5.4.1-1 NOTE 3: QAURR and the Query URR, exclusive, without a Cause
    let modification = SessionModificationRequest::default()
        .with_pfcpsmreq_flags(PFCPSMReqFlags {
            qaurr: true,
            ..Default::default()
        })
        .with_query_urr(QueryUrr::new(UrrId::new(1)));
    let message = Message {
        header: Header::session(1, 1),
        body: modification.into(),
    };
    let found: Vec<_> = message
        .check(Interfaces::N4)
        .into_iter()
        .map(|deviation| {
            (
                deviation.path,
                deviation.clause,
                deviation.kind,
                deviation.cause,
            )
        })
        .collect();
    assert_eq!(
        found,
        [(
            "/pfcp/Query URR".to_string(),
            "7.5.4.1-1",
            DeviationKind::Excluded { ie_type: 77 },
            None
        )]
    );
}

/// §7.6.6: the conditions of the C rows that the IEs beside them show, each where it
/// holds and where it does not; the NOTEs of Tables 7.4.4.1.3-1, 7.4.5.1.8-1 and 7.5.2.9-5,
/// of one IE or another, as the condition of each on the other.
#[test]
fn the_conditions_that_their_scope_shows() {
    // Table 7.4.4.1-1 and 7.4.4.2-1: an SMF of MPAS gives its SMF Set ID
    let mpas = CpFunctionFeatures {
        mpas: true,
        ..Default::default()
    };
    let setup = AssociationSetupRequest::new(NodeId::Ipv4(SMF), RecoveryTimeStamp::new(1))
        .with_cp_function_features(mpas.clone());
    let message = Message {
        header: Header::node(1),
        body: setup.clone().into(),
    };
    assert_eq!(
        kinds(&message, Interfaces::N4),
        [DeviationKind::ConditionalMissing { ie_type: 180 }]
    );
    let set = SmfSetId {
        fqdn: Fqdn(b"\x03set".to_vec().into()),
        ..Default::default()
    };
    let message = Message {
        header: Header::node(1),
        body: setup.with_smf_set_id(set).into(),
    };
    assert_eq!(kinds(&message, Interfaces::N4), []);
    let response = AssociationSetupResponse::new(
        NodeId::Ipv4(SMF),
        Cause::new(CauseValue::RequestAccepted),
        RecoveryTimeStamp::new(1),
    )
    .with_cp_function_features(mpas);
    let message = Message {
        header: Header::node(1),
        body: response.into(),
    };
    assert_eq!(
        kinds(&message, Interfaces::N4),
        [DeviationKind::ConditionalMissing { ie_type: 180 }]
    );
    // Table 7.4.4.1.2-1: the thresholds of what the Clock Drift Control Information asks
    let mut clock = ClockDriftControlInformation {
        requested_clock_drift_information: Some(RequestedClockDriftInformation {
            rrto: true,
            rrcr: true,
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(
        missing_where_shown(&clock),
        ["Time Offset Threshold", "Cumulative rateRatio Threshold"]
    );
    clock.requested_clock_drift_information = Some(RequestedClockDriftInformation {
        rrcr: true,
        ..Default::default()
    });
    assert_eq!(
        missing_where_shown(&clock),
        ["Cumulative rateRatio Threshold"]
    );
    // Table 7.4.4.1.3-1: a periodic report has its period; a peer or an interface type
    let mut path = GtpUPathQoSControlInformation {
        qos_report_trigger: Some(QoSReportTrigger {
            per: true,
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(
        missing_where_shown(&path),
        [
            "Remote GTP-U Peer",
            "GTP-U Path Interface Type",
            "Measurement Period"
        ]
    );
    path.gtp_u_path_interface_type = Some(GtpUPathInterfaceType {
        n3: true,
        ..Default::default()
    });
    path.measurement_period = Some(MeasurementPeriod::new(10));
    assert_eq!(missing_where_shown(&path), Vec::<String>::new());
    path.gtp_u_path_interface_type = None;
    path.remote_gtp_u_peer.push(RemoteGtpUPeer::default());
    assert_eq!(missing_where_shown(&path), Vec::<String>::new());
    // Table 7.4.4.1.4-1: a periodic N6 delay measurement has its period
    let mut n6 = N6DelayMeasurementControlInformation {
        measurement_reporting_type: Some(MeasurementReportingType {
            per: true,
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(missing_where_shown(&n6), ["Measurement Period"]);
    n6.measurement_reporting_type = Some(MeasurementReportingType {
        evt: true,
        ..Default::default()
    });
    assert_eq!(missing_where_shown(&n6), Vec::<String>::new());
    // Table 7.4.5.1.8-1: an N6 delay report has its information or its failure
    let mut report = N6DelayMeasurementReport::default();
    assert_eq!(
        missing_where_shown(&report),
        [
            "N6 Delay Measurement Information",
            "N6 Delay Measurement Failure Information"
        ]
    );
    report.n6_delay_measurement_failure_information =
        Some(N6DelayMeasurementFailureInformation::default());
    assert_eq!(missing_where_shown(&report), Vec::<String>::new());
    // Table 7.5.2.2-1: a PDR without a predefined rule or a MAR has its FAR
    let mut pdr = CreatePdr::new_n4(
        PdrId::new(1),
        Precedence::new(1),
        Pdi::new(SourceInterface::new(SourceInterfaceValue::Access)),
    );
    assert_eq!(missing_where_shown(&pdr), ["FAR ID"]);
    pdr.mar_id = Some(MarId::new(1));
    assert_eq!(missing_where_shown(&pdr), Vec::<String>::new());
    pdr.mar_id = None;
    pdr.activate_predefined_rules
        .push(ActivatePredefinedRules(b"rule".to_vec().into()));
    assert_eq!(missing_where_shown(&pdr), Vec::<String>::new());
    // Tables 7.5.2.2-8 and 7.5.2.2-9: an RTP header extension has its ID, an RTP payload
    // format its payload type
    let extension = RtpHeaderExtensionInformation {
        rtp_header_extension_type: Some(RtpHeaderExtensionType::default()),
        ..Default::default()
    };
    assert_eq!(missing_where_shown(&extension), ["RTP Header Extension ID"]);
    let payload = RtpPayloadInformation {
        rtp_payload_format: Some(RtpPayloadFormat::default()),
        ..Default::default()
    };
    assert_eq!(missing_where_shown(&payload), ["RTP Payload Type"]);
    // Table 7.5.2.3-1: a FAR that forwards and duplicates for redundant transmission
    let mut far = far(1);
    far.apply_action = Some(ApplyAction {
        forw: true,
        dfrt: true,
        ..Default::default()
    });
    assert_eq!(
        missing_where_shown(&far),
        ["Redundant Transmission Forwarding Parameters"]
    );
    far.forwarding_parameters = None;
    assert_eq!(missing_where_shown(&far), ["Forwarding Parameters"]);
    // Table 7.5.2.3-2: forwarding to SGi-LAN/N6-LAN has a Forwarding Policy
    let forwarding = ForwardingParameters::new(DestinationInterface::new(
        DestinationInterfaceValue::SgiLanN6Lan,
    ));
    assert_eq!(missing_where_shown(&forwarding), ["Forwarding Policy"]);
    let forwarding =
        ForwardingParameters::new(DestinationInterface::new(DestinationInterfaceValue::Core));
    assert_eq!(missing_where_shown(&forwarding), Vec::<String>::new());
    // Table 7.5.2.3-9: a header handling without a reference says it all
    let mut handling = HeaderHandlingControlInformation {
        header_handling_control_id: Some(HeaderHandlingControlId::default()),
        ..Default::default()
    };
    assert_eq!(
        missing_where_shown(&handling),
        [
            "Header Handling Action",
            "Header Information",
            "Header Value",
            "Header Handling Condition"
        ]
    );
    handling.header_handling_control_reference = Some(HeaderHandlingControlReference::default());
    assert_eq!(missing_where_shown(&handling), Vec::<String>::new());
    // Table 7.5.2.8-1: an MPQUIC steering functionality has its transport mode
    let mar = |value| CreateMar {
        steering_functionality: Some(SteeringFunctionality {
            steering_functionality_value: value,
            ..Default::default()
        }),
        ..Default::default()
    };
    for value in [
        SteeringFunctionalityValue::MpquicUdp,
        SteeringFunctionalityValue::MpquicIp,
        SteeringFunctionalityValue::MpquicE,
    ] {
        assert_eq!(missing_where_shown(&mar(value)), ["Transport Mode"]);
    }
    assert_eq!(
        missing_where_shown(&mar(SteeringFunctionalityValue::Mptcp)),
        Vec::<String>::new()
    );
    // Table 7.5.2.9-3: periodic QoS monitoring has its period, event triggered its minimum
    // wait time, and of congestion or data rate its thresholds
    let monitoring = |frequency, requested| QoSMonitoringPerQoSFlowControlInformation {
        reporting_frequency: Some(frequency),
        requested_qos_monitoring: Some(requested),
        ..Default::default()
    };
    let periodic = ReportingFrequency {
        perio: true,
        ..Default::default()
    };
    let event = ReportingFrequency {
        evett: true,
        ..Default::default()
    };
    let delay = RequestedQoSMonitoring {
        dlpd: true,
        ..Default::default()
    };
    assert_eq!(
        missing_where_shown(&monitoring(periodic, delay.clone())),
        ["Measurement Period"]
    );
    assert_eq!(
        missing_where_shown(&monitoring(event.clone(), delay)),
        ["Minimum Wait Time"]
    );
    for requested in [
        RequestedQoSMonitoring {
            ulci: true,
            ..Default::default()
        },
        RequestedQoSMonitoring {
            dldr: true,
            ..Default::default()
        },
    ] {
        assert_eq!(
            missing_where_shown(&monitoring(event.clone(), requested)),
            ["Minimum Wait Time", "Reporting Thresholds"]
        );
    }
    // Table 7.5.2.9-5: a period or a threshold
    let mut traffic = TrafficParameterMeasurementControlInformation::default();
    assert_eq!(
        missing_where_shown(&traffic),
        ["Measurement Period", "Traffic Parameter Threshold"]
    );
    traffic.measurement_period = Some(MeasurementPeriod::new(10));
    assert_eq!(missing_where_shown(&traffic), Vec::<String>::new());
    // Tables 7.5.5.2-1, 7.5.7.2-1 and 7.5.8.3-1: a usage report has its start and end
    // times, but of the start or stop of traffic, or of MAC addresses
    let periodic = UsageReportTrigger {
        perio: true,
        ..Default::default()
    };
    let start = UsageReportTrigger {
        start: true,
        ..Default::default()
    };
    let times = ["Start Time", "End Time"];
    let report = |trigger| UsageReport::new(UrrId::new(1), UrSeqn::new(0), trigger);
    assert_eq!(missing_where_shown(&report(periodic.clone())), times);
    assert_eq!(
        missing_where_shown(&report(start.clone())),
        Vec::<String>::new()
    );
    for trigger in [
        UsageReportTrigger {
            stopt: true,
            ..Default::default()
        },
        UsageReportTrigger {
            macar: true,
            ..Default::default()
        },
    ] {
        assert_eq!(missing_where_shown(&report(trigger)), Vec::<String>::new());
    }
    let modification = UsageReportModification {
        usage_report_trigger: Some(periodic.clone()),
        ..Default::default()
    };
    assert_eq!(missing_where_shown(&modification), times);
    let deletion = UsageReportDeletion {
        usage_report_trigger: Some(periodic),
        ..Default::default()
    };
    assert_eq!(missing_where_shown(&deletion), times);
    let deletion = UsageReportDeletion {
        usage_report_trigger: Some(start),
        ..Default::default()
    };
    assert_eq!(missing_where_shown(&deletion), Vec::<String>::new());
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
        ReportingTriggers {
            start: true,
            ..Default::default()
        },
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
    )
    .with_start_time(StartTime::new(1))
    .with_end_time(EndTime::new(2));
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
                    )
                    .with_far_id(FarId::new(1)),
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
                    CreatePdr::new_n4mb(PdrId::new(1), Precedence::new(1), pdi())
                        .with_far_id(FarId::new(1)),
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

/// What the flags of a UE IP Address (§8.2.62) and an F-TEID (§8.2.3), and the SEID of an
/// establishment (§7.2.2.4.2), do not let a message have.
#[test]
fn flags_and_seids_that_do_not_go_together() {
    let establishment = |seid, pdi: Vec<u8>| {
        let pdr = ie(
            1,
            &[ie(56, &[0, 1]), ie(29, &[0, 0, 0, 255]), ie(2, &pdi)].concat(),
        );
        let far = ie(3, &[ie(108, &[0, 0, 0, 1]), ie(44, &[1, 0])].concat());
        let node = ie(60, &[0, 10, 0, 0, 1]);
        let f_seid = ie(57, &[2, 0, 0, 0, 0, 0, 0, 0, 1, 10, 0, 0, 1]);
        session_message(50, seid, &[node, f_seid, pdr, far])
    };
    let rules = |octets: &[u8]| -> Vec<&'static str> {
        found(octets)
            .into_iter()
            .filter_map(|(kind, ..)| match kind {
                DeviationKind::Rule(rule) => Some(rule),
                _ => None,
            })
            .collect()
    };
    let source = ie(20, &[0]);
    // IP6PL and IPv6D, without V6 or CHV6
    let ue_ip = ie(93, &[0x48, 4, 64]);
    assert_eq!(
        rules(&establishment(0, [source.clone(), ue_ip].concat())),
        [
            "IPv6D is set and neither V6 nor CHV6 is",
            "IP6PL is set and neither V6 nor CHV6 is",
            "IP6PL and IPv6D are both set",
        ]
    );
    // CH with a TEID after the flags
    let f_teid = ie(21, &[0x05, 0, 0, 0, 1]);
    assert_eq!(
        rules(&establishment(0, [source.clone(), f_teid].concat())),
        ["CH is set, and octets of a TEID or an address follow"]
    );
    // CH and CHID, with a TEID and an address placed before the CHOOSE ID: the octets of
    // a TEID and an address are flagged here too (CHID does not exempt them).
    let f_teid = ie(21, &[0x0d, 0, 0, 0, 1, 10, 0, 0, 2, 7]);
    assert_eq!(
        rules(&establishment(0, [source.clone(), f_teid].concat())),
        ["CH is set, and octets of a TEID or an address follow"]
    );
    // An establishment of SEID 5
    assert_eq!(
        rules(&establishment(5, source)),
        ["a Session Establishment Request of a SEID other than 0"]
    );
}

/// Unknown octets after an Extendable IE pass (§8.1.2), but those of a TEID and the
/// addresses after an F-TEID with CH; and an establishment's SEID other than 0 is of
/// N4mb, on N4mb or on a set with it.
#[test]
fn what_the_new_rules_let_pass() {
    let rules = |octets: &[u8], interface: Interfaces| -> Vec<&'static str> {
        let message = Message::decode(octets).unwrap();
        message
            .check(interface)
            .into_iter()
            .filter_map(|deviation| match deviation.kind {
                DeviationKind::Rule(rule) => Some(rule),
                _ => None,
            })
            .collect()
    };
    let establishment = |seid, pdi: Vec<u8>| {
        let pdr = ie(
            1,
            &[ie(56, &[0, 1]), ie(29, &[0, 0, 0, 255]), ie(2, &pdi)].concat(),
        );
        let far = ie(3, &[ie(108, &[0, 0, 0, 1]), ie(44, &[1, 0])].concat());
        let node = ie(60, &[0, 10, 0, 0, 1]);
        let f_seid = ie(57, &[2, 0, 0, 0, 0, 0, 0, 0, 1, 10, 0, 0, 1]);
        session_message(50, seid, &[node, f_seid, pdr, far])
    };
    let source = ie(20, &[0]);
    // CH, CHID and its CHOOSE ID, then an octet of a later release
    let later = ie(21, &[0x0d, 7, 0xaa]);
    assert!(
        rules(
            &establishment(0, [source.clone(), later].concat()),
            Interfaces::N4
        )
        .is_empty()
    );
    // CH and V4, then a TEID and an IPv4 address
    let teid = ie(21, &[0x05, 0, 0, 0, 1, 10, 0, 0, 2]);
    assert_eq!(
        rules(
            &establishment(0, [source.clone(), teid].concat()),
            Interfaces::N4
        ),
        ["CH is set, and octets of a TEID or an address follow"]
    );
    for interface in [Interfaces::N4MB, Interfaces::N4 | Interfaces::N4MB] {
        assert!(rules(&establishment(5, source.clone()), interface).is_empty());
    }
}

/// §8.2.56: at least one bit of the Outer Header Creation Description is set, of its
/// octets 5 and 6. The OHC of an MB-UPF's FSSM FAR has only 6/3, "Low Layer SSM and
/// C-TEID", which NOTE 7 of Table 8.2.56-1 gives no TEID, address or port (Table
/// 7.5.2.3-5): it is no deviation, nor is 6/1 or 6/2 alone. None at all is one.
#[test]
fn an_outer_header_creation_of_octet_6_alone() {
    let of = |creation: OuterHeaderCreation| {
        let forwarding =
            ForwardingParameters::new(DestinationInterface::new(DestinationInterfaceValue::Core))
                .with_outer_header_creation(creation);
        let mut message = establishment();
        if let Body::SessionEstablishmentRequest(request) = &mut message.body {
            request.create_far[0].forwarding_parameters = Some(forwarding);
        }
        let octets = message.encode().unwrap();
        Message::decode(&octets)
            .unwrap()
            .check(Interfaces::N4 | Interfaces::N4MB)
            .into_iter()
            .filter(|deviation| deviation.clause == "8.2.56")
            .map(|deviation| deviation.kind)
            .collect::<Vec<_>>()
    };
    let low_layer_ssm = OuterHeaderCreation {
        low_layer_ssm_and_c_teid: true,
        ..Default::default()
    };
    assert_eq!(of(low_layer_ssm), []);
    let n19 = OuterHeaderCreation {
        n19_indication: true,
        ..Default::default()
    };
    assert_eq!(of(n19), []);
    assert_eq!(
        of(OuterHeaderCreation::default()),
        [DeviationKind::Rule("no bit of the description is set")]
    );
}

/// The rules of clause 8.2 on which flags go together, in messages (tests/spec/flag-rules.tsv
/// has each): an Apply Action of no action or of two, a Report Type, a Measurement Method,
/// Reporting Triggers and a Node Report Type of no bit. Each in a mandatory IE of a request
/// is answered "Mandatory IE incorrect", with the IE.
#[test]
fn the_flag_rules_of_clause_8_2_in_a_message() {
    let rules = |message: &Message| -> Vec<(&'static str, &'static str, Option<CauseValue>)> {
        let octets = message.encode().unwrap();
        Message::decode(&octets)
            .unwrap()
            .check(Interfaces::N4)
            .into_iter()
            .filter_map(|deviation| match deviation.kind {
                DeviationKind::Rule(rule) => Some((deviation.clause, rule, deviation.cause())),
                _ => None,
            })
            .collect()
    };
    let incorrect = Some(CauseValue::MandatoryIeIncorrect);
    for (action, rule) in [
        (
            ApplyAction::default(),
            "none, or more than one, of DROP, FORW, BUFF, IPMA, IPMD, and FSSM or MBSU is set",
        ),
        (
            ApplyAction {
                drop: true,
                forw: true,
                ..Default::default()
            },
            "none, or more than one, of DROP, FORW, BUFF, IPMA, IPMD, and FSSM or MBSU is set",
        ),
        (
            ApplyAction {
                forw: true,
                nocp: true,
                ..Default::default()
            },
            "NOCP or BDPN is set and BUFF is not",
        ),
        (
            ApplyAction {
                drop: true,
                dfrt: true,
                ..Default::default()
            },
            "DFRT is set and FORW is not",
        ),
    ] {
        let mut message = establishment();
        if let Body::SessionEstablishmentRequest(request) = &mut message.body {
            request.create_far[0].apply_action = Some(action);
            request.create_far[0].forwarding_parameters = None;
        }
        let found = rules(&message);
        assert_eq!(found, [("8.2.26", rule, incorrect)], "{rule}");
    }
    let report = Message {
        header: Header::session(5, 1),
        body: SessionReportRequest::new(ReportType::default()).into(),
    };
    assert_eq!(rules(&report), [("8.2.21", "no bit is set", incorrect)]);
    let urr = CreateUrr::new(
        UrrId::new(1),
        MeasurementMethod::default(),
        ReportingTriggers::default(),
    );
    let modification = Message {
        header: Header::session(5, 1),
        body: SessionModificationRequest::default()
            .with_create_urr(urr)
            .into(),
    };
    assert_eq!(
        rules(&modification),
        [
            ("8.2.40", "no bit is set", incorrect),
            ("8.2.19", "no bit is set", incorrect)
        ]
    );
    let node = Message {
        header: Header::node(1),
        body: NodeReportRequest::new(NodeId::Ipv4(SMF), NodeReportType::default()).into(),
    };
    assert_eq!(rules(&node), [("8.2.69", "no bit is set", incorrect)]);
}

/// What check() finds in a value of `octets`, which encodes back to them.
fn value_found<T: Codec + Check>(octets: &str) -> Vec<(&'static str, DeviationKind)> {
    let octets = hex::decode(octets).unwrap();
    let value = T::decode(&octets).unwrap();
    let mut again = Vec::new();
    value.encode(&mut again).unwrap();
    assert_eq!(again, octets);
    let mut found = Vec::new();
    value.check(&Path::Root("/value"), &mut found);
    found
        .into_iter()
        .map(|deviation| (deviation.clause, deviation.kind))
        .collect()
}

/// §8.2.5: an SDF Filter of SMMII has at least one (S)RTP Multiplexed Media Identification
/// Information, and one of neither the Payload Type nor the RTCP Packet Type, which is of
/// both RTP and RTCP (NOTE 4), has the SSRC or the Media Identification Tag.
#[test]
fn the_media_identifications_of_an_sdf_filter() {
    let none = "SMMII is set with no (S)RTP Multiplexed Media Identification Information";
    let empty = "an (S)RTP and (S)RTCP media identification has neither SSRC nor a Media Identification Tag";
    for (octets, rule) in [
        ("200000", none),
        ("200001000100", empty),
        ("2000010000", empty),
    ] {
        assert_eq!(
            value_found::<SdfFilter>(octets),
            [("8.2.5", DeviationKind::Rule(rule))],
            "{octets}"
        );
    }
    // An SSRC, of RTP and RTCP; a Payload Type, of RTP alone; two media identifications
    for octets in [
        "20000100050100000001",
        "2000010002027f",
        "200002000501000000010002027f",
    ] {
        assert_eq!(value_found::<SdfFilter>(octets), [], "{octets}");
    }
}

/// §8.2.168: bit 3 of Reporting Frequency is reserved, "set to "0" by the sender" and
/// ignored by the receiver: set, it is a deviation as a spare bit is, which the receiver
/// ignores.
#[test]
fn the_reserved_bit_of_reporting_frequency() {
    let reserved = || ("8.2.168", DeviationKind::SpareBits);
    assert_eq!(value_found::<ReportingFrequency>("05"), [reserved()]);
    assert_eq!(
        value_found::<ReportingFrequency>("04"),
        [
            reserved(),
            ("8.2.168", DeviationKind::Rule("no bit is set"))
        ]
    );
    assert_eq!(value_found::<ReportingFrequency>("03"), []);
}

/// §8.1.2, §8.2.27 and §8.2.214: the Paging Policy Indication value and the QFI of a
/// Downlink Data Service Information, and each DSCP value of a DSCP to PPI Mapping
/// Information, have the six low bits of their octet, whose two others are spare; and "X
/// shall not be larger than 63" of the DSCP values.
#[test]
fn the_spare_bits_of_an_octet_of_six_bits() {
    let spare = || ("8.1.2", DeviationKind::SpareBits);
    assert_eq!(
        value_found::<DownlinkDataServiceInformation>("01c1"),
        [spare()]
    );
    assert_eq!(
        value_found::<DownlinkDataServiceInformation>("0241"),
        [spare()]
    );
    assert_eq!(value_found::<DownlinkDataServiceInformation>("033f3f"), []);
    assert_eq!(
        value_found::<DscpToPpiMappingInformation>("01c1"),
        [spare()]
    );
    assert_eq!(value_found::<DscpToPpiMappingInformation>("012e3f00"), []);
    let dscp = |count: usize| format!("01{}", "2e".repeat(count));
    assert_eq!(value_found::<DscpToPpiMappingInformation>(&dscp(63)), []);
    assert_eq!(
        value_found::<DscpToPpiMappingInformation>(&dscp(64)),
        [("8.2.214", DeviationKind::Rule("more than 63 DSCP values"))]
    );
}

/// §8.2.12: the second octet of the ToS/Traffic Class of a Transport Level Marking is its
/// mask, "which shall be set to "0xFC""; the first, the DSCP value, is any.
#[test]
fn the_mask_of_a_transport_level_marking() {
    let mask = || {
        (
            "8.2.12",
            DeviationKind::Rule("a ToS/Traffic Class mask other than 0xFC"),
        )
    };
    assert_eq!(value_found::<TransportLevelMarking>("b8fc"), []);
    assert_eq!(value_found::<TransportLevelMarking>("00fc"), []);
    assert_eq!(value_found::<TransportLevelMarking>("b800"), [mask()]);
    assert_eq!(value_found::<TransportLevelMarking>("b8ff"), [mask()]);
}

/// §8.2.103 and §8.2.104: the C-TAG and the S-TAG of MAC Addresses Detected and Removed,
/// after their lengths, "encoded as the Customer-VLAN tag defined in clause 8.2.94" and
/// the Service-VLAN tag of §8.2.95, "excluding octets 1 to 4": of three octets, the more
/// of a later release as the tag has them (Table 8.1.2-1), with at least one of PCP, DEI
/// and VID set, and spare bits of 0. A length of 0 says that the field is absent.
#[test]
fn the_tags_of_mac_addresses() {
    let mac = "01aabbccddeeff";
    let detected = |tags: &str| value_found::<MacAddressesDetected>(&format!("{mac}{tags}"));
    assert_eq!(detected(""), []);
    assert_eq!(detected("03040064"), []);
    assert_eq!(detected("0304006403040064"), []);
    assert_eq!(detected("0003040064"), []);
    assert_eq!(detected("0404006400"), []);
    let rule = |rule| ("8.2.103", DeviationKind::Rule(rule));
    assert_eq!(
        detected("020400"),
        [rule("a C-TAG field of fewer than three octets")]
    );
    assert_eq!(
        detected("03000064"),
        [rule("a C-TAG field with none of PCP, DEI and VID set")]
    );
    assert_eq!(
        detected("03040064020400"),
        [rule("an S-TAG field of fewer than three octets")]
    );
    assert_eq!(
        detected("0304006403000064"),
        [rule("an S-TAG field with none of PCP, DEI and VID set")]
    );
    assert_eq!(detected("030c0064"), [("8.1.2", DeviationKind::SpareBits)]);
    assert_eq!(
        value_found::<MacAddressesRemoved>(&format!("{mac}03000064")),
        [(
            "8.2.104",
            DeviationKind::Rule("a C-TAG field with none of PCP, DEI and VID set")
        )]
    );
}

/// §8.2.76: AOCI "shall be set to "1" by the UP function, if the "Overload Control
/// Information" is included in the PFCP Session Establishment Response and the Cause IE is
/// set to a rejection cause value": not of an accepted establishment, nor of another
/// response.
#[test]
fn the_aoci_of_a_rejected_establishment() {
    let oci = |flags: Option<OciFlags>| OverloadControlInformation {
        overload_control_sequence_number: Some(SequenceNumber::new(1)),
        overload_reduction_metric: Some(Metric::new(Percent(50))),
        period_of_validity: Some(Timer {
            timer_value: 1,
            ..Default::default()
        }),
        overload_control_information_flags: flags,
        ..Default::default()
    };
    let aoci = |aoci| {
        Some(OciFlags {
            aoci,
            ..Default::default()
        })
    };
    let establishment = |cause, flags| {
        let response = SessionEstablishmentResponse::new(NodeId::Ipv4(SMF), Cause::new(cause))
            .with_overload_control_information(oci(flags));
        let response = match cause {
            CauseValue::RequestAccepted => response.with_up_f_seid(FSeid {
                v4: true,
                seid: Some(0x2001),
                ipv4: Some(SMF),
                ..Default::default()
            }),
            _ => response,
        };
        Message {
            header: Header::session(0x1001, 7),
            body: response.into(),
        }
    };
    let found = |message: Message| {
        message
            .check(Interfaces::N4)
            .into_iter()
            .map(|found| (found.path, found.clause, found.kind))
            .collect::<Vec<_>>()
    };
    let broken = vec![(
        "/pfcp/Overload Control Information/Overload Control Information Flags".to_string(),
        "8.2.76",
        DeviationKind::Rule(
            "an Overload Control Information of a rejected establishment without AOCI",
        ),
    )];
    let rejected = CauseValue::NoResourcesAvailable;
    assert_eq!(found(establishment(rejected, None)), broken);
    assert_eq!(found(establishment(rejected, aoci(false))), broken);
    assert_eq!(found(establishment(rejected, aoci(true))), []);
    assert_eq!(found(establishment(CauseValue::RequestAccepted, None)), []);
    let modification = Message {
        header: Header::session(0x1001, 7),
        body: SessionModificationResponse::new(Cause::new(rejected))
            .with_overload_control_information(oci(None))
            .into(),
    };
    assert_eq!(found(modification), []);
}
