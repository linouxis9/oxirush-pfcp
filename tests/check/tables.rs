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

//! The tables of a message and of its grouped IEs: the IEs that a scope needs, may have, repeats
//! and keeps as octets, and the Cause of each.

use super::*;

/// A field that rows of several presences share is, on an interface, of the presence of
/// its row there: the Source IP Address of an IP Multicast Addressing Info is O on N4 and
/// M on N4mb (Table 7.5.2.2-4), the weakest on both. A row
/// is on no interface that lacks it, and on a set of interfaces that one of them lacks, of
/// no presence, as no IE is needed there: Precedence is M in Create PDR on Sxb, and not on
/// Sxa (Table 7.5.2.2-1).
#[test]
fn a_shared_field_has_the_presence_of_its_row_on_the_interface() {
    let row = IpMulticastAddressingInfo::table().row_of(192).unwrap();
    assert_eq!(row.roles.len(), 2);
    assert_eq!(
        row.on(Interfaces::N4).and_then(|on| on.presence),
        Some(Presence::Optional)
    );
    assert_eq!(
        row.on(Interfaces::N4MB).and_then(|on| on.presence),
        Some(Presence::Mandatory)
    );
    assert_eq!(
        row.on(Interfaces::N4 | Interfaces::N4MB)
            .and_then(|on| on.presence),
        Some(Presence::Optional)
    );
    assert_eq!(row.on(Interfaces::SXA).and_then(|on| on.presence), None);
    let pdr_id = CreatePdr::table().row_of(56).unwrap();
    assert_eq!(
        pdr_id.on(Interfaces::N4).and_then(|on| on.presence),
        Some(Presence::Mandatory)
    );
    let precedence = CreatePdr::table().row_of(29).unwrap();
    assert_eq!(
        precedence.on(Interfaces::SXA).and_then(|on| on.presence),
        None
    );
    assert_eq!(
        precedence
            .on(Interfaces::SXB | Interfaces::N4)
            .and_then(|on| on.presence),
        Some(Presence::Mandatory)
    );
    assert_eq!(
        precedence
            .on(Interfaces::SXA_SXB)
            .and_then(|on| on.presence),
        None
    );
    // A shared field of no row on N4mb
    let fq_csid = SessionEstablishmentRequest::table().row_of(65).unwrap();
    assert_eq!(
        fq_csid.on(Interfaces::N4MB).and_then(|on| on.presence),
        None
    );
    assert_eq!(
        fq_csid.on(Interfaces::SXA_SXB).and_then(|on| on.presence),
        Some(Presence::Conditional)
    );
    assert_eq!(
        fq_csid
            .on(Interfaces::SXA | Interfaces::N4MB)
            .and_then(|on| on.presence),
        None
    );
}

/// A field that rows share takes as many IEs as its rows allow on the interface: one for
/// a row there once, any number for a row that is a list. The DNS Query and Response
/// Filters of a PDI are lists on N4 (Table 7.5.2.2-2), and so is the Source IP Address of
/// an IP Multicast Addressing Info, which is one on N4mb (Table 7.5.2.2-4).
#[test]
fn a_shared_field_whose_rows_are_lists_takes_as_many_ies_as_they_allow() {
    let repeated = |message: &Message, interface: Interfaces| -> Vec<String> {
        let found = message.check(interface).into_iter();
        let repeated =
            found.filter(|deviation| matches!(deviation.kind, DeviationKind::Repeated { .. }));
        repeated.map(|deviation| deviation.path).collect()
    };
    let filter = DnsQueryResponseFilter {
        domain_name_pattern: Lv16(b"example".to_vec().into()),
        ..Default::default()
    };
    let source = SourceIpAddress {
        v4: true,
        ipv4_address: Some(Ipv4Addr::new(10, 1, 1, 1)),
        ..Default::default()
    };
    let multicast = IpMulticastAddressingInfo::new_n4mb(
        IpMulticastAddress {
            v4: true,
            ipv4_address: Some(Ipv4Addr::new(232, 0, 0, 1)),
            ..Default::default()
        },
        source.clone(),
    )
    .with_source_ip_address(source);
    let mut message = establishment();
    request_with(&mut message, |request| {
        let pdi = request.create_pdr[0].pdi.as_mut().unwrap();
        pdi.dns_query_response_filter = vec![filter; 3];
        pdi.ip_multicast_addressing_info.push(multicast);
    });
    assert_eq!(repeated(&message, Interfaces::N4), Vec::<String>::new());
    assert_eq!(
        repeated(&message, Interfaces::N4MB),
        ["/pfcp/Create PDR/0/PDI/IP Multicast Addressing Info/0/Source IP Address"]
    );
    assert_eq!(
        repeated(&message, Interfaces::N4 | Interfaces::N4MB),
        Vec::<String>::new()
    );
}

/// §7.6.8: a mandatory IE that does not decode is of the clause of an incorrect IE,
/// whether the scope needs it, or has it beyond what it needs: a Precedence of three
/// octets, and the Recovery Time Stamp of a rejection.
#[test]
fn a_mandatory_ie_that_does_not_decode_is_of_7_6_8() {
    let incorrect = |octets: &[u8]| {
        let message = Message::decode(octets).unwrap();
        message
            .check(Interfaces::N4)
            .into_iter()
            .filter(|deviation| matches!(deviation.kind, DeviationKind::MandatoryIncorrect { .. }))
            .map(|deviation| (deviation.kind, deviation.clause))
            .collect::<Vec<_>>()
    };
    let [_, far] = rules();
    let pdr = ie(
        1,
        &[
            ie(56, &[0, 1]),
            ie(29, &[0, 0, 1]),
            ie(2, &ie(20, &[0])),
            ie(108, &[0, 0, 0, 1]),
        ]
        .concat(),
    );
    let f_seid = [2, 0, 0, 0, 0, 0, 0, 0x10, 0x01, 10, 0, 0, 1];
    let ies = [ie(60, &[0, 10, 0, 0, 1]), ie(57, &f_seid), pdr, far];
    assert_eq!(
        incorrect(&session_message(50, 0, &ies)),
        [(DeviationKind::MandatoryIncorrect { ie_type: 29 }, "7.6.8")]
    );
    let rejection = node_message(6, &[ie(60, &[0, 10, 0, 0, 1]), ie(19, &[64]), ie(96, &[0])]);
    assert_eq!(
        incorrect(&rejection),
        [(DeviationKind::MandatoryIncorrect { ie_type: 96 }, "7.6.8")]
    );
    // Of a row there once, the first IE is the one handled (§7.6.10): one that does not
    // decode, then one of a null length, is incorrect
    let pdr = ie(
        1,
        &[
            ie(56, &[0, 1]),
            ie(29, &[0, 0, 1]),
            ie(29, &[]),
            ie(2, &ie(20, &[0])),
            ie(108, &[0, 0, 0, 1]),
        ]
        .concat(),
    );
    let [_, far] = rules();
    let ies = [ie(60, &[0, 10, 0, 0, 1]), ie(57, &f_seid), pdr, far.clone()];
    assert_eq!(
        incorrect(&session_message(50, 0, &ies)),
        [(DeviationKind::MandatoryIncorrect { ie_type: 29 }, "7.6.8")]
    );
    // One that does not decode, then one that does, which is a repetition of it
    let pdr = ie(
        1,
        &[
            ie(56, &[0, 1]),
            ie(29, &[0, 0, 1]),
            ie(29, &[0, 0, 0, 1]),
            ie(2, &ie(20, &[0])),
            ie(108, &[0, 0, 0, 1]),
        ]
        .concat(),
    );
    let [_, far] = rules();
    let ies = [ie(60, &[0, 10, 0, 0, 1]), ie(57, &f_seid), pdr, far.clone()];
    let message = Message::decode(&session_message(50, 0, &ies)).unwrap();
    let Body::SessionEstablishmentRequest(request) = &message.body else {
        panic!()
    };
    assert!(request.create_pdr[0].precedence.is_none());
    assert_eq!(request.create_pdr[0].raw.len(), 2);
    assert_eq!(
        incorrect(&session_message(50, 0, &ies)),
        [(DeviationKind::MandatoryIncorrect { ie_type: 29 }, "7.6.8")]
    );
    // Of a list, an IE of a null length is no first that the others repeat: the next is a
    // value of the list
    let [pdr, far] = rules();
    let ies = [
        ie(60, &[0, 10, 0, 0, 1]),
        ie(57, &f_seid),
        ie(1, &[]),
        pdr,
        far.clone(),
    ];
    let message = Message::decode(&session_message(50, 0, &ies)).unwrap();
    let Body::SessionEstablishmentRequest(request) = &message.body else {
        panic!()
    };
    assert_eq!((request.create_pdr.len(), request.raw.len()), (1, 1));
    // Of a list, the one Create PDR, whose IEs run past it: of an invalid length (§7.6.7)
    let ies = [
        ie(60, &[0, 10, 0, 0, 1]),
        ie(57, &f_seid),
        ie(1, &[0, 56, 0, 9]),
        far,
    ];
    let message = Message::decode(&session_message(50, 0, &ies)).unwrap();
    let found = message.check(Interfaces::N4);
    let found: Vec<_> = found
        .iter()
        .map(|deviation| (&deviation.kind, deviation.clause))
        .collect();
    assert_eq!(
        found,
        [(&DeviationKind::InvalidLength { ie_type: 56 }, "7.6.7")]
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
    let message = Message::session(0x2002, 8, modification);
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
    // More rules than the IDs that the check keeps on the stack
    let mut modification = SessionModificationRequest::default();
    for id in [5].into_iter().chain(0..40) {
        modification = modification.with_remove_pdr(RemovePdr::new(PdrId::new(id)));
    }
    let message = Message::session(0x2002, 9, modification);
    assert_eq!(
        kinds(&message, Interfaces::N4),
        [DeviationKind::RuleChangedTwice { rule: "PDR", id: 5 }]
    );
    // On Sxb, whose table has no MAR nor BAR, their receiver discards them (§7.6.9): what
    // they hold breaks nothing more
    let mar = || {
        CreateMar::new(
            MarId::new(1),
            SteeringFunctionality::new(SteeringFunctionalityValue::AtsssLl),
            SteeringMode::new(SteeringModeValue::ActiveStandby),
        )
    };
    let mars = SessionModificationRequest::default()
        .with_create_mar(mar())
        .with_create_mar(mar());
    let mars = Message::session(0x2002, 10, mars);
    let twice = DeviationKind::RuleChangedTwice { rule: "MAR", id: 1 };
    assert!(kinds(&mars, Interfaces::N4).contains(&twice));
    assert_eq!(
        kinds(&mars, Interfaces::SXB),
        [DeviationKind::NotOnInterface { ie_type: 165 }]
    );
    let bars = SessionModificationRequest::default()
        .with_create_bar(CreateBar::new(BarId::new(1)))
        .with_remove_bar(RemoveBar::new(BarId::new(1)));
    let bars = Message::session(0x2002, 11, bars);
    let twice = DeviationKind::RuleChangedTwice { rule: "BAR", id: 1 };
    assert_eq!(kinds(&bars, Interfaces::N4), [twice]);
    assert!(
        kinds(&bars, Interfaces::SXB)
            .iter()
            .all(|kind| matches!(kind, DeviationKind::NotOnInterface { .. }))
    );
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
    let request = Message::node(1, NodeReportRequest::default());
    let causes: Vec<_> = request
        .check(Interfaces::N4)
        .iter()
        .map(|deviation| deviation.cause)
        .collect();
    assert_eq!(causes, [Some(CauseValue::MandatoryIeMissing); 2]);
    let response = Message::node(1, NodeReportResponse::default());
    assert!(
        response
            .check(Interfaces::N4)
            .iter()
            .all(|deviation| deviation.cause.is_none())
    );
}

/// §7.6.9 and §8.1.2: an IE of a type of Table 8.1.2-1 that the table of its scope has no
/// row of is unexpected; one of a type that no release has is unknown. Each is at its
/// name in the tree.
#[test]
fn an_ie_of_no_row_is_unexpected_and_one_of_no_type_unknown() {
    let octets = node_message(
        1,
        &[ie(96, &RTS), ie(60, &[0, 10, 0, 0, 1]), ie(1000, &[1])],
    );
    let message = Message::decode(&octets).unwrap();
    let found: Vec<(String, &str, DeviationKind)> = message
        .check(Interfaces::N4)
        .into_iter()
        .map(|deviation| (deviation.path, deviation.clause, deviation.kind))
        .collect();
    assert_eq!(
        found,
        [
            (
                "/pfcp/Node ID".to_string(),
                "7.6.9",
                DeviationKind::Unexpected { ie_type: 60 }
            ),
            (
                "/pfcp/1000".to_string(),
                "8.1.2",
                DeviationKind::UnknownType { ie_type: 1000 }
            ),
        ]
    );
    // A vendor IE of a vendor's Enterprise ID is no deviation; one of 3GPP's, or without
    // one, is (§8.1.1)
    let vendor = |content: &[u8]| {
        let octets = node_message(1, &[ie(96, &RTS), ie(32769, content)]);
        let found = Message::decode(&octets).unwrap().check(Interfaces::N4);
        found
            .into_iter()
            .map(|deviation| deviation.kind)
            .collect::<Vec<_>>()
    };
    assert_eq!(vendor(&[0x48, 0x79, 1]), []);
    assert_eq!(vendor(&[0x28, 0xaf, 1]), [DeviationKind::VendorId]);
    assert_eq!(vendor(&[1]), [DeviationKind::VendorId]);
}

/// §7.6.10: an IE of a list beyond the most that its row allows, which decodes, is a
/// repetition, and is told at its position: the seventh FQ-CSID of a Session Set Deletion
/// Request on Sxb, whose six rows have one each (Table 7.4.6.1-1).
#[test]
fn an_ie_beyond_its_list_is_repeated() {
    let node = ie(60, &[0, 10, 0, 0, 1]);
    let fq_csids = (0..7u8).map(|csid| ie(65, &[0x01, 10, 0, 0, 1, 0, csid]));
    let ies: Vec<Vec<u8>> = [node].into_iter().chain(fq_csids).collect();
    let message = Message::decode(&node_message(14, &ies)).unwrap();
    let found: Vec<(String, DeviationKind)> = message
        .check(Interfaces::SXB)
        .into_iter()
        .map(|deviation| (deviation.path, deviation.kind))
        .collect();
    let repeated = DeviationKind::Repeated { ie_type: 65 };
    assert_eq!(found, [("/pfcp/FQ-CSID/6".to_string(), repeated)]);
}

/// §7.6.10: of an IE that its table has once, the first is handled and the others are
/// ignored; when the first does not decode, the second is not taken in its place.
#[test]
fn the_first_of_a_repeated_ie_is_the_one_handled() {
    // A Node ID of a null length, then one of a value: the first is handled, and the
    // second is not taken in its place
    let octets = node_message(5, &[ie(60, &[]), ie(60, &[0, 10, 0, 0, 9]), ie(96, &RTS)]);
    let Body::AssociationSetupRequest(request) = Message::decode(&octets).unwrap().body else {
        panic!()
    };
    assert_eq!((request.node_id, request.raw.len()), (None, 2));
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
    // An optional IE: the first is the one handled, and each of the others a repetition
    let octets = node_message(1, &[ie(96, &RTS), ie(96, &RTS[..2]), ie(96, &RTS)]);
    assert_eq!(
        found(&octets),
        vec![(DeviationKind::Repeated { ie_type: 96 }, None, None); 2]
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
    // An address of its type with an octet after it, which a later release may add
    // (§8.1.2)
    let longer = node_message(5, &[ie(60, &[0, 10, 0, 0, 1, 0xff]), ie(96, &RTS)]);
    assert_eq!(found(&longer), []);
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
            .all(|deviation| deviation.cause.is_none())
    );
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
    // A second Create PDR, whose IEs do not frame, at its position in the list: of an
    // invalid length (§7.6.7)
    let mut message = establishment();
    request_with(&mut message, |request| {
        request.raw.push(cut(1, &[0, 56, 0, 9]));
    });
    assert_eq!(
        checked(&message),
        [(
            "/pfcp/Create PDR/1".to_string(),
            DeviationKind::InvalidLength { ie_type: 56 },
            Some(CauseValue::InvalidLength),
            Some(56)
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
    let response = Message::session(
        0x1001,
        7,
        SessionEstablishmentResponse::new(
            NodeId::Ipv4(SMF),
            Cause::new(CauseValue::RequestAccepted),
        )
        .with_up_f_seid(FSeid::ipv4(0x2001, SMF))
        .with_created_pdr(created),
    );
    assert_eq!(
        checked(&response),
        [(
            "/pfcp/Created PDR/0/F-TEID/0".to_string(),
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
    // The one Create PDR that an establishment needs, of a null length
    let f_seid = ie(57, &[2, 0, 0, 0, 0, 0, 0, 0x10, 0x01, 10, 0, 0, 1]);
    let [_, far] = rules();
    let ies = [ie(60, &[0, 10, 0, 0, 1]), f_seid, ie(1, &[]), far];
    assert_eq!(found(&session_message(50, 0, &ies)), [null(1)]);
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
        found(&session_message(
            51,
            1,
            &[node.clone(), ie(19, &[1]), ie(57, &[])]
        )),
        [null(57)]
    );
    // One that is there and does not decode is incorrect, not of a null length
    assert_eq!(
        found(&session_message(51, 1, &[node, ie(19, &[1]), ie(57, &[2])])),
        [(
            DeviationKind::ConditionalIncorrect { ie_type: 57 },
            None,
            None
        )]
    );
}
