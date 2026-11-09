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

//! The values of clause 8.2: their fields, flags, lengths, and their reserved and spare values.

use super::*;

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
        up_f_seid: Some(FSeid::ipv4(1, SMF)),
        overload_control_information: Some(Box::new(overload)),
        ..Default::default()
    };
    let message = Message::session(0x1001, 7, response);
    assert_eq!(
        kinds(&message, Interfaces::N4),
        [DeviationKind::ReadAs {
            value: 101,
            read: 0
        }]
    );
    // 100 is the most that a percentage is
    assert!(Metric::new(Percent(100)).deviations().is_empty());
    assert!(!Metric::new(Percent(101)).deviations().is_empty());
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
    assert_eq!(found[0].cause, None, "an optional IE");
}

/// The lengths of clause 8.2: a DL Buffering Suggested Packet Count of one or two octets
/// (§8.2.30); a Failed Rule ID whose value has the length of the ID of its type, a type
/// that a receiver reads as FAR that of a FAR ID, and octets after it of a later release
/// (§8.2.80, §8.1.2); an LNS Address and the IP Address of the Trace Collection Entity of a
/// Trace Information of four or sixteen octets (§8.2.188, §8.2.108); a Key ID of 80 octets
/// at most (§8.2.276).
#[test]
fn the_lengths_of_clause_8_2() {
    fn rules<T: Codec + Check>(octets: &[u8]) -> Vec<(&'static str, DeviationKind)> {
        let value = T::decode(octets).unwrap();
        let mut again = Vec::new();
        value.encode(&mut again).unwrap();
        assert_eq!(again, octets, "byte for byte");
        let found = value.deviations().into_iter();
        let rules = found.filter(|deviation| matches!(deviation.kind, DeviationKind::Rule(_)));
        rules
            .map(|deviation| (deviation.clause, deviation.kind))
            .collect()
    }
    let count = |octets: &[u8]| rules::<DlBufferingSuggestedPacketCount>(octets);
    assert_eq!(count(&[1]), []);
    assert_eq!(count(&[1, 2]), []);
    let rule = DeviationKind::Rule("a Packet Count value of neither one nor two octets");
    assert_eq!(count(&[1, 2, 3]), [("8.2.30", rule)]);
    let failed = |octets: &[u8]| rules::<FailedRuleId>(octets);
    let rule = || {
        [(
            "8.2.80",
            DeviationKind::Rule("a Rule ID value of another length than the ID of its type"),
        )]
    };
    for good in [
        &[0, 0, 1][..],
        &[1, 0, 0, 0, 1],
        &[4, 1],
        &[5, 0, 1],
        &[6, 1],
        &[7, 0, 0, 0, 1],
    ] {
        assert_eq!(failed(good), [], "{good:?}");
    }
    for short in [&[4][..], &[0, 1], &[1, 0, 1], &[3, 0, 0, 1], &[31, 0, 0, 1]] {
        assert_eq!(failed(short), rule(), "{short:?}");
    }
    let later = FailedRuleId::decode(&[0, 0, 0, 0, 1]).unwrap();
    assert_eq!(later.rule_id_value, Rest(vec![0, 0].into()));
    assert_eq!(&later.extra[..], [0, 1]);
    let built = FailedRuleId {
        rule_id_value: Rest(vec![0, 0, 0, 1].into()),
        ..Default::default()
    };
    assert_eq!(built.deviations()[0].kind, rule()[0].1);
    let lns = |octets: &[u8]| rules::<LnsAddress>(octets);
    assert_eq!(lns(&[10, 0, 0, 1]), []);
    assert_eq!(lns(&[0x20; 16]), []);
    let rule = DeviationKind::Rule("an LNS Address value of neither 4 nor 16 octets");
    for wrong in [&[][..], &[10, 0, 0], &[10, 0, 0, 1, 9], &[0x20; 17]] {
        assert_eq!(lns(wrong), [("8.2.188", rule.clone())], "{wrong:?}");
    }
    let trace = |address: &[u8]| {
        let head = [0x02, 0xf8, 0x39, 0, 0, 1, 1, 0xff, 1, 1, 0xff];
        let octets = [&head[..], &[address.len() as u8], address].concat();
        rules::<TraceInformation>(&octets)
    };
    assert_eq!(trace(&[10, 0, 0, 1]), []);
    assert_eq!(trace(&[0x20; 16]), []);
    let rule = DeviationKind::Rule(
        "an IP Address of the Trace Collection Entity of neither 4 nor 16 octets",
    );
    for wrong in [&[][..], &[10, 0, 0, 1, 9]] {
        assert_eq!(trace(wrong), [("8.2.108", rule.clone())], "{wrong:?}");
    }
    let key = |id: usize| {
        let octets = [&[id as u8][..], &vec![b'k'; id], &[1, b's']].concat();
        rules::<KeyIdAndSharedSecret>(&octets)
    };
    assert_eq!(key(80), []);
    let rule = DeviationKind::Rule("a Key ID of more than 80 octets");
    assert_eq!(key(81), [("8.2.276", rule)]);
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
            found[0].cause,
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
        (found[0].cause, found[0].offending_ie()),
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
            .map(|deviation| deviation.cause)
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
            node_address: [10, 0, 0, 1].into(),
            csids: vec![1],
            node_type: None,
            extra: Octets::default(),
        })
    });
    let found = message.check(Interfaces::N4);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        (
            found[0].kind.clone(),
            found[0].cause,
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
    let setup = |fqdn: Fqdn| {
        Message::node(
            1,
            AssociationSetupRequest::new(NodeId::Ipv4(SMF), RecoveryTimeStamp::new(1))
                .with_cp_function_features(CpFunctionFeatures {
                    mpas: true,
                    ..Default::default()
                })
                .with_smf_set_id(SmfSetId {
                    fqdn,
                    ..Default::default()
                }),
        )
    };
    let label = |length: u8| [&[length][..], &vec![b'a'; usize::from(length)]].concat();
    let labels = |last| [label(63), label(63), label(63), label(last)].concat();
    for (fqdn, broken) in [
        (Fqdn::new("smf.set").unwrap(), false),
        (Fqdn(b"smf.set".to_vec().into()), true),
        (Fqdn(b"\x09set".to_vec().into()), true),
        (Fqdn(Octets::default()), true),
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
                DeviationKind::Rule(rule) => Some((deviation.clause, rule, deviation.cause)),
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
    let report = Message::session(5, 1, SessionReportRequest::new(ReportType::default()));
    assert_eq!(rules(&report), [("8.2.21", "no bit is set", incorrect)]);
    let urr = CreateUrr::new(
        UrrId::new(1),
        MeasurementMethod::default(),
        ReportingTriggers::default(),
    );
    let modification = Message::session(
        5,
        1,
        SessionModificationRequest::default().with_create_urr(urr),
    );
    assert_eq!(
        rules(&modification),
        [
            ("8.2.40", "no bit is set", incorrect),
            ("8.2.19", "no bit is set", incorrect)
        ]
    );
    let node = Message::node(
        1,
        NodeReportRequest::new(NodeId::Ipv4(SMF), NodeReportType::default()),
    );
    assert_eq!(rules(&node), [("8.2.69", "no bit is set", incorrect)]);
}

/// What check() finds in a value of `octets`, which encodes back to them.
/// A field that its clause has encoded as another IE, from its octet 5, is checked as that
/// IE: the Destination Interface and the Network Instance fields of a Remote GTP-U Peer
/// (§8.2.70), whose Destination Interface of a spare value is told as that of the IE, and
/// one without its octet 5 as no Destination Interface; the QFIs of a PMF Control
/// Information, each the octet 5 of a QFI IE (§8.2.156), whose two bits above are spare.
#[test]
fn a_field_encoded_as_an_ie_is_checked_as_that_ie() {
    let spare = value_found::<DestinationInterface>("0f");
    assert_eq!(spare, [("8.2.24", DeviationKind::SpareValue { value: 15 })]);
    // V4 and DI, then the address, and the Destination Interface field after its length
    let peer = |field: &str| value_found::<RemoteGtpUPeer>(&format!("060a000001{field}"));
    assert_eq!(peer("00010f"), spare);
    assert_eq!(peer("000101"), []);
    assert_eq!(peer("00020102"), []);
    let missing = "a Destination Interface field without the octet of its value";
    assert_eq!(peer("0000"), [("8.2.70", DeviationKind::Rule(missing))]);
    // NI, with V4: any octets are a Network Instance
    assert_eq!(value_found::<RemoteGtpUPeer>("0a0a00000100036e3666"), []);
    assert_eq!(value_found::<PmfControlInformation>("04020105"), []);
    let qfis = value_found::<PmfControlInformation>("04020145");
    assert_eq!(qfis, [("8.1.2", DeviationKind::SpareBits)]);
}

fn value_found<T: Codec + Check>(octets: &str) -> Vec<(&'static str, DeviationKind)> {
    let octets = hex::decode(octets).unwrap();
    let value = T::decode(&octets).unwrap();
    let mut again = Vec::new();
    value.encode(&mut again).unwrap();
    assert_eq!(again, octets);
    value
        .deviations()
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
/// the Service-VLAN tag of §8.2.95, "excluding octets 1 to 4", checked as those IEs: of
/// three octets, the more of a later release as the IE has them (Table 8.1.2-1), with at
/// least one of PCP, DEI and VID set, and spare bits of 0. A length of 0 says that the
/// field is absent. The C-TAG and S-TAG fields of Outer Header Creation are octets 5 to 7
/// of those IEs (§8.2.56).
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
    let unflagged = |clause| {
        (
            clause,
            DeviationKind::Rule("none of PCP, DEI and VID is set"),
        )
    };
    assert_eq!(detected("03000064"), [unflagged("8.2.94")]);
    assert_eq!(
        detected("03040064020400"),
        [rule("an S-TAG field of fewer than three octets")]
    );
    assert_eq!(detected("0304006403000064"), [unflagged("8.2.95")]);
    assert_eq!(detected("030c0064"), [("8.1.2", DeviationKind::SpareBits)]);
    assert_eq!(
        value_found::<MacAddressesRemoved>(&format!("{mac}03000064")),
        [unflagged("8.2.94")]
    );
    // The C-TAG and S-TAG fields of Outer Header Creation, three octets each (§8.2.56)
    let creation = |tags: &str| value_found::<OuterHeaderCreation>(&format!("c000{tags}"));
    assert_eq!(creation("040064040064"), []);
    assert_eq!(
        creation("f80000000000"),
        [
            ("8.1.2", DeviationKind::SpareBits),
            unflagged("8.2.94"),
            unflagged("8.2.95")
        ]
    );
}
