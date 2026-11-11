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
    // One longer than its length, whose octets would read as the ID and unknown octets,
    // which encode() refuses
    let kinds: Vec<_> = built
        .deviations()
        .into_iter()
        .map(|deviation| deviation.kind)
        .collect();
    let longer = DeviationKind::Inconsistent {
        field: "Rule ID value",
    };
    assert_eq!(kinds, [longer, rule()[0].1.clone()]);
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

/// Table 8.2.64-1, NOTE 7: of an Outer Header Removal Description that the table does not
/// name, 9 to 255, "If the UP function receives an unknown value, it shall reject the
/// request message with the cause set to "Mandatory IE incorrect" together with the
/// Offending IE set to the IE type of Outer Header Removal IE": the value is told as one
/// that the table reserves is, and not as a spare one, which a receiver ignores.
#[test]
fn an_unknown_outer_header_removal_description_is_rejected() {
    for unknown in [9, 200, 255] {
        let told = value_found::<OuterHeaderRemoval>(&format!("{unknown:02x}"));
        let kind = DeviationKind::ReservedValue {
            value: unknown.into(),
        };
        assert_eq!(told, [("8.2.64", kind.clone())]);
        let mut message = establishment();
        request_with(&mut message, |request| {
            let removal = OuterHeaderRemoval {
                outer_header_removal_description: OuterHeaderRemovalDescription::from_value(
                    unknown,
                ),
                present: 1,
                ..Default::default()
            };
            request.create_pdr[0].outer_header_removal = Some(removal);
        });
        let found = message.check(Interfaces::N4);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].path, "/pfcp/Create PDR/0/Outer Header Removal");
        assert_eq!(
            (
                found[0].kind.clone(),
                found[0].cause,
                found[0].offending_ie()
            ),
            (kind, Some(CauseValue::MandatoryIeIncorrect), Some(95))
        );
        let said = found[0].to_string();
        assert!(
            said.contains("is a reserved value") && said.contains("\"Mandatory IE incorrect\""),
            "{said}"
        );
    }
    // The values that the table names
    for known in 0..=8 {
        assert_eq!(
            value_found::<OuterHeaderRemoval>(&format!("{known:02x}")),
            []
        );
    }
    assert_eq!(OuterHeaderRemovalDescription::RESERVED.len(), 247);
    assert_eq!(OuterHeaderRemovalDescription::RESERVED[..2], [9, 10]);
    assert_eq!(OuterHeaderRemovalDescription::RESERVED.last(), Some(&255));
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

/// Table 8.2.56-1, NOTE 7: with "Low Layer SSM and C-TEID" (6/3), "the TEID, IPv4/IPv6
/// address and Port Number fields shall not be present": the bits of octet 5 that have
/// them there are told with it.
#[test]
fn an_outer_header_creation_of_a_low_layer_ssm_has_no_teid_address_or_port() {
    let rule = "Low Layer SSM and C-TEID is set with a TEID, an IP address or a Port Number";
    let v6 = "20010db8000000000000000000000001";
    // 5/1 and its TEID and IPv4 address; 5/2; 5/3 and its address and port; 5/4; 5/5; 5/6
    for with in [
        "0104000000010a000001".to_string(),
        format!("020400000001{v6}"),
        "04040a0000011f90".to_string(),
        format!("0804{v6}1f90"),
        "10040a000001".to_string(),
        format!("2004{v6}"),
    ] {
        let told = value_found::<OuterHeaderCreation>(&with);
        assert_eq!(told, [("8.2.56", DeviationKind::Rule(rule))], "{with}");
    }
    // 6/3 alone, with 6/1 and 6/2, and with a C-TAG; and 5/1 without it
    for without in ["0004", "0007", "4004010064", "0100000000010a000001"] {
        assert_eq!(value_found::<OuterHeaderCreation>(without), [], "{without}");
    }
}

/// §8.2.62, bit 4: IPv6D "is only applicable to the UE IP address IE in the PDI IE, Create
/// Traffic Endpoint IE and Update Traffic Endpoint IE", as S/D is: set in another IE, as
/// the UE IP Address of a Created PDR or of a usage report, it is told as S/D is there,
/// a bit that its place does not have, with no Cause.
#[test]
fn the_ipv6d_of_a_ue_ip_address_is_of_a_pdi_and_a_traffic_endpoint() {
    let delegated = UeIpAddress {
        v6: true,
        ipv6d: true,
        ipv6: Some("2001:db8::".parse().unwrap()),
        ipv6_prefix_delegation_bits: Some(56),
        ..Default::default()
    };
    let told = |message: Message| -> Vec<(String, DeviationKind, Option<CauseValue>)> {
        let octets = message.encode().unwrap();
        let found = Message::decode(&octets).unwrap().check(Interfaces::N4);
        let found = found.into_iter().filter(|found| found.clause == "8.2.62");
        found
            .map(|found| (found.path, found.kind, found.cause))
            .collect()
    };
    let mut message = establishment();
    request_with(&mut message, |request| {
        let pdi = request.create_pdr[0].pdi.as_mut().unwrap();
        pdi.ue_ip_address = vec![delegated.clone()];
        request.create_traffic_endpoint = vec![CreateTrafficEndpoint {
            traffic_endpoint_id: Some(TrafficEndpointId::new(1)),
            ue_ip_address: vec![delegated.clone()],
            ..Default::default()
        }];
    });
    assert_eq!(told(message), []);
    let update = SessionModificationRequest {
        update_traffic_endpoint: vec![UpdateTrafficEndpoint {
            traffic_endpoint_id: Some(TrafficEndpointId::new(1)),
            ue_ip_address: vec![delegated.clone()],
            ..Default::default()
        }],
        ..Default::default()
    };
    assert_eq!(told(Message::session(1, 8, update)), []);
    // In a Created PDR, and in a usage report of a Session Report Request
    let response = SessionEstablishmentResponse {
        node_id: Some(NodeId::Ipv4(SMF)),
        cause: Some(Cause::new(CauseValue::RequestAccepted)),
        up_f_seid: Some(FSeid::ipv4(1, SMF)),
        created_pdr: vec![CreatedPdr {
            pdr_id: Some(PdrId::new(1)),
            ue_ip_address: vec![delegated.clone()],
            ..Default::default()
        }],
        ..Default::default()
    };
    let spare = |path: &str| (path.to_string(), DeviationKind::SpareBits, None);
    assert_eq!(
        told(Message::session(1, 7, response)),
        [spare("/pfcp/Created PDR/0/UE IP Address/0")]
    );
    let report = SessionReportRequest {
        report_type: Some(ReportType {
            usar: true,
            ..Default::default()
        }),
        usage_report: vec![UsageReport {
            ue_ip_address: Some(delegated.clone()),
            ..Default::default()
        }],
        ..Default::default()
    };
    assert_eq!(
        told(Message::session(1, 9, report)),
        [spare("/pfcp/Usage Report/0/UE IP address")]
    );
    // The IE alone has no place to tell
    assert_eq!(delegated.deviations(), []);
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
/// both RTP and RTCP (NOTE 4), has the SSRC or the Media Identification Tag. One of no
/// octets has no flags to read, and the SDF Filter does not decode.
#[test]
fn the_media_identifications_of_an_sdf_filter() {
    let none = "SMMII is set with no (S)RTP Multiplexed Media Identification Information";
    let empty = "an (S)RTP and (S)RTCP media identification has neither SSRC nor a Media Identification Tag";
    for (octets, rule) in [("200000", none), ("200001000100", empty)] {
        assert_eq!(
            value_found::<SdfFilter>(octets),
            [("8.2.5", DeviationKind::Rule(rule))],
            "{octets}"
        );
    }
    assert_eq!(SdfFilter::decode(&hex::decode("2000010000").unwrap()), None);
    // An SSRC, of RTP and RTCP; a Payload Type, of RTP alone; two media identifications
    for octets in [
        "20000100050100000001",
        "2000010002027f",
        "200002000501000000010002027f",
    ] {
        assert_eq!(value_found::<SdfFilter>(octets), [], "{octets}");
    }
    // Bits 6 to 8 of the flags of a media identification "are spare and reserved for future
    // use, shall be set to "0" by the sender and discarded by the receiver"
    for octets in ["20000100052100000001", "200002000501000000010002827f"] {
        let spare = ("8.1.2", DeviationKind::SpareBits);
        assert_eq!(value_found::<SdfFilter>(octets), [spare], "{octets}");
    }
}

/// Figure 8.2.5-2: the fields of an (S)RTP Multiplexed Media Identification Information
/// after its flags, each where its flag has it, in the order of the figure: the SSRC, of
/// four octets, the Payload Type, the Media Identification Tag after its length, the RTP
/// SDES Header Extension ID for MID and the RTCP Packet Type, of one octet each; the octets
/// after them are a later release's. One that lacks octets of a field that its flags
/// announce does not decode, nor does its SDF Filter; a Payload Type that is not "between
/// (and including) 0 and 127" and an RTP SDES Header Extension ID for MID that is not "in
/// the range 1 to 255" are told, at the place of the media identification in its list.
#[cfg(feature = "tree")]
#[test]
fn the_fields_of_a_media_identification_of_an_sdf_filter() {
    let high = "the Payload Type of a media identification is above 127";
    let zero = "the RTP SDES Header Extension ID for MID of a media identification is 0";
    // An SDF Filter of SMMII and one media identification of `entry`
    let octets = |entry: &str| {
        let entry = hex::decode(entry).unwrap();
        let length = (entry.len() as u16).to_be_bytes();
        [&[0x20, 0, 1][..], &length, &entry].concat()
    };
    let found = |entry: &str| value_found::<SdfFilter>(&hex::encode(octets(entry)));
    let rule = |rule| [("8.2.5", DeviationKind::Rule(rule))];
    // Every field, each of octets that another place would read amiss: an SSRC and a tag
    // of a Payload Type above 127, and of 0
    let all = "1f000000c87f02c80001c8";
    assert_eq!(found(all), []);
    let filter = SdfFilter::decode(&octets(all)).unwrap();
    let media = &filter.rtp_multiplexed_media.as_ref().unwrap().0[0];
    assert_eq!(
        (
            media.ssrc,
            media.payload_type,
            media.rtp_sdes_header_extension_id,
            media.rtcp_packet_type
        ),
        (Some(0xc8), Some(0x7f), Some(1), Some(0xc8))
    );
    assert_eq!(
        media.media_identification_tag,
        Some(Lv8(vec![0xc8, 0].into()))
    );
    // And octets of a later release after them
    assert_eq!(found(&format!("{all}0000ff")), []);
    assert_eq!(found("0100000001020304"), []);
    // Cut in each field: the SSRC, the Payload Type, the length of the tag, the tag, the
    // RTP SDES Header Extension ID for MID, the RTCP Packet Type
    for cut in [2, 8, 10, 12, 14, 18, 20] {
        assert_eq!(
            SdfFilter::decode(&octets(&all[..cut])),
            None,
            "{}",
            &all[..cut]
        );
    }
    // The Payload Type and the RTP SDES Header Extension ID for MID, at their places
    assert_eq!(found("1f000000c88002c80001c8"), rule(high));
    assert_eq!(found("1f000000c87f02c80000c8"), rule(zero));
    // Each field alone, of its octets and of one fewer: the SSRC; the Payload Type; the
    // Media Identification Tag, of an RTCP Packet Type; the RTP SDES Header Extension ID
    // for MID, of an SSRC
    for (entry, short) in [
        ("0100000001", "01000000"),
        ("0200", "02"),
        ("14026162c8", "14026162"),
        ("09000000017f", "0900000001"),
    ] {
        assert_eq!(found(entry), [], "{entry}");
        assert_eq!(SdfFilter::decode(&octets(short)), None, "{short}");
    }
    // A media identification of SSRCPI without an SSRC, and of a tag of Length 5 that
    // holds one octet, do not decode; of a Payload Type of 200 and of an ID of 0
    assert_eq!(SdfFilter::decode(&octets("01")), None);
    assert_eq!(SdfFilter::decode(&octets("0c05ab")), None);
    assert_eq!(found("02c8"), rule(high));
    assert_eq!(found("0c016100"), rule(zero));
    // In a tree, a media identification is its flags and its fields; a deviation is at its
    // place in the list, and has the Cause of its SDF Filter
    let second =
        SdfFilter::decode(&hex::decode("2000020002027f0002".to_owned() + "02c8").unwrap()).unwrap();
    let name = "(S)RTP Multiplexed Media Identification Information";
    assert_eq!(
        tree::Tree::to_tree(&second)[name],
        tree!([{"PTPI": true, "Payload Type (PT)": 127}, {"PTPI": true, "Payload Type (PT)": 200}])
    );
    assert_eq!(
        tree::from_value::<SdfFilter>(&tree::Tree::to_tree(&second)).ok(),
        Some(second.clone())
    );
    let told = second.deviations();
    assert_eq!(told.len(), 1, "{told:?}");
    assert_eq!(told[0].path, format!("/{name}/1"));
    let mut message = establishment();
    request_with(&mut message, |request| {
        let filter = EthernetPacketFilter {
            sdf_filter: vec![second.clone()],
            ..Default::default()
        };
        request.create_pdr[0]
            .pdi
            .as_mut()
            .unwrap()
            .ethernet_packet_filter = vec![filter];
    });
    let told = message.check(Interfaces::N4);
    assert_eq!(told.len(), 1, "{told:?}");
    assert_eq!(
        told[0].path,
        format!("/pfcp/Create PDR/0/PDI/Ethernet Packet Filter/0/SDF Filter/0/{name}/1")
    );
    assert_eq!(told[0].kind, DeviationKind::Rule(high));
    assert!(paths::select(&message.to_tree(), &told[0].path).is_ok_and(|at| at.len() == 1));
}

/// Figures 8.2.39-2, 8.2.39-3 and 8.2.39-4: the Additional Flow Description and the
/// Additional URL of PFD Contents are Flow Descriptions and URLs, each a text after its
/// length of two octets, and the Additional Domain Name and Domain Name Protocol are
/// Domain Names, each with its Domain Name Protocol after it. A field that its entries
/// do not fill, each with its length, does not decode, nor does a Domain Name without its
/// protocol.
#[cfg(feature = "tree")]
#[test]
fn the_additional_fields_of_pfd_contents() {
    let decoded = |octets: &str| PfdContents::decode(&hex::decode(octets).unwrap());
    for flag in ["20", "40", "80"] {
        // "abc" then "de": two flow descriptions or URLs, or a domain name and its protocol
        let two = format!("{flag}000009000361626300026465");
        assert_eq!(value_found::<PfdContents>(&two), [], "{two}");
        // "abc" alone: one flow description or URL; a domain name without its protocol
        let one = format!("{flag}0000050003616263");
        assert_eq!(decoded(&one).is_some(), flag != "80", "{one}");
        // A Length of 5 that holds one octet; an octet after "abc"; a Length cut
        for cut in ["0003000561", "0006000361626300", "000100"] {
            assert_eq!(decoded(&format!("{flag}00{cut}")), None, "{flag} {cut}");
        }
        // A field of no entry
        assert_eq!(value_found::<PfdContents>(&format!("{flag}000000")), []);
    }
    // In a tree, each is the list of its entries
    let contents =
        decoded("e0000009000361626300026465000500036768690009000361626300026465").unwrap();
    let written = tree!({
        "ADNP": true, "AURL": true, "AFD": true,
        "Additional Flow Description": ["abc", "de"],
        "Additional URL": ["ghi"],
        "Additional Domain Name and Domain Name Protocol": [{"Domain Name": "abc", "Domain Name Protocol": "6465"}],
    });
    assert_eq!(tree::Tree::to_tree(&contents), written);
    assert_eq!(
        tree::from_value::<PfdContents>(&written).ok(),
        Some(contents.clone())
    );
    let names = contents
        .additional_domain_name_and_protocol
        .as_ref()
        .unwrap();
    assert_eq!(names.0[0].domain_name.text(), Some("abc"));
    assert_eq!(&names.0[0].domain_name_protocol.0[..], b"de");
}

/// The values that their clauses bound: the Downlink and the Uplink Congestion information
/// of a QoS Monitoring Measurement, and their thresholds of Reporting Thresholds, "in the
/// (decimal) values range 0 to 10000 (included)" (§8.2.171, §8.2.240); an RTP Payload
/// Type, "an integer between (and including) 0 and 127" (§8.2.236); an RTP Header
/// Extension ID, "a decimal value in the range 1 to 255" (§8.2.235); and the PSI value of
/// a PDU Set Importance for N6-unmarked PDUs, "within the range (inclusive) of values 1 to
/// 15" (§8.2.282). A value outside its range is told, and the ends of the range are not.
#[test]
fn the_ranges_of_the_values_of_clause_8_2() {
    fn told<T: Codec + Check>(
        clause: &'static str,
        rule: &'static str,
        outside: &[&str],
        within: &[&str],
    ) {
        for octets in outside {
            let expected = [(clause, DeviationKind::Rule(rule))];
            assert_eq!(value_found::<T>(octets), expected, "{octets}");
        }
        for octets in within {
            assert_eq!(value_found::<T>(octets), [], "{octets}");
        }
    }
    // DLCI, ULCI, and both: 10001 and 65535; 0 and 10000
    told::<QoSMonitoringMeasurement>(
        "8.2.171",
        "a Downlink or Uplink Congestion information above 10000",
        &["102711", "10ffff", "202711", "3000002711", "3027110000"],
        &["100000", "102710", "202710", "3027102710"],
    );
    told::<ReportingThresholds>(
        "8.2.240",
        "a Downlink or Uplink Congestion information threshold above 10000",
        &["012711", "01ffff", "022711", "0300002711", "0327110000"],
        &["010000", "012710", "022710", "0327102710"],
    );
    told::<RtpPayloadType>(
        "8.2.236",
        "a Payload Type above 127",
        &["80", "c8", "ff"],
        &["00", "7f"],
    );
    told::<RtpHeaderExtensionId>(
        "8.2.235",
        "an RTP Header Extension ID of 0",
        &["00"],
        &["01", "ff"],
    );
    told::<PduSetImportanceForN6UnmarkedPDUs>(
        "8.2.282",
        "a PSI value of 0",
        &["00"],
        &["01", "0f"],
    );
}

/// §8.2.129, §8.2.135, §8.2.199 and §8.2.270: an Alternative SMF IP Address, a CP PFCP
/// Entity IP Address, a CP IP Address and a MoQ Relay IP Address "shall contain an IPv4
/// and/or IPv6 address": one of neither V4 nor V6 is told.
#[test]
fn an_ie_of_an_address_has_an_address() {
    fn told<T: Codec + Check>(clause: &'static str) {
        let rule = DeviationKind::Rule("neither V4 nor V6 is set");
        assert_eq!(value_found::<T>("00"), [(clause, rule)]);
        for octets in [
            "020a000001",
            "0120010db8000000000000000000000001",
            "030a00000120010db8000000000000000000000001",
        ] {
            assert_eq!(value_found::<T>(octets), [], "{octets}");
        }
    }
    told::<AlternativeSmfIpAddress>("8.2.129");
    told::<CpPfcpEntityIpAddress>("8.2.135");
    told::<CpIpAddress>("8.2.199");
    told::<MoQRelayIpAddress>("8.2.270");
    // A preferred PFCP entity of no address
    let rule = DeviationKind::Rule("neither V4 nor V6 is set");
    assert_eq!(
        value_found::<AlternativeSmfIpAddress>("04"),
        [("8.2.129", rule)]
    );
    assert_eq!(value_found::<AlternativeSmfIpAddress>("060a000001"), []);
}

/// §8.2.117: "The content of the APN/DNN field shall be the full APN/DNN with both the
/// APN/DNN Network Identifier and APN/DNN Operator Identifier being present as specified
/// in TS 23.003 clauses 9.1.1 and 9.1.2": the Operator Identifier "is composed of three
/// labels. The last label (or domain) shall be "gprs"", after the Network Identifier, of
/// "at least one label". The case of the letters "is not significant".
#[test]
fn an_apn_dnn_has_its_operator_identifier() {
    let rule = "an APN/DNN without its Operator Identifier, three labels that end with gprs, after its Network Identifier";
    let found = |name: &str| {
        let labels = NetworkInstance::from_name(name).unwrap().0;
        value_found::<ApnDnn>(&hex::encode(&labels[..]))
    };
    for full in [
        "internet.mnc093.mcc208.gprs",
        "ims.MNC001.MCC001.GPRS",
        "a.b.example.mnc012.mcc345.gprs",
        "internet.nid000007ed9d5.mnc093.mcc208.gprs",
        "internet.operator-name.operator-group.gprs",
    ] {
        assert_eq!(found(full), [], "{full}");
    }
    for other in [
        "internet",
        "mnc093.mcc208.gprs",
        "internet.mnc093.mcc208",
        "internet.mnc093.mcc208.gprs.example",
        "gprs",
    ] {
        assert_eq!(
            found(other),
            [("8.2.117", DeviationKind::Rule(rule))],
            "{other}"
        );
    }
    // Octets that are no labels: a dotted string, which "is not" how the field is encoded
    let dotted = hex::encode("internet.mnc093.mcc208.gprs");
    assert_eq!(
        value_found::<ApnDnn>(&dotted),
        [("8.2.117", DeviationKind::Rule(rule))]
    );
    // In a Session Establishment Request, where it is optional: of no Cause
    let mut message = establishment();
    request_with(&mut message, |request| {
        request.apn_dnn = Some(ApnDnn(b"\x08internet".to_vec().into()))
    });
    let found = message.check(Interfaces::N4);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        (
            found[0].path.as_str(),
            found[0].kind.clone(),
            found[0].cause
        ),
        ("/pfcp/APN~1DNN", DeviationKind::Rule(rule), None)
    );
}

/// The formats that clause 8.2 gives a value with "shall": an NF Instance ID, "a
/// Universally Unique Identifier (UUID) version 4" (§8.2.175); a Metadata, "base64-encoded
/// characters" (§8.2.219); a Calling Number, a Called Number, a Tunnel Password, and the
/// Key ID and the Shared Secret of a Key ID and Shared Secret, "encoded in UTF8String
/// format", the Key ID "without padding with zero octets" (§8.2.190, §8.2.191, §8.2.212,
/// §8.2.276). A value of another format is told.
#[test]
fn the_formats_of_the_values_of_clause_8_2() {
    fn told<T: Codec + Check>(
        clause: &'static str,
        rule: &'static str,
        other: &[&str],
        kept: &[&str],
    ) {
        for octets in other {
            let octets = octets.replace(' ', "");
            let expected = [(clause, DeviationKind::Rule(rule))];
            assert_eq!(value_found::<T>(&octets), expected, "{octets}");
        }
        for octets in kept {
            let octets = octets.replace(' ', "");
            assert_eq!(value_found::<T>(&octets), [], "{octets}");
        }
    }
    // Of every bit set, of no bit set, of version 1, of version 4 and another variant; of
    // version 4, 550e8400-e29b-41d4-a716-446655440000, and of each variant of RFC 9562
    told::<NfInstanceId>(
        "8.2.175",
        "an NF Instance ID that is no UUID of version 4",
        &[
            "ffffffffffffffffffffffffffffffff",
            "00000000000000000000000000000000",
            "550e8400e29b11d4a716446655440000",
            "550e8400e29b41d4c716446655440000",
            "550e8400e29b41d42716446655440000",
        ],
        &[
            "550e8400e29b41d4a716446655440000",
            "550e8400e29b41d48716446655440000",
            "550e8400e29b4fffbfffffffffffffff",
        ],
    );
    // Octets that are no characters; three characters; a padding within; the alphabet of
    // URLs; a space. "abc", "ab" and "a" as base64, and every character of the alphabet
    let hex = |text: &str| hex::encode(text);
    told::<Metadata>(
        "8.2.219",
        "a Metadata that is not base64-encoded characters",
        &[
            "00ff2a",
            &hex("YWJ"),
            &hex("YQ=a"),
            &hex("Y==="),
            &hex("YW-_"),
            &hex("YW J"),
            &hex("YWJj\n"),
        ],
        &[&hex("YWJj"), &hex("YWI="), &hex("YQ=="), &hex("AZaz09+/")],
    );
    told::<CallingNumber>(
        "8.2.190",
        "a Calling Number value that is not UTF-8",
        &["fffe", "33c3"],
        &[&hex("33612345678"), &hex("é")],
    );
    told::<CalledNumber>(
        "8.2.191",
        "a Called Number value that is not UTF-8",
        &["fffe"],
        &[&hex("internet")],
    );
    told::<TunnelPassword>(
        "8.2.212",
        "a Tunnel Password value that is not UTF-8",
        &["fffe"],
        &[&hex("secret")],
    );
    told::<KeyIdAndSharedSecret>(
        "8.2.276",
        "a Key ID that is not UTF-8",
        &["02 fffe 01 61"],
        &["02 6162 01 61", "00 01 61"],
    );
    told::<KeyIdAndSharedSecret>(
        "8.2.276",
        "a Key ID padded with zero octets",
        &["03 616200 01 61", "01 00 01 61"],
        &["03 610062 01 61"],
    );
    told::<KeyIdAndSharedSecret>(
        "8.2.276",
        "a Shared Secret that is not UTF-8",
        &["01 61 02 fffe"],
        &["01 61 02 c3a9"],
    );
    // No refusal prints the password or the passphrase
    let secret = KeyIdAndSharedSecret::decode(&[1, b'k', 2, 0xff, 0xfe]).unwrap();
    let said = format!("{:?}", secret.deviations());
    assert!(
        !said.contains("fffe") && !said.contains("255, 254"),
        "{said}"
    );
}

/// §8.2.20: the Redirect Server Address "shall be encoded in UTF8String format", and is
/// the address that the Redirect Address Type says, as IETF RFC 4006 has the
/// Redirect-Server-Address of a Redirect-Address-Type: an IPv4 address in text, or an IPv6
/// address; and "If the Redirect Address type is set to "IPv4 and IPv6 address", the
/// Redirect Information IE shall include an IPv4 address and an IPv6 address in the
/// Redirect Server Address IE and Other Redirect Server Address", in either order. A URL
/// and a SIP URI are any text.
#[test]
fn the_addresses_of_a_redirect_information_are_those_of_its_type() {
    // A Redirect Information of the type, its addresses and, of a type with one, a port
    let found = |kind: u8, addresses: &[&[u8]]| {
        let mut octets = vec![kind];
        for address in addresses {
            octets.extend((address.len() as u16).to_be_bytes());
            octets.extend(*address);
        }
        if (5..=8).contains(&kind) {
            octets.extend(8080u16.to_be_bytes());
        }
        value_found::<RedirectInformation>(&hex::encode(octets))
    };
    let rule = |rule| [("8.2.20", DeviationKind::Rule(rule))];
    let text = "a Redirect Server Address that is not UTF-8";
    let one = "the Redirect Server Address does not match its Redirect Address Type: an IPv4 or IPv6 address in text, a URL or a SIP URI";
    let two = "a Redirect Server Address and an Other Redirect Server Address that are not an IPv4 address and an IPv6 address, in text";
    let (v4, v6): (&[u8], &[u8]) = (b"192.0.2.1", b"2001:db8::1");
    for (kind, address, other) in [(0, v4, v6), (6, v4, v6), (1, v6, v4), (7, v6, v4)] {
        assert_eq!(found(kind, &[address]), [], "{kind}");
        for wrong in [
            other,
            b"http://example.com/",
            b"",
            b"192.0.2",
            b"0xc0000201",
        ] {
            assert_eq!(found(kind, &[wrong]), rule(one), "{kind} {wrong:?}");
        }
        assert_eq!(found(kind, &[&[0xff]]), rule(text), "{kind}");
    }
    assert_eq!(found(1, &[b"2001:0db8:0000:0000:0000:0000:0000:0001"]), []);
    assert_eq!(found(1, &[b"::ffff:192.0.2.1"]), []);
    for kind in [4, 8] {
        assert_eq!(found(kind, &[v4, v6]), [], "{kind}");
        assert_eq!(found(kind, &[v6, v4]), [], "{kind}");
        for (first, second) in [
            (v4, v4),
            (v6, v6),
            (v4, &b"example.com"[..]),
            (&b""[..], v6),
        ] {
            assert_eq!(found(kind, &[first, second]), rule(two), "{kind}");
        }
        assert_eq!(found(kind, &[v4, &[0xff]]), rule(text), "{kind}");
        assert_eq!(found(kind, &[&[0xff], v6]), rule(text), "{kind}");
    }
    // A URL, of a scheme and what follows it (IETF RFC 3986), and a SIP URI, `sip:` or
    // `sips:` (IETF RFC 3261)
    for url in [
        &b"http://example.com/"[..],
        b"sip:alice@example.com",
        b"a+b.c-1:x",
    ] {
        assert_eq!(found(2, &[url]), [], "{url:?}");
    }
    for other in [
        v4,
        b"example.com",
        b"http:",
        b"://example.com",
        b"1http://x",
        b"http://a b/",
    ] {
        assert_eq!(found(2, &[other]), rule(one), "{other:?}");
    }
    for uri in [
        &b"sip:alice@example.com"[..],
        b"sips:example.com",
        b"SIP:alice@example.com:5060",
    ] {
        assert_eq!(found(3, &[uri]), [], "{uri:?}");
    }
    for other in [
        &b"http://example.com/"[..],
        b"alice@example.com",
        b"sip:",
        b"sip:a b",
    ] {
        assert_eq!(found(3, &[other]), rule(one), "{other:?}");
    }
    for kind in [2, 3] {
        assert_eq!(found(kind, &[&[0xff]]), rule(text), "{kind}");
    }
    // A Port alone has no address
    assert_eq!(found(5, &[]), []);
}

/// The formats of other documents that a clause cites: the digits of the IMSI, the IMEI
/// and the MSISDN of a User ID, TBCD digits as TS 29.274 clauses 8.3, 8.10 and 8.11 have
/// them, of the numbers of TS 23.003 (an IMSI of at most 15 digits, an IMEI of 15 or an
/// IMEISV of 16, an MSISDN of at most 15); and the Flow Description of an SDF Filter and
/// of a Flow Information, an IPFilterRule as TS 29.212 clause 5.4.2 restricts it: `permit
/// out`, a protocol number or `ip`, `from` an address `to` an address, each with its
/// ports, no option and no `!`.
#[test]
fn the_formats_of_other_documents_that_a_clause_cites() {
    let rule = |clause, rule| [(clause, DeviationKind::Rule(rule))];
    // IMSIF, IMEIF and MSISDNF, each with its digits
    let user = |flag: u8, digits: &str| {
        let octets = hex::decode(digits).unwrap();
        value_found::<UserId>(&format!("{flag:02x}{:02x}{digits}", octets.len()))
    };
    let imsi = "the IMSI is not 6 to 15 decimal digits";
    let imei = "the IMEI is not 15 or 16 decimal digits";
    let msisdn = "the MSISDN is not 1 to 15 decimal digits";
    for (flag, kept, others, told) in [
        (
            1,
            &["029803", "02980300000000f1"][..],
            &["0298f3", "0a9803", "0298030000000010", ""][..],
            imsi,
        ),
        (
            2,
            &["1032547698103254", "10325476981032f4"],
            &["1032547698", "103254769810325476", "1a325476981032f4"],
            imei,
        ),
        (
            4,
            &["33", "33163254769810f2", "f3"],
            &["", "3316325476981032", "3b"],
            msisdn,
        ),
    ] {
        for digits in kept {
            assert_eq!(user(flag, digits), [], "{flag} {digits}");
        }
        for digits in others {
            assert_eq!(user(flag, digits), rule("8.2.101", told), "{flag} {digits}");
        }
    }
    // FD and its Flow Description; a Flow Information of the Flow Direction "Downlink"
    let told = "the Flow Description is not an IPFilterRule (TS 29.212 clause 5.4.2)";
    let filter = |text: &str| {
        let length = (text.len() as u16).to_be_bytes();
        value_found::<SdfFilter>(&hex::encode(
            [&[1, 0][..], &length, text.as_bytes()].concat(),
        ))
    };
    let flow = |text: &str| {
        let length = (text.len() as u16).to_be_bytes();
        value_found::<FlowInformation>(&hex::encode([&[1][..], &length, text.as_bytes()].concat()))
    };
    for kept in [
        "permit out ip from any to assigned",
        "permit out 58 from ff02::2/128 to assigned",
        "permit out 17 from 192.0.2.0/24 5000-5010 to assigned 4000",
        "permit out 6 from 2001:db8::1 80,443 to 10.45.0.2/32",
        "permit out ip from any to any",
    ] {
        assert_eq!(filter(kept), [], "{kept}");
        assert_eq!(flow(kept), [], "{kept}");
    }
    for other in [
        "",
        "deny out ip from any to assigned",
        "permit in ip from any to assigned",
        "permit out tcp from any to assigned",
        "permit out 256 from any to assigned",
        "permit out ip from !192.0.2.1 to assigned",
        "permit out ip from 192.0.2.0/33 to assigned",
        "permit out ip from any 70000 to assigned",
        "permit out ip from any 20-10 to assigned",
        "permit out ip from any to assigned frag",
        "permit out ip to assigned from any",
        "permit out ip from any",
        "permit  out ip from any to assigned",
    ] {
        assert_eq!(filter(other), rule("8.2.5", told), "{other}");
        assert_eq!(flow(other), rule("8.2.61", told), "{other}");
    }
    assert_eq!(value_found::<SdfFilter>("01000001ff"), rule("8.2.5", told));
}

/// §8.2.67: "For a HTTP Header Type, the contents of the Header Field Name and Header
/// Field Value shall comply with the HTTP header field format (see clause 5 of IETF RFC
/// 9110)": the name is a token, and the value field content, of visible characters, of
/// spaces and tabs between them, and of the octets above them, with no whitespace before
/// or after it.
#[test]
fn the_header_field_of_a_header_enrichment_is_one_of_http() {
    let found = |kind: u8, name: &[u8], value: &[u8]| {
        let octets = [
            &[kind, name.len() as u8][..],
            name,
            &[value.len() as u8],
            value,
        ]
        .concat();
        value_found::<HeaderEnrichment>(&hex::encode(octets))
    };
    let rule = |rule| [("8.2.67", DeviationKind::Rule(rule))];
    let named = "a Header Field Name that is no field name of HTTP";
    let valued = "a Header Field Value that is no field value of HTTP";
    for (name, value) in [
        (&b"X-Test"[..], &b"abc"[..]),
        (b"x", b""),
        (b"!#$%&'*+-.^_`|~09AZaz", b"a b\tc \xe9!"),
        (b"Host", b"example.com:8080"),
    ] {
        assert_eq!(found(0, name, value), [], "{name:?} {value:?}");
    }
    for name in [
        &b""[..],
        b"X Test",
        b"X:Test",
        b"X-Test:",
        b"X\xe9",
        b"(x)",
        b"a\0",
    ] {
        assert_eq!(found(0, name, b"abc"), rule(named), "{name:?}");
    }
    for value in [
        &b" abc"[..],
        b"abc ",
        b"\tabc",
        b"a\r\nb",
        b"a\0b",
        b"a\x7fb",
        b"\n",
    ] {
        assert_eq!(found(0, b"X-Test", value), rule(valued), "{value:?}");
    }
    // Of another Header Type, which Table 8.2.67-1 has as spare: of no format
    let spare = [("8.2.67", DeviationKind::SpareValue { value: 1 })];
    assert_eq!(found(1, b"X Test", b" abc"), spare);
}

/// §8.2.39, bit 5: with DNP, "the Length of Domain Name and the Domain Name fields shall
/// also be present", which DN has there: a Domain Name Protocol is of a Domain Name.
#[test]
fn the_domain_name_protocol_of_pfd_contents_has_its_domain_name() {
    // DNP alone, and the protocol "tls"
    let alone = value_found::<PfdContents>("10000003746c73");
    let rule = DeviationKind::Rule("DNP is set and DN is not");
    assert_eq!(alone, [("8.2.39", rule)]);
    // DN and DNP: "a.com", then "tls"; and DN alone
    assert_eq!(
        value_found::<PfdContents>("14000005612e636f6d0003746c73"),
        []
    );
    assert_eq!(value_found::<PfdContents>("04000005612e636f6d"), []);
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

/// The bits 8 to 5 of the octet "v" of a Flow Label are spare and zero (§8.2.5), and the
/// Number of Additional Usage Reports is 0 where AURI says that more follow, "set to "0" by
/// the sender and ignored by the receiver" (§8.2.91): told as a spare bit is, with no Cause.
#[test]
fn the_spare_bits_of_a_flow_label_and_the_number_of_more_usage_reports() {
    let kinds = |value: &dyn Check| -> Vec<(&'static str, DeviationKind)> {
        let found = value.deviations().into_iter();
        found
            .map(|deviation| (deviation.clause, deviation.kind))
            .collect()
    };
    let label = |flow_label| SdfFilter {
        fl: true,
        flow_label: Some(U24(flow_label)),
        ..Default::default()
    };
    assert_eq!(kinds(&label(0x0f_ffff)), []);
    assert_eq!(
        kinds(&label(0xf0_0001)),
        [("8.2.5", DeviationKind::SpareBits)]
    );
    let more = |auri, number| AdditionalUsageReportsInformation {
        auri,
        number,
        ..Default::default()
    };
    assert_eq!(kinds(&more(true, 0)), []);
    assert_eq!(kinds(&more(false, 3)), []);
    assert_eq!(
        kinds(&more(true, 3)),
        [("8.2.91", DeviationKind::SpareBits)]
    );
    // In a request, whose receiver answers a deviation of its IEs with a Cause
    let report = SessionReportRequest {
        report_type: Some(ReportType {
            usar: true,
            ..Default::default()
        }),
        additional_usage_reports_information: Some(more(true, 5)),
        ..Default::default()
    };
    let found: Vec<_> = Message::session(1, 7, report)
        .check(Interfaces::N4)
        .into_iter()
        .map(|deviation| (deviation.path, deviation.kind, deviation.cause))
        .collect();
    let at = "/pfcp/Additional Usage Reports Information".to_string();
    assert!(
        found.contains(&(at, DeviationKind::SpareBits, None)),
        "{found:?}"
    );
    // A field that its receiver ignores is no spare bit, which the words say
    let said = Deviation::new("/pfcp", "8.2.91", DeviationKind::SpareBits).to_string();
    assert_eq!(
        said,
        "spare or ignored bits are not zero (TS 29.244 8.2.91), at /pfcp"
    );
}

/// §8.2.241: where FI, PSSAI or NPDSI is 0, the Format, PSSA or NPDS field of octet 6 "shall
/// be coded as all "0" and be ignored by the receiver": one set is told as a spare bit is,
/// and a Format of 0 is no spare value where FI is 0.
#[test]
fn the_fields_of_rtp_header_extension_additional_information_that_a_flag_gives() {
    type Rtp = RtpHeaderExtensionAdditionalInformation;
    let ignored = || ("8.2.241", DeviationKind::SpareBits);
    // FI 0, Format 0; FI, Format 1; PSSAI, PSSA; NPDSI, NPDS; PSSAI and NPDSI without them
    for octets in ["0000", "0101", "0204", "0408", "0600"] {
        assert_eq!(value_found::<Rtp>(octets), [], "{octets}");
    }
    // FI 0, Format 1; PSSAI 0, PSSA; NPDSI 0, NPDS; FI 0, Format 3, PSSA and NPDS
    for (octets, found) in [
        ("0001", vec![ignored()]),
        ("0105", vec![ignored()]),
        ("0008", vec![ignored()]),
        ("000f", vec![ignored(), ignored(), ignored()]),
    ] {
        assert_eq!(value_found::<Rtp>(octets), found, "{octets}");
    }
    // FI with a Format of Table 8.2.241-1's spare values
    let spare = |value| ("8.2.241", DeviationKind::SpareValue { value });
    assert_eq!(value_found::<Rtp>("0100"), [spare(0)]);
    assert_eq!(value_found::<Rtp>("0103"), [spare(3)]);
}

/// §8.2.20 and §8.2.229: a Redirect Information of type "Port" has no Redirect Server
/// Address, and a Reporting Suggestion Info has a Reporting Time Info where it is "Delay
/// tolerant" alone. Octets of that field after a value that does not have it are told, as
/// those of a TEID after an F-TEID's CH are: its receiver ignores them as octets of a
/// later release (§8.1.2), which other octets are. In a request on N4, its receiver reads
/// the port of a Port redirect, and the urgency of a suggestion that is not delay tolerant.
#[test]
fn a_field_that_the_value_of_another_has_not() {
    let port = "the Redirect Address Type is Port, and octets of a Redirect Server Address follow";
    assert_eq!(value_found::<RedirectInformation>("051f90"), []);
    assert_eq!(value_found::<RedirectInformation>("051f90ab"), []);
    for octets in ["0500001f90", "050004616263641f90"] {
        let told = value_found::<RedirectInformation>(octets);
        assert_eq!(told, [("8.2.20", DeviationKind::Rule(port))], "{octets}");
    }
    let time =
        "the Reporting Urgency is not Delay tolerant, and octets of a Reporting Time Info follow";
    assert_eq!(value_found::<ReportingSuggestionInfo>("01"), []);
    assert_eq!(value_found::<ReportingSuggestionInfo>("0000000005"), []);
    assert_eq!(value_found::<ReportingSuggestionInfo>("0100"), []);
    let told = value_found::<ReportingSuggestionInfo>("0100000005");
    assert_eq!(told, [("8.2.229", DeviationKind::Rule(time))]);
    // In a Session Establishment Request: a Create FAR that redirects, and a Create SRR
    let node = ie(60, &[0, 10, 0, 0, 1]);
    let seid = ie(57, &[2, 0, 0, 0, 0, 0, 0, 0, 1, 10, 0, 0, 1]);
    let [pdr, _] = rules();
    let redirect = |octets: &str| {
        let forwarding = [ie(42, &[1]), ie(38, &hex::decode(octets).unwrap())].concat();
        let far = [ie(108, &[0, 0, 0, 1]), ie(44, &[2, 0]), ie(4, &forwarding)].concat();
        found(&session_message(
            50,
            0,
            &[node.clone(), seid.clone(), pdr.clone(), ie(3, &far)],
        ))
    };
    assert_eq!(redirect("051f90"), []);
    let told = (
        DeviationKind::Rule(port),
        Some(CauseValue::MandatoryIeIncorrect),
        Some(38),
    );
    for octets in ["0500001f90", "050004616263641f90"] {
        assert_eq!(redirect(octets), std::slice::from_ref(&told), "{octets}");
    }
    let suggestion = |octets: &str| {
        let control = [
            ie(124, &[9]),
            ie(243, &[1]),
            ie(244, &[2]),
            ie(64, &[0, 0, 0, 10]),
            ie(335, &hex::decode(octets).unwrap()),
        ]
        .concat();
        let srr = ie(212, &[ie(215, &[1]), ie(242, &control)].concat());
        let [pdr, far] = rules();
        found(&session_message(
            50,
            0,
            &[node.clone(), seid.clone(), pdr, far, srr],
        ))
    };
    assert_eq!(suggestion("01"), []);
    assert_eq!(suggestion("0000000005"), []);
    assert_eq!(
        suggestion("0100000005"),
        [(DeviationKind::Rule(time), None, None)]
    );
}

/// §8.2.62: S/D of a UE IP Address says a source or a destination address in a PDI, a
/// Create and an Update Traffic Endpoint, and "shall be set to "0" and ignored by the
/// receiver" in the others: told there as a spare bit is, with no Cause. CH and CHID of an
/// F-TEID, CHV4 and CHV6 of a UE IP Address, CH of a Local Ingress Tunnel and CHV4 of a
/// Mapped N6 IP Address "shall only be set by the CP function": set in an IE of a message
/// that the UP function sends, they are told. §8.2.206: bits 4 to 1 of the last octet of
/// the NID of an MBS Session Identifier "shall all be encoded as 0".
#[test]
fn what_the_place_of_a_value_has_it_set() {
    let placed = |message: &Message,
                  interface|
     -> Vec<(String, &'static str, DeviationKind, Option<CauseValue>)> {
        let octets = message.encode().unwrap();
        Message::decode(&octets)
            .unwrap()
            .check(interface)
            .into_iter()
            .filter(|deviation| {
                ["8.2.3", "8.2.62", "8.2.209", "8.2.242"].contains(&deviation.clause)
            })
            .map(|deviation| {
                (
                    deviation.path,
                    deviation.clause,
                    deviation.kind,
                    deviation.cause,
                )
            })
            .collect()
    };
    let destination = UeIpAddress {
        v4: true,
        sd: true,
        ipv4: Some(Ipv4Addr::new(10, 45, 0, 2)),
        ..Default::default()
    };
    let chosen = UeIpAddress {
        chv4: true,
        ..Default::default()
    };
    // In a PDI, a Create and an Update Traffic Endpoint of the CP function: neither is told
    let mut message = establishment();
    request_with(&mut message, |request| {
        let pdi = request.create_pdr[0].pdi.as_mut().unwrap();
        pdi.ue_ip_address = vec![destination.clone(), chosen.clone()];
        pdi.local_f_teid = Some(FTeid::choose_ipv4());
        request.create_traffic_endpoint = vec![CreateTrafficEndpoint {
            traffic_endpoint_id: Some(TrafficEndpointId::new(1)),
            ue_ip_address: vec![destination.clone(), chosen.clone()],
            ..Default::default()
        }];
    });
    assert_eq!(placed(&message, Interfaces::N4), []);
    let update = SessionModificationRequest {
        update_traffic_endpoint: vec![UpdateTrafficEndpoint {
            traffic_endpoint_id: Some(TrafficEndpointId::new(1)),
            ue_ip_address: vec![destination.clone()],
            ..Default::default()
        }],
        ..Default::default()
    };
    assert_eq!(placed(&Message::session(1, 8, update), Interfaces::N4), []);
    // In a Created PDR and a Created Traffic Endpoint of the UP function
    let response = SessionEstablishmentResponse {
        node_id: Some(NodeId::Ipv4(SMF)),
        cause: Some(Cause::new(CauseValue::RequestAccepted)),
        up_f_seid: Some(FSeid::ipv4(1, SMF)),
        created_pdr: vec![CreatedPdr {
            pdr_id: Some(PdrId::new(1)),
            f_teid: vec![FTeid::choose_ipv4()],
            ue_ip_address: vec![destination.clone(), chosen.clone()],
            ..Default::default()
        }],
        created_traffic_endpoint: vec![CreatedTrafficEndpoint {
            traffic_endpoint_id: Some(TrafficEndpointId::new(1)),
            ue_ip_address: vec![destination.clone()],
            mapped_n6_ip_address: Some(MappedN6IpAddress {
                chv4: true,
                ..Default::default()
            }),
            ..Default::default()
        }],
        ..Default::default()
    };
    let spare = |path: &str| (path.to_string(), "8.2.62", DeviationKind::SpareBits, None);
    let rule =
        |path: &str, clause, rule| (path.to_string(), clause, DeviationKind::Rule(rule), None);
    let by_up = "CH or CHID is set in an IE of the UP function";
    let chosen_by_up = "CHV4 or CHV6 is set in an IE of the UP function";
    let mapped_by_up = "CHV4 is set in an IE of the UP function";
    assert_eq!(
        placed(&Message::session(1, 7, response.clone()), Interfaces::N4),
        [
            rule("/pfcp/Created PDR/0/F-TEID/0", "8.2.3", by_up),
            spare("/pfcp/Created PDR/0/UE IP Address/0"),
            rule(
                "/pfcp/Created PDR/0/UE IP Address/1",
                "8.2.62",
                chosen_by_up
            ),
            spare("/pfcp/Created Traffic Endpoint/0/UE IP Address/0"),
            rule(
                "/pfcp/Created Traffic Endpoint/0/Mapped N6 IP Address",
                "8.2.242",
                mapped_by_up
            ),
        ]
    );
    // A Local Ingress Tunnel of an MB-UPF, on N4mb
    let tunnel = LocalIngressTunnel {
        ch: true,
        v4: true,
        ..Default::default()
    };
    let mbs = SessionEstablishmentResponse {
        created_pdr: vec![CreatedPdr {
            pdr_id: Some(PdrId::new(1)),
            local_ingress_tunnel: Some(tunnel.clone()),
            ..Default::default()
        }],
        ..response.clone()
    };
    let by_up = "CH is set in an IE of the UP function";
    assert_eq!(
        placed(&Message::session(1, 7, mbs), Interfaces::N4MB),
        [rule(
            "/pfcp/Created PDR/0/Local Ingress Tunnel",
            "8.2.209",
            by_up
        )]
    );
    // In an Updated PDR of a Session Modification Response, and in a Usage Report of a
    // Session Report Request
    let modified = SessionModificationResponse {
        cause: Some(Cause::new(CauseValue::RequestAccepted)),
        updated_pdr: vec![UpdatedPdr {
            pdr_id: Some(PdrId::new(1)),
            ue_ip_address: vec![destination.clone()],
            ..Default::default()
        }],
        ..Default::default()
    };
    assert_eq!(
        placed(&Message::session(1, 8, modified), Interfaces::N4),
        [spare("/pfcp/Updated PDR/0/UE IP Address/0")]
    );
    let report = SessionReportRequest {
        report_type: Some(ReportType {
            usar: true,
            ..Default::default()
        }),
        usage_report: vec![UsageReport {
            urr_id: Some(UrrId::new(1)),
            ur_seqn: Some(UrSeqn::new(1)),
            usage_report_trigger: Some(UsageReportTrigger {
                perio: true,
                ..Default::default()
            }),
            ue_ip_address: Some(destination),
            ..Default::default()
        }],
        ..Default::default()
    };
    assert_eq!(
        placed(&Message::session(1, 9, report), Interfaces::N4),
        [spare("/pfcp/Usage Report/0/UE IP address")]
    );
    // The NID: 11 digits, and four bits of 0
    let nid = |last: &str| format!("05 010203 02f839 123456789a{last}").replace(' ', "");
    assert_eq!(value_found::<MbsSessionIdentifier>(&nid("b0")), []);
    assert_eq!(
        value_found::<MbsSessionIdentifier>(&nid("b5")),
        [("8.2.206", DeviationKind::SpareBits)]
    );
}

/// §8.2.43: "Values of Number of CSID greater than 1 shall only be employed in the PFCP
/// Session Deletion Request", which has no FQ-CSID: in a Session Set Deletion Request, and
/// in the Session Change Info of a Session Set Modification Request, which are of sets of
/// sessions too. "The value 0 shall be used in a PFCP Session Modification Request, with
/// the FQ-CSID Node-ID Type and Node-Address fields set to all zeros, and with the Node
/// Type indicating one node type, to remove an FQ-CSID". §8.2.108: the MCC and the MNC of a
/// Trace Information are decimal digits, but the filler of an MNC of two (TS 24.008 clause
/// 10.5.1.4).
#[test]
fn the_identifiers_of_an_fq_csid_in_its_message_and_the_digits_of_a_plmn() {
    let told = |message: Message| -> Vec<(String, &'static str, DeviationKind)> {
        let octets = message.encode().unwrap();
        Message::decode(&octets)
            .unwrap()
            .check(Interfaces::N4)
            .into_iter()
            .filter(|deviation| ["8.2.43", "8.2.108"].contains(&deviation.clause))
            .map(|deviation| (deviation.path, deviation.clause, deviation.kind))
            .collect()
    };
    let fq_csid = |node_address: [u8; 4], csids: Vec<u16>, node_type| FqCsid {
        node_id_type: 0,
        node_address: node_address.into(),
        csids,
        node_type,
        extra: Octets::default(),
    };
    let smf = Some(Narrow {
        value: NodeType::PgwCSmf,
        spare: 0,
    });
    let several =
        "more than one PDN Connection Set Identifier outside a request of a set of sessions";
    let mut message = establishment();
    request_with(&mut message, |request| {
        request.fq_csid = vec![fq_csid([10, 0, 0, 1], vec![1, 2], smf)];
    });
    assert_eq!(
        told(message),
        [(
            "/pfcp/FQ-CSID/0".to_string(),
            "8.2.43",
            DeviationKind::Rule(several)
        )]
    );
    let set = SessionSetDeletionRequest {
        node_id: Some(NodeId::Ipv4(SMF)),
        fq_csid: vec![fq_csid([10, 0, 0, 1], vec![1, 2, 3], smf)],
        ..Default::default()
    };
    assert_eq!(told(Message::node(1, set)), []);
    // A removal in a Session Modification Request
    let removal = |fq_csid| {
        let request = SessionModificationRequest {
            fq_csid: vec![fq_csid],
            ..Default::default()
        };
        told(Message::session(1, 8, request))
    };
    assert_eq!(removal(fq_csid([0; 4], vec![], smf)), []);
    let removes = "an FQ-CSID of no PDN Connection Set Identifier with a Node-ID Type or a Node-Address other than zeros, or no Node Type";
    let rule = || {
        vec![(
            "/pfcp/FQ-CSID/0".to_string(),
            "8.2.43",
            DeviationKind::Rule(removes),
        )]
    };
    assert_eq!(removal(fq_csid([10, 0, 0, 1], vec![], smf)), rule());
    assert_eq!(removal(fq_csid([0; 4], vec![], None)), rule());
    assert_eq!(removal(fq_csid([10, 0, 0, 1], vec![7], smf)), []);
    // The digits of the PLMN of a Trace Information
    let trace = |plmn: [u8; 3]| {
        let mut message = establishment();
        request_with(&mut message, |request| {
            request.trace_information = Some(TraceInformation {
                mcc_mnc: PlmnId(plmn),
                trace_id: U24(1),
                triggering_events: Lv8(vec![1u8].into()),
                session_trace_depth: 1,
                list_of_interfaces: Lv8(vec![1u8].into()),
                ip_address_of_trace_collection_entity: Lv8(vec![10u8, 0, 0, 1].into()),
                ..Default::default()
            });
        });
        told(message)
    };
    assert_eq!(trace([0x02, 0xf8, 0x39]), []);
    assert_eq!(trace([0x13, 0x00, 0x14]), []);
    let digits = "an MCC or MNC digit that is not decimal";
    for plmn in [[0x0a, 0xf8, 0x39], [0x02, 0xf8, 0x3b], [0x02, 0xe8, 0x39]] {
        assert_eq!(
            trace(plmn),
            [(
                "/pfcp/Trace Information".to_string(),
                "8.2.108",
                DeviationKind::Rule(digits)
            )],
            "{plmn:02x?}"
        );
    }
}

/// The Additional Monitoring Time of a Create URR has its subsequent event threshold and
/// quota of the IE types of Event Threshold (149) and Event Quota (148), as Table 7.5.2.4-3
/// has them, where Create URR and Update URR have rows of the same names of the types 151
/// and 150, which are of no row of the table.
#[test]
fn the_subsequent_event_threshold_and_quota_of_an_additional_monitoring_time() {
    let urr = |ies: &[Vec<u8>]| {
        let additional = ie(147, &[&[ie(33, &[0, 0, 0, 1])][..], ies].concat().concat());
        let urr = [
            ie(81, &[0, 0, 0, 1]),
            ie(62, &[4]),
            ie(37, &[1, 0]),
            ie(64, &[0, 0, 0, 10]),
            additional,
        ];
        ie(6, &urr.concat())
    };
    let node = ie(60, &[0, 10, 0, 0, 1]);
    let seid = ie(57, &[2, 0, 0, 0, 0, 0, 0, 0, 1, 10, 0, 0, 1]);
    let [pdr, far] = rules();
    let kinds = |ies: &[Vec<u8>]| -> Vec<DeviationKind> {
        let message = session_message(
            50,
            0,
            &[
                node.clone(),
                seid.clone(),
                pdr.clone(),
                far.clone(),
                urr(ies),
            ],
        );
        found(&message).into_iter().map(|(kind, ..)| kind).collect()
    };
    assert_eq!(kinds(&[ie(149, &[0, 0, 0, 5]), ie(148, &[0, 0, 0, 9])]), []);
    assert_eq!(
        kinds(&[ie(151, &[0, 0, 0, 5]), ie(150, &[0, 0, 0, 9])]),
        [
            DeviationKind::Unexpected { ie_type: 151 },
            DeviationKind::Unexpected { ie_type: 150 }
        ]
    );
}
