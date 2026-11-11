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

//! The interfaces: the Appl. columns of each table, the messages of each interface, and a set of
//! them.

use super::*;

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
fn the_conditions_read_each_row_that_the_interface_has() {
    // A Create PDR of an Outer Header Removal, which Sxc does not have, then of Activate
    // Predefined Rules, without a FAR ID: the row after the one that the interface
    // discards is read, and has the FAR ID not needed (Table 7.5.2.2-1)
    let node = ie(60, &[0, 10, 0, 0, 1]);
    let seid = ie(57, &[2, 0, 0, 0, 0, 0, 0, 0, 1, 10, 0, 0, 1]);
    let pdr = ie(
        1,
        &[
            ie(56, &[0, 1]),
            ie(29, &[0, 0, 0, 1]),
            ie(2, &ie(20, &[0])),
            ie(95, &[0]),
            ie(106, b"rule"),
        ]
        .concat(),
    );
    let far = ie(3, &[ie(108, &[0, 0, 0, 1]), ie(44, &[1, 0])].concat());
    let message = Message::decode(&session_message(50, 0, &[node, seid, pdr, far])).unwrap();
    let on = |interface| -> Vec<(String, DeviationKind)> {
        let found = message.check(interface).into_iter();
        found.map(|found| (found.path, found.kind)).collect()
    };
    assert_eq!(
        on(Interfaces::SXC),
        [(
            "/pfcp/Create PDR/0/Outer Header Removal".to_string(),
            DeviationKind::NotOnInterface { ie_type: 95 }
        )]
    );
    assert_eq!(on(Interfaces::N4), []);
}

/// A grouped IE on its own is checked on the interfaces of its table.
#[test]
fn a_grouped_ie_on_its_own_needs_what_its_interfaces_need() {
    let found = CreateMar::default().deviations();
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

/// On a set of interfaces, a message needs what each of them needs: a conditional IE
/// that one of them lacks is not missing where its condition holds, as a mandatory one
/// that one of them lacks is not. Volume Quota is conditional in Create URR on Sxb, and
/// not on Sxa (Table 7.5.2.4-1); Precedence is mandatory in Create PDR on Sxb, and not on
/// Sxa (Table 7.5.2.2-1).
#[test]
fn on_a_set_of_interfaces_a_conditional_ie_that_one_lacks_is_not_missing() {
    let urr = CreateUrr::new(
        UrrId::new(1),
        MeasurementMethod {
            volum: true,
            ..Default::default()
        },
        ReportingTriggers {
            volqu: true,
            ..Default::default()
        },
    );
    let message = Message::session(
        1,
        1,
        SessionModificationRequest::default().with_create_urr(urr),
    );
    let missing = DeviationKind::ConditionalMissing { ie_type: 73 };
    assert_eq!(kinds(&message, Interfaces::SXB), [missing]);
    assert_eq!(kinds(&message, Interfaces::SXA), []);
    assert_eq!(kinds(&message, Interfaces::SXA_SXB), []);
    let row = CreateUrr::table().row_of(73).unwrap();
    let on = |interfaces| row.on(interfaces).and_then(|on| on.presence);
    assert_eq!(on(Interfaces::SXB), Some(Presence::Conditional));
    assert_eq!(on(Interfaces::SXA), None);
    assert_eq!(on(Interfaces::SXA_SXB), None);
}

/// §7.6.9: an IE of a row that is not on the interface is discarded whole, and the
/// message processed: it is told once, without a Cause, and not for what its value breaks
/// or for a value that does not decode. A Precedence of three octets on Sxa, which has no
/// Precedence in Create PDR, and on the combined Sxa/Sxb, which does not need it, where it
/// is incorrect; on Sxc, a Transport Level Marking of a mask other than 0xFC and an Outer
/// Header Creation of no description, which Forwarding Parameters has on Sxa, Sxb and N4
/// (Table 7.5.2.3-2).
#[test]
fn an_ie_of_a_row_not_on_the_interface_is_told_once() {
    let checked = |forwarding: &[Vec<u8>], precedence: &[u8], interface: Interfaces| {
        let pdr = ie(
            1,
            &[
                ie(56, &[0, 1]),
                ie(29, precedence),
                ie(2, &ie(20, &[0])),
                ie(108, &[0, 0, 0, 1]),
            ]
            .concat(),
        );
        let far = ie(
            3,
            &[
                ie(108, &[0, 0, 0, 1]),
                ie(44, &[2, 0]),
                ie(4, &[&ie(42, &[1])[..], &forwarding.concat()].concat()),
            ]
            .concat(),
        );
        let f_seid = [2, 0, 0, 0, 0, 0, 0, 0x10, 0x01, 10, 0, 0, 1];
        let ies = [ie(60, &[0, 10, 0, 0, 1]), ie(57, &f_seid), pdr, far];
        let message = Message::decode(&session_message(50, 0, &ies)).unwrap();
        message
            .check(interface)
            .into_iter()
            .map(|deviation| (deviation.kind, deviation.cause))
            .collect::<Vec<_>>()
    };
    let short = [0, 0, 1];
    assert_eq!(
        checked(&[], &short, Interfaces::SXA),
        [(DeviationKind::NotOnInterface { ie_type: 29 }, None)]
    );
    // A value of the row, and an IE of it kept as octets after it, are told once
    let pdr = [ie(56, &[0, 1]), ie(29, &[0, 0, 0, 1]), ie(29, &short)];
    let pdr = ie(
        1,
        &[
            &pdr.concat()[..],
            &ie(2, &ie(20, &[0])),
            &ie(108, &[0, 0, 0, 1]),
        ]
        .concat(),
    );
    let [_, far] = rules();
    let f_seid = [2, 0, 0, 0, 0, 0, 0, 0x10, 0x01, 10, 0, 0, 1];
    let ies = [ie(60, &[0, 10, 0, 0, 1]), ie(57, &f_seid), pdr, far];
    let message = Message::decode(&session_message(50, 0, &ies)).unwrap();
    assert_eq!(
        kinds(&message, Interfaces::SXA),
        [DeviationKind::NotOnInterface { ie_type: 29 }]
    );
    assert_eq!(
        checked(&[], &short, Interfaces::SXA_SXB),
        [(DeviationKind::Incorrect { ie_type: 29 }, None)]
    );
    let precedence = [0, 0, 0, 1];
    let marking = ie(30, &[0x11, 0x11]);
    assert_eq!(
        checked(std::slice::from_ref(&marking), &precedence, Interfaces::SXC),
        [(DeviationKind::NotOnInterface { ie_type: 30 }, None)]
    );
    let found = checked(&[marking], &precedence, Interfaces::N4);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].1, Some(CauseValue::MandatoryIeIncorrect));
    let creation = ie(84, &[0, 0]);
    let found = checked(
        std::slice::from_ref(&creation),
        &precedence,
        Interfaces::SXC,
    );
    assert_eq!(
        found,
        [(DeviationKind::NotOnInterface { ie_type: 84 }, None)]
    );
    // On Sxa, which has the Outer Header Creation and no Precedence
    let found = checked(&[creation], &precedence, Interfaces::SXA);
    let rule = DeviationKind::Rule("no bit of the description is set");
    assert_eq!(
        found,
        [
            (DeviationKind::NotOnInterface { ie_type: 29 }, None),
            (rule, Some(CauseValue::MandatoryIeIncorrect))
        ]
    );
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
    assert_eq!(Interfaces::SXA_SXB | Interfaces::SXB, Interfaces::SXA_SXB);
}

/// Table 7.3-1: PFD management is not on Sxa; a message type of no table is reported.
#[test]
fn a_message_type_of_the_interface() {
    let request = PfdManagementRequest::default();
    let message = Message::node(3, request);
    assert!(kinds(&message, Interfaces::N4).is_empty());
    assert_eq!(
        kinds(&message, Interfaces::SXA),
        [DeviationKind::MessageNotOnInterface { message_type: 3 }]
    );
    let other = Message::node(
        3,
        Body::Other {
            message_type: 99,
            octets: Octets::default(),
        },
    );
    assert_eq!(
        kinds(&other, Interfaces::N4),
        [DeviationKind::UnknownMessage { message_type: 99 }]
    );
}

/// EPS CUPS: an SGW-U checks an SGW-C's message on Sxa, a combined SGW/PGW-U on both
/// Sxa and Sxb (§5.2.6), where a message may have the IEs of either and needs those that
/// both need; each interface has its constructor where their mandatory IEs differ.
#[test]
fn eps_cups_on_its_interfaces() {
    let smf = NodeId::Ipv4(SMF);
    let seid = FSeid::ipv4(0x1001, SMF);
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
    let sxa = Message::session(0, 1, sxa);
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
            extra: Octets::default(),
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
    let sxb = Message::session(0, 2, sxb);
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
    let both = Message::session(0, 3, both);
    assert!(
        both.check(Interfaces::SXA_SXB).is_empty(),
        "{:?}",
        both.check(Interfaces::SXA_SXB)
    );
    assert!(!both.check(Interfaces::N4).is_empty());
}

/// That each message, built, decodes back, has no deviation on its interface, and some
/// on another that it names.
fn on_and_off(cases: Vec<(Message, Interfaces, Option<Interfaces>)>) {
    for (message, on, off) in cases {
        let octets = message.encode().unwrap();
        assert_eq!(Message::decode(&octets).unwrap(), message);
        let found = message.check(on);
        assert!(found.is_empty(), "{message} on {on:?}: {found:?}");
        if let Some(off) = off {
            assert!(!message.check(off).is_empty(), "{message} on {off:?}");
        }
    }
}

fn fq_csid(node_address: [u8; 4], csid: u16) -> FqCsid {
    FqCsid {
        node_id_type: 0,
        node_address: node_address.into(),
        csids: vec![csid],
        node_type: None,
        extra: Octets::default(),
    }
}

/// Session messages of each interface, built, decoded back and checked where they are and
/// where they are not: Sxb modification and report, a TDF's establishment on Sxc, an
/// MB-SMF's on N4mb.
#[test]
fn session_messages_of_each_interface() {
    let node = NodeId::Ipv4(SMF);
    let seid = FSeid::ipv4(0x1001, SMF);
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
    on_and_off(vec![
        (
            Message::session(
                0x2001,
                1,
                SessionModificationRequest::default()
                    .with_update_far(
                        UpdateFar::new(FarId::new(1)).with_apply_action(ApplyAction {
                            drop: true,
                            ..Default::default()
                        }),
                    )
                    .with_remove_qer(RemoveQer::new(QerId::new(1))),
            ),
            Interfaces::SXB,
            Some(Interfaces::SXA),
        ),
        (
            Message::session(
                0x2001,
                2,
                SessionReportRequest::new(ReportType {
                    usar: true,
                    ..Default::default()
                })
                .with_usage_report(urr),
            ),
            Interfaces::SXB,
            None,
        ),
        (
            Message::session(
                0,
                7,
                SessionEstablishmentRequest::new_sxc(
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
                ),
            ),
            Interfaces::SXC,
            Some(Interfaces::SXA),
        ),
        (
            Message::session(
                0,
                8,
                SessionEstablishmentRequest::new_n4mb(
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
                ),
            ),
            Interfaces::N4MB,
            Some(Interfaces::SXA),
        ),
    ]);
}

/// Node messages of each interface, built, decoded back and checked where they are and
/// where they are not: association update and release, PFD management on Sxb and Sxc,
/// session set deletion with the FQ-CSIDs of its roles.
#[test]
fn node_messages_of_each_interface() {
    let node = NodeId::Ipv4(SMF);
    let pfd = PfdContents {
        fd: true,
        spare_octet: Spare(0),
        flow_description: Some(TextLv16(b"permit out ip from any to any".into())),
        ..Default::default()
    };
    on_and_off(vec![
        (
            Message::node(3, AssociationUpdateRequest::new(node.clone())),
            Interfaces::SXA,
            None,
        ),
        (
            Message::node(4, AssociationReleaseRequest::new(node.clone())),
            Interfaces::SXB,
            None,
        ),
        (
            Message::node(
                5,
                PfdManagementRequest::default().with_application_ids_pfds(
                    ApplicationIDsPFDs::new(ApplicationId(b"app".to_vec().into()))
                        .with_pfd_context(PfdContext::new(pfd)),
                ),
            ),
            Interfaces::SXC,
            Some(Interfaces::SXA),
        ),
        (
            Message::node(
                6,
                SessionSetDeletionRequest::new(node.clone())
                    .with_fq_csid(fq_csid([10, 0, 0, 1], 1))
                    .with_fq_csid(fq_csid([10, 0, 0, 5], 2)),
            ),
            Interfaces::SXA,
            Some(Interfaces::SXC),
        ),
    ]);
}

/// The FQ-CSIDs of a Session Set Deletion Request: one of each of its roles on the
/// interface, which Sxa has four of and N4 two (Table 7.4.6.1-1): three are too many on N4,
/// two are not.
#[test]
fn a_session_set_deletion_has_an_fq_csid_of_each_role() {
    let mut deletion = SessionSetDeletionRequest::new(NodeId::Ipv4(SMF));
    for csid in 0..3 {
        deletion = deletion.with_fq_csid(fq_csid([10, 0, 0, 1], csid));
    }
    let deletion = Message::node(9, deletion);
    assert!(deletion.check(Interfaces::SXA).is_empty());
    assert_eq!(
        deletion
            .check(Interfaces::N4)
            .iter()
            .map(|deviation| deviation.kind.clone())
            .collect::<Vec<_>>(),
        [DeviationKind::Repeated { ie_type: 65 }]
    );
    // As many as the rows of N4 are no more than they allow
    let two = SessionSetDeletionRequest::new(NodeId::Ipv4(SMF))
        .with_fq_csid(fq_csid([10, 0, 0, 1], 1))
        .with_fq_csid(fq_csid([10, 0, 0, 1], 2));
    assert!(Message::node(9, two).check(Interfaces::N4).is_empty());
}
