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

//! The conditions that the tables write beside their rows, as the IEs of a scope show them: of
//! presence and of absence.

use super::*;

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
            (found[0].cause, found[0].offending_ie()),
            (cause, cause.map(|_| ie_type)),
            "{message}: {found:?}"
        );
    };
    // An accepted establishment has the UP F-SEID
    let response =
        SessionEstablishmentResponse::new(node.clone(), Cause::new(CauseValue::RequestAccepted));
    missing(Message::session(0x1001, 7, response), 57, None);
    // A rejection for a missing or incorrect IE names it
    for cause in [
        CauseValue::MandatoryIeMissing,
        CauseValue::ConditionalIeMissing,
        CauseValue::MandatoryIeIncorrect,
    ] {
        let response = SessionModificationResponse::new(Cause::new(cause));
        missing(Message::session(0x1001, 7, response), 40, None);
    }
    let response =
        SessionModificationResponse::new(Cause::new(CauseValue::RuleCreationModificationFailure));
    missing(Message::session(0x1001, 7, response), 114, None);
    let response =
        SessionModificationResponse::new(Cause::new(CauseValue::RequestPartiallyAccepted));
    missing(Message::session(0x1001, 7, response), 272, None);
    // A report has what its type says
    let report = NodeReportRequest::new(
        node.clone(),
        NodeReportType {
            upfr: true,
            ..Default::default()
        },
    );
    missing(
        Message::node(1, report),
        102,
        Some(CauseValue::ConditionalIeMissing),
    );
    let report = SessionReportRequest::new(ReportType {
        dldr: true,
        ..Default::default()
    });
    missing(
        Message::session(0x1001, 7, report),
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
    request_with(&mut message, |request| request.create_urr.push(urr.clone()));
    missing(message, 31, Some(CauseValue::ConditionalIeMissing));
    // and one that measures no volume has none to report
    let mut message = establishment();
    let duration = MeasurementMethod {
        durat: true,
        ..Default::default()
    };
    let urr = CreateUrr {
        measurement_method: Some(duration),
        ..urr
    };
    request_with(&mut message, |request| request.create_urr.push(urr));
    assert!(message.check(Interfaces::N4).is_empty());
}

/// The paths of the deviations of a kind that a value has on its own, without the
/// leading slash: its conditional IEs `missing` where it shows their condition, and its
/// IEs there where it has them `excluded`.
fn paths(value: &impl Check, of: fn(&DeviationKind) -> bool) -> Vec<String> {
    value
        .deviations()
        .into_iter()
        .filter(|deviation| of(&deviation.kind))
        .map(|deviation| deviation.path.trim_start_matches('/').to_string())
        .collect()
}

fn missing(kind: &DeviationKind) -> bool {
    matches!(kind, DeviationKind::ConditionalMissing { .. })
}

fn excluded(kind: &DeviationKind) -> bool {
    matches!(kind, DeviationKind::Excluded { .. })
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
    let ethernet =
        EthernetPacketFilter::default().with_ethernet_filter_id(EthernetFilterId::new(1));
    let forwarding =
        || ForwardingParameters::new(DestinationInterface::new(DestinationInterfaceValue::Core));
    let marking = || TransportLevelMarking::new(0x00fc);
    let extended = ExtendedTransportLevelMarking::new(
        marking(),
        PduSetImportance {
            psi0: true,
            ..Default::default()
        },
    );
    let mar = |functionality| {
        CreateMar::new(
            MarId::new(1),
            SteeringFunctionality::new(functionality),
            SteeringMode::new(SteeringModeValue::ActiveStandby),
        )
    };
    let mode = || TransportMode::new(TransportModeValue::DatagramMode1);
    let cases: Vec<(Vec<String>, &[&str])> = vec![
        // Table 7.5.2.2-2: of a Traffic Endpoint ID, none of the four
        (
            paths(&pdi().with_traffic_endpoint_id(endpoint.clone()), excluded),
            &[],
        ),
        (
            paths(&pdi().with_local_f_teid(FTeid::choose_ipv4()), excluded),
            &[],
        ),
        (
            paths(
                &pdi()
                    .with_local_f_teid(FTeid::choose_ipv4())
                    .with_local_ingress_tunnel(LocalIngressTunnel::default())
                    .with_network_instance(instance.clone())
                    .with_ue_ip_address(ue.clone())
                    .with_traffic_endpoint_id(endpoint.clone()),
                excluded,
            ),
            &[
                "Local F-TEID",
                "Local Ingress Tunnel",
                "Network Instance",
                "UE IP address",
            ],
        ),
        // NOTE 3: no SDF Filter beside an Ethernet Packet Filter
        (paths(&pdi().with_sdf_filter(filter.clone()), excluded), &[]),
        (
            paths(
                &pdi()
                    .with_sdf_filter(filter)
                    .with_ethernet_packet_filter(ethernet),
                excluded,
            ),
            &["SDF Filter"],
        ),
        // Table 7.5.2.3-2: no Transport Level Marking beside an Extended one
        (
            paths(
                &forwarding().with_transport_level_marking(marking()),
                excluded,
            ),
            &[],
        ),
        (
            paths(
                &forwarding()
                    .with_transport_level_marking(marking())
                    .with_extended_transport_level_marking(extended.clone()),
                excluded,
            ),
            &["Transport Level Marking"],
        ),
        // Table 7.5.2.8-1: a Transport Mode of MPQUIC alone, and NOTE 2
        (
            paths(
                &mar(SteeringFunctionalityValue::MpquicUdp).with_transport_mode(mode()),
                excluded,
            ),
            &[],
        ),
        (
            paths(
                &mar(SteeringFunctionalityValue::AtsssLl).with_transport_mode(mode()),
                excluded,
            ),
            &["Transport Mode"],
        ),
        (
            paths(
                &mar(SteeringFunctionalityValue::AtsssLl)
                    .with_threshold_values(Thresholds::default())
                    .with_steering_mode_indicator(SteeringModeIndicator::default()),
                excluded,
            ),
            &["Steering Mode Indicator"],
        ),
    ];
    for (found, expected) in cases {
        assert_eq!(found, expected);
    }
    // A Transport Level Marking that the scope keeps as octets is there; an IE of
    // another type is not it
    let mut kept = forwarding().with_extended_transport_level_marking(extended);
    kept.raw.push(RawIe::new(116, vec![1]));
    assert_eq!(paths(&kept, excluded), Vec::<String>::new());
    kept.raw.push(RawIe::new(30, vec![0xfc]));
    assert_eq!(paths(&kept, excluded), ["Transport Level Marking"]);
    // The Network Instance of a UE IP address that the UP function allocates, without a
    // Traffic Endpoint ID
    assert_eq!(
        paths(&pdi().with_ue_ip_address(chosen.clone()), missing),
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
        assert!(paths(&present, missing).is_empty(), "{present:?}");
    }
}

/// Table 7.5.4.1-1 NOTE 3: QAURR and the Query URR of a modification are exclusive, and
/// the Query URR is there where QAURR has it absent, without a Cause.
#[test]
fn qaurr_and_a_query_urr_exclude_each_other() {
    // Table 7.5.4.1-1 NOTE 3: QAURR and the Query URR, exclusive, without a Cause
    let modification = SessionModificationRequest::default()
        .with_pfcpsmreq_flags(PFCPSMReqFlags {
            qaurr: true,
            ..Default::default()
        })
        .with_query_urr(QueryUrr::new(UrrId::new(1)));
    let message = Message::session(1, 1, modification);
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

/// That the rows of `value` missing where their conditions show are `expected`.
fn shown(value: &impl Check, expected: &[&str]) {
    assert_eq!(paths(value, missing), expected);
}

/// §7.6.6: the conditions of the C rows of the node messages and their grouped IEs that
/// the IEs beside them show, each where it holds and where it does not; the NOTEs of
/// Tables 7.4.4.1.3-1 and 7.4.5.1.8-1, of one IE or another, as the condition of each on
/// the other.
#[test]
fn the_conditions_that_the_ies_of_a_node_message_show() {
    // Table 7.4.4.1-1 and 7.4.4.2-1: an SMF of MPAS gives its SMF Set ID
    let mpas = CpFunctionFeatures {
        mpas: true,
        ..Default::default()
    };
    let setup = AssociationSetupRequest::new(NodeId::Ipv4(SMF), RecoveryTimeStamp::new(1))
        .with_cp_function_features(mpas.clone());
    let message = Message::node(1, setup.clone());
    assert_eq!(
        kinds(&message, Interfaces::N4),
        [DeviationKind::ConditionalMissing { ie_type: 180 }]
    );
    let set = SmfSetId {
        fqdn: Fqdn(b"\x03set".to_vec().into()),
        ..Default::default()
    };
    let message = Message::node(1, setup.with_smf_set_id(set));
    assert_eq!(kinds(&message, Interfaces::N4), []);
    let response = AssociationSetupResponse::new(
        NodeId::Ipv4(SMF),
        Cause::new(CauseValue::RequestAccepted),
        RecoveryTimeStamp::new(1),
    )
    .with_cp_function_features(mpas);
    let message = Message::node(1, response);
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
    shown(
        &clock,
        &["Time Offset Threshold", "Cumulative rateRatio Threshold"],
    );
    clock.requested_clock_drift_information = Some(RequestedClockDriftInformation {
        rrcr: true,
        ..Default::default()
    });
    shown(&clock, &["Cumulative rateRatio Threshold"]);
    // Table 7.4.4.1.3-1: a periodic report has its period; a peer or an interface type
    let mut path = GtpUPathQoSControlInformation {
        qos_report_trigger: Some(QoSReportTrigger {
            per: true,
            ..Default::default()
        }),
        ..Default::default()
    };
    shown(&path, &["Remote GTP-U Peer", "Measurement Period"]);
    path.gtp_u_path_interface_type = Some(GtpUPathInterfaceType {
        n3: true,
        ..Default::default()
    });
    path.measurement_period = Some(MeasurementPeriod::new(10));
    shown(&path, &[]);
    path.gtp_u_path_interface_type = None;
    path.remote_gtp_u_peer.push(RemoteGtpUPeer::default());
    shown(&path, &[]);
    // Table 7.4.4.1.4-1: a periodic N6 delay measurement has its period
    let mut n6 = N6DelayMeasurementControlInformation {
        measurement_reporting_type: Some(MeasurementReportingType {
            per: true,
            ..Default::default()
        }),
        ..Default::default()
    };
    shown(&n6, &["Measurement Period"]);
    n6.measurement_reporting_type = Some(MeasurementReportingType {
        evt: true,
        ..Default::default()
    });
    shown(&n6, &[]);
    // Table 7.4.5.1.8-1: an N6 delay report has its information or its failure
    let mut report = N6DelayMeasurementReport::default();
    shown(&report, &["N6 Delay Measurement Information"]);
    report.n6_delay_measurement_failure_information =
        Some(N6DelayMeasurementFailureInformation::default());
    shown(&report, &[]);
}

/// §7.6.6: the conditions of the C rows of the rules of a session that the IEs beside
/// them show, each where it holds and where it does not; the NOTE of Table 7.5.2.9-5, of
/// one IE or another, as the condition of each on the other.
#[test]
fn the_conditions_that_the_ies_of_a_rule_show() {
    // Table 7.5.2.2-1: a PDR without a predefined rule or a MAR has its FAR
    let mut pdr = CreatePdr::new_n4(
        PdrId::new(1),
        Precedence::new(1),
        Pdi::new(SourceInterface::new(SourceInterfaceValue::Access)),
    );
    shown(&pdr, &["FAR ID"]);
    pdr.mar_id = Some(MarId::new(1));
    shown(&pdr, &[]);
    pdr.mar_id = None;
    pdr.activate_predefined_rules
        .push(ActivatePredefinedRules(b"rule".to_vec().into()));
    shown(&pdr, &[]);
    // Tables 7.5.2.2-8 and 7.5.2.2-9: an RTP header extension has its ID, an RTP payload
    // format its payload type
    let extension = RtpHeaderExtensionInformation {
        rtp_header_extension_type: Some(RtpHeaderExtensionType::default()),
        ..Default::default()
    };
    shown(&extension, &["RTP Header Extension ID"]);
    let payload = RtpPayloadInformation {
        rtp_payload_format: Some(RtpPayloadFormat::default()),
        ..Default::default()
    };
    shown(&payload, &["RTP Payload Type"]);
    // Table 7.5.2.3-1: a FAR that forwards and duplicates for redundant transmission, on
    // N4, which alone has its parameters, and one that forwards without its parameters,
    // which N4mb lacks: on its own, on every interface of its table, a FAR needs neither
    let on_n4 = |far: &CreateFar| {
        let mut message = establishment();
        request_with(&mut message, |request| request.create_far[0] = far.clone());
        let found = message.check(Interfaces::N4).into_iter();
        let paths = found.map(|deviation| deviation.path.replace("/pfcp/Create FAR/0/", ""));
        paths.collect::<Vec<_>>()
    };
    let mut far = far(1);
    far.apply_action = Some(ApplyAction {
        forw: true,
        dfrt: true,
        ..Default::default()
    });
    shown(&far, &[]);
    assert_eq!(
        on_n4(&far),
        ["Redundant Transmission Forwarding Parameters"]
    );
    far.forwarding_parameters = None;
    shown(&far, &[]);
    assert_eq!(on_n4(&far), ["Forwarding Parameters"]);
    // Table 7.5.2.3-2: forwarding to SGi-LAN/N6-LAN has a Forwarding Policy, which Sxa
    // lacks
    let forwarding = ForwardingParameters::new(DestinationInterface::new(
        DestinationInterfaceValue::SgiLanN6Lan,
    ));
    shown(&forwarding, &[]);
    let mut far = far.clone();
    far.apply_action = Some(ApplyAction {
        forw: true,
        ..Default::default()
    });
    far.forwarding_parameters = Some(forwarding);
    let policy = "Forwarding Parameters/Forwarding Policy";
    assert_eq!(on_n4(&far), [policy]);
    let forwarding =
        ForwardingParameters::new(DestinationInterface::new(DestinationInterfaceValue::Core));
    shown(&forwarding, &[]);
    // Table 7.5.2.3-9: a header handling without a reference says it all
    let mut handling = HeaderHandlingControlInformation {
        header_handling_control_id: Some(HeaderHandlingControlId::default()),
        ..Default::default()
    };
    shown(
        &handling,
        &[
            "Header Handling Action",
            "Header Information",
            "Header Value",
            "Header Handling Condition",
        ],
    );
    handling.header_handling_control_reference =
        Some(HeaderHandlingControlReference(b"reference".to_vec().into()));
    shown(&handling, &[]);
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
        shown(&mar(value), &["Transport Mode"]);
    }
    shown(&mar(SteeringFunctionalityValue::Mptcp), &[]);
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
        paths(&monitoring(periodic, delay.clone()), missing),
        ["Measurement Period"]
    );
    assert_eq!(
        paths(&monitoring(event.clone(), delay), missing),
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
            paths(&monitoring(event.clone(), requested), missing),
            ["Minimum Wait Time", "Reporting Thresholds"]
        );
    }
    // Table 7.5.2.9-5: a period or a threshold
    let mut traffic = TrafficParameterMeasurementControlInformation::default();
    shown(&traffic, &["Measurement Period"]);
    traffic.measurement_period = Some(MeasurementPeriod::new(10));
    shown(&traffic, &[]);
}

/// §7.6.6: a usage report has its start and end times, but of the start or the stop of
/// traffic, or of MAC addresses.
#[test]
fn the_times_that_a_usage_report_has() {
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
    assert_eq!(paths(&report(periodic.clone()), missing), times);
    assert_eq!(paths(&report(start.clone()), missing), Vec::<String>::new());
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
        shown(&report(trigger), &[]);
    }
    let modification = UsageReportModification {
        usage_report_trigger: Some(periodic.clone()),
        ..Default::default()
    };
    assert_eq!(paths(&modification, missing), times);
    let deletion = UsageReportDeletion {
        usage_report_trigger: Some(periodic),
        ..Default::default()
    };
    assert_eq!(paths(&deletion, missing), times);
    let deletion = UsageReportDeletion {
        usage_report_trigger: Some(start),
        ..Default::default()
    };
    shown(&deletion, &[]);
}

/// The rows whose condition `check()` checks are those that say so: a conditional row, or
/// an optional one that its comment has absent by what the IEs beside it show.
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
            let mandatory = row
                .roles
                .iter()
                .all(|role| role.presence == Presence::Mandatory);
            assert!(!mandatory, "{} {}", info.name(), row.name);
        }
    }
}

/// §7.6.9: a condition reads the scope as its receiver on the interface takes it, without
/// the IEs of a row that the interface does not have, which it discards: they neither
/// make a condition hold nor have an IE absent. One of each kind: a MAR ID on Sxa leaves
/// the FAR ID that its absence needs, a UE IP address on Sxa that asks for an address needs
/// no Network Instance, and an Ethernet Packet Filter on Sxb, or an Extended Transport
/// Level Marking on Sxa, has no SDF Filter or Transport Level Marking absent. On N4, which
/// has each row, they do.
#[test]
fn a_condition_reads_the_rows_of_the_interface_alone() {
    let node = NodeId::Ipv4(SMF);
    let seid = FSeid::ipv4(1, SMF);
    let far = far(1);
    let tunnel =
        |source| Pdi::new(SourceInterface::new(source)).with_local_f_teid(FTeid::choose_ipv4());
    let sxa = |pdr: CreatePdr, far: CreateFar| {
        Message::session(
            0,
            1,
            SessionEstablishmentRequest::new_sxa(node.clone(), seid.clone(), pdr, far),
        )
    };
    let sxb = |pdr: CreatePdr| {
        Message::session(
            0,
            1,
            SessionEstablishmentRequest::new_sxb(node.clone(), seid.clone(), pdr, far.clone()),
        )
    };
    let n4 = |pdr: CreatePdr, far: CreateFar| {
        Message::session(
            0,
            1,
            SessionEstablishmentRequest::new_n4(node.clone(), seid.clone(), pdr, far),
        )
    };
    let at = |message: &Message, interface| -> Vec<(String, DeviationKind, Option<CauseValue>)> {
        let found = message.check(interface).into_iter();
        found
            .map(|deviation| (deviation.path, deviation.kind, deviation.cause))
            .collect()
    };
    let off = |path: &str, ie_type| {
        (
            path.to_string(),
            DeviationKind::NotOnInterface { ie_type },
            None,
        )
    };
    // A MAR ID, which Sxa discards: the FAR ID is missing
    let mar = CreatePdr::new_sxa(PdrId::new(1), tunnel(SourceInterfaceValue::Access))
        .with_mar_id(MarId::new(1));
    assert_eq!(
        at(&sxa(mar, far.clone()), Interfaces::SXA),
        [
            (
                "/pfcp/Create PDR/0/FAR ID".to_string(),
                DeviationKind::ConditionalMissing { ie_type: 108 },
                Some(CauseValue::ConditionalIeMissing),
            ),
            off("/pfcp/Create PDR/0/MAR ID", 170),
        ]
    );
    let mar = pdr(1).with_mar_id(MarId::new(1));
    let mar = CreatePdr {
        far_id: None,
        ..mar
    };
    assert_eq!(at(&n4(mar, far.clone()), Interfaces::N4), []);
    // A UE IP address that asks for an address, which Sxa discards: no Network Instance is
    // needed
    let ue = UeIpAddress {
        chv4: true,
        ..Default::default()
    };
    let pdi = tunnel(SourceInterfaceValue::Access).with_ue_ip_address(ue.clone());
    let pdr = CreatePdr::new_sxa(PdrId::new(1), pdi).with_far_id(FarId::new(1));
    assert_eq!(
        at(&sxa(pdr, far.clone()), Interfaces::SXA),
        [off("/pfcp/Create PDR/0/PDI/UE IP address", 93)]
    );
    let pdi = tunnel(SourceInterfaceValue::Access).with_ue_ip_address(ue);
    let pdr = CreatePdr::new_n4(PdrId::new(1), Precedence::new(1), pdi).with_far_id(FarId::new(1));
    let kinds: Vec<_> = at(&n4(pdr, far.clone()), Interfaces::N4)
        .into_iter()
        .map(|(_, kind, _)| kind)
        .collect();
    assert_eq!(kinds, [DeviationKind::ConditionalMissing { ie_type: 22 }]);
    // An Ethernet Packet Filter, which Sxb discards: the SDF Filter may be there
    let sdf = SdfFilter {
        fd: true,
        flow_description: Some(TextLv16::from("permit out ip from any to assigned")),
        ..Default::default()
    };
    let pdi = Pdi::new(SourceInterface::new(SourceInterfaceValue::Core))
        .with_sdf_filter(sdf)
        .with_ethernet_packet_filter(
            EthernetPacketFilter::default().with_ethernet_filter_id(EthernetFilterId::new(1)),
        );
    let pdr = |pdi: Pdi| {
        CreatePdr::new_n4(PdrId::new(1), Precedence::new(1), pdi).with_far_id(FarId::new(1))
    };
    assert_eq!(
        at(&sxb(pdr(pdi.clone())), Interfaces::SXB),
        [off("/pfcp/Create PDR/0/PDI/Ethernet Packet Filter", 132)]
    );
    let excluded =
        |path: &str, ie_type| (path.to_string(), DeviationKind::Excluded { ie_type }, None);
    assert_eq!(
        at(&n4(pdr(pdi), far.clone()), Interfaces::N4),
        [excluded("/pfcp/Create PDR/0/PDI/SDF Filter", 23)]
    );
    // An Extended Transport Level Marking, which Sxa discards: the Transport Level Marking
    // may be there
    let forwarding =
        ForwardingParameters::new(DestinationInterface::new(DestinationInterfaceValue::Core))
            .with_transport_level_marking(TransportLevelMarking::new(0xb8fc))
            .with_extended_transport_level_marking(ExtendedTransportLevelMarking::new(
                TransportLevelMarking::new(0xb8fc),
                PduSetImportance {
                    psi0: true,
                    ..Default::default()
                },
            ));
    let marked = CreateFar::new(
        FarId::new(1),
        ApplyAction {
            forw: true,
            ..Default::default()
        },
    )
    .with_forwarding_parameters(forwarding);
    let pdr = CreatePdr::new_sxa(PdrId::new(1), tunnel(SourceInterfaceValue::Access))
        .with_far_id(FarId::new(1));
    assert_eq!(
        at(&sxa(pdr, marked.clone()), Interfaces::SXA),
        [off(
            "/pfcp/Create FAR/0/Forwarding Parameters/Extended Transport Level Marking",
            383
        )]
    );
    assert_eq!(
        at(&n4(self::pdr(1), marked), Interfaces::N4),
        [excluded(
            "/pfcp/Create FAR/0/Forwarding Parameters/Transport Level Marking",
            30
        )]
    );
}

/// What check() finds below `prefix` in the message that `ies` are of, on N4: the path and
/// the kind of each deviation.
#[cfg(feature = "tree")]
fn below(message: &str, ies: tree::Value, prefix: &str) -> Vec<(String, DeviationKind)> {
    let written =
        tree!({"message": message, "header": {"SEID": 1, "Sequence Number": 1}, "ies": ies});
    let message = Message::from_tree(&written).unwrap_or_else(|error| panic!("{error}"));
    let found = message.check(Interfaces::N4).into_iter();
    let found = found.filter(|found| found.path.starts_with(prefix));
    found.map(|found| (found.path, found.kind)).collect()
}

/// Conditions of a row on the IEs beside it that the tables write in other words than
/// "may be present if the X IE is present": a Query URR Reference "may be present if the
/// Query URR IE is present or the QAURR flag is set" (Table 7.5.4.1-1); "When PMIC IE is
/// present", the NW-TT Port Number "shall contain the related NW-TT Port Number" (Table
/// 7.5.4.18-1); and a subsequent threshold or quota of a Create URR "may be present if the
/// Monitoring Time IE is present and" the measurement of its kind "is used" (Table
/// 7.5.2.4-1), which the Measurement Method says.
#[cfg(feature = "tree")]
#[test]
fn a_row_by_the_ies_beside_it() {
    let modification = "PFCP Session Modification Request";
    let reference = "/pfcp/Query URR Reference";
    let excluded =
        |path: &str, ie_type| vec![(path.to_string(), DeviationKind::Excluded { ie_type })];
    let told = below(modification, tree!({"Query URR Reference": 7}), reference);
    assert_eq!(told, excluded(reference, 125));
    for with in [
        tree!({"Query URR Reference": 7, "Query URR": [{"URR ID": 1}]}),
        tree!({"Query URR Reference": 7, "PFCPSMReq-Flags": {"QAURR": true}}),
    ] {
        assert_eq!(below(modification, with, reference), []);
    }
    // A Port Management Information Container without the port that it is of
    let tsc = "/pfcp/TSC Management Information";
    let container =
        tree!({"TSC Management Information": [{"Port Management Information Container": "00"}]});
    let missing = DeviationKind::ConditionalMissing { ie_type: 197 };
    assert_eq!(
        below(modification, container, tsc),
        [(format!("{tsc}/0/NW-TT Port Number"), missing)]
    );
    for with in [
        tree!({"TSC Management Information": [{"Port Management Information Container": "00", "NW-TT Port Number": 1}]}),
        tree!({"TSC Management Information": [{"User Plane Node Management Information Container": "00"}]}),
    ] {
        assert_eq!(below(modification, with, tsc), []);
    }
    // A URR that measures the volume: its subsequent thresholds and quotas of the time
    // and of events are told, with the Monitoring Time that they need
    let urr = |more: tree::Value| {
        let mut urr = tree!({
            "URR ID": 1, "Measurement Method": {"VOLUM": true}, "Reporting Triggers": {"VOLTH": true},
            "Monitoring Time": 5,
        });
        for (name, value) in more.as_object().unwrap() {
            urr[name.as_str()] = value.clone();
        }
        below(
            modification,
            tree!({"Create URR": [urr]}),
            "/pfcp/Create URR/0/Subsequent",
        )
    };
    let volume = tree!({"TOVOL": true, "Total Volume": 1});
    assert_eq!(
        urr(
            tree!({"Subsequent Volume Threshold": volume.clone(), "Subsequent Volume Quota": volume.clone()})
        ),
        []
    );
    let others = urr(tree!({
        "Subsequent Time Threshold": 1, "Subsequent Time Quota": 1,
        "Subsequent Event Threshold": 1, "Subsequent Event Quota": 1,
    }));
    let kinds: Vec<_> = others.into_iter().map(|(_, kind)| kind).collect();
    let excluded = |ie_type| DeviationKind::Excluded { ie_type };
    assert_eq!(
        kinds,
        [excluded(35), excluded(122), excluded(151), excluded(150)]
    );
}

/// Conditions of a row that a scope above it shows (`check()` reads the whole message):
/// the subsequent thresholds and quotas of an Additional Monitoring Time, by the
/// Measurement Method of its URR (Table 7.5.2.4-3); the Weight and the Priority of the
/// forwarding action information of an access, by the Steering Mode of its MAR (Tables
/// 7.5.2.8-2 and 7.5.2.8-3, NOTE 2); the Tunnel Preference of an L2TP Tunnel Information,
/// "if multiple L2TP Tunnel Information IEs are included in the message" (Table
/// 7.5.2.1-2); and the QFI of a PDI, which "shall not be present if Traffic Endpoint ID is
/// present and the QFI(s) are included in the Traffic Endpoint" (Table 7.5.2.2-2).
#[cfg(feature = "tree")]
#[test]
fn a_row_by_the_ies_of_a_scope_above_it() {
    let establishment = "PFCP Session Establishment Request";
    let excluded = |ie_type| DeviationKind::Excluded { ie_type };
    let missing = |ie_type| DeviationKind::ConditionalMissing { ie_type };
    // An Additional Monitoring Time of a URR that measures the duration
    let time = "/pfcp/Create URR/0/Additional Monitoring Time/0";
    let urr = |time: tree::Value| {
        let urr = tree!({
            "URR ID": 1, "Measurement Method": {"DURAT": true}, "Reporting Triggers": {"TIMTH": true},
            "Additional Monitoring Time": [time],
        });
        below(
            establishment,
            tree!({"Create URR": [urr]}),
            "/pfcp/Create URR/0/Additional",
        )
    };
    assert_eq!(
        urr(
            tree!({"Monitoring Time": 5, "Subsequent Time Threshold": 1, "Subsequent Time Quota": 1})
        ),
        []
    );
    let volume = tree!({"TOVOL": true, "Total Volume": 1});
    assert_eq!(
        urr(
            tree!({"Monitoring Time": 5, "Subsequent Volume Threshold": volume, "Subsequent Event Quota": 1})
        ),
        [
            (format!("{time}/Subsequent Volume Threshold"), excluded(34)),
            (format!("{time}/Subsequent Event Quota"), excluded(148)),
        ]
    );
    // A MAR of each Steering Mode
    let mar = |mode: &str, access: tree::Value, other: tree::Value| {
        let mar = tree!({
            "MAR ID": 1, "Steering Functionality": "ATSSS-LL", "Steering Mode": mode,
            "3GPP Access Forwarding Action Information": access,
            "Non-3GPP Access Forwarding Action Information": other,
        });
        below(
            establishment,
            tree!({"Create MAR": [mar]}),
            "/pfcp/Create MAR/0",
        )
    };
    let first = "/pfcp/Create MAR/0/3GPP Access Forwarding Action Information";
    let second = "/pfcp/Create MAR/0/Non-3GPP Access Forwarding Action Information";
    assert_eq!(
        mar(
            "Load Balancing",
            tree!({"FAR ID": 1, "Weight": 60}),
            tree!({"FAR ID": 2, "Weight": 40})
        ),
        []
    );
    assert_eq!(
        mar(
            "Load Balancing",
            tree!({"FAR ID": 1}),
            tree!({"FAR ID": 2, "Weight": 40, "Priority": "Active"})
        ),
        [
            (format!("{first}/Weight"), missing(173)),
            (format!("{second}/Priority"), excluded(174))
        ]
    );
    assert_eq!(
        mar(
            "Active-Standby",
            tree!({"FAR ID": 1, "Priority": "Active"}),
            tree!({"FAR ID": 2, "Priority": "Standby"})
        ),
        []
    );
    assert_eq!(
        mar(
            "Active-Standby",
            tree!({"FAR ID": 1}),
            tree!({"FAR ID": 2, "Priority": "High"})
        ),
        [
            (format!("{first}/Priority"), missing(174)),
            (
                format!("{second}/Priority"),
                DeviationKind::Rule(
                    "the Priority value is not allowed with the Steering Mode of its MAR"
                )
            ),
        ]
    );
    assert_eq!(
        mar(
            "Priority-based",
            tree!({"FAR ID": 1, "Priority": "High"}),
            tree!({"FAR ID": 2, "Priority": "High"})
        ),
        [(
            "/pfcp/Create MAR/0".to_string(),
            DeviationKind::Rule("the two accesses of a MAR have the same Priority value")
        )]
    );
    assert_eq!(
        mar("Redundant", tree!({"FAR ID": 1}), tree!({"FAR ID": 2})),
        []
    );
    assert_eq!(
        mar(
            "Redundant",
            tree!({"FAR ID": 1, "Priority": "Primary"}),
            tree!({"FAR ID": 2, "Priority": "Secondary"})
        ),
        []
    );
    assert_eq!(
        mar("Smallest Delay", tree!({"FAR ID": 1}), tree!({"FAR ID": 2})),
        []
    );
    // Two L2TP Tunnel Information, one without its Tunnel Preference; and one alone
    let tunnels = "/pfcp/L2TP Tunnel Information";
    let tunnel = |more: tree::Value| {
        let mut tunnel = tree!({"LNS Address": "0a000001"});
        for (name, value) in more.as_object().unwrap() {
            tunnel[name.as_str()] = value.clone();
        }
        tunnel
    };
    let two = tree!({"L2TP Tunnel Information": [tunnel(tree!({"Tunnel Preference": 1})), tunnel(tree!({}))]});
    assert_eq!(
        below(establishment, two, tunnels),
        [(format!("{tunnels}/1/Tunnel Preference"), missing(281))]
    );
    let one = tree!({"L2TP Tunnel Information": [tunnel(tree!({}))]});
    assert_eq!(below(establishment, one, tunnels), []);
    // A PDI of a Traffic Endpoint that the message creates with its QFIs, and without
    let pdr = |endpoint: tree::Value| {
        let pdr = tree!({
            "PDR ID": 1, "Precedence": 1, "FAR ID": 1,
            "PDI": {"Source Interface": "Access", "Traffic Endpoint ID": [1], "QFI": [5]},
        });
        let ies = tree!({"Create PDR": [pdr], "Create Traffic Endpoint": [endpoint]});
        below(establishment, ies, "/pfcp/Create PDR/0/PDI/QFI")
    };
    assert_eq!(
        pdr(tree!({"Traffic Endpoint ID": 1, "QFI": [5]})),
        [("/pfcp/Create PDR/0/PDI/QFI".to_string(), excluded(124))]
    );
    assert_eq!(pdr(tree!({"Traffic Endpoint ID": 1})), []);
    assert_eq!(pdr(tree!({"Traffic Endpoint ID": 2, "QFI": [5]})), []);
}
