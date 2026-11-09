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
                        .with_extended_transport_level_marking(
                            ExtendedTransportLevelMarking::default(),
                        ),
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
    let mut kept = forwarding()
        .with_extended_transport_level_marking(ExtendedTransportLevelMarking::default());
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
    handling.header_handling_control_reference = Some(HeaderHandlingControlReference::default());
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
            let conditional = row
                .roles
                .iter()
                .any(|role| role.presence == Presence::Conditional);
            assert!(conditional, "{} {}", info.name(), row.name);
        }
    }
}
