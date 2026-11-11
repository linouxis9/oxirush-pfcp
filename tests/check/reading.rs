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

//! A message checked as its receiver reads its octets: the IEs that a scope keeps as octets, and
//! the Lengths that do not frame.

use super::*;

/// A value of no octets, which a caller builds, writes an IE of a null length: `check()`
/// reads the message as its receiver does, and tells a mandatory one so, where the value
/// alone would count as the IE that its table needs (§8.1.2).
#[test]
fn a_built_value_of_no_octets_is_an_ie_of_a_null_length() {
    let pfds = |application: &[u8]| {
        let pfds = ApplicationIDsPFDs {
            application_id: Some(ApplicationId(application.to_vec().into())),
            ..Default::default()
        };
        let request = PfdManagementRequest {
            application_ids_pfds: vec![pfds],
            ..Default::default()
        };
        Message::node(1, request).check(Interfaces::N4)
    };
    assert_eq!(pfds(b"app"), []);
    let found = pfds(b"");
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].kind, DeviationKind::NullLength { ie_type: 24 });
    assert_eq!(
        found[0].path,
        "/pfcp/Application ID's PFDs/0/Application ID"
    );
}

/// An IE that a scope keeps as octets, which its receiver reads as the value of its row,
/// is checked as that value: `check(m)` is `check(Message::decode(m.encode()))`. A
/// mandatory Recovery Time Stamp, an optional Source IP Address, and a Create MAR of a
/// list, whose MAR ID the message then changes twice (§6.3.3.2).
#[test]
fn an_ie_kept_as_octets_that_decode_is_checked_as_its_value() {
    let read = |message: &Message| Message::decode(&message.encode().unwrap()).unwrap();
    let mut setup = AssociationSetupRequest {
        node_id: Some(NodeId::Ipv4(SMF)),
        ..Default::default()
    };
    setup.raw.push(RawIe::new(96, vec![0, 0, 0, 7]));
    let setup = Message::node(1, setup);
    assert_eq!(setup.check(Interfaces::N4), []);
    assert_eq!(read(&setup).check(Interfaces::N4), []);
    let mut heartbeat = HeartbeatRequest::new(RecoveryTimeStamp::new(7));
    heartbeat.raw.push(RawIe::new(192, vec![2, 10, 0, 0, 1]));
    assert_eq!(Message::node(1, heartbeat).check(Interfaces::N4), []);
    let mar = CreateMar {
        mar_id: Some(MarId::new(1)),
        ..Default::default()
    };
    let mut content = Vec::new();
    mar.encode(&mut content).unwrap();
    let mut modification = SessionModificationRequest {
        create_mar: vec![mar],
        ..Default::default()
    };
    modification.raw.push(RawIe::new(165, content));
    let modification = Message::session(1, 1, modification);
    let found = modification.check(Interfaces::N4);
    assert_eq!(found, read(&modification).check(Interfaces::N4));
    let twice = DeviationKind::RuleChangedTwice { rule: "MAR", id: 1 };
    assert!(
        found.iter().any(|deviation| deviation.kind == twice),
        "{found:?}"
    );
    // A Node ID of a spare Node ID Type, decoded or kept as its octets
    let ies = [ie(60, &[8, 127, 0, 0, 1]), ie(96, &[0, 0, 0, 7])];
    let decoded = Message::decode(&node_message(5, &ies)).unwrap();
    let Body::AssociationSetupRequest(setup) = &decoded.body else {
        panic!()
    };
    let mut kept = (**setup).clone();
    kept.node_id = None;
    kept.raw.push(RawIe::new(60, vec![8, 127, 0, 0, 1]));
    let kept = Message::node(decoded.header.sequence, kept);
    let found = decoded.check(Interfaces::N4);
    assert!(!found.is_empty());
    assert_eq!(kept.check(Interfaces::N4), found);
}

/// §7.6.3, §7.6.7: a Message Length that is not the length of the octets after the first
/// four, and an IE whose Length is not the length of its content, which does not frame, are
/// told, with "Invalid length" in a request and the IE that does not frame; a Length that is
/// the length is no fault. A Heartbeat Request is answered with no Cause.
#[test]
fn a_false_length_is_told_with_its_ie() {
    let told =
        |message: &Message| -> Vec<(String, DeviationKind, Option<CauseValue>, Option<u16>)> {
            let found = message.check(Interfaces::N4).into_iter();
            let found = found.map(|deviation| {
                let offending = deviation.offending_ie();
                (deviation.path, deviation.kind, deviation.cause, offending)
            });
            found.collect()
        };
    let false_ie = |length| RawIe {
        length: Some(length),
        ..RawIe::new(96, vec![0, 0, 0, 7])
    };
    let mut setup = AssociationSetupRequest {
        node_id: Some(NodeId::Ipv4(SMF)),
        ..Default::default()
    };
    setup.raw.push(false_ie(9));
    let invalid = Some(CauseValue::InvalidLength);
    assert_eq!(
        told(&Message::node(1, setup.clone())),
        [(
            "/pfcp/Recovery Time Stamp".into(),
            DeviationKind::InvalidLength { ie_type: 96 },
            invalid,
            Some(96)
        )]
    );
    setup.raw[0] = false_ie(4);
    assert_eq!(told(&Message::node(1, setup)), []);
    let mut setup = Message::node(
        1,
        AssociationSetupRequest::new(NodeId::Ipv4(SMF), RecoveryTimeStamp::new(7)),
    );
    let length = Message::decode(&setup.encode().unwrap())
        .unwrap()
        .encode()
        .unwrap()
        .len()
        - 4;
    setup.header.length = Some(length as u16);
    assert_eq!(told(&setup), []);
    setup.header.length = Some(4);
    let rule = DeviationKind::Rule("a Message Length other than the octets after the first four");
    assert_eq!(
        told(&setup),
        [("/header/Message Length".into(), rule.clone(), invalid, None)]
    );
    // A heartbeat, with an IE of a list and one of no row that do not frame
    let mut heartbeat = HeartbeatRequest::new(RecoveryTimeStamp::new(7));
    heartbeat.raw.push(RawIe {
        length: Some(9),
        ..RawIe::new(192, vec![2, 10, 0, 0, 1])
    });
    heartbeat.raw.push(RawIe {
        enterprise_id: Some(7),
        length: Some(1),
        ..RawIe::new(40_000, vec![1])
    });
    let mut heartbeat = Message::node(1, heartbeat);
    heartbeat.header.length = Some(4);
    assert_eq!(
        told(&heartbeat),
        [
            (
                "/pfcp/Source IP Address".into(),
                DeviationKind::InvalidLength { ie_type: 192 },
                None,
                None
            ),
            (
                "/pfcp/40000".into(),
                DeviationKind::InvalidLength { ie_type: 40_000 },
                None,
                None
            ),
            ("/header/Message Length".into(), rule, None, None),
        ]
    );
}

/// §7.6.7: an IE whose Length runs past the grouped IE that holds it is told as at the
/// level of the message, with "Invalid length" in a request and the type of the IE, at the
/// grouped IE, which its receiver cannot read: a BAR ID of the Length 5 and one octet in a
/// Create BAR, a vendor IE of the Length 9 and five octets at the end of a Create PDR, and
/// a Source Interface of the Length 3 in the PDI of a Create PDR, a level below.
#[test]
fn an_ie_whose_length_runs_past_its_grouped_ie_is_of_an_invalid_length() {
    let told = |octets: &[u8]| -> Vec<(String, DeviationKind, Option<CauseValue>, Option<u16>)> {
        let message = Message::decode(octets).unwrap();
        let found = message.check(Interfaces::N4).into_iter();
        let found = found.map(|deviation| {
            let offending = deviation.offending_ie();
            (deviation.path, deviation.kind, deviation.cause, offending)
        });
        found.collect()
    };
    let invalid = |path: &str, ie_type| {
        let cause = Some(CauseValue::InvalidLength);
        (
            path.to_string(),
            DeviationKind::InvalidLength { ie_type },
            cause,
            Some(ie_type),
        )
    };
    let [pdr, far] = rules();
    let node = ie(60, &[0, 10, 0, 0, 1]);
    let seid = ie(57, &[2, 0, 0, 0, 0, 0, 0, 0, 1, 10, 0, 0, 1]);
    let bar = ie(85, &[0, 88, 0, 5, 1]);
    let octets = session_message(
        50,
        0,
        &[node.clone(), seid.clone(), pdr.clone(), far.clone(), bar],
    );
    assert_eq!(told(&octets), [invalid("/pfcp/Create BAR", 88)]);
    let vendor = [0x80, 0x01, 0, 9, 0x48, 0xf9, 1, 2, 3];
    let pdr = ie(1, &[&pdr[4..], &vendor[..]].concat());
    let octets = session_message(50, 0, &[node.clone(), seid.clone(), pdr, far.clone()]);
    assert_eq!(told(&octets), [invalid("/pfcp/Create PDR/0", 32769)]);
    let pdi = ie(2, &[0, 20, 0, 3, 0]);
    let pdr = ie(
        1,
        &[
            ie(56, &[0, 1]),
            ie(29, &[0, 0, 0, 255]),
            pdi,
            ie(108, &[0, 0, 0, 1]),
        ]
        .concat(),
    );
    let octets = session_message(50, 0, &[node, seid, pdr, far]);
    assert_eq!(told(&octets), [invalid("/pfcp/Create PDR/0/PDI", 20)]);
}

/// What `check()` finds of a message is what it finds of its octets, however the message
/// holds its IEs: each pair below encodes to the same octets, and is checked alike. (a) A
/// false Message Length, with the Recovery Time Stamp held as octets or as a value, and an
/// IE of a false Length at the end of the message; (b) a vendor IE of a false Length in a
/// Create PDR, with the PDR ID as octets or as a value; (c) a vendor IE held with the
/// Enterprise ID that its octets begin with, or without; (d) a QER ID of a null length
/// before its value, as a tree may write it, whose receiver handles the first (§7.6.10).
#[test]
fn a_message_is_checked_as_its_octets_whatever_holds_them() {
    let same = |a: &Message, b: &Message| {
        assert_eq!(a.encode().unwrap(), b.encode().unwrap());
        let found = a.check(Interfaces::N4);
        assert_eq!(found, b.check(Interfaces::N4));
        found
            .into_iter()
            .map(|deviation| deviation.kind)
            .collect::<Vec<_>>()
    };
    // (a)
    let mut raw = HeartbeatRequest::default();
    raw.raw.push(RawIe::new(96, vec![0, 0, 0, 7]));
    let mut octets = Message::node(1, raw);
    octets.header.length = Some(3);
    let mut value = Message::node(1, HeartbeatRequest::new(RecoveryTimeStamp::new(7)));
    value.header.length = Some(3);
    let rule = DeviationKind::Rule("a Message Length other than the octets after the first four");
    assert_eq!(same(&octets, &value), [rule]);
    let mut octets = HeartbeatRequest::default();
    octets.raw.push(RawIe::new(96, vec![0, 0, 0, 7]));
    octets.raw.push(RawIe {
        length: Some(9),
        ..RawIe::new(192, vec![2, 10, 0, 0, 1])
    });
    let mut value = HeartbeatRequest::new(RecoveryTimeStamp::new(7));
    value.raw.push(octets.raw[1].clone());
    let (octets, value) = (Message::node(1, octets), Message::node(1, value));
    assert_eq!(
        same(&octets, &value),
        [DeviationKind::InvalidLength { ie_type: 192 }]
    );
    // (b)
    let mut bad = RawIe::new(0x8001, vec![1, 2, 3]);
    bad.enterprise_id = Some(18681);
    bad.length = Some(9);
    let mut by_value = pdr(1);
    let mut by_octets = by_value.clone();
    by_octets.pdr_id = None;
    by_octets.raw.push(RawIe::new(56, vec![0, 1]));
    by_value.raw.push(bad.clone());
    by_octets.raw.push(bad);
    let of = |pdr: CreatePdr| {
        let seid = FSeid::ipv4(1, SMF);
        let request = SessionEstablishmentRequest::new_n4(NodeId::Ipv4(SMF), seid, pdr, far(1));
        Message::session(0, 1, request)
    };
    assert_eq!(
        same(&of(by_octets), &of(by_value)),
        [DeviationKind::InvalidLength { ie_type: 0x8001 }]
    );
    // (c)
    let mut without = HeartbeatRequest::new(RecoveryTimeStamp::new(7));
    without.raw.push(RawIe::new(0x8001, vec![0xaa, 0xbb, 0xcc]));
    let mut with = HeartbeatRequest::new(RecoveryTimeStamp::new(7));
    with.raw.push(RawIe {
        enterprise_id: Some(0xaabb),
        ..RawIe::new(0x8001, vec![0xcc])
    });
    assert_eq!(
        same(&Message::node(1, without), &Message::node(1, with)),
        []
    );
    // (d)
    #[cfg(feature = "tree")]
    {
        let written = oxirush_utils::tree!({"message": "PFCP Session Establishment Request", "header": {"SEID": 0, "Sequence Number": 1}, "ies": {
        "Node ID": "10.0.0.1", "CP F-SEID": {"V4": true, "SEID": 1, "IPv4 address": "10.0.0.1"},
        "Create PDR": [{"PDR ID": 1, "Precedence": 1, "PDI": {"Source Interface": "Core"}, "FAR ID": 1}],
        "Create FAR": [{"FAR ID": 1, "Apply Action": {"DROP": true}}],
        "Create QER": [{"QER ID": [{"octets": ""}, 3], "Gate Status": {"UL Gate": "OPEN", "DL Gate": "OPEN"}}]}});
        let message = Message::from_tree(&written).unwrap();
        assert_eq!(message.to_tree(), written);
        let read = Message::decode(&message.encode().unwrap()).unwrap();
        assert_eq!(
            same(&message, &read),
            [
                DeviationKind::NullLength { ie_type: 109 },
                DeviationKind::Repeated { ie_type: 109 },
            ]
        );
    }
}

/// A Failed Rule ID shorter than the ID of its type, with octets after it, would read as
/// another value: wherever it is, its message does not encode, and `check()` tells it, as
/// a tree of it does not load.
#[test]
fn a_failed_rule_id_that_would_read_as_another_is_refused_wherever_it_is() {
    let rule = FailedRuleId {
        rule_id_type: RuleIdType::Pdr,
        rule_id_value: Rest(vec![1u8].into()),
        extra: vec![0xaau8].into(),
        ..Default::default()
    };
    let partial = PartialFailureInformation {
        failed_rule_id: Some(rule.clone()),
        failure_cause: Some(Cause::new(CauseValue::RuleCreationModificationFailure)),
        offending_ie_information: vec![OffendingIeInformation::default()],
        ..Default::default()
    };
    let establishment = |change: &dyn Fn(&mut SessionEstablishmentResponse)| {
        let mut response = SessionEstablishmentResponse {
            node_id: Some(NodeId::Ipv4(SMF)),
            ..Default::default()
        };
        change(&mut response);
        Message::session(1, 7, response)
    };
    let modification = |change: &dyn Fn(&mut SessionModificationResponse)| {
        let mut response = SessionModificationResponse::default();
        change(&mut response);
        Message::session(1, 7, response)
    };
    let failed = Some(Cause::new(CauseValue::RuleCreationModificationFailure));
    let partially = Some(Cause::new(CauseValue::RequestPartiallyAccepted));
    let at_top = "/pfcp/Failed Rule ID";
    let within = "/pfcp/Partial Failure Information/0/Failed Rule ID";
    for (message, at) in [
        (
            establishment(&|r| {
                r.cause = failed.clone();
                r.failed_rule_id = Some(rule.clone());
            }),
            at_top,
        ),
        (
            establishment(&|r| {
                r.cause = partially.clone();
                r.partial_failure_information = vec![partial.clone()];
            }),
            within,
        ),
        (
            modification(&|r| {
                r.cause = failed.clone();
                r.failed_rule_id = Some(rule.clone());
            }),
            at_top,
        ),
        (
            modification(&|r| {
                r.cause = partially.clone();
                r.partial_failure_information = vec![partial.clone()];
            }),
            within,
        ),
    ] {
        match message.encode() {
            Err(Error::Inconsistent { field, .. }) => assert_eq!(field, "Rule ID value"),
            other => panic!("{at}: {other:?}"),
        }
        let told = DeviationKind::Inconsistent {
            field: "Rule ID value",
        };
        let found = message.check(Interfaces::N4);
        assert!(
            found
                .iter()
                .any(|deviation| deviation.kind == told && deviation.path == at),
            "{found:?}"
        );
        #[cfg(feature = "tree")]
        assert!(Message::from_tree(&message.to_tree()).is_err(), "{at}");
    }
}
