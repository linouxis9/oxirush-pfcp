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
        [("/Message Length".into(), rule.clone(), invalid, None)]
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
            ("/Message Length".into(), rule, None, None),
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
