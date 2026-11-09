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

//! The header: its flags, and the SEID that the message type and the Cause decide.

use super::*;

/// §7.2.2.4.2: SEID 0 in an establishment, or in an answer that rejects; not in a
/// modification, nor in an answer that accepts. A Cause of 0, reserved (Table 8.2.1-1),
/// neither accepts nor rejects, and is told once.
#[test]
fn seid_0_only_where_the_peer_seid_is_not_known() {
    let establishment = establishment();
    assert!(establishment.check(Interfaces::N4).is_empty());
    let modification = Message::session(0, 8, SessionModificationRequest::default());
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
    let mut message = Message::session(0, 8, response);
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
    let deletion = SessionDeletionResponse::new(Cause::new(CauseValue::from_value(0)));
    let reserved = DeviationKind::ReservedValue { value: 0 };
    assert_eq!(
        kinds(&Message::session(0, 8, deletion), Interfaces::N4),
        [reserved]
    );
    // An answer of "Session context not found" has SEID 0, as its peer's is not known
    // (bullet 2); one of another Cause may have another
    let response = SessionModificationResponse::new(Cause::new(CauseValue::SessionContextNotFound));
    let found = Message::session(0x1001, 8, response).check(Interfaces::N4);
    let found: Vec<_> = found
        .iter()
        .map(|deviation| (deviation.path.as_str(), deviation.clause, &deviation.kind))
        .collect();
    let rule = DeviationKind::Rule(
        "a response of the Cause Session context not found of a SEID other than 0",
    );
    assert_eq!(found, [("/header/SEID", "7.2.2.4.2", &rule)]);
    let response = SessionModificationResponse::new(Cause::new(CauseValue::MandatoryIeMissing))
        .with_offending_ie(OffendingIe::new(1));
    assert_eq!(
        kinds(&Message::session(0x1001, 8, response), Interfaces::N4),
        []
    );
}

/// §7.2.2.4.2 bullet 4, §5.22.2 bullet 4, Table 7.5.8.1-1: a Session Report Request of
/// SEID 0 moves the session to another SMF of the set and carries the Old CP F-SEID of
/// the previous one; one of a known SEID has none.
#[test]
fn a_report_of_seid_0_carries_the_old_cp_f_seid() {
    let old = FSeid::ipv4(0x1234, SMF);
    let report = |seid, with_old| {
        let mut body = SessionReportRequest::new(ReportType {
            uisr: true,
            ..Default::default()
        });
        if with_old {
            body = body.with_old_cp_f_seid(old.clone());
        }
        Message::session(seid, 9, body)
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
    // On Sxb, whose table has no Old CP F-SEID, its receiver discards it (§7.6.9): a known
    // SEID with it breaks nothing more, and SEID 0 is without it
    let off = DeviationKind::NotOnInterface { ie_type: 57 };
    assert_eq!(
        kinds(&report(0x1001, true), Interfaces::SXB),
        std::slice::from_ref(&off)
    );
    let without =
        DeviationKind::Rule("a Session Report Request of SEID 0 without the Old CP F-SEID");
    assert_eq!(kinds(&report(0, true), Interfaces::SXB), [without, off]);
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
