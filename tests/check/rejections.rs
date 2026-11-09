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

//! A response with a rejection Cause, and the Causes of the answers to a request.

use super::*;

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
        found[0].cause,
        Some(CauseValue::MandatoryIeMissing),
        "{found:?}"
    );
    assert_eq!(found[0].offending_ie(), Some(20));

    let mut modification = SessionModificationRequest::default().with_create_pdr(pdr(1));
    modification.create_pdr[0].pdr_id = None;
    let message = Message::session(0x2002, 8, modification);
    let found = message.check(Interfaces::N4);
    assert_eq!(
        found[0].kind,
        DeviationKind::MandatoryMissing { ie_type: 56 },
        "{found:?}"
    );
    assert_eq!(found[0].cause, Some(CauseValue::ConditionalIeMissing));

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
    assert_eq!(found[0].cause, None, "an optional grouped IE");

    let response = SessionEstablishmentResponse::default();
    let message = Message::session(0x1001, 7, response);
    assert!(
        message
            .check(Interfaces::N4)
            .iter()
            .all(|deviation| deviation.cause.is_none())
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
    let mut message = Message::session(0x1001, 7, response);
    assert!(
        message.check(Interfaces::N4).is_empty(),
        "{:?}",
        message.check(Interfaces::N4)
    );
    let Body::SessionEstablishmentResponse(response) = &mut message.body else {
        panic!()
    };
    response.up_f_seid = Some(FSeid::ipv4(1, SMF));
    assert_eq!(
        kinds(&message, Interfaces::N4),
        [DeviationKind::WithRejection { ie_type: 57 }]
    );
}

/// §5.22.2: an SMF redirects a UPF's request to another SMF of its set by rejecting it
/// with "Redirection Requested" and the IP address of the new SMF, the Alternative SMF IP
/// Address that Table 7.5.9.1-1 writes beside the Cause; the other row of that IE, the
/// address kept for the session, does not accompany a rejection, nor does either
/// accompany another Cause, or another message.
#[test]
fn a_redirection_carries_the_address_of_the_new_smf() {
    let address = AlternativeSmfIpAddress {
        v4: true,
        ipv4_address: Some(Ipv4Addr::new(10, 0, 0, 9)),
        ..Default::default()
    };
    let report = |cause: CauseValue, addresses: usize| {
        let response = SessionReportResponse {
            cause: Some(Cause::new(cause)),
            alternative_smf_ip_address: vec![address.clone(); addresses],
            ..Default::default()
        };
        kinds(&Message::session(0x1001, 7, response), Interfaces::N4)
    };
    let with_rejection = [DeviationKind::WithRejection { ie_type: 178 }];
    assert_eq!(report(CauseValue::RedirectionRequested, 1), []);
    assert_eq!(report(CauseValue::RedirectionRequested, 2), with_rejection);
    assert_eq!(report(CauseValue::RequestRejected, 1), with_rejection);
    let setup = AssociationSetupResponse::new(
        NodeId::Ipv4(SMF),
        Cause::new(CauseValue::RedirectionRequested),
        RecoveryTimeStamp::new(1),
    )
    .with_alternative_smf_ip_address(address);
    let found = kinds(&Message::node(7, setup), Interfaces::N4);
    assert!(found.contains(&with_rejection[0]), "{found:?}");
}

/// §7.2.3.2: a rejection carries no Created PDR, whatever its octets: one of a null length,
/// one that does not decode, and one that does, beside one that does not, each once at
/// the row. A row of kept IEs is on its interfaces alone, as one of values.
#[test]
fn a_rejection_carries_no_ie_that_it_may_not_as_octets_either() {
    let checked = |cause: u8, pdrs: &[&[u8]], interface: Interfaces| {
        let mut ies = vec![ie(60, &[0, 10, 0, 0, 1]), ie(19, &[cause])];
        ies.extend(pdrs.iter().map(|pdr| ie(8, pdr)));
        let octets = session_message(51, 0x1001, &ies);
        let message = Message::decode(&octets).unwrap();
        message
            .check(interface)
            .into_iter()
            .map(|deviation| (deviation.path, deviation.kind))
            .collect::<Vec<_>>()
    };
    let rejected = |pdrs: &[&[u8]]| checked(64, pdrs, Interfaces::N4);
    let with_rejection = (
        "/pfcp/Created PDR".to_string(),
        DeviationKind::WithRejection { ie_type: 8 },
    );
    let pdr = ie(56, &[0, 1]);
    let broken = [0, 56, 0, 9, 0];
    let alone = std::slice::from_ref(&with_rejection);
    assert_eq!(rejected(&[&[]]), alone);
    assert_eq!(rejected(&[&[], &[]]), alone);
    let found = rejected(&[&broken]);
    assert_eq!(found[0], with_rejection);
    assert_eq!(
        found
            .iter()
            .filter(|found| **found == with_rejection)
            .count(),
        1
    );
    let found = rejected(&[&pdr, &broken]);
    assert_eq!(
        found
            .iter()
            .filter(|found| **found == with_rejection)
            .count(),
        1,
        "{found:?}"
    );
    let off = (
        "/pfcp/Created PDR".to_string(),
        DeviationKind::NotOnInterface { ie_type: 8 },
    );
    assert_eq!(
        checked(64, &[&[]], Interfaces::SXC),
        [with_rejection, off.clone()]
    );
    let found = checked(1, &[&[]], Interfaces::SXC);
    assert!(found.contains(&off), "{found:?}");
    assert!(!checked(1, &[&[]], Interfaces::N4).contains(&off));
}

/// Table 8.2.1-1 NOTE 1: a Cause of 4 to 63 is read as "Request accepted (success)", so an
/// establishment accepted with one needs the UP F-SEID, as the node reads it; NOTE 2: one
/// of 93 to 255 is a rejection, which carries no Created PDR (§7.2.3.2).
#[test]
fn a_spare_cause_is_read_as_its_receiver_reads_it() {
    let establishment = |cause: u8, pdr: bool| {
        let mut response =
            SessionEstablishmentResponse::new(NodeId::Ipv4(SMF), Cause::new(cause.into()));
        if pdr {
            response = response.with_created_pdr(CreatedPdr::new(PdrId::new(1)));
        }
        Message::session(0x1001, 7, response)
    };
    let up_f_seid = DeviationKind::ConditionalMissing { ie_type: 57 };
    let read_as = |value| DeviationKind::ReadAs { value, read: 1 };
    let found = kinds(&establishment(1, false), Interfaces::N4);
    assert_eq!(found, std::slice::from_ref(&up_f_seid));
    for cause in [5, 63] {
        let found = kinds(&establishment(cause, false), Interfaces::N4);
        assert_eq!(found, [read_as(cause.into()), up_f_seid.clone()]);
    }
    let found = kinds(&establishment(95, true), Interfaces::N4);
    assert!(
        found.contains(&DeviationKind::WithRejection { ie_type: 8 }),
        "{found:?}"
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
            CauseValue::RequestAccepted => response.with_up_f_seid(FSeid::ipv4(0x2001, SMF)),
            _ => response,
        };
        Message::session(0x1001, 7, response)
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
    let modification = Message::session(
        0x1001,
        7,
        SessionModificationResponse::new(Cause::new(rejected))
            .with_overload_control_information(oci(None)),
    );
    assert_eq!(found(modification), []);
}
