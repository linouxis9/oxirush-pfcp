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

//! What `check()` and `check_on()` find, with the clause and the Cause of each.

use std::net::Ipv4Addr;

use oxirush_pfcp::*;

const SMF: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

fn pdr(id: u16) -> CreatePdr {
    CreatePdr::new(PdrId::new(id), Precedence::new(255), Pdi::new(SourceInterface::new(SourceInterfaceValue::Access)))
        .with_far_id(FarId::new(1))
}

fn far(id: u32) -> CreateFar {
    CreateFar::new(FarId::new(id), ApplyAction { forw: true, ..Default::default() })
}

fn establishment() -> Message {
    let seid = FSeid { v4: true, seid: Some(0x1001), ipv4: Some(SMF), ..Default::default() };
    let request = SessionEstablishmentRequest::new(NodeId::Ipv4(SMF), seid, pdr(1), far(1));
    Message { header: Header::session(0, 7), body: request.into() }
}

fn kinds(message: &Message, interface: Interfaces) -> Vec<DeviationKind> {
    message.check_on(interface).into_iter().map(|deviation| deviation.kind).collect()
}

#[test]
fn a_built_establishment_has_no_deviation() {
    let found = establishment().check();
    assert!(found.is_empty(), "{found:?}");
}

/// Precedence is mandatory in Create PDR on N4 and not on Sxa, which has no row for it.
#[test]
fn check_on_takes_the_rows_of_the_interface() {
    let mut message = establishment();
    let Body::SessionEstablishmentRequest(request) = &mut message.body else { panic!() };
    request.create_pdr[0].precedence = None;
    let on_n4 = message.check();
    assert_eq!(on_n4.len(), 1, "{on_n4:?}");
    assert_eq!(on_n4[0].kind, DeviationKind::MandatoryMissing { ie_type: 29 });
    assert_eq!(on_n4[0].path, "/pfcp/Create PDR/0/Precedence");
    assert!(kinds(&message, Interfaces::SXA).is_empty());
    // An IE that the interface does not have.
    request_with(&mut message, |request| request.create_pdr[0].precedence = Some(Precedence::new(1)));
    assert_eq!(kinds(&message, Interfaces::SXA), [DeviationKind::NotOnInterface { ie_type: 29 }]);
}

fn request_with(message: &mut Message, change: impl FnOnce(&mut SessionEstablishmentRequest)) {
    let Body::SessionEstablishmentRequest(request) = &mut message.body else { panic!() };
    change(request);
}

/// §7.2.3.2: the mandatory IE of a mandatory grouped IE is answered with "Mandatory IE
/// missing", that of a conditional one with "Conditional IE missing", and that of an
/// optional one not at all; nor is any of a response.
#[test]
fn the_cause_follows_the_presence_of_the_grouped_ie() {
    let mut message = establishment();
    request_with(&mut message, |request| request.create_pdr[0].pdi.as_mut().unwrap().source_interface = None);
    let found = message.check();
    assert_eq!(found[0].cause(), Some(CauseValue::MandatoryIeMissing), "{found:?}");
    assert_eq!(found[0].offending_ie(), Some(20));

    let mut modification = SessionModificationRequest::default().with_create_pdr(pdr(1));
    modification.create_pdr[0].pdr_id = None;
    let message = Message { header: Header::session(0x2002, 8), body: modification.into() };
    let found = message.check();
    assert_eq!(found[0].kind, DeviationKind::MandatoryMissing { ie_type: 56 }, "{found:?}");
    assert_eq!(found[0].cause(), Some(CauseValue::ConditionalIeMissing));

    let mut establishment = establishment();
    request_with(&mut establishment, |request| {
        request.create_bar = Some(Box::default());
    });
    let found = establishment.check();
    assert_eq!(found[0].kind, DeviationKind::MandatoryMissing { ie_type: 88 }, "{found:?}");
    assert_eq!(found[0].cause(), None, "an optional grouped IE");

    let response = SessionEstablishmentResponse::default();
    let message = Message { header: Header::session(0x1001, 7), body: response.into() };
    assert!(message.check().iter().all(|deviation| deviation.cause().is_none()));
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
    let mut message = Message { header: Header::session(0x1001, 7), body: response.into() };
    assert!(message.check().is_empty(), "{:?}", message.check());
    let Body::SessionEstablishmentResponse(response) = &mut message.body else { panic!() };
    response.up_f_seid = Some(FSeid { v4: true, seid: Some(1), ipv4: Some(SMF), ..Default::default() });
    assert_eq!(kinds(&message, Interfaces::N4), [DeviationKind::WithRejection { ie_type: 57 }]);
}

/// §7.2.2.4.2: SEID 0 in an establishment, or in an answer that rejects; not in a
/// modification, nor in an answer that accepts.
#[test]
fn seid_0_only_where_the_peer_seid_is_not_known() {
    let establishment = establishment();
    assert!(establishment.check().is_empty());
    let modification = Message { header: Header::session(0, 8), body: SessionModificationRequest::default().into() };
    assert!(modification.check().iter().any(|deviation| deviation.clause == "7.2.2.4.2"));
    let response = SessionModificationResponse { cause: Some(Cause::new(CauseValue::SessionContextNotFound)), ..Default::default() };
    let mut message = Message { header: Header::session(0, 8), body: response.into() };
    assert!(message.check().is_empty(), "{:?}", message.check());
    let Body::SessionModificationResponse(response) = &mut message.body else { panic!() };
    response.cause = Some(Cause::new(CauseValue::RequestAccepted));
    assert!(message.check().iter().any(|deviation| deviation.clause == "7.2.2.4.2"));
}

/// Table 7.3-1: PFD management is not on Sxa; a message type of no table is reported.
#[test]
fn a_message_type_of_the_interface() {
    let request = PfdManagementRequest::default();
    let message = Message { header: Header::node(3), body: request.into() };
    assert!(kinds(&message, Interfaces::N4).is_empty());
    assert_eq!(kinds(&message, Interfaces::SXA), [DeviationKind::MessageNotOnInterface { message_type: 3 }]);
    let other = Message { header: Header::node(3), body: Body::Other { message_type: 99, octets: Octets::new() } };
    assert_eq!(kinds(&other, Interfaces::N4), [DeviationKind::UnknownMessage { message_type: 99 }]);
}

/// §6.3.3.2: one message does not create, update or remove one rule twice.
#[test]
fn check_one_change_per_rule() {
    let modification = SessionModificationRequest::default()
        .with_create_pdr(pdr(3))
        .with_remove_pdr(RemovePdr::new(PdrId::new(3)))
        .with_create_far(far(4))
        .with_update_far(UpdateFar::new(FarId::new(5)));
    let message = Message { header: Header::session(0x2002, 8), body: modification.into() };
    assert_eq!(kinds(&message, Interfaces::N4), [DeviationKind::RuleChangedTwice { rule: "PDR", id: 3 }]);
    let mut establishment = establishment();
    request_with(&mut establishment, |request| request.create_far.push(far(1)));
    assert_eq!(kinds(&establishment, Interfaces::N4), [DeviationKind::RuleChangedTwice { rule: "FAR", id: 1 }]);
}

/// §8.2.34: a Metric is a percentage, and a receiver takes another value as 0.
#[test]
fn check_overload_reduction_metric() {
    let overload = OverloadControlInformation::new(
        SequenceNumber::new(1),
        Metric::new(Percent(101)),
        Timer { timer_unit: TimerUnit::OneMinute, timer_value: 1, ..Default::default() },
    );
    let response = SessionEstablishmentResponse {
        node_id: Some(NodeId::Ipv4(SMF)),
        cause: Some(Cause::new(CauseValue::RequestAccepted)),
        up_f_seid: Some(FSeid { v4: true, seid: Some(1), ipv4: Some(SMF), ..Default::default() }),
        overload_control_information: Some(Box::new(overload)),
        ..Default::default()
    };
    let message = Message { header: Header::session(0x1001, 7), body: response.into() };
    assert_eq!(kinds(&message, Interfaces::N4), [DeviationKind::SpareValue { value: 101 }]);
}

/// §7.6.8: a reserved value is an incorrect IE, a spare one is ignored; Table 8.1.2-1: an
/// IE of a fixed length has that length.
#[test]
fn reserved_values_and_fixed_lengths() {
    let mut message = establishment();
    request_with(&mut message, |request| request.rat_type = Some(RatType::new(RatTypeValue::from_value(0))));
    assert_eq!(kinds(&message, Interfaces::N4), [DeviationKind::ReservedValue { value: 0 }]);
    request_with(&mut message, |request| request.rat_type = Some(RatType::new(RatTypeValue::from_value(200))));
    assert_eq!(kinds(&message, Interfaces::N4), [DeviationKind::SpareValue { value: 200 }]);
    request_with(&mut message, |request| {
        request.rat_type = None;
        request.s_nssai = SNssai::decode(&[1, 0, 0, 1, 9]);
    });
    let found = message.check();
    assert_eq!(found[0].kind, DeviationKind::FixedLength { ie_type: 257, length: 5 }, "{found:?}");
    assert_eq!(found[0].cause(), None, "an optional IE");
}
