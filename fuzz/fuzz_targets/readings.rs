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

//! What the differential target compares, of the octets read by this crate and by rs-pfcp
//! 0.5.0, a codec of PFCP written apart from it:
//! - a message that one decodes and the other refuses, which is a difference but for
//!   those of [`READINGS`], each a reading of rs-pfcp that TS 29.244 does not have, which
//!   the case is checked to be;
//! - of a message that both decode, its message type, SEID and sequence number;
//! - each IE that rs-pfcp keeps of it, at every level of the grouped IEs that both read as
//!   one, by its type, its Enterprise ID and its octets: one that this crate reads, as
//!   many times, at that level; and the IEs that rs-pfcp drops of the message, which this
//!   crate keeps as octets, each one of [`READINGS`];
//! - the value of each IE of a type of [`VALUES`] at any level, as each reads it: the same,
//!   or one of [`READINGS`].

use oxirush_pfcp::framing::{self, IeSlice};
use oxirush_pfcp::tree::Value;
use oxirush_pfcp::{Check, Codec, DeviationKind, Form, Interfaces, Message, ie_type_info};
use rs_pfcp::error::PfcpError;
use rs_pfcp::ie::Ie;

/// The readings of rs-pfcp that TS 29.244 does not have, which a difference may be.
pub const READINGS: [&str; 8] = [
    "rs-pfcp refuses a message without an IE that it needs, which this crate decodes and \
     check() tells: a mandatory IE missing, incorrect or of a null length (§7.6.6, §7.6.8)",
    "rs-pfcp needs the UP F-SEID of every Session Establishment Response, which Table \
     7.5.3.1-1 has where the request is accepted",
    "rs-pfcp refuses a message of an IE whose value it does not decode, or of a null length, \
     which this crate decodes and check() tells (§7.6.8, §8.1.2)",
    "rs-pfcp reads a message whose Message Length, or the Length of an IE, does not frame \
     it, which a receiver answers \"Invalid length\" (§7.6.3, §7.6.7)",
    "rs-pfcp refuses the IEs of a grouped IE of which one has a null length, or is a vendor \
     IE without its Enterprise ID, which this crate keeps as octets (§8.1.1, §8.1.2)",
    "rs-pfcp drops an IE that its message has no field for, or that repeats one there once, \
     which this crate keeps as octets (§7.6.9, §7.6.10)",
    "rs-pfcp refuses or reads otherwise a value whose fields break a rule of its clause, \
     which this crate decodes and check() tells (§7.6.8)",
    "rs-pfcp reads a Cause value that its table lacks as another",
];

/// The IE types whose values both read: Cause, F-TEID, Precedence, PDR ID, F-SEID, Node
/// ID, URR ID, UE IP Address, FAR ID and QER ID.
pub const VALUES: [u16; 10] = [19, 21, 29, 56, 57, 60, 81, 93, 108, 109];

/// Compare the readings of `octets`, and panic at a difference that is not one of
/// [`READINGS`].
pub fn compare(octets: &[u8]) {
    let (ours, theirs) = match (Message::decode(octets), rs_pfcp::message::parse(octets)) {
        (Ok(ours), Ok(theirs)) => (ours, theirs),
        (Err(_), Err(_)) => return,
        (Ok(ours), Err(error)) => return refused(&ours, &error),
        (Err(error), Ok(_)) => {
            let unframed = matches!(
                error,
                oxirush_pfcp::Error::MessageLength { .. } | oxirush_pfcp::Error::Ies { .. }
            );
            assert!(unframed, "rs-pfcp decodes what this crate refuses: {error}");
            let _ = READINGS[3];
            return;
        }
    };
    assert_eq!(theirs.msg_type_code(), ours.body.message_type(), "the message type");
    assert_eq!(theirs.seid().map(|seid| seid.0), ours.header.seid, "the SEID");
    assert_eq!(theirs.sequence().0, ours.header.sequence, "the sequence number");
    let Ok((_, _, ies)) = framing::message_ies(octets) else {
        panic!("a message that decodes and does not frame")
    };
    let ies: Vec<IeSlice> = ies.map(Result::unwrap).collect();
    let kept: Vec<Ie> = theirs.all_ies().into_iter().cloned().collect();
    let dropped = same_ies(&ies, &kept);
    // What rs-pfcp drops, the message keeps as octets
    let tree = ours.to_tree();
    for ie in dropped {
        let as_octets = |value: &Value| value.get("octets").is_some();
        let held = tree["ies"].as_object().into_iter().flatten().any(|(_, value)| match value {
            Value::Array(entries) => entries.iter().any(as_octets),
            value => as_octets(value),
        });
        assert!(held, "rs-pfcp drops IE type {} that this crate reads", ie.ie_type);
        let _ = READINGS[5];
    }
}

/// A message that this crate decodes and rs-pfcp refuses.
fn refused(ours: &Message, error: &PfcpError) {
    let each = [Interfaces::SXA, Interfaces::SXB, Interfaces::SXC, Interfaces::N4, Interfaces::N4MB];
    let found: Vec<DeviationKind> = each
        .iter()
        .flat_map(|interface| ours.check(*interface))
        .map(|deviation| deviation.kind)
        .collect();
    let mandatory = found.iter().any(|kind| {
        matches!(
            kind,
            DeviationKind::MandatoryMissing { .. }
                | DeviationKind::MandatoryIncorrect { .. }
                | DeviationKind::NullLength { .. }
                | DeviationKind::InvalidLength { .. }
                | DeviationKind::Repeated { .. }
                | DeviationKind::NotOnInterface { .. }
        )
    });
    let reading = match error {
        PfcpError::MissingMandatoryIe { .. } if mandatory => 0,
        PfcpError::MissingMandatoryIe { ie_type, .. }
            if ours.body.message_type() == 51 && *ie_type == rs_pfcp::ie::IeType::Fseid =>
        {
            1
        }
        PfcpError::MissingMandatoryIe { .. } => {
            panic!("rs-pfcp needs an IE that this crate does not: {error}: {found:?}")
        }
        _ if !found.is_empty() => 2,
        _ => panic!("rs-pfcp refuses a message that this crate decodes: {error}"),
    };
    let _ = READINGS[reading];
}

/// Whether `ours`, the IEs of a scope as this crate frames them, has each of `theirs`, as
/// many times, and each of a grouped IE has the IEs of rs-pfcp's, as deep as they go; and
/// each value of [`VALUES`] read alike. What rs-pfcp does not keep.
fn same_ies<'a>(ours: &[IeSlice<'a>], theirs: &[Ie]) -> Vec<IeSlice<'a>> {
    let mut left: Vec<IeSlice> = ours.to_vec();
    for ie in theirs {
        let kept = (ie.raw_type(), ie.enterprise_id(), &ie.payload[..]);
        let Some(at) = left.iter().position(|ours| (ours.ie_type, ours.enterprise_id, ours.value) == kept) else {
            panic!("rs-pfcp keeps an IE that this crate does not, or not as many times: {kept:02x?}")
        };
        let ours = left.remove(at);
        let grouped = ie_type_info(ours.ie_type).is_some_and(|info| matches!(info.form, Form::Grouped));
        match grouped {
            true => {
                let (mut ie, ies) = (ie.clone(), ours.ies().collect::<Result<Vec<_>, _>>());
                match (ies, ie.as_ies()) {
                    (Ok(ours), Ok(theirs)) => {
                        let theirs = theirs.to_vec();
                        let dropped = same_ies(&ours, &theirs);
                        assert!(dropped.is_empty(), "rs-pfcp drops an IE of a grouped IE: {dropped:02x?}");
                    }
                    (Err(_), Err(_)) => {}
                    (Ok(ours), Err(error)) => {
                        let refused = |ie: &IeSlice| {
                            ie.content().is_empty() || ie.ie_type >= 0x8000 && ie.enterprise_id.is_none()
                        };
                        assert!(
                            ours.iter().any(refused),
                            "rs-pfcp refuses the IEs of a grouped IE that this crate frames: {error}"
                        );
                        let _ = READINGS[4];
                    }
                    (Err(fault), Ok(_)) => panic!("rs-pfcp frames the IEs of a grouped IE that this crate does not: {fault}"),
                }
            }
            false => value(ours.ie_type, ours.value),
        }
    }
    left
}

/// The value of an IE of [`VALUES`] as each reads it.
fn value(ie_type: u16, octets: &[u8]) {
    use rs_pfcp::ie as theirs;
    if !VALUES.contains(&ie_type) {
        return;
    }
    let (ours, theirs, told): (Option<String>, Option<String>, bool) = match ie_type {
        19 => {
            let theirs = theirs::cause::Cause::unmarshal(octets).ok();
            // A value that rs-pfcp writes back as another, which its table lacks
            if theirs.as_ref().is_some_and(|cause| cause.marshal()[..] != octets[..1]) {
                let _ = READINGS[7];
                return;
            }
            let ours = oxirush_pfcp::Cause::decode(octets).map(|cause| u32::from(cause.value.value()));
            (fmt(ours), fmt(theirs.map(|cause| cause.value as u32)), told::<oxirush_pfcp::Cause>(octets))
        }
        21 => (
            fmt(oxirush_pfcp::FTeid::decode(octets).map(|f| (f.ch, f.chid, f.teid.unwrap_or(0), f.ipv4, f.ipv6, f.choose_id.unwrap_or(0)))),
            fmt(theirs::f_teid::Fteid::unmarshal(octets).ok().map(|f| (f.ch, f.chid, f.teid.0, f.ipv4_address, f.ipv6_address, f.choose_id))),
            told::<oxirush_pfcp::FTeid>(octets),
        ),
        29 => (
            fmt(oxirush_pfcp::Precedence::decode(octets).map(|v| v.value)),
            fmt(theirs::precedence::Precedence::unmarshal(octets).ok().map(|v| v.value)),
            false,
        ),
        56 => (
            fmt(oxirush_pfcp::PdrId::decode(octets).map(|v| v.value)),
            fmt(theirs::pdr_id::PdrId::unmarshal(octets).ok().map(|v| v.value)),
            false,
        ),
        57 => (
            fmt(oxirush_pfcp::FSeid::decode(octets).map(|f| (f.seid, f.ipv4, f.ipv6))),
            fmt(theirs::fseid::Fseid::unmarshal(octets).ok().map(|f| (f.seid.0, f.ipv4_address, f.ipv6_address))),
            told::<oxirush_pfcp::FSeid>(octets),
        ),
        60 => {
            // As a receiver takes it: an address of more octets than its type is the address
            use oxirush_pfcp::NodeId;
            let ours = NodeId::decode(octets).and_then(|node| node.effective());
            let ours = ours.map(|node| match node {
                NodeId::Ipv4(address) => format!("{address}"),
                NodeId::Ipv6(address) => format!("{address}"),
                NodeId::Fqdn(labels) => format!("{:02x?}", &labels[..]),
                NodeId::Other(..) => String::new(),
            });
            let theirs = theirs::node_id::NodeId::unmarshal(octets).ok().map(|node| match node {
                theirs::node_id::NodeId::IPv4(address) => format!("{address}"),
                theirs::node_id::NodeId::IPv6(address) => format!("{address}"),
                theirs::node_id::NodeId::FQDN(labels) => format!("{:02x?}", labels.as_bytes()),
            });
            (ours, theirs, told::<NodeId>(octets))
        }
        81 => (
            fmt(oxirush_pfcp::UrrId::decode(octets).map(|v| v.value)),
            fmt(theirs::urr_id::UrrId::unmarshal(octets).ok().map(|v| v.id)),
            false,
        ),
        93 => (
            fmt(oxirush_pfcp::UeIpAddress::decode(octets).map(|v| (v.sd, v.chv4, v.chv6, v.ipv4, v.ipv6, v.ipv6_prefix_delegation_bits, v.ipv6_prefix_length))),
            fmt(theirs::ue_ip_address::UeIpAddress::unmarshal(octets).ok().map(|v| (v.source_destination, v.choose_ipv4, v.choose_ipv6, v.ipv4_address, v.ipv6_address, v.ipv6_prefix_delegation_bits, v.ipv6_prefix_length))),
            told::<oxirush_pfcp::UeIpAddress>(octets),
        ),
        108 => (
            fmt(oxirush_pfcp::FarId::decode(octets).map(|v| v.value)),
            fmt(theirs::far_id::FarId::unmarshal(octets).ok().map(|v| v.value)),
            false,
        ),
        109 => (
            fmt(oxirush_pfcp::QerId::decode(octets).map(|v| v.value)),
            fmt(theirs::qer_id::QerId::unmarshal(octets).ok().map(|v| v.value)),
            false,
        ),
        _ => return,
    };
    if ours != theirs {
        assert!(told, "IE type {ie_type} of {octets:02x?}: this crate reads {ours:?}, rs-pfcp {theirs:?}");
        let _ = READINGS[6];
    }
}

fn fmt<T: core::fmt::Debug>(value: Option<T>) -> Option<String> {
    value.map(|value| format!("{value:?}"))
}

/// Whether check() tells a deviation of a value of `T` of `octets`.
fn told<T: Codec + Check>(octets: &[u8]) -> bool {
    T::decode(octets).is_some_and(|value| !value.deviations().is_empty())
}
