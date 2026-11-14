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
//! 0.5.0, a codec of PFCP of N4 written apart from it:
//! - a message that one decodes and the other refuses, which is a difference but for
//!   those of [`READINGS`], each a reading of rs-pfcp that TS 29.244 does not have, which
//!   the case is checked to be: what check() tells, on N4 where the message type has it, of
//!   the IE that rs-pfcp names or of the whole message, or what the octets show;
//! - of a message that both decode, its message type, SEID and sequence number;
//! - each IE that rs-pfcp keeps of it, at every level of the grouped IEs that both read as
//!   one, by its type, its Enterprise ID and its octets: one that this crate reads, as
//!   many times, at that level; and each IE that rs-pfcp drops of the message, which this
//!   crate keeps as octets, under the name of its type, or one of [`READINGS`];
//! - the value of each IE of a type of [`VALUES`] at any level, as each reads it: the same,
//!   or one of [`READINGS`].

use oxirush_pfcp::framing::{self, IeSlice};
use oxirush_pfcp::tree::{self, Value};
use oxirush_pfcp::{
    Check, Codec, DeviationKind, Form, IE_TYPES, Interfaces, Message, VENDOR, ie_type_info,
    is_node_related, message_type_info, paths,
};
use rs_pfcp::error::PfcpError;
use rs_pfcp::ie::{Ie, IeType};

/// The readings of rs-pfcp that TS 29.244 does not have, which a difference may be.
pub const READINGS: [&str; 14] = [
    "rs-pfcp refuses a message without an IE that it needs, which this crate decodes and \
     check() tells of that IE: missing, incorrect or of a null length (§7.6.6, §7.6.8)",
    "rs-pfcp needs the UP F-SEID of every Session Establishment Response, which Table \
     7.5.3.1-1 has where the request is accepted",
    "rs-pfcp refuses a message of an IE whose value it does not decode, which this crate \
     decodes and check() tells of that IE, or of the whole message, which its receiver \
     discards (§7.6.2, §7.6.4, §7.6.5, §7.6.8, §8.1.2)",
    "rs-pfcp reads a message whose Message Length, or the Length of an IE, does not frame \
     it, which a receiver answers \"Invalid length\" (§7.6.3, §7.6.7)",
    "rs-pfcp refuses the IEs of a grouped IE of which one has a null length, or is a vendor \
     IE without its Enterprise ID, which this crate keeps as octets (§8.1.1, §8.1.2)",
    "rs-pfcp drops an IE that its message has no field for, or that repeats one there once, \
     which this crate keeps as octets (§7.6.9, §7.6.10)",
    "rs-pfcp refuses or reads otherwise a value whose fields break a rule of its clause, \
     which this crate decodes and check() tells (§7.6.8)",
    "rs-pfcp reads a Cause value that its table lacks as another",
    "rs-pfcp refuses a Node ID of an FQDN whose labels are not UTF-8 (String::from_utf8 in \
     ie/node_id.rs), where §8.2.38 names RFC 1035 §3.1, which has no character set",
    "rs-pfcp keeps the last of the IEs that repeat one that its message has once, where the \
     receiver handles the first, which this crate reads, and keeps the others as octets \
     (§7.6.10)",
    "rs-pfcp refuses an IE of a null length other than a Network Instance, an APN/DNN or a \
     Forwarding Policy (allows_zero_length in ie/mod.rs), which §8.1.2 has a receiver not \
     take as an error",
    "rs-pfcp reads the Node ID and the Application ID's PFDs of a PFD Management Request \
     into fields of their own, which its all_ies() leaves out",
    "rs-pfcp gives no SEID of a node related message whose S flag is set, which check() \
     tells (§7.2.2.1)",
    "rs-pfcp panics on an FQ-CSID whose bits 4 to 1 of octet 5 are 2, which it reads as the \
     Node-ID Type of an FQDN, and whose bits 8 to 5 count more PDN Connection Set \
     Identifiers than its octets hold (a subtraction that overflows in ie/fq_csid.rs), \
     where §8.2.43 has the Node-ID Type in bits 8 to 5 and the Number of CSID in bits 4 \
     to 1: the octets are not compared",
];

/// The IE types whose values both read: Cause, F-TEID, Precedence, PDR ID, F-SEID, Node
/// ID, URR ID, UE IP Address, FAR ID and QER ID.
pub const VALUES: [u16; 10] = [19, 21, 29, 56, 57, 60, 81, 93, 108, 109];

/// Compare the readings of `octets`, and panic at a difference that is not one of
/// [`READINGS`].
pub fn compare(octets: &[u8]) {
    if panics_rs_pfcp(octets) {
        let _ = READINGS[13];
        return;
    }
    let (ours, theirs) = match (Message::decode(octets), rs_pfcp::message::parse(octets)) {
        (Ok(ours), Ok(theirs)) => (ours, theirs),
        (Err(_), Err(_)) => return,
        (Ok(ours), Err(error)) => return refused(&ours, octets, &error),
        (Err(error), Ok(_)) => {
            // The octets do not frame: the Message Length, or the Length of an IE
            let length = octets.get(2..4).map(|length| usize::from(u16::from_be_bytes([length[0], length[1]])));
            let unframed = length != octets.len().checked_sub(4)
                || framing::message_ies(octets).map_or(true, |(_, _, mut ies)| ies.any(|ie| ie.is_err()));
            assert!(unframed, "rs-pfcp decodes what this crate refuses: {error}");
            let _ = READINGS[3];
            return;
        }
    };
    assert_eq!(theirs.msg_type_code(), ours.body.message_type(), "the message type");
    if theirs.seid().map(|seid| seid.0) != ours.header.seid {
        let node = is_node_related(ours.body.message_type());
        assert!(node && theirs.seid().is_none(), "the SEID: {:?}, {:?}", theirs.seid(), ours.header.seid);
        let _ = READINGS[12];
    }
    assert_eq!(theirs.sequence().0, ours.header.sequence, "the sequence number");
    let Ok((_, _, ies)) = framing::message_ies(octets) else {
        panic!("a message that decodes and does not frame")
    };
    let ies: Vec<IeSlice> = ies.map(Result::unwrap).collect();
    let kept: Vec<Ie> = theirs.all_ies().into_iter().cloned().collect();
    let dropped = same_ies(&ies, &kept);
    // What rs-pfcp drops, the message keeps as octets: that IE itself, under the name of
    // its type
    let tree = ours.to_tree();
    let table = message_type_info(ours.body.message_type()).map(|info| info.table);
    for ie in dropped {
        let named = |name: &str| {
            name.parse() == Ok(ie.ie_type)
                || table.and_then(|table| table.row_of(ie.ie_type)).is_some_and(|row| row.name == name)
                || ie_type_info(ie.ie_type).is_some_and(|info| info.name == name)
        };
        let as_octets = |value: &Value| {
            value.get("octets").and_then(Value::as_str) == Some(&hex(ie.value)[..])
                && value.get("Enterprise ID").and_then(Value::as_u64) == ie.enterprise_id.map(u64::from)
        };
        let held = tree["ies"].as_object().into_iter().flatten().any(|(name, value)| {
            named(name)
                && match value {
                    Value::Array(entries) => entries.iter().any(as_octets),
                    value => as_octets(value),
                }
        });
        if held {
            let _ = READINGS[5];
            continue;
        }
        if ours.body.message_type() == 3 && [58, 60].contains(&ie.ie_type) {
            use rs_pfcp::message::{Message as _, pfd_management_request::PfdManagementRequest};
            let request = PfdManagementRequest::unmarshal(octets).expect("a message that rs-pfcp reads");
            let read = match ie.ie_type {
                60 => request.node_id.is_some(),
                _ => request.application_ids_pfds.is_some_and(|pfds| !pfds.is_empty()),
            };
            assert!(read, "rs-pfcp drops IE type {} of a PFD Management Request", ie.ie_type);
            let _ = READINGS[11];
            continue;
        }
        let first = ies.iter().find(|other| other.ie_type == ie.ie_type) == Some(&ie);
        let later = kept.iter().any(|other| other.raw_type() == ie.ie_type);
        assert!(first && later, "rs-pfcp drops IE type {} that this crate reads", ie.ie_type);
        let _ = READINGS[9];
    }
}

/// A message that this crate decodes and rs-pfcp refuses: check() tells a deviation of the
/// IE that rs-pfcp names, on N4, of which rs-pfcp is a codec, where the message type has it.
fn refused(ours: &Message, octets: &[u8], error: &PfcpError) {
    let own = message_type_info(ours.body.message_type()).map_or(Interfaces::N4, |info| info.interfaces);
    let found = ours.check(if own.has(Interfaces::N4) { Interfaces::N4 } else { own });
    let tree = ours.to_tree();
    // A deviation of the whole message, which its receiver discards (§7.6.2, §7.6.4, §7.6.5)
    let whole = found.iter().any(|deviation| ["/message", "/header/Version"].contains(&&deviation.path[..]));
    // A deviation of an IE of one of `types`: one that names its type, or at it or within it
    let about = |types: &[u16], kinds: &dyn Fn(&DeviationKind) -> bool| {
        found.iter().any(|deviation| {
            let at = deviation.path.match_indices('/').map(|(end, _)| &deviation.path[..end]);
            let at = at.chain([&deviation.path[..]]).any(|path| {
                let number = path.rsplit('/').next().and_then(|name| name.parse().ok());
                let row = paths::row_at(&tree, path).ok().flatten().map(|(_, info)| info.ie_type);
                types.iter().any(|ie_type| number == Some(*ie_type) || row == Some(*ie_type))
            });
            kinds(&deviation.kind) && (at || ie_type_of(&deviation.kind).is_some_and(|ie_type| types.contains(&ie_type)))
        })
    };
    let mandatory = |kind: &DeviationKind| {
        matches!(
            kind,
            DeviationKind::MandatoryMissing { .. }
                | DeviationKind::MandatoryIncorrect { .. }
                | DeviationKind::NullLength { .. }
                | DeviationKind::InvalidLength { .. }
                | DeviationKind::Repeated { .. }
                | DeviationKind::NotOnInterface { .. }
        )
    };
    let reading = match error {
        PfcpError::MissingMandatoryIe { ie_type, .. } if about(&[*ie_type as u16], &mandatory) => 0,
        PfcpError::MissingMandatoryIe { ie_type, .. }
            if ours.body.message_type() == 51 && *ie_type == IeType::Fseid =>
        {
            1
        }
        PfcpError::MissingMandatoryIe { .. } => {
            panic!("rs-pfcp needs an IE that this crate does not: {error}: {found:?}")
        }
        PfcpError::InvalidValue { field, .. } if field == "Node ID (FQDN)" && fqdn_not_utf8(octets) => 8,
        PfcpError::InvalidValue { field, value, reason } if field == "IE" && reason == "Zero-length IE not allowed" => {
            let types = named(octets, error);
            let null = every_ie(octets).iter().any(|ie| types.contains(&ie.ie_type) && ie.length == 0);
            assert!(null, "rs-pfcp refuses an IE of a null length that the message does not have: {value}");
            10
        }
        _ if whole => 2,
        _ => {
            let types = named(octets, error);
            assert!(!types.is_empty(), "rs-pfcp refuses a message that this crate decodes, of no IE that it names: {error}");
            assert!(about(&types, &|_| true), "rs-pfcp refuses an IE that this crate decodes, of IE type {types:?}: {error}: {found:?}");
            2
        }
    };
    let _ = READINGS[reading];
}

/// The IE types of the IE that a refusal of rs-pfcp names: by its type, by the type of its
/// text (`Unknown (type 0)`) or by its name; where it names no type, a vendor IE too short
/// for its Enterprise ID, an IE of a type that it lacks, or one cut short in a grouped IE.
fn named(octets: &[u8], error: &PfcpError) -> Vec<u16> {
    // The IE type of the longest name that a text begins with
    let by_name = |text: &str| -> Vec<u16> {
        let begins = |name: &str| text.get(..name.len()).is_some_and(|head| tree::same_name(head, name));
        let longest = IE_TYPES.iter().filter(|info| begins(info.name)).max_by_key(|info| info.name.len());
        longest.map(|info| info.ie_type).into_iter().collect()
    };
    match error {
        PfcpError::InvalidLength { ie_name, .. } if ie_name.starts_with("Vendor-specific IE") => {
            let mut types = vendor_without_id(octets);
            types.extend(unframed(octets));
            types
        }
        // A type that rs-pfcp lacks, or an IE cut short in a grouped IE, which it does not name
        PfcpError::IeParseError { ie_type: IeType::Unknown, .. } | PfcpError::InvalidLength { ie_type: IeType::Unknown, .. } => {
            let ies = every_ie(octets);
            let unknown = ies.iter().filter(|ie| IeType::from(ie.ie_type) == IeType::Unknown).map(|ie| ie.ie_type);
            unknown.chain(unframed(octets)).collect()
        }
        PfcpError::IeParseError { ie_type, .. } | PfcpError::InvalidLength { ie_type, .. } | PfcpError::EncodingError { ie_type, .. } => {
            vec![*ie_type as u16]
        }
        PfcpError::ZeroLengthNotAllowed { ie_type, .. } => vec![*ie_type],
        PfcpError::InvalidValue { field, value, .. } if field == "IE" => {
            let number = value.rsplit_once("(type ").and_then(|(_, rest)| rest.strip_suffix(')'));
            number.and_then(|number| number.parse().ok()).into_iter().collect()
        }
        PfcpError::InvalidValue { field, .. } => by_name(field),
        PfcpError::MessageParseError { reason, .. } => {
            let duplicate = reason.split_once("Duplicate ").and_then(|(_, ie)| ie.strip_suffix(" IE"));
            duplicate.map_or(Vec::new(), |name| IE_TYPES.iter().filter(|info| tree::same_name(info.name, name)).map(|info| info.ie_type).collect())
        }
        _ => Vec::new(),
    }
}

/// The types of the vendor IEs of the message, at any level of the grouped IEs, that are
/// too short for an Enterprise ID.
fn vendor_without_id(octets: &[u8]) -> Vec<u16> {
    let ies = every_ie(octets);
    ies.iter().filter(|ie| ie.ie_type >= VENDOR && ie.enterprise_id.is_none()).map(|ie| ie.ie_type).collect()
}

/// The IEs of the message at every level of the grouped IEs that frame.
fn every_ie(octets: &[u8]) -> Vec<IeSlice<'_>> {
    fn walk<'a>(ies: framing::Ies<'a>, found: &mut Vec<IeSlice<'a>>) {
        for ie in ies.flatten() {
            found.push(ie);
            if ie_type_info(ie.ie_type).is_some_and(|info| matches!(info.form, Form::Grouped)) {
                walk(ie.ies(), found);
            }
        }
    }
    let mut found = Vec::new();
    if let Ok((_, _, ies)) = framing::message_ies(octets) {
        walk(ies, &mut found);
    }
    found
}

/// The grouped IEs of the message whose IEs do not frame, and the type of the IE that does
/// not.
fn unframed(octets: &[u8]) -> Vec<u16> {
    let grouped = every_ie(octets).into_iter().filter(|ie| ie_type_info(ie.ie_type).is_some_and(|info| matches!(info.form, Form::Grouped)));
    let fault = |ie: IeSlice| ie.ies().find_map(Result::err).map(|fault| (ie.ie_type, fault));
    grouped.filter_map(fault).flat_map(|(grouped, fault)| match fault {
        oxirush_pfcp::IeFault::Length { ie_type, .. } => vec![grouped, ie_type],
        _ => vec![grouped],
    }).collect()
}

/// Whether the message has a Node ID of an FQDN of octets that are no UTF-8.
fn fqdn_not_utf8(octets: &[u8]) -> bool {
    let not_utf8 = |ie: &IeSlice| ie.value.first() == Some(&2) && core::str::from_utf8(&ie.value[1..]).is_err();
    every_ie(octets).iter().any(|ie| ie.ie_type == 60 && not_utf8(ie))
}

/// Whether rs-pfcp panics on the octets: an FQ-CSID, at any level, whose low half of its
/// first octet is 2 and whose high half counts more identifiers of two octets than the IE
/// has octets (`READINGS[13]`).
fn panics_rs_pfcp(octets: &[u8]) -> bool {
    let panics = |ie: &IeSlice| {
        ie.value.first().is_some_and(|first| first & 0x0f == 2 && ie.value.len() < 2 * usize::from(first >> 4))
    };
    every_ie(octets).iter().any(|ie| ie.ie_type == 65 && panics(ie))
}

/// The IE type that a deviation names.
fn ie_type_of(kind: &DeviationKind) -> Option<u16> {
    match kind {
        DeviationKind::MandatoryMissing { ie_type }
        | DeviationKind::MandatoryIncorrect { ie_type }
        | DeviationKind::ConditionalMissing { ie_type }
        | DeviationKind::ConditionalIncorrect { ie_type }
        | DeviationKind::NullLength { ie_type }
        | DeviationKind::Repeated { ie_type }
        | DeviationKind::Unexpected { ie_type }
        | DeviationKind::Excluded { ie_type }
        | DeviationKind::NotOnInterface { ie_type }
        | DeviationKind::WithRejection { ie_type }
        | DeviationKind::InvalidLength { ie_type }
        | DeviationKind::FixedLength { ie_type, .. }
        | DeviationKind::UnknownType { ie_type } => Some(*ie_type),
        _ => None,
    }
}

fn hex(octets: &[u8]) -> String {
    octets.iter().map(|octet| format!("{octet:02x}")).collect()
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
            if theirs.is_none() && octets.first() == Some(&2) && core::str::from_utf8(&octets[1..]).is_err() {
                let _ = READINGS[8];
                return;
            }
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
