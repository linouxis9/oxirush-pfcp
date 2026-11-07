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

//! A PFCP message: its header and its typed body, and the datagram that carries one or
//! more of them (§7.2.1A).

use alloc::vec::Vec;

use crate::Error;
use crate::check::{Context, Deviation, DeviationKind};
use crate::enums::CauseValue;
use crate::header::Header;
use crate::macros::pfcp_messages;
use crate::table::{Interfaces, Presence};

pfcp_messages! {
    1 HeartbeatRequest [SXA SXB SXC N4 N4MB],
    2 HeartbeatResponse [SXA SXB SXC N4 N4MB],
    3 PfdManagementRequest [SXB SXC N4],
    4 PfdManagementResponse [SXB SXC N4],
    5 AssociationSetupRequest [SXA SXB SXC N4 N4MB],
    6 AssociationSetupResponse [SXA SXB SXC N4 N4MB],
    7 AssociationUpdateRequest [SXA SXB SXC N4 N4MB],
    8 AssociationUpdateResponse [SXA SXB SXC N4 N4MB],
    9 AssociationReleaseRequest [SXA SXB SXC N4 N4MB],
    10 AssociationReleaseResponse [SXA SXB SXC N4 N4MB],
    11 VersionNotSupportedResponse [SXA SXB SXC N4 N4MB],
    12 NodeReportRequest [SXA SXB SXC N4 N4MB],
    13 NodeReportResponse [SXA SXB SXC N4 N4MB],
    14 SessionSetDeletionRequest [SXA SXB N4],
    15 SessionSetDeletionResponse [SXA SXB N4],
    16 SessionSetModificationRequest [SXB N4],
    17 SessionSetModificationResponse [SXB N4],
    50 SessionEstablishmentRequest [SXA SXB SXC N4 N4MB],
    51 SessionEstablishmentResponse [SXA SXB SXC N4 N4MB],
    52 SessionModificationRequest [SXA SXB SXC N4 N4MB],
    53 SessionModificationResponse [SXA SXB SXC N4 N4MB],
    54 SessionDeletionRequest [SXA SXB SXC N4 N4MB],
    55 SessionDeletionResponse [SXA SXB SXC N4 N4MB],
    56 SessionReportRequest [SXA SXB SXC N4 N4MB],
    57 SessionReportResponse [SXA SXB SXC N4 N4MB],
}

/// The name of the message, its SEID and its sequence number: `PFCP Session
/// Establishment Request (SEID 0, sequence 7)`.
impl core::fmt::Display for Message {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self.body.name() {
            Some(name) => f.write_str(name)?,
            None => write!(f, "PFCP message type {}", self.body.message_type())?,
        }
        match self.header.seid {
            Some(seid) => write!(f, " (SEID {seid:#x}, sequence {})", self.header.sequence),
            None => write!(f, " (sequence {})", self.header.sequence),
        }
    }
}

/// A message type as Table 7.3-1 has it.
#[derive(Debug, Clone, Copy)]
pub struct MessageTypeInfo {
    /// The message type.
    pub message_type: u8,
    /// The interfaces that have it: its Applicability columns.
    pub interfaces: crate::table::Interfaces,
    /// The table of its IEs.
    pub table: &'static crate::table::Table,
}

impl MessageTypeInfo {
    /// The name that Table 7.3-1 gives it.
    pub fn name(&self) -> &'static str {
        self.table.name
    }
}

/// The message type of `message_type`.
pub fn message_type_info(message_type: u8) -> Option<&'static MessageTypeInfo> {
    MESSAGE_TYPES
        .iter()
        .find(|info| info.message_type == message_type)
}

/// Whether a message type is one of a node related message (Table 7.3-1): from 1 to 49.
pub fn is_node_related(message_type: u8) -> bool {
    (1..50).contains(&message_type)
}

/// A PFCP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Its header.
    pub header: Header,
    /// Its message type and its IEs.
    pub body: Body,
}

impl Message {
    /// Decode one message, which `octets` are whole.
    ///
    /// # Errors
    ///
    /// Octets shorter than a header, a Message Length that is not the length of the
    /// octets (§7.6.3), and IEs whose framing runs past the message (§7.6.7). The error
    /// has the header, which the answer of a receiver takes.
    pub fn decode(octets: &[u8]) -> Result<Self, Error> {
        let (message, used) = Self::decode_first(octets)?;
        if used != octets.len() {
            let (header, message_type, length) = Header::decode(octets).ok_or(Error::TooShort {
                octets: octets.len(),
            })?;
            return Err(Error::MessageLength {
                header,
                message_type,
                length,
                available: octets.len() - 4,
            });
        }
        Ok(message)
    }

    /// Decode each message of a datagram, which the FO flag of each chains (§7.2.1A),
    /// each on its own (§6.5): a message that does not decode is the error of
    /// [`decode`](Self::decode) in its place, and the next one is decoded after it. The
    /// message without the FO flag is the rest of the datagram, which has no octets after
    /// it (§7.6.3), and so is one whose FO flag says that another follows where the
    /// datagram ends. A Message Length that runs past the datagram ends it.
    pub fn decode_datagram(octets: &[u8]) -> Vec<Result<Self, Error>> {
        datagram_parts(octets)
            .into_iter()
            .map(Message::decode)
            .collect()
    }

    fn decode_first(octets: &[u8]) -> Result<(Self, usize), Error> {
        let (header, message_type, length) = Header::decode(octets).ok_or(Error::TooShort {
            octets: octets.len(),
        })?;
        let end = 4 + usize::from(length);
        let Some(content) = octets
            .get(header.len()..end)
            .filter(|_| end >= header.len())
        else {
            return Err(Error::MessageLength {
                header,
                message_type,
                length,
                available: octets.len() - 4,
            });
        };
        let body = Body::decode(message_type, content).map_err(|fault| Error::Ies {
            header,
            message_type,
            fault,
        })?;
        Ok((Self { header, body }, end))
    }

    /// Encode the message.
    ///
    /// # Errors
    ///
    /// A field that disagrees with the flags of its IE ([`Error::Inconsistent`]), a field
    /// or a field of the header too long for its bits or its length
    /// ([`Error::FieldLength`], [`Error::HeaderField`]), and an IE or a message too long
    /// for its Length ([`Error::TooLong`], [`Error::MessageTooLong`]).
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        // The IEs after room for the header, which their length then completes.
        let header = self.header.len();
        let expected = self.body.encoded_len();
        let mut out = Vec::with_capacity(header + expected);
        out.resize(header, 0);
        self.body.encode(&mut out)?;
        let body = out.len() - header;
        debug_assert_eq!(
            body, expected,
            "the encoded length of the IEs is the one computed first"
        );
        self.header
            .encode_into(self.body.message_type(), body, &mut out)?;
        Ok(out)
    }

    /// Each way in which the message is not as TS 29.244 has a sender construct it on
    /// `interface`: its mandatory IEs, and the IEs that it may have, are those of the
    /// Appl. column of the interface. On a set of interfaces, as [`Interfaces::SXA_SXB`]
    /// of a combined SGW/PGW (§5.2.6), a message may have the IEs of any of them, and
    /// needs those that each of them needs.
    pub fn check(&self, interface: Interfaces) -> Vec<Deviation> {
        let mut found = Vec::new();
        let header = &self.header;
        let message_type = self.body.message_type();
        let node = is_node_related(message_type);
        let known = !matches!(self.body, Body::Other { .. });
        let path = "/header";
        if header.version != 1 {
            found.push(Deviation::new(
                path,
                "7.2.2.4.1",
                DeviationKind::Rule("the version is not 1"),
            ));
        }
        if let Some((field, _)) = header.overflow() {
            let rule = match field {
                "Version" => "a version of more than 3 bits",
                "Spare" => "spare bits of octet 1 of more than 2 bits",
                "Sequence Number" => "a sequence number of more than 24 bits",
                "Message Priority" => "a message priority of more than 4 bits",
                _ => "spare bits of the last octet of more than its bits",
            };
            found.push(Deviation::new(path, "7.2.2.1", DeviationKind::Rule(rule)));
        }
        // The last octet is spare, or its bits after the priority are (§7.2.2.3).
        if header.spare != 0 || header.spare_last != 0 {
            found.push(Deviation::new(path, "7.2.2.1", DeviationKind::SpareBits));
        }
        if known && node && header.seid.is_some() {
            found.push(Deviation::new(
                path,
                "7.2.2.2",
                DeviationKind::Rule("a node related message has the S flag"),
            ));
        }
        if known && !node && header.seid.is_none() {
            found.push(Deviation::new(
                path,
                "7.2.2.4.1",
                DeviationKind::Rule("a session related message has no SEID"),
            ));
        }
        if known && node && header.priority.is_some() {
            found.push(Deviation::new(
                path,
                "7.2.2.2",
                DeviationKind::Rule("a node related message has the MP flag"),
            ));
        }
        if known && node && header.follow_on {
            found.push(Deviation::new(
                path,
                "6.5",
                DeviationKind::Rule("a node related message is bundled"),
            ));
        }
        // An establishment has SEID 0, the peer's SEID being not known yet, but on N4mb,
        // which a set of interfaces with it allows.
        if message_type == 50
            && header.seid.is_some_and(|seid| seid != 0)
            && !interface.has(Interfaces::N4MB)
        {
            found.push(Deviation::new(
                path,
                "7.2.2.4.2",
                DeviationKind::Rule("a Session Establishment Request of a SEID other than 0"),
            ));
        }
        let cause = self.body.cause();
        // SEID 0: an establishment, a report to another SMF, or an answer to a session
        // that the node does not have or to a request that it rejects (§7.2.2.4.2).
        let rejection = cause.is_some_and(|cause| cause.value() >= 64);
        if header.seid == Some(0) && matches!(message_type, 52 | 54)
            || header.seid == Some(0) && cause.is_some() && !rejection
        {
            found.push(Deviation::new(
                path,
                "7.2.2.4.2",
                DeviationKind::Rule("SEID 0 where the peer's SEID is known"),
            ));
        }
        // A Session Report Request of SEID 0 moves the session to another SMF of the set
        // and carries the Old CP F-SEID of the previous one; one of a known SEID has none
        // (§7.2.2.4.2 bullet 4, §5.22.2 bullet 4, Table 7.5.8.1-1).
        if let Body::SessionReportRequest(request) = &self.body {
            let old = request.old_cp_f_seid.is_some();
            if header.seid == Some(0) && !old {
                found.push(Deviation::new(
                    path,
                    "7.2.2.4.2",
                    DeviationKind::Rule(
                        "a Session Report Request of SEID 0 without the Old CP F-SEID",
                    ),
                ));
            }
            if header.seid.is_some_and(|seid| seid != 0) && old {
                found.push(Deviation::new(
                    path,
                    "7.2.2.4.2",
                    DeviationKind::Rule(
                        "a Session Report Request of a SEID other than 0 with the Old CP F-SEID",
                    ),
                ));
            }
        }
        // "This flag shall be set to "1" by the UP function, if the "Overload Control
        // Information" is included in the PFCP Session Establishment Response and the Cause
        // IE is set to a rejection cause value" (§8.2.76): AOCI, which the value of the IE
        // does not show alone.
        if let Body::SessionEstablishmentResponse(response) = &self.body
            && rejection
            && let Some(overload) = &response.overload_control_information
            && !overload
                .overload_control_information_flags
                .as_ref()
                .is_some_and(|flags| flags.aoci)
        {
            found.push(Deviation::new(
                "/pfcp/Overload Control Information/Overload Control Information Flags",
                "8.2.76",
                DeviationKind::Rule(
                    "an Overload Control Information of a rejected establishment without AOCI",
                ),
            ));
        }
        match message_type_info(message_type) {
            Some(info) if !info.interfaces.has(interface) => {
                found.push(Deviation::new(
                    "/message",
                    "7.3",
                    DeviationKind::MessageNotOnInterface { message_type },
                ));
            }
            _ => {}
        }
        let context = Context {
            interface,
            view: Presence::Mandatory,
            request: is_request(message_type) && message_type != 1,
            rejected: rejection,
        };
        self.body
            .check(&crate::check::Path::Root("/pfcp"), context, &mut found);
        // An establishment that creates a rule twice gives two rules one Rule ID, which
        // identifies one rule of its type in the session (§5.2.1); a modification changes
        // a rule once (§6.3.3.2).
        let clause = if message_type == 50 {
            "5.2.1"
        } else {
            "6.3.3.2"
        };
        for (rule, id) in self.body.rules_changed_twice() {
            found.push(Deviation::new(
                "/pfcp",
                clause,
                DeviationKind::RuleChangedTwice { rule, id },
            ));
        }
        found
    }
}

/// The octets of each message of a datagram, as [`Message::decode_datagram`] frames
/// them, before they are decoded.
pub(crate) fn datagram_parts(mut octets: &[u8]) -> Vec<&[u8]> {
    let mut messages = Vec::new();
    loop {
        let Some((header, _, length)) = Header::decode(octets) else {
            messages.push(octets);
            return messages;
        };
        let end = 4 + usize::from(length);
        // An FO flag where the datagram ends follows on to nothing (§7.2.1A).
        let whole = header.follow_on && end < octets.len() && end >= header.len();
        let this = if whole { &octets[..end] } else { octets };
        messages.push(this);
        if !whole {
            return messages;
        }
        octets = &octets[end..];
    }
}

/// The IDs of the rules of one type that a message changes: on the stack while they are
/// few, as they are in a message of a lab.
#[derive(Default)]
struct Ids {
    few: [u32; 32],
    len: usize,
    many: Vec<u32>,
}

impl Ids {
    fn push(&mut self, id: u32) {
        match self.len < self.few.len() {
            true => self.few[self.len] = id,
            false => {
                if self.many.is_empty() {
                    self.many.extend_from_slice(&self.few);
                }
                self.many.push(id);
            }
        }
        self.len += 1;
    }

    fn clear(&mut self) {
        self.len = 0;
        self.many.clear();
    }

    /// Each ID that is there more than once, once.
    fn repeated(&mut self) -> Vec<u32> {
        let ids = match self.len <= self.few.len() {
            true => &mut self.few[..self.len],
            false => &mut self.many[..],
        };
        ids.sort_unstable();
        let mut repeated = Vec::new();
        for pair in ids.windows(2) {
            if pair[0] == pair[1] && repeated.last() != Some(&pair[0]) {
                repeated.push(pair[0]);
            }
        }
        repeated
    }
}

/// Whether a message type is a request of Table 7.3-1: 1 to 9 odd, then, after 11, Version
/// Not Supported Response, 12 to 16 even, and 50 to 56 even. A type that the table does
/// not have is none.
pub fn is_request(message_type: u8) -> bool {
    matches!(
        message_type,
        1 | 3 | 5 | 7 | 9 | 12 | 14 | 16 | 50 | 52 | 54 | 56
    )
}

impl Body {
    /// The Cause of a response.
    pub fn cause(&self) -> Option<CauseValue> {
        let cause = match self {
            Self::PfdManagementResponse(body) => &body.cause,
            Self::AssociationSetupResponse(body) => &body.cause,
            Self::AssociationUpdateResponse(body) => &body.cause,
            Self::AssociationReleaseResponse(body) => &body.cause,
            Self::NodeReportResponse(body) => &body.cause,
            Self::SessionSetDeletionResponse(body) => &body.cause,
            Self::SessionSetModificationResponse(body) => &body.cause,
            Self::SessionEstablishmentResponse(body) => &body.cause,
            Self::SessionModificationResponse(body) => &body.cause,
            Self::SessionDeletionResponse(body) => &body.cause,
            Self::SessionReportResponse(body) => &body.cause,
            _ => return None,
        };
        cause.as_ref().map(|cause| cause.value)
    }

    /// Each rule that the message creates, updates or removes more than once (§5.2.1,
    /// §6.3.3.2), by the name of its type and its ID.
    fn rules_changed_twice(&self) -> Vec<(&'static str, u32)> {
        let mut twice = Vec::new();
        let mut ids = Ids::default();
        // The IDs of the rules of a type, of each of the lists of the message that change
        // them, and those that are there twice.
        macro_rules! rules {
            ($body:ident: $($rule:literal [$($list:ident),+] $id:ident),+ $(,)?) => {{$(
                $(
                    for rule in $body.$list.iter() {
                        if let Some(id) = rule.$id.as_ref() {
                            ids.push(id.value.into());
                        }
                    }
                )+
                twice.extend(ids.repeated().into_iter().map(|id| ($rule, id)));
                ids.clear();
            )+}};
        }
        match self {
            Self::SessionEstablishmentRequest(body) => rules!(body:
                "PDR" [create_pdr] pdr_id,
                "FAR" [create_far] far_id,
                "URR" [create_urr] urr_id,
                "QER" [create_qer] qer_id,
                "MAR" [create_mar] mar_id,
                "SRR" [create_srr] srr_id,
            ),
            Self::SessionModificationRequest(body) => rules!(body:
                "PDR" [create_pdr, update_pdr, remove_pdr] pdr_id,
                "FAR" [create_far, update_far, remove_far] far_id,
                "URR" [create_urr, update_urr, remove_urr] urr_id,
                "QER" [create_qer, update_qer, remove_qer] qer_id,
                "BAR" [create_bar, update_bar, remove_bar] bar_id,
                "MAR" [create_mar, update_mar, remove_mar] mar_id,
                "SRR" [create_srr, update_srr, remove_srr] srr_id,
            ),
            _ => {}
        }
        twice
    }
}

#[cfg(feature = "tree")]
pub(crate) mod forms {
    use oxirush_utils::tree::{self, Members, Reading, Refused, Tree, Value};

    use super::{Body, Message};
    use crate::header::Header;

    /// The members that the tree of a message may have.
    pub(crate) const NAMES: &[&str] = &[
        "message",
        "Version",
        "Spare",
        "FO",
        "SEID",
        "Sequence Number",
        "Message Priority",
        "Spare octet",
        "Message Length",
        "ies",
    ];

    #[cfg(feature = "serde")]
    oxirush_utils::impl_serde!(Message);

    /// `{"message": NAME, "SEID": ..., "Sequence Number": ..., "ies": {...}}`, with the
    /// other members of the header where they are not what a sender writes.
    impl Tree for Message {
        const NAME: &'static str = "PFCP message";

        fn to_tree(&self) -> Value {
            let header = &self.header;
            let mut members = Members::new();
            members.put(
                "message",
                match self.body.name() {
                    Some(name) => tree::text(name),
                    None => tree::unsigned(self.body.message_type().into()),
                },
            );
            if header.version != 1 {
                members.put("Version", tree::unsigned(header.version.into()));
            }
            if header.spare != 0 {
                members.put("Spare", tree::unsigned(header.spare.into()));
            }
            if header.follow_on {
                members.put("FO", Value::Bool(true));
            }
            members.put_optional("SEID", header.seid.map(tree::unsigned));
            members.put("Sequence Number", tree::unsigned(header.sequence.into()));
            members.put_optional(
                "Message Priority",
                header
                    .priority
                    .map(|priority| tree::unsigned(priority.into())),
            );
            if header.spare_last != 0 {
                members.put("Spare octet", tree::unsigned(header.spare_last.into()));
            }
            members.put_optional(
                "Message Length",
                header.length.map(|length| tree::unsigned(length.into())),
            );
            members.put("ies", self.body.ies_tree());
            members.finish()
        }

        fn from_tree(value: &Value, reading: &mut Reading) -> Result<Self, Refused> {
            let read = reading.members(value, NAMES)?;
            // A message of Table 7.3-1 by its name, and one of no table by its number.
            let kind = reading.member(&read, 0, |value, reading| match value.is_number() {
                true => {
                    let code = reading.unsigned(value, 0, 255)? as u8;
                    match super::message_type_info(code) {
                        Some(info) => Err(reading.refuse(
                            tree::ErrorKind::Value,
                            alloc::format!(
                                "message type {code} is the {}, which goes by its name",
                                info.name()
                            ),
                        )),
                        None => Ok(Err(code)),
                    }
                }
                false => Ok(Ok(reading.named(value, &Body::names())?)),
            })?;
            let small = |reading: &mut Reading, at: usize, most: u64| {
                reading.optional(&read, at, |value, reading| reading.unsigned(value, 0, most))
            };
            let version = small(reading, 1, 7)?.unwrap_or(1) as u8;
            let spare = small(reading, 2, 3)?.unwrap_or(0) as u8;
            let follow_on = reading
                .optional(&read, 3, |value, reading| reading.boolean(value))?
                .unwrap_or(false);
            let seid = reading.optional(&read, 4, |value, reading| {
                reading.unsigned(value, 0, u64::MAX)
            })?;
            let sequence = reading.member(&read, 5, |value, reading| {
                reading.unsigned(value, 0, 0xff_ffff)
            })? as u32;
            let priority = small(reading, 6, 15)?.map(|priority| priority as u8);
            let spare_last =
                small(reading, 7, if priority.is_some() { 15 } else { 255 })?.unwrap_or(0) as u8;
            let length = small(reading, 8, 65535)?.map(|length| length as u16);
            let header = Header {
                version,
                spare,
                follow_on,
                seid,
                sequence,
                priority,
                spare_last,
                length,
            };
            let body = reading.member(&read, 9, |value, reading| {
                Body::from_ies_tree(kind, value, reading)
            })?;
            Ok(Self { header, body })
        }
    }

    impl Message {
        /// The tree of the message.
        pub fn to_tree(&self) -> Value {
            Tree::to_tree(self)
        }

        /// The message that a tree writes.
        ///
        /// # Errors
        ///
        /// Where the tree is not a message, by the names on the way, and why.
        pub fn from_tree(value: &Value) -> Result<Message, tree::Error> {
            tree::from_value(value)
        }
    }
}
