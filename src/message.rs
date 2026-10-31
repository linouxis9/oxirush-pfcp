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

use alloc::string::String;
use alloc::vec::Vec;

use crate::Error;
use crate::check::{Deviation, DeviationKind};
use crate::header::Header;
use crate::octets::IntoOwned;
use crate::macros::pfcp_messages;

pfcp_messages! {
    1 HeartbeatRequest, 2 HeartbeatResponse, 3 PfdManagementRequest, 4 PfdManagementResponse,
    5 AssociationSetupRequest, 6 AssociationSetupResponse, 7 AssociationUpdateRequest,
    8 AssociationUpdateResponse, 9 AssociationReleaseRequest, 10 AssociationReleaseResponse,
    11 VersionNotSupportedResponse, 12 NodeReportRequest, 13 NodeReportResponse,
    14 SessionSetDeletionRequest, 15 SessionSetDeletionResponse, 16 SessionSetModificationRequest,
    17 SessionSetModificationResponse, 50 SessionEstablishmentRequest, 51 SessionEstablishmentResponse,
    52 SessionModificationRequest, 53 SessionModificationResponse, 54 SessionDeletionRequest,
    55 SessionDeletionResponse, 56 SessionReportRequest, 57 SessionReportResponse,
}

/// Whether a message type is one of a node related message (Table 7.3-1): from 1 to 49.
pub fn is_node_related(message_type: u8) -> bool {
    (1..50).contains(&message_type)
}

/// A PFCP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    /// Its header.
    pub header: Header,
    /// Its message type and its IEs.
    pub body: Body<'a>,
}

impl<'a> IntoOwned for Message<'a> {
    type Owned = Message<'static>;
    fn into_owned(self) -> Message<'static> {
        Message { header: self.header, body: self.body.into_owned() }
    }
}

impl<'a> Message<'a> {
    /// Decode one message, which `octets` are whole.
    ///
    /// # Errors
    ///
    /// Octets shorter than a header, a Message Length that is not the length of the
    /// octets (§7.6.3), and IEs whose framing runs past the message (§7.6.7). The error
    /// has the header, which the answer of a receiver takes.
    pub fn decode(octets: &'a [u8]) -> Result<Self, Error> {
        let (message, used) = Self::decode_first(octets)?;
        if used != octets.len() {
            let (header, message_type, length) = Header::decode(octets).ok_or(Error::TooShort { octets: octets.len() })?;
            return Err(Error::MessageLength { header, message_type, length, available: octets.len() - 4 });
        }
        Ok(message)
    }

    /// Decode each message of a datagram, which the FO flag of each chains (§7.2.1A).
    ///
    /// # Errors
    ///
    /// Those of [`decode`](Self::decode), for the first message that has one.
    pub fn decode_datagram(mut octets: &'a [u8]) -> Result<Vec<Self>, Error> {
        let mut messages = Vec::new();
        loop {
            let (message, used) = Self::decode_first(octets)?;
            let follows = message.header.follow_on;
            messages.push(message);
            octets = &octets[used..];
            if !follows || octets.is_empty() {
                break;
            }
        }
        Ok(messages)
    }

    fn decode_first(octets: &'a [u8]) -> Result<(Self, usize), Error> {
        let (header, message_type, length) = Header::decode(octets).ok_or(Error::TooShort { octets: octets.len() })?;
        let end = 4 + usize::from(length);
        let Some(content) = octets.get(header.len()..end).filter(|_| end >= header.len()) else {
            return Err(Error::MessageLength { header, message_type, length, available: octets.len() - 4 });
        };
        let body = Body::decode(message_type, content).map_err(|fault| Error::Ies { header, message_type, fault })?;
        Ok((Self { header, body }, end))
    }

    /// Encode the message.
    ///
    /// # Errors
    ///
    /// A value whose fields disagree with its flags, and an IE or a message longer than a
    /// Length can say.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        // The IEs after room for the header, which their length then completes.
        let header = self.header.len();
        let expected = self.body.encoded_len();
        let mut out = Vec::with_capacity(header + expected);
        out.resize(header, 0);
        self.body.encode(&mut out)?;
        let body = out.len() - header;
        debug_assert_eq!(body, expected, "the encoded length of the IEs is the one computed first");
        self.header
            .encode_into(self.body.message_type(), body, &mut out)
            .ok_or(Error::TooLong { ie_type: 0, length: body })?;
        Ok(out)
    }

    /// Each way in which the message is not as TS 29.244 has a sender construct it.
    pub fn check(&self) -> Vec<Deviation> {
        let mut found = Vec::new();
        let header = &self.header;
        let message_type = self.body.message_type();
        let node = is_node_related(message_type);
        let path = String::from("/header");
        if header.version != 1 {
            found.push(Deviation::new(&path, "7.2.2.4.1", DeviationKind::Rule("the version is not 1")));
        }
        if header.spare != 0 || (header.priority.is_none() && header.spare_last != 0) {
            found.push(Deviation::new(&path, "7.2.2.1", DeviationKind::SpareBits));
        }
        if node && header.seid.is_some() {
            found.push(Deviation::new(&path, "7.2.2.2", DeviationKind::Rule("a node related message has the S flag")));
        }
        if !node && header.seid.is_none() {
            found.push(Deviation::new(&path, "7.2.2.4.1", DeviationKind::Rule("a session related message has no SEID")));
        }
        if node && header.priority.is_some() {
            found.push(Deviation::new(&path, "7.2.2.2", DeviationKind::Rule("a node related message has the MP flag")));
        }
        if node && header.follow_on {
            found.push(Deviation::new(&path, "6.5", DeviationKind::Rule("a node related message is bundled")));
        }
        self.body.check("/pfcp", &mut found);
        found
    }
}

#[cfg(feature = "tree")]
mod forms {
    use oxirush_utils::tree::{self, Members, Reading, Refused, Tree, Value};

    use super::{Body, Message};
    use crate::header::Header;

    const NAMES: &[&str] = &[
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

    /// `{"message": NAME, "SEID": ..., "Sequence Number": ..., "ies": {...}}`, with the
    /// other members of the header where they are not what a sender writes.
    impl Tree for Message<'_> {
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
            members.put_optional("Message Priority", header.priority.map(|priority| tree::unsigned(priority.into())));
            if header.spare_last != 0 {
                members.put("Spare octet", tree::unsigned(header.spare_last.into()));
            }
            members.put_optional("Message Length", header.length.map(|length| tree::unsigned(length.into())));
            members.put("ies", self.body.ies_tree());
            members.finish()
        }

        fn from_tree(value: &Value, reading: &mut Reading) -> Result<Self, Refused> {
            let read = reading.members(value, NAMES)?;
            let kind = reading.member(&read, 0, |value, reading| match value.is_number() {
                true => Ok(Err(reading.unsigned(value, 0, 255)? as u8)),
                false => Ok(Ok(reading.named(value, &Body::names())?)),
            })?;
            let small = |reading: &mut Reading, at: usize, most: u64| {
                reading.optional(&read, at, |value, reading| reading.unsigned(value, 0, most))
            };
            let version = small(reading, 1, 7)?.unwrap_or(1) as u8;
            let spare = small(reading, 2, 3)?.unwrap_or(0) as u8;
            let follow_on = reading.optional(&read, 3, |value, reading| reading.boolean(value))?.unwrap_or(false);
            let seid = reading.optional(&read, 4, |value, reading| reading.unsigned(value, 0, u64::MAX))?;
            let sequence = reading.member(&read, 5, |value, reading| reading.unsigned(value, 0, 0xff_ffff))? as u32;
            let priority = small(reading, 6, 15)?.map(|priority| priority as u8);
            let spare_last = small(reading, 7, 255)?.unwrap_or(0) as u8;
            let length = small(reading, 8, 65535)?.map(|length| length as u16);
            let header = Header { version, spare, follow_on, seid, sequence, priority, spare_last, length };
            let body = reading.member(&read, 9, |value, reading| Body::from_ies_tree(kind, value, reading))?;
            Ok(Self { header, body })
        }
    }

    impl Message<'_> {
        /// The tree of the message.
        pub fn to_tree(&self) -> Value {
            Tree::to_tree(self)
        }

        /// The message that a tree writes.
        ///
        /// # Errors
        ///
        /// Where the tree is not a message, by the names on the way, and why.
        pub fn from_tree(value: &Value) -> Result<Message<'static>, tree::Error> {
            tree::from_value(value)
        }
    }
}
