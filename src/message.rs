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
use crate::known::Known;
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

/// The name of the message, its SEID and its sequence number:
///
/// ```
/// # use oxirush_pfcp::*;
/// let deletion = Message {
///     header: Header::session(0x1001, 7),
///     body: SessionDeletionRequest::default().into(),
/// };
/// assert_eq!(deletion.to_string(), "PFCP Session Deletion Request (SEID 0x1001, sequence 7)");
/// ```
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
    /// A node related message of `body` and `sequence`: a node sends a request of its
    /// own with a number of its own.
    pub fn node(sequence: u32, body: impl Into<Body>) -> Self {
        Self {
            header: Header::node(sequence),
            body: body.into(),
        }
    }

    /// A session related message of `body` and `sequence`, to the peer's SEID `seid`.
    pub fn session(seid: u64, sequence: u32, body: impl Into<Body>) -> Self {
        Self {
            header: Header::session(seid, sequence),
            body: body.into(),
        }
    }

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
        // A Message Length shorter than the header is a range that ends before it starts.
        let Some(content) = octets.get(header.encoded_len()..end) else {
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

    /// Encodes the message.
    ///
    /// `encode()` is permissive on purpose, so that a test tool can send malformed
    /// messages. It writes spare bits, reserved values, IEs that the table of the message
    /// does not have, and a false IE Length ([`RawIe::length`](crate::RawIe::length)) or
    /// Message Length ([`Header::length`]) as they are. [`check`](Self::check) reports
    /// each of them.
    ///
    /// # Errors
    ///
    /// `encode()` only refuses a value that it cannot write so that it decodes back to
    /// the same value:
    ///
    /// - [`Error::Inconsistent`]: a field that disagrees with the flags or the other
    ///   fields of its IE. A field is present without its flag, or missing with it; a
    ///   field is missing before a later field or before unknown octets, which a decoder
    ///   would read as the missing field; unknown octets follow a field that runs to the
    ///   end of the IE; or the length of a field differs from the length that its flags
    ///   give.
    /// - [`Error::FieldLength`] and [`Error::HeaderField`]: a value that does not fit in
    ///   the bits or in the length field of its IE field or header field.
    /// - [`Error::TooLong`] and [`Error::MessageTooLong`]: an IE or a message that is
    ///   longer than its 16-bit Length can express.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        self.encode_into(&mut out)?;
        Ok(out)
    }

    /// Appends the message to `out`, as [`encode`](Self::encode) writes it, with one
    /// reservation of its length: a buffer that is cleared and used again for each message
    /// allocates nothing once it is long enough. After an error, `out` is as it was.
    ///
    /// ```
    /// use oxirush_pfcp::*;
    ///
    /// // One buffer for the Heartbeat Requests of a node
    /// let mut buffer = Vec::with_capacity(1500);
    /// for sequence in [1, 2] {
    ///     buffer.clear();
    ///     let request = HeartbeatRequest::new(RecoveryTimeStamp::new(7));
    ///     Message::node(sequence, request).encode_into(&mut buffer)?;
    ///     assert_eq!(buffer[..4], [0x20, 1, 0, 12]);
    /// }
    /// # Ok::<(), Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Those of [`encode`](Self::encode).
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        // The IEs after room for the header, which their length then completes.
        let start = out.len();
        let header = self.header.encoded_len();
        let expected = self.body.encoded_len();
        out.reserve(header + expected);
        out.resize(start + header, 0);
        let written = self.body.encode(out).and_then(|()| {
            let body = out.len() - start - header;
            debug_assert_eq!(
                body, expected,
                "the encoded length of the IEs is the one computed first"
            );
            self.header
                .encode_into(self.body.message_type(), body, &mut out[start..])
        });
        if written.is_err() {
            out.truncate(start);
        }
        written
    }

    /// Validates the message against TS 29.244 V19.6.0 on `interface` and returns every
    /// deviation that it finds. Each [`Deviation`] has the path of the IE in the tree of
    /// the message, the clause that is broken, the kind of deviation and, when the
    /// specification defines one, the Cause that the receiver answers with.
    ///
    /// `interface` selects the "Appl." columns of the tables. It can be a set, such as
    /// [`Interfaces::SXA_SXB`] for a combined SGW/PGW (§5.2.6): the message may then carry
    /// the IEs of any interface of the set and must carry the mandatory IEs of each.
    ///
    /// The message is checked as its receiver reads it. An IE that is stored as raw
    /// octets is checked as the value of its row, so `check()` returns the same result
    /// before and after `Message::decode(m.encode())`. An IE whose Length prevents
    /// decoding is reported, and the rest of the message is still checked.
    ///
    /// [`check_with`](Self::check_with) also validates the message against context that
    /// one message does not carry.
    ///
    /// # What is checked
    ///
    /// - **Header** (§7.2.2): the version, the SEID for the message type, a SEID of 0
    ///   where the sender must know the SEID of its peer, the spare bits and the Message
    ///   Length.
    /// - **Framing** (§7.6): the Length of every IE, the fixed lengths of Table 8.1.2-1,
    ///   and IEs that do not decode.
    /// - **IE tables of clause 7**, for the message and for every grouped IE: missing
    ///   mandatory IEs, IEs that the table or the interface does not have, IEs that are
    ///   repeated more often than the table allows, IEs that a rejection must not carry
    ///   (§7.2.3.2), and IE types and message types that Release 19 does not define. A
    ///   missing mandatory IE inside a conditional grouped IE gets the Cause "Conditional
    ///   IE missing" (§7.2.3.2).
    /// - **Conditions of clause 7 that the message itself decides**, on 122 rows
    ///   ([`Row::checked`](crate::Row::checked)): an IE that "shall be present if"
    ///   another IE, a flag or a Cause is present; an IE that "may be present if" another
    ///   IE is present, when it is there without it; a flags IE that is "included if at
    ///   least one of the flags is set", when no flag is set; and conditions on an IE of
    ///   the enclosing scope, such as the Additional Monitoring Time of a URR by its
    ///   Measurement Method, the Weight and Priority of a MAR by its Steering Mode, or
    ///   the QFI of a PDI by the QFIs of its Traffic Endpoint.
    /// - **Rule IDs within the message**: a rule that is created, updated or removed more
    ///   than once (§5.2.1, §6.3.3.2).
    /// - **Values of clause 8.2**: flags and fields that must or must not be set
    ///   together, reserved and spare values, spare bits, value ranges, the values of
    ///   enumerations, and restrictions that depend on where the IE is (a bit that only
    ///   the CP function sets, a bit that is only valid in a PDI).
    /// - **Formats that another document defines**: UTF-8 text, the base64 of a Metadata,
    ///   a version 4 UUID, HTTP header field names and values, FQDN labels, the Operator
    ///   Identifier of an APN/DNN, the decimal digits of an IMSI, IMEI or MSISDN, a Flow
    ///   Description as an IPFilterRule (TS 29.212), and the Redirect Server Address for
    ///   its type (IPv4, IPv6, URL, SIP URI).
    ///
    /// # What is not checked
    ///
    /// A message without deviations is not proven conformant. `check()` does not cover:
    ///
    /// - **Session state**, which [`check_with`](Self::check_with) validates with
    ///   [`SessionRules`](crate::SessionRules). Even then, the order of UR-SEQN values is
    ///   not checked, because usage reports can arrive out of order.
    /// - **What only the sender knows.** Conditions on intent or on other interfaces: "if
    ///   the SMF wants to", "if the UE supports", the IMSI that the SMF received in a
    ///   SUPI, how a bidirectional SDF filter was written. Requirements written with
    ///   "should" are not checked either.
    /// - **A SEID of 0** in a header where the sender might not know the SEID of its peer
    ///   yet (§7.2.2.4.2). It is reported only in a Session Modification or Deletion
    ///   Request and in a response that accepts the request.
    /// - **Opaque content**: the JSON of a DNS Query/Response Filter (TS 29.571), the
    ///   content of containers such as a Port Management Information Container, and names
    ///   that are configured in the UP function (Network Instance, Forwarding Policy,
    ///   predefined rules).
    /// - **Later releases.** An IE type or message type that V19.6.0 does not define is
    ///   reported as unknown and its content is not validated. Trailing octets after the
    ///   known fields of a value are accepted.
    /// - **The procedures of clause 6** (retransmission, heartbeats, association and
    ///   session handling): these are the job of a `Node` (feature `node`).
    pub fn check(&self, interface: Interfaces) -> Vec<Deviation> {
        self.check_with(interface, &Known::default())
    }

    /// Like [`check`](Self::check), and also validates the message against the context
    /// in `known`. Each part of [`Known`] that is `None` is skipped.
    ///
    /// - **The request**, when the message is a response. Reports a response whose
    ///   message type or Sequence Number does not match the request (Table 7.3-1, §6.4),
    ///   and a Session Establishment Response whose SEID is not the SEID of the CP F-SEID
    ///   of the request (§7.2.2.4.1). When the response accepts the request, it also
    ///   reports a missing Created PDR, Created Traffic Endpoint, Created/Updated Traffic
    ///   Endpoint or Updated PDR for each rule that asked the UP function to allocate an
    ///   F-TEID or a UE IP address (CH, CHV4, CHV6), a missing allocation inside it, and
    ///   a missing or incomplete Created Bridge/Router Info (Tables 7.5.3.1-1, 7.5.3.6-1
    ///   and 7.5.5.1-1, §8.2.141).
    /// - **The state of the session**, as a [`SessionRules`](crate::SessionRules) records
    ///   it. Reports a rule that a request updates or removes but the session does not
    ///   have, a rule that it creates but the session already has (§5.2.1), an ID that
    ///   refers to no rule of the session or of the message (the FAR, URR, QER and MAR
    ///   IDs of a PDR, the BAR ID of a FAR, the Linked URR ID and FAR ID for Quota Action
    ///   of a URR, the FAR IDs of a MAR, the Traffic Endpoint IDs of a PDI), an SDF Filter
    ///   ID that another PDR of the session uses (§8.2.5), a QFI in a PDI whose traffic
    ///   endpoint has QFIs (Table 7.5.2.2-2), an NW-TT Port Number above 16 bits in a
    ///   bridge (§8.2.142), and a usage report for no URR of the session. Predefined
    ///   rules (§8.2.54, §8.2.74, §8.2.75) are configured in the UP function and are not
    ///   reported.
    /// - **Announced features.** Reports an IE that requires a feature which the UP or CP
    ///   function did not announce: for example a Number of Reports in a Create URR when
    ///   the UP function did not announce NORP. This covers 35 rows of clause 7. The
    ///   deviation is [`DeviationKind::Excluded`], or [`DeviationKind::Repeated`] when the
    ///   feature is only needed for more than one instance of the IE, and its clause is
    ///   the table of the row.
    ///
    /// ```
    /// use oxirush_pfcp::{Interfaces, Known, Message, UpFunctionFeatures};
    ///
    /// # fn main() -> Result<(), oxirush_pfcp::Error> {
    /// // A Session Report Response: Cause, then an Update BAR with a BAR ID and a
    /// // DL Buffering Duration (Table 7.5.9.2-1).
    /// let octets = [
    ///     0x21, 57, 0, 31, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, // header
    ///     0, 19, 0, 1, 1, // Cause
    ///     0, 12, 0, 10, 0, 88, 0, 1, 1, 0, 47, 0, 1, 2, // Update BAR
    /// ];
    /// let response = Message::decode(&octets)?;
    /// assert!(response.check(Interfaces::N4).is_empty());
    ///
    /// // The UP function announced its features, and DLBD is not one of them.
    /// let features = UpFunctionFeatures::default();
    /// let known = Known::default().with_up_features(&features);
    /// let found = response.check_with(Interfaces::N4, &known);
    /// assert_eq!(found[0].path, "/pfcp/Update BAR/DL Buffering Duration");
    /// assert_eq!(found[0].clause, "7.5.9.2-1");
    /// # Ok(())
    /// # }
    /// ```
    pub fn check_with(&self, interface: Interfaces, known: &Known<'_>) -> Vec<Deviation> {
        let message_type = self.body.message_type();
        let mut found = Vec::new();
        let context = Context {
            request: is_request(message_type) && message_type != 1,
            ..Context::on(interface)
        };
        let read = self.body.as_read(context, &mut found).map(|body| Self {
            header: self.header,
            body,
        });
        found.extend(read.as_ref().unwrap_or(self).check_read(interface, known));
        // The request and the session are compared with the IEs that the message decodes,
        // so that each deviation is at a path of its tree.
        if let Some(request) = known.request {
            crate::known::against(self, request, interface, &mut found);
        }
        if let Some(session) = known.session {
            crate::session::check(self, session, known.request, &mut found);
        }
        found
    }

    /// The check of a message as it is.
    fn check_read(&self, interface: Interfaces, known: &Known<'_>) -> Vec<Deviation> {
        let message_type = self.body.message_type();
        let rejection = self.body.cause().filter(|cause| cause.rejects());
        let context = Context {
            interface,
            view: Presence::Mandatory,
            request: is_request(message_type) && message_type != 1,
            rejected: rejection,
            lacking: crate::known::lacking(&self.body, known),
        };
        let mut found = self.header_deviations(interface, context);
        // "This flag shall be set to "1" by the UP function, if the "Overload Control
        // Information" is included in the PFCP Session Establishment Response and the Cause
        // IE is set to a rejection cause value" (§8.2.76): AOCI, which the value of the IE
        // does not show alone.
        if let Body::SessionEstablishmentResponse(response) = &self.body
            && rejection.is_some()
            && self.body.takes(54, interface)
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
        for (rule, id) in self.body.rules_changed_twice(interface) {
            found.push(Deviation::new(
                "/pfcp",
                clause,
                DeviationKind::RuleChangedTwice { rule, id },
            ));
        }
        found
    }

    /// The deviations of the header (§7.2.2), and of the SEID, which the message type and
    /// the Cause decide (§7.2.2.4.2), each a rule of a table: whether it is broken, where,
    /// the clause and what.
    fn header_deviations(&self, interface: Interfaces, context: Context) -> Vec<Deviation> {
        use DeviationKind::Rule;
        let header = &self.header;
        let message_type = self.body.message_type();
        let known = !matches!(self.body, Body::Other { .. });
        let node = known && is_node_related(message_type);
        let session = known && !node;
        let seid = header.seid;
        let cause = self.body.cause();
        // SEID 0: an establishment, a report to another SMF, or an answer to a session
        // that the node does not have, which has it, or to a request that it rejects
        // (§7.2.2.4.2).
        let seid_zero_known = seid == Some(0) && matches!(message_type, 52 | 54)
            || seid == Some(0) && cause.is_some_and(|cause| cause.accepts());
        // A Session Report Request of SEID 0 moves the session to another SMF of the set
        // and carries the Old CP F-SEID of the previous one; one of a known SEID has none
        // (§7.2.2.4.2 bullet 4, §5.22.2 bullet 4, Table 7.5.8.1-1).
        let old = match &self.body {
            Body::SessionReportRequest(request) => {
                Some(request.old_cp_f_seid.is_some() && self.body.takes(57, interface))
            }
            _ => None,
        };
        // A field of more than its bits, at its member of the tree of the message.
        let wide = header.overflow().map(|(field, _)| match field {
            "Version" => ("/header/Version", "a version of more than 3 bits"),
            "Spare" => ("/header/Spare", "spare bits of octet 1 of more than 2 bits"),
            "Sequence Number" => (
                "/header/Sequence Number",
                "a sequence number of more than 24 bits",
            ),
            "Message Priority" => (
                "/header/Message Priority",
                "a message priority of more than 4 bits",
            ),
            _ => (
                "/header/Spare octet",
                "spare bits of the last octet of more than its bits",
            ),
        });
        let (wide_field, too_wide) = wide.unwrap_or_default();
        let establishment = message_type == 50 && !interface.has(Interfaces::N4MB);
        // Whether each rule is broken, at which field of the header or IE, its clause and
        // what it is. An establishment has SEID 0, the peer's SEID being not known yet, but
        // on N4mb. The last octet is spare, or its bits after the priority are (§7.2.2.3).
        #[rustfmt::skip]
        let rules = [
            (header.version != 1, "/header/Version", "7.2.2.4.1", Rule("the version is not 1")),
            (wide.is_some(), wide_field, "7.2.2.1", Rule(too_wide)),
            (header.spare != 0, "/header/Spare", "7.2.2.1", DeviationKind::SpareBits),
            (header.spare_last != 0, "/header/Spare octet", "7.2.2.1", DeviationKind::SpareBits),
            (node && seid.is_some(), "/header/SEID", "7.2.2.2", Rule("a node related message has the S flag")),
            (session && seid.is_none(), "/header/SEID", "7.2.2.4.1", Rule("a session related message has no SEID")),
            (node && header.priority.is_some(), "/header/Message Priority", "7.2.2.2", Rule("a node related message has the MP flag")),
            (node && header.follow_on, "/header/FO", "6.5", Rule("a node related message is bundled")),
            (establishment && seid.is_some_and(|seid| seid != 0), "/header/SEID", "7.2.2.4.2",
                Rule("a Session Establishment Request of a SEID other than 0")),
            (seid_zero_known, "/header/SEID", "7.2.2.4.2", Rule("SEID 0 where the peer's SEID is known")),
            (seid.is_some_and(|seid| seid != 0) && cause == Some(CauseValue::SessionContextNotFound), "/header/SEID", "7.2.2.4.2",
                Rule("a response of the Cause Session context not found of a SEID other than 0")),
            (seid == Some(0) && old == Some(false), "/pfcp/Old CP F-SEID", "7.2.2.4.2",
                Rule("a Session Report Request of SEID 0 without the Old CP F-SEID")),
            (seid.is_some_and(|seid| seid != 0) && old == Some(true), "/pfcp/Old CP F-SEID", "7.2.2.4.2",
                Rule("a Session Report Request of a SEID other than 0 with the Old CP F-SEID")),
        ];
        let broken = rules.into_iter().filter(|(broken, ..)| *broken);
        let mut found: Vec<Deviation> = broken
            .map(|(_, path, clause, kind)| Deviation::new(path, clause, kind))
            .collect();
        // A Message Length that is not the length of the octets after the first four: the
        // receiver of a request answers "Invalid Length" (§7.6.3).
        let after = header.encoded_len() - 4 + self.body.encoded_len();
        if header
            .length
            .is_some_and(|length| usize::from(length) != after)
        {
            let rule = Rule("a Message Length other than the octets after the first four");
            let mut deviation = Deviation::new("/header/Message Length", "7.6.3", rule);
            deviation.cause = context.invalid_length();
            found.push(deviation);
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
        let whole = header.follow_on && end < octets.len() && end >= header.encoded_len();
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

/// Whether a message type is a request of Table 7.3-1: 1 to 9 odd, 12 to 16 even, and 50 to
/// 56 even; 11, the Version Not Supported Response, is none. A type that the table does not
/// have is none either.
pub fn is_request(message_type: u8) -> bool {
    matches!(
        message_type,
        1 | 3 | 5 | 7 | 9 | 12 | 14 | 16 | 50 | 52 | 54 | 56
    )
}

impl Body {
    /// Whether its receiver on `interface` takes the IEs of the row of `ie_type`: it
    /// discards those of a row that is not on the interface, and nothing that they hold is
    /// told (§7.6.9).
    fn takes(&self, ie_type: u16, interface: Interfaces) -> bool {
        let row = self.table().and_then(|table| table.row_of(ie_type));
        row.is_some_and(|row| row.on(interface).is_some())
    }

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
    fn rules_changed_twice(&self, interface: Interfaces) -> Vec<(&'static str, u32)> {
        let mut twice = Vec::new();
        let mut ids = Ids::default();
        // The IDs of the rules of a type, of each of the lists of the message that change
        // them on the interface, and those that are there twice.
        macro_rules! rules {
            ($body:ident: $($rule:literal [$($list:ident: $of:ident),+] $id:ident),+ $(,)?) => {{$(
                $(
                    let taken = self.takes(<$of as crate::ie::IeType>::IE_TYPE, interface);
                    for rule in $body.$list.iter().filter(|_| taken) {
                        if let Some(id) = rule.$id.as_ref() {
                            ids.push(id.value.into());
                        }
                    }
                )+
                twice.extend(ids.repeated().into_iter().map(|id| ($rule, id)));
                ids.clear();
            )+}};
        }
        use crate::registry::*;
        match self {
            Self::SessionEstablishmentRequest(body) => rules!(body:
                "PDR" [create_pdr: CreatePdr] pdr_id,
                "FAR" [create_far: CreateFar] far_id,
                "URR" [create_urr: CreateUrr] urr_id,
                "QER" [create_qer: CreateQer] qer_id,
                "MAR" [create_mar: CreateMar] mar_id,
                "SRR" [create_srr: CreateSrr] srr_id,
            ),
            Self::SessionModificationRequest(body) => rules!(body:
                "PDR" [create_pdr: CreatePdr, update_pdr: UpdatePdr, remove_pdr: RemovePdr] pdr_id,
                "FAR" [create_far: CreateFar, update_far: UpdateFar, remove_far: RemoveFar] far_id,
                "URR" [create_urr: CreateUrr, update_urr: UpdateUrr, remove_urr: RemoveUrr] urr_id,
                "QER" [create_qer: CreateQer, update_qer: UpdateQer, remove_qer: RemoveQer] qer_id,
                "BAR" [create_bar: CreateBar, update_bar: UpdateBar, remove_bar: RemoveBar] bar_id,
                "MAR" [create_mar: CreateMar, update_mar: UpdateMar, remove_mar: RemoveMar] mar_id,
                "SRR" [create_srr: CreateSrr, update_srr: UpdateSrr, remove_srr: RemoveSrr] srr_id,
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
    pub(crate) const NAMES: &[&str] = &["message", "header", "ies"];

    /// The members that the header of the tree of a message may have: the fields of the
    /// header (§7.2.2), and the Message Length to write in place of the message's.
    pub(crate) const HEADER: &[&str] = &[
        "Version",
        "Spare",
        "FO",
        "SEID",
        "Sequence Number",
        "Message Priority",
        "Spare octet",
        "Message Length",
    ];

    /// `{"message": NAME, "header": {"SEID": ..., "Sequence Number": ...}, "ies": {...}}`,
    /// with the other fields of the header where they are not what a sender writes.
    impl Tree for Message {
        const NAME: &'static str = "PFCP message";

        fn to_tree(&self) -> Value {
            let mut members = Members::new();
            members.put(
                "message",
                match self.body.name() {
                    Some(name) => tree::text(name),
                    None => tree::unsigned(self.body.message_type().into()),
                },
            );
            members.put("header", header_tree(&self.header));
            members.put("ies", self.body.ies_tree());
            members.finish()
        }

        fn from_tree(value: &Value, reading: &mut Reading) -> Result<Self, Refused> {
            let read = reading.members(value, NAMES)?;
            // A message of Table 7.3-1 by its name, and one of no table by its number.
            let kind =
                reading.member(&read, "message", |value, reading| match value.is_number() {
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
            let header = reading.member(&read, "header", read_header)?;
            let body = reading.member(&read, "ies", |value, reading| {
                Body::from_ies_tree(kind, value, reading)
            })?;
            Ok(Self { header, body })
        }
    }

    /// The tree of a header: the SEID that it has and its sequence number, and its other
    /// fields where they are not what a sender writes.
    fn header_tree(header: &Header) -> Value {
        let mut members = Members::new();
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
        members.finish()
    }

    /// The header that the tree of a header writes: its sequence number, and each other
    /// field that it does not write as a sender writes it.
    fn read_header(value: &Value, reading: &mut Reading) -> Result<Header, Refused> {
        let read = reading.members(value, HEADER)?;
        let small = |reading: &mut Reading, name: &'static str, most: u64| {
            reading.optional(&read, name, |value, reading| {
                reading.unsigned(value, 0, most)
            })
        };
        let version = small(reading, "Version", 7)?.unwrap_or(1) as u8;
        let spare = small(reading, "Spare", 3)?.unwrap_or(0) as u8;
        let follow_on = reading
            .optional(&read, "FO", |value, reading| reading.boolean(value))?
            .unwrap_or(false);
        let seid = reading.optional(&read, "SEID", |value, reading| {
            reading.unsigned(value, 0, u64::MAX)
        })?;
        let sequence = reading.member(&read, "Sequence Number", |value, reading| {
            reading.unsigned(value, 0, 0xff_ffff)
        })? as u32;
        let priority = small(reading, "Message Priority", 15)?.map(|priority| priority as u8);
        let spare_last = small(
            reading,
            "Spare octet",
            if priority.is_some() { 15 } else { 255 },
        )?
        .unwrap_or(0) as u8;
        let length = small(reading, "Message Length", 65535)?.map(|length| length as u16);
        Ok(Header {
            version,
            spare,
            follow_on,
            seid,
            sequence,
            priority,
            spare_last,
            length,
        })
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
        /// Where the tree is not a message, at the path of the place that it refuses,
        /// which [`paths::select`](crate::paths::select) takes, and why.
        pub fn from_tree(value: &Value) -> Result<Message, tree::Error> {
            tree::from_value(value).map_err(|error| {
                let said = alloc::format!("this is not a value of {}: ", <Self as Tree>::NAME);
                let why = error
                    .reason()
                    .strip_prefix(&said[..])
                    .unwrap_or(error.reason());
                let error = tree::Error::new(error.kind(), error.at(), why);
                crate::paths::located(value, error)
            })
        }
    }
}
