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

//! The paths of the tree of a message, which [`select`] reads and [`set`] edits.
//!
//! The tree uses the engine of oxirush-utils ([`tree`](mod@crate::tree)). A message, and
//! each grouped IE, is an object whose members are its IEs, named and ordered as in its
//! table. A row that repeats is a list, in the order of the wire. As in a JSON pointer, a
//! `/` inside a name is written `~1`: `/pfcp/APN~1DNN`. An IE that the crate keeps as
//! octets is `{"octets": ...}`, under the name of its row, of its type, or its number.
//!
//! A tree lists the IEs in the order of the tables, whatever order they arrived in
//! (§8.1.2 lets a receiver take them in any order), and a message encoded from a tree has
//! them in that order. A decoded message keeps the order of the wire: decoding and
//! encoding it again gives the same octets.
//!
//! Names in a path match in any case. A number selects an entry of a list, and `*` every
//! entry. `/pfcp` is the list of IEs of the message; the path of each deviation of
//! `check()` starts there. An IE without a row in its table, from a vendor or a later
//! release, goes by its number or the name of its type. A path into an IE that the
//! message does not have selects nothing; a misspelt name is an error only where the
//! value exists. [`set`] creates the grouped IEs and the lists on the way, adds an entry
//! at the position equal to the length of a list, and writes a missing value whole.

use alloc::string::String;
use alloc::vec::Vec;

use oxirush_utils::tree::{self, Members, Reading, Refused, Takes, Value};

use crate::Pfcp;
use crate::ie::RawIe;
use crate::message::{MESSAGE_TYPES, MessageTypeInfo};
use crate::registry::{IE_TYPES, IeTypeInfo};
use crate::table::{Row, Table};

pub(crate) use oxirush_utils::tables::{
    TreeScope, field_tree, read_field, scope_from_tree, scope_to_tree,
};

/// The rules of the paths of PFCP, which `select` and `set` share: `/pfcp` is short for
/// the IEs of the message, and each segment is checked against the tables and the members
/// of the trees of the values ([`IeTypeInfo::members`]), then the tree is walked by the
/// plain rule.
#[allow(non_upper_case_globals)]
#[cfg(test)]
const Paths: oxirush_utils::tables::Paths<Pfcp> = oxirush_utils::tables::Paths::new();

/// What the paths know of a place of the tree of a message.
#[cfg(test)]
type Of = oxirush_utils::tables::Of<Pfcp>;

/// The octets form of a raw IE.
fn raw_tree(ie: &RawIe) -> Value {
    let mut members = Members::new();
    members.put("octets", tree::octets(&ie.octets));
    members.put_optional(
        "length",
        ie.length.map(|length| tree::unsigned(length.into())),
    );
    members.put_optional(
        "Enterprise ID",
        ie.enterprise_id.map(|id| tree::unsigned(id.into())),
    );
    members.finish()
}

fn read_raw(ie_type: u16, value: &Value, reading: &mut Reading) -> Result<RawIe, Refused> {
    let read = reading.members(value, &["octets", "length", "Enterprise ID"])?;
    let octets = reading.member(&read, "octets", |value, reading| reading.octets(value))?;
    let length = reading.optional(&read, "length", |value, reading| {
        reading.unsigned(value, 0, 65535)
    })?;
    let enterprise = reading.optional(&read, "Enterprise ID", |value, reading| {
        reading.unsigned(value, 0, 65535)
    })?;
    Ok(RawIe {
        ie_type,
        enterprise_id: enterprise.map(|id| id as u16),
        length: length.map(|length| length as u16),
        octets: octets.into(),
    })
}

/// What an IE that a scope keeps as its octets takes, and each entry of a list of them.
const KEPT: Takes = Takes::Members(
    None,
    &[
        ("octets", &Takes::Octets(None)),
        ("length", &Takes::Number(u16::MAX as u64)),
        ("Enterprise ID", &Takes::Number(u16::MAX as u64)),
    ],
);

/// The trees and the paths of PFCP: `/pfcp` for the IEs of a message, an IE kept as
/// octets with its `length` and its `Enterprise ID`.
impl oxirush_utils::tables::TreeProtocol for Pfcp {
    const ROOT: &'static str = "pfcp";
    const MESSAGE_MEMBERS: &'static [&'static str] = crate::message::forms::NAMES;
    const HEADER_MEMBERS: &'static [&'static str] = crate::message::forms::HEADER;
    const KEPT: &'static Takes = &KEPT;

    fn ie_types() -> &'static [IeTypeInfo] {
        IE_TYPES
    }

    fn message_types() -> &'static [MessageTypeInfo] {
        MESSAGE_TYPES
    }

    fn ie_type(key: u16) -> u16 {
        key
    }

    fn key_of(ie_type: u16) -> u16 {
        ie_type
    }

    fn holds_secret(ie_type: u16) -> bool {
        crate::ie::holds_secret(ie_type)
    }

    fn tree_name(key: u16, table: Option<&Table>) -> String {
        crate::tree_name(key, table)
    }

    fn raw_tree(ie: &RawIe) -> Value {
        raw_tree(ie)
    }

    fn read_raw(ie_type: u16, value: &Value, reading: &mut Reading) -> Result<RawIe, Refused> {
        read_raw(ie_type, value, reading)
    }
}

/// The error of `from_value` of a message in `tree`, at the path of the place that it
/// refuses, which [`select`] takes, and `/pfcp` for the IEs of the message.
pub(crate) fn located(tree: &Value, error: tree::Error) -> tree::Error {
    oxirush_utils::tables::located::<Pfcp>(tree, error)
}

/// The values at `path` in the tree of a message. A row of a table that a message or a
/// grouped IE lacks, an IE of no row by its number or the name of its type, as
/// [`Message::from_tree`](crate::Message::from_tree) reads it, and a member that a value
/// or the header lacks of those that its tree may have, select nothing; a name that is
/// none of them is an error. Below what is not there, and below an entry past the end of
/// a list, nothing is selected, whatever the path names: a misspelt name there is not
/// told. A value or a field whose tree is a scalar or an object takes the same names in
/// either form.
///
/// # Errors
///
/// Those of `oxirush_utils::tree::select_in`: `NoSuchMember` for a name that the value at
/// its place does not have and that its table or the members of its tree do not name
/// either.
pub fn select<'v>(tree: &'v Value, path: &str) -> Result<Vec<&'v Value>, tree::Error> {
    oxirush_utils::tables::select::<Pfcp>(tree, path)
}

/// The row of a table and the IE type of the IE at `path` in the tree of a message, or of
/// the list of them that a row is: the row that the tables of the message name at the
/// path, which the message may lack, as may the grouped IEs above it. `None` for a path of
/// the header, of a member of a value, or of an IE of no row.
///
/// ```
/// use oxirush_pfcp::{paths, tree};
///
/// let tree = tree!({"message": "PFCP Heartbeat Request", "header": {"Sequence Number": 1}, "ies": {"Recovery Time Stamp": 7}});
/// let (row, info) = paths::row_at(&tree, "/pfcp/Source IP Address")?.unwrap();
/// assert_eq!((row.name, info.ie_type), ("Source IP Address", 192));
/// assert!(paths::row_at(&tree, "/header/Sequence Number")?.is_none());
/// # Ok::<(), tree::Error>(())
/// ```
///
/// # Errors
///
/// Those of [`select`].
pub fn row_at(
    tree: &Value,
    path: &str,
) -> Result<Option<(&'static Row, &'static IeTypeInfo)>, tree::Error> {
    oxirush_utils::tables::row_at::<Pfcp>(tree, path)
}

/// Give the place at `path` the value `value`: a path that [`select`] takes, with the rows
/// of grouped IEs and the lists that it lacks on the way added, an entry of a list at the
/// position of its length too. A member of the object of a value or a field that the tree
/// writes as a scalar writes the object, with the scalar as its member if it is one:
/// `{"value": "minute", "Spare": 8}` from `"minute"`. The tree is left as it was when the
/// edit fails.
///
/// A value that a message lacks is written whole: a path below it is refused
/// (`set(&mut tree, ".../Maximum Bitrate", tree!({"UL MBR": 5, "DL MBR": 6}))`). `set`
/// checks the names of the path, and not the value, which
/// [`Message::from_tree`](crate::Message::from_tree) reads.
///
/// # Errors
///
/// Those of `oxirush_utils::tree::set_in`: `NoSuchMember` for a name that [`select`]
/// refuses, the last of the path too, and `NothingSelected` for a path below what the tree
/// does not have.
pub fn set(tree: &mut Value, path: &str, value: impl Into<Value>) -> Result<(), tree::Error> {
    oxirush_utils::tables::set::<Pfcp>(tree, path, value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HeartbeatRequest, Message, RecoveryTimeStamp};
    use oxirush_utils::tree::Family;

    /// What the paths know of a place prints the names of the message, of the tables and
    /// of the IE types, not their rows.
    #[test]
    fn a_shape_prints_its_names() {
        let heartbeat = Message::node(1, HeartbeatRequest::new(RecoveryTimeStamp::new(7)));
        let heartbeat = heartbeat.to_tree();
        let message = Paths.start(&heartbeat, true);
        assert_eq!(
            alloc::format!("{message:?}"),
            r#"Message("PFCP Heartbeat Request")"#
        );
        let ies = Paths.member(&message, "ies", Some(&heartbeat["ies"]));
        assert_eq!(alloc::format!("{ies:?}"), r#"Ies("7.4.2.1-1")"#);
        // The header is no table of IEs: its fields are scalars
        let header = Paths.member(&message, "header", Some(&heartbeat["header"]));
        assert_eq!(alloc::format!("{header:?}"), "Header");
        let sequence = Paths.member(&header, "Sequence Number", None);
        assert_eq!(
            alloc::format!("{sequence:?}"),
            "Takes(Number(18446744073709551615))"
        );
        let nothing = Paths.member(&header, "Bogus", None);
        assert_eq!(alloc::format!("{nothing:?}"), "Nothing");
        let stamp = &heartbeat["ies"]["Recovery Time Stamp"];
        let value = Paths.member(&ies, "Recovery Time Stamp", Some(stamp));
        assert_eq!(
            alloc::format!("{value:?}"),
            r#"Value("Recovery Time Stamp")"#
        );
        let empty = Value::Array(Vec::new());
        let addresses = Paths.member(&ies, "Source IP Address", Some(&empty));
        assert_eq!(
            alloc::format!("{addresses:?}"),
            r#"List("Source IP Address")"#
        );
        let nothing = Paths.member(&value, "Bogus", None);
        assert_eq!(alloc::format!("{nothing:?}"), "Nothing");
        // The name of a message is a scalar, and no header
        let name = Paths.member(&message, "message", Some(&heartbeat["message"]));
        assert_eq!(alloc::format!("{name:?}"), "Takes(Text)");
        // A member of the IEs that is no row is an IE kept as octets, or nothing yet
        let kept = Paths.member(&ies, "Bogus", None);
        assert_eq!(
            alloc::format!("{kept:?}"),
            alloc::format!("{:?}", Of::Takes(&KEPT))
        );
        // An entry of a list of IEs is of the IE of the row, and one of a list of a field
        // of the kind of the field
        let entry = Paths.entry(&addresses, None);
        assert_eq!(alloc::format!("{entry:?}"), r#"Value("Source IP Address")"#);
        let entry = Paths.entry(&Of::Takes(&Takes::List(&Takes::Ipv4)), None);
        assert_eq!(alloc::format!("{entry:?}"), "Takes(Ipv4)");
        let entry = Paths.entry(&Of::Nothing, None);
        assert_eq!(alloc::format!("{entry:?}"), "Nothing");
    }
}
