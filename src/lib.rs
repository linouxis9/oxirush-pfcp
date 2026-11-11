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

//! PFCP, the protocol between the control plane and the user plane of 3GPP (TS 29.244
//! V19.6.0, Release 19): N4 between an SMF and a UPF, N4mb, and Sxa, Sxb and Sxc in EPC.
//!
//! - [`Message`] decodes and encodes a message, byte for byte. Its [`Body`] has a struct
//!   for each message type of Table 7.3-1, with a field for each row of its table; each
//!   IE has its type, with the fields of its figure in clause 8.2.
//! - [`Message::check`] lists what one message breaks of TS 29.244 on an interface, with
//!   the clause and the Cause of the answer: the tables of clause 7 and the values of
//!   clause 8.2, as its octets show them. A message in which it finds nothing is not
//!   thereby conformant: the README says what it does not check.
//! - With the feature `tree`, a message is a tree that prints as JSON ([`tree`](mod@tree)), read and
//!   edited by path ([`paths`]); with `serde`, it is serialized as its tree.
//! - [`framing`] walks the IEs of a message as slices, without decoding them.
//!
//! The [README](https://github.com/linouxis9/oxirush-pfcp#readme) has an example of
//! each.

#![no_std]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;
#[cfg(any(test, feature = "endpoint"))]
extern crate std;

mod across;
mod check;
#[cfg(feature = "endpoint")]
#[cfg_attr(docsrs, doc(cfg(feature = "endpoint")))]
pub mod endpoint;
mod enums;
mod fields;
pub mod framing;
mod header;
mod ie;
mod known;
mod macros;
mod message;
#[cfg(feature = "node")]
#[cfg_attr(docsrs, doc(cfg(feature = "node")))]
pub mod node;
mod octets;
#[cfg(feature = "tree")]
#[cfg_attr(docsrs, doc(cfg(feature = "tree")))]
pub mod paths;
mod registry;
mod table;
mod values;
mod values_clauses;
mod values_figures;

use alloc::string::{String, ToString};
use core::fmt;

pub use check::{Check, Deviation, DeviationKind};
pub use enums::*;
pub use fields::*;
pub use header::Header;
pub use ie::{Codec, IeFault, IeType, Placed, RawIe, VENDOR};
pub use known::Known;
#[doc(hidden)]
#[cfg(feature = "spec")]
pub use known::ROWS as FEATURE_ROWS;
pub use message::{
    Body, MESSAGE_TYPES, Message, MessageTypeInfo, is_node_related, is_request, message_type_info,
};
pub use octets::Octets;
pub use registry::*;
pub use table::{Interfaces, On, Presence, Repeat, Role, Row, Table};
pub use values::*;
pub use values_clauses::*;
pub use values_figures::*;

/// The trees of oxirush-utils, of the version that this crate is built with: a message
/// and each IE as JSON whose members keep the order of the specification,
/// [`tree::Value`], and `tree!`, which writes one in the code as `serde_json::json!` does.
/// A crate that reads or writes them takes them from here; [`paths`] reads and edits them
/// by path.
#[cfg(feature = "tree")]
#[cfg_attr(docsrs, doc(cfg(feature = "tree")))]
pub use oxirush_utils::tree;

/// Why a message does not decode or encode.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Fewer octets than the header that their S flag says (§7.6.3).
    TooShort {
        /// How many there are.
        octets: usize,
    },
    /// A Message Length that is not the length of the octets after the first four
    /// (§7.6.3): the receiver of a request answers with the Cause "Invalid Length".
    MessageLength {
        /// The header.
        header: Header,
        /// The message type.
        message_type: u8,
        /// The Message Length.
        length: u16,
        /// The octets after the first four.
        available: usize,
    },
    /// IEs whose framing does not fit the message (§7.6.7).
    Ies {
        /// The header.
        header: Header,
        /// The message type.
        message_type: u8,
        /// Where and how.
        fault: IeFault,
    },
    /// The content of an IE longer than its Length can say.
    TooLong {
        /// The IE type.
        ie_type: u16,
        /// The length of the content.
        length: usize,
    },
    /// A message longer than its Message Length can say (§7.2.2.4.1).
    MessageTooLong {
        /// Its message type.
        message_type: u8,
        /// Its octets after the first 4, which the Message Length counts.
        length: usize,
    },
    /// A message of a version of PFCP other than 1 (§7.6.2).
    Version {
        /// The version.
        version: u8,
    },
    /// A field of the header whose value its bits cannot hold (§7.2.2).
    HeaderField {
        /// The field.
        field: &'static str,
        /// Its value.
        value: u64,
    },
    /// A field longer than its length, its number or its type can say.
    FieldLength {
        /// The IE type.
        ie: &'static str,
        /// The field.
        field: &'static str,
    },
    /// A value whose fields disagree with its flags, as its clause has them, or whose
    /// octets would read as another value: a field missing where a later one, or unknown
    /// octets, would read as it, or one of the length that its flags give that is longer,
    /// or shorter with octets after it.
    Inconsistent {
        /// The IE type.
        ie: &'static str,
        /// The field.
        field: &'static str,
        /// The clause.
        clause: &'static str,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::TooShort { octets } => write!(f, "{octets} octets are fewer than a PFCP header"),
            Self::MessageLength {
                length, available, ..
            } => {
                write!(
                    f,
                    "the Message Length is {length}, and {available} octets follow the first four (TS 29.244 7.6.3)"
                )
            }
            Self::Ies { fault, .. } => write!(
                f,
                "the IEs do not fit the message: {fault} (TS 29.244 7.6.7)"
            ),
            Self::Version { version } => write!(
                f,
                "version {version} of PFCP is not supported (TS 29.244 7.6.2)"
            ),
            Self::HeaderField { field, value } => write!(
                f,
                "{value} is more than the bits of the {field} of the header hold (TS 29.244 7.2.2)"
            ),
            Self::TooLong { ie_type, length } => write!(
                f,
                "{length} octets of IE type {ie_type} are more than a Length says"
            ),
            Self::MessageTooLong {
                message_type,
                length,
            } => write!(
                f,
                "{length} octets of message type {message_type} are more than a Message Length says (TS 29.244 7.2.2.4.1)"
            ),
            Self::FieldLength { ie, field } => {
                write!(f, "{field} of {ie} is longer than its length can say")
            }
            Self::Inconsistent { ie, field, clause } => {
                write!(
                    f,
                    "{field} of {ie} disagrees with its flags or its other fields (TS 29.244 {clause})"
                )
            }
        }
    }
}

impl core::error::Error for Error {}

/// The name of an IE in the tree of a scope of `table`: the name of its row, of its type,
/// or its number.
pub(crate) fn tree_name(ie_type: u16, table: Option<&Table>) -> String {
    if let Some(row) = table.and_then(|table| table.row_of(ie_type)) {
        return row.name.to_string();
    }
    // A type whose name is that of a row of the table, for another type, goes by its
    // number: Packet Rate Status Report is the name of types 252 and of the row of 264.
    let letters = |name: &str| {
        name.chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|c| c.to_ascii_lowercase())
            .collect::<String>()
    };
    match ie_type {
        VENDOR.. => ie_type.to_string(),
        known => match ie_type_info(known).map(|info| info.name) {
            Some(name)
                if !table.is_some_and(|table| {
                    table
                        .rows
                        .iter()
                        .any(|row| letters(row.name) == letters(name))
                }) =>
            {
                name.to_string()
            }
            _ => known.to_string(),
        },
    }
}

/// What `f` gives, of a thread that has 10 s to end: a loop of the crate that does not end
/// fails the test that runs it, rather than holding the tests.
#[cfg(test)]
pub(crate) fn ends<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (given, taken) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = given.send(f());
    });
    taken
        .recv_timeout(core::time::Duration::from_secs(10))
        .expect("an end within 10 s")
}
