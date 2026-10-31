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
//! - [`Message::check`] and [`Message::check_on`] say how a message is not as TS 29.244
//!   has a sender construct it, with the clause and the Cause of the answer.
//! - With the feature `tree`, a message is a tree that prints as JSON, read and edited by
//!   path ([`tree`]); with `serde`, it is serialized as its tree.
//! - [`framing`] walks the IEs of a message as slices, without decoding them.
//!
//! The [README](https://github.com/linouxis9/oxirush-pfcp#readme) has an example of
//! each.

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod check;
mod enums;
mod header;
mod ie;
mod macros;
mod list;
mod message;
#[cfg(feature = "node")]
pub mod node;
#[cfg(feature = "endpoint")]
pub mod endpoint;
mod octets;
pub mod framing;
mod registry;
mod table;
#[cfg(feature = "tree")]
pub mod tree;
mod values;
mod values_gen;
mod values_hand;

use alloc::string::{String, ToString};
use core::fmt;

pub use check::{Check, Deviation, DeviationKind, Path};
pub use enums::*;
pub use header::Header;
pub use ie::{Codec, IeFault, IeType, Listed, Placed, RawIe, VENDOR};
pub use check::Context;
pub use message::{Body, MESSAGE_TYPES, Message, MessageTypeInfo, is_node_related, is_request, message_type_info};
pub use list::List;
pub use octets::{IntoOwned, Octets};
pub use registry::*;
pub use table::{Interfaces, Presence, Repeat, Role, Row, Table};
pub use values::*;
pub use values_gen::*;
pub use values_hand::*;

/// The examples of the README, which the documentation tests compile and run.
#[cfg(all(doctest, feature = "serde"))]
#[doc = include_str!("../README.md")]
struct Readme;

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
    /// Content longer than a Length can say.
    TooLong {
        /// The IE type, or 0 for the message.
        ie_type: u16,
        /// The length of the content.
        length: usize,
    },
    /// A value whose fields disagree with its flags, as its clause has them.
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { octets } => write!(f, "{octets} octets are fewer than a PFCP header"),
            Self::MessageLength { length, available, .. } => {
                write!(f, "the Message Length is {length}, and {available} octets follow the first four (TS 29.244 7.6.3)")
            }
            Self::Ies { fault, .. } => write!(f, "the IEs do not fit the message: {fault:?} (TS 29.244 7.6.7)"),
            Self::TooLong { ie_type, length } => write!(f, "{length} octets of IE type {ie_type} are more than a Length says"),
            Self::Inconsistent { ie, field, clause } => {
                write!(f, "{field} of {ie} disagrees with its flags (TS 29.244 {clause})")
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
    match ie_type {
        VENDOR.. => ie_type.to_string(),
        known => type_name(known).map_or_else(|| known.to_string(), str::to_string),
    }
}
