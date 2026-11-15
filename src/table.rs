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

//! The tables of clause 7: for a message or a grouped IE, the IEs that it can have, each
//! with its presence, how many times it may be there and the interfaces that have it;
//! and what a typed scope does with them, written once for every table.

use alloc::vec::Vec;

use crate::Error;
use crate::ie::{Codec, IeType};

pub use oxirush_utils::tables::Repeat;
#[cfg(test)]
use oxirush_utils::tables::{Entry, each_entry};
pub(crate) use oxirush_utils::tables::{
    FieldValues, MAX_ROWS, decode_boxed, decode_scope, decode_scope_into, decode_scope_sized,
    encode_scope, place, value_positions,
};
#[cfg(test)]
use {crate::ie::Placed, oxirush_utils::tables::on_roles};

/// One row of a table of clause 7: an IE that the scope can have, a field of the scope. A
/// field that several rows of one IE type share, which the wire does not tell apart, is
/// one row of those roles.
pub type Row = oxirush_utils::tables::Row<crate::Pfcp>;
/// A row of a table, as the field of a scope has it: the one of a field of its own, or one
/// of the rows that share a field, which the wire does not tell apart.
pub type Role = oxirush_utils::tables::Role<crate::Pfcp>;
/// A table of clause 7: of a message, or of the content of a grouped IE in one place.
pub type Table = oxirush_utils::tables::Table<crate::Pfcp>;
/// What a row is on an interface, or on a set of them, as [`Row::on`] gives it: what
/// `check()` holds a message to.
pub type On = oxirush_utils::tables::On<crate::Pfcp>;

/// The presence of an IE in its table (§7.2.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// M: the sender includes it.
    Mandatory,
    /// C: the sender includes it when the condition of its row holds.
    Conditional,
    /// O: the sender may include it.
    Optional,
}

impl oxirush_utils::tables::Presence for Presence {
    const OPTIONAL: Self = Self::Optional;

    #[inline]
    fn is_mandatory(self) -> bool {
        self == Self::Mandatory
    }

    #[inline]
    fn rank(self) -> u8 {
        match self {
            Self::Mandatory => 0,
            Self::Conditional => 1,
            Self::Optional => 2,
        }
    }
}

/// The interfaces of a row: its Appl. columns. One of them, or a set of them that
/// [`BitOr`](core::ops::BitOr) makes.
///
/// ```compile_fail
/// // Not of bits of the caller's own: from_bits() refuses those of no interface.
/// let _ = oxirush_pfcp::Interfaces(0);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interfaces(pub(crate) u8);

impl Interfaces {
    /// Sxa, between SGW-C and SGW-U.
    pub const SXA: Self = Self(1);
    /// Sxb, between PGW-C and PGW-U.
    pub const SXB: Self = Self(2);
    /// Sxc, between TDF-C and TDF-U.
    pub const SXC: Self = Self(4);
    /// N4, between the SMF and the UPF.
    pub const N4: Self = Self(8);
    /// N4mb, between the MB-SMF and the MB-UPF.
    pub const N4MB: Self = Self(16);
    /// The combined Sxa/Sxb of a combined SGW/PGW (§5.2.6): a message may have the IEs
    /// of either, and needs those that both need.
    pub const SXA_SXB: Self = Self(Self::SXA.0 | Self::SXB.0);
    /// Every interface: a message may have the IEs of any, and needs those that all need.
    pub const ALL: Self = Self(Self::SXA.0 | Self::SXB.0 | Self::SXC.0 | Self::N4.0 | Self::N4MB.0);

    /// The set of `bits`, those of the constants: `None` for none, and for a bit of no
    /// interface.
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits != 0 && bits & !Self::ALL.0 == 0 {
            true => Some(Self(bits)),
            false => None,
        }
    }

    /// Its bits, those of the constants: 0 for none.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Whether the row has `interface`, or one of a set of them.
    pub const fn has(self, interface: Self) -> bool {
        self.0 & interface.0 != 0
    }
}

impl core::ops::BitOr for Interfaces {
    type Output = Self;

    /// A set of interfaces, which a message of either may be on.
    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}
impl oxirush_utils::tables::Interfaces for Interfaces {
    const NONE: Self = Self(0);

    #[inline]
    fn has(self, other: Self) -> bool {
        Interfaces::has(self, other)
    }

    #[inline]
    fn covers(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    #[inline]
    fn union(self, other: Self) -> Self {
        self | other
    }

    #[inline]
    fn each(self) -> impl Iterator<Item = Self> {
        (0..5)
            .map(|bit| Self(1 << bit))
            .filter(move |one| self.has(*one))
    }
}

/// The table of the content of a value: of a grouped IE, the table of its type of the
/// crate, which is one place's; none for another value. The registry writes it for each
/// type.
pub(crate) trait Content {
    const TABLE: Option<&'static Table> = None;
}

/// How many IEs `roles` allow together, `usize::MAX` for any number: what the field of a
/// row holds, which the table macro asserts.
#[allow(dead_code)]
pub(crate) const fn capacity(roles: &[Role]) -> usize {
    oxirush_utils::tables::capacity(roles)
}

/// What the table macro writes for a message or a grouped IE, which the code of every
/// scope takes, of PFCP.
pub(crate) trait Scope: oxirush_utils::tables::Scope<P = crate::Pfcp> {}

impl<S: oxirush_utils::tables::Scope<P = crate::Pfcp>> Scope for S {}

/// Write the `nth` value of a field as its IE: `false` when it has no such value.
#[inline]
pub(crate) fn emit_field<T: IeType + Codec, F: FieldValues<T>>(
    field: &F,
    nth: usize,
    out: &mut Vec<u8>,
) -> Result<bool, Error> {
    match field.values().get(nth) {
        Some(value) => crate::ie::encode_value(value, out).map(|()| true),
        None => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How many IEs the roles of a row allow together: one of a role that is there once,
    /// as many as a role says, any number of a role of any, and their sum.
    #[test]
    fn the_roles_of_a_row_allow_their_sum() {
        let role = |repeat| Role {
            name: "Row",
            presence: Presence::Optional,
            repeat,
            interfaces: Interfaces::N4,
        };
        assert_eq!(capacity(&[]), 0);
        assert_eq!(capacity(&[role(Repeat::Once)]), 1);
        assert_eq!(capacity(&[role(Repeat::AtMost(3))]), 3);
        assert_eq!(capacity(&[role(Repeat::Any)]), usize::MAX);
        assert_eq!(capacity(&[role(Repeat::Once), role(Repeat::AtMost(3))]), 4);
        assert_eq!(
            capacity(&[
                role(Repeat::AtMost(2)),
                role(Repeat::Once),
                role(Repeat::Once)
            ]),
            4
        );
        assert_eq!(
            capacity(&[role(Repeat::Any), role(Repeat::Once)]),
            usize::MAX
        );
    }

    /// The entries of a row, as the tree of its scope lists them: its values and the IEs
    /// that the scope keeps of it, in the order of the wire as far as the scope keeps one,
    /// which may name more values than the row has, and other rows; then the values and
    /// the kept IEs that the order does not have.
    #[test]
    fn the_entries_of_a_row_are_its_values_and_its_kept_ies() {
        use crate::{CreatePdr, RawIe, SessionEstablishmentRequest};
        let entries = |scope: &SessionEstablishmentRequest| {
            let mut entries = Vec::new();
            each_entry(scope, 1, |entry| entries.push(entry));
            entries
        };
        let mut request = SessionEstablishmentRequest {
            create_pdr: alloc::vec![CreatePdr::default(), CreatePdr::default()],
            raw: alloc::vec![
                RawIe::new(3, [1u8]),
                RawIe::new(1, [1u8]),
                RawIe::new(1, [2u8])
            ],
            ..Default::default()
        };
        // A Create FAR and a Create PDR kept, a value, a row of another type, a value, a
        // value that the row no longer has; then the Create PDR kept that the order lacks
        request.order = alloc::vec![
            Placed::Raw,
            Placed::Raw,
            Placed::Field(1),
            Placed::Field(3),
            Placed::Field(1),
            Placed::Field(1),
        ];
        assert_eq!(
            entries(&request),
            [
                Entry::Kept(1),
                Entry::Value(0),
                Entry::Value(1),
                Entry::Kept(2)
            ]
        );
        // Without an order: the values, then the kept IEs of the row
        request.order.clear();
        assert_eq!(
            entries(&request),
            [
                Entry::Value(0),
                Entry::Value(1),
                Entry::Kept(1),
                Entry::Kept(2)
            ]
        );
        // An order of fewer values than the row has: the others after them
        request.order = alloc::vec![Placed::Field(1)];
        assert_eq!(
            entries(&request),
            [
                Entry::Value(0),
                Entry::Value(1),
                Entry::Kept(1),
                Entry::Kept(2)
            ]
        );
    }

    /// A row of one role is on each set of interfaces what the walk of its roles says.
    #[test]
    fn a_row_of_one_role_is_on_each_set_of_interfaces_as_its_roles_say() {
        let mut tables: Vec<&Table> = crate::MESSAGE_TYPES.iter().map(|info| info.table).collect();
        tables.extend(
            crate::IE_TYPES
                .iter()
                .flat_map(|info| info.tables.iter().copied()),
        );
        let mut rows = 0;
        for table in tables {
            for row in table.rows.iter().filter(|row| row.roles.len() == 1) {
                rows += 1;
                for bits in 1..=Interfaces::ALL.0 {
                    let interfaces = Interfaces(bits);
                    assert_eq!(
                        row.on(interfaces),
                        on_roles(row.roles, interfaces),
                        "{}",
                        row.name
                    );
                }
            }
        }
        assert!(rows > 600, "{rows}");
    }

    /// A message read in another order than its table's keeps that order, and one of an IE
    /// of a row kept as octets has it after the values of its row: each is written once,
    /// and a value added after those of its row.
    #[test]
    fn a_message_in_the_order_of_the_wire_or_of_its_rows_is_written_once() {
        use crate::{HeartbeatRequest, Message, RawIe, RecoveryTimeStamp};
        let header = [0x20, 1, 0, 21, 0, 0, 5, 0];
        let stamp = [0, 96, 0, 4, 0, 0, 0, 7];
        let source = [0, 192, 0, 5, 2, 10, 0, 0, 1];
        let of_rows = [&header[..], &stamp, &source].concat();
        let wire = [&header[..], &source, &stamp].concat();
        let mut kept = HeartbeatRequest::new(RecoveryTimeStamp::new(7));
        kept.raw.push(RawIe::new(192, alloc::vec![2, 10, 0, 0, 1]));
        let read = Message::decode(&wire).unwrap();
        let written = crate::ends(move || {
            [Message::node(5, kept), read].map(|message| message.encode().unwrap())
        });
        assert_eq!(written, [of_rows, wire.clone()]);
        // A value added to a message of its own order goes after the IEs of that order
        let unknown = [11, 184, 0, 1, 7];
        let header = [0x20, 1, 0, 17, 0, 0, 5, 0];
        let mut added = Message::decode(&[&header[..], &unknown, &stamp].concat()).unwrap();
        let crate::Body::HeartbeatRequest(request) = &mut added.body else {
            panic!()
        };
        request.source_ip_address = Some(crate::SourceIpAddress {
            v4: true,
            ipv4_address: Some(core::net::Ipv4Addr::new(10, 0, 0, 1)),
            ..Default::default()
        });
        let written = crate::ends(move || added.encode().unwrap());
        let header = [0x20, 1, 0, 26, 0, 0, 5, 0];
        assert_eq!(written, [&header[..], &unknown, &stamp, &source].concat());
    }

    /// A field that rows share is, on an interface, of the weakest presence of its rows
    /// there, needs an IE for each of its mandatory rows there, and takes as many as they
    /// allow; on a set of interfaces, it is of the weakest presence on each, of none where
    /// one of them lacks it, needs the
    /// fewest IEs that one of them needs, as each needs an IE of the field, which the wire
    /// does not tell apart, and takes the IEs of the rows of any of them.
    #[test]
    fn a_shared_field_on_each_interface_and_on_a_set() {
        const fn role(
            name: &'static str,
            presence: Presence,
            repeat: Repeat,
            interfaces: Interfaces,
        ) -> Role {
            Role {
                name,
                presence,
                repeat,
                interfaces,
            }
        }
        static ROLES: [Role; 4] = [
            role("on N4", Presence::Mandatory, Repeat::Once, Interfaces::N4),
            role(
                "optional on N4",
                Presence::Optional,
                Repeat::AtMost(2),
                Interfaces::N4,
            ),
            role(
                "on N4mb",
                Presence::Mandatory,
                Repeat::Once,
                Interfaces::N4MB,
            ),
            role("on Sxb", Presence::Optional, Repeat::Any, Interfaces::SXB),
        ];
        let both = Interfaces::N4 | Interfaces::N4MB;
        let row = Row {
            name: "shared",
            ie_type: 1,
            roles: &ROLES,
            content: None,
            checked: false,
        };
        let optional = Some(Presence::Optional);
        let on = |presence, needed, most| {
            Some(On {
                presence,
                needed,
                most,
            })
        };
        assert_eq!(row.on(Interfaces::N4), on(optional, 1, Repeat::AtMost(3)));
        assert_eq!(
            row.on(Interfaces::N4MB),
            on(Some(Presence::Mandatory), 1, Repeat::Once)
        );
        assert_eq!(row.on(both), on(optional, 1, Repeat::AtMost(4)));
        assert_eq!(row.on(Interfaces::SXB), on(optional, 0, Repeat::Any));
        assert_eq!(row.on(both | Interfaces::SXB), on(optional, 0, Repeat::Any));
        assert_eq!(row.on(Interfaces::SXA), None);
        assert_eq!(row.on(Interfaces::SXA_SXB), on(None, 0, Repeat::Any));
    }
}
