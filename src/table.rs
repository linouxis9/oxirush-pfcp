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
use crate::ie::{IeFault, Placed, Placing, RawIe, VENDOR, raw};

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

/// How many IEs of a row a scope may have (§7.2.3.4, §7.6.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Repeat {
    /// One: the receiver handles the first and ignores the others.
    Once,
    /// As many as there are: "several IEs with the same IE type may be present".
    Any,
    /// At most this many.
    AtMost(u8),
}

/// The interfaces of a row: its Appl. columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interfaces(pub u8);

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

    /// Whether the row has `interface`.
    pub const fn has(self, interface: Self) -> bool {
        self.0 & interface.0 != 0
    }
}

/// One row of a table: an IE that the scope can have.
#[derive(Debug)]
pub struct Row {
    /// The name that the table gives the IE: `Local F-TEID`. A field that several rows of
    /// one IE type share, which the wire does not tell apart, has the name of the IE type,
    /// and `roles` has the names of the rows.
    pub name: &'static str,
    /// The IE type.
    pub ie_type: u16,
    /// Its presence: of a shared field, the strongest of its rows.
    pub presence: Presence,
    /// How many times it may be there.
    pub repeat: Repeat,
    /// The interfaces that have it.
    pub interfaces: Interfaces,
    /// The rows that share the field, when several do.
    pub roles: &'static [Role],
}

/// One of the rows of a table that share a field: the wire does not tell them apart.
#[derive(Debug)]
pub struct Role {
    /// The name that the table gives the row: `SGW-C FQ-CSID`.
    pub name: &'static str,
    /// Its presence.
    pub presence: Presence,
    /// The interfaces that have it.
    pub interfaces: Interfaces,
}

/// A table of clause 7: of a message, or of the content of a grouped IE in one place.
#[derive(Debug)]
pub struct Table {
    /// Its number in the specification: `7.5.2.2-1`.
    pub id: &'static str,
    /// The name of the message or of the IE: `Create PDR`.
    pub name: &'static str,
    /// The message type of a message, or the IE type of a grouped IE.
    pub code: u16,
    /// Its rows, in the order of the table.
    pub rows: &'static [Row],
}

impl Table {
    /// The row of `ie_type`.
    pub fn row_of(&self, ie_type: u16) -> Option<&'static Row> {
        let rows: &'static [Row] = self.rows;
        rows.iter().find(|row| row.ie_type == ie_type)
    }

    /// The position in the table of the row of `ie_type`.
    pub fn position_of(&self, ie_type: u16) -> Option<usize> {
        self.rows.iter().position(|row| row.ie_type == ie_type)
    }
}

/// What the table macro writes for a message or a grouped IE, which the code of every
/// scope takes: the fields by IE type, the raw IEs and the order.
pub(crate) trait Scope<'a>: Default {
    /// The table of the scope.
    fn table() -> &'static Table;
    /// The position in the table of the row of `ie_type`.
    fn position(ie_type: u16) -> Option<usize>;
    /// Whether a list of the scope is of values large enough to be sized before it is
    /// filled, by a first pass over the IEs.
    const PRESIZE: bool;
    /// Size the lists for the IEs of `octets`.
    fn presize(&mut self, octets: &[u8]);
    /// Read the content of an IE of `ie_type` into its field.
    fn place(&mut self, ie_type: u16, body: &'a [u8]) -> Placing;
    /// Write the `nth` value of the field of `ie_type`: `false` for one that is not there.
    fn emit(&self, ie_type: u16, nth: usize, out: &mut Vec<u8>) -> Result<bool, Error>;
    /// How many octets the IEs of the scope have, their headers included.
    fn encoded_len(&self) -> usize;
    /// Write every field, in the order of the table.
    fn encode_fields(&self, out: &mut Vec<u8>) -> Result<(), Error>;
    /// How many values the field of `ie_type` has.
    fn count(&self, ie_type: u16) -> usize;
    /// Whether `octets` decode as the value of the field of `ie_type`.
    fn decodes(&self, ie_type: u16, octets: &[u8]) -> bool;
    /// The IEs that the scope keeps as octets.
    fn raw(&self) -> &[RawIe<'a>];
    /// The same, to change.
    fn raw_mut(&mut self) -> &mut Vec<RawIe<'a>>;
    /// The order of the wire, when it is not that of the table.
    fn order(&self) -> &[Placed];
    /// The same, to change.
    fn order_mut(&mut self) -> &mut Vec<Placed>;
}

/// The scope of `octets`.
pub(crate) fn decode_scope<'a, S: Scope<'a>>(octets: &'a [u8]) -> Result<S, IeFault> {
    let mut scope = S::default();
    decode_scope_into(&mut scope, octets)?;
    Ok(scope)
}

/// The scope of `octets`, in `scope`, which is empty.
pub(crate) fn decode_scope_into<'a, S: Scope<'a>>(scope: &mut S, octets: &'a [u8]) -> Result<(), IeFault> {
    decode_scope_sized(scope, octets, false)
}

/// The scope of `octets`, in `scope`, which is empty; its large lists sized first by a
/// pass over its IEs where `presize` asks for it: a message, whose lists of grouped IEs
/// are long, and not a grouped IE, whose lists are short or empty.
pub(crate) fn decode_scope_sized<'a, S: Scope<'a>>(scope: &mut S, octets: &'a [u8], presize: bool) -> Result<(), IeFault> {
    if presize && S::PRESIZE {
        scope.presize(octets);
    }
    // No order is kept while the IEs come in the order of the table, which encoding the
    // fields in that order gives back.
    let mut order: Option<Vec<Placed>> = None;
    let mut last = 0;
    for ie in crate::framing::ies(octets) {
        let ie = ie?;
        let (ie_type, body) = (ie.ie_type, ie.content());
        let placing = match body.is_empty() || ie_type >= VENDOR {
            true => Placing::Unexpected,
            false => scope.place(ie_type, body),
        };
        let placed = match placing {
            Placing::Placed => Placed::Field(ie_type),
            _ => {
                scope.raw_mut().push(raw(ie_type, body));
                Placed::Raw
            }
        };
        if let Some(order) = &mut order {
            order.push(placed);
            continue;
        }
        let at = match placed {
            Placed::Field(ie_type) => S::position(ie_type).unwrap_or(usize::MAX),
            Placed::Raw => usize::MAX,
        };
        if placed != Placed::Raw && at >= last {
            last = at;
            continue;
        }
        // The first IE out of the order of the table: those before it were in that order.
        let mut kept = Vec::new();
        for row in S::table().rows {
            let mut values = scope.count(row.ie_type);
            if placed == Placed::Field(row.ie_type) {
                values -= 1;
            }
            kept.extend(core::iter::repeat_n(Placed::Field(row.ie_type), values));
        }
        kept.push(placed);
        order = Some(kept);
    }
    *scope.order_mut() = order.unwrap_or_default();
    Ok(())
}

/// Keep `order` in `scope`, unless the fields in the order of the table give the same
/// octets: then nothing is kept, and a scope that is changed stays in that order.
#[cfg(feature = "tree")]
pub(crate) fn keep_order<'a, S: Scope<'a>>(scope: &mut S, order: Vec<Placed>) {
    let mut last = 0;
    let in_table_order = order.iter().all(|placed| match placed {
        Placed::Raw => false,
        Placed::Field(ie_type) => {
            let at = S::position(*ie_type).unwrap_or(usize::MAX);
            let ordered = at >= last;
            last = at;
            ordered
        }
    });
    *scope.order_mut() = if in_table_order { Vec::new() } else { order };
}

/// Write `scope`: in the order that it keeps, with the values that were added since in
/// the places of their rows, or in the order of its table.
pub(crate) fn encode_scope<'a, S: Scope<'a>>(scope: &S, out: &mut Vec<u8>) -> Result<(), Error> {
    let order = scope.order();
    if order.is_empty() {
        scope.encode_fields(out)?;
        for ie in scope.raw() {
            ie.encode(out)?;
        }
        return Ok(());
    }
    let table = S::table();
    // How many values of each row the order has: those after are added.
    let mut ordered = [0usize; 64];
    for placed in order {
        if let Placed::Field(ie_type) = placed
            && let Some(at) = S::position(*ie_type)
        {
            ordered[at] += 1;
        }
    }
    let mut next_added = 0;
    let mut emit_added = |before: usize, out: &mut Vec<u8>| -> Result<(), Error> {
        while next_added < table.rows.len() && next_added < before {
            let ie_type = table.rows[next_added].ie_type;
            let mut nth = ordered[next_added];
            while scope.emit(ie_type, nth, out)? {
                nth += 1;
            }
            next_added += 1;
        }
        Ok(())
    };
    let mut emitted = [0usize; 64];
    let mut raw = scope.raw().iter();
    for placed in order {
        match placed {
            Placed::Field(ie_type) => {
                let at = S::position(*ie_type).unwrap_or(table.rows.len());
                emit_added(at, out)?;
                scope.emit(*ie_type, emitted[at], out)?;
                emitted[at] += 1;
            }
            Placed::Raw => {
                if let Some(ie) = raw.next() {
                    ie.encode(out)?;
                }
            }
        }
    }
    emit_added(usize::MAX, out)?;
    for ie in raw {
        ie.encode(out)?;
    }
    Ok(())
}
