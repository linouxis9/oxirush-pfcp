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
use crate::ie::{Codec, IeFault, IeType, Placed, Placing, RawIe, VENDOR, raw};

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

    /// Whether the row has each of `interfaces`.
    pub const fn has_all(self, interfaces: Self) -> bool {
        interfaces.0 != 0 && self.0 & interfaces.0 == interfaces.0
    }
}

impl core::ops::BitOr for Interfaces {
    type Output = Self;

    /// A set of interfaces, which a message of either may be on.
    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// One row of a table: an IE that the scope can have, a field of the scope. A field that
/// several rows of one IE type share, which the wire does not tell apart, is one row of
/// those roles.
#[derive(Debug)]
pub struct Row {
    /// The name that the table gives the IE: `Local F-TEID`. A field that several rows
    /// share has the name of the IE type, and `roles` the names of the rows.
    pub name: &'static str,
    /// The IE type.
    pub ie_type: u16,
    /// The rows of the table that the field is, each with its presence, its interfaces
    /// and how many IEs of it may be there: the row itself, or each row that shares the
    /// field. [`on`](Self::on) gives what they are on an interface.
    pub roles: &'static [Role],
    /// The table of the content of a grouped IE in this place: of an IE type whose content
    /// differs by place, as Session Report (Tables 7.5.7.3-1 and 7.5.8.6-1), the one of
    /// this place. `None` for another IE.
    pub content: Option<&'static Table>,
    /// Whether `check()` checks a condition of the row that the IEs of its scope show: of
    /// its presence (§7.6.6) or of its absence. A NOTE of two rows, as one of two IEs that
    /// one of them is needed, is checked at one of them.
    pub checked: bool,
}

/// The table of the content of a value: of a grouped IE, the table of its type of the
/// crate, which is one place's; none for another value. The registry writes it for each
/// type.
pub(crate) trait Content {
    const TABLE: Option<&'static Table> = None;
}

/// The values of a field of a scope: one, in its place or boxed, or a list. The
/// functions that each table writes for its rows call one generic function per kind of
/// field and type of value, which all the tables share.
pub(crate) trait FieldValues<T> {
    /// The values, in their order.
    fn values(&self) -> &[T];
    /// The first value: that of a field that is there once.
    #[inline(always)]
    fn first(&self) -> Option<&T> {
        self.values().first()
    }
    /// Set the value, or add it to the list.
    fn add(&mut self, value: T);
}

impl<T> FieldValues<T> for Option<T> {
    #[inline(always)]
    fn values(&self) -> &[T] {
        self.as_slice()
    }
    fn add(&mut self, value: T) {
        *self = Some(value);
    }
}

impl<T> FieldValues<T> for Option<alloc::boxed::Box<T>> {
    #[inline(always)]
    fn values(&self) -> &[T] {
        match self {
            Some(value) => core::slice::from_ref(&**value),
            None => &[],
        }
    }
    fn add(&mut self, value: T) {
        *self = Some(alloc::boxed::Box::new(value));
    }
}

impl<T> FieldValues<T> for Vec<T> {
    #[inline(always)]
    fn values(&self) -> &[T] {
        self
    }
    fn add(&mut self, value: T) {
        self.push(value);
    }
}

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

/// A row of a table, as the field of a scope has it: the one of a field of its own, or one
/// of the rows that share a field, which the wire does not tell apart.
#[derive(Debug)]
pub struct Role {
    /// The name that the table gives the row: `SGW-C FQ-CSID`.
    pub name: &'static str,
    /// Its presence.
    pub presence: Presence,
    /// How many IEs of it may be there.
    pub repeat: Repeat,
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
    /// The interfaces that have a constructor of their own, `new_sxa()` to `new_n4mb()`,
    /// for a table whose mandatory IEs differ between them: none for a table of one
    /// `new()`.
    pub constructors: Interfaces,
}

/// What a row is on an interface, or on a set of them, as [`Row::on`] gives it: what
/// `check()` holds a message to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct On {
    /// Its presence: the weakest of its roles there; on a set of interfaces, the weakest on
    /// each, and `None` where one of them lacks the row, which a message on the set may
    /// have and needs on none, whatever the condition beside it.
    pub presence: Option<Presence>,
    /// How many IEs of it a message needs: one for each of its mandatory roles there.
    pub needed: usize,
    /// How many IEs of it a message may have: as many as its roles there allow, `Once` for
    /// one.
    pub most: Repeat,
}

/// How many IEs `roles` allow together, `usize::MAX` for any number: what the field of a
/// row holds, which the table macro asserts. Rust 1.88 counts no use of it in a constant.
#[allow(dead_code)]
pub(crate) const fn capacity(roles: &[Role]) -> usize {
    let mut at = 0;
    let mut most = 0usize;
    while at < roles.len() {
        most = most.saturating_add(match roles[at].repeat {
            Repeat::Once => 1,
            Repeat::AtMost(at_most) => at_most as usize,
            Repeat::Any => usize::MAX,
        });
        at += 1;
    }
    most
}

impl Repeat {
    /// Whether `count` IEs may be there.
    pub(crate) const fn allows(self, count: usize) -> bool {
        match self {
            Self::Once => count <= 1,
            Self::Any => true,
            Self::AtMost(most) => count <= most as usize,
        }
    }
}

impl Row {
    /// What the row is on `interfaces`: `None` where none of them has it, as its IEs are
    /// discarded there (§7.6.9). On a set of interfaces, a message may have the IEs of the
    /// roles of any of them, and needs what each of them needs: the weakest presence of
    /// each, none where one of them lacks the row, and the fewest IEs that one of them
    /// needs.
    pub fn on(&self, interfaces: Interfaces) -> Option<On> {
        let roles = self.roles;
        if !roles.iter().any(|role| role.interfaces.has(interfaces)) {
            return None;
        }
        let rank = |presence: &Presence| match presence {
            Presence::Mandatory => 0,
            Presence::Conditional => 1,
            Presence::Optional => 2,
        };
        // Of each interface: the weakest presence of its roles, and the IEs of its mandatory
        // roles.
        let each = (0..5).map(|bit| Interfaces(1 << bit));
        let each = each.filter(|one| interfaces.has(*one)).map(|one| {
            let there = roles.iter().filter(move |role| role.interfaces.has(one));
            let presence = there.clone().map(|role| role.presence).max_by_key(rank);
            let needed = there.filter(|role| role.presence == Presence::Mandatory);
            (presence, needed.count())
        });
        let (presence, needed) = each
            .reduce(|(was, before), (presence, needed)| {
                let weakest = was
                    .zip(presence)
                    .map(|(was, presence)| core::cmp::max_by_key(was, presence, rank));
                (weakest, before.min(needed))
            })
            .unwrap_or_default();
        let most = roles
            .iter()
            .filter(|role| role.interfaces.has(interfaces))
            .try_fold(0usize, |most, role| match role.repeat {
                Repeat::Once => Some(most + 1),
                Repeat::AtMost(at) => Some(most + usize::from(at)),
                Repeat::Any => None,
            });
        let most = match most.map(u8::try_from) {
            Some(Ok(1)) => Repeat::Once,
            Some(Ok(most)) => Repeat::AtMost(most),
            _ => Repeat::Any,
        };
        Some(On {
            presence,
            needed,
            most,
        })
    }

    /// Whether the row is a list in the tree of its scope: of a role that may be there more
    /// than once, or of roles that share the field.
    pub fn is_list(&self) -> bool {
        match self.roles {
            [role] => role.repeat != Repeat::Once,
            _ => true,
        }
    }
}

impl Table {
    /// The interfaces that its rows have.
    pub fn interfaces(&self) -> Interfaces {
        let roles = self.rows.iter().flat_map(|row| row.roles.iter());
        Interfaces(roles.fold(0, |bits, role| bits | role.interfaces.0))
    }

    /// The row of `ie_type`.
    pub fn row_of(&self, ie_type: u16) -> Option<&'static Row> {
        let rows: &'static [Row] = self.rows;
        rows.iter().find(|row| row.ie_type == ie_type)
    }
}

/// What the table macro writes for a message or a grouped IE, which the code of every
/// scope takes: the fields by IE type, the raw IEs and the order.
pub(crate) trait Scope: Default {
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
    fn place(&mut self, ie_type: u16, body: &[u8]) -> Placing;
    /// Write the `nth` value of the field of `ie_type`: `false` for one that is not there.
    fn emit(&self, ie_type: u16, nth: usize, out: &mut Vec<u8>) -> Result<bool, Error>;
    /// How many octets the IEs of the scope have, their headers included.
    fn encoded_len(&self) -> usize;
    /// Write every field, in the order of the table.
    fn encode_fields(&self, out: &mut Vec<u8>) -> Result<(), Error>;
    /// The octets that the scope takes beyond its own size: its lists and boxes, and the
    /// IEs that it keeps as octets ([`Listed::held`](crate::ie::Listed::held)).
    #[cfg(feature = "endpoint")]
    fn held(&self) -> usize;
    /// How many values the field of `ie_type` has.
    fn count(&self, ie_type: u16) -> usize;
    /// Remove the values of the field of `ie_type`.
    fn clear(&mut self, ie_type: u16);
    /// Whether `octets` decode as the value of the field of `ie_type`.
    fn decodes(&self, ie_type: u16, octets: &[u8]) -> bool;
    /// Whether its octets read as the scope: it keeps no IE as octets, has no more values
    /// of a row than the row takes, and each value writes octets that read as it, here
    /// and in each grouped IE that it holds. A null length reads as no value, and a raw IE
    /// as what its octets are.
    fn plain(&self) -> bool;
    /// Whether it has no IE: its octets are none.
    fn is_empty(&self) -> bool;
    /// The IEs that the scope keeps as octets.
    fn raw(&self) -> &[RawIe];
    /// The same, to change.
    fn raw_mut(&mut self) -> &mut Vec<RawIe>;
    /// The order of the wire, when it is not that of the table.
    fn order(&self) -> &[Placed];
    /// The same, to change.
    fn order_mut(&mut self) -> &mut Vec<Placed>;
}

/// The scope that its octets read: `None` for one that does not encode, or whose octets
/// do not decode.
pub(crate) fn reread<S: Scope>(scope: &S) -> Option<S> {
    let mut octets = Vec::new();
    encode_scope(scope, &mut octets).ok()?;
    decode_scope(&octets).ok()
}

/// Decode a grouped IE in a box that `slot`, which is empty, takes: `false`, and the slot
/// left empty, for octets that are not one.
pub(crate) fn decode_boxed<S: Scope>(
    slot: &mut Option<alloc::boxed::Box<S>>,
    octets: &[u8],
) -> bool {
    let scope = slot.insert(alloc::boxed::Box::default());
    if decode_scope_into(&mut **scope, octets).is_err() {
        *slot = None;
        return false;
    }
    true
}

/// The scope of `octets`.
pub(crate) fn decode_scope<S: Scope>(octets: &[u8]) -> Result<S, IeFault> {
    let mut scope = S::default();
    decode_scope_into(&mut scope, octets)?;
    Ok(scope)
}

/// The scope of `octets`, in `scope`, which is empty.
pub(crate) fn decode_scope_into<S: Scope>(scope: &mut S, octets: &[u8]) -> Result<(), IeFault> {
    decode_scope_sized(scope, octets, false)
}

/// The scope of `octets`, in `scope`, which is empty; its large lists sized first by a
/// pass over its IEs where `presize` asks for it: a message, whose lists of grouped IEs
/// are long, and not a grouped IE, whose lists are short or empty.
pub(crate) fn decode_scope_sized<S: Scope>(
    scope: &mut S,
    octets: &[u8],
    presize: bool,
) -> Result<(), IeFault> {
    if presizes::<S>(presize) {
        scope.presize(octets);
    }
    // No order is kept while the IEs come in the order of the table, which encoding the
    // scope without one gives back.
    let mut order: Option<Vec<Placed>> = None;
    let mut last = (0, false);
    // The rows there once whose first IE the scope keeps as octets, of a null length or
    // not decoding: §7.6.10 handles that first one, and ignores the others.
    let mut kept_first: Vec<u16> = Vec::new();
    for ie in crate::framing::ies(octets) {
        let ie = ie?;
        let (ie_type, body) = (ie.ie_type, ie.content());
        let placing = match body.is_empty() || ie_type >= VENDOR {
            true => Placing::Unexpected,
            false if kept_first.contains(&ie_type) => Placing::Repeated,
            false => scope.place(ie_type, body),
        };
        // No row is of a vendor's type, which a null length leaves out.
        if unread(placing, body) && once::<S>(ie_type) && !kept_first.contains(&ie_type) {
            kept_first.push(ie_type);
        }
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
        let at = rank::<S>(ie_type, placed == Placed::Raw);
        if at >= last {
            last = at;
            continue;
        }
        // The first IE out of the order of the table: those before it were in that order.
        let raws = scope.raw();
        let before = match placed {
            Placed::Raw => &raws[..raws.len() - 1],
            Placed::Field(_) => raws,
        };
        let count = |ie_type| scope.count(ie_type) - usize::from(placed == Placed::Field(ie_type));
        let mut kept = in_table_order(S::table(), before, count);
        kept.push(placed);
        order = Some(kept);
    }
    *scope.order_mut() = order.unwrap_or_default();
    Ok(())
}

/// Whether a scope sizes its lists first: a message whose lists are of large values.
fn presizes<S: Scope>(presize: bool) -> bool {
    presize && S::PRESIZE
}

/// Whether an IE of `body` that a scope placed so is kept as octets unread: of a null
/// length, or that does not decode as its row's value.
fn unread(placing: Placing, body: &[u8]) -> bool {
    placing == Placing::Malformed || body.is_empty()
}

/// Whether the row of `ie_type` in a scope is there once.
fn once<S: Scope>(ie_type: u16) -> bool {
    S::table().row_of(ie_type).is_some_and(|row| !row.is_list())
}

/// Where an IE goes in the order of a table: at the position of its row, an IE that the
/// scope keeps as octets after the values of its row, and one of no row after every row.
fn rank<S: Scope>(ie_type: u16, kept: bool) -> (usize, bool) {
    (S::position(ie_type).unwrap_or(usize::MAX), kept)
}

/// The order of a scope that has `count` values of each row and keeps `raws`, in the order
/// of its table: each row, its values then its kept IEs, and the kept IEs of no row last.
fn in_table_order(table: &Table, raws: &[RawIe], count: impl Fn(u16) -> usize) -> Vec<Placed> {
    let kept = |ie_type: u16| raws.iter().filter(|ie| ie.ie_type == ie_type).count();
    let mut order = Vec::new();
    for row in table.rows {
        order.extend(core::iter::repeat_n(
            Placed::Field(row.ie_type),
            count(row.ie_type),
        ));
        order.extend(core::iter::repeat_n(Placed::Raw, kept(row.ie_type)));
    }
    let of_no_row = raws.iter().filter(|ie| table.row_of(ie.ie_type).is_none());
    order.extend(core::iter::repeat_n(Placed::Raw, of_no_row.count()));
    order
}

/// Keep `order` in `scope`, unless it is the order of the table, which the scope without
/// one is encoded in: then nothing is kept, and a scope that is changed stays in that order.
#[cfg(feature = "tree")]
pub(crate) fn keep_order<S: Scope>(scope: &mut S, order: Vec<Placed>) {
    let ordered = in_table_order(S::table(), scope.raw(), |ie_type| scope.count(ie_type));
    *scope.order_mut() = if order == ordered { Vec::new() } else { order };
}

/// An entry of a row in the tree of its scope: a value of its field, or an IE that the
/// scope keeps as octets, by its position among them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Entry {
    Value(usize),
    Kept(usize),
}

/// The entries of the row of `ie_type`, as the tree of the scope lists them: in the order
/// of the wire as far as the scope keeps one, then the values, then the kept IEs.
pub(crate) fn each_entry<S: Scope>(scope: &S, ie_type: u16, mut each: impl FnMut(Entry)) {
    let (raws, count) = (scope.raw(), scope.count(ie_type));
    let (mut values, mut kept) = (0, 0);
    for placed in scope.order() {
        match *placed {
            Placed::Field(of) if of == ie_type && values < count => {
                each(Entry::Value(values));
                values += 1;
            }
            Placed::Raw => {
                if raws.get(kept).is_some_and(|ie| ie.ie_type == ie_type) {
                    each(Entry::Kept(kept));
                }
                kept += 1;
            }
            Placed::Field(_) => {}
        }
    }
    (values..count).for_each(|nth| each(Entry::Value(nth)));
    for (at, ie) in raws.iter().enumerate().skip(kept) {
        if ie.ie_type == ie_type {
            each(Entry::Kept(at));
        }
    }
}

/// The position of each value of `row` in the list of the row in the tree of the scope,
/// which keeps IEs of the row as octets: the tree lists the values and those IEs.
pub(crate) fn value_positions<S: Scope>(scope: &S, row: &Row) -> Vec<usize> {
    let mut positions = Vec::new();
    positions_of(scope, row, |entry, position| {
        if let Entry::Value(_) = entry {
            positions.push(position);
        }
    });
    positions
}

/// The same of each IE that the scope keeps as octets, by its position in `raw`: `None`
/// for one of no row too.
pub(crate) fn kept_positions<S: Scope>(scope: &S) -> Vec<Option<usize>> {
    let raws = scope.raw();
    let mut positions = alloc::vec![None; raws.len()];
    let kept = |row: &&Row| raws.iter().any(|ie| ie.ie_type == row.ie_type);
    for row in S::table().rows.iter().filter(kept) {
        let mut of_row = Vec::new();
        let entries = positions_of(scope, row, |entry, position| {
            if let Entry::Kept(at) = entry {
                of_row.push((at, position));
            }
        });
        let listed = row.is_list() || entries > 1;
        for (at, position) in of_row {
            positions[at] = listed.then_some(position);
        }
    }
    positions
}

/// Each entry of `row` with its position in the tree, and how many there are.
fn positions_of<S: Scope>(scope: &S, row: &Row, mut each: impl FnMut(Entry, usize)) -> usize {
    let mut entries = 0;
    each_entry(scope, row.ie_type, |entry| {
        each(entry, entries);
        entries += 1;
    });
    entries
}

/// More than the rows of a table, which the table macro asserts: the counts of each row
/// that the encoder keeps on the stack.
pub(crate) const MAX_ROWS: usize = 64;

/// Write `scope`: in the order that it keeps, with the values that were added since in
/// the places of their rows, or in the order of its table, where an IE that it keeps as
/// octets follows the values of its row, and one of no row comes last.
pub(crate) fn encode_scope<S: Scope>(scope: &S, out: &mut Vec<u8>) -> Result<(), Error> {
    let order = scope.order();
    let table = S::table();
    if order.is_empty() {
        let raws = scope.raw();
        let of_row = |ie: &&RawIe| table.row_of(ie.ie_type).is_some();
        match raws.iter().any(|ie| of_row(&ie)) {
            false => scope.encode_fields(out)?,
            true => {
                for row in table.rows {
                    let mut nth = 0;
                    while scope.emit(row.ie_type, nth, out)? {
                        nth += 1;
                    }
                    for ie in raws.iter().filter(|ie| ie.ie_type == row.ie_type) {
                        ie.encode(out)?;
                    }
                }
            }
        }
        for ie in raws.iter().filter(|ie| !of_row(ie)) {
            ie.encode(out)?;
        }
        return Ok(());
    }
    // How many values of each row the order has: those after are added.
    let mut ordered = [0usize; MAX_ROWS];
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
    let mut emitted = [0usize; MAX_ROWS];
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

#[cfg(test)]
mod tests {
    use super::*;

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
