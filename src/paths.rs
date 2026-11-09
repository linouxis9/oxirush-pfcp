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
//! The tree of a message is on the engine of oxirush-utils ([`tree`](mod@crate::tree)): a
//! scope is an object whose members are its IEs by the names of its table, in the order of
//! the table; a row that is a list is a list, in the order of the wire. A path writes a
//! `/` of a name `~1`, as a JSON pointer does: `/pfcp/APN~1DNN`. An IE that the
//! scope keeps as octets is `{"octets": ...}` under the name of its row, of its type, or
//! its number.
//!
//! A tree is the message in the order of its tables: a message whose IEs came in another
//! order (§8.1.2 has a receiver take them in any order) has the same tree as one in the
//! order of its tables, and from any tree, in whatever order its rows are written, the
//! crate encodes the latter. The octets keep the order of the wire: decoding and encoding
//! them is byte-exact.
//!
//! A path names the members of the tree in any case, a list the positions of its entries,
//! and `*` each entry. `/pfcp` stands for the IEs of the message, and the path of a
//! deviation of `check()` is one of them. An IE of no row of its table, a vendor's or one
//! of a later release, goes by its number or the name of its type. What a message lacks
//! selects nothing, whatever the path names below it: a misspelt name is an error where
//! the value is there, and is not told below what is not. [`set`] adds the grouped IEs
//! and the lists on its way, an entry at the position of a list's length, and writes a
//! value that a message lacks whole.

use alloc::string::String;
use alloc::vec::Vec;

use oxirush_utils::tree::{
    Absent, Edit, ErrorKind, Map, Members, Next, Place, Reading, Refused, Root, Step,
};

use oxirush_utils::tree;
use oxirush_utils::tree::Value;

use crate::ie::{Placed, RawIe};
use crate::message::{MESSAGE_TYPES, MessageTypeInfo};
use crate::registry::{Form, IE_TYPES, IeTypeInfo, ie_type_info, members_below};
use crate::table::{Entry, FieldValues, Row, Scope, Table, each_entry, keep_order};

/// The tree hook of a scope, which the table macro writes.
pub(crate) trait TreeScope {
    /// The tree of the `nth` value of the field of `ie_type`.
    fn field_tree(&self, ie_type: u16, nth: usize) -> Option<Value>;
    /// Read a value of the field of `ie_type` from its tree, and add it to the field.
    fn read_field(
        &mut self,
        ie_type: u16,
        value: &Value,
        reading: &mut Reading,
    ) -> Result<(), Refused>;
}

/// The tree of the `nth` value of a field.
pub(crate) fn field_tree<T: tree::Tree, F: FieldValues<T>>(field: &F, nth: usize) -> Option<Value> {
    field.values().get(nth).map(tree::Tree::to_tree)
}

/// Read a value of a field from its tree, and add it to the field.
pub(crate) fn read_field<T: tree::Tree, F: FieldValues<T>>(
    field: &mut F,
    value: &Value,
    reading: &mut Reading,
) -> Result<(), Refused> {
    field.add(T::from_tree(value, reading)?);
    Ok(())
}

/// Put `value` under `name`: a list for a row that is a list, and for an IE that is
/// there more times than its row allows.
fn put(members: &mut Map, name: String, list: bool, value: Value) {
    match members.get_mut(&name) {
        Some(Value::Array(entries)) => entries.push(value),
        Some(single) => {
            let first = core::mem::take(single);
            *single = Value::Array(alloc::vec![first, value]);
        }
        None => {
            let value = if list {
                Value::Array(alloc::vec![value])
            } else {
                value
            };
            members.insert(name, value);
        }
    }
}

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

/// The tree of a scope, in the order of its table. The values of a row, and the IEs of
/// its type that the scope keeps as octets, keep the order of the wire among themselves
/// (§7.6.10); the IEs of no row come last, in the order of the wire.
pub(crate) fn scope_to_tree<S: Scope + TreeScope>(scope: &S) -> Value {
    let table = S::table();
    let raws = scope.raw();
    let mut members = Map::new();
    for row in table.rows {
        let list = row.is_list();
        each_entry(scope, row.ie_type, |entry| {
            let value = match entry {
                Entry::Value(nth) => scope.field_tree(row.ie_type, nth),
                Entry::Kept(at) => Some(raw_tree(&raws[at])),
            };
            if let Some(value) = value {
                put(&mut members, row.name.into(), list, value);
            }
        });
    }
    for ie in raws.iter().filter(|ie| table.row_of(ie.ie_type).is_none()) {
        put(
            &mut members,
            crate::tree_name(ie.ie_type, Some(table)),
            false,
            raw_tree(ie),
        );
    }
    Value::Object(members)
}

/// Whether an entry is written as octets.
fn is_octets(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|members| tree::member(members, "octets").is_some())
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

/// What a reading names an IE of no row by: the name of its type, or `IE` for a type of
/// no release.
fn label_of(ie_type: u16) -> &'static str {
    ie_type_info(ie_type).map_or("IE", |info| info.name)
}

/// The error of `from_value` of a message in `tree`, at the path of the place that it
/// refuses, which [`select`] takes: each name as the tree writes it, a `/` of it as `~1`,
/// and `/pfcp` for the IEs of the message. A reading names what it reads by the names of
/// the types, joined by `/`, which are matched with the names of the tree one by one.
pub(crate) fn located(tree: &Value, error: tree::Error) -> tree::Error {
    let mut path = String::new();
    let (mut place, mut rest) = (Some(tree), error.at());
    while !rest.is_empty() {
        // The longest of the names that the rest starts with, that the place has.
        let ends = rest
            .match_indices('/')
            .map(|(end, _)| end)
            .chain([rest.len()]);
        let named = |end: usize| -> Option<(String, &Value)> {
            let label = &rest[..end];
            match place? {
                Value::Object(members) => members
                    .iter()
                    .find(|(name, _)| names(name, label))
                    .map(|(name, held)| (name.clone(), held)),
                Value::Array(entries) => {
                    Some((label.into(), entries.get(label.parse::<usize>().ok()?)?))
                }
                _ => None,
            }
        };
        let found = ends
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .find_map(|end| Some((end, named(end)?)));
        let Some((end, (name, held))) = found else {
            // What the tree does not have, as a member that is missing: the names as read.
            for name in rest.split('/') {
                path.push('/');
                path.push_str(&tree::escape(name));
            }
            break;
        };
        match path.is_empty() && tree::same_name(&name, "ies") {
            true => path.push_str("/pfcp"),
            false => {
                path.push('/');
                path.push_str(&tree::escape(&name));
            }
        }
        place = Some(held);
        rest = rest[end..].strip_prefix('/').unwrap_or_default();
    }
    tree::Error::new(error.kind(), path, error.reason())
}

/// Whether the member `name` of a tree is what a reading names `label`: the same name, or
/// an IE of no row by its number or the name of its type.
fn names(name: &str, label: &str) -> bool {
    tree::same_name(name, label)
        || type_of_name(name).is_some_and(|ie_type| label_of(ie_type) == label)
}

/// The IE type that a name is, where its scope has no row of that name: the name of an IE
/// type of Table 8.1.2-1, or a number.
fn type_of_name(name: &str) -> Option<u16> {
    if let Ok(number) = name.parse::<u16>() {
        return Some(number);
    }
    IE_TYPES
        .iter()
        .find(|info| tree::same_name(info.name, name))
        .map(|info| info.ie_type)
}

/// A scope from its tree, which encodes in the order of its table whatever the order in
/// which the tree writes its rows: the values of a row, and the IEs of its type written
/// as octets, in the order written; the IEs of no row last.
pub(crate) fn scope_from_tree<S: Scope + TreeScope>(
    value: &Value,
    reading: &mut Reading,
) -> Result<S, Refused> {
    let Some(members) = value.as_object() else {
        return Err(reading.mismatch("an object of IEs", value));
    };
    let table = S::table();
    let names: Vec<&str> = table.rows.iter().map(|row| row.name).collect();
    let mut scope = S::default();
    // Each IE where its row puts it: the position of the row, or after them all.
    let mut placed: Vec<(usize, Placed)> = Vec::new();
    let mut kept: Vec<(usize, RawIe)> = Vec::new();
    let mut rows_written: Vec<(usize, &str)> = Vec::new();
    for (written, held) in members {
        let (at, ie_type) = written_ie(table, &names, written, &mut rows_written, reading)?;
        let row = at.map(|at| &table.rows[at]);
        let octets = match held {
            Value::Array(entries) => entries.iter().all(is_octets),
            held => is_octets(held),
        };
        let label = row.map_or_else(|| label_of(ie_type), |row| row.name);
        let read = reading.within(label, held, |held, reading| {
            if row.is_none() && !octets {
                let why = alloc::format!(
                    "{written:?} is an IE of no row of {}, which is written by its octets: {{\"octets\": ...}}",
                    table.name
                );
                return Err(reading.refuse(ErrorKind::Value, why));
            }
            read_ies(&mut scope, row, ie_type, held, reading)
        })?;
        let position = at.unwrap_or(usize::MAX);
        for ie in read {
            match ie {
                Some(ie) => {
                    kept.push((position, ie));
                    placed.push((position, Placed::Raw));
                }
                None => placed.push((position, Placed::Field(ie_type))),
            }
        }
    }
    // The order of the table; within a row, and after the rows, the order written.
    placed.sort_by_key(|(position, _)| *position);
    kept.sort_by_key(|(position, _)| *position);
    scope.raw_mut().extend(kept.into_iter().map(|(_, ie)| ie));
    keep_order(
        &mut scope,
        placed.into_iter().map(|(_, placed)| placed).collect(),
    );
    Ok(scope)
}

/// The row, by its position, and the IE type that a name of the tree of a scope writes:
/// the name of a row, written once, or of an IE type of no row, or its number.
fn written_ie<'w>(
    table: &Table,
    names: &[&str],
    written: &'w str,
    rows_written: &mut Vec<(usize, &'w str)>,
    reading: &mut Reading,
) -> Result<(Option<usize>, u16), Refused> {
    let at = tree::named(names, written);
    let Some(ie_type) = at
        .map(|at| table.rows[at].ie_type)
        .or_else(|| type_of_name(written))
    else {
        return Err(reading.refuse(ErrorKind::NoSuchMember, no_such_ie(table, names, written)));
    };
    match at {
        Some(at) => {
            if let Some((_, before)) = rows_written.iter().find(|(row, _)| *row == at) {
                let row = table.rows[at].name;
                let why = alloc::format!("{written:?} and {before:?} are both the row {row}");
                return Err(reading.refuse(ErrorKind::Value, why));
            }
            rows_written.push((at, written));
        }
        None => {
            if let Some(row) = table.row_of(ie_type) {
                let why = alloc::format!(
                    "{written:?} is the IE type of the row {}, which goes by its name",
                    row.name
                );
                return Err(reading.refuse(ErrorKind::NoSuchMember, why));
            }
        }
    }
    Ok((at, ie_type))
}

/// The IEs that a tree writes under the name of `row`, or of an IE type of no row, in the
/// order written: `None` for a value, which the scope takes, and the IEs written as octets.
fn read_ies<S: TreeScope>(
    scope: &mut S,
    row: Option<&Row>,
    ie_type: u16,
    held: &Value,
    reading: &mut Reading,
) -> Result<Vec<Option<RawIe>>, Refused> {
    let list = row.is_some_and(Row::is_list);
    let mut read = Vec::new();
    let mut entry = |value: &Value, reading: &mut Reading| -> Result<(), Refused> {
        if is_octets(value) || row.is_none() {
            read.push(Some(read_raw(ie_type, value, reading)?));
            return Ok(());
        }
        // A row that is there once has one value; the IEs of its type that the scope keeps
        // as octets come before or after it.
        if !list && read.iter().any(Option::is_none) {
            return Err(reading.refuse(
                ErrorKind::Value,
                "its table has it once: a repetition is written by its octets",
            ));
        }
        scope.read_field(ie_type, value, reading)?;
        read.push(None);
        Ok(())
    };
    match held {
        Value::Array(_) => {
            reading.list(held, &mut entry)?;
        }
        _ if list => return Err(reading.mismatch("a list", held)),
        single => entry(single, reading)?,
    }
    Ok(read)
}

/// Why a name is no IE of a table: the nearest names, or the row whose role it is.
fn no_such_ie(table: &Table, names: &[&str], written: &str) -> String {
    if let Some(row) = table.rows.iter().find(|row| {
        row.roles
            .iter()
            .any(|role| tree::same_name(role.name, written))
    }) {
        return alloc::format!(
            "{written:?} is a row that the wire does not tell apart from the others of {}: they are written as {}",
            row.name,
            row.name
        );
    }
    let near = tree::nearest(names, written, 3);
    alloc::format!(
        "{written:?} is no IE of {}{}",
        table.name,
        if near.is_empty() {
            String::new()
        } else {
            alloc::format!(": the nearest are {}", near.join(", "))
        }
    )
}

/// What the tree of a field of a value may hold below it ([`Field::BELOW`](crate::Field)),
/// which a path is checked against at a field that is there: the members that its object
/// may have, also where its tree writes it as a scalar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Below {
    /// Nothing: a flag, or a field whose tree is a scalar.
    Scalar,
    /// The members of an object, each with what it may hold below it, or a scalar: the
    /// member that it names, if any. A value without spare bits is its `value`, and one
    /// with them `{"value": ..., "Spare": ...}`; an IPv4 or IPv6 address is its `Address`,
    /// another `{"Address Type": ..., "Address": ...}`; an identity of digits or text is
    /// none of them, one of other octets `{"octets": ...}`.
    Object(
        Option<&'static str>,
        &'static [(&'static str, &'static Below)],
    ),
}

/// What an IE that a scope keeps as its octets may hold below it, and each entry of a list
/// of them.
const KEPT: Below = Below::Object(
    None,
    &[
        ("octets", &Below::Scalar),
        ("length", &Below::Scalar),
        ("Enterprise ID", &Below::Scalar),
    ],
);

impl Below {
    /// What the member `name` of the object may hold below it.
    fn member(&self, name: &str) -> Option<&'static Below> {
        let Self::Object(_, members) = self else {
            return None;
        };
        members
            .iter()
            .find(|(member, _)| tree::same_name(member, name))
            .map(|(_, below)| *below)
    }
}

/// What the tree of the field `name` of a value of `info` may hold below it.
fn below_member(info: &IeTypeInfo, name: &str) -> &'static Below {
    members_below(info.ie_type)
        .iter()
        .find(|(member, _)| tree::same_name(member, name))
        .map_or(&Below::Scalar, |(_, below)| below)
}

/// The rules of the paths of PFCP, which `select` and `set` share: `/pfcp` is short for
/// the IEs of the message, and each segment is checked against the tables and the members
/// of the trees of the values ([`IeTypeInfo::members`]), then the tree is walked by the
/// plain rule. A row that a scope lacks, an IE of no row by its number or the name of its
/// type, and a member that a value lacks, select nothing, where another name is an error;
/// below what is not there, nothing is selected, whatever the path names. A value or a
/// field that its tree writes as a scalar has the member that the scalar is, and the
/// others of its object, which select nothing; `set` writes the object to give one of them
/// a value.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Paths;

/// What [`Paths`] knows of a place of the tree of a message: the tables of the IEs that it
/// holds, or the members of the value that it is.
#[derive(Clone, Copy, Default)]
pub(crate) enum Of {
    /// Nothing: a place of the plain rule.
    #[default]
    Nothing,
    /// A message.
    Message(&'static MessageTypeInfo),
    /// The IEs of a message or of a grouped IE, of the table of their place.
    Ies(&'static Table),
    /// The values of a row, as a row that is a list has them, and one that is there more
    /// times than it allows.
    List(&'static Row),
    /// A value of an IE type that is no grouped IE: the members that its tree may have.
    Value(&'static IeTypeInfo),
    /// A field of a value, or of the header, an entry of a list of them, or a member of a
    /// field: what its tree may hold below it.
    Below(&'static Below),
}

impl core::fmt::Debug for Of {
    /// The names of the tables and the types, not their rows.
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::Nothing => f.write_str("Nothing"),
            Self::Message(info) => f.debug_tuple("Message").field(&info.name()).finish(),
            Self::Ies(table) => f.debug_tuple("Ies").field(&table.id).finish(),
            Self::List(row) => f.debug_tuple("List").field(&row.name).finish(),
            Self::Value(info) => f.debug_tuple("Value").field(&info.name).finish(),
            Self::Below(below) => f.debug_tuple("Below").field(below).finish(),
        }
    }
}

/// The row of `name` of `table`, as the tree names it.
fn row_named(table: &'static Table, name: &str) -> Option<&'static Row> {
    table
        .rows
        .iter()
        .find(|row| tree::same_name(row.name, name))
}

/// What `value` is, of a row: the list of its values, or its value.
fn of_row(row: &'static Row, value: Option<&Value>) -> Of {
    match value.map_or(row.is_list(), Value::is_array) {
        true => Of::List(row),
        false => of_value(row, value),
    }
}

/// What `value` is, of a row: the IEs of a grouped IE, of the table of its place, or a
/// value with the flags and fields of its figure. An IE that the scope keeps as its octets
/// has none of them.
fn of_value(row: &'static Row, value: Option<&Value>) -> Of {
    let Some(info) = ie_type_info(row.ie_type) else {
        return Of::Nothing;
    };
    match row.content {
        _ if value.is_some_and(is_octets) => Of::Below(&KEPT),
        Some(table) => Of::Ies(table),
        None => Of::Value(info),
    }
}

/// The IE type of no row of `table` that `name` writes, as [`scope_from_tree`] reads it:
/// its number, or the name of its type.
fn of_no_row(table: &Table, name: &str) -> Option<u16> {
    let ie_type = type_of_name(name)?;
    table.row_of(ie_type).is_none().then_some(ie_type)
}

impl Paths {
    /// At a value or a field that its tree writes as a scalar: the member that the scalar
    /// is selects it, another member of its object selects nothing, or, for an edit, has
    /// the scalar opened into its object, with the scalar as its member, and another name
    /// is none, in the words of [`Message::from_tree`](crate::Message::from_tree).
    fn at_scalar<'v>(
        &self,
        place: &Place<'v, Of>,
        scalar: &Value,
        segment: &str,
        next: &mut Next<'v, Of>,
    ) -> Result<Step<Of>, tree::Error> {
        let of = *place.shape();
        let (is, member) = match of {
            Of::Value(info) => {
                let known = info
                    .members
                    .iter()
                    .any(|member| tree::same_name(member, segment));
                (info.scalar, known.then(|| below_member(info, segment)))
            }
            Of::Below(below @ Below::Object(is, _)) => (*is, below.member(segment)),
            _ => return Ok(Step::Plain),
        };
        let Some(member) = member else {
            let reason = no_such_member(of, segment).unwrap_or_default();
            return Err(tree::Error::new(ErrorKind::NoSuchMember, "", reason));
        };
        if is.is_some_and(|is| tree::same_name(is, segment)) {
            next.stay(place, Of::Below(member));
        } else if next.edit() == Some(Edit::Open) {
            let mut members = Map::new();
            if let Some(is) = is {
                members.insert(is.into(), scalar.clone());
            }
            next.open(place, Value::Object(members));
        }
        Ok(Step::Taken)
    }
}

impl tree::Family for Paths {
    type Shape = Of;

    fn root(&self) -> Root<'_> {
        Root::new("pfcp", &["ies"], false)
    }

    /// What is not there selects nothing, whatever the path names below it: a row or a
    /// member that a value lacks, `null`, an entry past the end of a list. An edit has
    /// nothing to edit there: it opens the rows and the entries on its way ([`room`]), and
    /// writes a value that a message lacks whole. At a scalar, as [`Paths::at_scalar`] has
    /// it.
    fn step<'v>(
        &self,
        place: &Place<'v, Of>,
        segment: &str,
        next: &mut Next<'v, Of>,
    ) -> Result<Step<Of>, tree::Error> {
        let shape = *place.shape();
        let list = place.value().is_some_and(Value::is_array);
        if next.edit() == Some(Edit::Open)
            && let Some(opened) = room(place.value(), shape, list, segment)
        {
            next.open(place, opened);
            return Ok(Step::Taken);
        }
        let Some(value) = place.value().filter(|value| !value.is_null()) else {
            if next.edit() != Some(Edit::Set) {
                return Ok(Step::Taken);
            }
            let reason = "the path goes on below what the tree does not have: a value that a \
                          message lacks is written whole";
            return Err(tree::Error::new(ErrorKind::NothingSelected, "", reason));
        };
        match shape {
            // An IE of no row, by its number or the name of its type: each member that
            // names it so, or the name that the tree prints, where `set` adds it.
            Of::Ies(table) if row_named(table, segment).is_none() => {
                let Some(ie_type) = of_no_row(table, segment) else {
                    return Ok(Step::Plain);
                };
                let mut found = false;
                for (written, value) in value.as_object().into_iter().flatten() {
                    if row_named(table, written).is_none()
                        && of_no_row(table, written) == Some(ie_type)
                    {
                        next.member(written, value, Of::Below(&KEPT));
                        found = true;
                    }
                }
                if !found {
                    let name = crate::tree_name(ie_type, Some(table));
                    next.absent(&name, Of::Nothing);
                }
                Ok(Step::Taken)
            }
            _ if !value.is_object() && !value.is_array() => {
                self.at_scalar(place, value, segment, next)
            }
            _ => Ok(Step::Plain),
        }
    }

    /// The message of the name that the tree says: a message type of no table, which the
    /// tree says by its number, has its IEs as octets.
    fn start(&self, tree: &Value, _rooted: bool) -> Of {
        let name = tree
            .as_object()
            .and_then(|members| tree::member(members, "message"))
            .and_then(|(_, kind)| kind.as_str());
        let info = name.and_then(|name| {
            MESSAGE_TYPES
                .iter()
                .find(|info| tree::same_name(info.name(), name))
        });
        info.map_or(Of::Nothing, Of::Message)
    }

    fn member(&self, shape: &Of, name: &str, value: Option<&Value>) -> Of {
        if let Of::Ies(table) = *shape
            && let Some(row) = row_named(table, name)
        {
            return of_row(row, value);
        }
        match *shape {
            Of::Message(info) if tree::same_name(name, "ies") => Of::Ies(info.table),
            // The other members of the header are scalars.
            Of::Message(_) => Of::Below(&Below::Scalar),
            Of::Ies(_) => Of::Below(&KEPT),
            Of::Value(info)
                if info
                    .members
                    .iter()
                    .any(|member| tree::same_name(member, name)) =>
            {
                Of::Below(below_member(info, name))
            }
            Of::Below(below) => below.member(name).map_or(Of::Nothing, Of::Below),
            _ => Of::Nothing,
        }
    }

    fn entry(&self, shape: &Of, value: Option<&Value>) -> Of {
        match *shape {
            Of::List(row) => of_value(row, value),
            // An entry of a list of a field is of the kind of the field.
            Of::Below(below) => Of::Below(below),
            _ => Of::Nothing,
        }
    }

    fn absent(&self, shape: &Of, name: &str) -> Absent<Of> {
        let there = match *shape {
            Of::Message(_) => crate::message::forms::NAMES
                .iter()
                .any(|member| tree::same_name(member, name)),
            Of::Ies(table) => row_named(table, name).is_some(),
            Of::Value(info) => info
                .members
                .iter()
                .any(|member| tree::same_name(member, name)),
            Of::Below(below) => below.member(name).is_some(),
            _ => false,
        };
        match (there, no_such_member(*shape, name)) {
            (true, _) => Absent::Optional(self.member(shape, name, None)),
            (false, Some(reason)) => {
                Absent::Refused(tree::Error::new(ErrorKind::NoSuchMember, "", reason))
            }
            (false, None) => Absent::Unknown,
        }
    }
}

/// Why `name` is nothing at a place of `of`, in the words of
/// [`Message::from_tree`](crate::Message::from_tree): the row whose IE type it is, which
/// goes by its name, the nearest names of the table, or the members of the value. `None`
/// for a place that the paths know nothing of.
fn no_such_member(of: Of, name: &str) -> Option<String> {
    let members = |members: &[&str]| match members {
        [] => alloc::format!("{name:?} is not a member that its type has: it has none"),
        _ => alloc::format!(
            "{name:?} is not a member that its type has: it has {}",
            members.join(", ")
        ),
    };
    Some(match of {
        Of::Ies(table) => {
            if let Some(row) = type_of_name(name).and_then(|ie_type| table.row_of(ie_type)) {
                return Some(alloc::format!(
                    "{name:?} is the IE type of the row {}, which goes by its name",
                    row.name
                ));
            }
            let names: Vec<&str> = table.rows.iter().map(|row| row.name).collect();
            no_such_ie(table, &names, name)
        }
        Of::Message(_) => members(crate::message::forms::NAMES),
        Of::Value(info) => members(info.members),
        Of::Below(Below::Object(_, below)) => {
            members(&below.iter().map(|(member, _)| *member).collect::<Vec<_>>())
        }
        _ => return None,
    })
}

/// What an edit opens at a place so that `segment` goes into it: a list with one more
/// entry for the position of its length, empty, and a message without IEs, or an object
/// of IEs without the list or the grouped IE of the row, or with it `null`, with them
/// empty. `None` where the place has what the segment names, or is not there to open, as
/// its holder is opened first.
fn room(value: Option<&Value>, of: Of, list: bool, segment: &str) -> Option<Value> {
    let lacks = |members: &Map, name: &str| {
        tree::member(members, name).is_none_or(|(_, held)| held.is_null())
    };
    match (value?, of) {
        (Value::Array(entries), _) if list && tree::position(segment) == Some(entries.len()) => {
            // An IE is an object that the edit fills; a field, a value that it writes.
            let entry = match of {
                Of::List(_) => Value::Object(Map::new()),
                _ => Value::Null,
            };
            let mut grown = entries.clone();
            grown.push(entry);
            Some(Value::Array(grown))
        }
        (Value::Object(members), Of::Message(_))
            if tree::same_name(segment, "ies") && lacks(members, "ies") =>
        {
            let name = tree::member(members, "ies").map_or("ies", |(name, _)| name);
            let mut members = members.clone();
            members.insert(name.into(), Value::Object(Map::new()));
            Some(Value::Object(members))
        }
        (Value::Object(members), Of::Ies(table)) if lacks(members, segment) => {
            let row = row_named(table, segment)?;
            let empty = match (row.is_list(), ie_type_info(row.ie_type)?.form) {
                (false, Form::Grouped) => Value::Object(Map::new()),
                (false, _) => return None,
                _ => Value::Array(Vec::new()),
            };
            let name = tree::member(members, segment).map_or(row.name, |(name, _)| name);
            let mut members = members.clone();
            members.insert(name.into(), empty);
            Some(Value::Object(members))
        }
        _ => None,
    }
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
    tree::select_in(&Paths, tree, path)
}

/// The row of a table and the IE type of the IE at `path` in the tree of a message, or of
/// the list of them that a row is: the row that the tables of the message name at the
/// path, which the message may lack, as may the grouped IEs above it. `None` for a path of
/// the header, of a member of a value, or of an IE of no row.
///
/// ```
/// use oxirush_pfcp::{paths, tree};
///
/// let tree = tree!({"message": "PFCP Heartbeat Request", "Sequence Number": 1, "ies": {"Recovery Time Stamp": 7}});
/// let (row, info) = paths::row_at(&tree, "/pfcp/Source IP Address")?.unwrap();
/// assert_eq!((row.name, info.ie_type), ("Source IP Address", 192));
/// assert!(paths::row_at(&tree, "/Sequence Number")?.is_none());
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
    select(tree, path)?;
    let row = match tree::Family::start(&Paths, tree, true) {
        Of::Message(info) => row_of_path(info.table, &tree::segments(path)?),
        _ => None,
    };
    Ok(row.and_then(|row| Some((row, ie_type_info(row.ie_type)?))))
}

/// The row that `segments` name from the message of `table`: of the IEs of the message,
/// `/pfcp` or `/ies`, then a row of each table on the way, an entry of a list or `*` after
/// a row, and a row of the table of its place after a grouped IE.
fn row_of_path(mut table: &'static Table, segments: &[String]) -> Option<&'static Row> {
    let (ies, segments) = segments.split_first()?;
    if !tree::same_name(ies, "pfcp") && !tree::same_name(ies, "ies") {
        return None;
    }
    let (mut row, mut entry): (Option<&'static Row>, bool) = (None, false);
    for segment in segments {
        let entered = segment == "*" || tree::position(segment).is_some();
        match row {
            Some(_) if entered && !entry => entry = true,
            Some(at) => {
                table = at.content?;
                row = Some(row_named(table, segment)?);
                entry = false;
            }
            None => row = Some(row_named(table, segment)?),
        }
    }
    row
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
    let mut edited = tree.clone();
    tree::open_in(&Paths, &mut edited, path)?;
    tree::set_in(&Paths, &mut edited, path, value)?;
    *tree = edited;
    Ok(())
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
        let sequence = Paths.member(&message, "Sequence Number", None);
        assert_eq!(alloc::format!("{sequence:?}"), "Below(Scalar)");
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
    }
}
