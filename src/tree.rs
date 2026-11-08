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

//! The tree of a message, on the engine of oxirush-utils: a scope is an object whose
//! members are its IEs by the names of its table, in the order of the table; a row that
//! is a list is a list, in the order of the wire. An IE that the scope keeps as octets is
//! `{"octets": ...}` under the name of its row, of its type, or its number.
//!
//! A tree is the message in the order of its tables: a message whose IEs came in another
//! order (§8.1.2 has a receiver take them in any order) has the same tree as one in the
//! order of its tables, and from any tree, in whatever order its rows are written, the
//! crate encodes the latter. The octets keep the order of the wire: decoding and encoding
//! them is byte-exact.

use alloc::string::String;
use alloc::vec::Vec;

use oxirush_utils::tree::{
    Absent, Edit, ErrorKind, Map, Members, Next, Place, Reading, Refused, Root, Step,
};

/// The engine of the trees, oxirush-utils' `tree`, and its macro `tree!`, which writes a
/// tree as JSON is written.
pub use oxirush_utils::tree;
/// A tree.
pub use oxirush_utils::tree::Value;

use crate::ie::{Placed, RawIe};
use crate::message::{MESSAGE_TYPES, MessageTypeInfo};
use crate::registry::{Form, IE_TYPES, IeTypeInfo, ie_type_info, members_below};
use crate::table::{Entry, FieldValues, Repeat, Row, Scope, Table, each_entry, keep_order};

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
        let list = row.repeat != Repeat::Once;
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
    let octets = reading.member(&read, 0, |value, reading| reading.octets(value))?;
    let length = reading.optional(&read, 1, |value, reading| reading.unsigned(value, 0, 65535))?;
    let enterprise =
        reading.optional(&read, 2, |value, reading| reading.unsigned(value, 0, 65535))?;
    Ok(RawIe {
        ie_type,
        enterprise_id: enterprise.map(|id| id as u16),
        length: length.map(|length| length as u16),
        octets: octets.into(),
    })
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
        let label: &'static str = row.map_or("IE", |row| row.name);
        let read = reading.within(label, held, |held, reading| {
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
    let list = row.is_some_and(|row| row.repeat != Repeat::Once);
    let mut read = Vec::new();
    let mut entry = |value: &Value, reading: &mut Reading| -> Result<(), Refused> {
        if is_octets(value) {
            read.push(Some(read_raw(ie_type, value, reading)?));
            return Ok(());
        }
        if row.is_none() {
            return Err(reading.refuse(
                ErrorKind::Value,
                "an IE that its table does not have is written by its octets: {\"octets\": ...}",
            ));
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
/// which a path is checked against at a field that a value lacks, below an entry past the
/// end of a list, and at a field written as a scalar.
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
    /// The entries of a list, with what each may hold below it.
    List(&'static Below),
}

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
/// plain rule. A row that a scope lacks, and a member that a value lacks, select nothing,
/// where another name is an error, also below what is not there. A value or a field that
/// its tree writes as a scalar has the member that the scalar is, and the others of its
/// object, which select nothing; `set` writes the object to give one of them a value.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Paths;

/// What [`Paths`] knows of a place of the tree of a message: the tables of the IEs that it
/// holds, or the members of the value that it is.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Shape(Of);

#[derive(Clone, Copy, Default)]
enum Of {
    /// Nothing: a place of the plain rule.
    #[default]
    Nothing,
    /// A message.
    Message(&'static MessageTypeInfo),
    /// The IEs of a message or of a grouped IE, of the tables of its content: one, or each
    /// of those of a grouped IE that has other content in other places, which the tree does
    /// not tell apart.
    Ies(&'static [&'static Table]),
    /// The values of an IE type, as a row that is a list has them, and an IE that is there
    /// more times than its row allows.
    List(&'static IeTypeInfo),
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
            Self::Ies(tables) => {
                let ids = tables.iter().map(|table| table.id);
                f.debug_tuple("Ies")
                    .field(&ids.collect::<Vec<_>>())
                    .finish()
            }
            Self::List(info) => f.debug_tuple("List").field(&info.name).finish(),
            Self::Value(info) => f.debug_tuple("Value").field(&info.name).finish(),
            Self::Below(below) => f.debug_tuple("Below").field(below).finish(),
        }
    }
}

/// The row of `name` of `tables`, as the tree names it.
fn row_named(tables: &[&'static Table], name: &str) -> Option<&'static Row> {
    let mut rows = tables.iter().flat_map(|table| table.rows.iter());
    rows.find(|row| tree::same_name(row.name, name))
}

/// What `value` is, of a row: the list of its values, or its value.
fn of_row(row: &Row, value: Option<&Value>) -> Of {
    let Some(info) = ie_type_info(row.ie_type) else {
        return Of::Nothing;
    };
    match value.map_or(row.repeat != Repeat::Once, Value::is_array) {
        true => Of::List(info),
        false => of_value(info, value),
    }
}

/// What `value` is, of an IE type: the IEs of a grouped IE, or a value with the flags and
/// fields of its figure. An IE that the scope keeps as its octets has none of them.
fn of_value(info: &'static IeTypeInfo, value: Option<&Value>) -> Of {
    match info.form {
        _ if value.is_some_and(is_octets) => Of::Nothing,
        Form::Grouped => Of::Ies(info.tables),
        _ => Of::Value(info),
    }
}

impl Paths {
    /// At a value or a field that its tree writes as a scalar: the member that the scalar
    /// is selects it, another member of its object selects nothing, or, for an edit, has
    /// the scalar opened into its object, with the scalar as its member, and another name
    /// is none.
    fn at_scalar<'v>(
        &self,
        place: &Place<'v, Shape>,
        scalar: &Value,
        segment: &str,
        next: &mut Next<'v, Shape>,
    ) -> Result<Step<Shape>, tree::Error> {
        let (is, member) = match place.shape().0 {
            Of::Value(info) => {
                let known = info
                    .members
                    .iter()
                    .any(|member| tree::same_name(member, segment));
                let member = known.then(|| Shape(Of::Below(below_member(info, segment))));
                (info.scalar, member)
            }
            Of::Below(below @ Below::Object(is, _)) => (
                *is,
                below.member(segment).map(|inside| Shape(Of::Below(inside))),
            ),
            _ => return Ok(Step::Plain),
        };
        if is.is_some_and(|is| tree::same_name(is, segment)) {
            next.stay(place, member.unwrap_or(Shape(Of::Below(&Below::Scalar))));
            return Ok(Step::Taken);
        }
        let Some(inside) = member else {
            let reason = alloc::format!("{segment:?} is no member of this value, of either form");
            return Err(tree::Error::new(ErrorKind::NoSuchMember, "", reason));
        };
        match next.edit() {
            Some(Edit::Open) => {
                let mut members = Map::new();
                if let Some(is) = is {
                    members.insert(is.into(), scalar.clone());
                }
                next.open(place, Value::Object(members));
            }
            _ => next.absent(segment, inside),
        }
        Ok(Step::Taken)
    }
}

impl tree::Family for Paths {
    type Shape = Shape;

    fn root(&self) -> Root<'_> {
        Root::new("pfcp", &["ies"], false)
    }

    /// Below what is not there, a name is judged as where the value is there: a member
    /// that it could have selects nothing, and another is refused; so is an entry past
    /// the end of a list, and a field that a value lacks, by what its tree may hold
    /// ([`Below`]). At a scalar, as [`Paths::at_scalar`] has it.
    fn step<'v>(
        &self,
        place: &Place<'v, Shape>,
        segment: &str,
        next: &mut Next<'v, Shape>,
    ) -> Result<Step<Shape>, tree::Error> {
        let shape = place.shape();
        let list = matches!(shape.0, Of::List(_) | Of::Below(Below::List(_)));
        if next.edit() == Some(Edit::Open)
            && let Some(opened) = room(place.value(), shape.0, list, segment, next.is_last())
        {
            next.open(place, opened);
            return Ok(Step::Taken);
        }
        // What is null is not there.
        match (place.value().filter(|value| !value.is_null()), shape.0) {
            (_, Of::Nothing) => Ok(Step::Plain),
            // An entry of a list that is not there, or past the end of one, which has the
            // members of one.
            (None, _) if list && (segment == "*" || tree::position(segment).is_some()) => {
                next.absent(segment, self.entry(shape, None));
                Ok(Step::Taken)
            }
            (Some(Value::Array(entries)), _)
                if list && tree::position(segment).is_some_and(|at| at >= entries.len()) =>
            {
                next.absent(segment, self.entry(shape, None));
                Ok(Step::Taken)
            }
            (None, _) if list => {
                let reason = alloc::format!("{segment:?} is no position in a list");
                Err(tree::Error::new(ErrorKind::NotAList, "", reason))
            }
            // A field that is not there, whose tree is a scalar, has nothing below it.
            (None, Of::Below(Below::Scalar)) => {
                let reason = alloc::format!("{segment:?} is no member of a field, which has none");
                Err(tree::Error::new(ErrorKind::Scalar, "", reason))
            }
            (None, _) if segment == "*" => Ok(Step::Plain),
            (None, _) => match self.absent(shape, segment) {
                Absent::Optional(inside) => {
                    next.absent(segment, inside);
                    Ok(Step::Taken)
                }
                _ => {
                    let reason = alloc::format!("{segment:?} is no member of what is not there");
                    Err(tree::Error::new(ErrorKind::NoSuchMember, "", reason))
                }
            },
            (Some(value), _) if !value.is_object() && !value.is_array() => {
                self.at_scalar(place, value, segment, next)
            }
            _ => Ok(Step::Plain),
        }
    }

    /// The message of the name that the tree says: a message type of no table, which the
    /// tree says by its number, has its IEs as octets.
    fn start(&self, tree: &Value, _rooted: bool) -> Shape {
        let name = tree
            .as_object()
            .and_then(|members| tree::member(members, "message"))
            .and_then(|(_, kind)| kind.as_str());
        let info = name.and_then(|name| {
            MESSAGE_TYPES
                .iter()
                .find(|info| tree::same_name(info.name(), name))
        });
        Shape(info.map_or(Of::Nothing, Of::Message))
    }

    fn member(&self, shape: &Shape, name: &str, value: Option<&Value>) -> Shape {
        Shape(match shape.0 {
            Of::Message(info) if tree::same_name(name, "ies") => {
                Of::Ies(core::slice::from_ref(&info.table))
            }
            // The other members of the header are scalars.
            Of::Message(_) => Of::Below(&Below::Scalar),
            Of::Ies(tables) => {
                row_named(tables, name).map_or(Of::Nothing, |row| of_row(row, value))
            }
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
        })
    }

    fn entry(&self, shape: &Shape, value: Option<&Value>) -> Shape {
        Shape(match shape.0 {
            Of::List(info) => of_value(info, value),
            Of::Below(Below::List(below)) => Of::Below(below),
            _ => Of::Nothing,
        })
    }

    fn absent(&self, shape: &Shape, name: &str) -> Absent<Shape> {
        let there = match shape.0 {
            Of::Message(_) => crate::message::forms::NAMES
                .iter()
                .any(|member| tree::same_name(member, name)),
            Of::Ies(tables) => row_named(tables, name).is_some(),
            Of::Value(info) => info
                .members
                .iter()
                .any(|member| tree::same_name(member, name)),
            Of::Below(below) => below.member(name).is_some(),
            _ => false,
        };
        match there {
            true => Absent::Optional(self.member(shape, name, None)),
            false => Absent::Unknown,
        }
    }
}

/// What an edit opens at a place so that `segment` goes into it: a list with one more
/// entry, `null`, for the position of its length, and an object of IEs with the list or the
/// grouped IE of the row that it lacks, empty, for a path that goes on into it. `None` where
/// the place has what the segment names, or is not there to open, as its holder is opened
/// first.
fn room(value: Option<&Value>, of: Of, list: bool, segment: &str, last: bool) -> Option<Value> {
    match (value?, of) {
        (Value::Array(entries), _) if list && tree::position(segment) == Some(entries.len()) => {
            let mut grown = entries.clone();
            grown.push(Value::Null);
            Some(Value::Array(grown))
        }
        (Value::Null | Value::Object(_), Of::Ies(tables)) if !last => {
            let row = row_named(tables, segment)?;
            let empty = match (row.repeat, ie_type_info(row.ie_type)?.form) {
                (Repeat::Once, Form::Grouped) => Value::Object(Map::new()),
                (Repeat::Once, _) => return None,
                _ => Value::Array(Vec::new()),
            };
            let mut members = value?.as_object().cloned().unwrap_or_default();
            if tree::member(&members, segment).is_some() {
                return None;
            }
            members.insert(row.name.into(), empty);
            Some(Value::Object(members))
        }
        _ => None,
    }
}

/// The values at `path` in the tree of a message. A row of a table that a message or a
/// grouped IE lacks, and a member that a value or the header lacks of those that its tree
/// may have, select nothing; a name that is none of them is an error, also below what is
/// not there, and an entry past the end of a list selects nothing. A value or a field
/// whose tree is a scalar or an object takes the same names in either form.
///
/// # Errors
///
/// Those of `oxirush_utils::tree::select_in`: `NoSuchMember` for a name that the value at
/// its place does not have and that its table or the members of its tree do not name
/// either.
pub fn select<'v>(tree: &'v Value, path: &str) -> Result<Vec<&'v Value>, tree::Error> {
    tree::select_in(&Paths, tree, path)
}

/// Give the place at `path` the value `value`: a path that [`select`] takes, with what it
/// lacks added, an entry of a list at the position of its length too. A member of the
/// object of a value or a field that the tree writes as a scalar writes the object, with
/// the scalar as its member if it is one: `{"value": "minute", "Spare": 8}` from
/// `"minute"`. The tree is left as it was when the edit fails.
///
/// # Errors
///
/// Those of `oxirush_utils::tree::set_in`.
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
    use crate::{Header, HeartbeatRequest, Message, RecoveryTimeStamp};
    use oxirush_utils::tree::Family;

    /// What the paths know of a place prints the names of the message, of the tables and
    /// of the IE types, not their rows.
    #[test]
    fn a_shape_prints_its_names() {
        let heartbeat = Message {
            header: Header::node(1),
            body: HeartbeatRequest::new(RecoveryTimeStamp::new(7)).into(),
        };
        let heartbeat = heartbeat.to_tree();
        let message = Paths.start(&heartbeat, true);
        assert_eq!(
            alloc::format!("{message:?}"),
            r#"Shape(Message("PFCP Heartbeat Request"))"#
        );
        let ies = Paths.member(&message, "ies", Some(&heartbeat["ies"]));
        assert_eq!(alloc::format!("{ies:?}"), r#"Shape(Ies(["7.4.2.1-1"]))"#);
        // The header is no table of IEs: its fields are scalars
        let sequence = Paths.member(&message, "Sequence Number", None);
        assert_eq!(alloc::format!("{sequence:?}"), "Shape(Below(Scalar))");
        let stamp = &heartbeat["ies"]["Recovery Time Stamp"];
        let value = Paths.member(&ies, "Recovery Time Stamp", Some(stamp));
        assert_eq!(
            alloc::format!("{value:?}"),
            r#"Shape(Value("Recovery Time Stamp"))"#
        );
        let empty = Value::Array(Vec::new());
        let addresses = Paths.member(&ies, "Source IP Address", Some(&empty));
        assert_eq!(
            alloc::format!("{addresses:?}"),
            r#"Shape(List("Source IP Address"))"#
        );
        let nothing = Paths.member(&value, "Bogus", None);
        assert_eq!(alloc::format!("{nothing:?}"), "Shape(Nothing)");
    }
}
