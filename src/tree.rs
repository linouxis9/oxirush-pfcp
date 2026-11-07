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
    Absent, ErrorKind, Map, Members, Next, Place, Reading, Refused, Root, Step,
};

/// The engine of the trees, oxirush-utils' `tree`, and its macro `tree!`, which writes a
/// tree as JSON is written.
pub use oxirush_utils::tree;
/// A tree.
pub use oxirush_utils::tree::Value;

use crate::ie::{Placed, RawIe};
use crate::message::{MESSAGE_TYPES, MessageTypeInfo};
use crate::registry::{Form, IE_TYPES, IeTypeInfo, ie_type_info};
use crate::table::{FieldValues, Repeat, Row, Scope, Table, keep_order};

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
    let order = scope.order();
    // The kept IEs that the order places; those after them were added since.
    let ordered = order
        .iter()
        .filter(|placed| matches!(placed, Placed::Raw))
        .count()
        .min(raws.len());
    let mut members = Map::new();
    for row in table.rows {
        let kept = raws.iter().any(|ie| ie.ie_type == row.ie_type);
        if !kept && scope.count(row.ie_type) == 0 {
            continue;
        }
        let list = row.repeat != Repeat::Once;
        let mut nth = 0;
        let field = |members: &mut Map, nth: &mut usize| match scope.field_tree(row.ie_type, *nth) {
            Some(value) => {
                *nth += 1;
                put(members, row.name.into(), list, value);
                true
            }
            None => false,
        };
        let kept_from = match (kept, order.is_empty()) {
            // The values and the kept IEs of the row, in the order of the wire.
            (true, false) => {
                let mut at = 0;
                for placed in order {
                    match placed {
                        Placed::Field(ie_type) if *ie_type == row.ie_type => {
                            field(&mut members, &mut nth);
                        }
                        Placed::Raw => {
                            if let Some(ie) = raws.get(at).filter(|ie| ie.ie_type == row.ie_type) {
                                put(&mut members, row.name.into(), list, raw_tree(ie));
                            }
                            at += 1;
                        }
                        Placed::Field(_) => {}
                    }
                }
                ordered
            }
            _ => 0,
        };
        while field(&mut members, &mut nth) {}
        for ie in raws[kept_from..]
            .iter()
            .filter(|ie| ie.ie_type == row.ie_type)
        {
            put(&mut members, row.name.into(), list, raw_tree(ie));
        }
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
        let at = tree::named(&names, written);
        let row = at.map(|at| &table.rows[at]);
        let Some(ie_type) = row.map(|row| row.ie_type).or_else(|| type_of_name(written)) else {
            return Err(reading.refuse(ErrorKind::NoSuchMember, no_such_ie(table, &names, written)));
        };
        if let Some(at) = at {
            if let Some((_, before)) = rows_written.iter().find(|(row, _)| *row == at) {
                let why = alloc::format!(
                    "{written:?} and {before:?} are both the row {}",
                    table.rows[at].name
                );
                return Err(reading.refuse(ErrorKind::Value, why));
            }
            rows_written.push((at, written));
        }
        if row.is_none()
            && let Some(row) = table.row_of(ie_type)
        {
            let why = alloc::format!(
                "{written:?} is the IE type of the row {}, which goes by its name",
                row.name
            );
            return Err(reading.refuse(ErrorKind::NoSuchMember, why));
        }
        let position = at.unwrap_or(usize::MAX);
        let label: &'static str = row.map_or("IE", |row| row.name);
        let list = row.is_some_and(|row| row.repeat != Repeat::Once);
        reading.within(label, held, |held, reading| {
            // A row that is there once has one value; the IEs of its type that the scope
            // keeps as octets come before or after it.
            let mut valued = false;
            let mut entry = |value: &Value, reading: &mut Reading| -> Result<(), Refused> {
                if is_octets(value) {
                    kept.push((position, read_raw(ie_type, value, reading)?));
                    placed.push((position, Placed::Raw));
                    return Ok(());
                }
                if row.is_none() {
                    return Err(reading.refuse(
                        ErrorKind::Value,
                        "an IE that its table does not have is written by its octets: {\"octets\": ...}",
                    ));
                }
                if !list && valued {
                    return Err(reading.refuse(
                        ErrorKind::Value,
                        "its table has it once: a repetition is written by its octets",
                    ));
                }
                valued = true;
                scope.read_field(ie_type, value, reading)?;
                placed.push((position, Placed::Field(ie_type)));
                Ok(())
            };
            match held {
                Value::Array(_) => {
                    reading.list(held, &mut entry)?;
                    Ok(())
                }
                _ if list => Err(reading.mismatch("a list", held)),
                single => entry(single, reading),
            }
        })?;
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

/// Why a name is no IE of a table: the nearest names, or the row whose role it is.
fn no_such_ie(table: &crate::table::Table, names: &[&str], written: &str) -> String {
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

/// The rules of the paths of PFCP on the engine of oxirush-utils: `/pfcp` is short for
/// the IEs of the message, and the rest is the plain rule of a tree, which knows the
/// tables: a row that a message or a grouped IE lacks, and a member that a value or the
/// header lacks of those that its tree may have ([`IeTypeInfo::members`]), are not
/// there, where another name is no member. A value that its tree writes as a scalar has
/// the one field that it is.
#[derive(Debug, Clone, Copy, Default)]
pub struct Paths;

/// What [`Paths`] knows of a place of the tree of a message: the tables of the IEs that it
/// holds, or the figure of the value that it is.
#[derive(Debug, Clone, Copy, Default)]
pub struct Shape(Of);

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

/// The field that the tree of a value of `info` is, where it is a scalar: the one field of
/// its figure.
fn scalar_field(info: &IeTypeInfo) -> Option<&'static str> {
    match info.fields {
        [field] => Some(field),
        _ => None,
    }
}

impl tree::Family for Paths {
    type Shape = Shape;

    fn root(&self) -> Root<'_> {
        Root::new("pfcp", &["ies"], false)
    }

    /// At a value that its tree writes as a scalar, a member that it lacks selects nothing,
    /// and the one field that it is selects it.
    fn step<'v>(
        &self,
        place: &Place<'v, Shape>,
        segment: &str,
        next: &mut Next<'v, Shape>,
    ) -> Result<Step<Shape>, tree::Error> {
        if next.edit().is_some() {
            return Ok(Step::Plain);
        }
        let shape = place.shape();
        match (place.value(), shape.0) {
            (Some(value), Of::Value(info)) if !value.is_object() => {
                if scalar_field(info).is_some_and(|field| tree::same_name(field, segment)) {
                    next.stay(place, Shape(Of::Nothing));
                    return Ok(Step::Taken);
                }
                match info
                    .members
                    .iter()
                    .any(|member| tree::same_name(member, segment))
                {
                    true => Ok(Step::Taken),
                    false => Ok(Step::Plain),
                }
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
            Of::Ies(tables) => {
                row_named(tables, name).map_or(Of::Nothing, |row| of_row(row, value))
            }
            _ => Of::Nothing,
        })
    }

    fn entry(&self, shape: &Shape, value: Option<&Value>) -> Shape {
        Shape(match shape.0 {
            Of::List(info) => of_value(info, value),
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
            _ => false,
        };
        match there {
            true => Absent::Optional(self.member(shape, name, None)),
            false => Absent::Unknown,
        }
    }
}

/// The values at `path` in the tree of a message. A row of a table that a message or a
/// grouped IE lacks, and a member that a value or the header lacks of those that its tree
/// may have ([`IeTypeInfo::members`]), select nothing; a name that is none of them is an
/// error.
///
/// # Errors
///
/// Those of `oxirush_utils::tree::select_in`: `NoSuchMember` for a name that the value at
/// its place does not have and that its table or the members of its tree do not name
/// either.
pub fn select<'v>(tree: &'v Value, path: &str) -> Result<Vec<&'v Value>, tree::Error> {
    tree::select_in(&Paths, tree, path)
}

/// Give the place at `path` the value `value`.
///
/// # Errors
///
/// Those of `oxirush_utils::tree::set_in`.
pub fn set(tree: &mut Value, path: &str, value: impl Into<Value>) -> Result<(), tree::Error> {
    tree::set_in(&Paths, tree, path, value)
}
