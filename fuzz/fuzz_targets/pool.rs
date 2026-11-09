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

//! What the targets that edit trees share: the messages that they start from, of
//! tests/captures or of one IE of any row ([`Base`]), the values that the trees of the
//! captures have, and a value of the fuzzer.

#![allow(dead_code)]

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use oxirush_pfcp::tree::{self, Value};
use oxirush_pfcp::{
    DeviationKind, Interfaces, MESSAGE_TYPES, Message, Repeat, Row, Table, is_node_related,
    message_type_info,
};
use std::collections::BTreeMap;
use std::sync::LazyLock;

/// The messages of tests/captures: one a row, its octets in the last column.
const CAPTURES: &str = include_str!("../../tests/captures/messages.tsv");

/// The captured messages, and the values of their trees.
pub struct Pool {
    pub messages: Vec<Message>,
    /// For the last segment of each path of the trees, the values that it has, each once.
    pub values: BTreeMap<String, Vec<Value>>,
    /// Each text of the trees: the names of coded values above all.
    pub names: Vec<String>,
}

pub static POOL: LazyLock<Pool> = LazyLock::new(|| {
    let messages: Vec<Message> = CAPTURES
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.rsplit('\t').next())
        .filter_map(|text| Message::decode(&unhex(text)).ok())
        .collect();
    let mut values = BTreeMap::<String, Vec<Value>>::new();
    let mut names = Vec::new();
    for message in &messages {
        for (path, value) in tree::paths(&message.to_tree()) {
            if let Value::String(text) = &value {
                names.push(text.clone());
            }
            let last = path.rsplit('/').next().unwrap_or_default().to_owned();
            let seen = values.entry(last).or_default();
            if seen.len() < 64 && !seen.contains(&value) {
                seen.push(value);
            }
        }
    }
    names.sort();
    names.dedup();
    Pool {
        messages,
        values,
        names,
    }
});

impl Pool {
    /// The message that `number` picks.
    pub fn message(&self, number: u16) -> &Message {
        &self.messages[usize::from(number) % self.messages.len()]
    }
}

/// The message that a target starts from: a captured one, or one of an IE of any row of
/// any message type, as deep in the grouped IEs as `rows` goes, the last of the fuzzer's
/// octets, which a capture may not have.
#[derive(Arbitrary, Debug)]
pub enum Base {
    Captured(u16),
    Made { message: u8, rows: Vec<u16>, octets: Vec<u8> },
}

impl Base {
    /// The message, if the octets made decode.
    pub fn message(&self) -> Option<Message> {
        let (message, rows, octets) = match self {
            Base::Captured(number) => return Some(POOL.message(*number).clone()),
            Base::Made { message, rows, octets } => (message, rows, octets),
        };
        let info = &MESSAGE_TYPES[usize::from(*message) % MESSAGE_TYPES.len()];
        let (mut table, mut types) = (info.table, Vec::new());
        for row in rows.iter().take(4) {
            let Some(row) = table.rows.get(usize::from(*row) % table.rows.len().max(1)) else {
                break;
            };
            types.push(row.ie_type);
            match row.content {
                Some(content) => table = content,
                None => break,
            }
        }
        let mut content = octets.clone();
        for ie_type in types.iter().rev() {
            let length = u16::try_from(content.len()).ok()?;
            content = [&ie_type.to_be_bytes()[..], &length.to_be_bytes(), &content].concat();
        }
        let session = !is_node_related(info.message_type);
        let header: &[u8] = if session { &[0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 7, 0] } else { &[0, 0, 7, 0] };
        let length = u16::try_from(header.len() + content.len()).ok()?;
        let first = if session { 0x21 } else { 0x20 };
        let octets = [&[first, info.message_type][..], &length.to_be_bytes(), header, &content].concat();
        Message::decode(&octets).ok()
    }
}

pub fn unhex(text: &str) -> Vec<u8> {
    let digit = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
    text.as_bytes()
        .chunks(2)
        .map(|pair| digit(pair[0]) << 4 | pair.get(1).map_or(0, |low| digit(*low)))
        .collect()
}

pub fn hex(octets: &[u8]) -> String {
    octets.iter().map(|octet| format!("{octet:02x}")).collect()
}

/// A value that the fuzzer writes in the place of another.
#[derive(Arbitrary, Debug)]
pub enum Leaf {
    Unsigned(u64),
    Signed(i64),
    Small(u8),
    Text(String),
    Hex(Vec<u8>),
    Octets(Vec<u8>),
    Bool(bool),
    Null,
    /// A text of a tree of the captures: the name of a value above all
    Name(u16),
}

impl Leaf {
    pub fn value(&self) -> Value {
        match self {
            Leaf::Unsigned(number) => Value::from(*number),
            Leaf::Signed(number) => Value::from(*number),
            Leaf::Small(number) => Value::from(*number),
            Leaf::Text(text) => Value::from(text.as_str()),
            Leaf::Hex(octets) => Value::from(hex(octets)),
            Leaf::Octets(octets) => {
                let mut held = tree::Map::new();
                held.insert("octets".into(), Value::from(hex(octets)));
                Value::Object(held)
            }
            Leaf::Bool(flag) => Value::from(*flag),
            Leaf::Null => Value::Null,
            Leaf::Name(number) => {
                let names = &POOL.names;
                names
                    .get(usize::from(*number) % names.len().max(1))
                    .map_or(Value::Null, |name| Value::from(name.as_str()))
            }
        }
    }
}

/// Replace the leaf of `value` that `walk` goes to, a member or an entry by its place at
/// each step, with `leaf`.
pub fn change(value: &mut Value, walk: &[u16], leaf: Value) {
    let Some((&step, rest)) = walk.split_first() else {
        *value = leaf;
        return;
    };
    match value {
        Value::Array(entries) if !entries.is_empty() => {
            let at = usize::from(step) % entries.len();
            change(&mut entries[at], rest, leaf);
        }
        Value::Object(members) if !members.is_empty() => {
            let at = usize::from(step) % members.len();
            if let Some(member) = members.values_mut().nth(at) {
                change(member, rest, leaf);
            }
        }
        _ => *value = leaf,
    }
}

/// The interfaces of `check()`, one by one and together.
const INTERFACES: [Interfaces; 7] = [
    Interfaces::SXA,
    Interfaces::SXB,
    Interfaces::SXC,
    Interfaces::N4,
    Interfaces::N4MB,
    Interfaces::SXA_SXB,
    Interfaces::ALL,
];

/// The tree without the Lengths that it writes: the Message Length, and that of each IE
/// kept as octets.
fn cleared(value: &mut Value) {
    match value {
        Value::Object(members) => {
            members.shift_remove("Message Length");
            if members.contains_key("octets") {
                members.shift_remove("length");
            }
            members.values_mut().for_each(cleared);
        }
        Value::Array(entries) => entries.iter_mut().for_each(cleared),
        _ => {}
    }
}

/// What holds of a message that the crate wrote from a tree: it encodes, and its tree
/// loads back to it. Its octets decode to a message that encodes to them, whose tree loads
/// back to it, which has each value of the message as it is ([`held`]), and in which
/// `check()` finds what it finds in the message, on every interface: `check(m)` is
/// `check(Message::decode(m.encode()))`. A tree may write a false Length or Message Length,
/// for a test tool, which keeps the octets from decoding: then `check()` tells it, and the
/// message without the Lengths that the tree writes decodes.
pub fn written(message: &Message) {
    let octets = match message.encode() {
        Ok(octets) => octets,
        Err(error) => {
            panic!("a message that the crate wrote does not encode: {error}: {message:?}")
        }
    };
    let tree = message.to_tree();
    match Message::from_tree(&tree) {
        Ok(again) => assert_eq!(&again, message, "the tree of a message loads to another: {tree}"),
        Err(error) => panic!("the tree of a message is refused: {error}: {tree}"),
    }
    let read = match Message::decode(&octets) {
        Ok(read) => read,
        Err(error) => {
            let told = message.check(Interfaces::ALL).into_iter().any(|deviation| {
                matches!(deviation.kind, DeviationKind::InvalidLength { .. })
                    || deviation.path == "/Message Length"
            });
            assert!(told, "check() does not tell why the octets do not decode: {error}: {}", hex(&octets));
            let mut tree = tree;
            cleared(&mut tree);
            let cleared = Message::from_tree(&tree).and_then(|message| Ok(message.encode()));
            let decodes = cleared.is_ok_and(|octets| octets.is_ok_and(|octets| Message::decode(&octets).is_ok()));
            assert!(decodes, "a message of no false Length does not decode: {error}: {tree}");
            return;
        }
    };
    assert_eq!(read.encode().as_ref(), Ok(&octets), "{}", hex(&octets));
    let read_tree = read.to_tree();
    // The Message Length that a tree writes is no value, which a receiver does not keep
    let table = message_type_info(read.body.message_type()).map(|info| info.table);
    let mut values = tree.clone();
    cleared(&mut values);
    assert!(
        held(&values, &read_tree, table),
        "a value of a message reads as another: {tree} reads as {read_tree}"
    );
    assert_eq!(
        Message::from_tree(&read_tree).as_ref(),
        Ok(&read),
        "the tree of a decoded message loads to another: {read_tree}"
    );
    for interface in INTERFACES {
        assert_eq!(
            message.check(interface),
            read.check(interface),
            "check() of a message is not that of its octets {} on {interface:?}: {tree}",
            hex(&octets)
        );
    }
}

/// Whether each value that the tree of a message, or of a grouped IE of `table`, holds is in
/// the tree of its octets `read` as it is, in its place: but an IE that the message keeps as
/// octets, which its receiver may read as a value, and a value of no octets, or past the
/// IEs that its row takes, which its receiver keeps as octets (§7.6.10).
fn held(written: &Value, read: &Value, table: Option<&'static Table>) -> bool {
    let (Value::Object(written), Value::Object(read)) = (written, read) else {
        return written == read;
    };
    let kept = |value: &Value| value.get("octets").is_some();
    let entries = |value: &Value| match value {
        Value::Array(entries) => entries.clone(),
        value => vec![value.clone()],
    };
    written.len() == read.len()
        && written.iter().all(|(name, value)| {
            let Some(other) = read.get(name) else { return false };
            let row = table.and_then(|table| table.rows.iter().find(|row| row.name == name));
            match (name.as_str(), row) {
                ("ies", _) => held(value, other, table),
                (_, None) => value == other || kept(value),
                (_, Some(row)) => {
                    let (written, read) = (entries(value), entries(other));
                    written.len() == read.len()
                        && written.iter().zip(&read).enumerate().all(|(at, (value, other))| {
                            // The receiver handles the first IEs of the row, whether they
                            // decode or not, and keeps the others as octets (§7.6.10).
                            kept(value)
                                || other.get("octets").and_then(Value::as_str) == Some("")
                                || kept(other) && at >= capacity(row)
                                || match row.content {
                                    Some(content) => held(value, other, Some(content)),
                                    None => value == other,
                                }
                        })
                }
            }
        })
}

/// How many IEs the field of a row holds: as many as its roles allow together.
fn capacity(row: &Row) -> usize {
    let each = |repeat: Repeat| match repeat {
        Repeat::Once => 1,
        Repeat::AtMost(most) => usize::from(most),
        Repeat::Any => usize::MAX,
    };
    row.roles.iter().map(|role| each(role.repeat)).fold(0, usize::saturating_add)
}
