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

//! What the targets that edit trees share: the messages of tests/captures, which they
//! start from, the values that their trees have, and a value of the fuzzer.

#![allow(dead_code)]

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use oxirush_pfcp::Message;
use oxirush_pfcp::tree::{self, Value};
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

/// Whether an IE is kept as its octets.
fn octets(value: &Value) -> bool {
    matches!(value, Value::Object(members) if members.len() == 1 && members.contains_key("octets"))
}

/// Whether `read`, the tree of the octets of a message, is `written`, the tree of the
/// message that the crate wrote, but where one of them keeps an IE as its octets: an IE
/// written as octets that decode as a value of its type, or a value of a null length,
/// which the decoder keeps as octets.
fn same(written: &Value, read: &Value) -> bool {
    match (written, read) {
        _ if octets(written) || octets(read) => true,
        (Value::Object(written), Value::Object(read)) => {
            written.len() == read.len()
                && written
                    .iter()
                    .all(|(name, value)| read.get(name).is_some_and(|other| same(value, other)))
        }
        (Value::Array(written), Value::Array(read)) => {
            written.len() == read.len()
                && written
                    .iter()
                    .zip(read)
                    .all(|(value, other)| same(value, other))
        }
        _ => written == read,
    }
}

/// What holds of a message that the crate wrote from a tree: it encodes, its octets decode
/// to a message that encodes to the same octets and whose tree is that of the message, but
/// for the IEs that one of them keeps as octets, and its tree writes it again.
pub fn written(message: &Message) {
    let octets = match message.encode() {
        Ok(octets) => octets,
        Err(error) => {
            panic!("a message that the crate wrote does not encode: {error}: {message:?}")
        }
    };
    let tree = message.to_tree();
    let read = match Message::decode(&octets) {
        Ok(read) => read,
        Err(error) => panic!(
            "a message that the crate wrote does not decode: {error}: {}",
            hex(&octets)
        ),
    };
    assert_eq!(read.encode().as_ref(), Ok(&octets), "{}", hex(&octets));
    let read_tree = read.to_tree();
    assert!(
        same(&tree, &read_tree),
        "the tree of a message that the crate wrote is not that of its octets {}:\n{tree}\n{read_tree}",
        hex(&octets)
    );
    match Message::from_tree(&tree) {
        Ok(again) => assert_eq!(again.to_tree(), tree),
        Err(error) => panic!("the tree of a message is refused: {error}: {tree}"),
    }
}
