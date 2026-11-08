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

//! A path that the fuzzer writes, on the tree of a captured message: `paths::select` and
//! `paths::set`. The path starts as one that the tree has, cut anywhere, and goes on with
//! the fuzzer's text: escapes (`~1`), names of rows in any case, positions past the end
//! of a list, the header, `octets` under an IE.
//!
//! No path and no value makes either panic. Each path of the tree selects its value; a path
//! selects or is refused; a set is done whole or not at all, and a value that is set is the
//! one that the path selects. A tree that a set changed writes a message or is refused, and
//! a message that it writes is one that the crate wrote ([`pool::written`]).
#![no_main]

mod pool;

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use oxirush_pfcp::tree::{self, Value};
use oxirush_pfcp::{Message, paths};
use pool::POOL;

#[derive(Arbitrary, Debug)]
struct Call {
    base: u16,
    set: bool,
    /// A path that the tree has, cut after `cut` characters
    pick: u16,
    cut: u8,
    /// What the path goes on with
    extra: String,
    /// The value: JSON, or else a string of its text
    value: Vec<u8>,
}

/// Whether a member of `tree` is named `*`, at any depth: a path names no such member.
fn has_a_star(tree: &Value) -> bool {
    match tree {
        Value::Object(members) => members
            .iter()
            .any(|(name, member)| name == "*" || has_a_star(member)),
        Value::Array(entries) => entries.iter().any(has_a_star),
        _ => false,
    }
}

fuzz_target!(|call: Call| {
    let message = POOL.message(call.base);
    let tree = message.to_tree();
    let plain = !has_a_star(&tree);

    // Each path of the tree selects its value.
    let known = tree::paths(&tree);
    for (listed, held) in &known {
        if plain {
            let selected = paths::select(&tree, listed)
                .unwrap_or_else(|error| panic!("{listed} is in the tree and refused: {error}"));
            assert!(selected.contains(&held), "{listed}");
        }
    }

    // A path of the tree, cut short, with what the fuzzer adds to it
    let start = known
        .get(usize::from(call.pick) % known.len().max(1))
        .map_or("/pfcp", |(path, _)| path.as_str());
    let start: String = start.chars().take(usize::from(call.cut)).collect();
    let path = format!("{start}{}", call.extra);
    let value = serde_json::from_slice::<Value>(&call.value)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&call.value).into_owned()));

    // Any path selects, or is refused.
    if let Ok(selected) = paths::select(&tree, &path) {
        assert!(selected.len() <= 65_536, "{path}");
    }
    if !call.set {
        return;
    }

    // A set is done whole, or not at all; what was set is what is selected.
    let mut edited = tree.clone();
    match paths::set(&mut edited, &path, value.clone()) {
        Ok(()) if !value.is_null() && plain => {
            let selected = paths::select(&edited, &path)
                .unwrap_or_else(|error| panic!("{path} is set and refused: {error}"));
            assert!(
                !selected.is_empty() && selected.iter().all(|held| **held == value),
                "{path}: {selected:?}"
            );
        }
        Ok(()) => {}
        Err(_) => {
            assert_eq!(edited, tree, "{path}");
            return;
        }
    }
    if let Ok(written) = Message::from_tree(&edited) {
        pool::written(&written);
    }
});
