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

//! A captured message edited through its tree, as a user edits one: values at the paths
//! of its tree, from the fuzzer or from the trees of the other captures, with one of their
//! leaves changed or not, or the octets of an IE. `Message::from_tree` writes a message
//! from the tree that a user wrote, where the `tree` target reads back only the trees that
//! a decode wrote.
//!
//! A tree that its tables refuse is an error, never a panic. A message that `from_tree`
//! writes is one that the crate wrote ([`pool::written`]), and only what was edited
//! changes: where the edits were of rows, each row of the message that no edit was under
//! has the value that it had.
#![no_main]

mod pool;

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use oxirush_pfcp::tree;
use oxirush_pfcp::{Message, paths};
use pool::{Leaf, POOL, change};

#[derive(Arbitrary, Debug)]
struct Edits {
    base: u16,
    edits: Vec<Edit>,
}

/// One edit of a tree, at a path of the tree that the number picks.
#[derive(Arbitrary, Debug)]
enum Edit {
    /// A value of the fuzzer
    Set { path: u16, to: Leaf },
    /// A value that a path of a captured tree that ends as this one has, with one of its
    /// leaves changed or not
    Seen {
        path: u16,
        value: u16,
        walk: Vec<u16>,
        to: Option<Leaf>,
    },
    /// The value of the row that the path is in: a value of the fuzzer, in its place
    Row { path: u16, to: Leaf },
}

/// The row of the message that a path is under: its segment after the IEs, which a path
/// names `ies`, as the tree does, or `pfcp`.
fn row(path: &str) -> Option<String> {
    let segments = tree::segments(path).ok()?;
    match segments.as_slice() {
        [ies, name, ..] if tree::same_name(ies, "ies") || tree::same_name(ies, "pfcp") => {
            Some(name.clone())
        }
        _ => None,
    }
}

fuzz_target!(|input: Edits| {
    let message = POOL.message(input.base);
    let before = message.to_tree();
    let known = tree::paths(&before);
    if known.is_empty() {
        return;
    }
    let pick = |number: u16| known[usize::from(number) % known.len()].0.clone();
    let mut edited = before.clone();
    let mut touched = Vec::new();
    for edit in input.edits.iter().take(8) {
        let (path, value) = match edit {
            Edit::Set { path, to } => (pick(*path), to.value()),
            Edit::Seen {
                path,
                value,
                walk,
                to,
            } => {
                let path = pick(*path);
                let last = path.rsplit('/').next().unwrap_or_default();
                let Some(seen) = POOL.values.get(last).filter(|seen| !seen.is_empty()) else {
                    continue;
                };
                let mut value = seen[usize::from(*value) % seen.len()].clone();
                if let Some(to) = to {
                    change(&mut value, walk, to.value());
                }
                (path, value)
            }
            Edit::Row { path, to } => {
                let path = pick(*path);
                let Some(name) = row(&path) else { continue };
                (format!("/ies/{}", tree::escape(&name)), to.value())
            }
        };
        if paths::set(&mut edited, &path, value).is_ok() {
            touched.push(path);
        }
    }
    let Ok(written) = Message::from_tree(&edited) else {
        return;
    };
    pool::written(&written);

    // Each row that no edit was under is as it was, where the edits were of rows alone: a
    // header of another message type has other tables
    if touched.iter().any(|path| row(path).is_none()) {
        return;
    }
    let after = written.to_tree();
    let (Some(was), Some(is)) = (
        before.get("ies").and_then(|ies| ies.as_object()),
        after.get("ies").and_then(|ies| ies.as_object()),
    ) else {
        return;
    };
    for (name, value) in was {
        if touched
            .iter()
            .any(|path| row(path).is_some_and(|row| tree::same_name(&row, name)))
        {
            continue;
        }
        let other = is
            .iter()
            .find(|(other, _)| tree::same_name(other, name))
            .map(|(_, value)| value);
        assert_eq!(
            other,
            Some(value),
            "the row {name}, which no edit was under, changed with {touched:?}"
        );
    }
});
