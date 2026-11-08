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

//! What `check` says of a message, against its tree. Each deviation's path is one that
//! `paths::select` takes on the tree of the message, as the deviation says: an IE that is
//! not there selects nothing, and one whose value or place is at fault selects it. The
//! message that the tree writes, whose IEs are in the order of their tables, has on each
//! interface the deviations that a receiver answers at the same places, with the same
//! Causes and Offending IEs: a receiver takes the IEs in any order (§8.1.2), and answers
//! them alike.
#![no_main]

use libfuzzer_sys::fuzz_target;
use oxirush_pfcp::DeviationKind::*;
use oxirush_pfcp::{Interfaces, Message, paths};

const INTERFACES: [Interfaces; 7] = [
    Interfaces::N4,
    Interfaces::N4MB,
    Interfaces::SXA,
    Interfaces::SXB,
    Interfaces::SXC,
    Interfaces::SXA_SXB,
    Interfaces::ALL,
];

fuzz_target!(|octets: &[u8]| {
    let Ok(message) = Message::decode(octets) else {
        return;
    };
    let tree = message.to_tree();
    let back = Message::from_tree(&tree).ok();
    for interface in INTERFACES {
        let deviations = message.check(interface);
        for deviation in &deviations {
            let path = &deviation.path;
            let selected = match paths::select(&tree, path) {
                Ok(selected) => selected,
                Err(error) => panic!("{deviation:?}: its path is refused: {error}"),
            };
            match deviation.kind {
                MandatoryMissing { .. } | ConditionalMissing { .. } => {
                    assert!(selected.is_empty(), "{deviation:?}: {selected:?}")
                }
                MandatoryIncorrect { .. }
                | ConditionalIncorrect { .. }
                | Incorrect { .. }
                | NullLength { .. }
                | Repeated { .. }
                | Unexpected { .. }
                | Excluded { .. }
                | NotOnInterface { .. }
                | WithRejection { .. }
                | FixedLength { .. }
                | UnknownType { .. } => {
                    assert!(!selected.is_empty(), "{deviation:?} selects nothing")
                }
                _ => {}
            }
            let _ = (deviation.to_string(), deviation.offending_ie());
        }
        // The same answer of a receiver, in the order of the IEs of each message: the places
        // of the deviations that it answers, their Causes and their Offending IEs
        if let Some(back) = &back {
            let answer = |deviations: &[oxirush_pfcp::Deviation]| {
                let answered = deviations
                    .iter()
                    .filter(|deviation| deviation.cause.is_some());
                let mut answer: Vec<_> = answered
                    .map(|deviation| {
                        (
                            deviation.path.clone(),
                            format!("{:?}", deviation.cause),
                            deviation.offending_ie(),
                        )
                    })
                    .collect();
                answer.sort();
                answer.dedup();
                answer
            };
            assert_eq!(
                answer(&back.check(interface)),
                answer(&deviations),
                "{interface:?} of the message that the tree writes"
            );
        }
    }
});
