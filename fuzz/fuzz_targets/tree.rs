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

//! A message that decodes has a tree that reads back to itself, and that encodes the
//! same IEs as the message's octets, scope by scope: the same octets of each IE, and of
//! each type in the same order, the tree putting the rows in the order of their table.
#![no_main]

use libfuzzer_sys::fuzz_target;
use oxirush_pfcp::{Form, Message, framing, ie_type_info};

/// The IEs of a scope, by their type in the order of the wire among those of one type: a
/// grouped IE whose IEs frame is its own scope, any other its octets.
fn scope(octets: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut ies = Vec::new();
    for ie in framing::ies(octets) {
        let Ok(ie) = ie else {
            ies.push((u16::MAX, b"a fault of framing".to_vec()));
            break;
        };
        let grouped = ie_type_info(ie.ie_type).is_some_and(|info| info.form == Form::Grouped);
        let content = ie.content();
        let canonical = match grouped && !content.is_empty() && framing::ies(content).all(|inner| inner.is_ok()) {
            true => scope(content).into_iter().flat_map(|(ie_type, octets)| [&ie_type.to_be_bytes()[..], &(octets.len() as u32).to_be_bytes(), &octets].concat()).collect(),
            false => content.to_vec(),
        };
        ies.push((ie.ie_type, canonical));
    }
    // Stable: the IEs of one type keep their order.
    ies.sort_by_key(|(ie_type, _)| *ie_type);
    ies
}

fn hex(octets: &[u8]) -> String {
    octets.iter().map(|octet| format!("{octet:02x}")).collect()
}

fuzz_target!(|octets: &[u8]| {
    let Ok(message) = Message::decode(octets) else { return };
    let tree = message.to_tree();
    let back = Message::from_tree(&tree).expect("a message's tree reads back");
    assert_eq!(back.to_tree(), tree);
    let encoded = back.encode().expect("a tree's message encodes");
    assert_eq!(Message::decode(&encoded).expect("its octets decode").to_tree(), tree);
    let header = message.header.len();
    assert_eq!(octets[..header], encoded[..header], "the header");
    assert!(scope(&octets[header..]) == scope(&encoded[header..]), "the tree changed the IEs:\n{}\n{}", hex(octets), hex(&encoded));
});
