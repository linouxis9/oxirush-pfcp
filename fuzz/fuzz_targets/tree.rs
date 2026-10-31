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

//! A message that decodes has a tree that reads back to itself, and the octets that the
//! tree encodes decode to the same tree.
#![no_main]

use libfuzzer_sys::fuzz_target;
use oxirush_pfcp::Message;

fuzz_target!(|octets: &[u8]| {
    let Ok(message) = Message::decode(octets) else { return };
    let tree = message.to_tree();
    let back = Message::from_tree(&tree).expect("a message's tree reads back");
    assert_eq!(back.to_tree(), tree);
    let encoded = back.encode().expect("a tree's message encodes");
    assert_eq!(Message::decode(&encoded).expect("its octets decode").to_tree(), tree);
});
