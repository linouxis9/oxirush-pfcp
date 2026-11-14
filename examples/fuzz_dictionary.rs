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

//! The dictionary of the fuzz targets that read octets, from the tables of the crate:
//! the first two octets of the header of each message type of Table 7.3-1, and the
//! type of each IE type of Table 8.1.2-1, with its length and a value of zeros when
//! the table gives it a fixed number of octets, up to 16. The fuzzer inserts them, so
//! that it writes messages and IEs that a decoder reads from their first octet.
//!
//! ```sh
//! cargo run --example fuzz_dictionary > fuzz/pfcp.dict
//! ```

use oxirush_pfcp::{Form, IE_TYPES, MESSAGE_TYPES, is_node_related};

/// A name of the dictionary: the letters and digits of `name`.
fn keyword(name: &str) -> String {
    name.chars().filter(char::is_ascii_alphanumeric).collect()
}

/// `octets` as the dictionary writes them.
fn escaped(octets: &[u8]) -> String {
    octets
        .iter()
        .map(|octet| format!("\\x{octet:02x}"))
        .collect()
}

fn main() {
    println!(
        "# The message types and IE types of oxirush-pfcp: written by examples/fuzz_dictionary.rs."
    );
    for info in MESSAGE_TYPES {
        // Version 1, and the S flag of a message that has a SEID (§7.2.2).
        let flags = if is_node_related(info.message_type) {
            0x20
        } else {
            0x21
        };
        let header = [flags, info.message_type];
        println!("{}=\"{}\"", keyword(info.name()), escaped(&header));
    }
    for info in IE_TYPES {
        let mut octets = info.ie_type.to_be_bytes().to_vec();
        if let (Form::Fixed, Some(length @ 1..=16)) = (info.form, info.fixed) {
            octets.extend(length.to_be_bytes());
            octets.extend(std::iter::repeat_n(0, usize::from(length)));
        }
        println!("{}=\"{}\"", keyword(info.name), escaped(&octets));
    }
}
