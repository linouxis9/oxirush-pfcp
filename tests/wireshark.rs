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

//! What the crate reads of the messages of a corpus, for tests/wireshark/compare.py, which
//! compares it with Wireshark's dissector of PFCP: of each message, whether it decodes, its
//! header, what check() tells of it, and its IEs in the
//! order of the wire at every level of the grouped IEs, each with its offset in the message,
//! its type, Length and Enterprise ID, and the tree of its value.
//!
//! ```sh
//! PFCP_WIRESHARK_CORPUS=corpus.tsv PFCP_WIRESHARK_CRATE=crate.jsonl \
//!     cargo test --release --all-features --test wireshark -- --ignored
//! ```

use oxirush_pfcp::framing::{self, Ies};
use oxirush_pfcp::{Form, Interfaces, Message, ie_type_info, message_type_info};
use serde_json::{Value, json};
use std::io::Write;

/// The IEs of a scope that begins `base` octets into the message, until one does not
/// frame, which ends the list with its fault.
fn ies(scope: Ies<'_>, base: usize) -> Value {
    let mut found = Vec::new();
    let mut at = base;
    for ie in scope {
        let ie = match ie {
            Ok(ie) => ie,
            Err(fault) => {
                found.push(json!({"offset": at, "fault": fault.to_string()}));
                break;
            }
        };
        let info = ie_type_info(ie.ie_type);
        let grouped = info.is_some_and(|info| matches!(info.form, Form::Grouped));
        // The value begins after the Type and the Length, and the Enterprise ID
        let value_at = at + 4 + 2 * usize::from(ie.enterprise_id.is_some());
        let mut entry = json!({
            "offset": at,
            "type": ie.ie_type,
            "length": ie.length,
            "enterprise_id": ie.enterprise_id,
            "grouped": grouped,
        });
        if grouped {
            entry["ies"] = ies(ie.ies(), value_at);
        } else if let Some(info) = info {
            // The tree of the crate, as JSON
            let tree = info
                .tree_of(ie.value, None)
                .map(|tree| serde_json::from_str(&tree.to_string()).unwrap());
            entry["tree"] = tree.unwrap_or(Value::Null);
        }
        found.push(entry);
        at += 4 + usize::from(ie.length);
    }
    Value::Array(found)
}

/// What the crate reads of a message.
fn reading(name: &str, octets: &[u8]) -> Value {
    let decoded = Message::decode(octets);
    let mut found = json!({
        "name": name,
        "decodes": decoded.is_ok(),
        "error": decoded.as_ref().err().map(|error| error.to_string()),
    });
    if let Ok(message) = &decoded {
        found["message_type"] = json!(message.body.message_type());
        found["seid"] = json!(message.header.seid);
        found["sequence"] = json!(message.header.sequence);
        // What check() tells, on N4 where the message type has it
        let own = message_type_info(message.body.message_type())
            .map_or(Interfaces::N4, |info| info.interfaces);
        let interface = if own.has(Interfaces::N4) {
            Interfaces::N4
        } else {
            own
        };
        let told = message.check(interface).into_iter();
        let told: Vec<String> = told
            .map(|deviation| {
                format!(
                    "{} {}: {:?}",
                    deviation.clause, deviation.path, deviation.kind
                )
            })
            .collect();
        found["told"] = json!(told);
    }
    if let Ok((header, _, scope)) = framing::message_ies(octets) {
        found["ies"] = ies(scope, header.encoded_len());
    }
    found
}

/// Write what the crate reads of each message of `PFCP_WIRESHARK_CORPUS` to
/// `PFCP_WIRESHARK_CRATE`, a line of JSON a message.
#[test]
#[ignore = "writes the readings of a corpus: PFCP_WIRESHARK_CORPUS and PFCP_WIRESHARK_CRATE"]
fn write_the_readings_of_the_corpus() {
    let corpus =
        std::env::var("PFCP_WIRESHARK_CORPUS").expect("PFCP_WIRESHARK_CORPUS names the corpus");
    let out = std::env::var("PFCP_WIRESHARK_CRATE").expect("PFCP_WIRESHARK_CRATE names the output");
    let corpus = std::fs::read_to_string(corpus).unwrap();
    let mut out = std::io::BufWriter::new(std::fs::File::create(out).unwrap());
    for line in corpus.lines() {
        let (name, octets) = line.split_once('\t').unwrap();
        let octets = hex::decode(octets).unwrap();
        writeln!(out, "{}", reading(name, &octets)).unwrap();
    }
}
