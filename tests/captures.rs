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

//! The PFCP messages that Open5GS and free5GC sent in lab runs (tests/README.md says
//! which): each decodes, encodes back to its octets, has a tree that reads back, and is
//! checked on its interface, where only the deviations of `EXPECTED` are found.

use oxirush_pfcp::*;

/// What the check finds in the captures, each a finding of the peer that sent it: the
/// run, the number of the message, and the deviation as it is displayed.
const EXPECTED: &[(&str, &str, &str)] = &[
    // Open5GS 157f611a: the SMF as PGW-C sends Create BAR on Sxb, which Table 7.5.2.1-1
    // has on Sxa and N4 only (src/smf/n4-build.c).
    ("open5gs-eps-handover", "17", "Create BAR is not on this interface (TS 29.244 7.5.2.1-1), at /pfcp/Create BAR"),
    ("open5gs-eps-handover", "17", "BAR ID is not on this interface (TS 29.244 7.5.2.6-1), at /pfcp/Create BAR/BAR ID"),
    ("open5gs-eps-lifecycle", "17", "Create BAR is not on this interface (TS 29.244 7.5.2.1-1), at /pfcp/Create BAR"),
    ("open5gs-eps-lifecycle", "17", "BAR ID is not on this interface (TS 29.244 7.5.2.6-1), at /pfcp/Create BAR/BAR ID"),
];

#[test]
fn each_captured_message_is_read_written_and_checked() {
    let mut found = Vec::new();
    let mut count = 0;
    for line in include_str!("captures/messages.tsv").lines().filter(|line| !line.starts_with('#')) {
        let cells: Vec<&str> = line.split('\t').collect();
        let (run, number, interface, octets) = (cells[0], cells[1], cells[4], hex::decode(cells[5]).unwrap());
        let message = Message::decode(&octets).unwrap_or_else(|error| panic!("{run} {number}: {error}"));
        assert_eq!(message.encode().unwrap(), octets, "{run} {number}");
        assert!(!matches!(message.body, Body::Other { .. }), "{run} {number}");
        let tree = message.to_tree();
        assert_eq!(Message::from_tree(&tree).unwrap().encode().unwrap(), octets, "{run} {number}: its tree");
        let interface = match interface {
            "Sxa" => Interfaces::SXA,
            "Sxb" => Interfaces::SXB,
            _ => Interfaces::N4,
        };
        for deviation in message.check_on(interface) {
            found.push((run.to_string(), number.to_string(), deviation.to_string()));
        }
        count += 1;
    }
    assert_eq!(count, 213);
    let expected: Vec<(String, String, String)> = EXPECTED.iter().map(|(run, number, said)| (run.to_string(), number.to_string(), said.to_string())).collect();
    assert_eq!(found, expected);
}
