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
    // Open5GS 157f611a: the UPF's first usage report of a URR without ISTM, here of the
    // deletion (TERMR), has no Start Time, which Table 7.5.7.2-1 has but of the start or
    // stop of traffic and of MAC addresses: the time a URR starts is set for ISTM alone
    // (src/upf/n4-handler.c), and a time of 0 is left out (lib/pfcp/build.c).
    (
        "open5gs-5gs-handover",
        "16",
        "Start Time is missing where its condition holds (TS 29.244 7.5.7.2-1), at /pfcp/Usage Report/0/Start Time",
    ),
    (
        "open5gs-5gs-lifecycle",
        "20",
        "Start Time is missing where its condition holds (TS 29.244 7.5.7.2-1), at /pfcp/Usage Report/0/Start Time",
    ),
    (
        "open5gs-5gs-lifecycle",
        "22",
        "Start Time is missing where its condition holds (TS 29.244 7.5.7.2-1), at /pfcp/Usage Report/0/Start Time",
    ),
    (
        "open5gs-5gs-lifecycle",
        "32",
        "Start Time is missing where its condition holds (TS 29.244 7.5.7.2-1), at /pfcp/Usage Report/0/Start Time",
    ),
    (
        "open5gs-5gs-upf-restart",
        "20",
        "Start Time is missing where its condition holds (TS 29.244 7.5.7.2-1), at /pfcp/Usage Report/0/Start Time",
    ),
    (
        "open5gs-5gs-upf-restart",
        "22",
        "Start Time is missing where its condition holds (TS 29.244 7.5.7.2-1), at /pfcp/Usage Report/0/Start Time",
    ),
    // Open5GS 157f611a: the SMF that restores a session to a UPF that restarted (RESTI)
    // gives the header of its establishment the SEID of the UPF from before the restart,
    // where the UPF has none: SEID 0 (§7.2.2.4.2, src/smf/pfcp-path.c).
    (
        "open5gs-5gs-upf-restart",
        "43",
        "a Session Establishment Request of a SEID other than 0 (TS 29.244 7.2.2.4.2), at /header",
    ),
    // Open5GS 157f611a: the SMF as PGW-C sends Create BAR on Sxb, which Table 7.5.2.1-1
    // has on Sxa and N4 only (src/smf/n4-build.c).
    (
        "open5gs-eps-handover",
        "17",
        "Create BAR is not on this interface (TS 29.244 7.5.2.1-1), at /pfcp/Create BAR",
    ),
    (
        "open5gs-eps-handover",
        "17",
        "BAR ID is not on this interface (TS 29.244 7.5.2.6-1), at /pfcp/Create BAR/BAR ID",
    ),
    (
        "open5gs-eps-lifecycle",
        "17",
        "Create BAR is not on this interface (TS 29.244 7.5.2.1-1), at /pfcp/Create BAR",
    ),
    (
        "open5gs-eps-lifecycle",
        "17",
        "BAR ID is not on this interface (TS 29.244 7.5.2.6-1), at /pfcp/Create BAR/BAR ID",
    ),
];

#[test]
fn each_captured_message_is_read_written_and_checked() {
    let mut found = Vec::new();
    let mut count = 0;
    for line in include_str!("captures/messages.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let cells: Vec<&str> = line.split('\t').collect();
        let (run, number, interface, octets) =
            (cells[0], cells[1], cells[4], hex::decode(cells[5]).unwrap());
        let message =
            Message::decode(&octets).unwrap_or_else(|error| panic!("{run} {number}: {error}"));
        assert_eq!(message.encode().unwrap(), octets, "{run} {number}");
        assert!(
            !matches!(message.body, Body::Other { .. }),
            "{run} {number}"
        );
        let tree = message.to_tree();
        assert_eq!(
            Message::from_tree(&tree).unwrap().encode().unwrap(),
            octets,
            "{run} {number}: its tree"
        );
        let interface = match interface {
            "Sxa" => Interfaces::SXA,
            "Sxb" => Interfaces::SXB,
            _ => Interfaces::N4,
        };
        for deviation in message.check(interface) {
            found.push((run.to_string(), number.to_string(), deviation.to_string()));
        }
        count += 1;
    }
    assert_eq!(count, 213);
    let expected: Vec<(String, String, String)> = EXPECTED
        .iter()
        .map(|(run, number, said)| (run.to_string(), number.to_string(), said.to_string()))
        .collect();
    assert_eq!(found, expected);
}
