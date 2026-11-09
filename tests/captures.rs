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
use oxirush_pfcp::{framing, paths, tree};

/// What the check finds in the captures, each a finding of the peer that sent it: the
/// run, the number of the message, and the path, the clause, the kind and the Cause of the
/// deviation.
type Found = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    DeviationKind,
    Option<CauseValue>,
);

/// The Start Time that the deviations below are of.
const START_TIME: DeviationKind = DeviationKind::ConditionalMissing { ie_type: 75 };

const EXPECTED: &[Found] = &[
    // Open5GS 157f611a: the UPF's first usage report of a URR without ISTM, here of the
    // deletion (TERMR), has no Start Time, which Table 7.5.7.2-1 has but of the start or
    // stop of traffic and of MAC addresses: the time a URR starts is set for ISTM alone
    // (src/upf/n4-handler.c), and a time of 0 is left out (lib/pfcp/build.c).
    (
        "open5gs-5gs-handover",
        "16",
        "/pfcp/Usage Report/0/Start Time",
        "7.5.7.2-1",
        START_TIME,
        None,
    ),
    (
        "open5gs-5gs-lifecycle",
        "20",
        "/pfcp/Usage Report/0/Start Time",
        "7.5.7.2-1",
        START_TIME,
        None,
    ),
    (
        "open5gs-5gs-lifecycle",
        "22",
        "/pfcp/Usage Report/0/Start Time",
        "7.5.7.2-1",
        START_TIME,
        None,
    ),
    (
        "open5gs-5gs-lifecycle",
        "32",
        "/pfcp/Usage Report/0/Start Time",
        "7.5.7.2-1",
        START_TIME,
        None,
    ),
    (
        "open5gs-5gs-upf-restart",
        "20",
        "/pfcp/Usage Report/0/Start Time",
        "7.5.7.2-1",
        START_TIME,
        None,
    ),
    (
        "open5gs-5gs-upf-restart",
        "22",
        "/pfcp/Usage Report/0/Start Time",
        "7.5.7.2-1",
        START_TIME,
        None,
    ),
    // Open5GS 157f611a: the SMF that restores a session to a UPF that restarted (RESTI)
    // gives the header of its establishment the SEID of the UPF from before the restart,
    // where the UPF has none: SEID 0 (§7.2.2.4.2, src/smf/pfcp-path.c).
    (
        "open5gs-5gs-upf-restart",
        "43",
        "/header/SEID",
        "7.2.2.4.2",
        DeviationKind::Rule("a Session Establishment Request of a SEID other than 0"),
        None,
    ),
    // Open5GS 157f611a: the SMF as PGW-C sends Create BAR on Sxb, which Table 7.5.2.1-1
    // has on Sxa and N4 only (src/smf/n4-build.c): its receiver discards it whole.
    (
        "open5gs-eps-handover",
        "17",
        "/pfcp/Create BAR",
        "7.5.2.1-1",
        DeviationKind::NotOnInterface { ie_type: 85 },
        None,
    ),
    (
        "open5gs-eps-lifecycle",
        "17",
        "/pfcp/Create BAR",
        "7.5.2.1-1",
        DeviationKind::NotOnInterface { ie_type: 85 },
        None,
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
            let Deviation {
                path,
                clause,
                kind,
                cause,
                ..
            } = deviation;
            found.push((
                run.to_string(),
                number.to_string(),
                path,
                clause,
                kind,
                cause,
            ));
        }
        count += 1;
    }
    assert_eq!(count, 213);
    let expected: Vec<_> = EXPECTED
        .iter()
        .map(|(run, number, path, clause, kind, cause)| {
            let (run, number, path) = (run.to_string(), number.to_string(), path.to_string());
            (run, number, path, *clause, kind.clone(), *cause)
        })
        .collect();
    assert_eq!(found, expected);
}

/// Each deviation is at a path that `paths::select` takes on the tree of its message: of
/// the captures on every interface, and of rows and IE types whose names have a "/",
/// which a path writes "~1".
#[test]
fn each_deviation_is_at_a_path_that_select_takes() {
    let tree = |written| Message::from_tree(&written).unwrap();
    let mut messages: Vec<Message> = include_str!("captures/messages.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| Message::decode(&hex::decode(line.split('\t').nth(5).unwrap()).unwrap()))
        .map(Result::unwrap)
        .collect();
    // A Created/Updated Traffic Endpoint without its ID; an APN/DNN of no row of its
    // table; an HMAC Key (STAMP), of a table of N4 alone, on Sxa
    messages.push(tree(oxirush_utils::tree!({
        "message": "PFCP Session Modification Response", "header": {"SEID": 1, "Sequence Number": 1},
        "ies": {"Cause": 1, "Created/Updated Traffic Endpoint": [{"F-TEID": [{"V4": true, "TEID": 1, "IPv4 address": "10.0.0.2"}]}]}
    })));
    messages.push(tree(oxirush_utils::tree!({
        "message": "PFCP Heartbeat Request", "header": {"Sequence Number": 1},
        "ies": {"Recovery Time Stamp": 7, "APN/DNN": {"octets": "03696d73"}}
    })));
    messages.push(tree(oxirush_utils::tree!({
        "message": "PFCP Association Setup Request", "header": {"Sequence Number": 1},
        "ies": {"Node ID": "10.0.0.1", "Recovery Time Stamp": 7,
            "N6 Delay Measurement Control Information": [{"Measurement Protocols": [{"STAMP": true}],
                "Protocol Specific Configuration Parameters": {"Measurement Protocol": {"STAMP": true}, "HMAC Key (STAMP)": "00"}}]}
    })));
    let mut paths = 0;
    for message in &messages {
        let tree = message.to_tree();
        for interface in [
            Interfaces::SXA,
            Interfaces::SXB,
            Interfaces::SXC,
            Interfaces::N4,
            Interfaces::N4MB,
            Interfaces::SXA_SXB,
        ] {
            for deviation in message.check(interface) {
                let selected = paths::select(&tree, &deviation.path);
                assert!(selected.is_ok(), "{deviation}: {selected:?}");
                paths += 1;
            }
        }
    }
    assert!(paths > 900, "{paths}");
    let escaped = |message: &Message| {
        let found = message.check(Interfaces::N4).into_iter();
        found
            .map(|deviation| deviation.path)
            .filter(|path| path.contains('~'))
    };
    let at = |message| escaped(message).collect::<Vec<_>>();
    let [.., traffic, apn, hmac] = &messages[..] else {
        panic!()
    };
    assert_eq!(
        at(traffic),
        ["/pfcp/Created~1Updated Traffic Endpoint/0/Traffic Endpoint ID"]
    );
    assert_eq!(at(apn), ["/pfcp/APN~1DNN"]);
    assert_eq!(at(hmac), Vec::<String>::new());
}

/// The captures, each with the interface that it was sent on.
fn captures() -> Vec<(Vec<u8>, Interfaces)> {
    let lines = include_str!("captures/messages.tsv").lines();
    let lines = lines.filter(|line| !line.starts_with('#'));
    lines
        .map(|line| {
            let cells: Vec<&str> = line.split('\t').collect();
            let interface = match cells[4] {
                "Sxa" => Interfaces::SXA,
                "Sxb" => Interfaces::SXB,
                _ => Interfaces::N4,
            };
            (hex::decode(cells[5]).unwrap(), interface)
        })
        .collect()
}

/// The path in `tree` of each IE of `ies`, a scope of `table` at `scope`, and of each IE of
/// its grouped IEs, with its content: the IEs of a row whose entry is a value.
fn entries(
    tree: &tree::Value,
    scope: &str,
    table: &Table,
    ies: framing::Ies,
    out: &mut Vec<(String, Vec<u8>)>,
) {
    let mut before: Vec<u16> = Vec::new();
    for ie in ies.map_while(Result::ok) {
        let nth = before.iter().filter(|seen| **seen == ie.ie_type).count();
        before.push(ie.ie_type);
        let Some(row) = table.row_of(ie.ie_type) else {
            continue;
        };
        let mut path = format!("{scope}/{}", tree::escape(row.name));
        let Ok([held]) = <[_; 1]>::try_from(paths::select(tree, &path).unwrap()) else {
            continue;
        };
        let entry = match held {
            tree::Value::Array(entries) => {
                path = format!("{path}/{nth}");
                &entries[nth]
            }
            single => single,
        };
        if entry.get("octets").is_some() {
            continue;
        }
        out.push((path.clone(), ie.value.to_vec()));
        let inner = ie_type_info(ie.ie_type)
            .into_iter()
            .flat_map(|info| info.tables.iter())
            .find(|inner| {
                ie.ies()
                    .all(|ie| ie.is_ok_and(|ie| inner.row_of(ie.ie_type).is_some()))
            });
        if let Some(inner) = inner
            && entry.is_object()
        {
            entries(tree, &path, inner, ie.ies(), out);
        }
    }
}

/// That `check()` finds of `message` what it finds of its octets decoded, on each of
/// `interfaces`: those of a message that a tree writes decode, as it writes no false
/// Length.
fn checked_as_its_octets(message: &Message, interfaces: &[Interfaces], what: &str) {
    let octets = message
        .encode()
        .unwrap_or_else(|error| panic!("{what}: {error}"));
    let decoded = Message::decode(&octets).unwrap_or_else(|error| panic!("{what}: {error}"));
    for interface in interfaces {
        assert_eq!(
            message.check(*interface),
            decoded.check(*interface),
            "{what}: {}",
            hex::encode(&octets)
        );
    }
}

/// Each message of `octets`, and the same with each IE, at every level of its grouped
/// IEs, written as its octets, then as an IE of a null length in its place, and before it
/// where its row has one IE: `check(m)` is `check(Message::decode(m.encode()))` of each,
/// and of each IE written as its octets, what it finds in the message. How many there are.
fn written_as_octets(octets: &[u8], interfaces: &[Interfaces]) -> usize {
    let Ok(message) = Message::decode(octets) else {
        return 0;
    };
    let Some(table) = message.body.table() else {
        return 0;
    };
    checked_as_its_octets(&message, interfaces, "the message");
    let tree = message.to_tree();
    // A message whose tree writes it in the order of its tables, which a message of
    // another order does not: what check() finds is the same of both
    let same =
        Message::from_tree(&tree).is_ok_and(|read| read.encode().ok().as_deref() == Some(octets));
    let (_, _, ies) = framing::message_ies(octets).unwrap();
    let mut found = Vec::new();
    entries(&tree, "/pfcp", table, ies, &mut found);
    let mut count = 0;
    for (path, content) in found {
        let null = oxirush_utils::tree!({"octets": ""});
        let mut variants = Vec::new();
        for value in [
            oxirush_utils::tree!({"octets": hex::encode(&content)}),
            null.clone(),
        ] {
            let mut written = tree.clone();
            paths::set(&mut written, &path, value).unwrap();
            variants.push(written);
        }
        let [held] = &paths::select(&tree, &path).unwrap()[..] else {
            panic!("{path}")
        };
        if !paths::select(&tree, path.rsplit_once('/').unwrap().0)
            .unwrap()
            .iter()
            .any(|parent| parent.is_array())
        {
            let mut written = tree.clone();
            let before = tree::Value::Array(vec![null.clone(), (*held).clone()]);
            paths::set(&mut written, &path, before).unwrap();
            variants.push(written);
        }
        for (nth, written) in variants.iter().enumerate() {
            let read =
                Message::from_tree(written).unwrap_or_else(|error| panic!("{path}: {error}"));
            checked_as_its_octets(&read, interfaces, &path);
            if nth == 0 && same {
                for interface in interfaces {
                    assert_eq!(read.check(*interface), message.check(*interface), "{path}");
                }
            }
            count += 1;
        }
    }
    count
}

/// A message is checked as its receiver reads its octets: `check(m)` is
/// `check(Message::decode(m.encode()))` of each capture and of each of its IEs, at every
/// level of its grouped IEs, written as its octets, of a null length, or after an IE of a
/// null length of its row; one written as its octets is checked as its value, and changes
/// nothing of what `check()` finds.
#[test]
fn a_message_is_checked_as_its_octets() {
    let mut count = 0;
    for (octets, interface) in captures() {
        count += written_as_octets(&octets, &[interface]);
    }
    assert!(count > 4_000, "{count}");
}

/// The same of the messages of a corpus of the fuzz targets, the files of the directory
/// `PFCP_CORPUS`, on each interface.
#[test]
#[ignore = "of a corpus: PFCP_CORPUS=fuzz/corpus/decode cargo test --test captures -- --ignored"]
fn a_message_is_checked_as_its_octets_in_a_corpus() {
    let directory = std::env::var("PFCP_CORPUS").expect("PFCP_CORPUS names a directory");
    let interfaces = [
        Interfaces::SXA,
        Interfaces::SXB,
        Interfaces::SXC,
        Interfaces::N4,
        Interfaces::N4MB,
        Interfaces::SXA_SXB,
    ];
    let (mut files, mut count) = (0, 0);
    for entry in std::fs::read_dir(directory).unwrap() {
        let octets = std::fs::read(entry.unwrap().path()).unwrap();
        count += written_as_octets(&octets, &interfaces);
        files += 1;
    }
    println!("{files} files, {count} messages with an IE written otherwise");
    assert!(count > 0);
}
