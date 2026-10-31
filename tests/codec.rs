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

//! The codec of a typed message from its table is lossless, its tree reads back, its paths
//! go through the engine of oxirush-utils, and `check()` names the clause of each
//! deviation.

use std::net::Ipv4Addr;

use oxirush_pfcp::tree::{select, set};
use oxirush_pfcp::*;
use oxirush_utils::tree;

/// A Session Establishment Request of an SMF: one uplink PDR whose F-TEID the UPF
/// chooses, one downlink PDR to the UE's address.
fn establishment() -> Message {
    let uplink = CreatePdr::new_n4(
        PdrId::new(1),
        Precedence::new(255),
        Pdi::new(SourceInterface::new(SourceInterfaceValue::Access))
            .with_local_f_teid(FTeid::choose_ipv4()),
    )
    .with_far_id(FarId::new(1))
    .with_urr_id(UrrId::new(1));
    let ue = UeIpAddress {
        v4: true,
        sd: true,
        ipv4: Some(Ipv4Addr::new(10, 45, 0, 2)),
        ..Default::default()
    };
    let downlink = CreatePdr::new_n4(
        PdrId::new(2),
        Precedence::new(255),
        Pdi::new(SourceInterface::new(SourceInterfaceValue::Core)).with_ue_ip_address(ue),
    )
    .with_far_id(FarId::new(2));
    let smf = Ipv4Addr::new(10, 0, 0, 1);
    let seid = FSeid {
        v4: true,
        seid: Some(0x1001),
        ipv4: Some(smf),
        ..Default::default()
    };
    let request = SessionEstablishmentRequest::new_n4(
        NodeId::Ipv4(smf),
        seid,
        uplink,
        CreateFar::new(
            FarId::new(1),
            ApplyAction {
                forw: true,
                ..Default::default()
            },
        ),
    )
    .with_create_pdr(downlink);
    Message {
        header: Header::session(0, 7),
        body: request.into(),
    }
}

#[test]
fn a_built_message_is_in_the_order_of_its_table_and_decodes_back() {
    let message = establishment();
    let octets = message.encode().unwrap();
    let decoded = Message::decode(&octets).unwrap();
    assert_eq!(decoded.clone(), message);
    assert_eq!(decoded.encode().unwrap(), octets);
    let Body::SessionEstablishmentRequest(request) = &decoded.body else {
        panic!()
    };
    assert!(
        request.order.is_empty(),
        "a built message is in the order of its table"
    );
    let pdi = request.create_pdr[0].pdi.as_ref().unwrap();
    assert!(pdi.local_f_teid.as_ref().unwrap().ch);
}

#[test]
fn the_tree_reads_back_and_a_path_edits_it() {
    let message = establishment();
    let mut tree = message.to_tree();
    println!("{tree}");
    let read = Message::from_tree(&tree).unwrap();
    assert_eq!(read.encode().unwrap(), message.encode().unwrap());

    // The UE's address by its path, in any case
    let ue = select(&tree, "/pfcp/Create PDR/1/PDI/UE IP address/0/IPv4 address").unwrap();
    assert_eq!(ue, [&tree!("10.45.0.2")]);
    let teids = select(&tree, "/PFCP/create pdr/*/pdi/local-f-teid").unwrap();
    assert_eq!(teids, [&tree!({"V4": true, "CH": true})]);

    // An edit, then the message again
    set(
        &mut tree,
        "/pfcp/Create PDR/1/PDI/UE IP address/0/IPv4 address",
        "10.45.0.3",
    )
    .unwrap();
    let edited = Message::from_tree(&tree).unwrap();
    let Body::SessionEstablishmentRequest(request) = &edited.body else {
        panic!()
    };
    let address = request.create_pdr[1].pdi.as_ref().unwrap().ue_ip_address[0].ipv4;
    assert_eq!(address, Some(Ipv4Addr::new(10, 45, 0, 3)));

    // A misspelt name is refused, and says the nearest
    let mut wrong = message.to_tree();
    wrong["ies"]["Create PDR"][0]["PDI"]
        .as_object_mut()
        .unwrap()
        .insert("Local F-TEIDD".into(), tree!({}));
    let error = Message::from_tree(&wrong).unwrap_err().to_string();
    assert!(error.contains("Local F-TEID"), "{error}");
}

#[test]
fn what_the_table_does_not_have_is_kept_in_its_place() {
    let message = establishment();
    let mut octets = message.encode().unwrap();
    // After the header: a vendor IE, an IE of no release, a second Node ID, a Recovery
    // Time Stamp of a null length, all before the IEs of the table
    let extra: &[u8] = &[
        0x80, 0x01, 0x00, 0x04, 0x48, 0x79, 0xca, 0xfe, // vendor 32769, Enterprise ID 18553
        0x7f, 0xff, 0x00, 0x01, 0x42, // IE type 32767
        0x00, 0x3c, 0x00, 0x05, 0x00, 10, 0, 0, 9, // Node ID again
        0x00, 0x60, 0x00, 0x00, // Recovery Time Stamp, null length
    ];
    octets.splice(16..16, extra.iter().copied());
    let length = (octets.len() - 4) as u16;
    octets[2..4].copy_from_slice(&length.to_be_bytes());

    let decoded = Message::decode(&octets).unwrap();
    assert_eq!(
        decoded.encode().unwrap(),
        octets,
        "decode then encode gives the octets back"
    );
    let Body::SessionEstablishmentRequest(request) = &decoded.body else {
        panic!()
    };
    assert_eq!(request.raw.len(), 4);
    assert_eq!(
        request.node_id,
        Some(NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 9)))
    );

    let tree = decoded.to_tree();
    println!("{tree}");
    // The tree is in the order of the table, the IEs of a row together: the second Node
    // ID with the first, the vendor IE and the IE of no release last. The message means
    // the same, and its tree is the same.
    let read = Message::from_tree(&tree).unwrap();
    let encoded = read.encode().unwrap();
    let again = Message::decode(&encoded).unwrap();
    assert_eq!(again.to_tree(), tree);
    assert_eq!(read.encode().unwrap().len(), octets.len());

    let found = decoded.check(Interfaces::N4);
    for deviation in &found {
        println!("{deviation}");
    }
    let clauses: Vec<&str> = found.iter().map(|deviation| deviation.clause).collect();
    assert!(
        clauses.contains(&"7.6.10"),
        "the second Node ID is a repetition"
    );
    assert!(clauses.contains(&"8.1.2"), "IE type 32767 is in no release");
}

#[test]
fn check_names_the_clause() {
    let mut message = establishment();
    let Body::SessionEstablishmentRequest(request) = &mut message.body else {
        panic!()
    };
    request.node_id = None;
    let f_teid = request.create_pdr[0]
        .pdi
        .as_mut()
        .unwrap()
        .local_f_teid
        .as_mut()
        .unwrap();
    f_teid.chid = true;
    f_teid.choose_id = Some(1);
    f_teid.ch = false;
    f_teid.teid = Some(5);
    message.header.seid = None;
    let found = message.check(Interfaces::N4);
    for deviation in &found {
        println!("{deviation}");
    }
    let said: Vec<String> = found.iter().map(ToString::to_string).collect();
    assert!(
        said.iter()
            .any(|said| said.contains("Node ID is missing") && said.contains("7.5.2.1-1"))
    );
    assert!(said.iter().any(|said| said.contains(
        "CHID is set and CH is not (TS 29.244 8.2.3), at /pfcp/Create PDR/0/PDI/Local F-TEID"
    )));
    assert!(said.iter().any(|said| said.contains("no SEID")));
    assert_eq!(
        found[1].cause(),
        Some(CauseValue::MandatoryIeMissing),
        "{}",
        found[1]
    );
}

#[test]
fn a_false_length_is_written_and_does_not_decode() {
    let mut message = establishment();
    let Body::SessionEstablishmentRequest(request) = &mut message.body else {
        panic!()
    };
    request.raw.push(RawIe {
        length: Some(40),
        ..RawIe::new(96, vec![0xdf, 0xd5, 0x2c, 0x00])
    });
    let octets = message.encode().unwrap();
    match Message::decode(&octets) {
        Err(Error::Ies { header, fault, .. }) => {
            assert_eq!(header.sequence, 7);
            assert_eq!(
                fault,
                IeFault::Length {
                    ie_type: 96,
                    length: 40,
                    available: 4
                }
            );
        }
        other => panic!("{other:?}"),
    }
    message.header.length = Some(9);
    let octets = message.encode().unwrap();
    assert!(matches!(
        Message::decode(&octets),
        Err(Error::MessageLength { length: 9, .. })
    ));
}

#[test]
fn a_flag_that_disagrees_is_refused_where_it_is_written() {
    let message = establishment();
    let mut tree = message.to_tree();
    set(
        &mut tree,
        "/pfcp/Create PDR/0/PDI/Local F-TEID/IPv4 address",
        "10.0.0.5",
    )
    .unwrap();
    let error = Message::from_tree(&tree).unwrap_err().to_string();
    println!("{error}");
    assert!(
        error.contains("IPv4 address is written where its flags do not have it"),
        "{error}"
    );
}

/// The vectors of another implementation, when `PFCP_VECTORS` names their file: each
/// decodes and encodes back to its octets, and its tree, in the order of its tables,
/// reads back to itself. A fourth column names the
/// interface to check the message on; without it, on N4 with the IEs of any interface.
#[test]
fn other_vectors_round_trip() {
    let Ok(file) = std::env::var("PFCP_VECTORS") else {
        return;
    };
    let (mut read, mut reordered) = (0, 0);
    for line in std::fs::read_to_string(file).unwrap().lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let octets = hex::decode(fields[2]).unwrap();
        let messages: Vec<Message> = Message::decode_datagram(&octets)
            .into_iter()
            .collect::<Result<_, _>>()
            .unwrap_or_else(|error| panic!("{} {}: {error}", fields[0], fields[1]));
        let mut again = Vec::new();
        for message in &messages {
            again.extend(message.encode().unwrap());
            // The tree is the message in the order of its tables: it reads back to itself,
            // and so do the octets that it encodes; they are the message's own when its IEs
            // came in that order.
            let tree = message.to_tree();
            let back = Message::from_tree(&tree).unwrap();
            let encoded = back.encode().unwrap();
            assert_eq!(back.to_tree(), tree, "{} {}", fields[0], fields[1]);
            assert_eq!(
                Message::decode(&encoded).unwrap().to_tree(),
                tree,
                "{} {}",
                fields[0],
                fields[1]
            );
            assert_eq!(
                encoded.len(),
                message.encode().unwrap().len(),
                "{} {}",
                fields[0],
                fields[1]
            );
            if encoded != message.encode().unwrap() {
                reordered += 1;
            }
            if !matches!(message.body, Body::Other { .. }) {
                read += 1;
                println!("{} {}: {tree}", fields[0], fields[1]);
                let interface = match fields.get(3).copied() {
                    Some("Sxa") => Interfaces::SXA,
                    Some("Sxb") => Interfaces::SXB,
                    Some("Sxc") => Interfaces::SXC,
                    Some("N4mb") => Interfaces::N4MB,
                    _ => Interfaces::N4,
                };
                // A vector of no interface may have the IEs of any.
                let any = fields.len() < 4;
                for deviation in message.check(interface) {
                    if !(any && matches!(deviation.kind, DeviationKind::NotOnInterface { .. })) {
                        println!("  {deviation}");
                    }
                }
            }
        }
        assert_eq!(again, octets, "{} {}", fields[0], fields[1]);
    }
    println!(
        "{read} messages read by their tables, {reordered} of them not in the order of their tables"
    );
    assert!(read > 0, "no vector in the file");
}

/// The IE types of a scope, depth first, by the forms of the registry: what a dissector
/// lists in the order of the wire.
fn ie_types(mut octets: &[u8], out: &mut Vec<u16>) {
    while octets.len() >= 4 {
        let ie_type = u16::from_be_bytes([octets[0], octets[1]]);
        let length = usize::from(u16::from_be_bytes([octets[2], octets[3]]));
        let Some(body) = octets.get(4..4 + length) else {
            return;
        };
        out.push(ie_type);
        if ie_type_info(ie_type).is_some_and(|info| info.form == Form::Grouped) {
            ie_types(body, out);
        }
        octets = &octets[4 + length..];
    }
}

/// For a comparison with a dissector, when `PFCP_DUMP` names a file: each message of
/// `PFCP_VECTORS` and of this file, its IE types depth first, and values by their paths.
#[test]
fn dump_for_a_dissector() {
    let (Ok(file), Ok(dump)) = (std::env::var("PFCP_VECTORS"), std::env::var("PFCP_DUMP")) else {
        return;
    };
    let mut messages: Vec<(String, Vec<u8>)> = std::fs::read_to_string(file)
        .unwrap()
        .lines()
        .map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            (
                format!("{} {}", fields[0], fields[1]),
                hex::decode(fields[2]).unwrap(),
            )
        })
        .collect();
    messages.push(("establishment".into(), establishment().encode().unwrap()));
    let paths = [
        (
            "pfcp.f_teid.teid",
            "/pfcp/Create PDR/*/PDI/Local F-TEID/TEID",
        ),
        (
            "pfcp.f_teid.ipv4_addr",
            "/pfcp/Create PDR/*/PDI/Local F-TEID/IPv4 address",
        ),
        ("pfcp.pdr_id", "/pfcp/Create PDR/*/PDR ID"),
        ("pfcp.precedence", "/pfcp/Create PDR/*/Precedence"),
        (
            "pfcp.source_interface",
            "/pfcp/Create PDR/*/PDI/Source Interface",
        ),
        (
            "pfcp.ue_ip_addr_ipv4",
            "/pfcp/Create PDR/*/PDI/UE IP address/*/IPv4 address",
        ),
        ("pfcp.f_seid.ipv4", "/pfcp/CP F-SEID/IPv4 address"),
        ("pfcp.node_id_fqdn", "/pfcp/Node ID/FQDN"),
        ("pfcp.seid", "/SEID"),
    ];
    let mut lines = Vec::new();
    for (name, octets) in messages {
        let Ok(message) = Message::decode(&octets) else {
            continue;
        };
        if !matches!(message.body, Body::SessionEstablishmentRequest(_)) {
            continue;
        }
        let mut types = Vec::new();
        ie_types(&octets[message.header.len()..], &mut types);
        let tree = message.to_tree();
        let mut values = tree::Map::new();
        for (field, path) in paths {
            let found: Vec<tree::Value> = select(&tree, path)
                .unwrap_or_default()
                .into_iter()
                .cloned()
                .collect();
            values.insert(field.into(), tree::Value::Array(found));
        }
        let line = tree!({"name": name, "hex": hex::encode(&octets), "types": types, "values": tree::Value::Object(values)});
        lines.push(line.to_string());
    }
    std::fs::write(dump, lines.join("\n") + "\n").unwrap();
}

/// Rough times of the codec and the tree, in an optimized build: `cargo test --release
/// --features tree --test codec rough_times -- --ignored --nocapture`. No figure of it is
/// evidence: the machine is shared.
#[test]
#[ignore]
fn rough_times() {
    use std::hint::black_box;
    use std::time::Instant;
    let octets = establishment().encode().unwrap();
    let message = Message::decode(&octets).unwrap();
    let tree = message.to_tree();
    let rounds = 200_000;
    let time = |name: &str, run: &mut dyn FnMut()| {
        for _ in 0..rounds / 10 {
            run();
        }
        let start = Instant::now();
        for _ in 0..rounds {
            run();
        }
        println!(
            "{name}: {:.0} ns",
            start.elapsed().as_nanos() as f64 / rounds as f64
        );
    };
    println!("{} octets", octets.len());
    time("decode", &mut || {
        drop(black_box(Message::decode(black_box(&octets)).unwrap()))
    });
    time("encode", &mut || {
        drop(black_box(black_box(&message).encode().unwrap()))
    });
    time("check", &mut || {
        drop(black_box(black_box(&message).check(Interfaces::N4)))
    });
    time("to_tree", &mut || {
        drop(black_box(black_box(&message).to_tree()))
    });
    time("from_tree", &mut || {
        drop(black_box(Message::from_tree(black_box(&tree)).unwrap()))
    });
    time("edit by path, from_tree and encode", &mut || {
        let mut tree = tree.clone();
        set(
            &mut tree,
            "/pfcp/Create PDR/1/PDI/UE IP address/0/IPv4 address",
            "10.45.0.3",
        )
        .unwrap();
        drop(black_box(
            Message::from_tree(&tree).unwrap().encode().unwrap(),
        ));
    });
}

/// A message whose IEs come in another order than their table's (§8.1.2 has a receiver
/// take them in any order): its octets encode back as they came, and its tree is in the
/// order of the table, as the tree of the message in that order is.
#[test]
fn a_tree_is_in_the_order_of_the_tables() {
    let message = establishment();
    let octets = message.encode().unwrap();
    // The IEs of the message level.
    let (_, _, ies) = oxirush_pfcp::framing::message_ies(&octets).unwrap();
    let ies: Vec<Vec<u8>> = ies
        .map(|ie| {
            let ie = ie.unwrap();
            [
                &ie.ie_type.to_be_bytes()[..],
                &ie.length.to_be_bytes(),
                ie.content(),
            ]
            .concat()
        })
        .collect();
    let header = octets.len() - ies.iter().map(Vec::len).sum::<usize>();
    // Create FAR, the last IE, first: the two Create PDRs keep their order, as a list does.
    let mut reordered = octets[..header].to_vec();
    for ie in ies[ies.len() - 1..].iter().chain(&ies[..ies.len() - 1]) {
        reordered.extend_from_slice(ie);
    }
    let decoded = Message::decode(&reordered).unwrap();
    assert_eq!(
        decoded.encode().unwrap(),
        reordered,
        "the octets keep the order of the wire"
    );
    assert_eq!(
        decoded.to_tree(),
        message.to_tree(),
        "the tree has the order of the table"
    );
    assert_eq!(
        Message::from_tree(&decoded.to_tree())
            .unwrap()
            .encode()
            .unwrap(),
        octets
    );
}

/// A row that is there once, whose first IE does not decode and the second does: the
/// first is the one handled (§7.6.10), and the second is kept as octets, after it; the
/// tree has both, and reads back to the same octets (found by the fuzz target `tree`).
#[test]
fn the_first_ie_of_a_row_there_once_is_its_value() {
    let message = establishment();
    let mut octets = message.encode().unwrap();
    // A CP F-SEID cut after its SEID, before the CP F-SEID of the message
    let cut: &[u8] = &[0x00, 0x39, 0x00, 0x09, 0x02, 0, 0, 0, 0, 0, 0, 0x10, 0x01];
    let at = 16 + 9;
    assert_eq!(&octets[at..at + 2], &[0x00, 0x39]);
    octets.splice(at..at, cut.iter().copied());
    let length = (octets.len() - 4) as u16;
    octets[2..4].copy_from_slice(&length.to_be_bytes());
    let decoded = Message::decode(&octets).unwrap();
    let Body::SessionEstablishmentRequest(request) = &decoded.body else {
        panic!()
    };
    assert_eq!(request.cp_f_seid, None);
    assert_eq!(request.raw.len(), 2);
    assert_eq!(decoded.encode().unwrap(), octets);
    let tree = decoded.to_tree();
    assert!(tree["ies"]["CP F-SEID"].is_array(), "{tree}");
    let back = Message::from_tree(&tree).unwrap();
    assert_eq!(back.to_tree(), tree);
    assert_eq!(back.encode().unwrap(), octets);
}

/// An IE of no row whose type has the name of another row of the table: Packet Rate
/// Status Report (type 252) in a Session Modification Response, whose row of that name
/// is of type 264. Its tree is under its number, and reads back to the same octets
/// (found by the fuzz target `tree`).
#[test]
fn an_ie_of_no_row_named_as_a_row() {
    for (ie_type, length) in [(252u16, 0u16), (252, 2), (264, 0)] {
        let response = SessionModificationResponse::new(Cause::new(CauseValue::RequestAccepted));
        let mut octets = Message {
            header: Header::session(1, 9),
            body: response.into(),
        }
        .encode()
        .unwrap();
        octets.extend_from_slice(&ie_type.to_be_bytes());
        octets.extend_from_slice(&length.to_be_bytes());
        octets.extend(std::iter::repeat_n(0xff, usize::from(length)));
        let total = (octets.len() - 4) as u16;
        octets[2..4].copy_from_slice(&total.to_be_bytes());
        let decoded = Message::decode(&octets).unwrap();
        let tree = decoded.to_tree();
        let back = Message::from_tree(&tree)
            .unwrap_or_else(|error| panic!("{ie_type} of {length}: {error}: {tree}"));
        assert_eq!(
            back.encode().unwrap(),
            octets,
            "{ie_type} of {length}: {tree}"
        );
    }
}

/// Every row of every message, a list or not, with each kind of kept IE in it: one of a
/// null length, one that does not decode, each once and repeated; and each row of the
/// grouped IEs that a message has at its level, in one of them. Each tree reads back to
/// itself, and to the octets that it encodes.
#[test]
fn kept_ies_in_every_row_read_back() {
    // An IE: its type, its length, its content.
    let ie = |ie_type: u16, content: &[u8]| {
        [
            &ie_type.to_be_bytes()[..],
            &(content.len() as u16).to_be_bytes(),
            content,
        ]
        .concat()
    };
    let message = |message_type: u8, ies: &[u8]| {
        let session = !is_node_related(message_type);
        let header = if session {
            Header::session(1, 9)
        } else {
            Header::node(9)
        };
        let mut octets = Message {
            header,
            body: HeartbeatRequest::default().into(),
        }
        .encode()
        .unwrap();
        octets[1] = message_type;
        octets.truncate(if session { 16 } else { 8 });
        octets.extend_from_slice(ies);
        let total = (octets.len() - 4) as u16;
        octets[2..4].copy_from_slice(&total.to_be_bytes());
        octets
    };
    let read_back = |octets: &[u8], what: &str| {
        let decoded = Message::decode(octets).unwrap_or_else(|error| panic!("{what}: {error}"));
        let tree = decoded.to_tree();
        let back =
            Message::from_tree(&tree).unwrap_or_else(|error| panic!("{what}: {error}: {tree}"));
        assert_eq!(back.to_tree(), tree, "{what}");
        assert_eq!(
            Message::decode(&back.encode().unwrap()).unwrap().to_tree(),
            tree,
            "{what}"
        );
    };
    let kinds: [(&[u8], usize); 4] = [(&[], 1), (&[], 2), (&[0xff], 1), (&[0xff], 2)];
    let mut checked = 0;
    for info in MESSAGE_TYPES {
        let messages = info.table;
        for row in messages.rows {
            for (content, copies) in kinds {
                let ies: Vec<u8> = (0..copies).flat_map(|_| ie(row.ie_type, content)).collect();
                read_back(
                    &message(info.message_type, &ies),
                    &format!("{} {} {content:?} x{copies}", messages.name, row.name),
                );
                checked += 1;
            }
            // The rows of a grouped IE of the message, in it
            for table in IE_TYPES
                .iter()
                .filter(|ie_type| ie_type.ie_type == row.ie_type)
                .flat_map(|ie_type| ie_type.tables)
            {
                for inner in table.rows {
                    for (content, copies) in kinds {
                        let inside: Vec<u8> = (0..copies)
                            .flat_map(|_| ie(inner.ie_type, content))
                            .collect();
                        let what = format!(
                            "{} {} {} {content:?} x{copies}",
                            messages.name, row.name, inner.name
                        );
                        read_back(
                            &message(info.message_type, &ie(row.ie_type, &inside)),
                            &what,
                        );
                        checked += 1;
                    }
                }
            }
        }
    }
    // The IEs of a type that no row of the message has, whose name is a row's
    let letters = |name: &str| {
        name.chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|c| c.to_ascii_lowercase())
            .collect::<String>()
    };
    for info in MESSAGE_TYPES {
        let rows = info.table.rows;
        for other in IE_TYPES
            .iter()
            .filter(|other| rows.iter().all(|row| row.ie_type != other.ie_type))
        {
            if rows
                .iter()
                .any(|row| letters(row.name) == letters(other.name))
            {
                for (content, copies) in kinds {
                    let ies: Vec<u8> = (0..copies)
                        .flat_map(|_| ie(other.ie_type, content))
                        .collect();
                    read_back(
                        &message(info.message_type, &ies),
                        &format!(
                            "{} {} {content:?} x{copies}",
                            info.table.name, other.ie_type
                        ),
                    );
                    checked += 1;
                }
            }
        }
    }
    // And in the grouped IEs of a message
    for info in MESSAGE_TYPES {
        for row in info.table.rows {
            for table in IE_TYPES
                .iter()
                .filter(|ie_type| ie_type.ie_type == row.ie_type)
                .flat_map(|ie_type| ie_type.tables)
            {
                let rows = table.rows;
                for other in IE_TYPES
                    .iter()
                    .filter(|other| rows.iter().all(|inner| inner.ie_type != other.ie_type))
                {
                    if rows
                        .iter()
                        .any(|inner| letters(inner.name) == letters(other.name))
                    {
                        let inside = ie(other.ie_type, &[]);
                        read_back(
                            &message(info.message_type, &ie(row.ie_type, &inside)),
                            &format!("{} {} {}", info.table.name, row.name, other.ie_type),
                        );
                        checked += 1;
                    }
                }
            }
        }
    }
    assert!(checked > 3600, "{checked}");
}

/// §8.2.38: a Node ID as its receiver takes it, the spare bits of its type and the octets
/// after its value ignored (§8.1.2); and its tree, which reads back to its octets in each
/// form (the FQDN forms found by a fuzz target that compares octets).
#[test]
fn node_id_forms() {
    let read = |content: &[u8]| NodeId::decode(content).unwrap();
    let address = NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(
        read(&[0x10, 10, 0, 0, 1]).effective(),
        Some(address.clone())
    );
    assert_eq!(read(&[0, 10, 0, 0, 1, 0xff]).effective(), Some(address));
    assert_eq!(read(&[5, 10, 0, 0, 1]).effective(), None);
    assert_eq!(read(&[0, 10, 0, 0]).effective(), None);
    let fqdn = |labels: &[u8]| read(&[&[2], labels].concat());
    assert_eq!(
        fqdn(&[3, b'u', b'p', b'f', 2, b'e', b'x'])
            .fqdn()
            .as_deref(),
        Some("upf.ex")
    );
    for labels in [
        &[3, b'a', b'.', b'b'][..],
        &[0, 0],
        &[1, b'a', 0, 0],
        &[2, 0xc3, 0x28],
        &[3, b'a'],
    ] {
        assert_eq!(fqdn(labels).fqdn(), None, "{labels:?}");
    }
    let long = [&[64][..], &[b'a'; 64]].concat();
    assert_eq!(fqdn(&long).fqdn(), None);
    for content in [
        &[0x10, 10, 0, 0, 1][..],
        &[0, 10, 0, 0, 1, 0xff],
        &[5, 1, 2],
        &[2, 3, b'a', b'.', b'b'],
        &[2, 0, 0],
        &[2, 1, b'a', 0, 0],
        &[2, 2, 0xc3, 0x28],
        &[0x12, 1, b'a'],
        &[[2].as_slice(), &long].concat(),
    ] {
        let node_id = read(content);
        let tree = tree::Tree::to_tree(&node_id);
        let back: NodeId =
            tree::from_value(&tree).unwrap_or_else(|error| panic!("{content:?}: {error}: {tree}"));
        let mut octets = Vec::new();
        Codec::encode(&back, &mut octets).unwrap();
        assert_eq!(octets, content, "{tree}");
    }
    for name in ["a..b", "", ".a", "a.", &"a".repeat(64)] {
        let written = tree!({"FQDN": name});
        assert!(tree::from_value::<NodeId>(&written).is_err(), "{name}");
    }
}

/// A session related message of `message_type`, its FO flag and its IEs.
fn bundled(message_type: u8, follow_on: bool, ies: &[u8]) -> Vec<u8> {
    let flags = 0x21 | u8::from(follow_on) << 2;
    [
        &[flags, message_type][..],
        &((12 + ies.len()) as u16).to_be_bytes(),
        &1u64.to_be_bytes(),
        &[0, 0, 7, 0],
        ies,
    ]
    .concat()
}

/// §6.5, §7.2.1A, §7.6.3: each message of a datagram is decoded on its own; one that does
/// not decode is an error in its place, and does not take the others with it. The last
/// message is the rest of the datagram, and an FO flag on it says that a message follows
/// that is not there.
#[test]
fn each_message_of_a_datagram_on_its_own() {
    let heartbeat = Message {
        header: Header::node(1),
        ..heartbeat_request()
    }
    .encode()
    .unwrap();
    let junk = [
        heartbeat.clone(),
        vec![0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3, 4, 5],
    ]
    .concat();
    assert!(matches!(
        &Message::decode_datagram(&junk)[..],
        [Err(Error::MessageLength {
            length: 12,
            available: 22,
            ..
        })]
    ));
    assert!(Message::decode(&junk).is_err());
    let first = bundled(52, true, &[]);
    let cut = [first.clone(), vec![0x21, 52, 0, 0xff]].concat();
    assert!(matches!(
        &Message::decode_datagram(&cut)[..],
        [Ok(_), Err(Error::TooShort { octets: 4 })]
    ));
    assert!(matches!(
        &Message::decode_datagram(&first)[..],
        [Ok(_), Err(Error::TooShort { octets: 0 })]
    ));
    // An IE that runs past its message, then a message that decodes
    let broken = [
        bundled(52, true, &[0, 60, 0, 9, 0]),
        bundled(54, false, &[]),
    ]
    .concat();
    let messages = Message::decode_datagram(&broken);
    assert!(
        matches!(&messages[..], [Err(Error::Ies { .. }), Ok(message)] if message.body.message_type() == 54),
        "{messages:?}"
    );
    // A Message Length that runs past the datagram ends it
    let past = [bundled(52, true, &[])[..12].to_vec(), vec![0; 2]].concat();
    assert!(matches!(
        &Message::decode_datagram(&past)[..],
        [Err(Error::TooShort { .. })]
    ));
    let mut long = bundled(52, true, &[]);
    long[3] = 200;
    assert!(matches!(
        &Message::decode_datagram(&long)[..],
        [Err(Error::MessageLength { .. })]
    ));
}

fn heartbeat_request() -> Message {
    Message {
        header: Header::node(1),
        body: HeartbeatRequest::new(RecoveryTimeStamp::new(1)).into(),
    }
}

/// A list of grouped IEs is sized for the IEs that its values can be: not for those of a
/// null length, nor for those whose IEs run past them, which stay octets.
#[test]
fn a_list_is_sized_for_its_values() {
    for content in [&[][..], &[0, 56, 0, 9]] {
        let ies: Vec<u8> = (0..(65_535 - 12) / (4 + content.len()))
            .flat_map(|_| [&[0, 1][..], &(content.len() as u16).to_be_bytes(), content].concat())
            .collect();
        let octets = [
            &[0x21, 50][..],
            &((12 + ies.len()) as u16).to_be_bytes(),
            &0u64.to_be_bytes(),
            &[0, 0, 1, 0],
            &ies,
        ]
        .concat();
        let message = Message::decode(&octets).unwrap();
        let Body::SessionEstablishmentRequest(request) = &message.body else {
            panic!()
        };
        // One, of the IE decoded in its place, which does not decode
        assert!(
            request.create_pdr.capacity() <= 1,
            "{content:?}: {}",
            request.create_pdr.capacity()
        );
        assert_eq!(message.encode().unwrap(), octets);
    }
}

/// §7.2.2: a header value that its bits cannot hold is not cut: encode() refuses it, and
/// check() says it; a tree cannot write it.
#[test]
fn a_header_value_that_its_bits_cannot_hold() {
    let message = |header: Header| Message {
        header,
        body: SessionDeletionRequest::default().into(),
    };
    for header in [
        Header::session(1, 0x0100_0005),
        Header {
            priority: Some(17),
            ..Header::session(1, 5)
        },
        Header {
            priority: Some(1),
            spare_last: 0x35,
            ..Header::session(1, 5)
        },
        Header {
            version: 9,
            ..Header::session(1, 5)
        },
        Header {
            spare: 4,
            ..Header::session(1, 5)
        },
    ] {
        let message = message(header);
        assert!(
            matches!(message.encode(), Err(Error::HeaderField { .. })),
            "{header:?}"
        );
        assert!(!message.check(Interfaces::N4).is_empty(), "{header:?}");
    }
    // The spare bits after the priority are spare (§7.2.2.3)
    let mut octets = message(Header {
        priority: Some(3),
        ..Header::session(1, 5)
    })
    .encode()
    .unwrap();
    octets[15] |= 0x05;
    let decoded = Message::decode(&octets).unwrap();
    assert_eq!(
        decoded
            .check(Interfaces::N4)
            .iter()
            .map(|deviation| deviation.kind.clone())
            .collect::<Vec<_>>(),
        [DeviationKind::SpareBits]
    );
    let written = tree!({"message": "PFCP Session Deletion Request", "SEID": 1, "Sequence Number": 1, "Message Priority": 3, "Spare octet": 0x35, "ies": {}});
    assert!(Message::from_tree(&written).is_err());
}

/// A key is never printed: the Tunnel Password, the HMAC Key (STAMP) and the Shared
/// Secret, as values and as the octets that a scope keeps of them.
#[test]
fn keys_are_not_printed() {
    let password = TunnelPassword(b"secret".to_vec().into());
    assert!(
        !format!("{password:?}").contains("secret")
            && !format!("{password:?}").contains("736563726574"),
        "{password:?}"
    );
    // The password of PAP, in clear (Table 7.5.2.1-3, RFC 2661)
    let authentication = L2tpUserAuthentication {
        pan: true,
        par: true,
        proxy_authen_type_value: 3,
        proxy_authen_name_value: Some(Lv8(b"alice".to_vec())),
        proxy_authen_response_value: Some(SecretLv8(b"secret".to_vec())),
        ..Default::default()
    };
    let printed = format!("{authentication:?}");
    assert!(
        printed.contains("alice") || printed.contains("97, 108"),
        "{printed}"
    );
    assert!(
        !printed.contains("115, 101, 99") && !printed.contains("secret"),
        "{printed}"
    );
    let printed = format!("{:?}", RawIe::new(278, b"secret".to_vec()));
    assert!(
        !printed.contains("115, 101, 99") && !printed.contains("736563"),
        "{printed}"
    );
    let mut parameters = ProtocolSpecificConfigurationParameters {
        hmac_key_stamp: Some(HmacKeyStamp(vec![1, 2, 3].into())),
        ..Default::default()
    };
    for ie_type in [313, 391, 393] {
        parameters
            .raw
            .push(RawIe::new(ie_type, vec![0xaa, 0xbb, 0xcc]));
    }
    parameters.raw.push(RawIe::new(22, vec![0xaa, 0xbb, 0xcc]));
    let printed = format!("{parameters:?}");
    assert_eq!(
        printed.matches("aabbcc").count() + printed.matches("170, 187, 204").count(),
        1,
        "{printed}"
    );
}

/// The values that review round 1 found misread: each as its clause has it.
#[test]
fn values_as_their_clauses_have_them() {
    // Table 7.5.8.2-1: a Downlink Data Service Information for each PDR ID
    let service = DownlinkDataServiceInformation {
        ppi: true,
        paging_policy_indication: Some(3),
        ..Default::default()
    };
    let report = DownlinkDataReport::new(PdrId::new(1))
        .with_pdr_id(PdrId::new(2))
        .with_downlink_data_service_information(service.clone())
        .with_downlink_data_service_information(service);
    let message = Message {
        header: Header::session(1, 1),
        body: SessionReportRequest::new(ReportType {
            dldr: true,
            ..Default::default()
        })
        .with_downlink_data_report(report)
        .into(),
    };
    assert!(
        message.check(Interfaces::N4).is_empty(),
        "{:?}",
        message.check(Interfaces::N4)
    );
    let decoded = Message::decode(&message.encode().unwrap()).unwrap();
    assert_eq!(decoded, message);
    // §8.2.183: the number of UE IPv4 addresses is a number
    let usage = UeIpAddressUsageInformation::default().with_number_of_ue_ip_addresses(
        NumberOfUeIpAddresses {
            ipv4: true,
            number_of_ue_ipv4_addresses: Some(10),
            ..Default::default()
        },
    );
    let tree = tree::Tree::to_tree(&usage);
    assert_eq!(
        tree["Number of UE IP Addresses"]["Number of UE IPv4 Addresses"], 10,
        "{tree}"
    );
    // §8.2.63: the spare bits of a Time Unit are not the unit
    let rate = PacketRate::decode(&[0x01, 0x82, 0x00, 0x10]).unwrap();
    assert_eq!(
        rate.uplink_time_unit.map(|unit| unit.value),
        Some(TimeUnit::Hour)
    );
    assert_eq!(rate.check_kinds(), [DeviationKind::SpareBits]);
    let mut octets = Vec::new();
    rate.encode(&mut octets).unwrap();
    assert_eq!(octets, [0x01, 0x82, 0x00, 0x10]);
    // §8.2.43: nor those of a Node Type
    let fq_csid = FqCsid::decode(&[0x01, 10, 0, 0, 1, 0, 7, 0x12]).unwrap();
    assert_eq!(
        fq_csid
            .node_type
            .map(|node_type| (node_type.value, node_type.spare)),
        Some((NodeType::PgwCSmf, 0x10))
    );
    // Table 8.2.7-1: a Gate of 2 is read as CLOSED; Table 8.2.1-1: a Cause of 70 is a rejection
    assert_eq!(Gate::from_value(2).effective(), Gate::Closed);
    assert_eq!(
        CauseValue::from_value(99).effective(),
        CauseValue::RequestRejected
    );
    assert_eq!(
        CauseValue::from_value(5).effective(),
        CauseValue::RequestAccepted
    );
    let gate = GateStatus {
        ul_gate: Gate::from_value(2),
        ..Default::default()
    };
    assert_eq!(
        gate.check_kinds(),
        [DeviationKind::ReadAs { value: 2, read: 1 }]
    );
    // §8.2.84: the Exponent is an Integer32
    let multiplier = Multiplier {
        value_digits: 5,
        exponent: -2,
        extra: Octets::new(),
    };
    let tree = tree::Tree::to_tree(&multiplier);
    assert_eq!(tree["Exponent"], -2, "{tree}");
    assert_eq!(tree::from_value::<Multiplier>(&tree).unwrap(), multiplier);
    let mut octets = Vec::new();
    multiplier.encode(&mut octets).unwrap();
    assert_eq!(&octets[8..], [0xff, 0xff, 0xff, 0xfe]);
    // §8.2.206: the NID after the Source Specific IP Multicast Address
    let content = [
        &[0x07][..],
        &[0x12, 0x34, 0x56, 0x02, 0xf8, 0x39],
        &[4, 239, 0, 0, 1],
        &[4, 10, 0, 0, 2],
        &[1, 2, 3, 4, 5, 0x60],
    ]
    .concat();
    let identifier = MbsSessionIdentifier::decode(&content).unwrap();
    assert_eq!(identifier.nid, Some([1, 2, 3, 4, 5, 0x60]));
    assert_eq!(
        identifier
            .source_specific_ip_multicast_address
            .as_ref()
            .and_then(|ssm| ssm.source.ip()),
        Some(Ipv4Addr::new(10, 0, 0, 2).into())
    );
    assert!(identifier.extra.is_empty());
    // A length-prefixed field longer than its length can say
    let user = UserId {
        naif: true,
        nai: Some(TextLv8(vec![b'a'; 300])),
        ..Default::default()
    };
    assert!(matches!(
        user.encode(&mut Vec::new()),
        Err(Error::FieldLength { field: "NAI", .. })
    ));
    assert_eq!(
        user.check_kinds(),
        [DeviationKind::Rule("more octets than their length can say")]
    );
    // §8.2.101: an IMSI is its digits
    let user = UserId {
        imsif: true,
        imsi: Some(DigitsLv8::new("208930000000001").unwrap()),
        ..Default::default()
    };
    let tree = tree::Tree::to_tree(&user);
    assert_eq!(tree["IMSI"], "208930000000001", "{tree}");
    assert!(format!("{user:?}").contains("208930000000001"));
    assert_eq!(tree::from_value::<UserId>(&tree).unwrap(), user);
    // An enumeration compares by its number, and a value wider than its field is refused
    assert_eq!(CauseValue::Other(1), CauseValue::RequestAccepted);
    let interface = SourceInterface::new(SourceInterfaceValue::Other(0xff));
    assert!(matches!(
        interface.encode(&mut Vec::new()),
        Err(Error::FieldLength { .. })
    ));
    assert!(
        interface
            .check_kinds()
            .contains(&DeviationKind::Rule("a value wider than its bits"))
    );
}

/// The kinds of the deviations of a value.
trait CheckKinds {
    fn check_kinds(&self) -> Vec<DeviationKind>;
}

impl<T: Check> CheckKinds for T {
    fn check_kinds(&self) -> Vec<DeviationKind> {
        let mut found = Vec::new();
        self.check(&Path::Root("/value"), &mut found);
        found.into_iter().map(|deviation| deviation.kind).collect()
    }
}

/// A tree written in another order than its table's encodes in the table's order; within
/// a row, its values and its octets keep the order written.
#[test]
fn a_tree_written_in_any_order_encodes_in_the_order_of_its_table() {
    let written = tree!({
        "message": "PFCP Association Setup Request",
        "Sequence Number": 9,
        "ies": {"Recovery Time Stamp": 3_900_000_000u32, "Node ID": "10.0.0.1"}
    });
    let octets = Message::from_tree(&written).unwrap().encode().unwrap();
    assert_eq!(&octets[8..10], &[0, 60], "the Node ID first");
    let in_order = tree!({
        "message": "PFCP Association Setup Request",
        "Sequence Number": 9,
        "ies": {"Node ID": "10.0.0.1", "Recovery Time Stamp": 3_900_000_000u32}
    });
    assert_eq!(
        Message::from_tree(&in_order).unwrap().encode().unwrap(),
        octets
    );
    // With octets of a row and an IE of no row
    let written = tree!({
        "message": "PFCP Association Setup Request",
        "Sequence Number": 9,
        "ies": {"Source IP Address": {"octets": "0a"}, "Recovery Time Stamp": [{"octets": "01"}, 3_900_000_000u32], "Node ID": "10.0.0.1"}
    });
    let message = Message::from_tree(&written).unwrap();
    let types: Vec<u16> = framing::message_ies(&message.encode().unwrap())
        .unwrap()
        .2
        .map(|ie| ie.unwrap().ie_type)
        .collect();
    assert_eq!(types, [60, 96, 96, 192]);
}

/// A row goes by its name: by the name of its IE type, or by the name of one of the rows
/// that share it, a tree is refused with the name to write; and a row written twice is
/// refused.
#[test]
fn a_row_goes_by_its_name() {
    let response = |ies: tree::Value| tree!({"message": "PFCP Session Establishment Response", "SEID": 1, "Sequence Number": 1, "ies": ies});
    let error = Message::from_tree(&response(tree!({"Node ID": "10.0.0.2", "Cause": 1, "F-SEID": {"V4": true, "SEID": 1, "IPv4 address": "10.0.0.2"}}))).unwrap_err().to_string();
    assert!(
        error.contains("the IE type of the row UP F-SEID"),
        "{error}"
    );
    let request = tree!({"message": "PFCP Session Establishment Request", "SEID": 0, "Sequence Number": 1, "ies": {"SGW-C FQ-CSID": {"octets": "01"}}});
    let error = Message::from_tree(&request).unwrap_err().to_string();
    assert!(error.contains("written as FQ-CSID"), "{error}");
    let error = Message::from_tree(&response(
        tree!({"Node ID": "10.0.0.2", "node_id": "10.0.0.3", "Cause": 1}),
    ))
    .unwrap_err()
    .to_string();
    assert!(error.contains("are both the row Node ID"), "{error}");
}
