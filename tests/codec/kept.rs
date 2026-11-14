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

//! The IEs that a scope keeps as octets, in the order of the wire or of their table, which
//! encode back byte for byte.

use super::*;

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

/// A built message is in the order of its table, an IE that it keeps as octets with the
/// values of its row, and an IE of no row last: as its tree is, which reads back to the
/// same message and the same octets; decoded, it keeps no other order.
#[test]
fn a_kept_ie_of_a_row_is_with_its_row() {
    let mut response = AssociationReleaseResponse::new(
        NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
        Cause::new(CauseValue::RequestAccepted),
    );
    response.raw.push(RawIe::new(60, vec![0, 10, 0, 0, 2]));
    response.raw.push(RawIe::new(96, vec![0, 0, 0, 7]));
    let message = Message::node(2, response);
    let octets = message.encode().unwrap();
    let ies = "003c0005000a000001003c0005000a00000200130001010060000400000007";
    assert_eq!(hex::encode(&octets), format!("200a002300000200{ies}"));
    let back = Message::from_tree(&message.to_tree()).unwrap();
    assert_eq!(back, message);
    assert_eq!(back.encode().unwrap(), octets);
    let decoded = Message::decode(&octets).unwrap();
    assert_eq!(decoded, message);
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
    // A vendor IE is its Enterprise ID and the octets after it (§8.1.1)
    let vendor = &request.raw[0];
    assert_eq!((vendor.ie_type, vendor.enterprise_id), (32769, Some(18553)));
    assert_eq!(*vendor.octets, [0xca, 0xfe]);
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
        let mut octets = Message::session(1, 9, response).encode().unwrap();
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

/// A value added to a message that keeps the order of the wire goes to the place of its
/// row: before the first IE of a later row that the wire has, or last after them all.
#[test]
fn a_value_added_to_a_message_of_its_own_order_goes_to_its_row() {
    let ie = |ie_type: u16, content: &[u8]| {
        [
            &ie_type.to_be_bytes()[..],
            &(content.len() as u16).to_be_bytes(),
            content,
        ]
        .concat()
    };
    // A Remove FAR, then a Remove PDR, whose row is before it
    let ies = [ie(16, &ie(108, &[0, 0, 0, 1])), ie(15, &ie(56, &[0, 1]))].concat();
    let mut octets = vec![0x21, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0];
    octets.extend(ies);
    let length = (octets.len() - 4) as u16;
    octets[2..4].copy_from_slice(&length.to_be_bytes());
    let mut message = Message::decode(&octets).unwrap();
    assert_eq!(message.encode().unwrap(), octets);
    let Body::SessionModificationRequest(request) = &mut message.body else {
        panic!()
    };
    request.remove_pdr.push(RemovePdr::new(PdrId::new(2)));
    request.remove_far.push(RemoveFar::new(FarId::new(2)));
    let again = Message::decode(&message.encode().unwrap()).unwrap();
    let Body::SessionModificationRequest(request) = again.body else {
        panic!()
    };
    let pdrs: Vec<u16> = request
        .remove_pdr
        .iter()
        .map(|pdr| pdr.pdr_id.as_ref().unwrap().value)
        .collect();
    let fars: Vec<u32> = request
        .remove_far
        .iter()
        .map(|far| far.far_id.as_ref().unwrap().value)
        .collect();
    // The added Remove PDR before the Remove FAR of the wire, the added Remove FAR last
    assert_eq!((pdrs, fars), (vec![2, 1], vec![1, 2]));
}

/// A Length that a tree writes of an IE kept as octets, which is the length of its content,
/// is no false Length: the IE keeps it, as the header keeps a Message Length of its own,
/// and the tree of the message writes it again; its octets read back as the value that
/// they are, and are checked as it.
#[test]
fn the_length_of_its_own_content_is_no_false_length() {
    let tree = tree!({"message": "PFCP Association Setup Request", "header": {"Sequence Number": 1},
        "ies": {"Node ID": "127.0.0.4", "Recovery Time Stamp": 7, "CP Function Features": {"octets": "b9", "length": 1}}});
    let message = Message::from_tree(&tree).unwrap();
    let Body::AssociationSetupRequest(request) = &message.body else {
        panic!()
    };
    assert_eq!(request.raw[0].length, Some(1));
    assert_eq!(message.to_tree(), tree);
    assert_eq!(Message::from_tree(&message.to_tree()).unwrap(), message);
    let read = Message::decode(&message.encode().unwrap()).unwrap();
    let tree = read.to_tree();
    let features = select(&tree, "/pfcp/CP Function Features/LOAD").unwrap();
    assert_eq!(features, [&tree!(true)]);
    assert_eq!(message.check(Interfaces::N4), read.check(Interfaces::N4));
}

/// A false Length shorter than the octets of an IE leaves its other octets to frame as IEs
/// of their own: its receiver reads one octet of CP Function Features and a vendor IE of
/// type 40863 and of a null length after it, and `check()` finds in the message what it
/// finds in its octets. The `edit` fuzz target found it.
#[test]
fn a_false_length_reads_as_the_ies_that_its_octets_frame() {
    let tree = tree!({"message": "PFCP Association Setup Request", "header": {"Sequence Number": 1},
        "ies": {"Node ID": "127.0.0.4", "Recovery Time Stamp": 7, "CP Function Features": {"octets": "9f9f9f0000", "length": 1}}});
    let message = Message::from_tree(&tree).unwrap();
    assert_eq!(message.to_tree(), tree);
    let read = Message::decode(&message.encode().unwrap()).unwrap();
    let tree = read.to_tree();
    let features = select(&tree, "/pfcp/CP Function Features").unwrap();
    assert_eq!(features[0]["LOAD"], tree!(true));
    assert_eq!(features[0]["length"], tree!(1));
    let vendor = select(&tree, "/pfcp/40863").unwrap();
    assert_eq!(vendor, [&tree!({"octets": ""})]);
    for interface in [Interfaces::N4, Interfaces::SXB, Interfaces::ALL] {
        assert_eq!(message.check(interface), read.check(interface));
    }
}

/// An FQ-CSID of a Node-ID Type that §8.2.43 reserves, which a value may have and
/// `encode()` writes with the Node-Address that it has, for a test to send: its type does
/// not decode the octets, which give no length of the Node-Address, so its receiver keeps
/// the IE as octets. `check()` tells the value reserved and the IE that the receiver reads
/// incorrect (§7.6.8), at the same path. The `edit` fuzz target found it.
#[test]
fn an_fq_csid_of_a_reserved_node_id_type_is_received_as_octets() {
    let tree = tree!({"message": "PFCP Session Set Deletion Request", "header": {"Sequence Number": 7},
        "ies": {"FQ-CSID": [{"FQ-CSID Node-ID Type": 13, "Node-Address": "0d3fa72c", "PDN Connection Set Identifiers": [8973]}]}});
    let message = Message::from_tree(&tree).unwrap();
    let read = Message::decode(&message.encode().unwrap()).unwrap();
    let tree = read.to_tree();
    let kept = select(&tree, "/pfcp/FQ-CSID").unwrap();
    assert_eq!(kept, [&tree!([{"octets": "d10d3fa72c230d"}])]);
    let at = |message: &Message| -> Vec<DeviationKind> {
        let found = message.check(Interfaces::ALL).into_iter();
        found
            .filter(|deviation| deviation.path == "/pfcp/FQ-CSID/0")
            .map(|deviation| deviation.kind)
            .collect()
    };
    assert_eq!(at(&message), [DeviationKind::ReservedValue { value: 13 }]);
    assert_eq!(at(&read), [DeviationKind::Incorrect { ie_type: 65 }]);
}

