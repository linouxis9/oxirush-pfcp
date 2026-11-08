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

use oxirush_pfcp::paths::{select, set};
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
    let seid = FSeid::ipv4(0x1001, smf);
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
    Message::session(0, 7, request)
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

/// What is not there selects nothing, and a misspelt name is an error, `NoSuchMember`, as
/// oxirush-utils' `select_in` has it: a row of the table of a message or of a grouped IE
/// that it lacks, and a flag or a field of the figure of a value that it lacks, select
/// nothing, whether the path ends at them or goes on. A name that is none of them is
/// `NoSuchMember`, and so is a row of a grouped IE that the scope keeps as its octets.
#[test]
fn what_a_message_lacks_selects_nothing() {
    let nothing = |tree: &tree::Value, path: &str| {
        assert_eq!(
            select(tree, path).map_err(|error| error.kind()),
            Ok(vec![]),
            "{path}"
        );
    };
    let misspelt = |tree: &tree::Value, path: &str| {
        let kind = select(tree, path).map_err(|error| error.kind());
        assert_eq!(kind, Err(tree::ErrorKind::NoSuchMember), "{path}");
    };
    let heartbeat = Message::node(1, HeartbeatRequest::new(RecoveryTimeStamp::new(7)));
    let heartbeat = heartbeat.to_tree();
    nothing(&heartbeat, "/pfcp/Source IP Address");
    nothing(&heartbeat, "/pfcp/source-ip-address/IPv4 address");
    misspelt(&heartbeat, "/pfcp/No Such IE");
    misspelt(&heartbeat, "/pfcp/Source IP Adress");
    let establishment = establishment().to_tree();
    // Rows of grouped IEs, of a list and of a list of them
    nothing(&establishment, "/pfcp/Create PDR/0/Outer Header Removal");
    nothing(&establishment, "/pfcp/Create PDR/*/PDI/Network Instance");
    nothing(&establishment, "/pfcp/Create QER");
    nothing(&establishment, "/pfcp/Create QER/0/QER ID");
    misspelt(&establishment, "/pfcp/Create PDR/0/Outer Header Removals");
    misspelt(&establishment, "/pfcp/Create PDR/0/PDI/Network");
    // Flags and fields of a figure
    nothing(&establishment, "/pfcp/CP F-SEID/V6");
    nothing(&establishment, "/pfcp/CP F-SEID/IPv6 address");
    nothing(&establishment, "/pfcp/Create PDR/0/PDI/Local F-TEID/TEID");
    misspelt(&establishment, "/pfcp/CP F-SEID/IPv7 address");
    // What is there is selected
    let selected = select(&establishment, "/pfcp/Create PDR/*/PDR ID").unwrap();
    assert_eq!(selected, [&tree!(1), &tree!(2)]);
    // A response that lacks its UP F-SEID, and fields that a Created PDR lacks
    let response = tree!({
        "message": "PFCP Session Establishment Response", "SEID": 1, "Sequence Number": 1,
        "ies": {
            "Node ID": "10.0.0.1",
            "Cause": "Request accepted (success)",
            "Created PDR": [{"PDR ID": 1, "F-TEID": [{"V4": true, "TEID": 7, "IPv4 address": "10.0.0.2"}]}]
        }
    });
    let response = Message::from_tree(&response).unwrap().to_tree();
    nothing(&response, "/pfcp/UP F-SEID");
    nothing(&response, "/pfcp/UP F-SEID/SEID");
    nothing(&response, "/pfcp/Created PDR/0/F-TEID/0/IPv6 address");
    nothing(&response, "/pfcp/Created PDR/0/UE IP address");
    let teid = select(&response, "/pfcp/Created PDR/0/F-TEID/0/TEID").unwrap();
    assert_eq!(teid, [&tree!(7)]);
    misspelt(&response, "/pfcp/Created PDR/0/F-TID");
    assert!(select(&response, "/pfcp/Created PDR/0/F-TEID/0/TEID/deeper").is_err());
    // A grouped IE that the scope keeps as its octets has no rows
    let mut kept = establishment.clone();
    kept["ies"]["Create PDR"][0] = tree!({"octets": "003800020001"});
    misspelt(&kept, "/pfcp/Create PDR/0/FAR ID");
    // A row that a message lacks is set as before
    let mut edited = heartbeat.clone();
    let address = tree!({"V4": true, "IPv4 address": "10.0.0.9"});
    set(&mut edited, "/pfcp/Source IP Address", address).unwrap();
    let Body::HeartbeatRequest(request) = Message::from_tree(&edited).unwrap().body else {
        panic!()
    };
    let source = request.source_ip_address.unwrap().ipv4_address;
    assert_eq!(source, Some(Ipv4Addr::new(10, 0, 0, 9)));
    // An IE of no row of the table, a vendor's or one of another table, by its number or
    // its type's name, as a tree writes it: what is not there selects nothing, and set
    // adds it under the name that the tree prints
    nothing(&heartbeat, "/pfcp/32769");
    nothing(&heartbeat, "/pfcp/32769/octets");
    nothing(&heartbeat, "/pfcp/Node ID");
    nothing(&heartbeat, "/pfcp/60/Enterprise ID");
    nothing(&heartbeat, "/pfcp/32769/octet");
    // An IE type of a row goes by the name of its row
    misspelt(&heartbeat, "/pfcp/96");
    misspelt(&establishment, "/pfcp/Create PDR/0/PDI/F-TEID");
    let mut edited = heartbeat.clone();
    let vendor = tree!({"octets": "01", "Enterprise ID": 9});
    set(&mut edited, "/pfcp/32769", vendor.clone()).unwrap();
    set(&mut edited, "/pfcp/60", tree!({"octets": "000a000001"})).unwrap();
    set(&mut edited, "/pfcp/Node ID/length", tree!(4)).unwrap();
    assert_eq!(select(&edited, "/pfcp/32769").unwrap(), [&vendor]);
    let node_id = tree!({"octets": "000a000001", "length": 4});
    assert_eq!(select(&edited, "/pfcp/60").unwrap(), [&node_id]);
    assert_eq!(edited["ies"]["Node ID"], node_id);
    let Body::HeartbeatRequest(request) = Message::from_tree(&edited).unwrap().body else {
        panic!()
    };
    let kept: Vec<u16> = request.raw.iter().map(|ie| ie.ie_type).collect();
    assert_eq!(kept, [32769, 60]);
    // A tree that writes it by its number is read by its name too
    let written = tree!({"message": "PFCP Heartbeat Request", "Sequence Number": 1,
        "ies": {"Recovery Time Stamp": 7, "60": {"octets": "000a000001"}}});
    let node_id = tree!({"octets": "000a000001"});
    assert_eq!(select(&written, "/pfcp/Node ID").unwrap(), [&node_id]);
    assert_eq!(
        select(&written, "/pfcp/60/octets").unwrap(),
        [&tree!("000a000001")]
    );
}

/// The members that a tree prints only where a value has them select nothing where it
/// lacks them, as the flags and fields do: `Spare`, `length` and `unknown octets` of a
/// value, the FQDN of a Node ID that is an address, the members of a value that its tree
/// writes as a scalar, and the members of the header. A name that is no member of a value
/// is `NoSuchMember`, also below a row that a message lacks.
#[test]
fn what_a_value_lacks_selects_nothing() {
    let nothing = |tree: &tree::Value, path: &str| {
        assert_eq!(
            select(tree, path).map_err(|error| error.kind()),
            Ok(vec![]),
            "{path}"
        );
    };
    let failing = |tree: &tree::Value, path: &str, kind: tree::ErrorKind| {
        let found = select(tree, path).map_err(|error| error.kind());
        assert_eq!(found, Err(kind), "{path}");
    };
    let misspelt = |tree: &tree::Value, path: &str| {
        failing(tree, path, tree::ErrorKind::NoSuchMember);
    };
    // The response of the README, and the same with a spare bit and an octet more
    let response = "2133002b000000000000100100000700003c0005000a00000200130001010039000d0200000000000020010a000002";
    let response = Message::decode(&hex::decode(response).unwrap())
        .unwrap()
        .to_tree();
    let more = "2133002c000000000000100100000700003c0005000a00000200130001010039000e8200000000000020010a000002ff";
    let more = Message::decode(&hex::decode(more).unwrap())
        .unwrap()
        .to_tree();
    nothing(&response, "/pfcp/UP F-SEID/Spare");
    nothing(&response, "/pfcp/UP F-SEID/unknown octets");
    assert_eq!(
        select(&more, "/pfcp/UP F-SEID/Spare").unwrap(),
        [&tree!(128)]
    );
    let unknown = select(&more, "/pfcp/UP F-SEID/unknown octets").unwrap();
    assert_eq!(unknown, [&tree!("ff")]);
    // A Node ID that is an address has no FQDN and no octets, one that is an FQDN no
    // octets, and their trees no Node ID Type or value, which their form says
    nothing(&response, "/pfcp/Node ID/FQDN");
    nothing(&response, "/pfcp/Node ID/octets");
    misspelt(&response, "/pfcp/Node ID/Node ID value");
    misspelt(&response, "/pfcp/Node ID/Node ID Type");
    let name = b"\x03upf\x07example".to_vec();
    let setup = Message::node(
        1,
        AssociationSetupRequest::new(NodeId::Fqdn(name.into()), RecoveryTimeStamp::new(7)),
    );
    let setup = setup.to_tree();
    let fqdn = select(&setup, "/pfcp/Node ID/FQDN").unwrap();
    assert_eq!(fqdn, [&tree!("upf.example")]);
    nothing(&setup, "/pfcp/Node ID/octets");
    misspelt(&setup, "/pfcp/Node ID/Node ID value");
    misspelt(&setup, "/pfcp/Node ID/Node ID Type");
    // The header
    nothing(&response, "/Message Priority");
    nothing(&response, "/FO");
    let heartbeat = Message::node(1, HeartbeatRequest::new(RecoveryTimeStamp::new(7)));
    let heartbeat = heartbeat.to_tree();
    nothing(&heartbeat, "/SEID");
    nothing(&heartbeat, "/Spare");
    misspelt(&heartbeat, "/Bogus");
    // The length of a value of octets of bits that lacks some, and the spare bits of one
    let establishment = establishment().to_tree();
    nothing(&establishment, "/pfcp/Create FAR/0/Apply Action/length");
    nothing(&establishment, "/pfcp/Create FAR/0/Apply Action/Spare");
    misspelt(&establishment, "/pfcp/Create FAR/0/Apply Action/Bogus");
    // A value that its tree writes as a scalar: what it lacks selects nothing, and the
    // one field that it is selects it
    nothing(&establishment, "/pfcp/Create PDR/0/PDR ID/unknown octets");
    let rule = select(&establishment, "/pfcp/Create PDR/0/PDR ID/Rule ID").unwrap();
    assert_eq!(rule, [&tree!(1)]);
    misspelt(&establishment, "/pfcp/Create PDR/0/PDR ID/Bogus");
}

/// `set` takes each path that `select` takes, and errs on each that it errs on, with the
/// same kind: the one field of a value written as a scalar (the Cause value), the member
/// that a field of two forms is (the `value` of a Time Unit), the members of its object,
/// which write the object (the `Spare` of a Time Unit, the `FQDN` of a Node ID that is an
/// address), and a member that a value lacks, which `set` adds.
#[test]
fn set_takes_the_paths_that_select_takes() {
    let response = "2133002b000000000000100100000700003c0005000a00000200130001010039000d0200000000000020010a000002";
    let response = Message::decode(&hex::decode(response).unwrap())
        .unwrap()
        .to_tree();
    let rate = PacketRate {
        ulpr: true,
        uplink_time_unit: Some(Narrow::new(TimeUnit::Minute)),
        maximum_uplink_packet_rate: Some(10),
        ..Default::default()
    };
    let qer = CreateQer::new(QerId::new(1), GateStatus::default()).with_packet_rate(rate);
    let modification = Message::session(
        1,
        1,
        SessionModificationRequest::default().with_create_qer(qer),
    )
    .to_tree();
    let address = SourceIpAddress {
        v4: true,
        ipv4_address: Some(Ipv4Addr::new(10, 0, 0, 9)),
        ..Default::default()
    };
    let heartbeat =
        HeartbeatRequest::new(RecoveryTimeStamp::new(7)).with_source_ip_address(address);
    let heartbeat = Message::node(1, heartbeat).to_tree();
    let unit = "/pfcp/Create QER/0/Packet Rate/Uplink Time Unit";
    for (tree, path, value, written) in [
        (
            &response,
            "/pfcp/Cause/Cause value",
            tree!("Request rejected (reason not specified)"),
            tree!("Request rejected (reason not specified)"),
        ),
        (
            &response,
            "/pfcp/Node ID/FQDN",
            tree!("upf.example"),
            tree!({"FQDN": "upf.example"}),
        ),
        (
            &modification,
            &format!("{unit}/value")[..],
            tree!("hour"),
            tree!("hour"),
        ),
        (
            &modification,
            &format!("{unit}/Spare")[..],
            tree!(8),
            tree!({"value": "minute", "Spare": 8}),
        ),
        (
            &heartbeat,
            "/pfcp/Source IP Address/V6",
            tree!(true),
            tree!({"V4": true, "IPv4 address": "10.0.0.9", "V6": true}),
        ),
    ] {
        assert!(select(tree, path).is_ok(), "{path}");
        let mut edited = tree.clone();
        set(&mut edited, path, value.clone()).unwrap_or_else(|error| panic!("{path}: {error}"));
        let holder = path.rsplit_once('/').unwrap().0;
        let holder = if written.is_object() { holder } else { path };
        assert_eq!(select(&edited, holder).unwrap(), [&written], "{path}");
    }
    // What the edits write reads back
    let mut edited = modification.clone();
    set(&mut edited, &format!("{unit}/Spare"), 8).unwrap();
    let Body::SessionModificationRequest(request) = Message::from_tree(&edited).unwrap().body
    else {
        panic!()
    };
    let rate = request.create_qer[0].packet_rate.clone().unwrap();
    assert_eq!(
        rate.uplink_time_unit,
        Some(Narrow {
            value: TimeUnit::Minute,
            spare: 8
        })
    );
    let mut edited = response.clone();
    set(&mut edited, "/pfcp/Node ID/FQDN", "upf.example").unwrap();
    let Body::SessionEstablishmentResponse(answer) = Message::from_tree(&edited).unwrap().body
    else {
        panic!()
    };
    assert_eq!(answer.node_id, NodeId::from_fqdn("upf.example"));
    // The same errors, and a tree left as it was
    for (tree, path, kind) in [
        (
            &response,
            "/pfcp/Node ID/Node ID value",
            tree::ErrorKind::NoSuchMember,
        ),
        (
            &response,
            "/pfcp/Node ID/Node ID Type",
            tree::ErrorKind::NoSuchMember,
        ),
        (
            &response,
            "/pfcp/Cause/Bogus",
            tree::ErrorKind::NoSuchMember,
        ),
        (
            &response,
            "/pfcp/Cause/Cause value/Bogus",
            tree::ErrorKind::Scalar,
        ),
        (
            &modification,
            &format!("{unit}/Bogus")[..],
            tree::ErrorKind::NoSuchMember,
        ),
        (
            &heartbeat,
            "/pfcp/Source IP Address/Bogus",
            tree::ErrorKind::NoSuchMember,
        ),
    ] {
        let selected = select(tree, path).map_err(|error| error.kind());
        assert_eq!(selected, Err(kind), "{path}");
        let mut edited = tree.clone();
        let set = set(&mut edited, path, 1).map_err(|error| error.kind());
        assert_eq!(set, Err(kind), "{path}");
        assert_eq!(&edited, tree, "{path}");
    }
}

/// `set` adds an entry to a list at the position of its length, of a list that is there
/// and of one that is not, at any depth, and what it writes reads back; past the end, a
/// path selects nothing, which `set` refuses, and the tree is left as it was.
#[test]
fn set_adds_an_entry_at_the_end_of_a_list() {
    let mut tree = establishment().to_tree();
    for (path, value) in [
        ("/pfcp/Create PDR/2/PDR ID", tree!(3)),
        ("/pfcp/Create PDR/2/Precedence", tree!(9)),
        // A list in a grouped IE that the entry does not have yet
        ("/pfcp/Create PDR/2/PDI/SDF Filter/0/Spare octet", tree!(0)),
        ("/pfcp/Create PDR/2/PDI/Source Interface", tree!("Core")),
        (
            "/pfcp/Create PDR/3",
            tree!({"PDR ID": 4, "Precedence": 1, "PDI": {"Source Interface": "Access"}}),
        ),
        ("/pfcp/Create URR/0/URR ID", tree!(1)),
        (
            "/pfcp/Create URR/0/Measurement Method",
            tree!({"VOLUM": true}),
        ),
        (
            "/pfcp/Create URR/0/Reporting Triggers",
            tree!({"PERIO": true}),
        ),
    ] {
        set(&mut tree, path, value).unwrap_or_else(|error| panic!("{path}: {error}"));
    }
    let Body::SessionEstablishmentRequest(request) = Message::from_tree(&tree).unwrap().body else {
        panic!()
    };
    let ids: Vec<u16> = request
        .create_pdr
        .iter()
        .map(|pdr| pdr.pdr_id.as_ref().unwrap().value)
        .collect();
    assert_eq!(ids, [1, 2, 3, 4]);
    let pdi = request.create_pdr[2].pdi.as_ref().unwrap();
    assert_eq!(pdi.sdf_filter.len(), 1);
    assert_eq!(request.create_urr.len(), 1);
    // Below the IEs of a message that has none
    let mut written =
        tree!({"message": "PFCP Session Modification Request", "SEID": 1, "Sequence Number": 1});
    set(&mut written, "/pfcp/Remove PDR/0/PDR ID", 4).unwrap();
    let Body::SessionModificationRequest(request) = Message::from_tree(&written).unwrap().body
    else {
        panic!()
    };
    assert_eq!(request.remove_pdr.len(), 1);
    let before = tree.clone();
    for path in [
        "/pfcp/Create PDR/9/PDR ID",
        "/pfcp/Create URR/3",
        "/pfcp/Create PDR/4/Bogus",
    ] {
        assert!(set(&mut tree, path, 1).is_err(), "{path}");
        assert_eq!(tree, before, "{path}");
    }
}

/// What is not there selects nothing, whatever the path names below it: a row that a
/// message or a grouped IE lacks, a list that it lacks, an entry past the end of a list, a
/// field or a flag that a value or the header lacks, and a member of the object of a field
/// written as a scalar. A misspelt name below them is not told; one where the value is
/// there is `NoSuchMember`. `set` writes a value that a message lacks whole, and refuses a
/// path below it with `NothingSelected`, leaving the tree as it was.
#[test]
fn what_is_not_there_selects_nothing_whatever_the_path_names_below_it() {
    let response = "2133002b000000000000100100000700003c0005000a00000200130001010039000d0200000000000020010a000002";
    let response = Message::decode(&hex::decode(response).unwrap()).unwrap();
    let mut with_pdr = response.clone();
    let Body::SessionEstablishmentResponse(body) = &mut with_pdr.body else {
        panic!()
    };
    body.created_pdr.push(CreatedPdr::new(PdrId::new(1)));
    let (response, with_pdr) = (response.to_tree(), with_pdr.to_tree());
    let heartbeat = Message::node(1, HeartbeatRequest::new(RecoveryTimeStamp::new(7)));
    let heartbeat = heartbeat.to_tree();
    let misspelt = Err(tree::ErrorKind::NoSuchMember);
    for (tree, path, found) in [
        // Below a value, a grouped IE and a list that the message lacks
        (&heartbeat, "/pfcp/Source IP Address/Bogus", Ok(0)),
        (&heartbeat, "/pfcp/Source IP Address/V4/Bogus", Ok(0)),
        (&response, "/pfcp/Load Control Information/Bogus", Ok(0)),
        (&response, "/pfcp/Created PDR/0/Bogus", Ok(0)),
        (&response, "/pfcp/Created PDR/*/F-TEID/0/Bogus", Ok(0)),
        (&response, "/pfcp/Created PDR/Bogus", Ok(0)),
        // Below an entry past the end of a list
        (&with_pdr, "/pfcp/Created PDR/5/Bogus", Ok(0)),
        // Below a field or a flag that a value or the header lacks
        (&response, "/pfcp/UP F-SEID/IPv6 address/Bogus", Ok(0)),
        (&response, "/pfcp/UP F-SEID/V6/*", Ok(0)),
        (&response, "/Message Priority/Bogus", Ok(0)),
        // Below a member of the object of a value written as a scalar, an address
        (&response, "/pfcp/Node ID/FQDN/Bogus", Ok(0)),
        // Where the value is there, a misspelt name is an error, and a role that the wire
        // does not tell from the others of its row is no member
        (&with_pdr, "/pfcp/Created PDR/0/Bogus", misspelt),
        (&with_pdr, "/pfcp/Created PDR/*/Bogus", misspelt),
        (&with_pdr, "/pfcp/Created PDR/0/Local F-TEID/CHID", misspelt),
        (&response, "/pfcp/UP F-SEID/Bogus", misspelt),
        (&response, "/pfcp/Bogus/PDR ID", misspelt),
        (&heartbeat, "/pfcp/Recovery Time Stamp/Bogus", misspelt),
        (
            &with_pdr,
            "/pfcp/Created PDR/Bogus",
            Err(tree::ErrorKind::NotAList),
        ),
    ] {
        let selected = select(tree, path).map(|values| values.len());
        assert_eq!(selected.map_err(|error| error.kind()), found, "{path}");
    }
    // set refuses a path below a value that the message lacks, and writes the value whole
    let mut edited = heartbeat.clone();
    for path in [
        "/pfcp/Source IP Address/V4",
        "/pfcp/Source IP Address/Bogus/V4",
    ] {
        let below = set(&mut edited, path, true).map_err(|error| error.kind());
        assert_eq!(below, Err(tree::ErrorKind::NothingSelected), "{path}");
        assert_eq!(edited, heartbeat, "{path}");
    }
    let address = tree!({"V4": true, "IPv4 address": "10.0.0.9"});
    set(&mut edited, "/pfcp/Source IP Address", address).unwrap();
    set(&mut edited, "/pfcp/Source IP Address/V6", true).unwrap();
    let written = select(&edited, "/pfcp/Source IP Address/*").unwrap();
    assert_eq!(written, [&tree!(true), &tree!("10.0.0.9"), &tree!(true)]);
}

/// A misspelt name of a path says what `Message::from_tree` says of it: the IE type of a
/// row goes by the name of the row, and a name that is no IE of a table, or no member of
/// a value that is there, has the nearest names of the table, or the members of the
/// value.
#[test]
fn a_misspelt_name_says_what_from_tree_says() {
    let qer = CreateQer::new(QerId::new(1), GateStatus::default());
    let pdi = Pdi::new(SourceInterface::new(SourceInterfaceValue::Core));
    let pdr = CreatePdr::new_n4(PdrId::new(1), Precedence::new(1), pdi)
        .with_activate_predefined_rules(ActivatePredefinedRules(b"rule".to_vec().into()));
    let modification = SessionModificationRequest::default()
        .with_create_qer(qer)
        .with_create_pdr(pdr);
    let tree = Message::session(1, 1, modification).to_tree();
    let refused = |path: &str| {
        let error = select(&tree, path).unwrap_err();
        assert_eq!(error.kind(), tree::ErrorKind::NoSuchMember, "{path}");
        error.to_string()
    };
    let read = |written: tree::Value| Message::from_tree(&written).unwrap_err().to_string();
    let by_type = refused("/pfcp/7");
    assert!(
        by_type.contains("the row Create QER, which goes by its name"),
        "{by_type}"
    );
    let mut written = tree.clone();
    written["ies"]["7"] = tree!([]);
    assert!(read(written).contains("the row Create QER, which goes by its name"));
    for path in [
        "/pfcp/Create QER/0/Gate Statsu",
        "/pfcp/Create QER/0/Gate Statsu/UL Gate",
    ] {
        let near = refused(path);
        assert!(
            near.contains("is no IE of Create QER: the nearest are Gate Status"),
            "{near}"
        );
    }
    for path in [
        "/pfcp/Create QER/0/Gate Status/UL Gat",
        "/pfcp/Create QER/0/QER ID/Rule IDD",
    ] {
        let members = refused(path);
        assert!(
            members.contains("is not a member that its type has: it has "),
            "{members}"
        );
    }
    assert!(refused("/pfcp/Create QER/0/Gate Status/UL Gat").contains("DL Gate, UL Gate"));
    // A value whose tree is its octets has no member
    let octets = refused("/pfcp/Create PDR/0/Activate Predefined Rules/0/Bogus");
    assert!(
        octets.ends_with("it has none, at /pfcp/Create PDR/0/Activate Predefined Rules/0/Bogus"),
        "{octets}"
    );
    // The header, and an IE kept as its octets, have their members
    let header = refused("/Sequence Numbr");
    assert!(
        header.contains("it has message, Version, Spare"),
        "{header}"
    );
    let mut kept = tree.clone();
    kept["ies"]["Cause"] = tree!({"octets": "01"});
    let error = select(&kept, "/pfcp/Cause/Bogus").unwrap_err().to_string();
    assert!(
        error.contains("it has octets, length, Enterprise ID"),
        "{error}"
    );
    // `set` refuses a misspelt name, the last of its path too, and leaves the tree
    let mut edited = tree.clone();
    let misspelt = set(&mut edited, "/pfcp/Create QER/0/Gate Statsu", 1u64);
    assert_eq!(
        misspelt.map_err(|error| error.kind()),
        Err(tree::ErrorKind::NoSuchMember)
    );
    assert_eq!(edited, tree);
    // A value that the message lacks is written whole
    let below = set(
        &mut edited,
        "/pfcp/Create QER/0/Maximum Bitrate/UL MBR",
        5u64,
    );
    assert_eq!(
        below.map_err(|error| error.kind()),
        Err(tree::ErrorKind::NothingSelected)
    );
    assert_eq!(edited, tree);
    let mut whole = tree.clone();
    let bitrate = tree!({"UL MBR": 5, "DL MBR": 6});
    set(&mut whole, "/pfcp/Create QER/0/Maximum Bitrate", bitrate).unwrap();
    assert!(Message::from_tree(&whole).is_ok());
}

/// An error of `Message::from_tree` is at a path of the tree that `select` takes, of the
/// names as the tree writes them, a "/" of a name as "~1", and says why without saying
/// again that the tree is no message; an IE of no row that is not written by its octets is
/// refused by the name written.
#[test]
fn an_error_of_from_tree_is_at_a_path_that_select_takes() {
    let heartbeat = |ies: tree::Value| tree!({"message": "PFCP Heartbeat Request", "Sequence Number": 1, "ies": ies});
    let modification = |ies: tree::Value| tree!({"message": "PFCP Session Modification Response", "SEID": 1, "Sequence Number": 1, "ies": ies});
    for (tree, at, why) in [
        (
            heartbeat(tree!({"Recovery Time Stamp": 7, "Cause": 1, "Load Metric": 2})),
            "/pfcp",
            "\"Cause\" is an IE of no row of PFCP Heartbeat Request, which is written by its octets",
        ),
        (
            heartbeat(tree!({"Recovery Time Stamp": 7, "19": {"octets": "zz"}})),
            "/pfcp/19/octets",
            "octets in hexadecimal",
        ),
        (
            heartbeat(
                tree!({"Recovery Time Stamp": 7, "Source IP Address": {"V4": true, "IPv4 address": "10.0.0.1", "MPL": true, "mask/prefix length": "x"}}),
            ),
            "/pfcp/Source IP Address/mask~1prefix length",
            "a number",
        ),
        (
            modification(
                tree!({"Cause": 1, "created/updated traffic endpoint": [{"Traffic Endpoint ID": 1}, {"Traffic Endpoint ID": "x"}]}),
            ),
            "/pfcp/created~1updated traffic endpoint/1/Traffic Endpoint ID",
            "a number",
        ),
        (
            tree!({"message": "PFCP Session Establishment Response", "SEID": 1, "Sequence Number": 1,
                "ies": {"Node ID": "10.0.0.2", "Cause": 1, "UP F-SEID": {"V4": true, "SEIDD": 1}}}),
            "/pfcp/UP F-SEID",
            "\"SEIDD\" is not a member that its type has",
        ),
        (
            tree!({"message": "PFCP Heartbeat Request", "Sequence Number": "x", "ies": {}}),
            "/Sequence Number",
            "a number",
        ),
    ] {
        let error = Message::from_tree(&tree).unwrap_err();
        assert_eq!(error.at(), at, "{error}");
        assert!(error.reason().contains(why), "{error}");
        assert!(
            !error.reason().contains("this is not a value of"),
            "{error}"
        );
        assert!(select(&tree, error.at()).is_ok(), "{error}");
    }
}

/// An F-SEID of an IPv4 address and one of an IPv6 address, as their constructors build
/// them: the flag of the family, the SEID, then the address (§8.2.37).
#[test]
fn an_f_seid_of_each_family() {
    let encoded = |f_seid: FSeid| {
        let mut out = Vec::new();
        f_seid.encode(&mut out).unwrap();
        hex::encode(out)
    };
    let v4 = FSeid::ipv4(0x1001, Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(encoded(v4), "0200000000000010010a000001");
    let v6 = FSeid::ipv6(7, "2001:db8::1".parse().unwrap());
    assert_eq!(
        encoded(v6),
        "01000000000000000720010db8000000000000000000000001"
    );
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

/// The path of a deviation is one of the tree of its message, which selects what it names:
/// a field of the header, an IE of no row by its name in the tree, and an entry of a list
/// or of a row there more than once by its position, among the IEs that the scope keeps
/// as octets too.
#[test]
fn the_path_of_a_deviation_is_one_of_the_tree() {
    let paths = |message: &Message| -> Vec<(String, Vec<tree::Value>)> {
        let tree = message.to_tree();
        let deviations = message.check(Interfaces::N4).into_iter();
        let selected = deviations.map(|deviation| {
            let values = select(&tree, &deviation.path)
                .unwrap_or_else(|error| panic!("{deviation}: {error}"));
            (deviation.path, values.into_iter().cloned().collect())
        });
        selected.collect()
    };
    let header = Header {
        spare: 1,
        spare_last: 2,
        priority: Some(3),
        ..Header::node(1)
    };
    let heartbeat = Message {
        header,
        body: HeartbeatRequest::new(RecoveryTimeStamp::new(1)).into(),
    };
    assert_eq!(
        paths(&heartbeat),
        [
            ("/Spare".into(), vec![tree!(1)]),
            ("/Spare octet".into(), vec![tree!(2)]),
            ("/Message Priority".into(), vec![tree!(3)]),
        ]
    );
    // Packet Rate Status Report, type 252, in a Session Modification Response, whose row of
    // that name is of type 264: the tree has it by its number
    let mut response = SessionModificationResponse::new(Cause::new(CauseValue::RequestAccepted));
    response.raw.push(RawIe::new(252, vec![1]));
    let mut message = Message::session(1, 1, response);
    assert_eq!(
        paths(&message),
        [("/pfcp/252".into(), vec![tree!({"octets": "01"})])]
    );
    let Body::SessionModificationResponse(response) = &mut message.body else {
        panic!()
    };
    response.raw.push(RawIe::new(252, vec![2]));
    assert_eq!(
        paths(&message),
        [
            ("/pfcp/252/0".into(), vec![tree!({"octets": "01"})]),
            ("/pfcp/252/1".into(), vec![tree!({"octets": "02"})]),
        ]
    );
    // A Create PDR that does not decode between two, the second without its Precedence, and
    // a second Cause
    let pdr = |id| tree!({"PDR ID": id, "Precedence": 1, "PDI": {"Source Interface": "Access"}, "FAR ID": 1});
    let mut second = pdr(2);
    tree::remove(&mut second, "/Precedence").unwrap();
    let request = tree!({
        "message": "PFCP Session Establishment Request",
        "SEID": 0,
        "Sequence Number": 1,
        "ies": {
            "Node ID": "10.0.0.1",
            "CP F-SEID": {"V4": true, "SEID": 1, "IPv4 address": "10.0.0.1"},
            "Create PDR": [pdr(1), {"octets": "ff"}, second],
            "Create FAR": [{"FAR ID": 1, "Apply Action": {"DROP": true}}],
        }
    });
    let request = Message::from_tree(&request).unwrap();
    assert_eq!(
        paths(&request),
        [
            ("/pfcp/Create PDR/1".into(), vec![tree!({"octets": "ff"})]),
            ("/pfcp/Create PDR/2/Precedence".into(), vec![]),
        ]
    );
    let mut response = AssociationReleaseResponse::new(
        NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
        Cause::new(CauseValue::RequestAccepted),
    );
    response.raw.push(RawIe::new(19, vec![2]));
    let response = Message::node(2, response);
    assert_eq!(
        paths(&response),
        [("/pfcp/Cause/1".into(), vec![tree!({"octets": "02"})])]
    );
    // The Cause first on the wire, of a reserved value, and two more: each at its position
    // in the list of the row; then without the value of the first, the IEs kept as octets
    // are the entries of its row, the first of which its receiver reads as the Cause
    let octets = [
        [0x20, 10, 0, 28, 0, 0, 2, 0].as_slice(),
        &[0, 19, 0, 1, 0],
        &[0, 60, 0, 5, 0, 10, 0, 0, 1],
        &[0, 19, 0, 1, 2],
        &[0, 19, 0, 1, 3],
    ]
    .concat();
    let mut response = Message::decode(&octets).unwrap();
    assert_eq!(response.encode().unwrap(), octets);
    assert_eq!(
        paths(&response),
        [
            ("/pfcp/Cause/1".into(), vec![tree!({"octets": "02"})]),
            ("/pfcp/Cause/2".into(), vec![tree!({"octets": "03"})]),
            ("/pfcp/Cause/0".into(), vec![tree!(0)]),
        ]
    );
    let Body::AssociationReleaseResponse(released) = &mut response.body else {
        panic!()
    };
    released.cause = None;
    assert_eq!(
        paths(&response),
        [("/pfcp/Cause/1".into(), vec![tree!({"octets": "03"})])]
    );
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
        found[1].cause,
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

/// The values at `path`, or the kind of the error.
fn found(tree: &tree::Value, path: &str) -> Result<Vec<tree::Value>, tree::ErrorKind> {
    select(tree, path)
        .map(|values| values.into_iter().cloned().collect::<Vec<_>>())
        .map_err(|error| error.kind())
}

/// The tree of the establishment of `establishment()`, changed.
fn establishment_tree(change: &dyn Fn(&mut SessionEstablishmentRequest)) -> tree::Value {
    let Body::SessionEstablishmentRequest(mut request) = establishment().body else {
        panic!()
    };
    change(&mut request);
    Message::session(0, 1, Body::SessionEstablishmentRequest(request)).to_tree()
}

/// A field whose tree is a scalar or an object, as its value is, has one rule for each
/// form: the member that the scalar is selects it, as the object's; another member of the
/// object selects nothing at the scalar; another name is no member, whatever the form.
/// Where the field is absent, nothing is selected. Of a value without or with spare bits:
/// a Time Unit of a Packet Rate.
#[test]
fn a_value_with_spare_bits_has_one_rule_in_either_form() {
    let none = Ok(Vec::<tree::Value>::new());
    let misspelt = Err(tree::ErrorKind::NoSuchMember);
    // Spare bits: a Time Unit without them, with them, and none
    let rate = |downlink: Option<Narrow<TimeUnit>>| PacketRate {
        ulpr: true,
        dlpr: downlink.is_some(),
        uplink_time_unit: Some(Narrow::new(TimeUnit::Minute)),
        maximum_uplink_packet_rate: Some(10),
        downlink_time_unit: downlink,
        maximum_downlink_packet_rate: downlink.map(|_| 10),
        ..Default::default()
    };
    let spared = Narrow {
        value: TimeUnit::Minute,
        spare: 0x40,
    };
    let tree = establishment_tree(&|request| {
        let qer = CreateQer::new(QerId::new(1), GateStatus::default());
        request
            .create_qer
            .push(qer.with_packet_rate(rate(Some(spared))));
        let qer = CreateQer::new(QerId::new(2), GateStatus::default());
        request.create_qer.push(qer.with_packet_rate(rate(None)));
    });
    let minute = tree!("minute");
    for (unit, value, spare, there) in [
        (
            "0/Packet Rate/Uplink Time Unit",
            Ok(vec![minute.clone()]),
            none.clone(),
            true,
        ),
        (
            "0/Packet Rate/Downlink Time Unit",
            Ok(vec![minute.clone()]),
            Ok(vec![tree!(64)]),
            true,
        ),
        (
            "1/Packet Rate/Downlink Time Unit",
            none.clone(),
            none.clone(),
            false,
        ),
    ] {
        let unit = format!("/pfcp/Create QER/{unit}");
        assert_eq!(found(&tree, &format!("{unit}/value")), value, "{unit}");
        assert_eq!(found(&tree, &format!("{unit}/Spare")), spare, "{unit}");
        let (bogus, below) = match there {
            true => (misspelt.clone(), Err(tree::ErrorKind::Scalar)),
            false => (none.clone(), none.clone()),
        };
        assert_eq!(found(&tree, &format!("{unit}/Bogus")), bogus, "{unit}");
        assert_eq!(
            found(&tree, &format!("{unit}/value/Bogus")),
            below,
            "{unit}"
        );
    }
}

/// A field whose tree is a scalar or an object, as its value is, has one rule for each
/// form: the member that the scalar is selects it, as the object's; another member of the
/// object selects nothing at the scalar; another name is no member, whatever the form.
/// Where the field is absent, nothing is selected. Of an IPv4 or IPv6 address or another:
/// the addresses of a Source Specific IP Multicast Address.
#[test]
fn an_address_has_one_rule_in_either_form() {
    let none = Ok(Vec::<tree::Value>::new());
    let misspelt = Err(tree::ErrorKind::NoSuchMember);
    // An address of IPv4, of another type, and none
    let ssm = SsmAddress {
        distribution: TypedAddress::from(core::net::IpAddr::V4(Ipv4Addr::new(232, 0, 0, 1))),
        source: TypedAddress {
            address_type: 2,
            address: vec![1, 2],
        },
    };
    let mbs = |ssm: Option<SsmAddress>| {
        MbsSessionN4ControlInformation::new(MbsSessionIdentifier {
            tmgi: true,
            tmgi_field: Some([1, 2, 3, 4, 5, 6]),
            ssmi: ssm.is_some(),
            source_specific_ip_multicast_address: ssm,
            ..Default::default()
        })
    };
    let tree = establishment_tree(&|request| {
        *request = request
            .clone()
            .with_mbs_session_n4_control_information(mbs(Some(ssm.clone())))
    });
    let without = establishment_tree(&|request| {
        *request = request
            .clone()
            .with_mbs_session_n4_control_information(mbs(None))
    });
    for written in [&tree, &without] {
        assert_eq!(&Message::from_tree(written).unwrap().to_tree(), written);
    }
    let ssm = "/pfcp/MBS Session N4 Control Information/0/MBS Session Identifier/Source Specific IP Multicast Address";
    // An address of 63 octets at most, as its six bits of length say (§8.2.207)
    for (octets, read) in [(63, true), (64, false)] {
        let mut long = tree.clone();
        let address = tree!("ab".repeat(octets));
        set(
            &mut long,
            &format!("{ssm}/IP Source Address/Address"),
            address,
        )
        .unwrap();
        assert_eq!(Message::from_tree(&long).is_ok(), read, "{octets} octets");
    }
    for (tree, address, value, kind) in [
        (
            &tree,
            "IP Multicast Distribution Address",
            Ok(vec![tree!("232.0.0.1")]),
            none.clone(),
        ),
        (
            &tree,
            "IP Source Address",
            Ok(vec![tree!({"octets": "0102"})["octets"].clone()]),
            Ok(vec![tree!(2)]),
        ),
        (&without, "IP Source Address", none.clone(), none.clone()),
    ] {
        let bogus = match tree == &without {
            true => none.clone(),
            false => misspelt.clone(),
        };
        let address = format!("{ssm}/{address}");
        assert_eq!(
            found(tree, &format!("{address}/Address")),
            value,
            "{address}"
        );
        assert_eq!(
            found(tree, &format!("{address}/Address Type")),
            kind,
            "{address}"
        );
        assert_eq!(found(tree, &format!("{address}/Bogus")), bogus, "{address}");
    }
}

/// A field whose tree is a scalar or an object, as its value is, has one rule for each
/// form: the member that the scalar is selects it, as the object's; another member of the
/// object selects nothing at the scalar; another name is no member, whatever the form.
/// Where the field is absent, nothing is selected. Of an identity of digits or text, or of
/// other octets: the IMSI and the NAI of a User ID.
#[test]
fn an_identity_has_one_rule_in_either_form() {
    let none = Ok(Vec::<tree::Value>::new());
    let misspelt = Err(tree::ErrorKind::NoSuchMember);
    // An identity of digits, of text, of other octets, and none
    let user = |imsi: Option<DigitsLv8>| UserId {
        imsif: imsi.is_some(),
        imsi,
        naif: true,
        nai: Some(TextLv8::from("user@example")),
        ..Default::default()
    };
    for (imsi, octets) in [
        (Some(DigitsLv8::new("20893").unwrap()), none.clone()),
        (
            Some(DigitsLv8([0x02, 0xf8, 0x39].into())),
            Ok(vec![tree!({"octets": "02f839"})["octets"].clone()]),
        ),
        (None, none.clone()),
    ] {
        let tree = establishment_tree(&|request| request.user_id = Some(user(imsi.clone())));
        let bogus = match imsi.is_some() {
            true => misspelt.clone(),
            false => none.clone(),
        };
        let imsi = "/pfcp/User ID/IMSI";
        assert_eq!(found(&tree, &format!("{imsi}/octets")), octets, "{imsi:?}");
        assert_eq!(found(&tree, &format!("{imsi}/Bogus")), bogus, "{imsi:?}");
        assert_eq!(found(&tree, "/pfcp/User ID/NAI/octets"), none);
        assert_eq!(found(&tree, "/pfcp/User ID/NAI/Bogus"), misspelt);
    }
}

/// What the tree of a message holds of the members of its values: at each value of an IE
/// that is no grouped IE, each member that it has is a member of its IE type
/// (`IeTypeInfo::members`), and each other member of its type selects nothing, but the one
/// field that a value written as a scalar is, which selects it; each member of the header
/// that it lacks selects nothing. How many values it looked at.
fn members_hold(message: &tree::Value) -> usize {
    let members = message.as_object().unwrap();
    let name = members.get("message").and_then(tree::Value::as_str);
    let Some(info) = name.and_then(|name| MESSAGE_TYPES.iter().find(|info| info.name() == name))
    else {
        return 0;
    };
    let header = [
        "Version",
        "Spare",
        "FO",
        "SEID",
        "Message Priority",
        "Spare octet",
        "Message Length",
    ];
    for member in header.iter().filter(|member| !members.contains_key(member)) {
        let selected = select(message, &format!("/{member}"));
        assert_eq!(
            selected.map_err(|error| error.kind()),
            Ok(vec![]),
            "{member}"
        );
    }
    let mut count = 0;
    values_hold(message, &[info.table], &members["ies"], "/pfcp", &mut count);
    count
}

/// [`members_hold`] at the IEs `ies` of the tables `tables`, at `path`.
fn values_hold(
    message: &tree::Value,
    tables: &[&'static Table],
    ies: &tree::Value,
    path: &str,
    count: &mut usize,
) {
    for (name, held) in ies.as_object().unwrap() {
        let mut rows = tables.iter().flat_map(|table| table.rows.iter());
        let Some(row) = rows.find(|row| tree::same_name(row.name, name)) else {
            continue;
        };
        let info = ie_type_info(row.ie_type).unwrap();
        let place = format!("{path}/{}", tree::escape(name));
        let entries: Vec<(String, &tree::Value)> = match held {
            tree::Value::Array(list) => list
                .iter()
                .enumerate()
                .map(|(at, entry)| (format!("{place}/{at}"), entry))
                .collect(),
            single => vec![(place, single)],
        };
        for (at, entry) in entries {
            let printed: Vec<&str> = entry
                .as_object()
                .map(|members| members.keys().map(String::as_str).collect())
                .unwrap_or_default();
            if printed.contains(&"octets") {
                continue;
            }
            if info.form == Form::Grouped {
                values_hold(message, info.tables, entry, &at, count);
                continue;
            }
            *count += 1;
            for name in &printed {
                let known = info
                    .members
                    .iter()
                    .any(|member| tree::same_name(member, name));
                assert!(known, "{at}: {name:?} is no member of {}", info.name);
            }
            let lacked = info
                .members
                .iter()
                .filter(|member| !printed.iter().any(|name| tree::same_name(member, name)));
            for member in lacked {
                let path = format!("{at}/{}", tree::escape(member));
                let scalar_field = !entry.is_object() && info.scalar == Some(*member);
                let wanted = if scalar_field { vec![entry] } else { vec![] };
                let selected = select(message, &path).map_err(|error| error.kind());
                assert_eq!(selected, Ok(wanted), "{path}");
            }
            // What the tree of each field that the value has holds below it is what the
            // paths judge a field that a value lacks by: with the field taken out, each
            // member of its object, and an entry of its list, selects nothing
            for (name, field) in entry.as_object().into_iter().flatten() {
                let below: Vec<String> = match field {
                    tree::Value::Array(_) => vec!["0".to_string()],
                    tree::Value::Object(members) => members
                        .keys()
                        .map(|member| tree::escape(member).into_owned())
                        .collect(),
                    _ => continue,
                };
                let path = format!("{at}/{}", tree::escape(name));
                let mut lacking = message.clone();
                let plain = path.replacen("/pfcp", "/ies", 1);
                tree::remove(&mut lacking, &plain).unwrap();
                for below in below {
                    let selected = select(&lacking, &format!("{path}/{below}"));
                    assert_eq!(
                        selected.map_err(|error| error.kind()),
                        Ok(vec![]),
                        "{path}/{below}"
                    );
                }
            }
        }
    }
}

/// [`members_hold`] in each captured message, whose values are of many IE types.
#[test]
fn what_each_captured_value_lacks_selects_nothing() {
    let mut values = 0;
    for line in include_str!("captures/messages.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let octets = hex::decode(line.split('\t').nth(5).unwrap()).unwrap();
        values += members_hold(&Message::decode(&octets).unwrap().to_tree());
    }
    assert!(values > 1500, "{values} values");
}

/// The vectors of go-pfcp, in the file that `PFCP_VECTORS` names, which
/// tests/go-pfcp-vectors.py writes: each decodes and encodes back to its octets, its
/// tree, in the order of its tables, reads back to itself, and what its values lack of
/// their members selects nothing ([`members_hold`]); what check() finds in them is
/// what `go-pfcp-deviations.tsv` lists. A fourth column names the interface to check the
/// message on; without it, on N4 with the IEs of any interface. CI runs it with
/// `--ignored`.
#[test]
#[ignore = "the vectors of go-pfcp, in the file that PFCP_VECTORS names"]
fn other_vectors_round_trip() {
    let file = std::env::var("PFCP_VECTORS").expect("PFCP_VECTORS names the file of the vectors");
    let (mut read, mut reordered) = (0, 0);
    let mut found = Vec::new();
    let vectors = std::fs::read_to_string(file).unwrap();
    for line in vectors.lines() {
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
                members_hold(&tree);
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
                        let cause = deviation
                            .cause
                            .map_or("-".to_string(), |cause| format!("{cause:?}"));
                        let Deviation {
                            path, clause, kind, ..
                        } = deviation;
                        found.push(format!(
                            "{}\t{}\t{path}\t{clause}\t{kind:?}\t{cause}",
                            fields[0], fields[1]
                        ));
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
    let mut expected: Vec<&str> = include_str!("go-pfcp-deviations.tsv")
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .collect();
    let mut found: Vec<&str> = found.iter().map(String::as_str).collect();
    expected.sort_unstable();
    found.sort_unstable();
    let missing: Vec<&&str> = expected
        .iter()
        .filter(|line| !found.contains(line))
        .collect();
    let more: Vec<&&str> = found
        .iter()
        .filter(|line| !expected.contains(line))
        .collect();
    assert!(
        found == expected,
        "not found: {missing:#?}\nnot listed: {more:#?}"
    );
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

/// The four values that the crate reads by hand, whose figures the test `spec` does not
/// compare (`figure_places`), have the places of their figures, octet by octet: Node ID
/// (§8.2.38), FQ-CSID (§8.2.43), and MAC Addresses Detected and Removed (§8.2.103,
/// §8.2.104). Each decodes from octets written from its figure, and encodes back to them.
#[test]
fn the_values_read_by_hand_have_the_places_of_their_figures() {
    fn again<T: Codec>(value: &T) -> Vec<u8> {
        let mut octets = Vec::new();
        value.encode(&mut octets).unwrap();
        octets
    }
    // Node ID: the Node ID Type in bits 1 to 4 of octet 5, the others spare; the value from
    // octet 6, of the length that the type says
    let ipv4 = [0x00, 10, 0, 0, 1];
    assert_eq!(
        NodeId::decode(&ipv4),
        Some(NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 1)))
    );
    assert_eq!(again(&NodeId::decode(&ipv4).unwrap()), ipv4);
    let ipv6 = [&[0x01][..], &[0x20, 0x01], &[0; 13], &[0x01]].concat();
    assert!(
        matches!(NodeId::decode(&ipv6), Some(NodeId::Ipv6(address)) if address.segments()[0] == 0x2001)
    );
    let fqdn = [0x02, 3, b'u', b'p', b'f'];
    assert_eq!(
        NodeId::decode(&fqdn)
            .and_then(|node_id| node_id.fqdn())
            .as_deref(),
        Some("upf")
    );
    assert_eq!(again(&NodeId::decode(&fqdn).unwrap()), fqdn);
    let spare = NodeId::decode(&[0xf0, 10, 0, 0, 1]).unwrap();
    assert_eq!(
        spare.effective(),
        Some(NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 1)))
    );
    // FQ-CSID: the Node-ID Type in bits 5 to 8 of octet 5, the Number of CSIDs in bits 1
    // to 4; the Node-Address from octet 6, of 4 octets for types 0 and 2 and 16 for type
    // 1; the CSIDs of two octets each; the Node Type in bits 1 to 4 of the octet after
    let octets = [0x22, 0x0c, 0x80, 0x10, 0x01, 0x00, 0x07, 0x00, 0x09, 0x02];
    let fq_csid = FqCsid::decode(&octets).unwrap();
    assert_eq!(fq_csid.node_id_type, 2);
    assert_eq!(*fq_csid.node_address, [0x0c, 0x80, 0x10, 0x01]);
    assert_eq!(fq_csid.csids, [7, 9]);
    assert_eq!(
        fq_csid.node_type.map(|node_type| node_type.value),
        Some(NodeType::PgwCSmf)
    );
    assert_eq!(again(&fq_csid), octets);
    let ipv6 = FqCsid {
        node_id_type: 1,
        node_address: [0; 16].into(),
        csids: vec![1],
        ..Default::default()
    };
    assert_eq!(again(&ipv6), [&[0x11][..], &[0; 16], &[0, 1]].concat());
    // A reserved Node-ID Type is written with the Node-Address that the value has, which
    // a receiver cannot frame; one of more than four bits is not
    let mut out = Vec::new();
    let reserved = FqCsid {
        node_id_type: 3,
        node_address: [10, 0, 0, 1, 2].into(),
        csids: vec![1],
        ..Default::default()
    };
    reserved.encode(&mut out).unwrap();
    assert_eq!(out, [0x31, 10, 0, 0, 1, 2, 0, 1]);
    assert_eq!(FqCsid::decode(&out), None);
    let last = FqCsid {
        node_id_type: 15,
        ..reserved.clone()
    };
    assert!(last.encode(&mut Vec::new()).is_ok());
    let wide = FqCsid {
        node_id_type: 16,
        ..reserved
    };
    assert!(matches!(
        wide.encode(&mut Vec::new()),
        Err(Error::FieldLength { .. })
    ));
    // Fifteen CSIDs at most, which four bits count, and the Node-Address of a known type
    let csids = |count: u16, address: Vec<u8>| FqCsid {
        node_id_type: 0,
        node_address: address.into(),
        csids: (0..count).collect(),
        ..Default::default()
    };
    assert!(csids(15, vec![10, 0, 0, 1]).encode(&mut Vec::new()).is_ok());
    for refused in [csids(16, vec![10, 0, 0, 1]), csids(1, vec![10, 0, 0, 1, 2])] {
        assert!(matches!(
            refused.encode(&mut Vec::new()),
            Err(Error::Inconsistent { .. })
        ));
    }
    // MAC Addresses Detected and Removed: the number of MAC addresses in octet 5, each
    // address of 6 octets, then the C-TAG and the S-TAG, each after its length
    let octets = [
        &[2][..],
        &[0x02, 0, 0, 0, 0, 1],
        &[0x02, 0, 0, 0, 0, 2],
        &[3, 0x07, 0x00, 0x64],
        &[3, 0x07, 0x00, 0xc8],
    ]
    .concat();
    let detected = MacAddressesDetected::decode(&octets).unwrap();
    assert_eq!(
        detected.mac_addresses,
        [[0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2]]
    );
    assert_eq!(
        detected.c_tag.as_ref().map(|tag| tag.0.to_vec()),
        Some(vec![0x07, 0x00, 0x64])
    );
    assert_eq!(
        detected.s_tag.as_ref().map(|tag| tag.0.to_vec()),
        Some(vec![0x07, 0x00, 0xc8])
    );
    assert_eq!(again(&detected), octets);
    let removed = MacAddressesRemoved::decode(&octets[..13]).unwrap();
    assert_eq!(removed.mac_addresses.len(), 2);
    assert!(removed.c_tag.is_none() && removed.s_tag.is_none());
    assert_eq!(again(&removed), octets[..13]);
}

/// §8.2.38: a Node ID of an FQDN from its text, as RFC 1035 writes its labels, which
/// gives the text back; not from a text of an empty label, one of more than 63 octets, or
/// of more than 255 octets with the trailing zero byte that the IE leaves out (RFC 1035
/// §2.3.4).
#[test]
fn an_fqdn_node_id_from_its_text() {
    let node_id = NodeId::from_fqdn("upf.example").unwrap();
    assert_eq!(node_id, NodeId::Fqdn(b"\x03upf\x07example".to_vec().into()));
    assert_eq!(node_id.fqdn().as_deref(), Some("upf.example"));
    let longest = "a".repeat(63);
    assert_eq!(
        NodeId::from_fqdn(&longest).and_then(|node_id| node_id.fqdn()),
        Some(longest.clone())
    );
    // Labels of 254 octets, 255 with the trailing zero byte: 253 characters of text.
    let name = [&longest[..], &longest, &longest, &longest[..61]].join(".");
    assert_eq!(name.len(), 253);
    assert_eq!(
        NodeId::from_fqdn(&name).and_then(|node_id| node_id.fqdn()),
        Some(name.clone())
    );
    let over = format!("{name}a");
    for name in [
        "",
        "upf..example",
        "upf.",
        ".upf",
        &format!("{longest}a"),
        &over,
    ] {
        assert_eq!(NodeId::from_fqdn(name), None, "{name:?}");
    }
}

/// §8.2.131: the FQDN of an SMF Set ID is labels as RFC 1035 writes them, as that of a
/// Node ID: its tree is the name, and octets that are no labels are `{"octets": ...}`,
/// each read back to its octets.
#[test]
fn the_fqdn_of_an_smf_set_id_as_its_name() {
    let fqdn = Fqdn::new("smf.set").unwrap();
    assert_eq!(fqdn, Fqdn(b"\x03smf\x03set".to_vec().into()));
    assert_eq!(fqdn.name().as_deref(), Some("smf.set"));
    let request = |fqdn: Fqdn| {
        Message::node(
            1,
            AssociationSetupRequest::new(
                NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
                RecoveryTimeStamp::new(1),
            )
            .with_smf_set_id(SmfSetId {
                fqdn,
                ..Default::default()
            }),
        )
    };
    for (fqdn, tree) in [
        (fqdn, tree!("smf.set")),
        (
            Fqdn(b"smf.set".to_vec().into()),
            tree!({"octets": "736d662e736574"}),
        ),
    ] {
        let message = request(fqdn);
        let written = message.to_tree();
        assert_eq!(select(&written, "/pfcp/SMF Set ID/FQDN").unwrap(), [&tree]);
        assert_eq!(Message::from_tree(&written).unwrap(), message);
    }
    for name in ["", "smf..set", &"a".repeat(254)] {
        assert_eq!(Fqdn::new(name), None, "{name:?}");
    }
    // Decoded: the spare octet, then the labels, the rest of the IE
    let decoded = SmfSetId::decode(b"\x00\x03smf\x03set").unwrap();
    assert_eq!(decoded.fqdn, Fqdn::new("smf.set").unwrap());
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
    // Labels of 255 octets, 256 with the trailing zero byte (RFC 1035 §2.3.4).
    let label = [&[63][..], &[b'a'; 63]].concat();
    let too_long = [&label[..], &label, &label, &[62], &[b'a'; 62]].concat();
    assert_eq!(too_long.len(), 255);
    assert_eq!(fqdn(&too_long).fqdn(), None);
    assert!(
        fqdn(&[&too_long[..192], &[61], &[b'a'; 61]].concat())
            .fqdn()
            .is_some()
    );
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
        &[[2].as_slice(), &too_long].concat(),
    ] {
        let node_id = read(content);
        let tree = tree::Tree::to_tree(&node_id);
        let back: NodeId =
            tree::from_value(&tree).unwrap_or_else(|error| panic!("{content:?}: {error}: {tree}"));
        let mut octets = Vec::new();
        Codec::encode(&back, &mut octets).unwrap();
        assert_eq!(octets, content, "{tree}");
    }
    let over = [
        &"a".repeat(63)[..],
        &"a".repeat(63),
        &"a".repeat(63),
        &"a".repeat(62),
    ]
    .join(".");
    for name in ["a..b", "", ".a", "a.", &"a".repeat(64), &over] {
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
/// message is the rest of the datagram, whatever its FO flag says.
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
    // An FO flag on the last message follows on to nothing
    assert!(matches!(&Message::decode_datagram(&first)[..], [Ok(_)]));
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
    Message::node(1, HeartbeatRequest::new(RecoveryTimeStamp::new(1)))
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

/// A message longer than its Message Length can say is refused as a message, of its
/// type and length.
#[test]
fn a_message_too_long_for_its_length() {
    let mut request = HeartbeatRequest::new(RecoveryTimeStamp::new(1));
    for _ in 0..2 {
        request.raw.push(RawIe::new(1000, vec![0; 40_000]));
    }
    let message = Message::node(1, request);
    assert_eq!(
        message.encode(),
        Err(Error::MessageTooLong {
            message_type: 1,
            length: 4 + 8 + 2 * 40_004,
        })
    );
}

/// A spare octet of a value is 0 where its tree leaves it out, and its tree has it only
/// where it is set, as the spare bits of the header and of a narrow value: an SDF Filter,
/// PFD Contents, an SMF Set ID, a Multicast Transport Information and the DL and UL
/// Periodicity.
#[test]
fn a_spare_octet_is_in_the_tree_where_it_is_set() {
    fn spare<T: tree::Tree + Codec + PartialEq + core::fmt::Debug>(
        octets: &str,
        tree: tree::Value,
    ) {
        let octets = hex::decode(octets).unwrap();
        let value = T::decode(&octets).unwrap();
        assert_eq!(tree::Tree::to_tree(&value), tree, "{value:?}");
        assert_eq!(tree::from_value::<T>(&tree).unwrap(), value);
    }
    spare::<SdfFilter>(
        "010000026161",
        tree!({"FD": true, "Flow Description": "6161"}),
    );
    spare::<SdfFilter>(
        "010700026161",
        tree!({"FD": true, "Spare octet": 7, "Flow Description": "6161"}),
    );
    spare::<PfdContents>("0100000161", tree!({"FD": true, "Flow Description": "61"}));
    spare::<SmfSetId>("0003736d66", tree!({"FQDN": "smf"}));
    spare::<SmfSetId>("0103736d66", tree!({"Spare": 1, "FQDN": "smf"}));
    spare::<DlPeriodicity>("0000000014", tree!({"DL Periodicity": 20}));
    spare::<UlPeriodicity>("0200000014", tree!({"Spare": 2, "UL Periodicity": 20}));
    spare::<MulticastTransportInformation>(
        "00000000010400000001040a000001",
        tree!({
            "Common Tunnel Endpoint Identifier": 1,
            "IP Multicast Distribution Address (IPv4 or IPv6)": "0.0.0.1",
            "IP Source Address (IPv4 or IPv6)": "10.0.0.1"
        }),
    );
}

/// A value of octets of bits that has fewer octets than its release, its `length`, writes
/// those alone: a field, a spare bit or unknown octets past them, which the length would
/// not write, are refused by its tree and by `encode()`, and told by `check()`.
#[test]
fn the_length_of_a_value_of_bits_is_what_it_writes() {
    let features = |tree| tree::from_value::<UpFunctionFeatures>(&tree);
    let short = features(tree!({"FTUP": true, "length": 1})).unwrap();
    let mut octets = Vec::new();
    short.encode(&mut octets).unwrap();
    assert_eq!(octets, [0x10]);
    assert_eq!(
        tree::Tree::to_tree(&short),
        tree!({"FTUP": true, "length": 1})
    );
    for past in [
        tree!({"FTUP": true, "EMPU": true, "length": 1}),
        tree!({"Spare": "000000000000000000000001", "length": 11}),
        tree!({"FTUP": true, "length": 1, "unknown octets": "00"}),
    ] {
        assert!(features(past.clone()).is_err(), "{past}");
    }
    let past = UpFunctionFeatures {
        empu: true,
        present: 1,
        ..Default::default()
    };
    assert_eq!(
        past.encode(&mut Vec::new()),
        Err(Error::Inconsistent {
            ie: "UP Function Features",
            field: "length",
            clause: "8.2.25"
        })
    );
    let found: Vec<_> = past.deviations().into_iter().map(|d| d.kind).collect();
    assert_eq!(found, [DeviationKind::Inconsistent { field: "length" }]);
}

/// The octets after the fields of an IE, of a later release, are "the unknown octets" of
/// §8.1.2 in a tree. A value of one field, without flags, is that field alone without
/// them: a number, and the octets after their length of a Forwarding Policy.
#[test]
fn the_unknown_octets_of_an_ie() {
    let mut precedence = Precedence::new(1);
    assert_eq!(tree::Tree::to_tree(&precedence), tree!(1));
    precedence.extra = Octets::copied(&[0xaa]);
    let tree = tree::Tree::to_tree(&precedence);
    assert_eq!(
        tree.to_string(),
        r#"{"Precedence value":1,"unknown octets":"aa"}"#
    );
    assert_eq!(tree::from_value::<Precedence>(&tree).unwrap(), precedence);
    let mut policy = ForwardingPolicy {
        forwarding_policy_identifier: Lv8(Octets::copied(b"p1")),
        ..Default::default()
    };
    let tree = tree::Tree::to_tree(&policy);
    assert_eq!(tree, tree!("7031"));
    assert_eq!(tree::from_value::<ForwardingPolicy>(&tree).unwrap(), policy);
    policy.extra = Octets::copied(&[0xaa]);
    let tree = tree::Tree::to_tree(&policy);
    assert_eq!(
        tree.to_string(),
        r#"{"Forwarding Policy Identifier":"7031","unknown octets":"aa"}"#
    );
    assert_eq!(tree::from_value::<ForwardingPolicy>(&tree).unwrap(), policy);
}

/// A message read back from its tree is equal to the one decoded: an FQ-CSID of IPv6
/// whose content frames as IEs, and one that does not decode.
#[test]
fn a_message_read_back_equals_the_one_decoded() {
    let mut address = [0; 16];
    address[2] = 15;
    let fq_csid = FqCsid {
        node_id_type: 1,
        node_address: address.into(),
        csids: vec![1],
        ..Default::default()
    };
    let request = SessionSetDeletionRequest::new(NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 1)))
        .with_fq_csid(fq_csid);
    let mut octets = Message::node(1, request).encode().unwrap();
    octets.extend_from_slice(&[0, 65, 0, 4, 0, 0, 0, 0]);
    let length = (octets.len() - 4) as u16;
    octets[2..4].copy_from_slice(&length.to_be_bytes());
    let decoded = Message::decode(&octets).unwrap();
    assert_eq!(Message::from_tree(&decoded.to_tree()).unwrap(), decoded);
}

/// §7.2.2: a header value that its bits cannot hold is not cut: encode() refuses it, and
/// check() says it; a tree cannot write it.
#[test]
fn a_header_value_that_its_bits_cannot_hold() {
    let message = |header: Header| Message {
        header,
        body: SessionDeletionRequest::default().into(),
    };
    for (header, field) in [
        (Header::session(1, 0x0100_0005), "Sequence Number"),
        (
            Header {
                priority: Some(17),
                ..Header::session(1, 5)
            },
            "Message Priority",
        ),
        (
            Header {
                priority: Some(1),
                spare_last: 0x35,
                ..Header::session(1, 5)
            },
            "Spare octet",
        ),
        (
            Header {
                version: 9,
                ..Header::session(1, 5)
            },
            "Version",
        ),
        (
            Header {
                spare: 4,
                ..Header::session(1, 5)
            },
            "Spare",
        ),
    ] {
        let message = message(header);
        assert!(
            matches!(message.encode(), Err(Error::HeaderField { field: named, .. }) if named == field),
            "{header:?}"
        );
        // At the member of the field in the tree of the message
        let wide = message.check(Interfaces::N4).into_iter().find(|deviation| {
            deviation.clause == "7.2.2.1" && matches!(deviation.kind, DeviationKind::Rule(_))
        });
        assert_eq!(
            wide.map(|deviation| deviation.path),
            Some(format!("/{field}")),
            "{header:?}"
        );
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
        proxy_authen_name_value: Some(Lv8(b"alice".into())),
        proxy_authen_response_value: Some(SecretLv8(b"secret".into())),
        ..Default::default()
    };
    let printed = format!("{authentication:?}");
    assert!(printed.contains("616c696365"), "{printed}");
    assert!(
        !printed.contains("736563726574") && !printed.contains("secret"),
        "{printed}"
    );
    let printed = format!("{:?}", RawIe::new(278, b"secret".to_vec()));
    assert!(
        !printed.contains("115, 101, 99") && !printed.contains("736563"),
        "{printed}"
    );
    // An Enterprise ID, which a tree or a builder gives an IE of 3GPP, hides nothing
    let password = RawIe {
        enterprise_id: Some(7),
        ..RawIe::new(313, b"secret".to_vec())
    };
    let printed = format!("{password:?}");
    assert!(
        printed.contains("6 octets") && !printed.contains("736563"),
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

/// §8.2.27 and §8.2.214: a QFI, a Paging Policy Indication value and a DSCP value have the
/// six low bits of their octet, whose two others are spare: a tree has them apart, and
/// has no number that six bits cannot hold.
#[test]
fn a_number_of_six_bits_in_a_tree() {
    let service = DownlinkDataServiceInformation::decode(&[0x03, 0xc1, 0x41]).unwrap();
    let written = tree!({
        "QFII": true,
        "PPI": true,
        "Paging Policy Indication value": {"value": 1, "Spare": 192},
        "QFI": {"value": 1, "Spare": 64}
    });
    assert_eq!(tree::Tree::to_tree(&service), written);
    let read: DownlinkDataServiceInformation = tree::from_value(&written).unwrap();
    assert_eq!(read, service);
    let wide = tree!({"QFII": true, "QFI": 65});
    assert!(tree::from_value::<DownlinkDataServiceInformation>(&wide).is_err());
    let mapping = DscpToPpiMappingInformation::decode(&[0x01, 0x2e, 0xc1]).unwrap();
    let written = tree!({"PPI Value": 1, "DSCP Value": [46, {"value": 1, "Spare": 192}]});
    assert_eq!(tree::Tree::to_tree(&mapping), written);
}

/// Values that the crate once misread, each as its clause has it: a Downlink Data
/// Service Information for each PDR ID of a Downlink Data Report (Table 7.5.8.2-1).
#[test]
fn a_downlink_data_report_has_a_service_information_for_each_pdr() {
    // Table 7.5.8.2-1: a Downlink Data Service Information for each PDR ID
    let service = DownlinkDataServiceInformation {
        ppi: true,
        paging_policy_indication: Some(Narrow::new(Number(3))),
        ..Default::default()
    };
    let report = DownlinkDataReport::new(PdrId::new(1))
        .with_pdr_id(PdrId::new(2))
        .with_downlink_data_service_information(service.clone())
        .with_downlink_data_service_information(service);
    let message = Message::session(
        1,
        1,
        SessionReportRequest::new(ReportType {
            dldr: true,
            ..Default::default()
        })
        .with_downlink_data_report(report),
    );
    assert!(
        message.check(Interfaces::N4).is_empty(),
        "{:?}",
        message.check(Interfaces::N4)
    );
    let decoded = Message::decode(&message.encode().unwrap()).unwrap();
    assert_eq!(decoded, message);
}

/// Values that the crate once misread, each as its clause has it: numbers, and the spare
/// bits beside them.
#[test]
fn numbers_and_their_spare_bits_as_their_clauses_have_them() {
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
        tree["Number of UE IP Addresses"]["Number of UE IPv4 Addresses"],
        tree!(10),
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
        extra: Octets::default(),
    };
    let tree = tree::Tree::to_tree(&multiplier);
    assert_eq!(tree["Exponent"], tree!(-2), "{tree}");
    assert_eq!(tree::from_value::<Multiplier>(&tree).unwrap(), multiplier);
    let mut octets = Vec::new();
    multiplier.encode(&mut octets).unwrap();
    assert_eq!(&octets[8..], [0xff, 0xff, 0xff, 0xfe]);
}

/// Values that the crate once misread, each as its clause has it: fields after their
/// lengths and after other fields, and the enumerations.
#[test]
fn fields_after_their_lengths_as_their_clauses_have_them() {
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
        nai: Some(TextLv8(vec![b'a'; 300].into())),
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
    assert_eq!(tree["IMSI"], tree!("208930000000001"), "{tree}");
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
        let found = self.deviations();
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

/// A row is written as its table has it: a row of a list as a list, also of one entry, and
/// the repetitions of a row there once by their octets.
#[test]
fn a_row_is_written_as_its_table_has_it() {
    let request = |ies: tree::Value| tree!({"message": "PFCP Session Establishment Request", "SEID": 0, "Sequence Number": 1, "ies": ies});
    let far = tree!({"FAR ID": 1, "Apply Action": {"DROP": true}});
    let error = Message::from_tree(&request(tree!({"Create FAR": far.clone()})))
        .unwrap_err()
        .to_string();
    assert!(error.contains("a list is expected"), "{error}");
    assert!(Message::from_tree(&request(tree!({"Create FAR": [far]}))).is_ok());
    let error = Message::from_tree(&request(tree!({"Node ID": ["10.0.0.1", "10.0.0.2"]})))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("a repetition is written by its octets"),
        "{error}"
    );
    let repeated = tree!({"Node ID": ["10.0.0.1", {"octets": "000a000002"}]});
    assert!(Message::from_tree(&request(repeated)).is_ok());
}

/// A message goes by its name: a message type of Table 7.3-1 written by its number is
/// refused with the name to write, and the number is for a message type of no table, whose
/// IEs are octets.
#[test]
fn a_message_goes_by_its_name() {
    let heartbeat =
        tree!({"message": 1, "Sequence Number": 9, "ies": {"octets": "006000040000000a"}});
    let error = Message::from_tree(&heartbeat).unwrap_err().to_string();
    assert!(error.contains("PFCP Heartbeat Request"), "{error}");
    let other = tree!({"message": 99, "Sequence Number": 9, "ies": {"octets": "006000040000000a"}});
    let other = Message::from_tree(&other).unwrap();
    assert!(matches!(
        other.body,
        Body::Other {
            message_type: 99,
            ..
        }
    ));
    assert_eq!(Message::decode(&other.encode().unwrap()).unwrap(), other);
}

/// §8.2.137: the (end) addresses of an IP Multicast Address are there with R alone, a range;
/// a single address is its (start) address.
#[test]
fn an_ip_multicast_address_has_its_end_with_a_range() {
    let single = IpMulticastAddress::decode(&[0x02, 224, 0, 0, 1]).unwrap();
    assert_eq!(single.ipv4_address, Some(Ipv4Addr::new(224, 0, 0, 1)));
    assert_eq!(single.ipv4_address_2, None);
    assert!(single.extra.is_empty());
    let range = IpMulticastAddress::decode(&[0x06, 224, 0, 0, 1, 224, 0, 0, 255]).unwrap();
    assert_eq!(range.ipv4_address_2, Some(Ipv4Addr::new(224, 0, 0, 255)));
    let mut octets = Vec::new();
    single.encode(&mut octets).unwrap();
    assert_eq!(octets, [0x02, 224, 0, 0, 1]);
}

/// A value of one field that is no flag is built from it, as a Timer from its unit and its
/// value: without spare bits, of the octets of this release.
#[test]
fn small_values_from_their_fields() {
    assert_eq!(
        Qfi::new(5),
        Qfi {
            qfi_value: 5,
            ..Default::default()
        }
    );
    let steering = SteeringFunctionality::new(SteeringFunctionalityValue::MpquicIp);
    assert_eq!(
        steering.steering_functionality_value,
        SteeringFunctionalityValue::MpquicIp
    );
    let timer = Timer::new(TimerUnit::OneMinute, 30);
    let mut octets = Vec::new();
    Codec::encode(&timer, &mut octets).unwrap();
    assert_eq!(octets, [0x20 | 30]);
    assert_eq!(Timer::decode(&octets), Some(timer));
}

/// `T` read from `octets` (spaces apart), which it encodes back to, of the length that it
/// says, whose tree reads back.
fn read_back<T>(octets: &str) -> T
where
    T: Codec + tree::Tree + PartialEq + std::fmt::Debug,
{
    let octets = hex::decode(octets.replace(' ', "")).unwrap();
    let value = T::decode(&octets).unwrap_or_else(|| panic!("{}", hex::encode(&octets)));
    let mut again = Vec::new();
    value.encode(&mut again).unwrap();
    assert_eq!(again, octets, "{value:?}");
    assert_eq!(value.encoded_len(), octets.len(), "{value:?}");
    let written = tree::Tree::to_tree(&value);
    assert_eq!(tree::from_value::<T>(&written).unwrap(), value, "{written}");
    value
}

/// Fields of each kind, read and written back as their figures have them, with their
/// lengths and their trees: a counted list of QFIs (§8.2.156), a PLMN as TS 29.274 writes
/// it (§8.2.108), two addresses after their types (§8.2.206), a key after its length
/// (§8.2.276), a Rule ID after its type (§8.2.80), an FQ-CSID of an IPv6 node with a node
/// type and later octets (§8.2.46).
#[test]
fn fields_of_each_kind_read_back_as_their_figures_have_them() {
    let pmf: PmfControlInformation = read_back("04 02 01 05");
    assert_eq!(pmf.qfis.map(|qfis| qfis.0.len()), Some(2));
    let trace: TraceInformation = read_back("02f839 000001 0101 05 0102 040a000001");
    assert_eq!(tree::Tree::to_tree(&trace)["MCC and MNC"], tree!("208-93"));
    assert!(trace.deviations().is_empty());
    let mbs: MbsSessionIdentifier = read_back("03 010203040506 04e8000001 040a000001");
    assert!(mbs.deviations().is_empty(), "{:?}", mbs.deviations());
    read_back::<MbsSessionIdentifier>("03 010203040506 04e8000001 820102");
    let key: KeyIdAndSharedSecret = read_back("01aa 02bbcc");
    assert_eq!(&key.shared_secret.0[..], [0xbb, 0xcc]);
    assert_eq!(format!("{:?}", key.shared_secret), "SecretLv8(2 octets)");
    read_back::<FailedRuleId>("00 0001");
    let fq_csid: FqCsid = read_back("11 20010db8000000000000000000000001 0007 01 ff");
    assert_eq!(
        (fq_csid.node_type.is_some(), &fq_csid.extra[..]),
        (true, &[0xff][..])
    );
    let fq_csid: FqCsid = read_back("03 0a000001 0001 0002 0003");
    assert_eq!(
        tree::Tree::to_tree(&fq_csid)["Node-Address"],
        tree!("10.0.0.1")
    );
    // A tree of fifteen CSIDs at most, and of an address of the length of its type
    let csids = |count: usize, address: &str| {
        let written = tree!({"FQ-CSID Node-ID Type": 0, "Node-Address": address,
            "PDN Connection Set Identifiers": vec![1u16; count]});
        tree::from_value::<FqCsid>(&written)
    };
    assert!(csids(15, "10.0.0.1").is_ok());
    assert!(csids(16, "10.0.0.1").is_err());
    let short = tree!({"FQ-CSID Node-ID Type": 2, "Node-Address": "0a00",
        "PDN Connection Set Identifiers": [1]});
    assert!(tree::from_value::<FqCsid>(&short).is_err());
    // A user of an NAI, as text; a key of more octets than its length can say
    let user: UserId = read_back("08 0c 75736572406578616d706c65");
    assert_eq!(tree::Tree::to_tree(&user)["NAI"], tree!("user@example"));
    let key = KeyIdAndSharedSecret {
        shared_secret: SecretLv8(vec![1; 256].into()),
        ..key
    };
    assert!(key.encode(&mut Vec::new()).is_err());
    assert!(!key.deviations().is_empty());
}

/// What a field holds at most: 255 values of a counted list (§8.2.156), which its tree
/// reads too; a number of 40 bits (§8.2.8); a value of six bits (§8.2.214); an address of
/// one of four types and of 63 octets (§8.2.207).
#[test]
fn a_field_holds_what_its_bits_hold() {
    let qfis = |count: usize| PmfControlInformation {
        pqpm: true,
        qfis: Some(Counted(vec![SixBits::new(Number(1)); count])),
        ..Default::default()
    };
    assert!(qfis(255).deviations().is_empty());
    let many = DeviationKind::Rule("more values than their number can say");
    let found: Vec<_> = qfis(256).deviations().into_iter().map(|d| d.kind).collect();
    assert_eq!(found, [many]);
    let refused = tree::from_value::<PmfControlInformation>(&tree::Tree::to_tree(&qfis(256)));
    assert!(refused.is_err());
    let most = tree::from_value::<PmfControlInformation>(&tree::Tree::to_tree(&qfis(255)));
    assert_eq!(most.unwrap(), qfis(255));
    assert!(qfis(255).encode(&mut Vec::new()).is_ok());
    assert!(qfis(256).encode(&mut Vec::new()).is_err());
    let mut wide = qfis(1);
    wide.qfis = Some(Counted(vec![SixBits::new(Number(64))]));
    assert!(wide.encode(&mut Vec::new()).is_err());
    read_back::<DscpToPpiMappingInformation>("03 0a 0b");
    let most = (1u64 << 40) - 1;
    let mbr = |ul: u64| tree::from_value::<Mbr>(&tree!({"UL MBR": ul, "DL MBR": 0}));
    assert_eq!(mbr(most).unwrap().ul_mbr, U40(most));
    assert!(mbr(most + 1).is_err());
    // A number of 40 or 24 bits that a value built holds above them is refused, and told
    let wider = DeviationKind::Rule("a value wider than its bits");
    let kinds = |value: &dyn Check| {
        value
            .deviations()
            .into_iter()
            .map(|d| d.kind)
            .collect::<Vec<_>>()
    };
    for (ul, fits) in [(most, true), (most + 1, false)] {
        let mbr = Mbr {
            ul_mbr: U40(ul),
            ..Default::default()
        };
        assert_eq!(mbr.encode(&mut Vec::new()).is_ok(), fits, "{ul}");
        assert_eq!(kinds(&mbr).is_empty(), fits, "{ul}");
    }
    let trace: TraceInformation = read_back("02f839 000001 0101 05 0102 040a000001");
    for (id, fits) in [(0xff_ffff, true), (0x100_0000, false)] {
        let trace = TraceInformation {
            trace_id: U24(id),
            ..trace.clone()
        };
        assert_eq!(trace.encode(&mut Vec::new()).is_ok(), fits, "{id}");
        assert_eq!(kinds(&trace) == [wider.clone()], !fits, "{id}");
    }
    let dscp = DscpToPpiMappingInformation {
        dscp_values: Each(vec![SixBits::new(Number(64))]),
        ..Default::default()
    };
    assert!(dscp.encode(&mut Vec::new()).is_err());
    let address = |address_type: u8, length: usize| TypedAddress {
        address_type,
        address: vec![1; length],
    };
    let ssm = |source: TypedAddress| MbsSessionIdentifier {
        ssmi: true,
        source_specific_ip_multicast_address: Some(SsmAddress {
            distribution: address(0, 4),
            source,
        }),
        ..Default::default()
    };
    let wide = DeviationKind::Rule("an Address Type or an Address longer than their bits can say");
    for (source, fits) in [
        (address(3, 63), true),
        (address(4, 4), false),
        (address(0, 64), false),
    ] {
        let value = ssm(source);
        assert_eq!(value.encode(&mut Vec::new()).is_ok(), fits, "{value:?}");
        let found = value
            .deviations()
            .into_iter()
            .map(|deviation| deviation.kind);
        assert_eq!(
            !found.collect::<Vec<_>>().contains(&wide),
            fits,
            "{value:?}"
        );
    }
}

/// The parts of the values that a caller reads: the Node ID Type of a Node ID of other
/// octets, and the Node ID that its receiver takes (§8.2.38); the text of a text field;
/// whether an IE has a null length; and octets that differ.
#[test]
fn what_a_caller_reads_of_a_value() {
    let other = NodeId::Other(0x22, b"\x03smf".to_vec().into());
    assert_eq!(other.node_id_type(), NodeIdType::Fqdn);
    assert_eq!(
        other.effective(),
        Some(NodeId::Fqdn(b"\x03smf".to_vec().into()))
    );
    assert_eq!(NodeId::Other(0x02, Octets::default()).effective(), None);
    assert_eq!(TextLv8::from("user@example").text(), Some("user@example"));
    assert_eq!(TextLv8(vec![0xff].into()).text(), None);
    assert!(RawIe::new(60, vec![]).is_null());
    assert!(!RawIe::new(60, vec![1]).is_null());
    let vendor = RawIe {
        ie_type: 32769,
        enterprise_id: Some(18553),
        length: None,
        octets: Octets::default(),
    };
    assert!(!vendor.is_null());
    assert_ne!(Octets::from(vec![1]), Octets::from(vec![2]));
    // A Node ID of other octets of an IPv6 address, which needs sixteen
    let address: [u8; 16] = "2001:db8::1"
        .parse::<std::net::Ipv6Addr>()
        .unwrap()
        .octets();
    let v6 = NodeId::Other(0x01, address.to_vec().into());
    assert_eq!(
        v6.effective(),
        Some(NodeId::Ipv6("2001:db8::1".parse().unwrap()))
    );
    assert_eq!(
        NodeId::Other(0x01, address[..15].to_vec().into()).effective(),
        None
    );
    // An address of IPv6 after its type, and a PLMN of its digits
    let typed = TypedAddress::from(std::net::IpAddr::V6("2001:db8::1".parse().unwrap()));
    assert_eq!(
        (typed.address_type, typed.ip()),
        (1, Some("2001:db8::1".parse().unwrap()))
    );
    let plmn: oxirush_utils::identity::Plmn = "208-93".parse().unwrap();
    assert_eq!(PlmnId::from(plmn).plmn(), Some(plmn));
}

/// A value of each of the other kinds of field, read back with its length and its tree:
/// sixteen octets of an NF Instance ID (§8.2.175), an address of each of the four types
/// (§8.2.207), and a spare octet that is not zero, which check() tells (§8.1.2).
#[test]
fn the_other_fields_read_back_as_their_figures_have_them() {
    read_back::<NfInstanceId>("00112233445566778899aabbccddeeff");
    let typed = |address_type: u64| {
        let source = tree!({"Address Type": address_type, "Address": "0102"});
        let written = tree!({"SSMI": true, "Source Specific IP Multicast Address": {
            "IP Multicast Distribution Address": "232.0.0.1", "IP Source Address": source}});
        tree::from_value::<MbsSessionIdentifier>(&written)
    };
    assert!(typed(3).is_ok());
    assert!(typed(4).is_err());
    let filter: SdfFilter = read_back("00 01");
    let found: Vec<_> = filter
        .deviations()
        .into_iter()
        .map(|deviation| deviation.kind)
        .collect();
    assert_eq!(found, [DeviationKind::SpareBits]);
}

/// The Cause of a response, of each table of a response that has one, and none of the
/// others.
#[test]
fn the_cause_of_each_response() {
    let mut with = 0;
    for info in MESSAGE_TYPES {
        let session = !is_node_related(info.message_type);
        let mut written =
            tree!({"message": info.name(), "Sequence Number": 1, "ies": {"Cause": 3}});
        if session {
            written["SEID"] = tree!(1);
        }
        let has = info.table.row_of(19).is_some() && !is_request(info.message_type);
        let Ok(message) = Message::from_tree(&written) else {
            assert!(info.table.row_of(19).is_none(), "{}", info.name());
            continue;
        };
        let partially = Some(CauseValue::RequestPartiallyAccepted);
        assert_eq!(
            message.body.cause(),
            has.then_some(partially).flatten(),
            "{}",
            info.name()
        );
        with += usize::from(has);
    }
    assert_eq!(with, 11);
}

/// A Message Length that runs past the octets says how many follow the first four
/// (§7.6.3), of a message and of its IEs alone.
#[test]
fn a_message_length_past_the_octets_says_how_many_follow() {
    let octets = [0x20, 1, 0, 100, 0, 0, 1, 0, 0, 0x60, 0, 4];
    let available = |error: &Error| matches!(error, Error::MessageLength { available: 8, .. });
    assert!(available(&Message::decode(&octets).unwrap_err()));
    match framing::message_ies(&octets) {
        Err(error) => assert!(available(&error), "{error}"),
        Ok(_) => panic!(),
    }
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

/// Each error of the codec says what it is, apart from the others, with its numbers.
#[test]
fn an_error_of_the_codec_says_what_it_is() {
    let wide = Header {
        version: 9,
        ..Header::node(1)
    };
    let heartbeat = HeartbeatRequest::new(RecoveryTimeStamp::new(7));
    let long =
        HeartbeatRequest::new(RecoveryTimeStamp::new(7)).with_source_ip_address(SourceIpAddress {
            v4: true,
            ..Default::default()
        });
    let mut raw = HeartbeatRequest::new(RecoveryTimeStamp::new(7));
    raw.raw.push(RawIe::new(60, vec![0; 70_000]));
    let errors = [
        Message::decode(&[0x20, 1, 0]).unwrap_err(),
        Message::decode(&[0x20, 1, 0, 100, 0, 0, 1, 0]).unwrap_err(),
        Message::decode(&[0x20, 1, 0, 6, 0, 0, 1, 0, 0, 0x60]).unwrap_err(),
        Message::encode(&Message {
            header: wide,
            body: heartbeat.into(),
        })
        .unwrap_err(),
        Message::node(1, raw).encode().unwrap_err(),
        Message::node(1, long).encode().unwrap_err(),
    ];
    let texts: Vec<String> = errors.iter().map(ToString::to_string).collect();
    let distinct: std::collections::BTreeSet<&str> = texts.iter().map(String::as_str).collect();
    assert_eq!(distinct.len(), texts.len(), "{texts:?}");
    for (text, number) in texts
        .iter()
        .zip(["3", "100", "6", "9", "70000", "IPv4 address"])
    {
        assert!(text.contains(number), "{text}");
    }
    // The fault of the IEs: a header cut short, and a Length past its message
    let fault = |octets: &[u8]| match Message::decode(octets).unwrap_err() {
        Error::Ies { fault, .. } => fault.to_string(),
        other => panic!("{other}"),
    };
    let cut = fault(&[0x20, 1, 0, 6, 0, 0, 1, 0, 0, 0x60]);
    assert!(cut.contains("2 octets") && texts[2].contains(&cut), "{cut}");
    let long = fault(&[0x20, 1, 0, 9, 0, 0, 1, 0, 0, 0x60, 0, 9, 1]);
    assert!(
        long.contains("IE type 96 has the Length 9, and 1 octets"),
        "{long}"
    );
}

/// The framing of an IE: of a vendor, its Enterprise ID apart from its value, which an IE
/// of 3GPP has not (§8.1.1).
#[test]
fn the_framing_of_an_ie_of_a_vendor() {
    let first = |octets: &[u8]| {
        let ie = framing::ies(octets).next().unwrap().unwrap();
        (
            ie.ie_type,
            ie.length,
            ie.enterprise_id,
            ie.value.to_vec(),
            ie.content().to_vec(),
        )
    };
    let vendor = first(&[0x80, 0x01, 0, 3, 0x48, 0x79, 0xaa]);
    assert_eq!(
        vendor,
        (32769, 3, Some(18553), vec![0xaa], vec![0x48, 0x79, 0xaa])
    );
    assert_eq!(first(&[0, 60, 0, 1, 7]), (60, 1, None, vec![7], vec![7]));
}

/// The spare bits of a header that a sender set are written in their places, and read back
/// (§7.2.2.1): bits 4 and 5 of the first octet, and the last octet or its low half.
#[test]
fn the_spare_bits_of_a_header_are_in_their_places() {
    for header in [
        Header {
            spare: 2,
            spare_last: 0x55,
            ..Header::node(1)
        },
        Header {
            spare: 1,
            priority: Some(3),
            spare_last: 0x5,
            ..Header::session(7, 1)
        },
    ] {
        let message = Message {
            header,
            body: HeartbeatRequest::new(RecoveryTimeStamp::new(7)).into(),
        };
        let octets = message.encode().unwrap();
        assert_eq!(octets[0] >> 3 & 3, header.spare);
        assert_eq!(Message::decode(&octets).unwrap().header, header);
    }
}
