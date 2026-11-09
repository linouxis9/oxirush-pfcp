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

//! The paths of a tree: what `select` takes and selects, what `set` edits, and the paths of
//! the errors of `from_tree` and of the deviations of `check()`.

use super::*;

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
    // A Node ID that is an address has no FQDN and no Node ID Type or value, one that is
    // an FQDN no Node ID Type or value, and their trees no octets, which an IE kept as
    // octets has
    nothing(&response, "/pfcp/Node ID/FQDN");
    nothing(&response, "/pfcp/Node ID/Node ID value");
    nothing(&response, "/pfcp/Node ID/Node ID Type");
    misspelt(&response, "/pfcp/Node ID/octets");
    let name = b"\x03upf\x07example".to_vec();
    let setup = Message::node(
        1,
        AssociationSetupRequest::new(NodeId::Fqdn(name.into()), RecoveryTimeStamp::new(7)),
    );
    let setup = setup.to_tree();
    let fqdn = select(&setup, "/pfcp/Node ID/FQDN").unwrap();
    assert_eq!(fqdn, [&tree!("upf.example")]);
    nothing(&setup, "/pfcp/Node ID/Node ID value");
    nothing(&setup, "/pfcp/Node ID/Node ID Type");
    misspelt(&setup, "/pfcp/Node ID/octets");
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
            "/pfcp/Node ID/octets",
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
            "/pfcp/Cause",
            "\"Cause\" is an IE of no row of PFCP Heartbeat Request, which is written by its octets",
        ),
        (
            heartbeat(tree!({"Recovery Time Stamp": 7, "77": 5})),
            "/pfcp/77",
            "\"77\" is an IE of no row of PFCP Heartbeat Request, which is written by its octets",
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
            modification(
                tree!({"Cause": 1, "Created/Updated Traffic Endpoint": [{"Traffic Endpoint ID": 1}, {"traffic endpoint id": "x"}]}),
            ),
            "/pfcp/Created~1Updated Traffic Endpoint/1/traffic endpoint id",
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
pub(super) fn members_hold(message: &tree::Value) -> usize {
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
    for line in include_str!("../captures/messages.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let octets = hex::decode(line.split('\t').nth(5).unwrap()).unwrap();
        values += members_hold(&Message::decode(&octets).unwrap().to_tree());
    }
    assert!(values > 1500, "{values} values");
}

/// An IE type whose content differs by place, as Session Report (Tables 7.5.7.3-1 and
/// 7.5.8.6-1), has the rows of its place: in a Session Deletion Response, an Access
/// Availability Report, of the other table, is an IE of no row there, by the name of its
/// type, which is written by its octets, and `set` writes no row of it; in a Session
/// Report Request, it is a row.
#[test]
fn a_grouped_ie_has_the_rows_of_its_place() {
    let information =
        "/pfcp/Session Report/0/Access Availability Report/Access Availability Information";
    let value = || tree!([{"Access Type": "3GPP access type"}]);
    let mut deletion = tree!({"message": "PFCP Session Deletion Response", "SEID": 1, "Sequence Number": 1,
        "ies": {"Cause": "Request accepted (success)", "Session Report": [{"SRR ID": 1}]}});
    let availability = "/pfcp/Session Report/0/Access Availability Report";
    assert!(select(&deletion, availability).unwrap().is_empty());
    assert!(set(&mut deletion, information, value()).is_err());
    set(&mut deletion, availability, tree!({"octets": "0001"})).unwrap();
    Message::from_tree(&deletion).unwrap();
    let mut request = tree!({"message": "PFCP Session Report Request", "SEID": 1, "Sequence Number": 1,
        "ies": {"Report Type": {"SESR": true}, "Session Report": [{"SRR ID": 1}]}});
    set(&mut request, information, value()).unwrap();
    Message::from_tree(&request).unwrap();
}

/// `paths::row_at` names the row of a table and the IE type of the IE at a path, or of the
/// list of them, there or not, below grouped IEs that the message lacks too: none for the
/// header, a member of a value, or an IE of no row.
#[test]
fn a_path_is_at_the_row_of_its_ie() {
    let tree = establishment().to_tree();
    let at = |path: &str| {
        let found = oxirush_pfcp::paths::row_at(&tree, path).unwrap();
        found.map(|(row, info)| (row.name, info.ie_type))
    };
    assert_eq!(at("/pfcp/Node ID"), Some(("Node ID", 60)));
    assert_eq!(at("/pfcp/Create PDR"), Some(("Create PDR", 1)));
    assert_eq!(at("/pfcp/Create PDR/1"), Some(("Create PDR", 1)));
    assert_eq!(
        at("/pfcp/Create PDR/0/PDI/Local F-TEID"),
        Some(("Local F-TEID", 21))
    );
    assert_eq!(at("/pfcp/Create QER"), Some(("Create QER", 7)));
    assert_eq!(at("/pfcp/Create PDR/0/PDR ID/Rule ID"), None);
    assert_eq!(at("/SEID"), None);
    assert_eq!(at("/pfcp/Load Control Information/Sequence Number"), None);
    assert_eq!(at("/pfcp/Create PDR/7/PDI"), Some(("PDI", 2)));
    assert_eq!(at("/pfcp/Create PDR/*/PDI"), Some(("PDI", 2)));
    assert_eq!(at("/pfcp/Create BAR/BAR ID"), Some(("BAR ID", 88)));
    assert_eq!(
        at("/pfcp/Create PDR/0/PDI/Ethernet Packet Filter/0/MAC address"),
        Some(("MAC address", 133))
    );
    assert_eq!(at("/ies/Create PDR/0/PDI"), Some(("PDI", 2)));
    assert_eq!(at("/pfcp/Create PDR/0/1"), None);
    assert_eq!(at("/pfcp/Create PDR/0/PDI/Local F-TEID/TEID"), None);
    // A grouped IE of two contents, by the table of its place
    let report = tree!({"message": "PFCP Session Report Request", "SEID": 1, "Sequence Number": 1,
        "ies": {"Report Type": {"USAR": true}}});
    let found = oxirush_pfcp::paths::row_at(&report, "/pfcp/Usage Report/0/Start Time").unwrap();
    assert_eq!(
        found.map(|(row, info)| (row.name, info.ie_type)),
        Some(("Start Time", 75))
    );
    assert!(oxirush_pfcp::paths::row_at(&tree, "/pfcp/Bogus").is_err());
}

/// A row whose name is also that of another IE type, as the Packet Rate Status Report of
/// a Session Modification Response, of type 264 where type 252 has the name (Table
/// 8.1.2-1), is the row in a path; the IE of type 252, of no row there, goes by its
/// number.
#[test]
fn a_row_of_the_name_of_another_ie_type_is_the_row() {
    let tree = tree!({"message": "PFCP Session Modification Response", "SEID": 1, "Sequence Number": 1,
        "ies": {"Cause": 1, "Packet Rate Status Report": [{"QER ID": 1, "Packet Rate Status": {}}], "252": {"octets": "01"}}});
    let reports = select(&tree, "/pfcp/Packet Rate Status Report/0/QER ID").unwrap();
    assert_eq!(reports, [&tree!(1)]);
    assert_eq!(
        select(&tree, "/pfcp/252").unwrap(),
        [&tree!({"octets": "01"})]
    );
}
