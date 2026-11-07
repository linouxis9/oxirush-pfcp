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
    let heartbeat = Message {
        header: Header::node(1),
        body: HeartbeatRequest::new(RecoveryTimeStamp::new(7)).into(),
    };
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
    // A Node ID that is an address has no FQDN, one that is an FQDN no octets, and their
    // trees no Node ID Type
    nothing(&response, "/pfcp/Node ID/FQDN");
    nothing(&response, "/pfcp/Node ID/Node ID value");
    failing(
        &response,
        "/pfcp/Node ID/Node ID Type",
        tree::ErrorKind::Scalar,
    );
    let name = b"\x03upf\x07example".to_vec();
    let setup = Message {
        header: Header::node(1),
        body: AssociationSetupRequest::new(NodeId::Fqdn(name.into()), RecoveryTimeStamp::new(7))
            .into(),
    };
    let setup = setup.to_tree();
    let fqdn = select(&setup, "/pfcp/Node ID/FQDN").unwrap();
    assert_eq!(fqdn, [&tree!("upf.example")]);
    nothing(&setup, "/pfcp/Node ID/Node ID value");
    misspelt(&setup, "/pfcp/Node ID/Node ID Type");
    // The header
    nothing(&response, "/Message Priority");
    nothing(&response, "/FO");
    let heartbeat = Message {
        header: Header::node(1),
        body: HeartbeatRequest::new(RecoveryTimeStamp::new(7)).into(),
    };
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
    failing(
        &establishment,
        "/pfcp/Create PDR/0/PDR ID/Bogus",
        tree::ErrorKind::Scalar,
    );
    // An edit takes the plain rule: into a scalar, it goes nowhere
    let mut edited = establishment.clone();
    assert!(set(&mut edited, "/pfcp/Create PDR/0/PDR ID/Rule ID", 5).is_err());
    assert_eq!(edited, establishment);
}

/// oxirush-utils' `select_in`: "a misspelt name is not a member that is absent", also
/// below what a message lacks. Below a row that it lacks, a name is judged as where the row
/// is there: a member that it could have selects nothing, and another is `NoSuchMember`;
/// below a list that it lacks, an entry has the members of one, and a name that is no
/// position is `NotAList`.
#[test]
fn a_misspelt_name_below_what_a_message_lacks_is_an_error() {
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
    let response = "2133002b000000000000100100000700003c0005000a00000200130001010039000d0200000000000020010a000002";
    let response = Message::decode(&hex::decode(response).unwrap())
        .unwrap()
        .to_tree();
    let heartbeat = Message {
        header: Header::node(1),
        body: HeartbeatRequest::new(RecoveryTimeStamp::new(7)).into(),
    };
    let heartbeat = heartbeat.to_tree();
    misspelt(&heartbeat, "/pfcp/Source IP Address/Bogus");
    nothing(&heartbeat, "/pfcp/Source IP Address/V4");
    // Below a flag, which has nothing below it
    failing(
        &heartbeat,
        "/pfcp/Source IP Address/V4/Bogus",
        tree::ErrorKind::Scalar,
    );
    misspelt(&response, "/pfcp/Load Control Information/Bogus");
    nothing(&response, "/pfcp/Load Control Information/Load Metric");
    nothing(&response, "/pfcp/Load Control Information/*");
    misspelt(&response, "/pfcp/Created PDR/0/Bogus");
    misspelt(&response, "/pfcp/Created PDR/*/Bogus");
    nothing(&response, "/pfcp/Created PDR/*/PDR ID");
    failing(
        &response,
        "/pfcp/Created PDR/Bogus",
        tree::ErrorKind::NotAList,
    );
    nothing(&response, "/pfcp/Created PDR/*/F-TEID/0/CHID");
    misspelt(&response, "/pfcp/Created PDR/0/F-TEID/1/Bogus");
    // A role that the wire does not tell from the others of its row is no member
    misspelt(&response, "/pfcp/Created PDR/0/Local F-TEID/CHID");
    // An edit takes the plain rule: it adds no member below what is not there
    let mut edited = heartbeat.clone();
    assert!(set(&mut edited, "/pfcp/Source IP Address/V4", true).is_err());
    assert_eq!(edited, heartbeat);
}

/// oxirush-utils' `select_in`: "a misspelt name is not a member that is absent", also
/// below a flag or a field that a value or the header lacks, and below an entry past the
/// end of a list. Below such a field, a name is judged by what the tree of the field may
/// hold (`tree::Below`): nothing below a scalar, the members of a value with spare bits
/// or of an address, the entries of a list.
#[test]
fn a_misspelt_name_below_a_field_that_a_value_lacks_is_an_error() {
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
    let response = "2133002b000000000000100100000700003c0005000a00000200130001010039000d0200000000000020010a000002";
    let mut response = Message::decode(&hex::decode(response).unwrap()).unwrap();
    let Body::SessionEstablishmentResponse(body) = &mut response.body else {
        panic!()
    };
    body.created_pdr.push(CreatedPdr::new(PdrId::new(1)));
    let response = response.to_tree();
    // Below a field or a flag that a value lacks, of a scalar
    for path in [
        "/pfcp/UP F-SEID/IPv6 address/Bogus",
        "/pfcp/UP F-SEID/V6/Bogus",
        "/pfcp/UP F-SEID/IPv6 address/*",
        "/pfcp/Node ID/FQDN/Bogus",
        "/Message Priority/Bogus",
    ] {
        failing(&response, path, tree::ErrorKind::Scalar);
    }
    // Below an entry past the end of a list, as below an entry
    nothing(&response, "/pfcp/Created PDR/5/PDR ID");
    failing(
        &response,
        "/pfcp/Created PDR/5/Bogus",
        tree::ErrorKind::NoSuchMember,
    );
    // Below a field of a value with spare bits, of an address of another type, and of a
    // list, that a value lacks
    let rate = PacketRate {
        ulpr: true,
        uplink_time_unit: Some(Narrow::new(TimeUnit::Minute)),
        maximum_uplink_packet_rate: Some(10),
        ..Default::default()
    };
    let qer = CreateQer::new(QerId::new(1), GateStatus::default()).with_packet_rate(rate);
    let atsss = ProvideAtsssControlInformation {
        pmf_control_information: Some(PmfControlInformation {
            pmfi: true,
            ..Default::default()
        }),
        ..Default::default()
    };
    let mbs = MbsSessionN4ControlInformation::new(MbsSessionIdentifier {
        tmgi: true,
        tmgi_field: Some([1, 2, 3, 4, 5, 6]),
        ..Default::default()
    });
    let Body::SessionEstablishmentRequest(request) = establishment().body else {
        panic!()
    };
    let request = Message {
        header: Header::session(0, 1),
        body: request
            .with_create_qer(qer)
            .with_provide_atsss_control_information(atsss)
            .with_mbs_session_n4_control_information(mbs)
            .into(),
    }
    .to_tree();
    let rate = "/pfcp/Create QER/0/Packet Rate/Downlink Time Unit";
    nothing(&request, &format!("{rate}/Spare"));
    nothing(&request, &format!("{rate}/value"));
    failing(
        &request,
        &format!("{rate}/Bogus"),
        tree::ErrorKind::NoSuchMember,
    );
    failing(
        &request,
        &format!("{rate}/value/Bogus"),
        tree::ErrorKind::Scalar,
    );
    let qfis = "/pfcp/Provide ATSSS Control Information/PMF Control Information/value of QFI";
    nothing(&request, &format!("{qfis}/0"));
    nothing(&request, &format!("{qfis}/*"));
    failing(
        &request,
        &format!("{qfis}/Bogus"),
        tree::ErrorKind::NotAList,
    );
    failing(
        &request,
        &format!("{qfis}/0/Bogus"),
        tree::ErrorKind::Scalar,
    );
    let ssm = "/pfcp/MBS Session N4 Control Information/0/MBS Session Identifier/Source Specific IP Multicast Address";
    nothing(&request, &format!("{ssm}/IP Source Address/Address Type"));
    failing(
        &request,
        &format!("{ssm}/IP Source Address/Bogus"),
        tree::ErrorKind::NoSuchMember,
    );
    failing(
        &request,
        &format!("{ssm}/Bogus"),
        tree::ErrorKind::NoSuchMember,
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

/// A field whose tree is a scalar or an object, as its value is, has one rule for each
/// form and for its absence: a value without or with spare bits, an IPv4 or IPv6 address
/// or another, an identity of digits or text or of other octets. The member that the
/// scalar is selects it, as the object's; another member of the object selects nothing at
/// the scalar and where the field is absent; another name is no member, whatever the form.
#[test]
fn a_field_of_either_form_has_one_rule() {
    let found = |tree: &tree::Value, path: &str| {
        select(tree, path)
            .map(|values| values.into_iter().cloned().collect::<Vec<_>>())
            .map_err(|error| error.kind())
    };
    let none = Ok(Vec::<tree::Value>::new());
    let misspelt = Err(tree::ErrorKind::NoSuchMember);
    let request = |change: &dyn Fn(&mut SessionEstablishmentRequest)| {
        let Body::SessionEstablishmentRequest(mut request) = establishment().body else {
            panic!()
        };
        change(&mut request);
        Message {
            header: Header::session(0, 1),
            body: Body::SessionEstablishmentRequest(request),
        }
        .to_tree()
    };
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
    let tree = request(&|request| {
        let qer = CreateQer::new(QerId::new(1), GateStatus::default());
        request
            .create_qer
            .push(qer.with_packet_rate(rate(Some(spared))));
        let qer = CreateQer::new(QerId::new(2), GateStatus::default());
        request.create_qer.push(qer.with_packet_rate(rate(None)));
    });
    let minute = tree!("minute");
    for (unit, value, spare) in [
        (
            "0/Packet Rate/Uplink Time Unit",
            Ok(vec![minute.clone()]),
            none.clone(),
        ),
        (
            "0/Packet Rate/Downlink Time Unit",
            Ok(vec![minute.clone()]),
            Ok(vec![tree!(64)]),
        ),
        (
            "1/Packet Rate/Downlink Time Unit",
            none.clone(),
            none.clone(),
        ),
    ] {
        let unit = format!("/pfcp/Create QER/{unit}");
        assert_eq!(found(&tree, &format!("{unit}/value")), value, "{unit}");
        assert_eq!(found(&tree, &format!("{unit}/Spare")), spare, "{unit}");
        assert_eq!(found(&tree, &format!("{unit}/Bogus")), misspelt, "{unit}");
        let below = found(&tree, &format!("{unit}/value/Bogus"));
        assert_eq!(below, Err(tree::ErrorKind::Scalar), "{unit}");
    }
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
    let tree = request(&|request| {
        *request = request
            .clone()
            .with_mbs_session_n4_control_information(mbs(Some(ssm.clone())))
    });
    let without = request(&|request| {
        *request = request
            .clone()
            .with_mbs_session_n4_control_information(mbs(None))
    });
    let ssm = "/pfcp/MBS Session N4 Control Information/0/MBS Session Identifier/Source Specific IP Multicast Address";
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
        assert_eq!(
            found(tree, &format!("{address}/Bogus")),
            misspelt,
            "{address}"
        );
    }
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
            Some(DigitsLv8(vec![0x02, 0xf8, 0x39])),
            Ok(vec![tree!({"octets": "02f839"})["octets"].clone()]),
        ),
        (None, none.clone()),
    ] {
        let tree = request(&|request| request.user_id = Some(user(imsi.clone())));
        let imsi = "/pfcp/User ID/IMSI";
        assert_eq!(found(&tree, &format!("{imsi}/octets")), octets, "{imsi:?}");
        assert_eq!(found(&tree, &format!("{imsi}/Bogus")), misspelt, "{imsi:?}");
        assert_eq!(found(&tree, "/pfcp/User ID/NAI/octets"), none);
        assert_eq!(found(&tree, "/pfcp/User ID/NAI/Bogus"), misspelt);
    }
}

/// What the paths know of a place prints the names of the message, of the tables and of
/// the IE types, not their rows.
#[test]
fn a_shape_prints_its_names() {
    use tree::Family;
    let heartbeat = Message {
        header: Header::node(1),
        body: HeartbeatRequest::new(RecoveryTimeStamp::new(7)).into(),
    };
    let heartbeat = heartbeat.to_tree();
    let paths = oxirush_pfcp::tree::Paths;
    let message = paths.start(&heartbeat, true);
    assert_eq!(
        format!("{message:?}"),
        r#"Shape(Message("PFCP Heartbeat Request"))"#
    );
    let ies = paths.member(&message, "ies", Some(&heartbeat["ies"]));
    assert_eq!(format!("{ies:?}"), r#"Shape(Ies(["7.4.2.1-1"]))"#);
    // The header is no table of IEs: its fields are scalars
    let sequence = paths.member(&message, "Sequence Number", Some(&tree!(1)));
    assert_eq!(format!("{sequence:?}"), "Shape(Below(Scalar))");
    let stamp = &heartbeat["ies"]["Recovery Time Stamp"];
    let value = paths.member(&ies, "Recovery Time Stamp", Some(stamp));
    assert_eq!(
        format!("{value:?}"),
        r#"Shape(Value("Recovery Time Stamp"))"#
    );
    let addresses = paths.member(&ies, "Source IP Address", Some(&tree!([])));
    assert_eq!(
        format!("{addresses:?}"),
        r#"Shape(List("Source IP Address"))"#
    );
    let nothing = paths.member(&value, "Bogus", None);
    assert_eq!(format!("{nothing:?}"), "Shape(Nothing)");
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
                let scalar_field = !entry.is_object() && info.fields == [*member];
                let wanted = if scalar_field { vec![entry] } else { vec![] };
                let selected = select(message, &path).map_err(|error| error.kind());
                assert_eq!(selected, Ok(wanted), "{path}");
            }
            // What the tree of each field that the value has holds below it is what the
            // paths judge a field that a value lacks by (`tree::Below`): the entries of a
            // list, the members of an object
            for (name, field) in entry.as_object().into_iter().flatten() {
                let path = format!("{at}/{}", tree::escape(name));
                let place = tree::places_in(&oxirush_pfcp::tree::Paths, message, &path).unwrap();
                let below = format!("{:?}", place[0].shape());
                match field {
                    tree::Value::Array(_) => {
                        assert!(below.starts_with("Shape(Below(List("), "{path}: {below}");
                    }
                    tree::Value::Object(members) => {
                        for member in members.keys() {
                            let named = format!("({member:?}, ");
                            assert!(below.contains(&named), "{path}: {member} in {below}");
                        }
                    }
                    _ => {}
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
                        found.push(format!("{}\t{}\t{deviation}", fields[0], fields[1]));
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
    // What tests/README.md says of them
    let said = include_str!("README.md")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for count in [
        format!(
            "the {} vectors of go-pfcp's message tests",
            vectors.lines().count()
        ),
        format!("{reordered} of them have their IEs in another order"),
    ] {
        assert!(
            said.contains(&count),
            "tests/README.md does not say: {count}"
        );
    }
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
    assert_eq!(fq_csid.node_address, [0x0c, 0x80, 0x10, 0x01]);
    assert_eq!(fq_csid.csids, [7, 9]);
    assert_eq!(
        fq_csid.node_type.map(|node_type| node_type.value),
        Some(NodeType::PgwCSmf)
    );
    assert_eq!(again(&fq_csid), octets);
    let ipv6 = FqCsid {
        node_id_type: 1,
        node_address: vec![0; 16],
        csids: vec![1],
        ..Default::default()
    };
    assert_eq!(again(&ipv6), [&[0x11][..], &[0; 16], &[0, 1]].concat());
    // A reserved Node-ID Type is written with the Node-Address that the value has, which
    // a receiver cannot frame; one of more than four bits is not
    let mut out = Vec::new();
    let reserved = FqCsid {
        node_id_type: 3,
        node_address: vec![10, 0, 0, 1, 2],
        csids: vec![1],
        ..Default::default()
    };
    reserved.encode(&mut out).unwrap();
    assert_eq!(out, [0x31, 10, 0, 0, 1, 2, 0, 1]);
    assert_eq!(FqCsid::decode(&out), None);
    let wide = FqCsid {
        node_id_type: 16,
        ..reserved
    };
    assert!(matches!(
        wide.encode(&mut Vec::new()),
        Err(Error::FieldLength { .. })
    ));
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
        detected.c_tag.as_ref().map(|tag| tag.0.clone()),
        Some(vec![0x07, 0x00, 0x64])
    );
    assert_eq!(
        detected.s_tag.as_ref().map(|tag| tag.0.clone()),
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
    let request = |fqdn: Fqdn| Message {
        header: Header::node(1),
        body: AssociationSetupRequest::new(
            NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
            RecoveryTimeStamp::new(1),
        )
        .with_smf_set_id(SmfSetId {
            fqdn,
            ..Default::default()
        })
        .into(),
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

/// A message longer than its Message Length can say is refused as a message, of its
/// type and length.
#[test]
fn a_message_too_long_for_its_length() {
    let mut request = HeartbeatRequest::new(RecoveryTimeStamp::new(1));
    for _ in 0..2 {
        request.raw.push(RawIe::new(1000, vec![0; 40_000]));
    }
    let message = Message {
        header: Header::node(1),
        body: request.into(),
    };
    assert_eq!(
        message.encode(),
        Err(Error::MessageTooLong {
            message_type: 1,
            length: 4 + 8 + 2 * 40_004,
        })
    );
}

/// The octets after the fields of an IE, of a later release, are "the unknown octets" of
/// §8.1.2 in a tree.
#[test]
fn the_unknown_octets_of_an_ie() {
    let mut precedence = Precedence::new(1);
    precedence.extra = Octets::copied(&[0xaa]);
    let tree = tree::Tree::to_tree(&precedence);
    assert_eq!(
        tree.to_string(),
        r#"{"Precedence value":1,"unknown octets":"aa"}"#
    );
    assert_eq!(tree::from_value::<Precedence>(&tree).unwrap(), precedence);
}

/// A list is equal to another of the same values, however it holds them: a message
/// read back from its tree is equal to the one decoded.
#[test]
fn a_list_equals_by_its_values() {
    let mut reserved: List<u16> = List::new();
    reserved.reserve_exact(2);
    reserved.push(7);
    assert_eq!(reserved, List::from(vec![7]));
    assert_eq!(
        format!("{reserved:?}"),
        format!("{:?}", List::from(vec![7]))
    );
    // An FQ-CSID of IPv6 whose content frames as IEs, and one that does not decode
    let mut address = [0; 16];
    address[2] = 15;
    let fq_csid = FqCsid {
        node_id_type: 1,
        node_address: address.to_vec(),
        csids: vec![1],
        ..Default::default()
    };
    let request = SessionSetDeletionRequest::new(NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 1)))
        .with_fq_csid(fq_csid);
    let mut octets = Message {
        header: Header::node(1),
        body: request.into(),
    }
    .encode()
    .unwrap();
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

/// A Number of six bits is, as a field of its own, its whole octet, which a Narrow parts
/// into the number and the spare bits.
#[test]
fn a_number_of_six_bits_as_a_field() {
    let mut octets: &[u8] = &[0x2e, 0xc1];
    assert_eq!(Number::<6>::read(&mut octets), Some(Number(0x2e)));
    assert_eq!(octets, [0xc1]);
    assert_eq!(Number::<6>::read(&mut &[][..]), None);
    let mut out = Vec::new();
    Number::<6>(0xc1).write(&mut out);
    assert_eq!(out, [0xc1]);
    assert_eq!(Number::<6>(0x2e).size(), 1);
    assert_eq!(Field::to_tree(&Number::<6>(46)), tree!(46));
}

/// Values that the crate once misread: each as its clause has it.
#[test]
fn values_as_their_clauses_have_them() {
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
