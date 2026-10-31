//! What the spike proves: the codec of a typed message from its table is lossless, its
//! tree reads back, its paths go through the engine of oxirush-utils, and `check()` names
//! the clause of each deviation.

use std::net::Ipv4Addr;

use oxirush_pfcp::tree::{select, set};
use oxirush_pfcp::*;
use oxirush_utils::tree;

/// A Session Establishment Request of an SMF: one uplink PDR whose F-TEID the UPF
/// chooses, one downlink PDR to the UE's address.
fn establishment() -> Message<'static> {
    let uplink = CreatePdr::new(
        PdrId::new(1),
        Precedence::new(255),
        Pdi::new(SourceInterface::new(InterfaceValue::Access)).with_local_f_teid(FTeid::choose_ipv4()),
    )
    .with_far_id(FarId::new(1))
    .with_urr_id(UrrId::new(1));
    let ue = UeIpAddress { v4: true, sd: true, ipv4: Some(Ipv4Addr::new(10, 45, 0, 2)), ..Default::default() };
    let downlink = CreatePdr::new(
        PdrId::new(2),
        Precedence::new(255),
        Pdi::new(SourceInterface::new(InterfaceValue::Core)).with_ue_ip_address(ue),
    )
    .with_far_id(FarId::new(2));
    let smf = Ipv4Addr::new(10, 0, 0, 1);
    let seid = FSeid { v4: true, seid: Some(0x1001), ipv4: Some(smf), ..Default::default() };
    let request = SessionEstablishmentRequest::new(
        NodeId::Ipv4(smf),
        seid,
        uplink,
        CreateFar::new(FarId::new(1), ApplyAction { forw: true, ..Default::default() }),
    )
    .with_create_pdr(downlink);
    Message { header: Header::session(0, 7), body: Body::SessionEstablishmentRequest(request) }
}

#[test]
fn a_built_message_is_in_the_order_of_its_table_and_decodes_back() {
    let message = establishment();
    let octets = message.encode().unwrap();
    let decoded = Message::decode(&octets).unwrap();
    assert_eq!(decoded, message);
    assert_eq!(decoded.encode().unwrap(), octets);
    let Body::SessionEstablishmentRequest(request) = &decoded.body else { panic!() };
    assert!(request.order.is_empty(), "a built message is in the order of its table");
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
    set(&mut tree, "/pfcp/Create PDR/1/PDI/UE IP address/0/IPv4 address", "10.45.0.3").unwrap();
    let edited = Message::from_tree(&tree).unwrap();
    let Body::SessionEstablishmentRequest(request) = &edited.body else { panic!() };
    let address = request.create_pdr[1].pdi.as_ref().unwrap().ue_ip_address[0].ipv4;
    assert_eq!(address, Some(Ipv4Addr::new(10, 45, 0, 3)));

    // A misspelt name is refused, and says the nearest
    let mut wrong = message.to_tree();
    wrong["ies"]["Create PDR"][0]["PDI"].as_object_mut().unwrap().insert("Local F-TEIDD".into(), tree!({}));
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
    assert_eq!(decoded.encode().unwrap(), octets, "decode then encode gives the octets back");
    let Body::SessionEstablishmentRequest(request) = &decoded.body else { panic!() };
    assert_eq!(request.raw.len(), 4);
    assert_eq!(request.node_id, Some(NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 9))));

    let tree = decoded.to_tree();
    println!("{tree}");
    // The tree has the IEs of a name together, where they first come: the second Node
    // ID comes before the Recovery Time Stamp that was between them. The message means
    // the same, and its tree is the same.
    let read = Message::from_tree(&tree).unwrap();
    let encoded = read.encode().unwrap();
    let again = Message::decode(&encoded).unwrap();
    assert_eq!(again.to_tree(), tree);
    assert_eq!(read.encode().unwrap().len(), octets.len());

    let found = decoded.check();
    for deviation in &found {
        println!("{deviation}");
    }
    let clauses: Vec<&str> = found.iter().map(|deviation| deviation.clause).collect();
    assert!(clauses.contains(&"7.6.10"), "the second Node ID is a repetition");
    assert!(clauses.contains(&"8.1.2"), "IE type 32767 is in no release");
}

#[test]
fn check_names_the_clause() {
    let mut message = establishment();
    let Body::SessionEstablishmentRequest(request) = &mut message.body else { panic!() };
    request.node_id = None;
    let f_teid = request.create_pdr[0].pdi.as_mut().unwrap().local_f_teid.as_mut().unwrap();
    f_teid.chid = true;
    f_teid.choose_id = Some(1);
    f_teid.ch = false;
    f_teid.teid = Some(5);
    message.header.seid = None;
    let found = message.check();
    for deviation in &found {
        println!("{deviation}");
    }
    let said: Vec<String> = found.iter().map(ToString::to_string).collect();
    assert!(said.iter().any(|said| said.contains("Node ID is missing") && said.contains("7.5.2.1-1")));
    assert!(said.iter().any(|said| said.contains("CHID is set and CH is not (TS 29.244 8.2.3), at /pfcp/Create PDR/0/PDI/Local F-TEID")));
    assert!(said.iter().any(|said| said.contains("no SEID")));
    assert_eq!(found[1].cause(), Some(66), "{}", found[1]);
}

#[test]
fn a_false_length_is_written_and_does_not_decode() {
    let mut message = establishment();
    let Body::SessionEstablishmentRequest(request) = &mut message.body else { panic!() };
    request.raw.push(RawIe { length: Some(40), ..RawIe::new(96, vec![0xdf, 0xd5, 0x2c, 0x00]) });
    let octets = message.encode().unwrap();
    match Message::decode(&octets) {
        Err(Error::Ies { header, fault, .. }) => {
            assert_eq!(header.sequence, 7);
            assert_eq!(fault, IeFault::Length { ie_type: 96, length: 40, available: 4 });
        }
        other => panic!("{other:?}"),
    }
    message.header.length = Some(9);
    let octets = message.encode().unwrap();
    assert!(matches!(Message::decode(&octets), Err(Error::MessageLength { length: 9, .. })));
}

#[test]
fn a_flag_that_disagrees_is_refused_where_it_is_written() {
    let message = establishment();
    let mut tree = message.to_tree();
    set(&mut tree, "/pfcp/Create PDR/0/PDI/Local F-TEID/IPv4 address", "10.0.0.5").unwrap();
    let error = Message::from_tree(&tree).unwrap_err().to_string();
    println!("{error}");
    assert!(error.contains("IPv4 address is written where its flags do not have it"), "{error}");
}

/// The vectors of another implementation, when `PFCP_VECTORS` names their file: each
/// decodes and encodes back to its octets, and so does its tree.
#[test]
fn other_vectors_round_trip() {
    let Ok(file) = std::env::var("PFCP_VECTORS") else { return };
    let mut read = 0;
    for line in std::fs::read_to_string(file).unwrap().lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let octets = hex::decode(fields[2]).unwrap();
        let messages = match Message::decode_datagram(&octets) {
            Ok(messages) => messages,
            Err(error) => {
                println!("{} {}: {error}", fields[0], fields[1]);
                continue;
            }
        };
        let mut again = Vec::new();
        for message in &messages {
            again.extend(message.encode().unwrap());
            let tree = message.to_tree();
            let back = Message::from_tree(&tree).unwrap();
            assert_eq!(back.encode().unwrap(), message.encode().unwrap(), "{} {}", fields[0], fields[1]);
            if !matches!(message.body, Body::Other { .. }) {
                read += 1;
                println!("{} {}: {tree}", fields[0], fields[1]);
                for deviation in message.check() {
                    println!("  {deviation}");
                }
            }
        }
        assert_eq!(again, octets, "{} {}", fields[0], fields[1]);
    }
    println!("{read} messages read by their tables");
}

/// The IE types of a scope, depth first, by the forms of the registry: what a dissector
/// lists in the order of the wire.
fn ie_types(mut octets: &[u8], out: &mut Vec<u16>) {
    while octets.len() >= 4 {
        let ie_type = u16::from_be_bytes([octets[0], octets[1]]);
        let length = usize::from(u16::from_be_bytes([octets[2], octets[3]]));
        let Some(body) = octets.get(4..4 + length) else { return };
        out.push(ie_type);
        if ie_type_info(ie_type).is_some_and(|info| info.form == Form::Grouped) {
            ie_types(body, out);
        }
        octets = &octets[4 + length..];
    }
}

/// For a comparison with a dissector, when `PFCP_DUMP` names a file: each message of
/// `PFCP_VECTORS` and of this spike, its IE types depth first, and values by their paths.
#[test]
fn dump_for_a_dissector() {
    let (Ok(file), Ok(dump)) = (std::env::var("PFCP_VECTORS"), std::env::var("PFCP_DUMP")) else { return };
    let mut messages: Vec<(String, Vec<u8>)> = std::fs::read_to_string(file)
        .unwrap()
        .lines()
        .map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            (format!("{} {}", fields[0], fields[1]), hex::decode(fields[2]).unwrap())
        })
        .collect();
    messages.push(("spike establishment".into(), establishment().encode().unwrap()));
    let paths = [
        ("pfcp.f_teid.teid", "/pfcp/Create PDR/*/PDI/Local F-TEID/TEID"),
        ("pfcp.f_teid.ipv4_addr", "/pfcp/Create PDR/*/PDI/Local F-TEID/IPv4 address"),
        ("pfcp.pdr_id", "/pfcp/Create PDR/*/PDR ID"),
        ("pfcp.precedence", "/pfcp/Create PDR/*/Precedence"),
        ("pfcp.source_interface", "/pfcp/Create PDR/*/PDI/Source Interface"),
        ("pfcp.ue_ip_addr_ipv4", "/pfcp/Create PDR/*/PDI/UE IP address/*/IPv4 address"),
        ("pfcp.f_seid.ipv4", "/pfcp/CP F-SEID/IPv4 address"),
        ("pfcp.node_id_fqdn", "/pfcp/Node ID/FQDN"),
        ("pfcp.seid", "/SEID"),
    ];
    let mut lines = Vec::new();
    for (name, octets) in messages {
        let Ok(message) = Message::decode(&octets) else { continue };
        if !matches!(message.body, Body::SessionEstablishmentRequest(_)) {
            continue;
        }
        let mut types = Vec::new();
        ie_types(&octets[message.header.len()..], &mut types);
        let tree = message.to_tree();
        let mut values = tree::Map::new();
        for (field, path) in paths {
            let found: Vec<tree::Value> = select(&tree, path).unwrap_or_default().into_iter().cloned().collect();
            values.insert(field.into(), tree::Value::Array(found));
        }
        let line = tree!({"name": name, "hex": hex::encode(&octets), "types": types, "values": tree::Value::Object(values)});
        lines.push(line.to_string());
    }
    std::fs::write(dump, lines.join("\n") + "\n").unwrap();
}

/// Rough times of the codec and the tree, in an optimized build: `cargo test --release
/// --features tree --test spike rough_times -- --ignored --nocapture`. No figure of it is
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
        println!("{name}: {:.0} ns", start.elapsed().as_nanos() as f64 / rounds as f64);
    };
    println!("{} octets", octets.len());
    time("decode", &mut || drop(black_box(Message::decode(black_box(&octets)).unwrap())));
    time("encode", &mut || drop(black_box(black_box(&message).encode().unwrap())));
    time("check", &mut || drop(black_box(black_box(&message).check())));
    time("to_tree", &mut || drop(black_box(black_box(&message).to_tree())));
    time("from_tree", &mut || drop(black_box(Message::from_tree(black_box(&tree)).unwrap())));
    time("edit by path, from_tree and encode", &mut || {
        let mut tree = tree.clone();
        set(&mut tree, "/pfcp/Create PDR/1/PDI/UE IP address/0/IPv4 address", "10.45.0.3").unwrap();
        drop(black_box(Message::from_tree(&tree).unwrap().encode().unwrap()));
    });
}
