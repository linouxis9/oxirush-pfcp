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

//! The tree of a message and of its values, which reads back: its order, its names, its
//! forms, and what it does not print.

use super::*;

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
    let error = Message::from_tree(&tree).unwrap_err();
    assert_eq!(
        (error.kind(), error.at()),
        (
            tree::ErrorKind::Value,
            "/pfcp/Create PDR/0/PDI/Local F-TEID"
        ),
        "{error}"
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
        tree!({"FD": true, "Flow Description": "aa"}),
    );
    spare::<SdfFilter>(
        "010700026161",
        tree!({"FD": true, "Spare octet": 7, "Flow Description": "aa"}),
    );
    spare::<PfdContents>("0100000161", tree!({"FD": true, "Flow Description": "a"}));
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

/// A Flow Description, an IPFilterRule of text (TS 29.212 clause 5.4.2), and the URL and
/// the Domain Name of PFD Contents are their text in a tree, or `{"octets": ...}` for
/// octets that are no UTF-8.
#[test]
fn a_flow_description_is_its_text() {
    let rule = "permit out ip from any to assigned";
    let filter = tree!({"FD": true, "Flow Description": rule});
    let read = tree::from_value::<SdfFilter>(&filter).unwrap();
    assert_eq!(
        read.flow_description.as_ref().and_then(TextLv16::text),
        Some(rule)
    );
    assert_eq!(tree::Tree::to_tree(&read), filter);
    let mut octets = Vec::new();
    read.encode(&mut octets).unwrap();
    assert_eq!(&octets[4..], rule.as_bytes());
    let other = tree!({"FD": true, "Flow Description": {"octets": "ff"}});
    let read = tree::from_value::<SdfFilter>(&other).unwrap();
    assert_eq!(
        read.flow_description,
        Some(TextLv16(Octets::copied(&[0xff])))
    );
    assert_eq!(tree::Tree::to_tree(&read), other);
    let contents = tree!({"URL": true, "DN": true, "URL field": "http://a.example/", "Domain Name": "a.example"});
    let read = tree::from_value::<PfdContents>(&contents).unwrap();
    assert_eq!(tree::Tree::to_tree(&read), contents);
}

/// §8.2.20: the Redirect Server Address and the Other Redirect Server Address "shall be
/// encoded in UTF8String format": they are their text in a tree, or `{"octets": ...}` for
/// octets that are no UTF-8.
#[test]
fn a_redirect_server_address_is_its_text() {
    let redirect =
        tree!({"Redirect Address Type": "IPv4 address", "Redirect Server Address": "1.2.3.4"});
    let read = tree::from_value::<RedirectInformation>(&redirect).unwrap();
    assert_eq!(
        read.redirect_server_address
            .as_ref()
            .and_then(TextLv16::text),
        Some("1.2.3.4")
    );
    assert_eq!(tree::Tree::to_tree(&read), redirect);
    let mut octets = Vec::new();
    read.encode(&mut octets).unwrap();
    assert_eq!(hex::encode(&octets), "000007312e322e332e34");
    let both = tree!({
        "Redirect Address Type": "IPv4 and IPv6 addresses",
        "Redirect Server Address": "1.2.3.4",
        "Other Redirect Server Address": "2001:db8::1",
    });
    let read = tree::from_value::<RedirectInformation>(&both).unwrap();
    assert_eq!(tree::Tree::to_tree(&read), both);
    let other =
        tree!({"Redirect Address Type": "URL", "Redirect Server Address": {"octets": "ff"}});
    let read = tree::from_value::<RedirectInformation>(&other).unwrap();
    assert_eq!(
        read.redirect_server_address,
        Some(TextLv16(Octets::copied(&[0xff])))
    );
    assert_eq!(tree::Tree::to_tree(&read), other);
}

/// §8.2.193 and §8.2.194: the DNS Server Address and the NBNS Server Address "shall contain
/// an IPv4 address", which they are in a tree, and no number.
#[test]
fn a_dns_server_address_is_an_address() {
    let address = Ipv4Addr::new(10, 0, 0, 1);
    let dns = DnsServerAddress::new(address.into());
    assert_eq!(dns.value.0, address);
    assert_eq!(tree::Tree::to_tree(&dns), tree!("10.0.0.1"));
    assert_eq!(
        tree::from_value::<DnsServerAddress>(&tree!("10.0.0.1")).ok(),
        Some(dns.clone())
    );
    let mut octets = Vec::new();
    dns.encode(&mut octets).unwrap();
    assert_eq!(octets, [10, 0, 0, 1]);
    assert_eq!(DnsServerAddress::decode(&octets), Some(dns));
    let nbns = NbnsServerAddress::decode(&[192, 168, 0, 1, 0xab]).unwrap();
    let written = tree!({"NBNS Server Address value": "192.168.0.1", "unknown octets": "ab"});
    assert_eq!(tree::Tree::to_tree(&nbns), written);
    assert_eq!(
        tree::from_value::<NbnsServerAddress>(&written).ok(),
        Some(nbns)
    );
    for other in [tree!(167772161), tree!("0a000001"), tree!("::1")] {
        assert!(
            tree::from_value::<DnsServerAddress>(&other).is_err(),
            "{other}"
        );
    }
    assert_eq!(Ipv4Address::default().0, Ipv4Addr::UNSPECIFIED);
}

/// The values that their clauses have "encoded in UTF8String format" are their text in a
/// tree: a Calling Number and a Called Number (§8.2.190, §8.2.191), a Tunnel Password
/// (§8.2.212), and the Key ID and the Shared Secret of a Key ID and Shared Secret
/// (§8.2.276). Octets that are no UTF-8 are in hexadecimal: of a value that is one field,
/// in an object of that field, apart from `{"octets": ...}`, which an IE kept as octets
/// is; of a field, in `{"octets": ...}`. A password and a passphrase are in a tree, which
/// reads back, and not in `Debug`, nor in an error of their tree.
#[test]
fn a_number_a_password_and_a_key_id_are_their_text() {
    let calling = CallingNumber(b"33612345678".to_vec().into());
    assert_eq!(tree::Tree::to_tree(&calling), tree!("33612345678"));
    assert_eq!(
        tree::from_value::<CallingNumber>(&tree!("33612345678")).ok(),
        Some(calling)
    );
    let called = CalledNumber(b"internet".to_vec().into());
    assert_eq!(tree::Tree::to_tree(&called), tree!("internet"));
    assert_eq!(
        tree::from_value::<CalledNumber>(&tree!("internet")).ok(),
        Some(called)
    );
    let other = CallingNumber(vec![0xff, 0xfe].into());
    let written = tree!({"Calling Number value": "fffe"});
    assert_eq!(tree::Tree::to_tree(&other), written);
    assert_eq!(
        tree::from_value::<CallingNumber>(&written).ok(),
        Some(other)
    );
    assert!(tree::from_value::<CallingNumber>(&tree!({"octets": "fffe"})).is_err());
    assert!(tree::from_value::<CallingNumber>(&tree!(5)).is_err());
    // A password
    let password = TunnelPassword(b"secret!pass".to_vec().into());
    assert_eq!(tree::Tree::to_tree(&password), tree!("secret!pass"));
    assert_eq!(
        tree::from_value::<TunnelPassword>(&tree!("secret!pass")).ok(),
        Some(password.clone())
    );
    assert_eq!(format!("{password:?}"), "TunnelPassword(11 octets)");
    let other = TunnelPassword(vec![0xff, 0xfe].into());
    let written = tree!({"Tunnel Password value": "fffe"});
    assert_eq!(tree::Tree::to_tree(&other), written);
    assert_eq!(
        tree::from_value::<TunnelPassword>(&written).ok(),
        Some(other)
    );
    let refusal = tree!({"Tunnel Password value": "fffe", "secret!pass": 1});
    let error = tree::from_value::<TunnelPassword>(&refusal).unwrap_err();
    assert!(!error.to_string().contains("secret!pass"), "{error}");
    // An HMAC Key is octets, and no text
    let key = HmacKeyStamp(b"key".to_vec().into());
    assert_eq!(tree::Tree::to_tree(&key), tree!("6b6579"));
    // A Key ID and a Shared Secret
    let key = KeyIdAndSharedSecret {
        key_id: TextLv8::from("owamp"),
        shared_secret: SecretTextLv8(b"passphrase".to_vec().into()),
        ..Default::default()
    };
    let written = tree!({"Key ID": "owamp", "Shared Secret": "passphrase"});
    assert_eq!(tree::Tree::to_tree(&key), written);
    assert_eq!(
        tree::from_value::<KeyIdAndSharedSecret>(&written).ok(),
        Some(key.clone())
    );
    assert!(!format!("{key:?}").contains("passphrase"), "{key:?}");
    assert!(format!("{key:?}").contains("SecretTextLv8(10 octets)"));
    let written = tree!({"Key ID": {"octets": "ff"}, "Shared Secret": {"octets": "fe"}});
    let other: KeyIdAndSharedSecret = tree::from_value(&written).unwrap();
    assert_eq!(
        (&other.key_id.0[..], &other.shared_secret.0[..]),
        (&[0xff][..], &[0xfe][..])
    );
    assert_eq!(tree::Tree::to_tree(&other), written);
    let refusal = tree!({"Key ID": "owamp", "Shared Secret": {"passphrase": 1}});
    let error = tree::from_value::<KeyIdAndSharedSecret>(&refusal).unwrap_err();
    assert!(!error.to_string().contains("passphrase"), "{error}");
    // In a message: the value of octets that are no text, and the IE kept as octets
    let mut message = establishment();
    let mut written = message.to_tree();
    written["ies"]["L2TP Session Information"] = tree!({"Calling Number": {"Calling Number value": "fffe"}, "Called Number": {"octets": "fffe"}});
    let Body::SessionEstablishmentRequest(request) = &mut message.body else {
        panic!()
    };
    let session = L2tpSessionInformation {
        calling_number: Some(CallingNumber(vec![0xff, 0xfe].into())),
        raw: vec![RawIe::new(283, vec![0xff, 0xfe])],
        ..Default::default()
    };
    request.l2tp_session_information = Some(session.into());
    assert_eq!(Message::from_tree(&written).unwrap(), message);
    assert_eq!(message.to_tree(), written);
}

/// §8.2.43: an FQ-CSID of a Node-ID Type that the clause reserves, which a value may have
/// and `encode()` writes, with the Node-Address that it has, for a test to send: its tree
/// reads back, as the tree of any value that encodes does, and writes the same octets.
/// One of a type that the clause names has a Node-Address of the length of that type.
#[test]
fn an_fq_csid_of_a_reserved_node_id_type_reads_back_from_its_tree() {
    let reserved = FqCsid {
        node_id_type: 5,
        node_address: vec![1, 2, 3].into(),
        csids: vec![7],
        ..Default::default()
    };
    let mut octets = Vec::new();
    reserved.encode(&mut octets).unwrap();
    assert_eq!(octets, [0x51, 1, 2, 3, 0, 7]);
    let written = tree::Tree::to_tree(&reserved);
    let expected = tree!({"FQ-CSID Node-ID Type": 5, "Node-Address": "010203", "PDN Connection Set Identifiers": [7]});
    assert_eq!(written, expected);
    assert_eq!(
        tree::from_value::<FqCsid>(&written).ok(),
        Some(reserved.clone())
    );
    // In a message, whose tree reads back and encodes to the same octets
    let mut message = establishment();
    let Body::SessionEstablishmentRequest(request) = &mut message.body else {
        panic!()
    };
    request.fq_csid = vec![reserved];
    let read = Message::from_tree(&message.to_tree()).unwrap();
    assert_eq!(read, message);
    assert_eq!(read.encode().unwrap(), message.encode().unwrap());
    // Of a type that the clause names, the Node-Address has the length of its type
    for (kind, address) in [
        (0, tree!("0a00")),
        (1, tree!("10.0.0.1")),
        (2, tree!("0a00")),
    ] {
        let short = tree!({"FQ-CSID Node-ID Type": kind, "Node-Address": address, "PDN Connection Set Identifiers": [7]});
        assert!(tree::from_value::<FqCsid>(&short).is_err(), "{short}");
    }
    let many = tree!({"FQ-CSID Node-ID Type": 5, "Node-Address": "01", "PDN Connection Set Identifiers": vec![1u16; 16]});
    let error = tree::from_value::<FqCsid>(&many).unwrap_err().to_string();
    assert!(error.contains("at most fifteen identifiers"), "{error}");
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

/// A tree written in another order than its table's encodes in the table's order; within
/// a row, its values and its octets keep the order written.
#[test]
fn a_tree_written_in_any_order_encodes_in_the_order_of_its_table() {
    let written = tree!({
        "message": "PFCP Association Setup Request",
        "header": {"Sequence Number": 9},
        "ies": {"Recovery Time Stamp": 3_900_000_000u32, "Node ID": "10.0.0.1"}
    });
    let octets = Message::from_tree(&written).unwrap().encode().unwrap();
    assert_eq!(&octets[8..10], &[0, 60], "the Node ID first");
    let in_order = tree!({
        "message": "PFCP Association Setup Request",
        "header": {"Sequence Number": 9},
        "ies": {"Node ID": "10.0.0.1", "Recovery Time Stamp": 3_900_000_000u32}
    });
    assert_eq!(
        Message::from_tree(&in_order).unwrap().encode().unwrap(),
        octets
    );
    // With octets of a row and an IE of no row
    let written = tree!({
        "message": "PFCP Association Setup Request",
        "header": {"Sequence Number": 9},
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
    let response = |ies: tree::Value| tree!({"message": "PFCP Session Establishment Response", "header": {"SEID": 1, "Sequence Number": 1}, "ies": ies});
    // At the scope, with the name of the row to write
    let refused = |written: &tree::Value, row: &str| {
        let error = Message::from_tree(written).unwrap_err();
        assert!(error.reason().contains(row), "{error}");
        (error.kind(), error.at().to_string())
    };
    let no_such = (tree::ErrorKind::NoSuchMember, "/pfcp".to_string());
    let by_type = response(
        tree!({"Node ID": "10.0.0.2", "Cause": 1, "F-SEID": {"V4": true, "SEID": 1, "IPv4 address": "10.0.0.2"}}),
    );
    assert_eq!(refused(&by_type, "UP F-SEID"), no_such);
    let request = tree!({"message": "PFCP Session Establishment Request", "header": {"SEID": 0, "Sequence Number": 1}, "ies": {"SGW-C FQ-CSID": {"octets": "01"}}});
    assert_eq!(refused(&request, "FQ-CSID"), no_such);
    let twice = response(tree!({"Node ID": "10.0.0.2", "node_id": "10.0.0.3", "Cause": 1}));
    let value = (tree::ErrorKind::Value, "/pfcp".to_string());
    assert_eq!(refused(&twice, "Node ID"), value);
}

/// A row is written as its table has it: a row of a list as a list, also of one entry, and
/// the repetitions of a row there once by their octets.
#[test]
fn a_row_is_written_as_its_table_has_it() {
    let request = |ies: tree::Value| tree!({"message": "PFCP Session Establishment Request", "header": {"SEID": 0, "Sequence Number": 1}, "ies": ies});
    let far = tree!({"FAR ID": 1, "Apply Action": {"DROP": true}});
    let refused = |written: tree::Value| {
        let error = Message::from_tree(&request(written)).unwrap_err();
        (error.kind(), error.at().to_string())
    };
    let value = |at: &str| (tree::ErrorKind::Value, at.to_string());
    assert_eq!(
        refused(tree!({"Create FAR": far.clone()})),
        value("/pfcp/Create FAR")
    );
    assert!(Message::from_tree(&request(tree!({"Create FAR": [far]}))).is_ok());
    let twice = tree!({"Node ID": ["10.0.0.1", "10.0.0.2"]});
    assert_eq!(refused(twice), value("/pfcp/Node ID/1"));
    let repeated = tree!({"Node ID": ["10.0.0.1", {"octets": "000a000002"}]});
    assert!(Message::from_tree(&request(repeated)).is_ok());
}

/// A message goes by its name: a message type of Table 7.3-1 written by its number is
/// refused with the name to write, and the number is for a message type of no table, whose
/// IEs are octets.
#[test]
fn a_message_goes_by_its_name() {
    let heartbeat = tree!({"message": 1, "header": {"Sequence Number": 9}, "ies": {"octets": "006000040000000a"}});
    let error = Message::from_tree(&heartbeat).unwrap_err();
    assert_eq!(
        (error.kind(), error.at()),
        (tree::ErrorKind::Value, "/message")
    );
    let other = tree!({"message": 99, "header": {"Sequence Number": 9}, "ies": {"octets": "006000040000000a"}});
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

/// The header is a member of the tree of its own, beside the name of the message and its
/// IEs, as the paths and the deviations of `check()` name it: a field of the header beside
/// `ies` is no member of a message, and a member of the header that it has not is refused
/// with those that it has.
#[test]
fn a_header_is_a_member_of_the_tree() {
    let deletion = Message::session(1, 7, SessionDeletionRequest::default());
    let tree = deletion.to_tree();
    assert_eq!(
        tree,
        tree!({
            "message": "PFCP Session Deletion Request",
            "header": {"SEID": 1, "Sequence Number": 7},
            "ies": {}
        })
    );
    assert_eq!(select(&tree, "/header/SEID").unwrap(), [&tree!(1)]);
    assert_eq!(
        select(&tree, "/header/Message Priority").unwrap(),
        Vec::<&tree::Value>::new()
    );
    let refused = |written: &tree::Value| {
        let error = Message::from_tree(written).unwrap_err();
        (
            error.kind(),
            error.at().to_string(),
            error.reason().to_string(),
        )
    };
    let beside = tree!({"message": "PFCP Session Deletion Request", "SEID": 1, "header": {"Sequence Number": 7}, "ies": {}});
    let (kind, at, reason) = refused(&beside);
    assert_eq!((kind, at.as_str()), (tree::ErrorKind::NoSuchMember, ""));
    assert!(reason.contains("message, header, ies"), "{reason}");
    let misspelt = tree!({"message": "PFCP Session Deletion Request", "header": {"SEID": 1, "Sequense Number": 7}, "ies": {}});
    let (kind, at, reason) = refused(&misspelt);
    assert_eq!(
        (kind, at.as_str()),
        (tree::ErrorKind::NoSuchMember, "/header")
    );
    assert!(reason.contains("Sequence Number"), "{reason}");
    assert!(select(&tree, "/header/Sequense Number").is_err());
    // A deviation of the header is at its field in the header
    let node = Message::node(1, HeartbeatRequest::new(RecoveryTimeStamp::new(7)));
    let mut bundled = node.clone();
    bundled.header.follow_on = true;
    let paths: Vec<String> = bundled
        .check(Interfaces::N4)
        .into_iter()
        .map(|deviation| deviation.path)
        .collect();
    assert_eq!(paths, ["/header/FO"]);
}

/// A header that its user writes, in any spelling of its names, reads back as the header
/// that it writes, each of its fields, and prints by their names.
#[test]
fn a_header_written_by_its_user_reads_back() {
    let written = tree!({
        "message": "PFCP Session Deletion Request",
        "header": {
            "version": 2,
            "spare": 1,
            "fo": true,
            "seid": 1,
            "sequence_number": 9,
            "message-priority": 3,
            "spare_octet": 5,
            "Message Length": 12
        },
        "ies": {}
    });
    let message = Message::from_tree(&written).unwrap();
    assert_eq!(
        message.header,
        Header {
            version: 2,
            spare: 1,
            follow_on: true,
            seid: Some(1),
            sequence: 9,
            priority: Some(3),
            spare_last: 5,
            length: Some(12),
        }
    );
    let printed = tree!({
        "message": "PFCP Session Deletion Request",
        "header": {
            "Version": 2,
            "Spare": 1,
            "FO": true,
            "SEID": 1,
            "Sequence Number": 9,
            "Message Priority": 3,
            "Spare octet": 5,
            "Message Length": 12
        },
        "ies": {}
    });
    assert_eq!(message.to_tree(), printed);
    assert_eq!(Message::from_tree(&printed).unwrap(), message);
}

/// A Node ID of other octets than an address or an FQDN is its Node ID Type and its value
/// in the tree of its message, which loads back to it: `{"octets": ...}` is the form of an
/// IE kept as octets, which the scope would read.
#[test]
fn a_node_id_of_other_octets_is_no_ie_kept_as_octets() {
    for other in [
        NodeId::Other(0, vec![].into()),
        NodeId::Other(4, vec![127, 0, 0, 8].into()),
    ] {
        let setup = AssociationSetupRequest::new(other.clone(), RecoveryTimeStamp::new(7));
        let message = Message::decode(&Message::node(1, setup).encode().unwrap()).unwrap();
        let tree = message.to_tree();
        let Body::AssociationSetupRequest(read) = &Message::from_tree(&tree).unwrap().body else {
            panic!()
        };
        assert_eq!(read.node_id.as_ref(), Some(&other), "{tree}");
        assert!(read.raw.is_empty());
    }
    let tree = tree::Tree::to_tree(&NodeId::Other(4, vec![127, 0, 0, 8].into()));
    assert_eq!(
        tree,
        tree!({"Node ID Type": 4, "Node ID value": "7f000008"})
    );
    // Each member goes by its name, in any case
    let fqdn: NodeId = tree::from_value(&tree!({"fqdn": "upf.example"})).unwrap();
    assert_eq!(Some(fqdn), NodeId::from_fqdn("upf.example"));
    let other: NodeId =
        tree::from_value(&tree!({"node id type": 4, "node id value": "7f000008"})).unwrap();
    assert_eq!(other, NodeId::Other(4, vec![127, 0, 0, 8].into()));
    // A member that is null is not there, as in any value
    let written = tree!({"FQDN": null, "Node ID Type": 4, "Node ID value": "7f000008"});
    assert_eq!(tree::from_value::<NodeId>(&written).ok(), Some(other));
}

/// A Network Instance of the labels of a name is that name in a tree, whatever its
/// characters: a text is a name; other octets are `{"Network Instance": ...}`, in
/// hexadecimal (§8.2.4). So are an APN/DNN (§8.2.117), as `{"APN/DNN": ...}`, and the
/// Network Instance field of Remote GTP-U Peer (§8.2.70), and `NetworkInstance::from_name`
/// gives the labels of a name. A name has labels of 1 to 63 octets, of 253 octets at most.
#[test]
fn a_network_instance_of_labels_is_its_name() {
    let instance = |octets: &[u8]| NetworkInstance(octets.to_vec().into());
    for (octets, name) in [
        (&b"\x08internet"[..], Some("internet")),
        (b"\x03ims\x06mnc093", Some("ims.mnc093")),
        (b"\x04cafe", Some("cafe")),
        (b"\x041234", Some("1234")),
        (b"\x03abc", Some("abc")),
        (b"internet", None),
        (b"", None),
    ] {
        let (written, apn_written) = match name {
            Some(name) => (tree!(name), tree!(name)),
            None => (
                tree!({"Network Instance": hex::encode(octets)}),
                tree!({"APN/DNN": hex::encode(octets)}),
            ),
        };
        assert_eq!(
            tree::Tree::to_tree(&instance(octets)),
            written,
            "{octets:?}"
        );
        let read: NetworkInstance = tree::from_value(&written).unwrap();
        assert_eq!(read, instance(octets), "{written}");
        let apn = ApnDnn(octets.to_vec().into());
        assert_eq!(tree::Tree::to_tree(&apn), apn_written, "{octets:?}");
        assert_eq!(tree::from_value::<ApnDnn>(&apn_written).ok(), Some(apn));
    }
    // A DNN of hexadecimal digits in a message is that name
    let mut message = establishment();
    let mut written = message.to_tree();
    written["ies"]["APN/DNN"] = tree!("cafe");
    let Body::SessionEstablishmentRequest(request) = &mut message.body else {
        panic!()
    };
    request.apn_dnn = Some(ApnDnn(b"\x04cafe".to_vec().into()));
    assert_eq!(Message::from_tree(&written).unwrap(), message);
    // Of no name: an empty label, a label of 64 octets, more than 253 octets
    let long = ["a"; 128].join(".");
    for name in ["a..b", "", &"a".repeat(64), &long] {
        let error = tree::from_value::<NetworkInstance>(&tree!(name)).unwrap_err();
        assert!(error.to_string().contains("253 octets"), "{error}");
        assert_eq!(NetworkInstance::from_name(name), None, "{name}");
    }
    assert!(tree::from_value::<NetworkInstance>(&tree!(["a"; 127].join("."))).is_ok());
    assert!(tree::from_value::<NetworkInstance>(&tree!({"octets": "08"})).is_err());
    assert_eq!(
        NetworkInstance::from_name("ims.mnc093"),
        Some(instance(b"\x03ims\x06mnc093"))
    );
    for (octets, written) in [
        (
            &b"\x08internet"[..],
            tree!({"NI": true, "Network Instance field": "internet"}),
        ),
        (
            b"internet",
            tree!({"NI": true, "Network Instance field": {"Network Instance": "696e7465726e6574"}}),
        ),
    ] {
        let peer = RemoteGtpUPeer {
            ni: true,
            network_instance_field: Some(NameLv16(octets.to_vec().into())),
            ..Default::default()
        };
        assert_eq!(tree::Tree::to_tree(&peer), written);
        assert_eq!(
            tree::from_value::<RemoteGtpUPeer>(&written).ok(),
            Some(peer)
        );
    }
}
