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

//! The fields and values of clause 8.2 against their figures: their octets, their bits,
//! what a caller reads of them and the clause that `check()` names.

use super::*;

/// An F-SEID of an IPv4 address and one of an IPv6 address, as their constructors build
/// them: the flag of the family, the SEID, then the address (§8.2.37); an F-TEID of each
/// family likewise.
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
    // And an F-TEID, with a TEID or chosen by the UP function (§8.2.3)
    let encoded = |f_teid: FTeid| {
        let mut out = Vec::new();
        f_teid.encode(&mut out).unwrap();
        hex::encode(out)
    };
    let address = "2001:db8::1".parse().unwrap();
    let v6 = encoded(FTeid::ipv6(7, address));
    assert_eq!(v6, "020000000720010db8000000000000000000000001");
    assert_eq!(encoded(FTeid::choose_ipv6()), "06");
    assert_eq!(encoded(FTeid::choose_ipv4()), "05");
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
    // A vendor IE of a false Length, and an IE of a type that no release has
    let mut heartbeat = HeartbeatRequest::new(RecoveryTimeStamp::new(7));
    for ie_type in [32767, 0x8001] {
        heartbeat.raw.push(RawIe {
            length: Some(9),
            ..RawIe::new(ie_type, vec![0, 1, 2])
        });
    }
    let said: Vec<String> = Message::node(1, heartbeat)
        .check(Interfaces::N4)
        .iter()
        .map(ToString::to_string)
        .collect();
    assert!(
        said.iter()
            .any(|said| said.starts_with("an IE of no release has a Length")),
        "{said:?}"
    );
    assert!(
        said.iter()
            .any(|said| said.starts_with("a vendor IE has a Length")),
        "{said:?}"
    );
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
            tree!({"message": info.name(), "header": {"Sequence Number": 1}, "ies": {"Cause": 3}});
        if session {
            written["header"]["SEID"] = tree!(1);
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

/// A value whose octets would read as another value is refused, by `encode()`, by
/// `Message::from_tree` and as a deviation of `check()`; its octets read back as it where it
/// is not. A field read where octets remain after those before it is there where a later
/// one, or unknown octets, are (§8.1.2): the C-TAG and the S-TAG of MAC Addresses Detected
/// and Removed, whose C-TAG field is of no octets where it is absent before an S-TAG
/// (§8.2.103), and the Node Type of an FQ-CSID; no unknown octets follow a field that runs
/// to the end of the IE (Offending IE Information, SMF Set ID, DSCP to PPI Mapping
/// Information); a field of the length that its flags give has no more octets, and no
/// fewer with octets after it (Failed Rule ID); a value of bits has as many of its octets as
/// it may (Apply Action): the tree of each is refused. A Node ID of other octets is none
/// that a variant is: its tree is its Node ID Type and value, which load as that variant.
#[test]
fn a_value_whose_octets_would_read_as_another_is_refused() {
    fn refused<T: Codec + Check + tree::Tree + PartialEq>(value: T, field: &str) {
        match value.encode(&mut Vec::new()) {
            Err(Error::Inconsistent { field: named, .. }) => assert_eq!(named, field),
            other => panic!("{field}: {other:?}"),
        }
        let kinds: Vec<_> = value
            .deviations()
            .into_iter()
            .map(|deviation| deviation.kind)
            .collect();
        let told = |kind: &DeviationKind| matches!(kind, DeviationKind::Inconsistent { field: told } if *told == field);
        assert!(kinds.iter().any(told), "{field}: {kinds:?}");
        // Its tree does not load: it says why
        let written = tree::Tree::to_tree(&value);
        assert!(tree::from_value::<T>(&written).is_err(), "{written}");
    }
    fn kept<T: Codec + PartialEq + core::fmt::Debug>(value: T) {
        let mut octets = Vec::new();
        value.encode(&mut octets).unwrap();
        assert_eq!(T::decode(&octets).as_ref(), Some(&value));
    }
    let mac = MacAddressesDetected {
        mac_addresses: vec![[2, 0, 0, 0, 0, 1]],
        ..Default::default()
    };
    let unknown = Octets::from(vec![3u8, 0, 0, 0]);
    let tag = Lv8(Octets::from(vec![1u8, 0, 1]));
    refused(
        MacAddressesDetected {
            extra: unknown.clone(),
            ..mac.clone()
        },
        "C-TAG",
    );
    refused(
        MacAddressesDetected {
            s_tag: Some(tag.clone()),
            ..mac.clone()
        },
        "C-TAG",
    );
    let absent = MacAddressesDetected {
        c_tag: Some(Lv8::default()),
        ..mac.clone()
    };
    refused(
        MacAddressesDetected {
            extra: unknown.clone(),
            ..absent.clone()
        },
        "S-TAG",
    );
    kept(MacAddressesDetected {
        s_tag: Some(tag.clone()),
        ..absent
    });
    kept(MacAddressesRemoved {
        c_tag: Some(tag.clone()),
        s_tag: Some(tag),
        extra: unknown.clone(),
        mac_addresses: vec![],
    });
    let csid = FqCsid {
        node_id_type: 0,
        node_address: vec![10, 0, 0, 1].into(),
        csids: vec![1],
        ..Default::default()
    };
    refused(
        FqCsid {
            extra: unknown.clone(),
            ..csid.clone()
        },
        "Node Type",
    );
    kept(FqCsid {
        node_type: Some(Narrow::default()),
        extra: unknown.clone(),
        ..csid
    });
    let offending = OffendingIeInformation {
        type_of_the_offending_ie: 19,
        value_of_the_offending_ie: Rest(vec![1u8].into()),
        ..Default::default()
    };
    kept(offending.clone());
    refused(
        OffendingIeInformation {
            extra: unknown.clone(),
            ..offending
        },
        "unknown octets",
    );
    let set = SmfSetId {
        fqdn: Fqdn(b"\x03smf".to_vec().into()),
        ..Default::default()
    };
    kept(set.clone());
    refused(
        SmfSetId {
            extra: unknown.clone(),
            ..set
        },
        "unknown octets",
    );
    refused(
        DscpToPpiMappingInformation {
            extra: unknown.clone(),
            ..Default::default()
        },
        "unknown octets",
    );
    let rule = |octets: Vec<u8>| FailedRuleId {
        rule_id_type: RuleIdType::Pdr,
        rule_id_value: Rest(octets.into()),
        ..Default::default()
    };
    kept(rule(vec![0, 1]));
    kept(rule(vec![1]));
    kept(FailedRuleId {
        extra: unknown.clone(),
        ..rule(vec![0, 1])
    });
    refused(rule(vec![0, 1, 2]), "Rule ID value");
    // Shorter than its type's, with octets after it, which would read as part of it
    refused(
        FailedRuleId {
            extra: unknown,
            ..rule(vec![1])
        },
        "Rule ID value",
    );
    for present in [0, 3, 9] {
        refused(
            ApplyAction {
                forw: true,
                present,
                ..Default::default()
            },
            "length",
        );
    }
    kept(ApplyAction {
        forw: true,
        present: 1,
        ..Default::default()
    });
    for (node, field, read) in [
        (
            NodeId::Fqdn(Octets::default()),
            "Node ID value",
            NodeId::Other(2, Octets::default()),
        ),
        (
            NodeId::Other(0, vec![10u8, 0, 0, 1].into()),
            "Node ID value",
            NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
        ),
        (
            NodeId::Other(2, b"\x03smf".to_vec().into()),
            "Node ID value",
            NodeId::Fqdn(b"\x03smf".to_vec().into()),
        ),
    ] {
        match node.encode(&mut Vec::new()) {
            Err(Error::Inconsistent { field: named, .. }) => assert_eq!(named, field),
            other => panic!("{node:?}: {other:?}"),
        }
        let kinds: Vec<_> = node
            .deviations()
            .into_iter()
            .map(|deviation| deviation.kind)
            .collect();
        assert!(
            kinds.contains(&DeviationKind::Inconsistent {
                field: "Node ID value"
            }),
            "{kinds:?}"
        );
        // Its tree is its Node ID Type and value, which load as the Node ID that they read as
        let written = tree::Tree::to_tree(&node);
        assert_eq!(
            tree::from_value::<NodeId>(&written).ok(),
            Some(read),
            "{written}"
        );
    }
    kept(NodeId::Other(0, vec![10u8, 0, 0].into()));
    kept(NodeId::Other(2, Octets::default()));
    kept(NodeId::Other(0x12, vec![10u8, 0, 0, 1].into()));
}

/// A field that the value of another field has or not: the Redirect Server Address of a
/// Redirect Information, absent where the Redirect Address Type is "Port" (§8.2.20), and
/// the Reporting Time Info of a Reporting Suggestion Info, present where the Reporting
/// Urgency is "Delay tolerant" alone (§8.2.229). Their octets read so, and encode back to
/// them; a value or a tree that has the field where the other's value does not, or lacks
/// it where it does, is refused, and told by `check()` (`Inconsistent`).
#[test]
fn a_field_that_the_value_of_another_has_or_not() {
    fn refused<T: Codec + Check + tree::Tree + std::fmt::Debug>(value: T, field: &str) {
        match value.encode(&mut Vec::new()) {
            Err(Error::Inconsistent { field: named, .. }) => assert_eq!(named, field),
            other => panic!("{field}: {other:?}"),
        }
        let kinds: Vec<_> = value
            .deviations()
            .into_iter()
            .map(|deviation| deviation.kind)
            .collect();
        let told = |kind: &DeviationKind| matches!(kind, DeviationKind::Inconsistent { field: told } if *told == field);
        assert!(kinds.iter().any(told), "{field}: {kinds:?}");
        let written = tree::Tree::to_tree(&value);
        let refusal = tree::from_value::<T>(&written).unwrap_err().to_string();
        assert!(refusal.contains(field), "{refusal}");
    }
    // A Port alone: the Redirect Port, port 8080
    let port: RedirectInformation = read_back("05 1f90");
    assert_eq!(port.redirect_server_address, None);
    assert_eq!(port.redirect_port, Some(8080));
    let address = Some(Lv16(b"abcd".to_vec().into()));
    let typed = |value, redirect_server_address| RedirectInformation {
        redirect_address_type: RedirectAddressType::from_value(value),
        redirect_server_address,
        other_redirect_server_address: matches!(value, 4 | 8).then(|| Lv16(b"ef".to_vec().into())),
        redirect_port: (5..=8).contains(&value).then_some(8080),
        ..Default::default()
    };
    refused(typed(5, address.clone()), "Redirect Server Address");
    for value in [0, 4, 6, 8] {
        refused(typed(value, None), "Redirect Server Address");
        let mut octets = Vec::new();
        typed(value, address.clone()).encode(&mut octets).unwrap();
        assert_eq!(
            RedirectInformation::decode(&octets),
            Some(typed(value, address.clone()))
        );
    }
    let tree = tree!({"Redirect Address Type": "Port", "Redirect Server Address": "", "Redirect Port": 8080});
    assert!(tree::from_value::<RedirectInformation>(&tree).is_err());
    let tree = tree!({"Redirect Address Type": "Port", "Redirect Port": 8080});
    assert_eq!(
        tree::from_value::<RedirectInformation>(&tree).unwrap(),
        port
    );
    // Non delay tolerant, without a time; delay tolerant, with one
    let urgent: ReportingSuggestionInfo = read_back("01");
    assert_eq!(urgent.reporting_time_info, None);
    let tolerant: ReportingSuggestionInfo = read_back("00 00000005");
    assert_eq!(tolerant.reporting_time_info, Some(5));
    assert_eq!(ReportingSuggestionInfo::decode(&[0]), None);
    let suggestion = |value, reporting_time_info| ReportingSuggestionInfo {
        reporting_urgency: ReportingUrgencyValue::from_value(value),
        reporting_time_info,
        ..Default::default()
    };
    refused(suggestion(0, None), "Reporting Time Info");
    refused(suggestion(1, Some(5)), "Reporting Time Info");
    refused(suggestion(2, Some(5)), "Reporting Time Info");
    let tree = tree!({"Reporting Urgency value": "Non delay tolerant", "Reporting Time Info": 5});
    assert!(tree::from_value::<ReportingSuggestionInfo>(&tree).is_err());
    let tree = tree!({"Reporting Urgency value": "Delay tolerant"});
    assert!(tree::from_value::<ReportingSuggestionInfo>(&tree).is_err());
}
