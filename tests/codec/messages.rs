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

//! Messages and datagrams: headers, lengths, framing, the errors of the codec, and the
//! vectors of `PFCP_VECTORS`.

use super::paths::members_hold;
use super::*;

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
    let mut expected: Vec<&str> = include_str!("../go-pfcp-deviations.tsv")
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
            Some(format!("/header/{field}")),
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
    let written = tree!({"message": "PFCP Session Deletion Request", "header": {"SEID": 1, "Sequence Number": 1, "Message Priority": 3, "Spare octet": 0x35}, "ies": {}});
    assert!(Message::from_tree(&written).is_err());
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

/// `encode_into` appends what `encode` returns, and leaves the buffer as it was when the
/// header, an IE or the fields of an IE do not encode.
#[test]
fn encode_into_appends_or_leaves_the_buffer() {
    let heartbeat = || HeartbeatRequest::new(RecoveryTimeStamp::new(7));
    let source = SourceIpAddress {
        v4: true,
        ipv4_address: Some(Ipv4Addr::new(10, 0, 0, 1)),
        ..Default::default()
    };
    let message = Message::session(9, 1, heartbeat().with_source_ip_address(source));
    let mut buffer = vec![1, 2, 3];
    message.encode_into(&mut buffer).unwrap();
    assert_eq!(buffer[..3], [1, 2, 3]);
    assert_eq!(buffer[3..], message.encode().unwrap());

    let wide = Message {
        header: Header {
            version: 9,
            ..Header::node(1)
        },
        body: heartbeat().into(),
    };
    let mut raw = heartbeat();
    raw.raw.push(RawIe::new(60, vec![0; 70_000]));
    let inconsistent = heartbeat().with_source_ip_address(SourceIpAddress {
        v4: true,
        ..Default::default()
    });
    for refused in [wide, Message::node(1, raw), Message::node(1, inconsistent)] {
        let mut buffer = vec![1, 2, 3];
        refused.encode_into(&mut buffer).unwrap_err();
        assert_eq!(buffer, [1, 2, 3]);
    }
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
