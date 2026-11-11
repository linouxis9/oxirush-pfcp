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

//! A message and its IEs in a format of serde: their trees.

use std::net::Ipv4Addr;

use oxirush_pfcp::*;

#[test]
fn a_message_and_an_ie_are_their_trees_in_json() {
    let seid = FSeid::ipv4(0x1001, Ipv4Addr::new(10, 0, 0, 1));
    let pdr = CreatePdr::new_n4(
        PdrId::new(1),
        Precedence::new(255),
        Pdi::new(SourceInterface::new(SourceInterfaceValue::Access)),
    );
    let far = CreateFar::new(
        FarId::new(1),
        ApplyAction {
            forw: true,
            ..Default::default()
        },
    );
    let request = SessionEstablishmentRequest::new_n4(
        NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
        seid.clone(),
        pdr,
        far,
    );
    let message = Message::session(0, 7, request);

    let json = serde_json::to_string(&message).unwrap();
    assert!(json.contains(r#""Source Interface":"Access""#), "{json}");
    let back: Message = serde_json::from_str(&json).unwrap();
    assert_eq!(back.encode().unwrap(), message.encode().unwrap());

    let json = serde_json::to_string(&seid).unwrap();
    assert_eq!(json, r#"{"V4":true,"SEID":4097,"IPv4 address":"10.0.0.1"}"#);
    assert_eq!(serde_json::from_str::<FSeid>(&json).unwrap(), seid);
}

/// An error of a tree prints no key, nor does one of serde: a row that holds one, at any
/// depth, is read as a secret, of which a refusal says nothing that is written, whether
/// the row is written as a list where it is once or the reverse, as octets of other
/// digits, as an object of another member, or a grouped IE as its octets in hexadecimal.
#[test]
fn an_error_of_a_tree_prints_no_key() {
    let establishment = |ies: &str| {
        format!(
            r#"{{"message": "PFCP Session Establishment Request", "header": {{"SEID": 0, "Sequence Number": 7}}, "ies": {ies}}}"#
        )
    };
    let association = |ies: &str| {
        format!(
            r#"{{"message": "PFCP Association Setup Request", "header": {{"Sequence Number": 7}}, "ies": {{"Node ID": "10.0.0.1", "Recovery Time Stamp": 1, {ies}}}}}"#
        )
    };
    for written in [
        establishment(
            r#"{"L2TP Tunnel Information": [{"Tunnel Password": {"octets": "7365637265742170617373zz"}}]}"#,
        ),
        establishment(r#"{"L2TP Tunnel Information": ["0139000b7365637265742170617373"]}"#),
        establishment(
            r#"{"L2TP Tunnel Information": {"Tunnel Password": "7365637265742170617373"}}"#,
        ),
        establishment(
            r#"{"L2TP Tunnel Information": [{"Tunnel Password": "7365637265742170617373", "Bogus": 1}]}"#,
        ),
        establishment(
            r#"{"L2TP Tunnel Information": [{"Tunnel Password": {"Tunnel Password value": "73656372657421zz"}}]}"#,
        ),
        establishment(
            r#"{"L2TP Tunnel Information": [{"Tunnel Password": {"x": "7365637265742170617373"}}]}"#,
        ),
        establishment(
            r#"{"L2TP Tunnel Information": [{"octets": "0139000b7365637265742170617373", "length": "x"}]}"#,
        ),
        establishment(
            r#"{"Tunnel Password": {"octets": "7365637265742170617373", "length": "x"}}"#,
        ),
        establishment(
            r#"{"L2TP Session Information": {"L2TP User Authentication": {"Proxy Authen Type Value": 1, "PAR": true, "Proxy Authen Response Value": "7365637265742170617373", "x": 1}}}"#,
        ),
        association(
            r#""N6 Delay Measurement Control Information": [{"Protocol Specific Configuration Parameters": {"Key ID and Shared Secret (OWAMP or TWAMP)": {"Shared Secret": "7365637265742170617373", "Key ID": "01", "x": 1}}}]"#,
        ),
        association(
            r#""N6 Delay Measurement Control Information": [{"Protocol Specific Configuration Parameters": {"Key ID and Shared Secret (OWAMP or TWAMP)": {"Shared Secret": {"octets": "73656372657421zz"}, "Key ID": "01"}}}]"#,
        ),
        association(
            r#""N6 Delay Measurement Control Information": {"Protocol Specific Configuration Parameters": {"HMAC Key (STAMP)": "7365637265742170617373"}}"#,
        ),
    ] {
        let tree: tree::Value = serde_json::from_str(&written).unwrap();
        let error = Message::from_tree(&tree)
            .map(|_| ())
            .expect_err(&written)
            .to_string();
        assert!(!error.contains("736563726574"), "{written}: {error}");
        let error = serde_json::from_str::<Message>(&written)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("736563726574"), "{written}: {error}");
    }
    // What holds no key is still shown
    let written = establishment(r#"{"Create FAR": {"FAR ID": 1}}"#);
    let error = Message::from_tree(&serde_json::from_str(&written).unwrap()).unwrap_err();
    assert!(error.to_string().contains("FAR ID"), "{error}");
}
