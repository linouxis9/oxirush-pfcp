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
    let seid = FSeid { v4: true, seid: Some(0x1001), ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)), ..Default::default() };
    let pdr = CreatePdr::new_n4(PdrId::new(1), Precedence::new(255), Pdi::new(SourceInterface::new(SourceInterfaceValue::Access)));
    let far = CreateFar::new(FarId::new(1), ApplyAction { forw: true, ..Default::default() });
    let request = SessionEstablishmentRequest::new_n4(NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 1)), seid.clone(), pdr, far);
    let message = Message { header: Header::session(0, 7), body: request.into() };

    let json = serde_json::to_string(&message).unwrap();
    assert!(json.contains(r#""Source Interface":"Access""#), "{json}");
    let back: Message = serde_json::from_str(&json).unwrap();
    assert_eq!(back.encode().unwrap(), message.encode().unwrap());

    let json = serde_json::to_string(&seid).unwrap();
    assert_eq!(json, r#"{"V4":true,"SEID":4097,"IPv4 address":"10.0.0.1"}"#);
    assert_eq!(serde_json::from_str::<FSeid>(&json).unwrap(), seid);
}
