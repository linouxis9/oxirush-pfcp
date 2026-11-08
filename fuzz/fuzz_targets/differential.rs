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

//! The octets read by this crate and by rs-pfcp 0.5.0, a codec of PFCP written apart from
//! it: where both decode a message, they read the same message type, SEID and sequence
//! number, and each IE that rs-pfcp keeps of the message, by its type, its Enterprise ID
//! and its value, is one that the message has, as many times. A difference is a fault of
//! either, or a reading of TS 29.244 that the two do not share.
#![no_main]

use libfuzzer_sys::fuzz_target;
use oxirush_pfcp::{Message, framing};
use rs_pfcp::message::Message as _;

fuzz_target!(|octets: &[u8]| {
    let Ok(ours) = Message::decode(octets) else {
        return;
    };
    let Ok(theirs) = rs_pfcp::message::parse(octets) else {
        return;
    };
    let header = &ours.header;
    assert_eq!(
        theirs.msg_type_code(),
        ours.body.message_type(),
        "the message type"
    );
    assert_eq!(theirs.seid().map(|seid| seid.0), header.seid, "the SEID");
    assert_eq!(theirs.sequence().0, header.sequence, "the sequence number");

    // The IEs of the message, which framing reads as they are on the wire
    let Ok((_, _, ies)) = framing::message_ies(octets) else {
        return;
    };
    let mut wire: Vec<(u16, Option<u16>, Vec<u8>)> = ies
        .flatten()
        .map(|ie| (ie.ie_type, ie.enterprise_id, ie.value.to_vec()))
        .collect();
    for ie in theirs.all_ies() {
        let kept = (ie.raw_type(), ie.enterprise_id(), ie.payload.clone());
        match wire.iter().position(|ie| *ie == kept) {
            Some(at) => {
                wire.remove(at);
            }
            None => panic!(
                "rs-pfcp keeps an IE that the message does not have, or not as many times: {kept:02x?}"
            ),
        }
    }
});
