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

//! Any octets: a datagram that decodes encodes back to its octets, byte for byte, and its
//! check and its framing do not panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use oxirush_pfcp::{Message, framing};

fuzz_target!(|octets: &[u8]| {
    if let Ok(messages) = Message::decode_datagram(octets) {
        let mut again = Vec::new();
        for message in &messages {
            let _ = message.check();
            again.extend(message.encode().expect("a decoded message encodes"));
        }
        assert_eq!(again, octets[..again.len()], "decode then encode");
    }
    if let Ok((_, _, ies)) = framing::message_ies(octets) {
        for ie in ies.flatten() {
            let _ = ie.ies().count();
        }
    }
});
