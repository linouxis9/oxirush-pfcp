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

//! Framing-only scans: the IEs of a message or of a grouped IE as slices of its octets,
//! with nothing decoded and nothing copied, for a fast path that reads a few IEs, a proxy
//! that forwards them, or a fuzzer. The codec frames its scopes with the same iterator.
//!
//! ```
//! use oxirush_pfcp::framing;
//!
//! // A Heartbeat Request: its Recovery Time Stamp
//! let octets = [0x20, 0x01, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x00, 0x00, 0x60, 0x00, 0x04, 0xdf, 0xd5, 0x2c, 0x00];
//! let (header, message_type, ies) = framing::message_ies(&octets)?;
//! assert_eq!((header.sequence, message_type), (1, 1));
//! let stamp = ies.map(Result::unwrap).find(|ie| ie.ie_type == 96).unwrap();
//! assert_eq!(stamp.value, [0xdf, 0xd5, 0x2c, 0x00]);
//! # Ok::<(), oxirush_pfcp::Error>(())
//! ```

use crate::Error;
use crate::header::Header;
use crate::ie::{IeFault, VENDOR};

/// One IE, as a slice of the octets that hold it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IeSlice<'a> {
    /// The IE type.
    pub ie_type: u16,
    /// The Length of the IE header: the octets after it, the Enterprise ID included.
    pub length: u16,
    /// The Enterprise ID of a vendor IE that has one.
    pub enterprise_id: Option<u16>,
    /// The value: the octets after the Length, or after the Enterprise ID.
    pub value: &'a [u8],
    content: &'a [u8],
}

impl<'a> IeSlice<'a> {
    /// The IEs of a grouped IE, as slices too.
    pub fn ies(&self) -> Ies<'a> {
        ies(self.value)
    }

    /// The octets after the Length, the Enterprise ID included.
    pub fn content(&self) -> &'a [u8] {
        self.content
    }
}

/// The IEs of a scope, in the order of the wire. After a fault, it ends.
#[derive(Debug, Clone)]
pub struct Ies<'a> {
    rest: &'a [u8],
}

/// The IEs of `octets`: the IEs of a message after its header, or the content of a
/// grouped IE.
pub fn ies(octets: &[u8]) -> Ies<'_> {
    Ies { rest: octets }
}

/// The header, the message type and the IEs of the first message of `octets`, whose
/// Message Length is checked against the octets that it has.
///
/// # Errors
///
/// Octets shorter than a header, and a Message Length that runs past the octets
/// (§7.6.3).
pub fn message_ies(octets: &[u8]) -> Result<(Header, u8, Ies<'_>), Error> {
    let (header, message_type, length) = Header::decode(octets).ok_or(Error::TooShort {
        octets: octets.len(),
    })?;
    let end = 4 + usize::from(length);
    match octets.get(header.encoded_len()..end) {
        Some(content) if end >= header.encoded_len() => Ok((header, message_type, ies(content))),
        _ => Err(Error::MessageLength {
            header,
            message_type,
            length,
            available: octets.len() - 4,
        }),
    }
}

impl<'a> Iterator for Ies<'a> {
    type Item = Result<IeSlice<'a>, IeFault>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let octets = self.rest;
        if octets.is_empty() {
            return None;
        }
        let Some(&[t0, t1, l0, l1]) = octets.first_chunk::<4>() else {
            self.rest = &[];
            return Some(Err(IeFault::HeaderCut {
                octets: octets.len(),
            }));
        };
        let ie_type = u16::from_be_bytes([t0, t1]);
        let length = u16::from_be_bytes([l0, l1]);
        let end = 4 + usize::from(length);
        let Some(content) = octets.get(4..end) else {
            self.rest = &[];
            let available = octets.len() - 4;
            return Some(Err(IeFault::Length {
                ie_type,
                length,
                available,
            }));
        };
        self.rest = &octets[end..];
        let (enterprise_id, value) = match (ie_type >= VENDOR, content) {
            (true, [high, low, value @ ..]) => (Some(u16::from_be_bytes([*high, *low])), value),
            _ => (None, content),
        };
        Some(Ok(IeSlice {
            ie_type,
            length,
            enterprise_id,
            value,
            content,
        }))
    }
}
