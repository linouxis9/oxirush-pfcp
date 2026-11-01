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

//! The PFCP header (TS 29.244 §7.2.2): its flags, the SEID of a session message, the
//! sequence number and the message priority.

/// The length of the header of a node related message (§7.2.2.2).
pub const NODE_HEADER: usize = 8;
/// The length of the header of a session related message (§7.2.2.3).
pub const SESSION_HEADER: usize = 16;

/// The header of a message, without its message type, which is the message's.
///
/// What a sender sets to zero and a receiver ignores is kept as it is received, so that a
/// message encodes back to its octets: `spare` holds bits 5 and 4 of octet 1, and
/// `spare_last` the bits of the last octet that the priority does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The version, bits 8 to 6 of octet 1: 1 (§7.2.2.4.1).
    pub version: u8,
    /// Bits 5 and 4 of octet 1, which are spare.
    pub spare: u8,
    /// The FO flag: another message follows in the datagram (§7.2.1A).
    pub follow_on: bool,
    /// The SEID, after the S flag: a session related message has one (§7.2.2.3).
    pub seid: Option<u64>,
    /// The sequence number, of 24 bits.
    pub sequence: u32,
    /// The message priority, after the MP flag: 0, the highest, to 15 (§7.2.2.4.1).
    pub priority: Option<u8>,
    /// The bits of the last octet of the header that the priority does not have.
    pub spare_last: u8,
    /// A Message Length to write in place of the one of the message: a false length,
    /// which a test sends on purpose. A decoded message never has one: its octets say
    /// their length.
    pub length: Option<u16>,
}

impl Header {
    /// The header of a node related message.
    pub const fn node(sequence: u32) -> Self {
        Self {
            version: 1,
            spare: 0,
            follow_on: false,
            seid: None,
            sequence,
            priority: None,
            spare_last: 0,
            length: None,
        }
    }

    /// The header of a session related message, to the peer's SEID.
    pub const fn session(seid: u64, sequence: u32) -> Self {
        Self {
            seid: Some(seid),
            ..Self::node(sequence)
        }
    }

    /// The length of the header on the wire.
    pub fn len(&self) -> usize {
        match self.seid {
            Some(_) => SESSION_HEADER,
            None => NODE_HEADER,
        }
    }

    /// Never empty: a header has at least eight octets.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Write the header of a message of `message_type` whose IEs have `body` octets, at
    /// the start of `out`, which has room for it.
    pub(crate) fn encode_into(
        &self,
        message_type: u8,
        body: usize,
        out: &mut [u8],
    ) -> Result<(), crate::Error> {
        let (octets, length) = self.octets(message_type, body)?;
        out[..length].copy_from_slice(&octets[..length]);
        Ok(())
    }

    /// The field of the header whose value its bits cannot hold, and the value.
    pub(crate) fn overflow(&self) -> Option<(&'static str, u64)> {
        let fields = [
            ("Version", u64::from(self.version), 7),
            ("Spare", u64::from(self.spare), 3),
            ("Sequence Number", u64::from(self.sequence), 0x00ff_ffff),
            ("Message Priority", self.priority.map_or(0, u64::from), 15),
            (
                "Spare octet",
                u64::from(self.spare_last),
                if self.priority.is_some() { 15 } else { 255 },
            ),
        ];
        fields
            .into_iter()
            .find(|(_, value, most)| value > most)
            .map(|(field, value, _)| (field, value))
    }

    /// The octets of the header, and how many there are.
    fn octets(
        &self,
        message_type: u8,
        body: usize,
    ) -> Result<([u8; SESSION_HEADER], usize), crate::Error> {
        if let Some((field, value)) = self.overflow() {
            return Err(crate::Error::HeaderField { field, value });
        }
        let flags = (self.version & 7) << 5
            | (self.spare & 3) << 3
            | u8::from(self.follow_on) << 2
            | u8::from(self.priority.is_some()) << 1
            | u8::from(self.seid.is_some());
        let length = match self.length {
            Some(length) => length,
            None => {
                u16::try_from(self.len() - 4 + body).map_err(|_| crate::Error::MessageTooLong {
                    message_type,
                    length: self.len() - 4 + body,
                })?
            }
        };
        let mut octets = [0; SESSION_HEADER];
        octets[0] = flags;
        octets[1] = message_type;
        octets[2..4].copy_from_slice(&length.to_be_bytes());
        let mut at = 4;
        if let Some(seid) = self.seid {
            octets[4..12].copy_from_slice(&seid.to_be_bytes());
            at = 12;
        }
        octets[at..at + 3].copy_from_slice(&self.sequence.to_be_bytes()[1..]);
        octets[at + 3] = match self.priority {
            Some(priority) => priority << 4 | self.spare_last & 0x0f,
            None => self.spare_last,
        };
        Ok((octets, at + 4))
    }

    /// Read a header: the header, the message type and the Message Length. `None` for
    /// octets too short for the header that their S flag says.
    pub(crate) fn decode(octets: &[u8]) -> Option<(Self, u8, u16)> {
        let flags = *octets.first()?;
        let session = flags & 1 == 1;
        let length = if session { SESSION_HEADER } else { NODE_HEADER };
        let octets = octets.get(..length)?;
        let message_length = u16::from_be_bytes([octets[2], octets[3]]);
        let (seid, at) = match session {
            true => (Some(u64::from_be_bytes(octets[4..12].try_into().ok()?)), 12),
            false => (None, 4),
        };
        let sequence = u32::from_be_bytes([0, octets[at], octets[at + 1], octets[at + 2]]);
        let last = octets[at + 3];
        let priority = (flags & 2 == 2).then_some(last >> 4);
        let header = Self {
            version: flags >> 5,
            spare: flags >> 3 & 3,
            follow_on: flags & 4 == 4,
            seid,
            sequence,
            priority,
            spare_last: if priority.is_some() {
                last & 0x0f
            } else {
                last
            },
            length: None,
        };
        Some((header, octets[1], message_length))
    }
}
