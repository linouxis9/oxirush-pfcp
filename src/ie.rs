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

//! The information element of TS 29.244 §8.1.1, the IEs that a typed scope keeps as
//! octets, and the order of a scope on the wire.

use alloc::vec::Vec;

use crate::Error;
use crate::octets::Octets;

/// The first IE type of a vendor (§8.1.1): from here an IE has an Enterprise ID.
pub const VENDOR: u16 = 0x8000;

/// What a type of the crate is as an IE: its IE type and its name in Table 8.1.2-1.
/// The registry writes it for each type.
pub trait IeType {
    /// The IE type.
    const IE_TYPE: u16;
    /// Its name in Table 8.1.2-1.
    const TYPE_NAME: &'static str;
}

/// How a value is read from the octets of its IE, after the Length, and written back.
pub trait Codec<'a>: Sized {
    /// The value of the octets, or `None` for octets that are not one: the scope keeps
    /// them as they are.
    fn decode(octets: &'a [u8]) -> Option<Self>;

    /// Decode into the field of a row that is there once: `false`, and the field left
    /// empty, for octets that are no value. A grouped IE decodes in its place.
    #[inline]
    fn decode_into(slot: &mut Option<Self>, octets: &'a [u8]) -> bool {
        *slot = Self::decode(octets);
        slot.is_some()
    }

    /// Decode at the end of the field of a row that is a list.
    #[inline]
    fn decode_push(list: &mut Vec<Self>, octets: &'a [u8]) -> bool {
        match Self::decode(octets) {
            Some(value) => {
                list.push(value);
                true
            }
            None => false,
        }
    }

    /// Write the value.
    ///
    /// # Errors
    ///
    /// A value whose fields disagree with what its flags say, as its clause has them.
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error>;
}

/// An IE that a scope keeps as its octets, in its place: one whose type the table of the
/// scope does not have (§7.6.9) or that no release has, a vendor IE, one of a null
/// length, one whose value does not decode as its type, and one that repeats an IE that
/// the table has once (§7.6.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawIe<'a> {
    /// The IE type.
    pub ie_type: u16,
    /// The Enterprise ID of a vendor IE, which its octets follow.
    pub enterprise_id: Option<u16>,
    /// A Length to write in place of the one of the octets: a false length, which a test
    /// sends on purpose. A decoded IE never has one.
    pub length: Option<u16>,
    /// The content after the Length, or after the Enterprise ID of a vendor IE.
    pub octets: Octets<'a>,
}

impl<'a> RawIe<'a> {
    /// The IE of `ie_type` whose content is `octets`, whatever they are: none for an IE
    /// of a null length.
    pub fn new(ie_type: u16, octets: impl Into<Octets<'a>>) -> Self {
        Self {
            ie_type,
            enterprise_id: None,
            length: None,
            octets: octets.into(),
        }
    }

    /// Whether the IE has a null length.
    pub fn is_null(&self) -> bool {
        self.enterprise_id.is_none() && self.octets.is_empty()
    }

    /// Write the IE.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let at = begin(self.ie_type, out);
        if let Some(enterprise) = self.enterprise_id {
            out.extend_from_slice(&enterprise.to_be_bytes());
        }
        out.extend_from_slice(&self.octets);
        finish(self.ie_type, at, self.length, out)
    }
}

/// Where an IE of a decoded scope went: what the order of a scope keeps, from the first
/// IE that is not where the table has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placed {
    /// The next value of the field of this IE type.
    Field(u16),
    /// The next IE of the scope's raw IEs.
    Raw,
}

/// What a typed scope did with an IE of its octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Placing {
    /// It is the value of its field.
    Placed,
    /// Its row is there as many times as the table allows already.
    Repeated,
    /// Its value does not decode as the type of its row.
    Malformed,
    /// The table has no row of its type.
    Unexpected,
}

/// Why the IEs of a scope do not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IeFault {
    /// Fewer octets than the four of an IE header are left (§7.6.7).
    HeaderCut {
        /// How many there are.
        octets: usize,
    },
    /// The Length of an IE runs past its scope (§7.6.7).
    Length {
        /// The IE type.
        ie_type: u16,
        /// Its Length.
        length: u16,
        /// The octets that the scope has after the IE header.
        available: usize,
    },
}

/// The raw IE of `ie_type` and its content.
pub(crate) fn raw(ie_type: u16, body: &[u8]) -> RawIe<'_> {
    match (ie_type >= VENDOR, body) {
        (true, [high, low, rest @ ..]) => RawIe {
            ie_type,
            enterprise_id: Some(u16::from_be_bytes([*high, *low])),
            length: None,
            octets: Octets::wire(rest),
        },
        _ => RawIe { ie_type, enterprise_id: None, length: None, octets: Octets::wire(body) },
    }
}

impl<'a> crate::octets::IntoOwned for RawIe<'a> {
    type Owned = RawIe<'static>;
    fn into_owned(self) -> RawIe<'static> {
        RawIe { ie_type: self.ie_type, enterprise_id: self.enterprise_id, length: self.length, octets: self.octets.into_owned() }
    }
}

/// Start an IE of `ie_type`: where its Length goes.
pub(crate) fn begin(ie_type: u16, out: &mut Vec<u8>) -> usize {
    out.extend_from_slice(&ie_type.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.len() - 2
}

/// Write the Length of the IE that starts at `at`: `length`, or that of its content.
pub(crate) fn finish(ie_type: u16, at: usize, length: Option<u16>, out: &mut [u8]) -> Result<(), Error> {
    let written = out.len() - at - 2;
    let length = match length {
        Some(length) => length,
        None => u16::try_from(written).map_err(|_| Error::TooLong { ie_type, length: written })?,
    };
    out[at..at + 2].copy_from_slice(&length.to_be_bytes());
    Ok(())
}

/// Write the IE of a value.
pub(crate) fn encode_value<'a, T: IeType + Codec<'a>>(value: &T, out: &mut Vec<u8>) -> Result<(), Error> {
    let at = begin(T::IE_TYPE, out);
    value.encode(out)?;
    finish(T::IE_TYPE, at, None, out)
}
