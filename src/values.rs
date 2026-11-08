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

//! The fields of the values, and the values that the others are written after: numbers,
//! an enumeration, the layouts with conditional octets, and the Node ID.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};

use crate::Error;
use crate::check::{Deviation, DeviationKind, Rules};
use crate::enums::*;
use crate::ie::{Codec, listed_value};
use crate::macros::{pfcp_bits, pfcp_layout};
use crate::octets::Octets;

/// A field of a layout: its octets, read in network order.
pub(crate) trait Field: Sized {
    /// How many octets it has, when they are fixed.
    #[cfg(feature = "spec")]
    const OCTETS: Option<usize> = None;
    /// The cells narrower than an octet that it lays out, which the test `spec` compares
    /// with the figure: none for a field of whole octets.
    #[cfg(feature = "spec")]
    const CELLS: &'static [NarrowCell] = &[];
    /// Read the field, and step over it.
    fn read(octets: &mut &[u8]) -> Option<Self>;
    /// Write the field, which fits its bits: [`put`] refuses one that does not.
    fn write(&self, out: &mut Vec<u8>);
    /// Its length.
    fn size(&self) -> usize;
    /// What it breaks of the clause of its layout: a value that its table does not name.
    fn check(
        &self,
        _path: &crate::check::Path,
        _clause: &'static str,
        _found: &mut Vec<Deviation>,
    ) {
    }
    /// Whether its length, its number or its type fit the bits that say them: [`put`],
    /// which writes each field of a value, refuses one that does not, and `check()`
    /// reports it.
    fn fits(&self) -> bool {
        true
    }
    /// Its tree.
    #[cfg(feature = "tree")]
    fn to_tree(&self) -> oxirush_utils::tree::Value;
    /// Put its tree in the tree of its value, as the member `name`: a spare field only
    /// where it is set.
    #[cfg(feature = "tree")]
    fn put_member(&self, members: &mut oxirush_utils::tree::Members, name: &'static str) {
        members.put(name, self.to_tree());
    }
    /// Read it from the member `name` of the tree of its value: a spare field is 0 where
    /// the tree leaves it out.
    #[cfg(feature = "tree")]
    fn read_member(
        read: &oxirush_utils::tree::Read<'_>,
        name: &'static str,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        reading.member(read, name, Self::from_tree)
    }
    /// Read it from its tree.
    #[cfg(feature = "tree")]
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused>;
    /// What its tree may hold below it, which a path below it is judged by where a value
    /// lacks it, and in either form of a tree of two: nothing for a field whose tree is a
    /// scalar.
    #[cfg(feature = "tree")]
    const BELOW: &'static crate::paths::Below = &crate::paths::Below::Scalar;
}

/// Write `field`, named `name`, of a value of the IE `ie`: refused where its length, its
/// number or its type do not fit the bits that say them ([`Field::fits`]). Each value
/// writes each of its fields so.
pub(crate) fn put<F: Field>(
    field: &F,
    ie: &'static str,
    name: &'static str,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    if !field.fits() {
        return Err(Error::FieldLength { ie, field: name });
    }
    field.write(out);
    Ok(())
}

/// How a value is laid out, as the crate reads it: what the test `spec` compares with the
/// figure of its clause.
#[cfg(feature = "spec")]
#[doc(hidden)]
#[derive(Debug)]
pub struct Layout {
    /// The fields before its flags, in order.
    pub head: &'static [Member],
    /// Its flags, and the fields of its octets of bits.
    pub bits: &'static [Bits],
    /// The fields after them, in order.
    pub fields: &'static [Member],
}

/// A field of bits: where it is.
#[cfg(feature = "spec")]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bits {
    /// Its name in the figure.
    pub name: &'static str,
    /// Its name in the crate, which the conditions of the fields after it say.
    pub ident: &'static str,
    /// Its octet, from 0 for octet 5 of the IE, the first after the Length.
    pub octet: usize,
    /// Its lowest bit, from 1.
    pub bit: u8,
    /// How many bits it has.
    pub width: u8,
}

/// A field of octets: its octets when they are fixed, its cells narrower than an octet,
/// and when it is there.
#[cfg(feature = "spec")]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Member {
    /// Its name in the figure.
    pub name: &'static str,
    /// How many octets it has, when they are fixed.
    pub octets: Option<usize>,
    /// The cells narrower than an octet that it lays out.
    pub cells: &'static [NarrowCell],
    /// When it is there, as the crate writes it of the flags: `true` for always.
    pub condition: &'static str,
}

/// A cell of a figure narrower than an octet that a field lays out: a value of the low
/// bits of its octet, whose others are spare, or a part of a field of its own layout.
#[cfg(feature = "spec")]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NarrowCell {
    /// Its name in the figure: `None` for the field itself.
    pub name: Option<&'static str>,
    /// Its octet, from 0 for the first of the field.
    pub octet: usize,
    /// Its lowest bit, from 1.
    pub bit: u8,
    /// How many bits it has.
    pub width: u8,
}

/// A rule of clause 8.2 on which flags of a value go together, which `broken` breaks:
/// `rule` says how, in words (`tests/spec/flag-rules.tsv` lists them).
#[inline]
pub(crate) fn flag_rule(
    broken: bool,
    path: &crate::check::Path,
    clause: &'static str,
    rule: &'static str,
    found: &mut Vec<Deviation>,
) {
    if broken {
        found.push(Deviation::new(path, clause, DeviationKind::Rule(rule)));
    }
}

/// The octets of a field whose octets are fixed, or 0.
#[cfg(feature = "spec")]
pub(crate) const fn octets_of(octets: Option<usize>) -> usize {
    match octets {
        Some(octets) => octets,
        None => 0,
    }
}

fn take<const N: usize>(octets: &mut &[u8]) -> Option<[u8; N]> {
    let (taken, rest) = octets.split_first_chunk::<N>()?;
    *octets = rest;
    Some(*taken)
}

macro_rules! number_field {
    ($($t:ty),*) => {$(
        impl Field for $t {
            #[cfg(feature = "spec")]
            const OCTETS: Option<usize> = Some(core::mem::size_of::<$t>());
            fn read(octets: &mut &[u8]) -> Option<Self> {
                take(octets).map(<$t>::from_be_bytes)
            }
            fn write(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.to_be_bytes());
            }
            fn size(&self) -> usize {
                core::mem::size_of::<$t>()
            }
            #[cfg(feature = "tree")]
            fn to_tree(&self) -> oxirush_utils::tree::Value {
                oxirush_utils::tree::unsigned((*self).into())
            }
            #[cfg(feature = "tree")]
            fn from_tree(
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
            ) -> Result<Self, oxirush_utils::tree::Refused> {
                Ok(reading.unsigned(value, 0, <$t>::MAX.into())? as $t)
            }
        }
    )*};
}
number_field!(u8, u16, u32, u64);

/// The signed numbers of the clause, in two's complement.
macro_rules! signed_field {
    ($($t:ty),*) => {$(
        impl Field for $t {
            #[cfg(feature = "spec")]
            const OCTETS: Option<usize> = Some(core::mem::size_of::<$t>());
            fn read(octets: &mut &[u8]) -> Option<Self> {
                take(octets).map(<$t>::from_be_bytes)
            }
            fn write(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.to_be_bytes());
            }
            fn size(&self) -> usize {
                core::mem::size_of::<$t>()
            }
            #[cfg(feature = "tree")]
            fn to_tree(&self) -> oxirush_utils::tree::Value {
                oxirush_utils::tree::signed((*self).into())
            }
            #[cfg(feature = "tree")]
            fn from_tree(
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
            ) -> Result<Self, oxirush_utils::tree::Refused> {
                Ok(reading.signed(value, <$t>::MIN.into(), <$t>::MAX.into())? as $t)
            }
        }
    )*};
}
signed_field!(i32, i64);

/// An enumeration of the tables of values, as a [`Narrow`] field reads it.
pub(crate) trait Narrowable: Copy + Field {
    /// The width of its field, in bits.
    const BITS: u32;
    /// The value of a number.
    fn from_value(value: u8) -> Self;
    /// The number.
    fn value(self) -> u8;
}

/// A value of the low bits of its octet, whose other bits are spare (§8.1.2): a Time Unit
/// of a Packet Rate (§8.2.63), the Node Type of an FQ-CSID (§8.2.43). Its tree is the
/// value, or `{"value": ..., "Spare": ...}` for spare bits that are set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Narrow<E> {
    /// The value.
    pub value: E,
    /// The other bits of the octet, which are spare: zero from a sender.
    pub spare: u8,
}

impl<E> Narrow<E> {
    /// The value, without spare bits.
    pub fn new(value: E) -> Self {
        Self { value, spare: 0 }
    }
}

/// The bits of the octet of a [`Narrow`] value that are its value.
const fn mask<E: Narrowable>() -> u8 {
    ((1u16 << E::BITS) - 1) as u8
}

impl<E: Narrowable> Field for Narrow<E> {
    #[cfg(feature = "spec")]
    const OCTETS: Option<usize> = Some(1);
    #[cfg(feature = "tree")]
    const BELOW: &'static crate::paths::Below = &crate::paths::Below::Object(
        Some("value"),
        &[
            ("value", &crate::paths::Below::Scalar),
            ("Spare", &crate::paths::Below::Scalar),
        ],
    );
    #[cfg(feature = "spec")]
    const CELLS: &'static [NarrowCell] = &[NarrowCell {
        name: None,
        octet: 0,
        bit: 1,
        width: E::BITS as u8,
    }];
    fn read(octets: &mut &[u8]) -> Option<Self> {
        let octet = u8::read(octets)?;
        Some(Self {
            value: E::from_value(octet & mask::<E>()),
            spare: octet & !mask::<E>(),
        })
    }
    fn write(&self, out: &mut Vec<u8>) {
        let (spare, value) = (self.spare & !mask::<E>(), self.value.value() & mask::<E>());
        out.push(crate::octets::together(spare, value));
    }
    fn size(&self) -> usize {
        1
    }
    fn fits(&self) -> bool {
        self.value.value() <= mask::<E>() && self.spare & mask::<E>() == 0
    }
    fn check(&self, path: &crate::check::Path, clause: &'static str, found: &mut Vec<Deviation>) {
        if !self.fits() {
            found.push(Deviation::new(
                path,
                clause,
                DeviationKind::Rule("a value wider than its bits"),
            ));
        }
        if self.spare != 0 {
            found.push(Deviation::new(path, "8.1.2", DeviationKind::SpareBits));
        }
        Field::check(&self.value, path, clause, found);
    }
    #[cfg(feature = "tree")]
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        if self.spare == 0 {
            return self.value.to_tree();
        }
        let mut members = oxirush_utils::tree::Members::new();
        members.put("value", self.value.to_tree());
        members.put("Spare", oxirush_utils::tree::unsigned(self.spare.into()));
        members.finish()
    }
    #[cfg(feature = "tree")]
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        let narrow = match value.is_object() {
            false => Self::new(E::from_tree(value, reading)?),
            true => {
                let read = reading.members(value, &["value", "Spare"])?;
                let spare = reading
                    .optional(&read, "Spare", |value, reading| {
                        reading.unsigned(value, 0, 255)
                    })?
                    .unwrap_or(0) as u8;
                Self {
                    value: reading.member(&read, "value", E::from_tree)?,
                    spare,
                }
            }
        };
        if !narrow.fits() {
            return Err(
                reading.mismatch("a value of its bits, and spare bits of the others", value)
            );
        }
        Ok(narrow)
    }
}

/// A number of the low `BITS` bits of its octet, as a [`Narrow`] field reads it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Number<const BITS: u32>(pub u8);

/// A number of the six low bits of its octet, whose two others are spare: the Paging
/// Policy Indication value and the QFI of a Downlink Data Service Information (§8.2.27), a
/// DSCP value of a DSCP to PPI Mapping Information (§8.2.214).
pub type SixBits = Narrow<Number<6>>;

impl<const BITS: u32> Narrowable for Number<BITS> {
    const BITS: u32 = BITS;
    fn from_value(value: u8) -> Self {
        Self(value)
    }
    fn value(self) -> u8 {
        self.0
    }
}

/// A whole octet; [`Narrow`] keeps its spare bits apart.
impl<const BITS: u32> Field for Number<BITS> {
    #[cfg(feature = "spec")]
    const OCTETS: Option<usize> = Some(1);
    fn read(octets: &mut &[u8]) -> Option<Self> {
        u8::read(octets).map(Self)
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.0);
    }
    fn size(&self) -> usize {
        1
    }
    #[cfg(feature = "tree")]
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        oxirush_utils::tree::unsigned(self.0.into())
    }
    #[cfg(feature = "tree")]
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        u8::from_tree(value, reading).map(Self)
    }
}

/// A number of five octets: a bitrate of MBR and GBR, in kbps.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct U40(pub u64);

impl Field for U40 {
    #[cfg(feature = "spec")]
    const OCTETS: Option<usize> = Some(5);
    fn read(octets: &mut &[u8]) -> Option<Self> {
        let [a, b, c, d, e] = take::<5>(octets)?;
        Some(Self(u64::from_be_bytes([0, 0, 0, a, b, c, d, e])))
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_be_bytes()[3..]);
    }
    fn size(&self) -> usize {
        5
    }
    fn fits(&self) -> bool {
        self.0 < 1 << 40
    }
    fn check(&self, path: &crate::check::Path, clause: &'static str, found: &mut Vec<Deviation>) {
        if !self.fits() {
            found.push(Deviation::new(
                path,
                clause,
                DeviationKind::Rule("a value wider than its bits"),
            ));
        }
    }
    #[cfg(feature = "tree")]
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        oxirush_utils::tree::unsigned(self.0)
    }
    #[cfg(feature = "tree")]
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        Ok(Self(reading.unsigned(value, 0, (1 << 40) - 1)?))
    }
}

/// A VLAN tag of three octets: the C-TAG and S-TAG of Outer Header Creation, the octets 5
/// to 7 of the C-TAG and S-TAG IEs, which `check()` checks as those IEs (§8.2.56).
pub type VlanTag = [u8; 3];

/// Sixteen octets that their clause does not split: an NF Instance ID (a UUID).
pub type OctetArray16 = [u8; 16];

/// Octets of a fixed number, as they are.
impl<const N: usize> Field for [u8; N] {
    #[cfg(feature = "spec")]
    const OCTETS: Option<usize> = Some(N);
    fn read(octets: &mut &[u8]) -> Option<Self> {
        take::<N>(octets)
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
    fn size(&self) -> usize {
        N
    }
    #[cfg(feature = "tree")]
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        oxirush_utils::tree::octets(self)
    }
    #[cfg(feature = "tree")]
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        reading.octet_array::<N>(value)
    }
}

/// A MAC address.
pub type Mac = [u8; 6];

/// Octets after a length of one octet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lv8(pub Octets);

/// Octets after a length of two octets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lv16(pub Octets);

macro_rules! length_value {
    ($($ty:ident $length:ty),*) => {$(
        impl Field for $ty {
            fn read(octets: &mut &[u8]) -> Option<Self> {
                let length = usize::from(<$length as Field>::read(octets)?);
                let (value, rest) = octets.split_at_checked(length)?;
                *octets = rest;
                Some(Self(Octets::copied(value)))
            }
            fn write(&self, out: &mut Vec<u8>) {
                // encode() refuses a value longer than its length can say.
                let length = <$length>::try_from(self.0.len()).unwrap_or(<$length>::MAX);
                out.extend_from_slice(&length.to_be_bytes());
                out.extend_from_slice(&self.0);
            }
            fn size(&self) -> usize {
                core::mem::size_of::<$length>() + self.0.len()
            }
            fn fits(&self) -> bool {
                self.0.len() <= usize::from(<$length>::MAX)
            }
            fn check(&self, path: &crate::check::Path, clause: &'static str, found: &mut Vec<Deviation>) {
                if !self.fits() {
                    found.push(Deviation::new(path, clause, DeviationKind::Rule("more octets than their length can say")));
                }
            }
            #[cfg(feature = "tree")]
            fn to_tree(&self) -> oxirush_utils::tree::Value {
                oxirush_utils::tree::octets(&self.0)
            }
            #[cfg(feature = "tree")]
            fn from_tree(
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
            ) -> Result<Self, oxirush_utils::tree::Refused> {
                let octets = reading.octets(value)?;
                if octets.len() > usize::from(<$length>::MAX) {
                    return Err(reading.mismatch("octets that their length can say", value));
                }
                Ok(Self(octets.into()))
            }
        }
    )*};
}
length_value!(Lv8 u8, Lv16 u16);

/// The octets up to the end of the IE: the last field of a layout whose length its clause
/// does not give.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rest(pub Octets);

impl Field for Rest {
    fn read(octets: &mut &[u8]) -> Option<Self> {
        let all = core::mem::take(octets);
        Some(Self(Octets::copied(all)))
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
    fn size(&self) -> usize {
        self.0.len()
    }
    #[cfg(feature = "tree")]
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        oxirush_utils::tree::octets(&self.0)
    }
    #[cfg(feature = "tree")]
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        reading.octets(value).map(|octets| Self(octets.into()))
    }
}

/// A percentage, from 0 to 100: a receiver takes another value as 0 (§8.2.34, §8.2.126,
/// §8.2.196).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Percent(pub u8);

impl Percent {
    /// The percentage as a receiver takes it: 0 for a value above 100.
    pub const fn effective(self) -> u8 {
        match self.0 {
            0..=100 => self.0,
            _ => 0,
        }
    }
}

impl Field for Percent {
    #[cfg(feature = "spec")]
    const OCTETS: Option<usize> = Some(1);
    fn read(octets: &mut &[u8]) -> Option<Self> {
        u8::read(octets).map(Self)
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.0);
    }
    fn size(&self) -> usize {
        1
    }
    fn check(&self, path: &crate::check::Path, clause: &'static str, found: &mut Vec<Deviation>) {
        if self.0 > 100 {
            found.push(Deviation::new(
                path,
                clause,
                DeviationKind::ReadAs {
                    value: self.0.into(),
                    read: 0,
                },
            ));
        }
    }
    #[cfg(feature = "tree")]
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        oxirush_utils::tree::unsigned(self.0.into())
    }
    #[cfg(feature = "tree")]
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        u8::from_tree(value, reading).map(Self)
    }
}

/// An octet that is spare: zero from a sender, kept as it is. A tree has it where it is
/// set, as `"Spare": 8`, and is 0 without it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Spare(pub u8);

impl Field for Spare {
    #[cfg(feature = "spec")]
    const OCTETS: Option<usize> = Some(1);
    fn read(octets: &mut &[u8]) -> Option<Self> {
        u8::read(octets).map(Self)
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.0);
    }
    fn size(&self) -> usize {
        1
    }
    fn check(&self, path: &crate::check::Path, _clause: &'static str, found: &mut Vec<Deviation>) {
        if self.0 != 0 {
            found.push(Deviation::new(path, "8.1.2", DeviationKind::SpareBits));
        }
    }
    #[cfg(feature = "tree")]
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        oxirush_utils::tree::unsigned(self.0.into())
    }
    #[cfg(feature = "tree")]
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        u8::from_tree(value, reading).map(Self)
    }
    #[cfg(feature = "tree")]
    fn put_member(&self, members: &mut oxirush_utils::tree::Members, name: &'static str) {
        if self.0 != 0 {
            members.put(name, self.to_tree());
        }
    }
    #[cfg(feature = "tree")]
    fn read_member(
        read: &oxirush_utils::tree::Read<'_>,
        name: &'static str,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        let spare = reading.optional(read, name, Self::from_tree)?;
        Ok(spare.unwrap_or_default())
    }
}

/// A number of one octet, then that many values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counted<T>(pub Vec<T>);

impl<T: Field> Field for Counted<T> {
    #[cfg(feature = "tree")]
    const BELOW: &'static crate::paths::Below = T::BELOW;
    fn read(octets: &mut &[u8]) -> Option<Self> {
        let count = u8::read(octets)?;
        let mut values = Vec::with_capacity(usize::from(count).min(octets.len()));
        for _ in 0..count {
            values.push(T::read(octets)?);
        }
        Some(Self(values))
    }
    fn write(&self, out: &mut Vec<u8>) {
        // More values than the number can say are written with the number cut: check()
        // reports it.
        out.push(u8::try_from(self.0.len()).unwrap_or(u8::MAX));
        for value in &self.0 {
            value.write(out);
        }
    }
    fn size(&self) -> usize {
        1 + self.0.iter().map(Field::size).sum::<usize>()
    }
    fn fits(&self) -> bool {
        self.0.len() <= usize::from(u8::MAX) && self.0.iter().all(Field::fits)
    }
    fn check(&self, path: &crate::check::Path, clause: &'static str, found: &mut Vec<Deviation>) {
        if self.0.len() > usize::from(u8::MAX) {
            found.push(Deviation::new(
                path,
                clause,
                DeviationKind::Rule("more values than their number can say"),
            ));
        }
        for value in &self.0 {
            value.check(path, clause, found);
        }
    }
    #[cfg(feature = "tree")]
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        oxirush_utils::tree::Value::Array(self.0.iter().map(Field::to_tree).collect())
    }
    #[cfg(feature = "tree")]
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        let values = reading.list(value, T::from_tree)?;
        if values.len() > usize::from(u8::MAX) {
            return Err(reading.mismatch("at most 255 values", value));
        }
        Ok(Self(values))
    }
}

/// Values up to the end of the IE, each after the other, without their number.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Each<T>(pub Vec<T>);

impl<T: Field> Field for Each<T> {
    #[cfg(feature = "spec")]
    const CELLS: &'static [NarrowCell] = T::CELLS;
    #[cfg(feature = "tree")]
    const BELOW: &'static crate::paths::Below = T::BELOW;
    fn read(octets: &mut &[u8]) -> Option<Self> {
        let mut values = Vec::new();
        while !octets.is_empty() {
            values.push(T::read(octets)?);
        }
        Some(Self(values))
    }
    fn write(&self, out: &mut Vec<u8>) {
        for value in &self.0 {
            value.write(out);
        }
    }
    fn size(&self) -> usize {
        self.0.iter().map(Field::size).sum()
    }
    fn fits(&self) -> bool {
        self.0.iter().all(Field::fits)
    }
    fn check(&self, path: &crate::check::Path, clause: &'static str, found: &mut Vec<Deviation>) {
        for value in &self.0 {
            value.check(path, clause, found);
        }
    }
    #[cfg(feature = "tree")]
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        oxirush_utils::tree::Value::Array(self.0.iter().map(Field::to_tree).collect())
    }
    #[cfg(feature = "tree")]
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        reading.list(value, T::from_tree).map(Self)
    }
}

/// A PLMN of three octets, the MCC and the MNC in the order of TS 24.008 clause 10.5.1.3:
/// `"208-93"` in a tree, or the octets of digits that are not decimal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PlmnId(pub [u8; 3]);

impl PlmnId {
    /// The PLMN, when its digits are decimal.
    pub fn plmn(self) -> Option<oxirush_utils::identity::Plmn> {
        oxirush_utils::identity::Plmn::from_nas_octets(self.0).ok()
    }
}

impl From<oxirush_utils::identity::Plmn> for PlmnId {
    fn from(plmn: oxirush_utils::identity::Plmn) -> Self {
        Self(plmn.to_nas_octets())
    }
}

impl Field for PlmnId {
    #[cfg(feature = "spec")]
    const OCTETS: Option<usize> = Some(3);
    /// Its digits, by two in an octet (TS 24.008 clause 10.5.1.3).
    #[cfg(feature = "spec")]
    const CELLS: &'static [NarrowCell] = &[
        NarrowCell {
            name: Some("MCC digit 2"),
            octet: 0,
            bit: 5,
            width: 4,
        },
        NarrowCell {
            name: Some("MCC digit 1"),
            octet: 0,
            bit: 1,
            width: 4,
        },
        NarrowCell {
            name: Some("MNC digit 3"),
            octet: 1,
            bit: 5,
            width: 4,
        },
        NarrowCell {
            name: Some("MCC digit 3"),
            octet: 1,
            bit: 1,
            width: 4,
        },
        NarrowCell {
            name: Some("MNC digit 2"),
            octet: 2,
            bit: 5,
            width: 4,
        },
        NarrowCell {
            name: Some("MNC digit 1"),
            octet: 2,
            bit: 1,
            width: 4,
        },
    ];
    fn read(octets: &mut &[u8]) -> Option<Self> {
        take(octets).map(Self)
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
    fn size(&self) -> usize {
        3
    }
    #[cfg(feature = "tree")]
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        match self.plmn() {
            Some(plmn) if plmn.to_nas_octets() == self.0 => {
                oxirush_utils::tree::Value::String(alloc::format!("{plmn}"))
            }
            _ => oxirush_utils::tree::octets(&self.0),
        }
    }
    #[cfg(feature = "tree")]
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        if let Some(plmn) = value
            .as_str()
            .and_then(|text| text.parse::<oxirush_utils::identity::Plmn>().ok())
        {
            return Ok(plmn.into());
        }
        reading.octet_array::<3>(value).map(Self)
    }
}

/// An address after its type, of two bits, and its length, of six: an IPv4 address of
/// type 0 and length 4, or an IPv6 address of type 1 and length 16 (§8.2.207). The tree
/// is the address as text, or `{"Address Type": 2, "Address": "0a00"}` for another.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TypedAddress {
    /// The Address Type.
    pub address_type: u8,
    /// The Address, whose length is the Address Length.
    pub address: Vec<u8>,
}

impl TypedAddress {
    /// The address, when its type and its length are those of an IPv4 or IPv6 address.
    pub fn ip(&self) -> Option<core::net::IpAddr> {
        match (self.address_type, self.address.len()) {
            (0, 4) => Some(Ipv4Addr::from(<[u8; 4]>::try_from(&self.address[..]).ok()?).into()),
            (1, 16) => Some(Ipv6Addr::from(<[u8; 16]>::try_from(&self.address[..]).ok()?).into()),
            _ => None,
        }
    }
}

impl From<core::net::IpAddr> for TypedAddress {
    fn from(address: core::net::IpAddr) -> Self {
        match address {
            core::net::IpAddr::V4(address) => Self {
                address_type: 0,
                address: address.octets().to_vec(),
            },
            core::net::IpAddr::V6(address) => Self {
                address_type: 1,
                address: address.octets().to_vec(),
            },
        }
    }
}

impl Field for TypedAddress {
    #[cfg(feature = "tree")]
    const BELOW: &'static crate::paths::Below = &crate::paths::Below::Object(
        Some("Address"),
        &[
            ("Address Type", &crate::paths::Below::Scalar),
            ("Address", &crate::paths::Below::Scalar),
        ],
    );
    #[cfg(feature = "spec")]
    const CELLS: &'static [NarrowCell] = &[
        NarrowCell {
            name: Some("Address Type"),
            octet: 0,
            bit: 7,
            width: 2,
        },
        NarrowCell {
            name: Some("Address Length"),
            octet: 0,
            bit: 1,
            width: 6,
        },
    ];
    fn read(octets: &mut &[u8]) -> Option<Self> {
        let (&first, rest) = octets.split_first()?;
        let (address, rest) = rest.split_at_checked(usize::from(first & 0x3f))?;
        *octets = rest;
        Some(Self {
            address_type: first >> 6,
            address: address.to_vec(),
        })
    }
    fn write(&self, out: &mut Vec<u8>) {
        // encode() refuses a type or an address longer than their bits can say.
        let (address_type, length) = (self.address_type & 0x03, self.address.len().min(0x3f));
        out.push(crate::octets::together(address_type << 6, length as u8));
        out.extend_from_slice(&self.address[..self.address.len().min(0x3f)]);
    }
    fn size(&self) -> usize {
        1 + self.address.len().min(0x3f)
    }
    fn fits(&self) -> bool {
        self.address_type <= 3 && self.address.len() <= 0x3f
    }
    fn check(&self, path: &crate::check::Path, clause: &'static str, found: &mut Vec<Deviation>) {
        if !self.fits() {
            found.push(Deviation::new(
                path,
                clause,
                DeviationKind::Rule("an Address Type or an Address longer than their bits can say"),
            ));
        } else if self.ip().is_none() {
            found.push(Deviation::new(
                path,
                clause,
                DeviationKind::Rule("an address that is neither IPv4 of type 0 nor IPv6 of type 1"),
            ));
        }
    }
    #[cfg(feature = "tree")]
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        if let Some(address) = self.ip() {
            return oxirush_utils::tree::Value::String(alloc::format!("{address}"));
        }
        let mut members = oxirush_utils::tree::Members::new();
        members.put(
            "Address Type",
            oxirush_utils::tree::unsigned(self.address_type.into()),
        );
        members.put("Address", oxirush_utils::tree::octets(&self.address));
        members.finish()
    }
    #[cfg(feature = "tree")]
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        if let Some(text) = value.as_str() {
            return text
                .parse::<core::net::IpAddr>()
                .map(Self::from)
                .map_err(|_| reading.mismatch("an IP address", value));
        }
        let read = reading.members(value, &["Address Type", "Address"])?;
        let address_type = reading.member(&read, "Address Type", |value, reading| {
            reading.unsigned(value, 0, 3)
        })? as u8;
        let address = reading.member(&read, "Address", |value, reading| reading.octets(value))?;
        if address.len() > 0x3f {
            return Err(reading.mismatch("at most 63 octets", value));
        }
        Ok(Self {
            address_type,
            address,
        })
    }
}

/// A number of three octets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct U24(pub u32);

impl Field for U24 {
    #[cfg(feature = "spec")]
    const OCTETS: Option<usize> = Some(3);
    fn read(octets: &mut &[u8]) -> Option<Self> {
        let [a, b, c] = take::<3>(octets)?;
        Some(Self(u32::from_be_bytes([0, a, b, c])))
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0.to_be_bytes()[1..]);
    }
    fn size(&self) -> usize {
        3
    }
    fn fits(&self) -> bool {
        self.0 < 1 << 24
    }
    fn check(&self, path: &crate::check::Path, clause: &'static str, found: &mut Vec<Deviation>) {
        if !self.fits() {
            found.push(Deviation::new(
                path,
                clause,
                DeviationKind::Rule("a value wider than its bits"),
            ));
        }
    }
    #[cfg(feature = "tree")]
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        oxirush_utils::tree::unsigned(self.0.into())
    }
    #[cfg(feature = "tree")]
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        Ok(Self(reading.unsigned(value, 0, 0xff_ffff)? as u32))
    }
}

macro_rules! address_field {
    ($($t:ty, $n:literal);*) => {$(
        impl Field for $t {
            #[cfg(feature = "spec")]
            const OCTETS: Option<usize> = Some($n);
            fn read(octets: &mut &[u8]) -> Option<Self> {
                take::<$n>(octets).map(<$t>::from)
            }
            fn write(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.octets());
            }
            fn size(&self) -> usize {
                $n
            }
            #[cfg(feature = "tree")]
            fn to_tree(&self) -> oxirush_utils::tree::Value {
                oxirush_utils::tree::Value::String(alloc::format!("{self}"))
            }
            #[cfg(feature = "tree")]
            fn from_tree(
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
            ) -> Result<Self, oxirush_utils::tree::Refused> {
                let text = reading.text(value)?;
                text.parse().map_err(|_| reading.mismatch(stringify!($t), value))
            }
        }
    )*};
}
address_field!(Ipv4Addr, 4; Ipv6Addr, 16);

/// A value of one field, then the octets that a later release adds, and the rules of its
/// clause that follow it: a [`pfcp_layout`] of that field, whose tree is the field alone,
/// and `new()` of it.
macro_rules! pfcp_field {
    ($( $(#[$meta:meta])* $ty:ident($t:ty) $field:literal $clause:literal $( check($this:ident, $path:ident, $found:ident) $rules:block )?; )*) => {$(
        crate::macros::pfcp_layout! {
            $(#[$meta])*
            pub struct $ty $clause { fields { value $field: $t } }
            $( check($this, $path, $found) $rules )?
        }

        impl $ty {
            /// The value.
            pub fn new(value: $t) -> Self {
                Self { value, extra: Octets::default() }
            }
        }
    )*};
}

pfcp_field! {
    /// PDR ID (§8.2.36): the Rule ID of a PDR.
    PdrId(u16) "Rule ID" "8.2.36";
    /// Precedence (§8.2.11).
    Precedence(u32) "Precedence value" "8.2.11";
    /// FAR ID (§8.2.74): bit 8 of its first octet says a predefined FAR.
    FarId(u32) "FAR ID value" "8.2.74";
    /// URR ID (§8.2.54): bit 8 of its first octet says a predefined URR.
    UrrId(u32) "URR ID value" "8.2.54";
    /// QER ID (§8.2.75): bit 8 of its first octet says a predefined QER.
    QerId(u32) "QER ID value" "8.2.75";
}

pfcp_bits! {
    /// Source Interface (§8.2.2): where the packets of a PDR come from (Table 8.2.2-1).
    pub struct SourceInterface "8.2.2" octets 1 min 1 {
        interface_value "Interface value": 0 1 4 as SourceInterfaceValue,
    }
}

pfcp_layout! {
    /// F-TEID (§8.2.3): a TEID with its addresses, or a request that the UP function
    /// choose one (CH).
    pub struct FTeid "8.2.3" {
        flags(u8) { chid "CHID": 4, ch "CH": 3, v6 "V6": 2, v4 "V4": 1 }
        teid "TEID": u32 if !ch,
        ipv4 "IPv4 address": Ipv4Addr if v4 && !ch,
        ipv6 "IPv6 address": Ipv6Addr if v6 && !ch,
        choose_id "CHOOSE ID": u8 if chid,
    }
    check(fteid, path, found) {
        if !fteid.v4 && !fteid.v6 {
            found.push(Deviation::new(path, "8.2.3", DeviationKind::Rule("neither V4 nor V6 is set")));
        }
        if fteid.chid && !fteid.ch {
            found.push(Deviation::new(path, "8.2.3", DeviationKind::Rule("CHID is set and CH is not")));
        }
        // With CH, no TEID and no address, whether or not CHID adds a CHOOSE ID: octets
        // of the length of a TEID, and of the addresses that V4 and V6 announce, are
        // those, and other ones of a later release, which the receiver ignores (§8.1.2).
        let teid = [4, 4 + 4 * usize::from(fteid.v4), 4 + 16 * usize::from(fteid.v6)];
        let both = 4 + 4 * usize::from(fteid.v4) + 16 * usize::from(fteid.v6);
        if fteid.ch && (teid.contains(&fteid.extra.len()) || fteid.extra.len() == both) {
            found.push(Deviation::new(path, "8.2.3", DeviationKind::Rule("CH is set, and octets of a TEID or an address follow")));
        }
    }
}

pfcp_layout! {
    /// F-SEID (§8.2.37): a SEID with the addresses of its node.
    pub struct FSeid "8.2.37" {
        flags(u8) { v4 "V4": 2, v6 "V6": 1 }
        seid "SEID": u64,
        ipv4 "IPv4 address": Ipv4Addr if v4,
        ipv6 "IPv6 address": Ipv6Addr if v6,
    }
    check(fseid, path, found) {
        if !fseid.v4 && !fseid.v6 {
            found.push(Deviation::new(path, "8.2.37", DeviationKind::Rule("neither V4 nor V6 is set")));
        }
    }
}

pfcp_layout! {
    /// UE IP Address (§8.2.62): an address of the UE, or a request that the UP function
    /// choose one (CHV4, CHV6).
    pub struct UeIpAddress "8.2.62" {
        flags(u8) {
            ip6pl "IP6PL": 7, chv6 "CHV6": 6, chv4 "CHV4": 5, ipv6d "IPv6D": 4,
            sd "S/D": 3, v4 "V4": 2, v6 "V6": 1,
        }
        ipv4 "IPv4 address": Ipv4Addr if v4 && !chv4,
        ipv6 "IPv6 address": Ipv6Addr if v6 && !chv6,
        ipv6_prefix_delegation_bits "IPv6 Prefix Delegation Bits": u8 if ipv6d,
        ipv6_prefix_length "IPv6 Prefix Length": u8 if ip6pl,
    }
    check(address, path, found) {
        if address.v4 && address.chv4 {
            found.push(Deviation::new(path, "8.2.62", DeviationKind::Rule("V4 and CHV4 are both set")));
        }
        if address.v6 && address.chv6 {
            found.push(Deviation::new(path, "8.2.62", DeviationKind::Rule("V6 and CHV6 are both set")));
        }
        // IPv6D and IP6PL are of an IPv6 address or prefix, and IP6PL of one without IPv6D.
        if address.ipv6d && !address.v6 && !address.chv6 {
            found.push(Deviation::new(path, "8.2.62", DeviationKind::Rule("IPv6D is set and neither V6 nor CHV6 is")));
        }
        if address.ip6pl && !address.v6 && !address.chv6 {
            found.push(Deviation::new(path, "8.2.62", DeviationKind::Rule("IP6PL is set and neither V6 nor CHV6 is")));
        }
        if address.ip6pl && address.ipv6d {
            found.push(Deviation::new(path, "8.2.62", DeviationKind::Rule("IP6PL and IPv6D are both set")));
        }
    }
}

impl FSeid {
    /// An F-SEID of an IPv4 address.
    pub fn ipv4(seid: u64, address: Ipv4Addr) -> Self {
        Self {
            v4: true,
            seid,
            ipv4: Some(address),
            ..Self::default()
        }
    }

    /// An F-SEID of an IPv6 address.
    pub fn ipv6(seid: u64, address: Ipv6Addr) -> Self {
        Self {
            v6: true,
            seid,
            ipv6: Some(address),
            ..Self::default()
        }
    }
}

impl FTeid {
    /// An F-TEID of an IPv4 address.
    pub fn ipv4(teid: u32, address: Ipv4Addr) -> Self {
        Self {
            v4: true,
            teid: Some(teid),
            ipv4: Some(address),
            ..Self::default()
        }
    }

    /// A request that the UP function choose an F-TEID with an IPv4 address.
    pub fn choose_ipv4() -> Self {
        Self {
            v4: true,
            ch: true,
            ..Self::default()
        }
    }
}

/// Node ID (§8.2.38): an IPv4 address, an IPv6 address or an FQDN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeId {
    /// Node ID Type 0.
    Ipv4(Ipv4Addr),
    /// Node ID Type 1.
    Ipv6(Ipv6Addr),
    /// Node ID Type 2: the labels of the FQDN, as RFC 1035 writes them without the last
    /// zero octet.
    Fqdn(Octets),
    /// Any other octets, kept as they are: a Node ID Type that Table 8.2.38-2 has as
    /// spare, spare bits that are set, a value shorter than its type, octets after the
    /// value, an empty FQDN. [`effective`](Self::effective) reads it as a receiver does.
    Other(u8, Octets),
}

impl Codec for NodeId {
    fn decode(octets: &[u8]) -> Option<Self> {
        let (&first, rest) = octets.split_first()?;
        Some(match (first, rest.len()) {
            (0, 4) => Self::Ipv4(Ipv4Addr::from(<[u8; 4]>::try_from(rest).ok()?)),
            (1, 16) => Self::Ipv6(Ipv6Addr::from(<[u8; 16]>::try_from(rest).ok()?)),
            (2, 1..) => Self::Fqdn(Octets::copied(rest)),
            _ => Self::Other(first, Octets::copied(rest)),
        })
    }
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Self::Ipv4(address) => {
                out.push(0);
                out.extend_from_slice(&address.octets());
            }
            Self::Ipv6(address) => {
                out.push(1);
                out.extend_from_slice(&address.octets());
            }
            Self::Fqdn(labels) => {
                out.push(2);
                out.extend_from_slice(labels);
            }
            Self::Other(first, rest) => {
                out.push(*first);
                out.extend_from_slice(rest);
            }
        }
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        1 + match self {
            Self::Ipv4(_) => 4,
            Self::Ipv6(_) => 16,
            Self::Fqdn(labels) => labels.len(),
            Self::Other(_, rest) => rest.len(),
        }
    }
}

impl Rules for NodeId {
    fn check(&self, path: &crate::check::Path, found: &mut Vec<Deviation>) {
        let rule = |rule| Deviation::new(path, "8.2.38", DeviationKind::Rule(rule));
        let (kind, value) = match self {
            Self::Fqdn(labels) => (2, &labels[..]),
            Self::Other(first, rest) => {
                if first & 0xf0 != 0 {
                    found.push(Deviation::new(path, "8.1.2", DeviationKind::SpareBits));
                }
                (first & 0x0f, &rest[..])
            }
            _ => return,
        };
        let broken = match (kind, value.len()) {
            (0, 0..4) | (1, 0..16) => Some("a Node ID value shorter than its type"),
            (0 | 1, _) => None,
            (2, _) => fqdn_broken(value),
            _ => {
                Some("a Node ID Type that Table 8.2.38-2 has as spare: the Node ID cannot be read")
            }
        };
        if let Some(broken) = broken {
            found.push(rule(broken));
        }
    }
}

/// What the labels of an FQDN break of RFC 1035, as §8.2.38 and §8.2.131 have them
/// written: `None` for labels of 1 to 63 octets, each after its length.
fn fqdn_broken(labels: &[u8]) -> Option<&'static str> {
    match labels {
        [] => Some("an FQDN without a label"),
        _ if !fqdn_valid(labels) => Some(
            "labels that are no FQDN of RFC 1035: each of 1 to 63 octets, after its length, and 255 octets at most with the trailing zero byte",
        ),
        _ => None,
    }
}

/// Whether octets are labels of an FQDN as RFC 1035 writes them, without the last zero
/// octet: each of 1 to 63 octets, after its length, and [`FQDN_OCTETS`] at most.
fn fqdn_valid(mut octets: &[u8]) -> bool {
    if octets.len() > FQDN_OCTETS {
        return false;
    }
    while let [length @ 1..=63, rest @ ..] = octets {
        let Some(tail) = rest.get(usize::from(*length)..) else {
            return false;
        };
        octets = tail;
    }
    octets.is_empty()
}

/// The most octets of the labels of an FQDN, without the trailing zero byte: 255 with it
/// (RFC 1035 §2.3.4).
const FQDN_OCTETS: usize = 254;

/// The labels of an FQDN as RFC 1035 writes them, without the last zero octet: `None`
/// for octets that are not labels of 1 to 63 octets, each after its length, or that are
/// more than [`FQDN_OCTETS`].
fn fqdn_labels(mut octets: &[u8]) -> Option<Vec<&[u8]>> {
    if octets.len() > FQDN_OCTETS {
        return None;
    }
    let mut labels = Vec::new();
    while let [length @ 1..=63, rest @ ..] = octets {
        let (label, tail) = rest.split_at_checked(usize::from(*length))?;
        labels.push(label);
        octets = tail;
    }
    (octets.is_empty() && !labels.is_empty()).then_some(labels)
}

/// The labels of `name`, each after its length: `None` for an empty label, a label of
/// more than 63 octets, or more than [`FQDN_OCTETS`] of labels.
fn fqdn_of(name: &str) -> Option<Vec<u8>> {
    if name.len() + 1 > FQDN_OCTETS {
        return None;
    }
    let mut labels = Vec::with_capacity(name.len() + 1);
    for label in name.split('.') {
        let length = u8::try_from(label.len())
            .ok()
            .filter(|length| (1..=63).contains(length))?;
        labels.push(length);
        labels.extend_from_slice(label.as_bytes());
    }
    Some(labels)
}

/// The name of labels, with dots: `None` for labels that are not each of 1 to 63 octets
/// of UTF-8 without a dot, or more than [`FQDN_OCTETS`], which the name would not give
/// back.
fn fqdn_name(octets: &[u8]) -> Option<String> {
    let mut text = String::new();
    for label in fqdn_labels(octets)? {
        let label = core::str::from_utf8(label)
            .ok()
            .filter(|label| !label.contains('.'))?;
        if !text.is_empty() {
            text.push('.');
        }
        text.push_str(label);
    }
    Some(text)
}

/// An FQDN as a DNS message writes it (RFC 1035 §3.1), without the trailing zero byte:
/// its labels, each after its length, the rest of the IE, as the SMF Set ID has it
/// (§8.2.131). Its tree is the name, `"smf.example"`, or `{"octets": ...}` for octets
/// that are no such labels.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fqdn(pub Octets);

impl Fqdn {
    /// The labels of a name, `smf.example`: `None` for a name with an empty label, a
    /// label of more than 63 octets, or of more than 253 octets, whose labels are more
    /// than 255 with the trailing zero byte (RFC 1035 §2.3.4).
    pub fn new(name: &str) -> Option<Self> {
        fqdn_of(name).map(|labels| Self(labels.into()))
    }

    /// The name, its labels with dots: `None` for octets that are no labels of 1 to 63
    /// octets of UTF-8 without a dot, which the name would not give back.
    pub fn name(&self) -> Option<String> {
        fqdn_name(&self.0)
    }
}

impl Field for Fqdn {
    #[cfg(feature = "tree")]
    const BELOW: &'static crate::paths::Below =
        &crate::paths::Below::Object(None, &[("octets", &crate::paths::Below::Scalar)]);
    fn read(octets: &mut &[u8]) -> Option<Self> {
        Some(Self(Octets::copied(core::mem::take(octets))))
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
    fn size(&self) -> usize {
        self.0.len()
    }
    fn check(&self, path: &crate::check::Path, clause: &'static str, found: &mut Vec<Deviation>) {
        if let Some(broken) = fqdn_broken(&self.0) {
            found.push(Deviation::new(path, clause, DeviationKind::Rule(broken)));
        }
    }
    #[cfg(feature = "tree")]
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        use oxirush_utils::tree;
        match self.name() {
            Some(name) => tree::text(&name),
            None => tree::alternative("octets", tree::octets(&self.0)),
        }
    }
    #[cfg(feature = "tree")]
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        if let Some(name) = value.as_str() {
            return Self::new(name).ok_or_else(|| {
                reading.mismatch(
                    "a name of 253 octets at most, of labels of 1 to 63 octets with dots between them",
                    value,
                )
            });
        }
        let (_, content) = reading.alternative(value, &["octets"])?;
        let octets = reading.within("octets", content, |content, reading| {
            reading.octets(content)
        })?;
        Ok(Self(octets.into()))
    }
}

impl NodeId {
    /// The names of its fields.
    pub(crate) const FIELDS: &'static [&'static str] = &["Node ID Type", "Node ID value"];
    /// The members that its tree may have: the FQDN, or the octets of a Node ID that is no
    /// text. The tree of an address is the address alone.
    pub(crate) const MEMBERS: &'static [&'static str] = &["FQDN", "octets"];
    /// What the tree of each field may hold below it: nothing, of scalars alone.
    #[cfg(feature = "tree")]
    pub(crate) const MEMBERS_BELOW: &'static [(&'static str, &'static crate::paths::Below)] = &[];
    /// Read by hand: its layout depends on its type.
    #[doc(hidden)]
    #[cfg(feature = "spec")]
    pub const LAYOUT: Option<&'static Layout> = None;

    /// The Node ID Type (Table 8.2.38-2).
    pub fn node_id_type(&self) -> NodeIdType {
        match self {
            Self::Ipv4(_) => NodeIdType::Ipv4Address,
            Self::Ipv6(_) => NodeIdType::Ipv6Address,
            Self::Fqdn(_) => NodeIdType::Fqdn,
            Self::Other(first, _) => NodeIdType::from_value(first & 0x0f),
        }
    }

    /// The Node ID as its receiver takes it: the spare bits of its type and the octets
    /// after its value ignored (§8.1.2, an Extendable IE); `None` for a spare Node ID
    /// Type, a value shorter than its type, and an empty FQDN.
    pub fn effective(&self) -> Option<Self> {
        let Self::Other(first, rest) = self else {
            return Some(self.clone());
        };
        match (first & 0x0f, &rest[..]) {
            (0, [a, b, c, d, ..]) => Some(Self::Ipv4(Ipv4Addr::new(*a, *b, *c, *d))),
            (1, rest) if rest.len() >= 16 => Some(Self::Ipv6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&rest[..16]).ok()?,
            ))),
            (2, rest) if !rest.is_empty() => Some(Self::Fqdn(Octets::copied(rest))),
            _ => None,
        }
    }

    /// A Node ID of an FQDN from its text, `upf.example`: its labels as RFC 1035 writes
    /// them, each after its length (§8.2.38). `None` for a text with an empty label, a
    /// label of more than 63 octets, or labels of more than 255 octets with the trailing
    /// zero byte that the IE leaves out (RFC 1035 §2.3.4): a text of more than 253.
    pub fn from_fqdn(name: &str) -> Option<Self> {
        fqdn_of(name).map(|labels| Self::Fqdn(labels.into()))
    }

    /// The FQDN as text, its labels with dots: `None` for labels that are not each of 1
    /// to 63 octets of UTF-8 without a dot, or of more than 255 octets with the trailing
    /// zero byte (RFC 1035 §2.3.4), which the text could not give back.
    pub fn fqdn(&self) -> Option<String> {
        let Self::Fqdn(octets) = self else {
            return None;
        };
        fqdn_name(octets)
    }

    #[cfg(feature = "tree")]
    fn encoded(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let _ = Codec::encode(self, &mut out);
        out
    }
}

#[cfg(feature = "serde")]
oxirush_utils::impl_serde!(NodeId);

/// An address as text, or `{"FQDN": "upf.example"}`, or `{"octets": ...}` for another
/// Node ID, its octets after the Length.
#[cfg(feature = "tree")]
impl oxirush_utils::tree::Tree for NodeId {
    const NAME: &'static str = "Node ID";
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        use oxirush_utils::tree;
        match self {
            Self::Ipv4(address) => tree::Value::String(alloc::format!("{address}")),
            Self::Ipv6(address) => tree::Value::String(alloc::format!("{address}")),
            Self::Fqdn(_) | Self::Other(..) => match self.fqdn() {
                Some(text) => tree::alternative("FQDN", tree::text(&text)),
                None => tree::alternative("octets", tree::octets(&self.encoded())),
            },
        }
    }
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        if let Some(text) = value.as_str() {
            if let Ok(address) = text.parse::<Ipv4Addr>() {
                return Ok(Self::Ipv4(address));
            }
            if let Ok(address) = text.parse::<Ipv6Addr>() {
                return Ok(Self::Ipv6(address));
            }
            return Err(reading.mismatch("an IPv4 or IPv6 address, or {\"FQDN\": name}", value));
        }
        let (which, content) = reading.alternative(value, Self::MEMBERS)?;
        match which {
            0 => reading.within("FQDN", content, |content, reading| {
                let name = reading.text(content)?;
                Self::from_fqdn(name).ok_or_else(|| {
                    reading.mismatch(
                        "a name of 253 octets at most, of labels of 1 to 63 octets with dots between them",
                        content,
                    )
                })
            }),
            // The octets of a Node ID that the text does not give: read as they decode.
            _ => reading.within("octets", content, |content, reading| {
                let octets = reading.octets(content)?;
                Self::decode(&octets).ok_or_else(|| reading.mismatch("one octet at least", content))
            }),
        }
    }
}

pfcp_field! {
    /// BAR ID (§8.2.57).
    BarId(u8) "BAR ID value" "8.2.57";
    /// Transport Level Marking (§8.2.12): the ToS/Traffic Class, and its mask, of 0xFC.
    TransportLevelMarking(u16) "ToS/Traffic Class" "8.2.12" check(this, path, found) {
        // The second octet is the mask, "which shall be set to "0xFC"".
        if this.value & 0xff != 0xfc {
            let rule = DeviationKind::Rule("a ToS/Traffic Class mask other than 0xFC");
            found.push(Deviation::new(path, "8.2.12", rule));
        }
    };
    /// Time Threshold (§8.2.14), in seconds.
    TimeThreshold(u32) "Time Threshold" "8.2.14";
    /// Monitoring Time (§8.2.15), in the NTP timestamp of its seconds.
    MonitoringTime(u32) "Monitoring Time" "8.2.15";
    /// Subsequent Time Threshold (§8.2.17), in seconds.
    SubsequentTimeThreshold(u32) "Subsequent Time Threshold" "8.2.17";
    /// Inactivity Detection Time (§8.2.18), in seconds.
    InactivityDetectionTime(u32) "Inactivity Detection Time" "8.2.18";
    /// Measurement Period (§8.2.42), in seconds.
    MeasurementPeriod(u32) "Measurement Period" "8.2.42";
    /// Quota Holding Time (§8.2.48), in seconds.
    QuotaHoldingTime(u32) "Quota Holding Time value" "8.2.48";
    /// Time Quota (§8.2.51), in seconds.
    TimeQuota(u32) "Time Quota value" "8.2.51";
    /// Linked URR ID (§8.2.55).
    LinkedUrrId(u32) "Linked URR ID value" "8.2.55";
    /// QER Correlation ID (§8.2.10).
    QerCorrelationId(u32) "QER Correlation ID value" "8.2.10";
    /// Averaging Window (§8.2.115), in milliseconds.
    AveragingWindow(u32) "Averaging Window" "8.2.115";
}

/// A value that is octets that its clause does not split: a Network Instance, as a
/// domain name or an APN (§8.2.4).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkInstance(pub Octets);

impl NetworkInstance {
    /// The name of its field.
    pub(crate) const FIELDS: &'static [&'static str] = &["Network Instance"];
    /// None: its tree is its octets.
    pub(crate) const MEMBERS: &'static [&'static str] = &[];
    /// What the tree of each field may hold below it: nothing, of scalars alone.
    #[cfg(feature = "tree")]
    pub(crate) const MEMBERS_BELOW: &'static [(&'static str, &'static crate::paths::Below)] = &[];
    /// Its layout.
    #[doc(hidden)]
    #[cfg(feature = "spec")]
    pub const LAYOUT: Option<&'static Layout> = Some(&Layout {
        head: &[],
        bits: &[],
        fields: &[Member {
            name: "Network Instance",
            octets: None,
            cells: &[],
            condition: "true",
        }],
    });
}

impl Codec for NetworkInstance {
    fn decode(octets: &[u8]) -> Option<Self> {
        Some(Self(Octets::copied(octets)))
    }
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.extend_from_slice(&self.0);
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        self.0.len()
    }
}

impl Rules for NetworkInstance {}

#[cfg(feature = "serde")]
oxirush_utils::impl_serde!(NetworkInstance);

#[cfg(feature = "tree")]
impl oxirush_utils::tree::Tree for NetworkInstance {
    const NAME: &'static str = "Network Instance";
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        oxirush_utils::tree::octets(&self.0)
    }
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        reading.octets(value).map(|octets| Self(octets.into()))
    }
}

pfcp_layout! {
    /// MBR (§8.2.8): the maximum bitrates of the uplink and of the downlink, in kbps.
    pub struct Mbr "8.2.8" { fields { ul_mbr "UL MBR": U40, dl_mbr "DL MBR": U40 } }
    /// GBR (§8.2.9): the guaranteed bitrates of the uplink and of the downlink, in kbps.
    pub struct Gbr "8.2.9" { fields { ul_gbr "UL GBR": U40, dl_gbr "DL GBR": U40 } }
}

pfcp_layout! {
    /// Volume Threshold (§8.2.13), in octets.
    pub struct VolumeThreshold "8.2.13" {
        flags(u8) { dlvol "DLVOL": 3, ulvol "ULVOL": 2, tovol "TOVOL": 1 }
        total_volume "Total Volume": u64 if tovol,
        uplink_volume "Uplink Volume": u64 if ulvol,
        downlink_volume "Downlink Volume": u64 if dlvol,
    }
    check(volume, path, found) {
        flag_rule(!(volume.tovol || volume.ulvol || volume.dlvol), path, "8.2.13", "no bit is set", found);
    }
}

pfcp_layout! {
    /// Volume Quota (§8.2.50), in octets.
    pub struct VolumeQuota "8.2.50" {
        flags(u8) { dlvol "DLVOL": 3, ulvol "ULVOL": 2, tovol "TOVOL": 1 }
        total_volume "Total Volume": u64 if tovol,
        uplink_volume "Uplink Volume": u64 if ulvol,
        downlink_volume "Downlink Volume": u64 if dlvol,
    }
    check(volume, path, found) {
        flag_rule(!(volume.tovol || volume.ulvol || volume.dlvol), path, "8.2.50", "no bit is set", found);
    }
}

pfcp_layout! {
    /// Subsequent Volume Threshold (§8.2.16), in octets.
    pub struct SubsequentVolumeThreshold "8.2.16" {
        flags(u8) { dlvol "DLVOL": 3, ulvol "ULVOL": 2, tovol "TOVOL": 1 }
        total_volume "Total Volume": u64 if tovol,
        uplink_volume "Uplink Volume": u64 if ulvol,
        downlink_volume "Downlink Volume": u64 if dlvol,
    }
    check(volume, path, found) {
        flag_rule(!(volume.tovol || volume.ulvol || volume.dlvol), path, "8.2.16", "no bit is set", found);
    }
}

pfcp_layout! {
    /// Outer Header Creation (§8.2.56): the outer headers to create, from the bits of its
    /// description (Table 8.2.56-1), octet 5 in the high octet.
    pub struct OuterHeaderCreation "8.2.56" {
        flags(u16) {
            gtpu_udp_ipv4 "GTP-U/UDP/IPv4": 9, gtpu_udp_ipv6 "GTP-U/UDP/IPv6": 10,
            udp_ipv4 "UDP/IPv4": 11, udp_ipv6 "UDP/IPv6": 12, ipv4_header "IPv4": 13, ipv6_header "IPv6": 14,
            c_tag_header "C-TAG": 15, s_tag_header "S-TAG": 16,
            n19_indication "N19 Indication": 1, n6_indication "N6 Indication": 2,
            low_layer_ssm_and_c_teid "Low Layer SSM and C-TEID": 3,
        }
        teid "TEID": u32 if gtpu_udp_ipv4 || gtpu_udp_ipv6,
        ipv4 "IPv4 Address": Ipv4Addr if gtpu_udp_ipv4 || udp_ipv4 || ipv4_header,
        ipv6 "IPv6 Address": Ipv6Addr if gtpu_udp_ipv6 || udp_ipv6 || ipv6_header,
        port "Port Number": u16 if udp_ipv4 || udp_ipv6,
        c_tag "C-TAG field": VlanTag if c_tag_header,
        s_tag "S-TAG field": VlanTag if s_tag_header,
    }
    check(creation, path, found) {
        // Of its octets 5 and 6: 6/3 alone is an MB-UPF's FSSM FAR (Table 7.5.2.3-5).
        if !(creation.gtpu_udp_ipv4 || creation.gtpu_udp_ipv6 || creation.udp_ipv4 || creation.udp_ipv6 || creation.ipv4_header || creation.ipv6_header || creation.c_tag_header || creation.s_tag_header || creation.n19_indication || creation.n6_indication || creation.low_layer_ssm_and_c_teid) {
            found.push(Deviation::new(path, "8.2.56", DeviationKind::Rule("no bit of the description is set")));
        }
        let (c_tag, s_tag) = (creation.c_tag.as_ref(), creation.s_tag.as_ref());
        crate::values_clauses::check_tags(c_tag.map(|tag| &tag[..]), s_tag.map(|tag| &tag[..]), path, "8.2.56", found);
    }
}

pfcp_bits! {
    /// Apply Action (§8.2.26).
    pub struct ApplyAction "8.2.26" octets 2 min 1 {
        drop "DROP": 0 1 1, forw "FORW": 0 2 1, buff "BUFF": 0 3 1, nocp "NOCP": 0 4 1,
        dupl "DUPL": 0 5 1, ipma "IPMA": 0 6 1, ipmd "IPMD": 0 7 1, dfrt "DFRT": 0 8 1,
        edrt "EDRT": 1 1 1, bdpn "BDPN": 1 2 1, ddpn "DDPN": 1 3 1, fssm "FSSM": 1 4 1, mbsu "MBSU": 1 5 1,
    }
    check(action, path, found) {
        // FSSM and MBSU, alone or together, are one.
        let actions = [action.drop, action.forw, action.buff, action.ipma, action.ipmd, action.fssm || action.mbsu];
        let one = actions.iter().filter(|set| **set).count() == 1;
        flag_rule(!one, path, "8.2.26", "none, or more than one, of DROP, FORW, BUFF, IPMA, IPMD, and FSSM or MBSU is set", found);
        flag_rule((action.nocp || action.bdpn) && !action.buff, path, "8.2.26", "NOCP or BDPN is set and BUFF is not", found);
        flag_rule(action.dfrt && !action.forw, path, "8.2.26", "DFRT is set and FORW is not", found);
    }
}

pfcp_bits! {
    /// Destination Interface (§8.2.24): its Interface value (Table 8.2.24-1).
    pub struct DestinationInterface "8.2.24" octets 1 min 1 {
        interface_value "Interface value": 0 1 4 as DestinationInterfaceValue,
    }
}

pfcp_bits! {
    /// Outer Header Removal (§8.2.64): its description (Table 8.2.64-1), and the GTP-U
    /// extension headers to delete (Table 8.2.64-2), which a later release added.
    pub struct OuterHeaderRemoval "8.2.64" octets 2 min 1 {
        outer_header_removal_description "Outer Header Removal Description": 0 1 8 as OuterHeaderRemovalDescription,
        pdu_session_container "PDU Session Container": 1 1 1,
    }
}

pfcp_bits! {
    /// Measurement Method (§8.2.40).
    pub struct MeasurementMethod "8.2.40" octets 1 min 1 {
        durat "DURAT": 0 1 1, volum "VOLUM": 0 2 1, event "EVENT": 0 3 1,
    }
    check(method, path, found) {
        flag_rule(method.none_set(), path, "8.2.40", "no bit is set", found);
    }
}

pfcp_bits! {
    /// Reporting Triggers (§8.2.19).
    pub struct ReportingTriggers "8.2.19" octets 3 min 2 {
        perio "PERIO": 0 1 1, volth "VOLTH": 0 2 1, timth "TIMTH": 0 3 1, quhti "QUHTI": 0 4 1,
        start "START": 0 5 1, stopt "STOPT": 0 6 1, droth "DROTH": 0 7 1, liusa "LIUSA": 0 8 1,
        volqu "VOLQU": 1 1 1, timqu "TIMQU": 1 2 1, envcl "ENVCL": 1 3 1, macar "MACAR": 1 4 1,
        eveth "EVETH": 1 5 1, evequ "EVEQU": 1 6 1, ipmjl "IPMJL": 1 7 1, quvti "QUVTI": 1 8 1,
        reemr "REEMR": 2 1 1, upint "UPINT": 2 2 1,
    }
    check(triggers, path, found) {
        flag_rule(triggers.none_set(), path, "8.2.19", "no bit is set", found);
    }
}

pfcp_bits! {
    /// Gate Status (§8.2.7): the UL Gate and the DL Gate, 0 OPEN and 1 CLOSED.
    pub struct GateStatus "8.2.7" octets 1 min 1 {
        dl_gate "DL Gate": 0 1 2 as Gate, ul_gate "UL Gate": 0 3 2 as Gate,
    }
}

pfcp_bits! {
    /// QFI (§8.2.89).
    pub struct Qfi "8.2.89" octets 1 min 1 {
        qfi_value "QFI value": 0 1 6,
    }
}

pfcp_bits! {
    /// RQI (§8.2.88).
    pub struct Rqi "8.2.88" octets 1 min 1 {
        rqi "RQI": 0 1 1,
    }
}

pfcp_bits! {
    /// Paging Policy Indicator (§8.2.116).
    pub struct PagingPolicyIndicator "8.2.116" octets 1 min 1 {
        ppi_value "PPI value": 0 1 3,
    }
}

pfcp_bits! {
    /// 3GPP Interface Type (§8.2.118): its Interface Type value (Table 8.2.118-1).
    pub struct InterfaceType3gpp "8.2.118" octets 1 min 1 {
        interface_type_value "Interface Type value": 0 1 6 as InterfaceTypeValue,
    }
}

listed_value!(
    PdrId,
    Precedence,
    FarId,
    UrrId,
    QerId,
    SourceInterface,
    FTeid,
    FSeid,
    UeIpAddress,
    NodeId,
    BarId,
    TransportLevelMarking,
    TimeThreshold,
    MonitoringTime,
    SubsequentTimeThreshold,
    InactivityDetectionTime,
    MeasurementPeriod,
    QuotaHoldingTime,
    TimeQuota,
    LinkedUrrId,
    QerCorrelationId,
    AveragingWindow,
    NetworkInstance,
    Mbr,
    Gbr,
    VolumeThreshold,
    VolumeQuota,
    SubsequentVolumeThreshold,
    OuterHeaderCreation,
    ApplyAction,
    DestinationInterface,
    OuterHeaderRemoval,
    MeasurementMethod,
    ReportingTriggers,
    GateStatus,
    Qfi,
    Rqi,
    PagingPolicyIndicator,
    InterfaceType3gpp,
);

/// A value that is octets that its clause does not split, of the lengths that it gives, if
/// it gives some; `[secret]` for a key or a password, which `Debug` does not print, nor
/// an error of its tree: their number alone.
macro_rules! pfcp_octets {
    ($( $(#[$meta:meta])* $ty:ident $name:literal $clause:literal $(lengths $lengths:pat => $rule:literal)? $([$secret:ident])?; )*) => {$(
        $(#[$meta])*
        #[derive(Clone, Default, PartialEq, Eq)]
        pub struct $ty(pub Octets);

        impl $ty {
            /// The name of its field.
            pub(crate) const FIELDS: &'static [&'static str] = &[$name];
            /// None: its tree is its octets.
            pub(crate) const MEMBERS: &'static [&'static str] = &[];
            /// What the tree of each field may hold below it: nothing, of scalars alone.
            #[cfg(feature = "tree")]
            pub(crate) const MEMBERS_BELOW: &'static [(&'static str, &'static crate::paths::Below)] = &[];
            /// Its layout.
            #[doc(hidden)]
            #[cfg(feature = "spec")]
            pub const LAYOUT: Option<&'static Layout> = Some(&Layout { head: &[], bits: &[], fields: &[Member { name: $name, octets: None, cells: &[], condition: "true" }] });
            /// Whether its octets are a key or a password.
            const SECRET: bool = pfcp_octets!(@secret $($secret)?);
        }

        impl core::fmt::Debug for $ty {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                match Self::SECRET {
                    true => write!(f, concat!(stringify!($ty), "({} octets)"), self.0.len()),
                    false => f.debug_tuple(stringify!($ty)).field(&self.0).finish(),
                }
            }
        }

        impl Codec for $ty {
            fn decode(octets: &[u8]) -> Option<Self> {
                Some(Self(Octets::copied(octets)))
            }
            fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                out.extend_from_slice(&self.0);
                Ok(())
            }
            fn encoded_len(&self) -> usize {
                self.0.len()
            }
        }

        impl Rules for $ty {
            $(
                fn check(&self, path: &crate::check::Path, found: &mut alloc::vec::Vec<crate::check::Deviation>) {
                    crate::values::flag_rule(!matches!(self.0.len(), $lengths), path, $clause, $rule, found);
                }
            )?
        }

        #[cfg(feature = "serde")]
        oxirush_utils::impl_serde!($ty);

        #[cfg(feature = "tree")]
        impl oxirush_utils::tree::Tree for $ty {
            const NAME: &'static str = <$ty as crate::ie::IeType>::TYPE_NAME;
            fn to_tree(&self) -> oxirush_utils::tree::Value {
                oxirush_utils::tree::octets(&self.0)
            }
            fn from_tree(
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
            ) -> Result<Self, oxirush_utils::tree::Refused> {
                let octets = match Self::SECRET {
                    true => reading.secret(|reading| reading.octets(value))?,
                    false => reading.octets(value)?,
                };
                Ok(Self(octets.into()))
            }
        }

        crate::ie::listed_value!($ty);
    )*};
    (@secret) => { false };
    (@secret secret) => { true };
}

pub(crate) use {pfcp_field, pfcp_octets};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::values_clauses::*;
    use crate::values_figures::TunnelPreference;

    /// A field that its bits cannot say is refused, of each kind of field whose bits can
    /// be too few, by `put`, which writes each field of each kind of value: a layout, a
    /// value of one field, the tags of MAC Addresses and the Node Type of an FQ-CSID.
    #[test]
    fn a_field_that_its_bits_cannot_say_is_refused_by_encode() {
        let long = || Octets::from(alloc::vec![1; 256]);
        let address = TypedAddress {
            address_type: 4,
            address: alloc::vec![1; 4],
        };
        // Refused, and nothing written
        fn refused<F: Field>(field: &F) -> bool {
            let mut out = Vec::new();
            let refused = put(field, "IE", "field", &mut out);
            refused
                == Err(Error::FieldLength {
                    ie: "IE",
                    field: "field",
                })
                && out.is_empty()
        }
        assert!(refused(&U24(1 << 24)) && refused(&U40(1 << 40)));
        assert!(refused(&SixBits::new(Number(64))));
        assert!(refused(&Lv8(long())));
        assert!(refused(&Lv16(Octets::from(alloc::vec![1; 65_536]))));
        assert!(refused(&Counted(alloc::vec![0u8; 256])));
        assert!(refused(&Each(alloc::vec![U24(1 << 24)])));
        assert!(refused(&address));
        let ssm = SsmAddress {
            distribution: address.clone(),
            ..SsmAddress::default()
        };
        assert!(refused(&ssm));
        assert!(refused(&DigitsLv8(long())) && refused(&TextLv8(long())));
        assert!(refused(&SecretLv8(long())));
        let out = &mut Vec::new();
        // Each kind of value
        let length = |ie, field| Err(Error::FieldLength { ie, field });
        let preference = TunnelPreference::new(U24(1 << 24));
        assert_eq!(
            preference.encode(out),
            length("Tunnel Preference", "Tunnel Preference value")
        );
        let mbr = Mbr {
            ul_mbr: U40(1 << 40),
            ..Mbr::default()
        };
        assert_eq!(mbr.encode(out), length("MBR", "UL MBR"));
        let detected = MacAddressesDetected {
            c_tag: Some(Lv8(long())),
            ..MacAddressesDetected::default()
        };
        assert_eq!(
            detected.encode(out),
            length("MAC Addresses Detected", "C-TAG")
        );
        let removed = MacAddressesRemoved {
            c_tag: Some(Lv8(Octets::from(alloc::vec![1; 3]))),
            s_tag: Some(Lv8(long())),
            ..MacAddressesRemoved::default()
        };
        assert_eq!(
            removed.encode(out),
            length("MAC Addresses Removed", "S-TAG")
        );
        let fq_csid = FqCsid {
            node_address: Octets::from(alloc::vec![10, 0, 0, 1]),
            node_type: Some(Narrow::new(NodeType::from_value(16))),
            ..FqCsid::default()
        };
        assert_eq!(fq_csid.encode(out), length("FQ-CSID", "Node Type"));
    }

    /// A Number of six bits is, as a field of its own, its whole octet, which a Narrow parts
    /// into the number and the spare bits.
    #[test]
    fn a_number_of_six_bits_as_a_field() {
        let mut octets: &[u8] = &[0x2e, 0xc1];
        assert_eq!(Number::<6>::read(&mut octets), Some(Number(0x2e)));
        assert_eq!(octets, [0xc1]);
        assert_eq!(Number::<6>::read(&mut &[][..]), None);
        let mut out = Vec::new();
        Number::<6>(0xc1).write(&mut out);
        assert_eq!(out, [0xc1]);
        assert_eq!(Number::<6>(0x2e).size(), 1);
        #[cfg(feature = "tree")]
        assert_eq!(
            Field::to_tree(&Number::<6>(46)),
            oxirush_utils::tree::unsigned(46)
        );
    }
}
