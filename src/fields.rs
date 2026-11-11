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

//! The fields of the values of clause 8.2, read in network order: numbers, the narrow
//! values of a few bits, octets after their lengths, lists, addresses, PLMNs, FQDNs, text
//! and digits, and the octets of a key; how a value writes them ([`put`]), and the layout
//! of each value as the test `spec` compares it with its figure.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};

use crate::Error;
use crate::check::{Deviation, DeviationKind};
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
    /// Whether it reads the octets up to the end of the IE, which then has no unknown
    /// octets after it.
    const TO_THE_END: bool = false;
}

/// The names of the fields of a value read by hand, `FIELDS`, and the members of its tree,
/// `MEMBERS`: its fields and its unknown octets.
macro_rules! names {
    ($($name:literal),* $(,)?) => {
        /// The names of its fields.
        pub(crate) const FIELDS: &'static [&'static str] = &[$($name),*];
        /// The members that its tree may have: its fields and its unknown octets.
        pub(crate) const MEMBERS: &'static [&'static str] = &[$($name,)* crate::ie::UNKNOWN_OCTETS];
    };
}
pub(crate) use names;

/// The rule of the fields at the end of a value that are read where octets remain after
/// those before it, as the fields that a later release adds (§8.1.2): a field is there
/// where a later one, or unknown octets (`extra`), are, which would read as it. Of
/// `fields`, each by its name and whether the value has it, the first that is missing so;
/// `None` for none.
pub(crate) fn trailing(fields: &[(&'static str, bool)], extra: &[u8]) -> Option<&'static str> {
    let last = fields.iter().rposition(|(_, there)| *there);
    let read = match extra.is_empty() {
        true => last.unwrap_or_default(),
        false => fields.len(),
    };
    let missing = fields[..read].iter().find(|(_, there)| !there);
    missing.map(|(name, _)| *name)
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
    /// The names of the fields that it reads from octets, or `None` where they do not
    /// decode: the conditions of its fields as its reader takes them.
    pub read: fn(&[u8]) -> Option<Vec<&'static str>>,
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

/// The octets of a Network Instance after a length of two octets: the Network Instance
/// field of Remote GTP-U Peer (§8.2.70), whose tree is that of a Network Instance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameLv16(pub Octets);

macro_rules! length_value {
    ($($ty:ident $length:ty, $tree:ident),*) => {$(
        impl Field for $ty {
            #[cfg(feature = "tree")]
            const BELOW: &'static crate::paths::Below = length_value!(@below $tree);
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
                length_value!(@to_tree $tree &self.0)
            }
            #[cfg(feature = "tree")]
            fn from_tree(
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
            ) -> Result<Self, oxirush_utils::tree::Refused> {
                let octets = length_value!(@from_tree $tree value, reading)?;
                if octets.len() > usize::from(<$length>::MAX) {
                    return Err(reading.mismatch("octets that their length can say", value));
                }
                Ok(Self(octets.into()))
            }
        }
    )*};
    (@to_tree octets $octets:expr) => { oxirush_utils::tree::octets($octets) };
    (@to_tree name $octets:expr) => { crate::values::name_tree($octets, crate::values::NetworkInstance::FIELDS) };
    (@from_tree octets $value:ident, $reading:ident) => { $reading.octets($value) };
    (@from_tree name $value:ident, $reading:ident) => { crate::values::name_from_tree($value, $reading, crate::values::NetworkInstance::FIELDS) };
    (@below octets) => { &crate::paths::Below::Scalar };
    (@below name) => { &crate::paths::Below::Object(None, &[("Network Instance", &crate::paths::Below::Scalar)]) };
}
length_value!(Lv8 u8, octets, Lv16 u16, octets, NameLv16 u16, name);

/// The octets up to the end of the IE: the last field of a layout whose length its clause
/// does not give.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rest(pub Octets);

impl Field for Rest {
    const TO_THE_END: bool = true;
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
    const TO_THE_END: bool = true;
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

/// A length of two octets, then entries up to it, each after the other: the additional
/// flow descriptions, URLs and domain names of PFD Contents (Figures 8.2.39-2, 8.2.39-3
/// and 8.2.39-4). Its tree is the list of them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entries16<T>(pub Vec<T>);

impl<T: Field> Field for Entries16<T> {
    #[cfg(feature = "tree")]
    const BELOW: &'static crate::paths::Below = T::BELOW;
    fn read(octets: &mut &[u8]) -> Option<Self> {
        let length = usize::from(u16::read(octets)?);
        let (mut within, rest) = octets.split_at_checked(length)?;
        *octets = rest;
        let mut entries = Vec::new();
        while !within.is_empty() {
            entries.push(T::read(&mut within)?);
        }
        Some(Self(entries))
    }
    fn write(&self, out: &mut Vec<u8>) {
        // put() refuses entries longer than their length can say.
        let length = self.size() - 2;
        out.extend_from_slice(&u16::try_from(length).unwrap_or(u16::MAX).to_be_bytes());
        for entry in &self.0 {
            entry.write(out);
        }
    }
    fn size(&self) -> usize {
        2 + self.0.iter().map(Field::size).sum::<usize>()
    }
    fn fits(&self) -> bool {
        self.size() - 2 <= usize::from(u16::MAX) && self.0.iter().all(Field::fits)
    }
    fn check(&self, path: &crate::check::Path, clause: &'static str, found: &mut Vec<Deviation>) {
        if !self.fits() {
            let rule = DeviationKind::Rule("more octets than their length can say");
            found.push(Deviation::new(path, clause, rule));
        }
        for entry in &self.0 {
            entry.check(path, clause, found);
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

/// An additional Domain Name of PFD Contents with its Domain Name Protocol, each after
/// its length of two octets (Figure 8.2.39-4), "the same as the Domain Name field and
/// Domain Name Protocol field".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainNameAndProtocol {
    /// The Domain Name.
    pub domain_name: TextLv16,
    /// The Domain Name Protocol.
    pub domain_name_protocol: Lv16,
}

impl Field for DomainNameAndProtocol {
    #[cfg(feature = "tree")]
    const BELOW: &'static crate::paths::Below = &crate::paths::Below::Object(
        None,
        &[
            ("Domain Name", TextLv16::BELOW),
            ("Domain Name Protocol", &crate::paths::Below::Scalar),
        ],
    );
    fn read(octets: &mut &[u8]) -> Option<Self> {
        Some(Self {
            domain_name: TextLv16::read(octets)?,
            domain_name_protocol: Lv16::read(octets)?,
        })
    }
    fn write(&self, out: &mut Vec<u8>) {
        self.domain_name.write(out);
        self.domain_name_protocol.write(out);
    }
    fn size(&self) -> usize {
        self.domain_name.size() + self.domain_name_protocol.size()
    }
    fn fits(&self) -> bool {
        self.domain_name.fits() && self.domain_name_protocol.fits()
    }
    #[cfg(feature = "tree")]
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        let mut members = oxirush_utils::tree::Members::new();
        members.put("Domain Name", self.domain_name.to_tree());
        members.put("Domain Name Protocol", self.domain_name_protocol.to_tree());
        members.finish()
    }
    #[cfg(feature = "tree")]
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        let read = reading.members(value, &["Domain Name", "Domain Name Protocol"])?;
        Ok(Self {
            domain_name: reading.member(&read, "Domain Name", TextLv16::from_tree)?,
            domain_name_protocol: reading.member(&read, "Domain Name Protocol", Lv16::from_tree)?,
        })
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

/// An IPv4 address that a value always has: the DNS Server Address and the NBNS Server
/// Address (§8.2.193, §8.2.194), `0.0.0.0` by default. Its tree is the address, as text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Address(pub Ipv4Addr);

impl Default for Ipv4Address {
    fn default() -> Self {
        Self(Ipv4Addr::UNSPECIFIED)
    }
}

impl From<Ipv4Addr> for Ipv4Address {
    fn from(address: Ipv4Addr) -> Self {
        Self(address)
    }
}

impl Field for Ipv4Address {
    #[cfg(feature = "spec")]
    const OCTETS: Option<usize> = Some(4);
    fn read(octets: &mut &[u8]) -> Option<Self> {
        Ipv4Addr::read(octets).map(Self)
    }
    fn write(&self, out: &mut Vec<u8>) {
        self.0.write(out);
    }
    fn size(&self) -> usize {
        4
    }
    #[cfg(feature = "tree")]
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        self.0.to_tree()
    }
    #[cfg(feature = "tree")]
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        Ipv4Addr::from_tree(value, reading).map(Self)
    }
}

/// What the labels of an FQDN break of RFC 1035, as §8.2.38 and §8.2.131 have them
/// written: `None` for labels of 1 to 63 octets, each after its length.
pub(crate) fn fqdn_broken(labels: &[u8]) -> Option<&'static str> {
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

/// Whether octets are base64-encoded characters, as the `byte` format of OpenAPI that TS
/// 29.571 clause 5.5.2 names has them (IETF RFC 4648 clause 4): groups of four characters
/// of the alphabet, the last with one or two `=` of padding where the octets end short of
/// three.
pub(crate) fn base64(octets: &[u8]) -> bool {
    let padding = octets
        .iter()
        .rev()
        .take(2)
        .take_while(|octet| **octet == b'=');
    let characters = &octets[..octets.len() - padding.count()];
    octets.len().is_multiple_of(4)
        && characters
            .iter()
            .all(|octet| octet.is_ascii_alphanumeric() || matches!(octet, b'+' | b'/'))
}

/// Whether octets are an IPFilterRule as TS 29.212 clause 5.4.2 restricts it for a Flow
/// Description (IETF RFC 6733 clause 4.3.8): `permit out`, the decimal protocol number
/// or `ip`, `from` an address `to` an address, each `any`, `assigned` or an IPv4 or IPv6
/// address with its mask, and each with its ports, decimal numbers or ranges; no option,
/// and no `!` before an address.
pub(crate) fn ip_filter_rule(octets: &[u8]) -> bool {
    let number = |text: &str, most: u32| {
        let digits =
            !text.is_empty() && text.len() <= 5 && text.bytes().all(|b| b.is_ascii_digit());
        digits
            .then(|| text.parse::<u32>().ok())
            .flatten()
            .filter(|number| *number <= most)
    };
    let address = |word: &str| {
        let (address, bits) = match word.split_once('/') {
            Some((address, bits)) => (address, Some(number(bits, 128))),
            None => (word, None),
        };
        match (address.parse::<core::net::IpAddr>(), bits) {
            _ if matches!(word, "any" | "assigned") => true,
            (Ok(_), None) => true,
            (Ok(address), Some(Some(bits))) => bits <= if address.is_ipv4() { 32 } else { 128 },
            _ => false,
        }
    };
    let ports = |word: &str| {
        word.split(',').all(|part| match part.split_once('-') {
            Some((from, to)) => number(from, 65535)
                .zip(number(to, 65535))
                .is_some_and(|(from, to)| from <= to),
            None => number(part, 65535).is_some(),
        })
    };
    let Ok(text) = core::str::from_utf8(octets) else {
        return false;
    };
    let mut words = text.split(' ');
    let start = words.next() == Some("permit") && words.next() == Some("out");
    let protocol = words
        .next()
        .is_some_and(|word| word == "ip" || number(word, 255).is_some());
    let source = words.next() == Some("from") && words.next().is_some_and(address);
    if !(start && protocol && source) {
        return false;
    }
    let mut next = words.next();
    if next.is_some_and(|word| word != "to") {
        if !next.is_some_and(ports) {
            return false;
        }
        next = words.next();
    }
    let destination = next == Some("to") && words.next().is_some_and(address);
    destination && words.next().is_none_or(ports) && words.next().is_none()
}

/// Whether a text is a URL by its generic syntax (IETF RFC 3986 clause 3): a scheme, of a
/// letter and of letters, digits, `+`, `-` and `.`, a colon, and visible characters of
/// ASCII after it.
pub(crate) fn url(text: &str) -> bool {
    let Some((scheme, rest)) = text.split_once(':') else {
        return false;
    };
    let of_scheme = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.');
    scheme
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
        && scheme.bytes().all(of_scheme)
        && !rest.is_empty()
        && rest.bytes().all(|c| c.is_ascii_graphic())
}

/// Whether a text is a SIP URI by its scheme (IETF RFC 3261 clause 19.1.1): `sip:` or
/// `sips:`, in letters of any case, and what a URL has after it.
pub(crate) fn sip_uri(text: &str) -> bool {
    let scheme = text.split(':').next().unwrap_or_default();
    (scheme.eq_ignore_ascii_case("sip") || scheme.eq_ignore_ascii_case("sips")) && url(text)
}

/// Whether octets are a field name of HTTP, a token (IETF RFC 9110 clauses 5.1 and 5.6.2):
/// one or more letters, digits and ``!#$%&'*+-.^_`|~``.
pub(crate) fn http_field_name(octets: &[u8]) -> bool {
    let token = |octet: &u8| octet.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(octet);
    !octets.is_empty() && octets.iter().all(token)
}

/// Whether octets are a field value of HTTP (IETF RFC 9110 clause 5.5): visible characters
/// and the octets above them, with spaces and tabs between them, and none before or after.
pub(crate) fn http_field_value(octets: &[u8]) -> bool {
    let blank = |octet: &u8| matches!(octet, b' ' | b'\t');
    let content = |octet: &u8| blank(octet) || matches!(octet, 0x21..=0x7e | 0x80..);
    octets.iter().all(content)
        && !octets.first().is_some_and(blank)
        && !octets.last().is_some_and(blank)
}

/// Whether labels are a full APN or DNN, of a Network Identifier and an Operator
/// Identifier (TS 23.003 clauses 9.1.1 and 9.1.2): the Operator Identifier "is composed of
/// three labels. The last label (or domain) shall be "gprs"", in letters of any case,
/// after the "at least one label" of the Network Identifier.
pub(crate) fn full_apn(octets: &[u8]) -> bool {
    fqdn_labels(octets).is_some_and(|labels| {
        labels.len() >= 4
            && labels
                .last()
                .is_some_and(|last| last.eq_ignore_ascii_case(b"gprs"))
    })
}

/// The labels of `name`, each after its length: `None` for an empty label, a label of
/// more than 63 octets, or more than [`FQDN_OCTETS`] of labels.
pub(crate) fn fqdn_of(name: &str) -> Option<Vec<u8>> {
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
pub(crate) fn fqdn_name(octets: &[u8]) -> Option<String> {
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
    const TO_THE_END: bool = true;
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

/// A Source Specific IP Multicast Address (§8.2.206): octets 10 to m of the Multicast
/// Transport Information (§8.2.207), the IP Multicast Distribution Address and the IP
/// Source Address, each after its type and its length.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SsmAddress {
    /// The IP Multicast Distribution Address.
    pub distribution: TypedAddress,
    /// The IP Source Address.
    pub source: TypedAddress,
}

impl Field for SsmAddress {
    #[cfg(feature = "tree")]
    const BELOW: &'static crate::paths::Below = &crate::paths::Below::Object(
        None,
        &[
            ("IP Multicast Distribution Address", TypedAddress::BELOW),
            ("IP Source Address", TypedAddress::BELOW),
        ],
    );
    fn read(octets: &mut &[u8]) -> Option<Self> {
        Some(Self {
            distribution: TypedAddress::read(octets)?,
            source: TypedAddress::read(octets)?,
        })
    }
    fn write(&self, out: &mut Vec<u8>) {
        self.distribution.write(out);
        self.source.write(out);
    }
    fn size(&self) -> usize {
        self.distribution.size() + self.source.size()
    }
    fn fits(&self) -> bool {
        self.distribution.fits() && self.source.fits()
    }
    fn check(&self, path: &crate::check::Path, clause: &'static str, found: &mut Vec<Deviation>) {
        self.distribution.check(path, clause, found);
        self.source.check(path, clause, found);
    }
    #[cfg(feature = "tree")]
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        let mut members = oxirush_utils::tree::Members::new();
        members.put(
            "IP Multicast Distribution Address",
            self.distribution.to_tree(),
        );
        members.put("IP Source Address", self.source.to_tree());
        members.finish()
    }
    #[cfg(feature = "tree")]
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        let read = reading.members(
            value,
            &["IP Multicast Distribution Address", "IP Source Address"],
        )?;
        Ok(Self {
            distribution: reading.member(
                &read,
                "IP Multicast Distribution Address",
                TypedAddress::from_tree,
            )?,
            source: reading.member(&read, "IP Source Address", TypedAddress::from_tree)?,
        })
    }
}

// ── Secrets ────────────────────────────────────────────────────────────────

/// Octets of a key or a password that are no text, which `Debug` does not print: their
/// length alone.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretLv8(pub Octets);

impl fmt::Debug for SecretLv8 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SecretLv8({} octets)", self.0.len())
    }
}

impl Field for SecretLv8 {
    fn read(octets: &mut &[u8]) -> Option<Self> {
        Lv8::read(octets).map(|value| Self(value.0))
    }
    fn write(&self, out: &mut Vec<u8>) {
        Lv8(self.0.clone()).write(out);
    }
    fn size(&self) -> usize {
        1 + self.0.len()
    }
    fn fits(&self) -> bool {
        self.0.len() <= usize::from(u8::MAX)
    }
    fn check(&self, path: &crate::check::Path, clause: &'static str, found: &mut Vec<Deviation>) {
        if !self.fits() {
            found.push(Deviation::new(
                path,
                clause,
                crate::check::DeviationKind::Rule("more octets than their length can say"),
            ));
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
        reading
            .secret(|reading| Lv8::from_tree(value, reading))
            .map(|value| Self(value.0))
    }
}

/// A passphrase after a length of one octet, a UTF8String, which `Debug` does not print,
/// nor an error of its tree: the Shared Secret of a Key ID and Shared Secret (§8.2.276).
/// Its tree is the text, or `{"octets": ...}` for octets that are no UTF-8.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretTextLv8(pub Octets);

impl fmt::Debug for SecretTextLv8 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SecretTextLv8({} octets)", self.0.len())
    }
}

impl Field for SecretTextLv8 {
    #[cfg(feature = "tree")]
    const BELOW: &'static crate::paths::Below = TextLv8::BELOW;
    fn read(octets: &mut &[u8]) -> Option<Self> {
        Lv8::read(octets).map(|value| Self(value.0))
    }
    fn write(&self, out: &mut Vec<u8>) {
        Lv8(self.0.clone()).write(out);
    }
    fn size(&self) -> usize {
        1 + self.0.len()
    }
    fn fits(&self) -> bool {
        self.0.len() <= usize::from(u8::MAX)
    }
    fn check(&self, path: &crate::check::Path, clause: &'static str, found: &mut Vec<Deviation>) {
        Lv8(self.0.clone()).check(path, clause, found);
    }
    #[cfg(feature = "tree")]
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        TextLv8(self.0.clone()).to_tree()
    }
    #[cfg(feature = "tree")]
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        reading.secret(|reading| {
            let octets = crate::values::text_from_tree(value, reading, "octets")?;
            if octets.len() > usize::from(u8::MAX) {
                return Err(reading.mismatch("octets that their length can say", value));
            }
            Ok(Self(octets.into()))
        })
    }
}

/// Digits after a length of one octet, as TBCD: an IMSI, an IMEI or an MSISDN, as TS
/// 29.274 §8.3, §8.10 and §8.11 write them. Its tree is the digits, or `{"octets": ...}`
/// for octets that are no TBCD string.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct DigitsLv8(pub Octets);

impl DigitsLv8 {
    /// The digits, as `tbcd::encode` gives back their octets.
    pub fn digits(&self) -> Option<alloc::string::String> {
        let text = oxirush_utils::identity::tbcd::decode(&self.0).ok()?;
        (oxirush_utils::identity::tbcd::encode(&text).ok()? == *self.0).then_some(text)
    }

    /// How many digits it has, when they are TBCD digits of 0 to 9 alone.
    pub(crate) fn decimal(&self) -> Option<usize> {
        let digits = self.digits()?;
        digits
            .bytes()
            .all(|digit| digit.is_ascii_digit())
            .then_some(digits.len())
    }

    /// The octets of `digits`.
    ///
    /// # Errors
    ///
    /// A character that TBCD does not have.
    pub fn new(digits: &str) -> Result<Self, oxirush_utils::identity::Error> {
        oxirush_utils::identity::tbcd::encode(digits).map(|octets| Self(octets.into()))
    }
}

impl fmt::Debug for DigitsLv8 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.digits() {
            Some(digits) => write!(f, "DigitsLv8({digits:?})"),
            None => write!(f, "DigitsLv8({:?})", Octets::copied(&self.0)),
        }
    }
}

/// Text after a length of one octet: a NAI, a SUPI, a GPSI or a PEI, and the Key ID of a
/// Key ID and Shared Secret, a UTF8String (§8.2.276). Its tree is the text, or
/// `{"octets": ...}` for octets that are no UTF-8.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextLv8(pub Octets);

impl TextLv8 {
    /// The text.
    pub fn text(&self) -> Option<&str> {
        core::str::from_utf8(&self.0).ok()
    }
}

impl From<&str> for TextLv8 {
    fn from(text: &str) -> Self {
        Self(Octets::copied(text.as_bytes()))
    }
}

macro_rules! identity_lv8 {
    ($($ty:ident($length:ty) $as_text:ident $from_text:expr),*) => {$(
        impl Field for $ty {
            #[cfg(feature = "tree")]
            const BELOW: &'static crate::paths::Below = &crate::paths::Below::Object(
                None,
                &[("octets", &crate::paths::Below::Scalar)],
            );
            fn read(octets: &mut &[u8]) -> Option<Self> {
                let length = usize::from(<$length as Field>::read(octets)?);
                let (value, rest) = octets.split_at_checked(length)?;
                *octets = rest;
                Some(Self(Octets::copied(value)))
            }
            fn write(&self, out: &mut Vec<u8>) {
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
                    found.push(Deviation::new(path, clause, crate::check::DeviationKind::Rule("more octets than their length can say")));
                }
            }
            #[cfg(feature = "tree")]
            fn to_tree(&self) -> oxirush_utils::tree::Value {
                match self.$as_text() {
                    Some(text) => oxirush_utils::tree::text(&text),
                    None => oxirush_utils::tree::alternative("octets", oxirush_utils::tree::octets(&self.0)),
                }
            }
            #[cfg(feature = "tree")]
            fn from_tree(
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
            ) -> Result<Self, oxirush_utils::tree::Refused> {
                let octets = match value.as_str() {
                    Some(text) => {
                        let from_text: fn(&str) -> Option<Vec<u8>> = $from_text;
                        from_text(text).ok_or_else(|| reading.mismatch(stringify!($ty), value))?
                    }
                    None => {
                        let (_, content) = reading.alternative(value, &["octets"])?;
                        reading.within("octets", content, |content, reading| reading.octets(content))?
                    }
                };
                if octets.len() > usize::from(<$length>::MAX) {
                    return Err(reading.mismatch("octets that their length can say", value));
                }
                Ok(Self(octets.into()))
            }
        }
    )*};
}
identity_lv8!(
    DigitsLv8(u8) digits |text| oxirush_utils::identity::tbcd::encode(text).ok(),
    TextLv8(u8) text_owned |text| Some(text.as_bytes().to_vec()),
    TextLv16(u16) text_owned |text| Some(text.as_bytes().to_vec())
);

impl TextLv8 {
    #[cfg(feature = "tree")]
    fn text_owned(&self) -> Option<alloc::string::String> {
        self.text().map(alloc::string::String::from)
    }
}

/// Text after a length of two octets: a Flow Description, an IPFilterRule of TS 29.212
/// clause 5.4.2, the URL and the Domain Name of PFD Contents (§8.2.39), and the Redirect
/// Server Address and the Other Redirect Server Address of a Redirect Information, a
/// UTF8String (§8.2.20). Its tree is the text, or `{"octets": ...}` for octets that are
/// no UTF-8.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextLv16(pub Octets);

impl TextLv16 {
    /// The text.
    pub fn text(&self) -> Option<&str> {
        core::str::from_utf8(&self.0).ok()
    }

    #[cfg(feature = "tree")]
    fn text_owned(&self) -> Option<alloc::string::String> {
        self.text().map(alloc::string::String::from)
    }
}

impl From<&str> for TextLv16 {
    fn from(text: &str) -> Self {
        Self(Octets::copied(text.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TunnelPreference;
    use crate::ie::Codec;
    use crate::{FqCsid, MacAddressesDetected, MacAddressesRemoved, Mbr, NodeType};

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
