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
use crate::check::{Check, Deviation, DeviationKind};
use crate::enums::*;
use crate::ie::{Codec, IeType, listed_value};
use crate::macros::{pfcp_bits, pfcp_layout};
use crate::octets::Octets;

/// A field of a layout: its octets, read in network order.
pub trait Field: Sized {
    /// How many octets it has, when they are fixed.
    const OCTETS: Option<usize> = None;
    /// Read the field, and step over it.
    fn read(octets: &mut &[u8]) -> Option<Self>;
    /// Write the field.
    fn write(&self, out: &mut Vec<u8>);
    /// Its length.
    fn size(&self) -> usize;
    /// What it breaks of the clause of its layout: a value that its table does not name.
    fn check(&self, _path: &crate::check::Path, _clause: &'static str, _found: &mut Vec<Deviation>) {}
    /// Whether its length, its number or its type fit the bits that say them: a value
    /// that does not is refused by `encode()` and reported by `check()`.
    fn fits(&self) -> bool {
        true
    }
    /// Its tree.
    #[cfg(feature = "tree")]
    fn to_tree(&self) -> oxirush_utils::tree::Value;
    /// Read it from its tree.
    #[cfg(feature = "tree")]
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused>;
}

/// How a value is laid out, as the crate reads it: what the test `spec` compares with the
/// figure of its clause.
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

/// A field of octets: its octets when they are fixed, and when it is there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Member {
    /// Its name in the figure.
    pub name: &'static str,
    /// How many octets it has, when they are fixed.
    pub octets: Option<usize>,
    /// When it is there, as the crate writes it of the flags: `true` for always.
    pub condition: &'static str,
}

/// The octets of a field whose octets are fixed, or 0.
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
pub trait Narrowable: Copy + Field {
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

impl<E: Narrowable> Narrow<E> {
    const MASK: u8 = ((1u16 << E::BITS) - 1) as u8;

    /// The value, without spare bits.
    pub fn new(value: E) -> Self {
        Self { value, spare: 0 }
    }
}

impl<E: Narrowable> Field for Narrow<E> {
    const OCTETS: Option<usize> = Some(1);
    fn read(octets: &mut &[u8]) -> Option<Self> {
        let octet = u8::read(octets)?;
        Some(Self { value: E::from_value(octet & Self::MASK), spare: octet & !Self::MASK })
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.spare & !Self::MASK | self.value.value() & Self::MASK);
    }
    fn size(&self) -> usize {
        1
    }
    fn fits(&self) -> bool {
        self.value.value() <= Self::MASK && self.spare & Self::MASK == 0
    }
    fn check(&self, path: &crate::check::Path, clause: &'static str, found: &mut Vec<Deviation>) {
        if !self.fits() {
            found.push(Deviation::new(path, clause, DeviationKind::Rule("a value wider than its bits")));
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
                let spare = reading.optional(&read, 1, |value, reading| reading.unsigned(value, 0, 255))?.unwrap_or(0) as u8;
                Self { value: reading.member(&read, 0, E::from_tree)?, spare }
            }
        };
        if !narrow.fits() {
            return Err(reading.mismatch("a value of its bits, and spare bits of the others", value));
        }
        Ok(narrow)
    }
}

/// A number of five octets: a bitrate of MBR and GBR, in kbps.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct U40(pub u64);

impl Field for U40 {
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

/// A VLAN tag of three octets: the C-TAG and S-TAG of Outer Header Creation.
pub type VlanTag = [u8; 3];

/// Sixteen octets that their clause does not split: an NF Instance ID (a UUID).
pub type OctetArray16 = [u8; 16];

/// Octets of a fixed number, as they are.
impl<const N: usize> Field for [u8; N] {
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
pub struct Lv8(pub Vec<u8>);

/// Octets after a length of two octets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lv16(pub Vec<u8>);

macro_rules! length_value {
    ($($ty:ident $length:ty),*) => {$(
        impl Field for $ty {
            fn read(octets: &mut &[u8]) -> Option<Self> {
                let length = usize::from(<$length as Field>::read(octets)?);
                let (value, rest) = octets.split_at_checked(length)?;
                *octets = rest;
                Some(Self(value.to_vec()))
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
                Ok(Self(octets))
            }
        }
    )*};
}
length_value!(Lv8 u8, Lv16 u16);

/// The octets up to the end of the IE: the last field of a layout whose length its clause
/// does not give.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rest(pub Vec<u8>);

impl Field for Rest {
    fn read(octets: &mut &[u8]) -> Option<Self> {
        let all = core::mem::take(octets);
        Some(Self(all.to_vec()))
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
        reading.octets(value).map(Self)
    }
}

/// A percentage, from 0 to 100: a receiver takes another value as 0 (§8.2.34, §8.2.126,
/// §8.2.196).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Percent(pub u8);

impl Field for Percent {
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
            found.push(Deviation::new(path, clause, DeviationKind::ReadAs { value: self.0.into(), read: 0 }));
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

/// An octet that is spare: zero from a sender, kept as it is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Spare(pub u8);

impl Field for Spare {
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
}

/// A number of one octet, then that many values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counted<T>(pub Vec<T>);

impl<T: Field> Field for Counted<T> {
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
            found.push(Deviation::new(path, clause, DeviationKind::Rule("more values than their number can say")));
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
    const OCTETS: Option<usize> = Some(3);
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
            Some(plmn) if plmn.to_nas_octets() == self.0 => oxirush_utils::tree::Value::String(alloc::format!("{plmn}")),
            _ => oxirush_utils::tree::octets(&self.0),
        }
    }
    #[cfg(feature = "tree")]
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        if let Some(plmn) = value.as_str().and_then(|text| text.parse::<oxirush_utils::identity::Plmn>().ok()) {
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
            core::net::IpAddr::V4(address) => Self { address_type: 0, address: address.octets().to_vec() },
            core::net::IpAddr::V6(address) => Self { address_type: 1, address: address.octets().to_vec() },
        }
    }
}

impl Field for TypedAddress {
    fn read(octets: &mut &[u8]) -> Option<Self> {
        let (&first, rest) = octets.split_first()?;
        let (address, rest) = rest.split_at_checked(usize::from(first & 0x3f))?;
        *octets = rest;
        Some(Self { address_type: first >> 6, address: address.to_vec() })
    }
    fn write(&self, out: &mut Vec<u8>) {
        // encode() refuses a type or an address longer than their bits can say.
        out.push((self.address_type & 0x03) << 6 | (self.address.len().min(0x3f) as u8));
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
            found.push(Deviation::new(path, clause, DeviationKind::Rule("an Address Type or an Address longer than their bits can say")));
        } else if self.ip().is_none() {
            found.push(Deviation::new(path, clause, DeviationKind::Rule("an address that is neither IPv4 of type 0 nor IPv6 of type 1")));
        }
    }
    #[cfg(feature = "tree")]
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        if let Some(address) = self.ip() {
            return oxirush_utils::tree::Value::String(alloc::format!("{address}"));
        }
        let mut members = oxirush_utils::tree::Members::new();
        members.put("Address Type", oxirush_utils::tree::unsigned(self.address_type.into()));
        members.put("Address", oxirush_utils::tree::octets(&self.address));
        members.finish()
    }
    #[cfg(feature = "tree")]
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        if let Some(text) = value.as_str() {
            return text.parse::<core::net::IpAddr>().map(Self::from).map_err(|_| reading.mismatch("an IP address", value));
        }
        let read = reading.members(value, &["Address Type", "Address"])?;
        let address_type = reading.member(&read, 0, |value, reading| reading.unsigned(value, 0, 3))? as u8;
        let address = reading.member(&read, 1, |value, reading| reading.octets(value))?;
        if address.len() > 0x3f {
            return Err(reading.mismatch("at most 63 octets", value));
        }
        Ok(Self { address_type, address })
    }
}

/// A number of three octets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct U24(pub u32);

impl Field for U24 {
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

/// The octets of an IE type that the crate does not read yet, of the IE type `N`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Raw<const N: u16>(pub Octets);

impl<const N: u16> IeType for Raw<N> {
    const IE_TYPE: u16 = N;
    const TYPE_NAME: &'static str = "IE";
}

impl<const N: u16> Codec for Raw<N> {
    fn decode(octets: &[u8]) -> Option<Self> {
        Some(Self(Octets::wire(octets)))
    }
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.extend_from_slice(&self.0);
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        self.0.len()
    }
}

impl<const N: u16> Check for Raw<N> {}

#[cfg(feature = "tree")]
impl<const N: u16> oxirush_utils::tree::Tree for Raw<N> {
    const NAME: &'static str = "IE";
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

/// A value that is one number, then the octets that a later release adds.
macro_rules! pfcp_number {
    ($( $(#[$meta:meta])* $ty:ident($t:ty) $field:literal $clause:literal; )*) => {$(
        $(#[$meta])*
        #[derive(Debug, Clone, Default, PartialEq, Eq)]
        pub struct $ty {
            #[doc = concat!("The ", $field, ".")]
            pub value: $t,
            /// The octets after it, which a later release adds.
            pub extra: Octets,
        }

        impl $ty {
            /// The name of its field.
            pub const FIELDS: &'static [&'static str] = &[$field];
            /// Its layout.
            pub const LAYOUT: Option<&'static Layout> = Some(&Layout {
                head: &[],
                bits: &[],
                fields: &[Member { name: $field, octets: <$t as Field>::OCTETS, condition: "true" }],
            });

            /// The value.
            pub fn new(value: $t) -> Self {
                Self { value, extra: Octets::new() }
            }
        }

        impl Codec for $ty {
            fn decode(mut octets: &[u8]) -> Option<Self> {
                let value = Field::read(&mut octets)?;
                Some(Self { value, extra: Octets::wire(octets) })
            }
            fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                Field::write(&self.value, out);
                out.extend_from_slice(&self.extra);
                Ok(())
            }
            fn encoded_len(&self) -> usize {
                Field::size(&self.value) + self.extra.len()
            }
        }

        impl Check for $ty {
            fn check(&self, path: &crate::check::Path, found: &mut Vec<crate::check::Deviation>) {
                Field::check(&self.value, path, $clause, found);
            }
        }

        #[cfg(feature = "serde")]
        oxirush_utils::impl_serde!($ty);

        /// The number alone, or `{"Rule ID": 1, "extra": "00"}` with the octets of a later
        /// release.
        #[cfg(feature = "tree")]
        impl oxirush_utils::tree::Tree for $ty {
            const NAME: &'static str = <$ty as crate::ie::IeType>::TYPE_NAME;
            fn to_tree(&self) -> oxirush_utils::tree::Value {
                if self.extra.is_empty() {
                    return Field::to_tree(&self.value);
                }
                let mut members = oxirush_utils::tree::Members::new();
                members.put($field, Field::to_tree(&self.value));
                members.put("extra", oxirush_utils::tree::octets(&self.extra));
                members.finish()
            }
            fn from_tree(
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
            ) -> Result<Self, oxirush_utils::tree::Refused> {
                if !value.is_object() {
                    return Ok(Self::new(<$t as Field>::from_tree(value, reading)?));
                }
                let read = reading.members(value, &[$field, "extra"])?;
                Ok(Self {
                    value: reading.member(&read, 0, <$t as Field>::from_tree)?,
                    extra: reading.optional(&read, 1, |value, reading| reading.octets(value))?.map(Octets::from).unwrap_or_default(),
                })
            }
        }
    )*};
}

pfcp_number! {
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

impl SourceInterface {
    /// The interface.
    pub fn new(interface_value: SourceInterfaceValue) -> Self {
        Self { interface_value, ..Self::default() }
    }
}

impl DestinationInterface {
    /// The interface.
    pub fn new(interface_value: DestinationInterfaceValue) -> Self {
        Self { interface_value, ..Self::default() }
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
    }
}

pfcp_layout! {
    /// F-SEID (§8.2.37): a SEID with the addresses of its node.
    pub struct FSeid "8.2.37" {
        flags(u8) { v4 "V4": 2, v6 "V6": 1 }
        seid "SEID": u64 if true,
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
    }
}

impl FTeid {
    /// An F-TEID of an IPv4 address.
    pub fn ipv4(teid: u32, address: Ipv4Addr) -> Self {
        Self { v4: true, teid: Some(teid), ipv4: Some(address), ..Self::default() }
    }

    /// A request that the UP function choose an F-TEID with an IPv4 address.
    pub fn choose_ipv4() -> Self {
        Self { v4: true, ch: true, ..Self::default() }
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
            (2, 1..) => Self::Fqdn(Octets::wire(rest)),
            _ => Self::Other(first, Octets::wire(rest)),
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

impl Check for NodeId {
    fn check(&self, path: &crate::check::Path, found: &mut Vec<Deviation>) {
        let rule = |rule| Deviation::new(path, "8.2.38", DeviationKind::Rule(rule));
        if let Self::Other(first, _) = self
            && first & 0xf0 != 0
        {
            found.push(Deviation::new(path, "8.1.2", DeviationKind::SpareBits));
        }
        let labels = match (self, self.effective()) {
            (_, None) => {
                found.push(rule(match self.node_id_type() {
                    NodeIdType::Ipv4Address | NodeIdType::Ipv6Address => "a Node ID value shorter than its type",
                    NodeIdType::Fqdn => "an FQDN without a label",
                    _ => "a Node ID Type that Table 8.2.38-2 has as spare: the Node ID cannot be read",
                }));
                return;
            }
            (_, Some(Self::Fqdn(labels))) => labels,
            _ => return,
        };
        if fqdn_labels(&labels).is_none() {
            found.push(rule("labels that are no FQDN of RFC 1035: each of 1 to 63 octets, after its length"));
        }
    }
}

/// The labels of an FQDN as RFC 1035 writes them, without the last zero octet: `None`
/// for octets that are not labels of 1 to 63 octets, each after its length.
fn fqdn_labels(mut octets: &[u8]) -> Option<Vec<&[u8]>> {
    let mut labels = Vec::new();
    while let [length @ 1..=63, rest @ ..] = octets {
        let (label, tail) = rest.split_at_checked(usize::from(*length))?;
        labels.push(label);
        octets = tail;
    }
    (octets.is_empty() && !labels.is_empty()).then_some(labels)
}

impl NodeId {
    /// The names of its fields.
    pub const FIELDS: &'static [&'static str] = &["Node ID Type", "Node ID value"];
    /// Read by hand: its layout depends on its type.
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
        let Self::Other(first, rest) = self else { return Some(self.clone()) };
        match (first & 0x0f, &rest[..]) {
            (0, [a, b, c, d, ..]) => Some(Self::Ipv4(Ipv4Addr::new(*a, *b, *c, *d))),
            (1, rest) if rest.len() >= 16 => Some(Self::Ipv6(Ipv6Addr::from(<[u8; 16]>::try_from(&rest[..16]).ok()?))),
            (2, rest) if !rest.is_empty() => Some(Self::Fqdn(Octets::copied(rest))),
            _ => None,
        }
    }

    /// The FQDN as text, its labels with dots: `None` for labels that are not each of 1
    /// to 63 octets of UTF-8 without a dot, which the text could not give back.
    pub fn fqdn(&self) -> Option<String> {
        let Self::Fqdn(octets) = self else { return None };
        let mut text = String::new();
        for label in fqdn_labels(octets)? {
            let label = core::str::from_utf8(label).ok().filter(|label| !label.contains('.'))?;
            if !text.is_empty() {
                text.push('.');
            }
            text.push_str(label);
        }
        Some(text)
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

/// An address as text, or `{"FQDN": "upf.example"}`, or the octets of another Node ID.
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
                None => tree::alternative("Node ID value", tree::octets(&self.encoded())),
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
        let (which, content) = reading.alternative(value, &["FQDN", "Node ID value"])?;
        match which {
            0 => reading.within("FQDN", content, |content, reading| {
                let name = reading.text(content)?;
                let mut labels = Vec::new();
                for label in name.split('.') {
                    let length = u8::try_from(label.len()).ok().filter(|length| (1..=63).contains(length));
                    let Some(length) = length else {
                        return Err(reading.mismatch("a name of labels of 1 to 63 octets, with dots between them", content));
                    };
                    labels.push(length);
                    labels.extend_from_slice(label.as_bytes());
                }
                Ok(Self::Fqdn(labels.into()))
            }),
            // The octets of a Node ID that the text does not give: read as they decode.
            _ => reading.within("Node ID value", content, |content, reading| {
                let octets = reading.octets(content)?;
                Self::decode(&octets).ok_or_else(|| reading.mismatch("one octet at least", content))
            }),
        }
    }
}

pfcp_number! {
    /// BAR ID (§8.2.57).
    BarId(u8) "BAR ID value" "8.2.57";
    /// Transport Level Marking (§8.2.12): the ToS/Traffic Class, and its mask.
    TransportLevelMarking(u16) "ToS/Traffic Class" "8.2.12";
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
    pub const FIELDS: &'static [&'static str] = &["Network Instance"];
    /// Its layout.
    pub const LAYOUT: Option<&'static Layout> = Some(&Layout { head: &[], bits: &[], fields: &[Member { name: "Network Instance", octets: None, condition: "true" }] });
}

impl Codec for NetworkInstance {
    fn decode(octets: &[u8]) -> Option<Self> {
        Some(Self(Octets::wire(octets)))
    }
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.extend_from_slice(&self.0);
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        self.0.len()
    }
}

impl Check for NetworkInstance {}

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

/// A value of fixed fields without flags, then the octets that a later release adds.
macro_rules! pfcp_fields {
    ($( $(#[$meta:meta])* pub struct $ty:ident $clause:literal { $( $field:ident $name:literal : $kind:ty ),* $(,)? } )*) => {$(
        $(#[$meta])*
        #[derive(Debug, Clone, Default, PartialEq, Eq)]
        pub struct $ty {
            $(
                #[doc = concat!("The ", $name, " field.")]
                pub $field: $kind,
            )*
            /// The octets after the fields, which a later release adds.
            pub extra: Octets,
        }

        impl $ty {
            /// The names of its fields.
            pub const FIELDS: &'static [&'static str] = &[$($name),*];
            /// Its layout.
            pub const LAYOUT: Option<&'static Layout> = Some(&Layout {
                head: &[],
                bits: &[],
                fields: &[$(Member { name: $name, octets: <$kind as Field>::OCTETS, condition: "true" }),*],
            });
        }

        impl Codec for $ty {
            fn decode(mut octets: &[u8]) -> Option<Self> {
                $( let $field = <$kind as Field>::read(&mut octets)?; )*
                Some(Self { $($field,)* extra: Octets::wire(octets) })
            }
            fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                $(
                    if !Field::fits(&self.$field) {
                        return Err(Error::FieldLength { ie: <Self as crate::ie::IeType>::TYPE_NAME, field: $name });
                    }
                )*
                $( Field::write(&self.$field, out); )*
                out.extend_from_slice(&self.extra);
                Ok(())
            }
            fn encoded_len(&self) -> usize {
                0 $( + Field::size(&self.$field) )* + self.extra.len()
            }
        }

        impl Check for $ty {
            #[allow(unused_variables)]
            fn check(&self, path: &crate::check::Path, found: &mut Vec<crate::check::Deviation>) {
                $( Field::check(&self.$field, path, $clause, found); )*
            }
        }

        #[cfg(feature = "serde")]
        oxirush_utils::impl_serde!($ty);

        #[cfg(feature = "tree")]
        impl oxirush_utils::tree::Tree for $ty {
            const NAME: &'static str = <Self as crate::ie::IeType>::TYPE_NAME;
            fn to_tree(&self) -> oxirush_utils::tree::Value {
                let mut members = oxirush_utils::tree::Members::new();
                $( members.put($name, Field::to_tree(&self.$field)); )*
                if !self.extra.is_empty() {
                    members.put("extra", oxirush_utils::tree::octets(&self.extra));
                }
                members.finish()
            }
            fn from_tree(
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
            ) -> Result<Self, oxirush_utils::tree::Refused> {
                let read = reading.members(value, &[$($name,)* "extra"])?;
                let mut at = 0;
                $(
                    let $field = reading.member(&read, at, <$kind as Field>::from_tree)?;
                    at += 1;
                )*
                let extra = reading.optional(&read, at, |value, reading| reading.octets(value))?;
                Ok(Self { $($field,)* extra: extra.map(Octets::from).unwrap_or_default() })
            }
        }
    )*};
}

pfcp_fields! {
    /// MBR (§8.2.8): the maximum bitrates of the uplink and of the downlink, in kbps.
    pub struct Mbr "8.2.8" { ul_mbr "UL MBR": U40, dl_mbr "DL MBR": U40 }
    /// GBR (§8.2.9): the guaranteed bitrates of the uplink and of the downlink, in kbps.
    pub struct Gbr "8.2.9" { ul_gbr "UL GBR": U40, dl_gbr "DL GBR": U40 }
}

pfcp_layout! {
    /// Volume Threshold (§8.2.13), in octets.
    pub struct VolumeThreshold "8.2.13" {
        flags(u8) { dlvol "DLVOL": 3, ulvol "ULVOL": 2, tovol "TOVOL": 1 }
        total_volume "Total Volume": u64 if tovol,
        uplink_volume "Uplink Volume": u64 if ulvol,
        downlink_volume "Downlink Volume": u64 if dlvol,
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
}

pfcp_layout! {
    /// Subsequent Volume Threshold (§8.2.16), in octets.
    pub struct SubsequentVolumeThreshold "8.2.16" {
        flags(u8) { dlvol "DLVOL": 3, ulvol "ULVOL": 2, tovol "TOVOL": 1 }
        total_volume "Total Volume": u64 if tovol,
        uplink_volume "Uplink Volume": u64 if ulvol,
        downlink_volume "Downlink Volume": u64 if dlvol,
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
        if !(creation.gtpu_udp_ipv4 || creation.gtpu_udp_ipv6 || creation.udp_ipv4 || creation.udp_ipv6 || creation.ipv4_header || creation.ipv6_header || creation.c_tag_header || creation.s_tag_header) {
            found.push(Deviation::new(path, "8.2.56", DeviationKind::Rule("no bit of the description is set")));
        }
    }
}

pfcp_bits! {
    /// Apply Action (§8.2.26).
    pub struct ApplyAction "8.2.26" octets 2 min 1 {
        drop "DROP": 0 1 1, forw "FORW": 0 2 1, buff "BUFF": 0 3 1, nocp "NOCP": 0 4 1,
        dupl "DUPL": 0 5 1, ipma "IPMA": 0 6 1, ipmd "IPMD": 0 7 1, dfrt "DFRT": 0 8 1,
        edrt "EDRT": 1 1 1, bdpn "BDPN": 1 2 1, ddpn "DDPN": 1 3 1, fssm "FSSM": 1 4 1, mbsu "MBSU": 1 5 1,
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
    PdrId, Precedence, FarId, UrrId, QerId, SourceInterface, FTeid, FSeid, UeIpAddress, NodeId,
    BarId, TransportLevelMarking, TimeThreshold, MonitoringTime, SubsequentTimeThreshold,
    InactivityDetectionTime, MeasurementPeriod, QuotaHoldingTime, TimeQuota, LinkedUrrId,
    QerCorrelationId, AveragingWindow, NetworkInstance, Mbr, Gbr, VolumeThreshold, VolumeQuota,
    SubsequentVolumeThreshold, OuterHeaderCreation, ApplyAction, DestinationInterface,
    OuterHeaderRemoval, MeasurementMethod, ReportingTriggers, GateStatus, Qfi, Rqi,
    PagingPolicyIndicator, InterfaceType3gpp,
);

impl<const N: u16> crate::ie::Listed for Raw<N> {
    type List = crate::list::List<Self>;
    type Slot = Option<Self>;
    fn decode_slot(slot: &mut Self::Slot, octets: &[u8]) -> bool {
        *slot = Some(Self(Octets::wire(octets)));
        true
    }
    #[inline]
    fn decode_push(list: &mut Self::List, octets: &[u8]) -> bool {
        list.push(Self(Octets::wire(octets)));
        true
    }
}

/// A value that is octets that its clause does not split.
macro_rules! pfcp_octets {
    ($( $(#[$meta:meta])* $ty:ident $name:literal $clause:literal; )*) => {$(
        $(#[$meta])*
        #[derive(Debug, Clone, Default, PartialEq, Eq)]
        pub struct $ty(pub Octets);

        impl $ty {
            /// The name of its field.
            pub const FIELDS: &'static [&'static str] = &[$name];
            /// Its layout.
            pub const LAYOUT: Option<&'static Layout> = Some(&Layout { head: &[], bits: &[], fields: &[Member { name: $name, octets: None, condition: "true" }] });
        }

        impl Codec for $ty {
            fn decode(octets: &[u8]) -> Option<Self> {
                Some(Self(Octets::wire(octets)))
            }
            fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                out.extend_from_slice(&self.0);
                Ok(())
            }
            fn encoded_len(&self) -> usize {
                self.0.len()
            }
        }

        impl Check for $ty {}

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
                reading.octets(value).map(|octets| Self(octets.into()))
            }
        }

        crate::ie::listed_value!($ty);
    )*};
}

pub(crate) use {pfcp_fields, pfcp_number, pfcp_octets};
