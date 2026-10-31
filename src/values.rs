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

//! The values of the IE types that the spike reads: numbers, an enumeration, the layouts
//! with conditional octets, and the Node ID.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};

use crate::Error;
use crate::check::{Check, Deviation, DeviationKind};
use crate::ie::{Codec, IeType, listed_value};
use crate::macros::{pfcp_bits, pfcp_layout};
use crate::octets::{IntoOwned, Octets};

/// A field of a layout: its octets, read in network order.
pub trait Field: Sized {
    /// Read the field, and step over it.
    fn read(octets: &mut &[u8]) -> Option<Self>;
    /// Write the field.
    fn write(&self, out: &mut Vec<u8>);
    /// Its length.
    fn size(&self) -> usize;
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

fn take<const N: usize>(octets: &mut &[u8]) -> Option<[u8; N]> {
    let (taken, rest) = octets.split_first_chunk::<N>()?;
    *octets = rest;
    Some(*taken)
}

macro_rules! number_field {
    ($($t:ty),*) => {$(
        impl Field for $t {
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

/// A number of five octets: a bitrate of MBR and GBR, in kbps.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct U40(pub u64);

impl Field for U40 {
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

impl Field for [u8; 3] {
    fn read(octets: &mut &[u8]) -> Option<Self> {
        take::<3>(octets)
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
    fn size(&self) -> usize {
        3
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
        reading.octet_array::<3>(value)
    }
}

macro_rules! address_field {
    ($($t:ty, $n:literal);*) => {$(
        impl Field for $t {
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
pub struct Raw<'a, const N: u16>(pub Octets<'a>);

impl<const N: u16> IeType for Raw<'_, N> {
    const IE_TYPE: u16 = N;
    const TYPE_NAME: &'static str = "IE";
}

impl<'a, const N: u16> Codec<'a> for Raw<'a, N> {
    fn decode(octets: &'a [u8]) -> Option<Self> {
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

impl<const N: u16> Check for Raw<'_, N> {}

impl<'a, const N: u16> IntoOwned for Raw<'a, N> {
    type Owned = Raw<'static, N>;
    fn into_owned(self) -> Raw<'static, N> {
        Raw(self.0.into_owned())
    }
}

#[cfg(feature = "tree")]
impl<const N: u16> oxirush_utils::tree::Tree for Raw<'_, N> {
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
        pub struct $ty<'a> {
            #[doc = concat!("The ", $field, ".")]
            pub value: $t,
            /// The octets after it, which a later release adds.
            pub extra: Octets<'a>,
        }

        impl $ty<'_> {
            /// The value.
            pub fn new(value: $t) -> Self {
                Self { value, extra: Octets::new() }
            }
        }

        impl<'a> IntoOwned for $ty<'a> {
            type Owned = $ty<'static>;
            fn into_owned(self) -> $ty<'static> {
                $ty { value: self.value, extra: self.extra.into_owned() }
            }
        }

        impl<'a> Codec<'a> for $ty<'a> {
            fn decode(mut octets: &'a [u8]) -> Option<Self> {
                let value = Field::read(&mut octets)?;
                Some(Self { value, extra: Octets::wire(octets) })
            }
            fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                Field::write(&self.value, out);
                out.extend_from_slice(&self.extra);
                Ok(())
            }
            fn encoded_len(&self) -> usize {
                core::mem::size_of::<$t>() + self.extra.len()
            }
        }

        impl Check for $ty<'_> {}

        /// The number alone, or `{"Rule ID": 1, "extra": "00"}` with the octets of a later
        /// release.
        #[cfg(feature = "tree")]
        impl oxirush_utils::tree::Tree for $ty<'_> {
            const NAME: &'static str = <$ty<'static> as IeType>::TYPE_NAME;
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

/// The Interface value of a Source Interface (Table 8.2.2-1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum InterfaceValue {
    /// 0: Access.
    #[default]
    Access,
    /// 1: Core.
    Core,
    /// 2: SGi-LAN/N6-LAN.
    SgiLanN6Lan,
    /// 3: CP-function.
    CpFunction,
    /// 4: 5G VN Internal.
    FiveGVnInternal,
    /// A value that Table 8.2.2-1 has as spare, kept as it is.
    Spare(u8),
}

impl InterfaceValue {
    const NAMES: &'static [&'static str] =
        &["Access", "Core", "SGi-LAN/N6-LAN", "CP-function", "5G VN Internal"];

    fn from_bits(bits: u8) -> Self {
        match bits {
            0 => Self::Access,
            1 => Self::Core,
            2 => Self::SgiLanN6Lan,
            3 => Self::CpFunction,
            4 => Self::FiveGVnInternal,
            other => Self::Spare(other),
        }
    }

    fn bits(self) -> u8 {
        match self {
            Self::Access => 0,
            Self::Core => 1,
            Self::SgiLanN6Lan => 2,
            Self::CpFunction => 3,
            Self::FiveGVnInternal => 4,
            Self::Spare(bits) => bits & 0x0f,
        }
    }
}

/// Source Interface (§8.2.2): where the packets of a PDR come from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceInterface<'a> {
    /// The Interface value, bits 4 to 1.
    pub value: InterfaceValue,
    /// Bits 8 to 5, which are spare.
    pub spare: u8,
    /// The octets after it, which a later release adds.
    pub extra: Octets<'a>,
}

impl SourceInterface<'_> {
    /// The interface.
    pub fn new(value: InterfaceValue) -> Self {
        Self { value, spare: 0, extra: Octets::new() }
    }
}

impl<'a> IntoOwned for SourceInterface<'a> {
    type Owned = SourceInterface<'static>;
    fn into_owned(self) -> SourceInterface<'static> {
        SourceInterface { value: self.value, spare: self.spare, extra: self.extra.into_owned() }
    }
}

impl<'a> Codec<'a> for SourceInterface<'a> {
    fn decode(octets: &'a [u8]) -> Option<Self> {
        let (&first, rest) = octets.split_first()?;
        Some(Self {
            value: InterfaceValue::from_bits(first & 0x0f),
            spare: first >> 4,
            extra: Octets::wire(rest),
        })
    }
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.push(self.spare << 4 | self.value.bits());
        out.extend_from_slice(&self.extra);
        Ok(())
    }
    fn encoded_len(&self) -> usize {
        1 + self.extra.len()
    }
}

impl Check for SourceInterface<'_> {
    fn check(&self, path: &str, found: &mut Vec<Deviation>) {
        if let InterfaceValue::Spare(value) = self.value {
            found.push(Deviation::new(path, "8.2.2", DeviationKind::SpareValue { value: value.into() }));
        }
        if self.spare != 0 {
            found.push(Deviation::new(path, "8.1.2", DeviationKind::SpareBits));
        }
    }
}

/// The name of the value, or its number for a spare one.
#[cfg(feature = "tree")]
impl oxirush_utils::tree::Tree for SourceInterface<'_> {
    const NAME: &'static str = "Source Interface";
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        let value = match self.value {
            InterfaceValue::Spare(bits) => oxirush_utils::tree::unsigned(bits.into()),
            known => oxirush_utils::tree::text(InterfaceValue::NAMES[usize::from(known.bits())]),
        };
        if self.spare == 0 && self.extra.is_empty() {
            return value;
        }
        let mut members = oxirush_utils::tree::Members::new();
        members.put("Interface value", value);
        if self.spare != 0 {
            members.put("Spare", oxirush_utils::tree::unsigned(self.spare.into()));
        }
        if !self.extra.is_empty() {
            members.put("extra", oxirush_utils::tree::octets(&self.extra));
        }
        members.finish()
    }
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        fn interface(
            value: &oxirush_utils::tree::Value,
            reading: &mut oxirush_utils::tree::Reading,
        ) -> Result<InterfaceValue, oxirush_utils::tree::Refused> {
            match value.is_number() {
                true => Ok(InterfaceValue::from_bits(reading.unsigned(value, 0, 15)? as u8)),
                false => Ok(InterfaceValue::from_bits(reading.named(value, InterfaceValue::NAMES)? as u8)),
            }
        }
        if !value.is_object() {
            return Ok(Self::new(interface(value, reading)?));
        }
        let read = reading.members(value, &["Interface value", "Spare", "extra"])?;
        Ok(Self {
            value: reading.member(&read, 0, interface)?,
            spare: reading.optional(&read, 1, |value, reading| reading.unsigned(value, 0, 15))?.unwrap_or(0) as u8,
            extra: reading.optional(&read, 2, |value, reading| reading.octets(value))?.map(Octets::from).unwrap_or_default(),
        })
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
}

pfcp_layout! {
    /// F-SEID (§8.2.37): a SEID with the addresses of its node.
    pub struct FSeid "8.2.37" {
        flags(u8) { v4 "V4": 2, v6 "V6": 1 }
        seid "SEID": u64 if true,
        ipv4 "IPv4 address": Ipv4Addr if v4,
        ipv6 "IPv6 address": Ipv6Addr if v6,
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
        ipv4 "IPv4 address": Ipv4Addr if v4,
        ipv6 "IPv6 address": Ipv6Addr if v6,
        ipv6_prefix_delegation_bits "IPv6 Prefix Delegation Bits": u8 if ipv6d,
        ipv6_prefix_length "IPv6 Prefix Length": u8 if ip6pl,
    }
}

impl FTeid<'_> {
    /// An F-TEID of an IPv4 address.
    pub fn ipv4(teid: u32, address: Ipv4Addr) -> Self {
        Self { v4: true, teid: Some(teid), ipv4: Some(address), ..Self::default() }
    }

    /// A request that the UP function choose an F-TEID with an IPv4 address.
    pub fn choose_ipv4() -> Self {
        Self { v4: true, ch: true, ..Self::default() }
    }
}

impl Check for FTeid<'_> {
    fn check(&self, path: &str, found: &mut Vec<Deviation>) {
        layout_checks(self.inconsistent(), self.spare, path, Self::CLAUSE, found);
        if !self.v4 && !self.v6 {
            found.push(Deviation::new(path, "8.2.3", DeviationKind::Rule("neither V4 nor V6 is set")));
        }
        if self.chid && !self.ch {
            found.push(Deviation::new(path, "8.2.3", DeviationKind::Rule("CHID is set and CH is not")));
        }
    }
}

impl Check for FSeid<'_> {
    fn check(&self, path: &str, found: &mut Vec<Deviation>) {
        layout_checks(self.inconsistent(), self.spare, path, Self::CLAUSE, found);
    }
}

impl Check for UeIpAddress<'_> {
    fn check(&self, path: &str, found: &mut Vec<Deviation>) {
        layout_checks(self.inconsistent(), self.spare, path, Self::CLAUSE, found);
        if self.v4 && self.chv4 {
            found.push(Deviation::new(path, "8.2.62", DeviationKind::Rule("V4 and CHV4 are both set")));
        }
        if self.v6 && self.chv6 {
            found.push(Deviation::new(path, "8.2.62", DeviationKind::Rule("V6 and CHV6 are both set")));
        }
    }
}

fn layout_checks(
    inconsistent: Option<&'static str>,
    spare: u8,
    path: &str,
    clause: &'static str,
    found: &mut Vec<Deviation>,
) {
    if let Some(field) = inconsistent {
        found.push(Deviation::new(path, clause, DeviationKind::Inconsistent { field }));
    }
    if spare != 0 {
        found.push(Deviation::new(path, "8.1.2", DeviationKind::SpareBits));
    }
}

/// Node ID (§8.2.38): an IPv4 address, an IPv6 address or an FQDN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeId<'a> {
    /// Node ID Type 0.
    Ipv4(Ipv4Addr),
    /// Node ID Type 1.
    Ipv6(Ipv6Addr),
    /// Node ID Type 2: the labels of the FQDN, as RFC 1035 writes them without the last
    /// zero octet.
    Fqdn(Octets<'a>),
    /// A Node ID Type that Table 8.2.38-2 has as spare, or a value of a length that its
    /// type does not have: the first octet, then the others.
    Other(u8, Octets<'a>),
}

impl<'a> IntoOwned for NodeId<'a> {
    type Owned = NodeId<'static>;
    fn into_owned(self) -> NodeId<'static> {
        match self {
            Self::Ipv4(address) => NodeId::Ipv4(address),
            Self::Ipv6(address) => NodeId::Ipv6(address),
            Self::Fqdn(labels) => NodeId::Fqdn(labels.into_owned()),
            Self::Other(first, rest) => NodeId::Other(first, rest.into_owned()),
        }
    }
}

impl<'a> Codec<'a> for NodeId<'a> {
    fn decode(octets: &'a [u8]) -> Option<Self> {
        let (&first, rest) = octets.split_first()?;
        Some(match (first, rest.len()) {
            (0, 4) => Self::Ipv4(Ipv4Addr::from(<[u8; 4]>::try_from(rest).ok()?)),
            (1, 16) => Self::Ipv6(Ipv6Addr::from(<[u8; 16]>::try_from(rest).ok()?)),
            (2, _) if !rest.is_empty() => Self::Fqdn(Octets::wire(rest)),
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

impl Check for NodeId<'_> {
    fn check(&self, path: &str, found: &mut Vec<Deviation>) {
        if let Self::Other(first, _) = self {
            let kind = match first & 0x0f {
                0..=2 => DeviationKind::Rule("the Node ID value has a length that its type does not have"),
                value => DeviationKind::SpareValue { value: value.into() },
            };
            found.push(Deviation::new(path, "8.2.38", kind));
        }
    }
}

impl NodeId<'_> {
    /// The FQDN as text, its labels with dots: `None` for labels that are not.
    pub fn fqdn(&self) -> Option<String> {
        let Self::Fqdn(labels) = self else { return None };
        let mut text = String::new();
        let mut rest: &[u8] = labels;
        while let [length, tail @ ..] = rest {
            let label = tail.get(..usize::from(*length))?;
            if !text.is_empty() {
                text.push('.');
            }
            text.push_str(core::str::from_utf8(label).ok()?);
            rest = &tail[usize::from(*length)..];
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

/// An address as text, or `{"FQDN": "upf.example"}`, or the octets of another Node ID.
#[cfg(feature = "tree")]
impl oxirush_utils::tree::Tree for NodeId<'_> {
    const NAME: &'static str = "Node ID";
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        use oxirush_utils::tree;
        match self {
            Self::Ipv4(address) => tree::Value::String(alloc::format!("{address}")),
            Self::Ipv6(address) => tree::Value::String(alloc::format!("{address}")),
            Self::Fqdn(_) => match self.fqdn() {
                Some(text) => tree::alternative("FQDN", tree::text(&text)),
                None => tree::alternative("FQDN", tree::octets(self.encoded().get(1..).unwrap_or_default())),
            },
            Self::Other(..) => tree::alternative("Node ID value", tree::octets(&self.encoded())),
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
                    let Ok(length) = u8::try_from(label.len()) else {
                        return Err(reading.mismatch("labels of at most 63 octets", content));
                    };
                    labels.push(length);
                    labels.extend_from_slice(label.as_bytes());
                }
                Ok(Self::Fqdn(labels.into()))
            }),
            _ => reading.within("Node ID value", content, |content, reading| {
                let octets = reading.octets(content)?;
                let (first, rest) = octets.split_first().ok_or_else(|| reading.mismatch("one octet at least", content))?;
                Ok(Self::Other(*first, Octets::copied(rest)))
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
pub struct NetworkInstance<'a>(pub Octets<'a>);

impl<'a> Codec<'a> for NetworkInstance<'a> {
    fn decode(octets: &'a [u8]) -> Option<Self> {
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

impl Check for NetworkInstance<'_> {}

impl<'a> IntoOwned for NetworkInstance<'a> {
    type Owned = NetworkInstance<'static>;
    fn into_owned(self) -> NetworkInstance<'static> {
        NetworkInstance(self.0.into_owned())
    }
}

#[cfg(feature = "tree")]
impl oxirush_utils::tree::Tree for NetworkInstance<'_> {
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
        pub struct $ty<'a> {
            $(
                #[doc = concat!("The ", $name, " field.")]
                pub $field: $kind,
            )*
            /// The octets after the fields, which a later release adds.
            pub extra: Octets<'a>,
        }

        impl<'a> Codec<'a> for $ty<'a> {
            fn decode(mut octets: &'a [u8]) -> Option<Self> {
                $( let $field = <$kind as Field>::read(&mut octets)?; )*
                Some(Self { $($field,)* extra: Octets::wire(octets) })
            }
            fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                $( Field::write(&self.$field, out); )*
                out.extend_from_slice(&self.extra);
                Ok(())
            }
            fn encoded_len(&self) -> usize {
                0 $( + Field::size(&self.$field) )* + self.extra.len()
            }
        }

        impl Check for $ty<'_> {}

        impl<'a> IntoOwned for $ty<'a> {
            type Owned = $ty<'static>;
            fn into_owned(self) -> $ty<'static> {
                $ty { $($field: self.$field,)* extra: self.extra.into_owned() }
            }
        }

        #[cfg(feature = "tree")]
        impl oxirush_utils::tree::Tree for $ty<'_> {
            const NAME: &'static str = <Self as IeType>::TYPE_NAME;
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
}

impl Check for VolumeThreshold<'_> {}
impl Check for VolumeQuota<'_> {}
impl Check for SubsequentVolumeThreshold<'_> {}
impl Check for OuterHeaderCreation<'_> {
    fn check(&self, path: &str, found: &mut Vec<Deviation>) {
        layout_checks(self.inconsistent(), u8::from(self.spare != 0), path, Self::CLAUSE, found);
        if !(self.gtpu_udp_ipv4 || self.gtpu_udp_ipv6 || self.udp_ipv4 || self.udp_ipv6 || self.ipv4_header || self.ipv6_header || self.c_tag_header || self.s_tag_header) {
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
        interface_value "Interface value": 0 1 4,
    }
}

pfcp_bits! {
    /// Outer Header Removal (§8.2.64): its description (Table 8.2.64-1), and the GTP-U
    /// extension headers to delete (Table 8.2.64-2), which a later release added.
    pub struct OuterHeaderRemoval "8.2.64" octets 2 min 1 {
        outer_header_removal_description "Outer Header Removal Description": 0 1 8,
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
        dl_gate "DL Gate": 0 1 2, ul_gate "UL Gate": 0 3 2,
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
        interface_type_value "Interface Type value": 0 1 6,
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

impl<'a, const N: u16> crate::ie::Listed<'a> for Raw<'a, N> {
    type List = crate::list::List<Self>;
    type Slot = Option<Self>;
    fn decode_slot(slot: &mut Self::Slot, octets: &'a [u8]) -> bool {
        *slot = Some(Self(Octets::wire(octets)));
        true
    }
    fn slot_get(slot: &Self::Slot) -> Option<&Self> {
        slot.as_ref()
    }
    fn slot_set(slot: &mut Self::Slot, value: Self) {
        *slot = Some(value);
    }
    #[inline]
    fn decode_push(list: &mut Self::List, octets: &'a [u8]) -> bool {
        list.push(Self(Octets::wire(octets)));
        true
    }
}
