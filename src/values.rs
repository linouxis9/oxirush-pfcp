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
use crate::ie::{Codec, IeType};
use crate::macros::pfcp_layout;

/// A field of a layout: its octets, read in network order.
pub trait Field: Sized {
    /// Read the field, and step over it.
    fn read(octets: &mut &[u8]) -> Option<Self>;
    /// Write the field.
    fn write(&self, out: &mut Vec<u8>);
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

macro_rules! address_field {
    ($($t:ty, $n:literal);*) => {$(
        impl Field for $t {
            fn read(octets: &mut &[u8]) -> Option<Self> {
                take::<$n>(octets).map(<$t>::from)
            }
            fn write(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.octets());
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
pub struct Raw<const N: u16>(pub Vec<u8>);

impl<const N: u16> IeType for Raw<N> {
    const IE_TYPE: u16 = N;
    const TYPE_NAME: &'static str = "IE";
}

impl<const N: u16> Codec for Raw<N> {
    fn decode(octets: &[u8]) -> Option<Self> {
        Some(Self(octets.to_vec()))
    }
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.extend_from_slice(&self.0);
        Ok(())
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
        reading.octets(value).map(Self)
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
            pub extra: Vec<u8>,
        }

        impl $ty {
            /// The value.
            pub fn new(value: $t) -> Self {
                Self { value, extra: Vec::new() }
            }
        }

        impl Codec for $ty {
            fn decode(mut octets: &[u8]) -> Option<Self> {
                let value = Field::read(&mut octets)?;
                Some(Self { value, extra: octets.to_vec() })
            }
            fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
                Field::write(&self.value, out);
                out.extend_from_slice(&self.extra);
                Ok(())
            }
        }

        impl Check for $ty {}

        /// The number alone, or `{"Rule ID": 1, "extra": "00"}` with the octets of a later
        /// release.
        #[cfg(feature = "tree")]
        impl oxirush_utils::tree::Tree for $ty {
            const NAME: &'static str = <$ty as IeType>::TYPE_NAME;
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
                    extra: reading.optional(&read, 1, |value, reading| reading.octets(value))?.unwrap_or_default(),
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
pub struct SourceInterface {
    /// The Interface value, bits 4 to 1.
    pub value: InterfaceValue,
    /// Bits 8 to 5, which are spare.
    pub spare: u8,
    /// The octets after it, which a later release adds.
    pub extra: Vec<u8>,
}

impl SourceInterface {
    /// The interface.
    pub fn new(value: InterfaceValue) -> Self {
        Self { value, spare: 0, extra: Vec::new() }
    }
}

impl Codec for SourceInterface {
    fn decode(octets: &[u8]) -> Option<Self> {
        let (&first, rest) = octets.split_first()?;
        Some(Self {
            value: InterfaceValue::from_bits(first & 0x0f),
            spare: first >> 4,
            extra: rest.to_vec(),
        })
    }
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.push(self.spare << 4 | self.value.bits());
        out.extend_from_slice(&self.extra);
        Ok(())
    }
}

impl Check for SourceInterface {
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
impl oxirush_utils::tree::Tree for SourceInterface {
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
            extra: reading.optional(&read, 2, |value, reading| reading.octets(value))?.unwrap_or_default(),
        })
    }
}

pfcp_layout! {
    /// F-TEID (§8.2.3): a TEID with its addresses, or a request that the UP function
    /// choose one (CH).
    pub struct FTeid "8.2.3" {
        flags { chid "CHID": 4, ch "CH": 3, v6 "V6": 2, v4 "V4": 1 }
        teid "TEID": u32 if !ch,
        ipv4 "IPv4 address": Ipv4Addr if v4 && !ch,
        ipv6 "IPv6 address": Ipv6Addr if v6 && !ch,
        choose_id "CHOOSE ID": u8 if chid,
    }
}

pfcp_layout! {
    /// F-SEID (§8.2.37): a SEID with the addresses of its node.
    pub struct FSeid "8.2.37" {
        flags { v4 "V4": 2, v6 "V6": 1 }
        seid "SEID": u64 if true,
        ipv4 "IPv4 address": Ipv4Addr if v4,
        ipv6 "IPv6 address": Ipv6Addr if v6,
    }
}

pfcp_layout! {
    /// UE IP Address (§8.2.62): an address of the UE, or a request that the UP function
    /// choose one (CHV4, CHV6).
    pub struct UeIpAddress "8.2.62" {
        flags {
            ip6pl "IP6PL": 7, chv6 "CHV6": 6, chv4 "CHV4": 5, ipv6d "IPv6D": 4,
            sd "S/D": 3, v4 "V4": 2, v6 "V6": 1,
        }
        ipv4 "IPv4 address": Ipv4Addr if v4,
        ipv6 "IPv6 address": Ipv6Addr if v6,
        ipv6_prefix_delegation_bits "IPv6 Prefix Delegation Bits": u8 if ipv6d,
        ipv6_prefix_length "IPv6 Prefix Length": u8 if ip6pl,
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

impl Check for FTeid {
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

impl Check for FSeid {
    fn check(&self, path: &str, found: &mut Vec<Deviation>) {
        layout_checks(self.inconsistent(), self.spare, path, Self::CLAUSE, found);
    }
}

impl Check for UeIpAddress {
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
pub enum NodeId {
    /// Node ID Type 0.
    Ipv4(Ipv4Addr),
    /// Node ID Type 1.
    Ipv6(Ipv6Addr),
    /// Node ID Type 2: the labels of the FQDN, as RFC 1035 writes them without the last
    /// zero octet.
    Fqdn(Vec<u8>),
    /// A Node ID Type that Table 8.2.38-2 has as spare, or a value of a length that its
    /// type does not have: the first octet, then the others.
    Other(u8, Vec<u8>),
}

impl Codec for NodeId {
    fn decode(octets: &[u8]) -> Option<Self> {
        let (&first, rest) = octets.split_first()?;
        Some(match (first, rest.len()) {
            (0, 4) => Self::Ipv4(Ipv4Addr::from(<[u8; 4]>::try_from(rest).ok()?)),
            (1, 16) => Self::Ipv6(Ipv6Addr::from(<[u8; 16]>::try_from(rest).ok()?)),
            (2, _) if !rest.is_empty() => Self::Fqdn(rest.to_vec()),
            _ => Self::Other(first, rest.to_vec()),
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
}

impl Check for NodeId {
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

impl NodeId {
    /// The FQDN as text, its labels with dots: `None` for labels that are not.
    pub fn fqdn(&self) -> Option<String> {
        let Self::Fqdn(mut labels) = self.clone() else { return None };
        let mut text = String::new();
        let mut rest = labels.as_mut_slice();
        while let [length, tail @ ..] = rest {
            let label = tail.get(..usize::from(*length))?;
            if !text.is_empty() {
                text.push('.');
            }
            text.push_str(core::str::from_utf8(label).ok()?);
            rest = &mut tail[usize::from(*length)..];
        }
        Some(text)
    }
}

/// An address as text, or `{"FQDN": "upf.example"}`, or the octets of another Node ID.
#[cfg(feature = "tree")]
impl oxirush_utils::tree::Tree for NodeId {
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
                Ok(Self::Fqdn(labels))
            }),
            _ => reading.within("Node ID value", content, |content, reading| {
                let octets = reading.octets(content)?;
                let (first, rest) = octets.split_first().ok_or_else(|| reading.mismatch("one octet at least", content))?;
                Ok(Self::Other(*first, rest.to_vec()))
            }),
        }
    }
}

impl NodeId {
    #[cfg(feature = "tree")]
    fn encoded(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let _ = Codec::encode(self, &mut out);
        out
    }
}
