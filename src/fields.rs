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

//! The fields of the values of clause 8.2, read in network order: those of oxirush-utils
//! (numbers, the narrow values of a few bits, octets after their lengths, lists,
//! addresses, PLMNs, FQDNs, text and digits, and the octets of a key), and those of
//! PFCP alone; how a value writes them ([`put`]), and the layout of each value as the
//! test `spec` compares it with its figure.

use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};

use crate::Error;

pub(crate) use oxirush_utils::field_names as names;
pub(crate) use oxirush_utils::fields::*;
#[cfg(feature = "spec")]
#[doc(hidden)]
pub use oxirush_utils::fields::{Bits, Layout, Member, NarrowCell};
pub use oxirush_utils::fields::{
    Counted, DigitsLv8, Each, Entries16, Fqdn, Ipv4Address, Lv8, Lv16, Mac, Narrow, Number,
    OctetArray16, Percent, PlmnId, Rest, SecretLv8, SecretTextLv8, SixBits, Spare, TextLv8,
    TextLv16, U24, U40, VlanTag,
};

/// Write `field`, named `name`, of a value of the IE `ie`: refused where its length, its
/// number or its type do not fit the bits that say them ([`Field::fits`]). Each value
/// writes each of its fields so.
pub(crate) fn put<F: Field>(
    field: &F,
    ie: &'static str,
    name: &'static str,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    oxirush_utils::fields::put(field, ie, name, out)
        .map_err(|FieldLength { ie, field }| Error::FieldLength { ie, field })
}
/// The octets of a Network Instance after a length of two octets: the Network Instance
/// field of Remote GTP-U Peer (§8.2.70), whose tree is that of a Network Instance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameLv16(pub Octets);

oxirush_utils::__length_value!(NameLv16 u16, name(crate::values::NetworkInstance::FIELDS, crate::values::NAME_TAKES));
/// An additional Domain Name of PFD Contents together with its Domain Name Protocol
/// (Figure 8.2.39-4). Each field follows its own two-octet length and has the same format
/// as the Domain Name and Domain Name Protocol fields of PFD Contents.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainNameAndProtocol {
    /// The Domain Name.
    pub domain_name: TextLv16,
    /// The Domain Name Protocol.
    pub domain_name_protocol: Lv16,
}

impl Field for DomainNameAndProtocol {
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
}

#[cfg(feature = "tree")]
impl FieldTree for DomainNameAndProtocol {
    const TAKES: &'static oxirush_utils::tree::Takes = &oxirush_utils::tree::Takes::Members(
        None,
        &[
            ("Domain Name", TextLv16::TAKES),
            ("Domain Name Protocol", Lv16::TAKES),
        ],
    );
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        let mut members = oxirush_utils::tree::Members::new();
        members.put("Domain Name", self.domain_name.to_tree());
        members.put("Domain Name Protocol", self.domain_name_protocol.to_tree());
        members.finish()
    }
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
        out.push(together(address_type << 6, length as u8));
        out.extend_from_slice(&self.address[..self.address.len().min(0x3f)]);
    }
    fn size(&self) -> usize {
        1 + self.address.len().min(0x3f)
    }
    fn fits(&self) -> bool {
        self.address_type <= 3 && self.address.len() <= 0x3f
    }
    fn check<D: Deviate>(&self, path: &Path<'_>, clause: &'static str, found: &mut Vec<D>) {
        if !self.fits() {
            found.push(D::found(
                path,
                Some(clause),
                Finding::Rule("an Address Type or an Address longer than their bits can say"),
            ));
        } else if self.ip().is_none() {
            found.push(D::found(
                path,
                Some(clause),
                Finding::Rule("an address that is neither IPv4 of type 0 nor IPv6 of type 1"),
            ));
        }
    }
}

#[cfg(feature = "tree")]
impl FieldTree for TypedAddress {
    const TAKES: &'static oxirush_utils::tree::Takes = &oxirush_utils::tree::Takes::OneOf(&[
        &oxirush_utils::tree::Takes::Ipv4,
        &oxirush_utils::tree::Takes::Ipv6,
        &oxirush_utils::tree::Takes::Members(
            Some("Address"),
            &[
                ("Address Type", &oxirush_utils::tree::Takes::Number(3)),
                ("Address", &oxirush_utils::tree::Takes::Octets(None)),
            ],
        ),
    ]);
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        if let Some(address) = self.ip() {
            return oxirush_utils::tree::Value::String(alloc::format!("{address}").into());
        }
        let mut members = oxirush_utils::tree::Members::new();
        members.put(
            "Address Type",
            oxirush_utils::tree::unsigned(self.address_type.into()),
        );
        members.put("Address", oxirush_utils::tree::octets(&self.address));
        members.finish()
    }
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
    fn check<D: Deviate>(&self, path: &Path<'_>, clause: &'static str, found: &mut Vec<D>) {
        self.distribution.check(path, clause, found);
        self.source.check(path, clause, found);
    }
}

#[cfg(feature = "tree")]
impl FieldTree for SsmAddress {
    const TAKES: &'static oxirush_utils::tree::Takes = &oxirush_utils::tree::Takes::Members(
        None,
        &[
            ("IP Multicast Distribution Address", TypedAddress::TAKES),
            ("IP Source Address", TypedAddress::TAKES),
        ],
    );
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        let mut members = oxirush_utils::tree::Members::new();
        members.put(
            "IP Multicast Distribution Address",
            self.distribution.to_tree(),
        );
        members.put("IP Source Address", self.source.to_tree());
        members.finish()
    }
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
}
