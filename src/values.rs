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

//! The values that the others are written after: numbers, the layouts with conditional
//! octets, and the Node ID; and the macros of a value of one field and of octets.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, Ipv6Addr};

use crate::Error;
use crate::check::{Deviation, DeviationKind, Rules};
use crate::enums::*;
use crate::fields::*;
use crate::ie::{Codec, listed_value};
use crate::macros::{pfcp_bits, pfcp_layout};
use crate::octets::Octets;

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
    placed(fteid, table, path, found) {
        // "This bit shall only be set by the CP function", of CH and of CHID.
        flag_rule((fteid.ch || fteid.chid) && crate::check::of_the_up_function(table), path, "8.2.3", "CH or CHID is set in an IE of the UP function", found);
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
    placed(address, table, path, found) {
        // S/D "is only applicable to the UE IP Address IE in the PDI IE, Create Traffic
        // Endpoint IE and Update Traffic Endpoint IE", whose rows have it a source or a
        // destination, and "shall be set to "0" and ignored by the receiver" in the others.
        if address.sd && !["7.5.2.2-2", "7.5.2.7-1", "7.5.4.13-1"].contains(&table) {
            found.push(Deviation::new(path, "8.2.62", DeviationKind::SpareBits));
        }
        flag_rule((address.chv4 || address.chv6) && crate::check::of_the_up_function(table), path, "8.2.62", "CHV4 or CHV6 is set in an IE of the UP function", found);
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

    /// An F-TEID of an IPv6 address.
    pub fn ipv6(teid: u32, address: Ipv6Addr) -> Self {
        Self {
            v6: true,
            teid: Some(teid),
            ipv6: Some(address),
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

    /// A request that the UP function choose an F-TEID with an IPv6 address.
    pub fn choose_ipv6() -> Self {
        Self {
            v6: true,
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
        if !self.reads_back() {
            return Err(Error::Inconsistent {
                ie: "Node ID",
                field: "Node ID value",
                clause: "8.2.38",
            });
        }
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
        if !self.reads_back() {
            let field = "Node ID value";
            found.push(Deviation::new(
                path,
                "8.2.38",
                DeviationKind::Inconsistent { field },
            ));
        }
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

impl NodeId {
    /// The names of its fields.
    pub(crate) const FIELDS: &'static [&'static str] = &["Node ID Type", "Node ID value"];
    /// The members that its tree may have: the FQDN, or the Node ID Type and the octets of
    /// the value of a Node ID that is no text, apart from the form of an IE kept as octets.
    /// The tree of an address is the address alone.
    pub(crate) const MEMBERS: &'static [&'static str] = &["FQDN", "Node ID Type", "Node ID value"];
    /// What the tree of each field may hold below it: nothing, of scalars alone.
    #[cfg(feature = "tree")]
    pub(crate) const MEMBERS_BELOW: &'static [(&'static str, &'static crate::paths::Below)] = &[];
    /// Read by hand: its layout depends on its type.
    #[doc(hidden)]
    #[cfg(feature = "spec")]
    pub const LAYOUT: Option<&'static Layout> = None;

    /// Whether its octets read as it: not an FQDN of no octets, nor other octets of a type
    /// and a length that an address or an FQDN has, which `encode()` refuses.
    fn reads_back(&self) -> bool {
        match self {
            Self::Fqdn(labels) => !labels.is_empty(),
            Self::Other(first, rest) => !matches!((first, rest.len()), (0, 4) | (1, 16) | (2, 1..)),
            _ => true,
        }
    }

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
}

#[cfg(feature = "serde")]
oxirush_utils::impl_serde!(NodeId);

/// An address as text, or `{"FQDN": "upf.example"}`, or `{"Node ID Type": 5, "Node ID
/// value": ...}` for another Node ID, its first octet and the octets after it: not
/// `{"octets": ...}`, which an IE kept as octets is in the tree of its scope.
#[cfg(feature = "tree")]
impl oxirush_utils::tree::Tree for NodeId {
    const NAME: &'static str = "Node ID";
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        use oxirush_utils::tree;
        let other = |kind: u8, value: &[u8]| {
            let mut members = tree::Members::new();
            members.put("Node ID Type", tree::unsigned(kind.into()));
            members.put("Node ID value", tree::octets(value));
            members.finish()
        };
        match self {
            Self::Ipv4(address) => tree::Value::String(alloc::format!("{address}")),
            Self::Ipv6(address) => tree::Value::String(alloc::format!("{address}")),
            Self::Fqdn(labels) => match self.fqdn() {
                Some(text) => tree::alternative("FQDN", tree::text(&text)),
                None => other(2, labels),
            },
            Self::Other(first, rest) => other(*first, rest),
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
        let fqdn = value
            .as_object()
            .and_then(|members| oxirush_utils::tree::member(members, "FQDN"));
        if fqdn.is_some() {
            let (_, content) = reading.alternative(value, &Self::MEMBERS[..1])?;
            return reading.within("FQDN", content, |content, reading| {
                let name = reading.text(content)?;
                Self::from_fqdn(name).ok_or_else(|| {
                    reading.mismatch(
                        "a name of 253 octets at most, of labels of 1 to 63 octets with dots between them",
                        content,
                    )
                })
            });
        }
        // The octets of a Node ID that the text does not give: read as they decode.
        let read = reading.members(value, &Self::MEMBERS[1..])?;
        let kind = reading.member(&read, "Node ID Type", |value, reading| {
            reading.unsigned(value, 0, 255)
        })?;
        let rest = reading.member(&read, "Node ID value", |value, reading| {
            reading.octets(value)
        })?;
        let octets = [&[kind as u8][..], &rest].concat();
        Ok(Self::decode(&octets).unwrap_or(Self::Other(kind as u8, rest.into())))
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
    /// Its field, which its tree is of octets that are no name: its tree is its name
    /// otherwise.
    pub(crate) const MEMBERS: &'static [&'static str] = Self::FIELDS;
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
        read: |octets| Self::decode(octets).map(|_| alloc::vec!["Network Instance"]),
    });
}

impl NetworkInstance {
    /// A Network Instance of a domain name or an APN from its text, `internet`: its labels
    /// as RFC 1035 writes them, each after its length (§8.2.4, TS 23.003 clause 9.1).
    /// `None` for a text with an empty label, a label of more than 63 octets, or of more
    /// than 253 octets.
    pub fn from_name(name: &str) -> Option<Self> {
        fqdn_of(name).map(|labels| Self(labels.into()))
    }
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

/// The name of the labels of a domain name or an APN, `"internet"` (§8.2.4, TS 23.003
/// clause 9.1), or `{"Network Instance": ...}`, its octets in hexadecimal, of other octets.
#[cfg(feature = "tree")]
impl oxirush_utils::tree::Tree for NetworkInstance {
    const NAME: &'static str = "Network Instance";
    fn to_tree(&self) -> oxirush_utils::tree::Value {
        name_tree(&self.0, Self::FIELDS)
    }
    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> Result<Self, oxirush_utils::tree::Refused> {
        name_from_tree(value, reading, Self::FIELDS).map(|octets| Self(octets.into()))
    }
}

/// The tree of the octets of a Network Instance, of an APN/DNN and of the Network Instance
/// field of Remote GTP-U Peer: the name of their labels, a text whatever its characters,
/// or, of other octets, an object of one member, the one name of `field`, of the octets in
/// hexadecimal. `{"octets": ...}` is an IE kept as octets.
#[cfg(feature = "tree")]
pub(crate) fn name_tree(
    octets: &[u8],
    field: &'static [&'static str],
) -> oxirush_utils::tree::Value {
    match fqdn_name(octets) {
        Some(name) => oxirush_utils::tree::text(&name),
        None => oxirush_utils::tree::alternative(field[0], oxirush_utils::tree::octets(octets)),
    }
}

/// The octets of the tree of a Network Instance, an APN/DNN or the Network Instance field
/// of Remote GTP-U Peer ([`name_tree`]).
#[cfg(feature = "tree")]
pub(crate) fn name_from_tree(
    value: &oxirush_utils::tree::Value,
    reading: &mut oxirush_utils::tree::Reading,
    field: &'static [&'static str],
) -> Result<Vec<u8>, oxirush_utils::tree::Refused> {
    if let Some(name) = value.as_str() {
        return fqdn_of(name).ok_or_else(|| {
            reading.mismatch(
                "a name of 253 octets at most, of labels of 1 to 63 octets with dots between them",
                value,
            )
        });
    }
    let (_, octets) = reading.alternative(value, field)?;
    reading.within(field[0], octets, |octets, reading| reading.octets(octets))
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
/// an error of its tree: their number alone; `[name]` for the labels of a name, whose tree
/// is that of a Network Instance, with its own field.
macro_rules! pfcp_octets {
    ($( $(#[$meta:meta])* $ty:ident $name:literal $clause:literal $(lengths $lengths:pat => $rule:literal)? $([$secret:ident])?; )*) => {$(
        $(#[$meta])*
        #[derive(Clone, Default, PartialEq, Eq)]
        pub struct $ty(pub Octets);

        impl $ty {
            /// The name of its field.
            pub(crate) const FIELDS: &'static [&'static str] = &[$name];
            /// None, as its tree is its octets; or, of the labels of a name, its field,
            /// which its tree is of octets that are no name.
            pub(crate) const MEMBERS: &'static [&'static str] = pfcp_octets!(@members $($secret)?);
            /// What the tree of each field may hold below it: nothing, of scalars alone.
            #[cfg(feature = "tree")]
            pub(crate) const MEMBERS_BELOW: &'static [(&'static str, &'static crate::paths::Below)] = &[];
            /// Its layout.
            #[doc(hidden)]
            #[cfg(feature = "spec")]
            pub const LAYOUT: Option<&'static Layout> = Some(&Layout {
                head: &[],
                bits: &[],
                fields: &[Member { name: $name, octets: None, cells: &[], condition: "true" }],
                read: |octets| <Self as Codec>::decode(octets).map(|_| alloc::vec![$name]),
            });
            /// Whether its octets are a key or a password.
            const SECRET: bool = pfcp_octets!(@secret $($secret)?);
            /// Whether its octets are the labels of a name.
            #[cfg(feature = "tree")]
            const NAME_LABELS: bool = pfcp_octets!(@name $($secret)?);
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
                    crate::fields::flag_rule(!matches!(self.0.len(), $lengths), path, $clause, $rule, found);
                }
            )?
        }

        #[cfg(feature = "serde")]
        oxirush_utils::impl_serde!($ty);

        #[cfg(feature = "tree")]
        impl oxirush_utils::tree::Tree for $ty {
            const NAME: &'static str = <$ty as crate::ie::IeType>::TYPE_NAME;
            fn to_tree(&self) -> oxirush_utils::tree::Value {
                match Self::NAME_LABELS {
                    true => crate::values::name_tree(&self.0, Self::FIELDS),
                    false => oxirush_utils::tree::octets(&self.0),
                }
            }
            fn from_tree(
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
            ) -> Result<Self, oxirush_utils::tree::Refused> {
                let octets = match (Self::SECRET, Self::NAME_LABELS) {
                    (true, _) => reading.secret(|reading| reading.octets(value))?,
                    (false, true) => crate::values::name_from_tree(value, reading, Self::FIELDS)?,
                    (false, false) => reading.octets(value)?,
                };
                Ok(Self(octets.into()))
            }
        }

        crate::ie::listed_value!($ty);
    )*};
    (@secret) => { false };
    (@secret secret) => { true };
    (@secret name) => { false };
    (@name) => { false };
    (@name secret) => { false };
    (@name name) => { true };
    (@members name) => { Self::FIELDS };
    (@members $($secret:ident)?) => { &[] };
}

pub(crate) use {pfcp_field, pfcp_octets};
