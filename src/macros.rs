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

//! The macros that expand the tables of the registry: the IE types of Table 8.1.2-1, the
//! layouts of clause 8.2, and the tables of clause 7.

/// The IE types of Table 8.1.2-1, one line each: the type, its name, its form and the
/// number of fixed octets that the table gives it, the clause or the table that defines
/// it, and the types of the crate that are its values.
macro_rules! pfcp_ies {
    ($( $num:literal $name:literal $form:ident $(($fixed:literal))? $clause:literal $(=> $($ty:ident),+)? ; )*) => {
        /// Every IE type of Table 8.1.2-1, in the order of their numbers.
        pub static IE_TYPES: &[crate::registry::IeTypeInfo] = &[
            $( crate::registry::IeTypeInfo {
                ie_type: $num,
                name: $name,
                form: pfcp_ies!(@form $form),
                fixed: pfcp_ies!(@fixed $($fixed)?),
                clause: $clause,
                #[cfg(feature = "spec")]
                fields: pfcp_ies!(@fields $form $($($ty),+)?),
                members: pfcp_ies!(@members $form $($($ty),+)?),
                scalar: crate::registry::one(pfcp_ies!(@fields $form $($($ty),+)?)),
                #[cfg(feature = "spec")]
                layout: pfcp_ies!(@layout $form $($($ty),+)?),
                tables: pfcp_ies!(@tables $form $($($ty),+)?),
            }, )*
        ];
        $( pfcp_ies!(@impls $num $name [pfcp_ies!(@length $form $(($fixed))?)] $($($ty),+)?); )*

        /// What the tree of each field of a value of `ie_type` may hold below it, of those
        /// whose tree is no scalar: none for a grouped IE.
        #[cfg(feature = "tree")]
        pub(crate) fn members_below(ie_type: u16) -> &'static [(&'static str, &'static crate::tree::Below)] {
            match ie_type {
                $( $num => pfcp_ies!(@below $form $($($ty),+)?), )*
                _ => &[],
            }
        }
    };
    (@impls $num:literal $name:literal [$fixed:expr] $($ty:ident),*) => {
        $(
            impl crate::ie::IeType for $ty {
                const IE_TYPE: u16 = $num;
                const TYPE_NAME: &'static str = $name;
                const FIXED: Option<u16> = $fixed;
            }
        )*
    };
    (@form fixed) => { crate::registry::Form::Fixed };
    (@form variable) => { crate::registry::Form::Variable };
    (@form extendable) => { crate::registry::Form::Extendable };
    (@form grouped) => { crate::registry::Form::Grouped };
    (@fixed) => { None };
    (@fixed $fixed:literal) => { Some($fixed) };
    (@length fixed ($fixed:literal)) => { Some($fixed) };
    (@length $form:ident $(($fixed:literal))?) => { None };
    (@fields grouped $($ty:ident),+) => { &[] };
    (@fields $form:ident $ty:ident) => { $ty::FIELDS };
    (@below grouped $($ty:ident),+) => { &[] };
    (@below $form:ident $ty:ident) => { $ty::MEMBERS_BELOW };
    (@below $form:ident) => { &[] };
    (@members grouped $($ty:ident),+) => { &[] };
    (@members $form:ident $ty:ident) => { $ty::MEMBERS };
    (@layout grouped $($ty:ident),+) => { None };
    (@layout $form:ident $ty:ident) => { $ty::LAYOUT };
    (@layout $form:ident) => { None };
    (@tables grouped $($ty:ident),+) => { pastey::paste! { &[$(&[<$ty:snake:upper _TABLE>]),+] } };
    (@tables $form:ident $($ty:ident),*) => { &[] };
}

/// A value of a layout of clause 8.2: an octet of flags, then fields, each present when
/// its condition over the flags holds, then the octets that a later release adds
/// ("present only if explicitly specified"), which the value keeps.
///
/// ```text
/// pub struct FTeid "8.2.3" {
///     flags(u8) { chid "CHID": 4, ch "CH": 3, v6 "V6": 2, v4 "V4": 1 }
///     teid "TEID": u32 if !ch,
///     ipv4 "IPv4 address": Ipv4Addr if v4 && !ch,
/// }
/// ```
macro_rules! pfcp_layout {
    (
        $(#[$meta:meta])*
        pub struct $ty:ident $clause:literal {
            $( head { $( $head:ident $head_name:literal : $hkind:ident ),* $(,)? } )?
            flags($fk:ty) { $( $flag:ident $flag_name:literal : $bit:literal $(/ $width:literal $(as $fkind:ident)?)? ),* $(,)? }
            $( $field:ident $field_name:literal : $kind:ident $(<$param:ident>)? if $cond:expr ),* $(,)?
        }
        $( check($this:ident, $path:ident, $found:ident) $rules:block )?
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Default, PartialEq, Eq)]
        pub struct $ty {
            $($(
                #[doc = concat!("The ", $head_name, " field, before the flags.")]
                pub $head: $hkind,
            )*)?
            $(
                #[doc = concat!("The ", $flag_name, " field of the octet of flags, from bit ", stringify!($bit), ".")]
                pub $flag: pfcp_layout!(@ft $($width $(as $fkind)?)?),
            )*
            /// The other bits of the first octet, which are spare: zero from a sender.
            pub spare: $fk,
            $(
                #[doc = concat!("The ", $field_name, " field.")]
                pub $field: Option<$kind $(<$param>)?>,
            )*
            /// The octets after the fields, which a later release adds: the unknown octets
            /// of §8.1.2, `"unknown octets"` in a tree.
            pub extra: crate::octets::Octets,
        }

        impl $ty {
            /// The bits of the first octet that are flags.
            const FLAGS: $fk = 0 $( | pfcp_layout!(@fmask $bit $(, $width)?) )*;
            /// The names of its flags and fields.
            pub(crate) const FIELDS: &'static [&'static str] = &[$($($head_name,)*)? $($flag_name,)* $($field_name),*];
            /// The members that its tree may have: its flags and fields, its spare bits and
            /// its unknown octets.
            pub const MEMBERS: &'static [&'static str] = &[$($($head_name,)*)? $($flag_name,)* "Spare", $($field_name,)* crate::ie::UNKNOWN_OCTETS];
            /// What the tree of each field may hold below it.
            #[cfg(feature = "tree")]
            pub(crate) const MEMBERS_BELOW: &'static [(&'static str, &'static crate::tree::Below)] = &[
                $($( ($head_name, <$hkind as crate::values::Field>::BELOW), )*)?
                $( ($field_name, <$kind $(<$param>)? as crate::values::Field>::BELOW), )*
            ];
            /// The octets of the fields before its flags.
            #[cfg(feature = "spec")]
            const HEAD_OCTETS: usize = 0 $($( + crate::values::octets_of(<$hkind as crate::values::Field>::OCTETS) )*)?;
            /// Its layout.
            #[doc(hidden)]
            #[cfg(feature = "spec")]
            pub const LAYOUT: Option<&'static crate::values::Layout> = Some(&crate::values::Layout {
                head: &[$($(crate::values::Member { name: $head_name, octets: <$hkind as crate::values::Field>::OCTETS, cells: <$hkind as crate::values::Field>::CELLS, condition: "true" }),*)?],
                bits: &[$(crate::values::Bits {
                    name: $flag_name,
                    ident: stringify!($flag),
                    octet: Self::HEAD_OCTETS + (core::mem::size_of::<$fk>() - 1 - ($bit - 1) / 8),
                    bit: ($bit - 1) % 8 + 1,
                    width: pfcp_layout!(@fwidth $($width)?),
                }),*],
                fields: &[$(crate::values::Member { name: $field_name, octets: <$kind $(<$param>)? as crate::values::Field>::OCTETS, cells: <$kind $(<$param>)? as crate::values::Field>::CELLS, condition: stringify!($cond) }),*],
            });
            /// The clause of the layout.
            pub const CLAUSE: &'static str = $clause;

            /// The first field of the octet of flags whose value is wider than its bits.
            fn wide(&self) -> Option<&'static str> {
                $(
                    if pfcp_layout!(@fwide self.$flag $(, $width $(as $fkind)?)?) {
                        return Some($flag_name);
                    }
                )*
                None
            }

            /// Whether each field is there as its flags say: the name of the first that is
            /// not.
            #[allow(unused_variables)]
            pub fn inconsistent(&self) -> Option<&'static str> {
                $( let $flag = self.$flag; )*
                $(
                    if self.$field.is_some() != ($cond) {
                        return Some($field_name);
                    }
                )*
                None
            }
        }

        impl crate::ie::Codec for $ty {
            #[allow(unused_variables)]
            fn decode(octets: &[u8]) -> Option<Self> {
                let mut rest = octets;
                $($( let $head = <$hkind as crate::values::Field>::read(&mut rest)?; )*)?
                let first = <$fk as crate::values::Field>::read(&mut rest)?;
                $( let $flag = pfcp_layout!(@fread first, $bit $(, $width $(as $fkind)?)?); )*
                $(
                    let $field = match $cond {
                        true => Some(<$kind $(<$param>)? as crate::values::Field>::read(&mut rest)?),
                        false => None,
                    };
                )*
                Some(Self {
                    $($( $head, )*)?
                    $( $flag, )*
                    spare: first & !Self::FLAGS,
                    $( $field, )*
                    extra: crate::octets::Octets::copied(rest),
                })
            }

            fn encode(&self, out: &mut alloc::vec::Vec<u8>) -> Result<(), crate::Error> {
                if let Some(field) = self.inconsistent() {
                    return Err(crate::Error::Inconsistent {
                        ie: <Self as crate::ie::IeType>::TYPE_NAME,
                        field,
                        clause: $clause,
                    });
                }
                let ie = <Self as crate::ie::IeType>::TYPE_NAME;
                if let Some(field) = self.wide() {
                    return Err(crate::Error::FieldLength { ie, field });
                }
                $($(
                    if !crate::values::Field::fits(&self.$head) {
                        return Err(crate::Error::FieldLength { ie, field: $head_name });
                    }
                )*)?
                $(
                    if let Some(field) = &self.$field
                        && !crate::values::Field::fits(field)
                    {
                        return Err(crate::Error::FieldLength { ie, field: $field_name });
                    }
                )*
                $($( crate::values::Field::write(&self.$head, out); )*)?
                crate::values::Field::write(&(self.spare & !Self::FLAGS $( | pfcp_layout!(@fwrite $fk, self.$flag, $bit $(, $width $(as $fkind)?)?) )*), out);
                $(
                    if let Some(field) = &self.$field {
                        crate::values::Field::write(field, out);
                    }
                )*
                out.extend_from_slice(&self.extra);
                Ok(())
            }

            fn encoded_len(&self) -> usize {
                core::mem::size_of::<$fk>() $($( + crate::values::Field::size(&self.$head) )*)?
                    $( + self.$field.as_ref().map_or(0, crate::values::Field::size) )* + self.extra.len()
            }
        }

        impl crate::check::Rules for $ty {
            fn check(&self, path: &crate::check::Path, found: &mut alloc::vec::Vec<crate::check::Deviation>) {
                if let Some(field) = self.inconsistent() {
                    found.push(crate::check::Deviation::new(path, $clause, crate::check::DeviationKind::Inconsistent { field }));
                }
                if self.wide().is_some() {
                    found.push(crate::check::Deviation::new(path, $clause, crate::check::DeviationKind::Rule("a value wider than its bits")));
                }
                if self.spare != 0 {
                    found.push(crate::check::Deviation::new(path, "8.1.2", crate::check::DeviationKind::SpareBits));
                }
                $($( crate::values::Field::check(&self.$head, path, $clause, found); )*)?
                $( pfcp_layout!(@fcheck self.$flag, path, found $(, $width $(as $fkind)?)?); )*
                $(
                    if let Some(field) = &self.$field {
                        crate::values::Field::check(field, path, $clause, found);
                    }
                )*
                $(
                    let ($this, $path, $found) = (self, path, found);
                    $rules
                )?
            }
        }

        #[cfg(feature = "serde")]
        oxirush_utils::impl_serde!($ty);

        #[cfg(feature = "tree")]
        impl oxirush_utils::tree::Tree for $ty {
            const NAME: &'static str = <Self as crate::ie::IeType>::TYPE_NAME;

            fn to_tree(&self) -> oxirush_utils::tree::Value {
                let mut members = oxirush_utils::tree::Members::new();
                $($( members.put($head_name, crate::values::Field::to_tree(&self.$head)); )*)?
                $( pfcp_layout!(@fput members, $flag_name, self.$flag $(, $width $(as $fkind)?)?); )*
                if self.spare != 0 {
                    members.put("Spare", oxirush_utils::tree::unsigned(self.spare.into()));
                }
                $(
                    if let Some(field) = &self.$field {
                        members.put($field_name, crate::values::Field::to_tree(field));
                    }
                )*
                if !self.extra.is_empty() {
                    members.put(crate::ie::UNKNOWN_OCTETS, oxirush_utils::tree::octets(&self.extra));
                }
                members.finish()
            }

            fn from_tree(
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
            ) -> Result<Self, oxirush_utils::tree::Refused> {
                let read = reading.members(value, Self::MEMBERS)?;
                $($(
                    let $head = reading.optional(&read, $head_name, <$hkind as crate::values::Field>::from_tree)?.unwrap_or_default();
                )*)?
                $(
                    let $flag = pfcp_layout!(@fget reading, read, $flag_name $(, $width $(as $fkind)?)?);
                )*
                let spare = reading
                    .optional(&read, "Spare", |value, reading| reading.unsigned(value, 0, <$fk>::MAX.into()))?
                    .unwrap_or(0) as $fk;
                $(
                    let $field = reading.optional(&read, $field_name, <$kind $(<$param>)? as crate::values::Field>::from_tree)?;
                )*
                let extra = reading.optional(&read, crate::ie::UNKNOWN_OCTETS, |value, reading| reading.octets(value))?;
                let value = Self { $($($head,)*)? $($flag,)* spare, $($field,)* extra: extra.map(crate::octets::Octets::from).unwrap_or_default() };
                if spare & Self::FLAGS != 0 {
                    return Err(reading.refuse(
                        oxirush_utils::tree::ErrorKind::Value,
                        "Spare has a bit that is a flag",
                    ));
                }
                match value.inconsistent() {
                    None => Ok(value),
                    Some(field) => Err(reading.refuse(
                        oxirush_utils::tree::ErrorKind::Value,
                        alloc::format!(
                            "{field} is written where its flags do not have it, or is missing where they do ({})",
                            $clause
                        ),
                    )),
                }
            }
        }
    };
    // A field of the first octet: a flag of one bit, or a number of `width` bits.
    (@ft) => { bool };
    (@ft $width:literal) => { u8 };
    (@ft $width:literal as $kind:ident) => { $kind };
    (@fwidth) => { 1 };
    (@fwidth $width:literal) => { $width };
    (@fwide $value:expr) => { false };
    (@fwide $value:expr, $width:literal) => { u16::from($value) >= (1u16 << $width) };
    (@fwide $value:expr, $width:literal as $kind:ident) => { u16::from($value.value()) >= (1u16 << $width) };
    (@fmask $bit:literal) => { 1 << ($bit - 1) };
    (@fmask $bit:literal, $width:literal) => { ((1 << $width) - 1) << ($bit - 1) };
    (@fread $first:ident, $bit:literal) => { $first & 1 << ($bit - 1) != 0 };
    (@fread $first:ident, $bit:literal, $width:literal) => { (($first >> ($bit - 1)) & ((1 << $width) - 1)) as u8 };
    (@fread $first:ident, $bit:literal, $width:literal as $kind:ident) => {
        $kind::from_value(pfcp_layout!(@fread $first, $bit, $width))
    };
    (@fwrite $fk:ty, $value:expr, $bit:literal) => { <$fk>::from($value) << ($bit - 1) };
    (@fwrite $fk:ty, $value:expr, $bit:literal, $width:literal) => { (<$fk>::from($value) & ((1 << $width) - 1)) << ($bit - 1) };
    (@fwrite $fk:ty, $value:expr, $bit:literal, $width:literal as $kind:ident) => {
        pfcp_layout!(@fwrite $fk, $value.value(), $bit, $width)
    };
    (@fput $members:ident, $name:literal, $value:expr) => {
        if $value { $members.put($name, oxirush_utils::tree::Value::Bool(true)); }
    };
    (@fput $members:ident, $name:literal, $value:expr, $width:literal) => {
        $members.put($name, oxirush_utils::tree::unsigned($value.into()));
    };
    (@fput $members:ident, $name:literal, $value:expr, $width:literal as $kind:ident) => {
        $members.put($name, $value.tree());
    };
    (@fget $reading:ident, $read:ident, $name:literal) => {
        $reading.optional(&$read, $name, |value, reading| reading.boolean(value))?.unwrap_or(false)
    };
    (@fget $reading:ident, $read:ident, $name:literal, $width:literal) => {
        $reading.optional(&$read, $name, |value, reading| reading.unsigned(value, 0, (1 << $width) - 1))?.unwrap_or(0) as u8
    };
    (@fget $reading:ident, $read:ident, $name:literal, $width:literal as $kind:ident) => {
        $reading
            .optional(&$read, $name, |value, reading| $kind::read_tree(value, reading, ((1u16 << $width) - 1) as u8))?
            .unwrap_or_default()
    };
    (@fcheck $value:expr, $path:ident, $found:ident $(, $width:literal)?) => {};
    (@fcheck $value:expr, $path:ident, $found:ident, $width:literal as $kind:ident) => {
        crate::values::Field::check(&$value, $path, Self::CLAUSE, $found)
    };
}

/// A value of octets of bits: flags of one bit and fields of a few, each at its octet
/// (from 0), its lowest bit (from 1) and its width, in at most `N` octets of which the
/// first `MIN` are always there; then the octets that a later release adds. The other
/// bits are spare and kept, and so is how many of the `N` octets a decoded value had. The
/// rules of its clause on which flags go together follow it.
///
/// ```text
/// pub struct ApplyAction "8.2.26" octets 2 min 1 {
///     drop "DROP": 0 1 1, forw "FORW": 0 2 1, edrt "EDRT": 1 1 1,
/// }
/// check(action, path, found) { ... }
/// ```
macro_rules! pfcp_bits {
    (
        $(#[$meta:meta])*
        pub struct $ty:ident $clause:literal octets $n:literal min $min:literal {
            $( $field:ident $name:literal : $octet:literal $low:literal $width:tt $(+ $octet2:literal $low2:literal $width2:tt)? $(as $kind:ident)? ),* $(,)?
        }
        $( check($this:ident, $path:ident, $found:ident) $rules:block )?
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $ty {
            $(
                #[doc = concat!("The ", $name, " field.")]
                pub $field: pfcp_bits!(@type $width [$($kind)? $(+ $octet2 $low2 $width2)?]),
            )*
            /// The bits of each octet that no field has, which are spare.
            pub spare: [u8; $n],
            /// How many of the octets of the fields the value has: the first ones of a
            /// later release are absent from a sender of an earlier one.
            pub present: u8,
            /// The octets after them, which a later release adds: the unknown octets of
            /// §8.1.2, `"unknown octets"` in a tree.
            pub extra: crate::octets::Octets,
        }

        impl Default for $ty {
            fn default() -> Self {
                Self { $( $field: Default::default(), )* spare: [0; $n], present: $n, extra: Default::default() }
            }
        }

        pfcp_bits!(@new $ty $([$field $name $width [$($kind)? $(+ $octet2 $low2 $width2)?]])*);

        impl $ty {
            /// The clause of the layout.
            pub const CLAUSE: &'static str = $clause;
            /// The names of its flags and fields.
            pub(crate) const FIELDS: &'static [&'static str] = &[$($name),*];
            /// The members that its tree may have: its flags and fields, its spare bits, the
            /// number of the octets of its fields that it has, and its unknown octets.
            pub const MEMBERS: &'static [&'static str] = &[$($name,)* "Spare", "length", crate::ie::UNKNOWN_OCTETS];
            /// What the tree of each field may hold below it: nothing, of scalars alone.
            #[cfg(feature = "tree")]
            pub(crate) const MEMBERS_BELOW: &'static [(&'static str, &'static crate::tree::Below)] = &[];
            /// Its layout.
            #[doc(hidden)]
            #[cfg(feature = "spec")]
            pub const LAYOUT: Option<&'static crate::values::Layout> = Some(&crate::values::Layout {
                head: &[],
                bits: &[$(
                    crate::values::Bits { name: $name, ident: stringify!($field), octet: $octet, bit: $low, width: $width },
                    $( crate::values::Bits { name: $name, ident: stringify!($field), octet: $octet2, bit: $low2, width: $width2 }, )?
                )*],
                fields: &[],
            });
            /// Whether the tree is the value of the field alone: one field, not a flag.
            #[cfg(feature = "tree")]
            const BARE: bool = { let widths: &[u32] = &[$($width),*]; widths.len() == 1 && widths[0] > 1 };
            /// The bits of each octet that a field has.
            const MASKS: [u8; $n] = {
                let mut masks = [0u8; $n];
                $( pfcp_bits!(@mask masks, $octet, $low, $width [$($kind)? $(+ $octet2 $low2 $width2)?]); )*
                masks
            };

            /// Whether no bit of a field is set: "at least one bit shall be set to 1" of a
            /// value of flags alone.
            #[allow(dead_code)]
            fn none_set(&self) -> bool {
                let (octets, _) = self.octets();
                octets.iter().zip(Self::MASKS).all(|(octet, mask)| octet & mask == 0)
            }

            /// The octets of the fields, and how many are written.
            fn octets(&self) -> ([u8; $n], usize) {
                let mut octets = [0u8; $n];
                for (octet, (spare, mask)) in octets.iter_mut().zip(self.spare.iter().zip(Self::MASKS)) {
                    *octet = spare & !mask;
                }
                $( pfcp_bits!(@store octets, $width [$($kind)? $(+ $octet2 $low2 $width2)?] self.$field, $octet, $low); )*
                let mut used = usize::from(self.present).clamp($min, $n);
                if !self.extra.is_empty() {
                    used = $n;
                }
                for (at, octet) in octets.iter().enumerate().skip(used) {
                    if *octet != 0 {
                        used = at + 1;
                    }
                }
                (octets, used)
            }
        }

        impl crate::ie::Codec for $ty {
            fn decode(octets: &[u8]) -> Option<Self> {
                if octets.len() < $min {
                    return None;
                }
                let present = octets.len().min($n);
                let at = |octet: usize| if octet < present { octets[octet] } else { 0 };
                let mut spare = [0u8; $n];
                for octet in 0..present {
                    spare[octet] = octets[octet] & !Self::MASKS[octet];
                }
                Some(Self {
                    $( $field: pfcp_bits!(@read $width [$($kind)? $(+ $octet2 $low2 $width2)?] at, $octet, $low), )*
                    spare,
                    present: present as u8,
                    extra: crate::octets::Octets::copied(&octets[present..]),
                })
            }

            fn encode(&self, out: &mut alloc::vec::Vec<u8>) -> Result<(), crate::Error> {
                if let Some(field) = self.wide() {
                    return Err(crate::Error::FieldLength { ie: <Self as crate::ie::IeType>::TYPE_NAME, field });
                }
                let (octets, used) = self.octets();
                out.extend_from_slice(&octets[..used]);
                out.extend_from_slice(&self.extra);
                Ok(())
            }

            fn encoded_len(&self) -> usize {
                self.octets().1 + self.extra.len()
            }
        }

        impl $ty {
            /// The first field whose value is wider than its bits: encode() refuses it.
            #[allow(unused_comparisons)]
            fn wide(&self) -> Option<&'static str> {
                $(
                    if pfcp_bits!(@wide $width [$($kind)? $(+ $octet2 $low2 $width2)?] self.$field) {
                        return Some($name);
                    }
                )*
                None
            }
        }

        impl crate::check::Rules for $ty {
            fn check(&self, path: &crate::check::Path, found: &mut alloc::vec::Vec<crate::check::Deviation>) {
                if self.wide().is_some() {
                    found.push(crate::check::Deviation::new(path, $clause, crate::check::DeviationKind::Rule("a value wider than its bits")));
                }
                if self.spare.iter().any(|spare| *spare != 0) {
                    found.push(crate::check::Deviation::new(path, "8.1.2", crate::check::DeviationKind::SpareBits));
                }
                $( pfcp_bits!(@check [$($kind)? $(+ $octet2 $low2 $width2)?] self.$field, path, found); )*
                $(
                    let ($this, $path, $found) = (self, path, found);
                    $rules
                )?
            }
        }

        #[cfg(feature = "serde")]
        oxirush_utils::impl_serde!($ty);

        /// The flags that are set and the fields, with `Spare`, `length` (the octets of
        /// the fields that the value has, when it lacks some) and `extra` where they are
        /// not what a sender of this release writes.
        #[cfg(feature = "tree")]
        impl oxirush_utils::tree::Tree for $ty {
            const NAME: &'static str = <Self as crate::ie::IeType>::TYPE_NAME;

            fn to_tree(&self) -> oxirush_utils::tree::Value {
                if Self::BARE && self.spare.iter().all(|spare| *spare == 0) && usize::from(self.present) == $n && self.extra.is_empty() {
                    $( if Self::BARE { return pfcp_bits!(@tree $width [$($kind)? $(+ $octet2 $low2 $width2)?] self.$field); } )*
                }
                let mut members = oxirush_utils::tree::Members::new();
                $( pfcp_bits!(@put $width [$($kind)? $(+ $octet2 $low2 $width2)?] members, $name, self.$field); )*
                if self.spare.iter().any(|spare| *spare != 0) {
                    members.put("Spare", oxirush_utils::tree::octets(&self.spare));
                }
                if usize::from(self.present) < $n {
                    members.put("length", oxirush_utils::tree::unsigned(self.present.into()));
                }
                if !self.extra.is_empty() {
                    members.put(crate::ie::UNKNOWN_OCTETS, oxirush_utils::tree::octets(&self.extra));
                }
                members.finish()
            }

            fn from_tree(
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
            ) -> Result<Self, oxirush_utils::tree::Refused> {
                let mut bits = Self::default();
                if Self::BARE && !value.is_object() {
                    $( bits.$field = pfcp_bits!(@get $width [$($kind)? $(+ $octet2 $low2 $width2)?] value, reading)?; )*
                    return Ok(bits);
                }
                let read = reading.members(value, Self::MEMBERS)?;
                $(
                    if let Some(value) = reading.optional(&read, $name, |value, reading| pfcp_bits!(@get $width [$($kind)? $(+ $octet2 $low2 $width2)?] value, reading))? {
                        bits.$field = value;
                    }
                )*
                if let Some(spare) = reading.optional(&read, "Spare", |value, reading| reading.octet_array::<$n>(value))? {
                    bits.spare = spare;
                }
                if let Some(present) = reading.optional(&read, "length", |value, reading| reading.unsigned(value, $min, $n))? {
                    bits.present = present as u8;
                }
                bits.extra = reading
                    .optional(&read, crate::ie::UNKNOWN_OCTETS, |value, reading| reading.octets(value))?
                    .map(crate::octets::Octets::from)
                    .unwrap_or_default();
                if bits.spare.iter().zip(Self::MASKS).any(|(spare, mask)| spare & mask != 0) {
                    return Err(reading.refuse(oxirush_utils::tree::ErrorKind::Value, "Spare has a bit that a field has"));
                }
                Ok(bits)
            }
        }
    };
    // A field of one bit is a flag; of a few, a number or a value of its table (`as`); of
    // two parts (`+`), a number whose high bits are in the first and low bits in the second.
    (@type $width:tt [+ $octet2:literal $low2:literal $width2:tt]) => { u16 };
    (@wide 1 [] $value:expr) => { false };
    (@wide $width:tt [] $value:expr) => { u16::from($value) >= (1u16 << $width) };
    (@wide $width:tt [$kind:ident] $value:expr) => { u16::from($value.value()) >= (1u16 << $width) };
    (@wide $width:tt [+ $octet2:literal $low2:literal $width2:tt] $value:expr) => { u32::from($value) >= (1u32 << ($width + $width2)) };
    // A value of one field that is no flag is built from it.
    (@new $ty:ident [$field:ident $name:literal 1 []]) => {};
    (@new $ty:ident [$field:ident $name:literal $width:tt [$($kind:tt)*]]) => {
        impl $ty {
            #[doc = concat!("A value of its ", $name, " field, without spare bits.")]
            pub fn new($field: pfcp_bits!(@type $width [$($kind)*])) -> Self {
                Self { $field, ..Self::default() }
            }
        }
    };
    (@new $ty:ident $($fields:tt)*) => {};
    (@type 1 []) => { bool };
    (@type $width:tt []) => { u8 };
    (@type $width:tt [$kind:ident]) => { $kind };
    (@mask $masks:ident, $octet:literal, $low:literal, $width:tt [+ $octet2:literal $low2:literal $width2:tt]) => {
        pfcp_bits!(@mask $masks, $octet, $low, $width []);
        pfcp_bits!(@mask $masks, $octet2, $low2, $width2 []);
    };
    (@mask $masks:ident, $octet:literal, $low:literal, $width:tt [$($kind:ident)?]) => {
        $masks[$octet] |= ((((1u16 << $width) - 1) << ($low - 1)) & 0xff) as u8;
    };
    (@read $width:tt [+ $octet2:literal $low2:literal $width2:tt] $at:ident, $octet:literal, $low:literal) => {
        (u16::from(pfcp_bits!(@read $width [] $at, $octet, $low)) << $width2) | u16::from(pfcp_bits!(@read $width2 [] $at, $octet2, $low2))
    };
    (@read 1 [] $at:ident, $octet:literal, $low:literal) => { $at($octet) >> ($low - 1) & 1 == 1 };
    (@read $width:tt [] $at:ident, $octet:literal, $low:literal) => { ($at($octet) >> ($low - 1)) & (((1u16 << $width) - 1) as u8) };
    (@read $width:tt [$kind:ident] $at:ident, $octet:literal, $low:literal) => {
        $kind::from_value(pfcp_bits!(@read $width [] $at, $octet, $low))
    };
    (@store $octets:ident, $width:tt [+ $octet2:literal $low2:literal $width2:tt] $value:expr, $octet:literal, $low:literal) => {
        $octets[$octet] |= pfcp_bits!(@write $width [] ($value >> $width2) as u8, $low);
        $octets[$octet2] |= pfcp_bits!(@write $width2 [] ($value & ((1u16 << $width2) - 1)) as u8, $low2);
    };
    (@store $octets:ident, $width:tt [$($kind:ident)?] $value:expr, $octet:literal, $low:literal) => {
        $octets[$octet] |= pfcp_bits!(@write $width [$($kind)?] $value, $low);
    };
    (@write 1 [] $value:expr, $low:literal) => { u8::from($value) << ($low - 1) };
    (@write $width:tt [] $value:expr, $low:literal) => { ($value & (((1u16 << $width) - 1) as u8)) << ($low - 1) };
    (@write $width:tt [$kind:ident] $value:expr, $low:literal) => { pfcp_bits!(@write $width [] $value.value(), $low) };
    (@check [+ $($part:tt)*] $value:expr, $path:ident, $found:ident) => {};
    (@check [] $value:expr, $path:ident, $found:ident) => {};
    (@check [$kind:ident] $value:expr, $path:ident, $found:ident) => {
        crate::values::Field::check(&$value, $path, Self::CLAUSE, $found)
    };
    (@tree $width:tt [+ $($part:tt)*] $value:expr) => { oxirush_utils::tree::unsigned($value.into()) };
    (@tree 1 [] $value:expr) => { oxirush_utils::tree::Value::Bool($value) };
    (@tree $width:tt [] $value:expr) => { oxirush_utils::tree::unsigned($value.into()) };
    (@tree $width:tt [$kind:ident] $value:expr) => { $value.tree() };
    (@put 1 [] $members:ident, $name:literal, $value:expr) => {
        if $value { $members.put($name, oxirush_utils::tree::Value::Bool(true)); }
    };
    (@put $width:tt [$($part:tt)*] $members:ident, $name:literal, $value:expr) => {
        $members.put($name, pfcp_bits!(@tree $width [$($part)*] $value));
    };
    (@get $width:tt [+ $octet2:literal $low2:literal $width2:tt] $value:expr, $reading:expr) => {
        $reading.unsigned($value, 0, (1u64 << ($width + $width2)) - 1).map(|value| value as u16)
    };
    (@get 1 [] $value:expr, $reading:expr) => { $reading.boolean($value) };
    (@get $width:tt [] $value:expr, $reading:expr) => {
        $reading.unsigned($value, 0, (1u64 << $width) - 1).map(|value| value as u8)
    };
    (@get $width:tt [$kind:ident] $value:expr, $reading:expr) => {
        $kind::read_tree($value, $reading, ((1u16 << $width) - 1) as u8)
    };
}

/// The messages of Table 7.3-1, one each: their type and the struct of their table. It
/// writes the body of a message, and what is done with it by its type.
macro_rules! pfcp_messages {
    ($( $code:literal $ty:ident [$($interface:ident)*] ),* $(,)?) => { pastey::paste! {
        /// Every message type of Table 7.3-1, in the order of their numbers.
        pub static MESSAGE_TYPES: &[crate::message::MessageTypeInfo] = &[$(
            crate::message::MessageTypeInfo {
                message_type: $code,
                interfaces: crate::table::Interfaces(0 $(| crate::table::Interfaces::$interface.0)*),
                table: &crate::registry::[<$ty:snake:upper _TABLE>],
            },
        )*];

        /// The body of a message: one type of Table 7.3-1 each.
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[non_exhaustive]
        pub enum Body {
            $(
                #[doc = concat!("Message type ", stringify!($code), ".")]
                $ty(alloc::boxed::Box<crate::registry::$ty>),
            )*
            /// A message type that Table 7.3-1 does not have, with the octets after its
            /// header (§7.6.4).
            Other {
                /// The message type.
                message_type: u8,
                /// The octets of its IEs.
                octets: crate::octets::Octets,
            },
        }

        $(
            impl From<crate::registry::$ty> for Body {
                fn from(body: crate::registry::$ty) -> Self {
                    Self::$ty(alloc::boxed::Box::new(body))
                }
            }
        )*

        impl Body {
            /// The message type.
            pub fn message_type(&self) -> u8 {
                match self {
                    $( Self::$ty(_) => $code, )*
                    Self::Other { message_type, .. } => *message_type,
                }
            }

            /// The table of the message.
            pub fn table(&self) -> Option<&'static crate::table::Table> {
                match self {
                    $( Self::$ty(_) => Some(crate::registry::$ty::table()), )*
                    Self::Other { .. } => None,
                }
            }

            /// The name that Table 7.3-1 gives the message.
            pub fn name(&self) -> Option<&'static str> {
                self.table().map(|table| table.name)
            }

            /// The names of the messages, in the order of their types.
            #[cfg(feature = "tree")]
            pub(crate) fn names() -> [&'static str; [$($code),*].len()] {
                [$( crate::registry::$ty::table().name ),*]
            }

            pub(crate) fn decode(message_type: u8, octets: &[u8]) -> Result<Self, crate::ie::IeFault> {
                Ok(match message_type {
                    $( $code => {
                        // The message is decoded in its box, and not moved there.
                        let mut body = alloc::boxed::Box::<crate::registry::$ty>::default();
                        crate::table::decode_scope_sized(&mut *body, octets, true)?;
                        Self::$ty(body)
                    } )*
                    other => Self::Other { message_type: other, octets: crate::octets::Octets::copied(octets) },
                })
            }

            pub(crate) fn encode(&self, out: &mut alloc::vec::Vec<u8>) -> Result<(), crate::Error> {
                match self {
                    $( Self::$ty(body) => crate::table::encode_scope(&**body, out), )*
                    Self::Other { octets, .. } => {
                        out.extend_from_slice(octets);
                        Ok(())
                    }
                }
            }

            pub(crate) fn encoded_len(&self) -> usize {
                match self {
                    $( Self::$ty(body) => crate::table::Scope::encoded_len(&**body), )*
                    Self::Other { octets, .. } => octets.len(),
                }
            }

            /// The octets that the body takes beyond its own size: its box, and what its
            /// IEs hold ([`Listed::held`](crate::ie::Listed::held)).
            #[cfg(feature = "endpoint")]
            pub(crate) fn held(&self) -> usize {
                match self {
                    $( Self::$ty(body) => core::mem::size_of::<crate::registry::$ty>() + crate::table::Scope::held(&**body), )*
                    Self::Other { .. } => 0,
                }
            }

            pub(crate) fn check(&self, path: &crate::check::Path, context: crate::check::Context, found: &mut alloc::vec::Vec<crate::check::Deviation>) {
                match self {
                    $( Self::$ty(body) => crate::check::check_scope(&**body, path, context, found), )*
                    Self::Other { message_type, .. } => {
                        let _ = context;
                        found.push(crate::check::Deviation::new(
                            "/message",
                            "7.6.4",
                            crate::check::DeviationKind::UnknownMessage { message_type: *message_type },
                        ));
                    }
                }
            }

            #[cfg(feature = "tree")]
            pub(crate) fn ies_tree(&self) -> oxirush_utils::tree::Value {
                match self {
                    $( Self::$ty(body) => crate::tree::scope_to_tree(&**body), )*
                    Self::Other { octets, .. } => oxirush_utils::tree::alternative("octets", oxirush_utils::tree::octets(octets)),
                }
            }

            /// The body of the message of `kind`, a position among the names or a message
            /// type that none has, from the tree of its IEs.
            #[cfg(feature = "tree")]
            pub(crate) fn from_ies_tree(
                kind: Result<usize, u8>,
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
            ) -> Result<Self, oxirush_utils::tree::Refused> {
                const CODES: &[u8] = &[$($code),*];
                let code = match kind {
                    Ok(position) => CODES[position],
                    Err(code) => code,
                };
                Ok(match code {
                    $( $code => Self::$ty(alloc::boxed::Box::new(crate::tree::scope_from_tree(value, reading)?)), )*
                    other => {
                        let (_, octets) = reading.alternative(value, &["octets"])?;
                        let octets = reading.within("octets", octets, |value, reading| reading.octets(value))?;
                        Self::Other { message_type: other, octets: octets.into() }
                    }
                })
            }
        }
    }};
}

/// A message or the content of a grouped IE, from its table of clause 7: a struct with a
/// field for each row, `new()` with the mandatory IEs, a `with_` builder for each row,
/// the codec, the check and the tree.
///
/// A row is `field: "Name" P TYPE [INTERFACES]`, where `P` is `M`, `C` or `O`, followed by
/// `*` for a list or `*N` for a list of at most N, and `TYPE` the type of its value, or
/// `raw N` for an IE type that the crate keeps as octets. `Cb` and `Ob` are `C` and `O` of
/// a grouped IE that the field boxes, as it is large and most scopes lack it. A field that several rows
/// share, which the wire does not tell apart, lists them after `roles`, each with its
/// presence and its interfaces. A row whose condition the scope alone shows ends with
/// `absent(|scope| condition)`, where `check()` reports it there, and `if |scope|
/// condition`, where it reports it missing.
macro_rules! pfcp_table {
    // A table whose mandatory IEs differ between its interfaces has a constructor for each
    // interface that it lists, and no `new()`.
    (
        $(#[$meta:meta])*
        $kind:ident $ty:ident = $code:literal, $name:literal, $id:literal by [$($by:ident)*] { $($rows:tt)* }
    ) => {
        pfcp_table!(@table [$($by)*] $(#[$meta])* $kind $ty = $code, $name, $id { $($rows)* });
    };
    (
        $(#[$meta:meta])*
        $kind:ident $ty:ident = $code:literal, $name:literal, $id:literal { $($rows:tt)* }
    ) => {
        pfcp_table!(@table [] $(#[$meta])* $kind $ty = $code, $name, $id { $($rows)* });
    };
    (
        @table [$($by:ident)*]
        $(#[$meta:meta])*
        $kind:ident $ty:ident = $code:literal, $name:literal, $id:literal {
            $( $field:ident : $row:literal $p:ident $(* $($max:literal)?)? $vty:ident $($raw:literal)?
                [$($interface:ident)*] $(roles [$($role:literal $rp:ident [$($ri:ident)*]),*])?
                $(absent(|$ascope:ident| $absent:expr))? $(if |$scope:ident| $condition:expr)? , )*
        }
    ) => { pastey::paste! {
        $(#[$meta])*
        #[derive(Debug, Clone, Default, PartialEq, Eq)]
        pub struct $ty {
            $(
                #[doc = concat!("The ", $row, " IE.")]
                pub $field: pfcp_table!(@field [$(* $($max)?)?] $p (pfcp_table!(@type $vty $($raw)?))),
            )*
            /// The IEs that the scope keeps as octets, in the order of the wire.
            pub raw: alloc::vec::Vec<crate::ie::RawIe>,
            /// The order of the wire, when it is not that of the table: each row, its values
            /// then the IEs of its type in `raw`, and the IEs of no row last.
            pub order: alloc::vec::Vec<crate::ie::Placed>,
        }

        const _: () = assert!(
            <[&str]>::len(&[$($row),*]) < crate::table::MAX_ROWS,
            "a table of more rows than the encoder counts"
        );

        pub(crate) static [<$ty:snake:upper _TABLE>]: crate::table::Table = crate::table::Table {
            id: $id,
            name: $name,
            code: $code,
            constructors: crate::table::Interfaces(0 $(| crate::table::Interfaces::$by.0)*),
            rows: &[$(
                crate::table::Row {
                    name: $row,
                    ie_type: <pfcp_table!(@type_static $vty $($raw)?) as crate::ie::IeType>::IE_TYPE,
                    presence: pfcp_table!(@presence $p),
                    repeat: pfcp_table!(@repeat $(* $($max)?)?),
                    interfaces: crate::table::Interfaces(0 $(| crate::table::Interfaces::$interface.0)*),
                    mandatory: crate::table::mandatory(
                        pfcp_table!(@presence $p),
                        crate::table::Interfaces(0 $(| crate::table::Interfaces::$interface.0)*),
                        &[$($(crate::table::Role {
                            name: $role,
                            presence: pfcp_table!(@presence $rp),
                            interfaces: crate::table::Interfaces(0 $(| crate::table::Interfaces::$ri.0)*),
                        }),*)?],
                    ),
                    roles: &[$($(crate::table::Role {
                        name: $role,
                        presence: pfcp_table!(@presence $rp),
                        interfaces: crate::table::Interfaces(0 $(| crate::table::Interfaces::$ri.0)*),
                    }),*)?],
                    checked: pfcp_table!(@checked $($scope)? $($ascope)?),
                },
            )*],
        };

        impl $ty {
            /// The table of the scope.
            pub fn table() -> &'static crate::table::Table {
                &[<$ty:snake:upper _TABLE>]
            }

            $(
                #[doc = concat!("Builder: add the ", $row, " IE.")]
                pub fn [<with_ $field>](mut self, value: pfcp_table!(@type $vty $($raw)?)) -> Self {
                    crate::table::FieldValues::<pfcp_table!(@type $vty $($raw)?)>::add(&mut self.$field, value);
                    self
                }
            )*
        }

        pfcp_table!(@ctors [$($by)*] $ty { $( $field : $row $p $(* $($max)?)? $vty $($raw)? [$($interface)*] , )* });

        // A table without rows leaves its arguments unused.
        #[allow(unused_variables, unused_mut, unused_assignments)]
        impl crate::table::Scope for $ty {
            fn table() -> &'static crate::table::Table {
                &[<$ty:snake:upper _TABLE>]
            }

            #[allow(unused_assignments, unused_variables, unused_mut)]
            fn position(ie_type: u16) -> Option<usize> {
                let mut at = 0;
                $(
                    if ie_type == <pfcp_table!(@type_any $vty $($raw)?) as crate::ie::IeType>::IE_TYPE {
                        return Some(at);
                    }
                    at += 1;
                )*
                None
            }

            const PRESIZE: bool = false $( || pfcp_table!(@large [$(* $($max)?)?] (pfcp_table!(@type_static $vty $($raw)?))) )*;

            // Only the IEs that can be values are counted: not one of a null length, nor
            // one whose IEs run past it, which the scope keeps as octets.
            #[allow(unused_variables)]
            fn presize(&mut self, octets: &[u8]) {
                $( let mut [<count_ $field>] = 0usize; )*
                for ie in crate::framing::ies(octets).flatten() {
                    $(
                        if pfcp_table!(@large [$(* $($max)?)?] (pfcp_table!(@type_static $vty $($raw)?)))
                            && ie.ie_type == <pfcp_table!(@type_any $vty $($raw)?) as crate::ie::IeType>::IE_TYPE
                        {
                            let content = ie.content();
                            if !content.is_empty() && crate::framing::ies(content).all(|inner| inner.is_ok()) {
                                [<count_ $field>] += 1;
                            }
                            continue;
                        }
                    )*
                }
                $( pfcp_table!(@reserve [$(* $($max)?)?] self.$field, [<count_ $field>]); )*
            }

            fn place(&mut self, ie_type: u16, body: &[u8]) -> crate::ie::Placing {
                $(
                    if ie_type == <pfcp_table!(@type $vty $($raw)?) as crate::ie::IeType>::IE_TYPE {
                        return pfcp_table!(@place [$(* $($max)?)?] $p (pfcp_table!(@type $vty $($raw)?)) self.$field, body);
                    }
                )*
                crate::ie::Placing::Unexpected
            }

            fn emit(&self, ie_type: u16, nth: usize, out: &mut alloc::vec::Vec<u8>) -> Result<bool, crate::Error> {
                $(
                    if ie_type == <pfcp_table!(@type $vty $($raw)?) as crate::ie::IeType>::IE_TYPE {
                        return crate::table::emit_field::<pfcp_table!(@type $vty $($raw)?), _>(&self.$field, nth, out);
                    }
                )*
                Ok(false)
            }

            fn encoded_len(&self) -> usize {
                let mut length = 0;
                $( pfcp_table!(@each [$(* $($max)?)?] (pfcp_table!(@type $vty $($raw)?)) self.$field, |value| {
                    length += 4 + crate::ie::Codec::encoded_len(value);
                }); )*
                for ie in &self.raw {
                    length += 4 + 2 * usize::from(ie.enterprise_id.is_some()) + ie.octets.len();
                }
                length
            }

            fn encode_fields(&self, out: &mut alloc::vec::Vec<u8>) -> Result<(), crate::Error> {
                $( pfcp_table!(@each [$(* $($max)?)?] (pfcp_table!(@type $vty $($raw)?)) self.$field, |value| {
                    crate::ie::encode_value(value, out)?;
                }); )*
                Ok(())
            }

            #[cfg(feature = "endpoint")]
            fn held(&self) -> usize {
                let mut held = self.raw.capacity() * core::mem::size_of::<crate::ie::RawIe>()
                    + self.order.capacity() * core::mem::size_of::<crate::ie::Placed>();
                $( held += pfcp_table!(@held [$(* $($max)?)?] $p (pfcp_table!(@type $vty $($raw)?)) self.$field); )*
                held
            }

            fn count(&self, ie_type: u16) -> usize {
                $(
                    if ie_type == <pfcp_table!(@type $vty $($raw)?) as crate::ie::IeType>::IE_TYPE {
                        return crate::table::FieldValues::<pfcp_table!(@type $vty $($raw)?)>::values(&self.$field).len();
                    }
                )*
                0
            }

            fn decodes(&self, ie_type: u16, octets: &[u8]) -> bool {
                $(
                    if ie_type == <pfcp_table!(@type $vty $($raw)?) as crate::ie::IeType>::IE_TYPE {
                        return <pfcp_table!(@type_any $vty $($raw)?) as crate::ie::Codec>::decode(octets).is_some();
                    }
                )*
                false
            }

            fn raw(&self) -> &[crate::ie::RawIe] { &self.raw }
            fn raw_mut(&mut self) -> &mut alloc::vec::Vec<crate::ie::RawIe> { &mut self.raw }
            fn order(&self) -> &[crate::ie::Placed] { &self.order }
            fn order_mut(&mut self) -> &mut alloc::vec::Vec<crate::ie::Placed> { &mut self.order }
        }

        // A table without rows leaves its arguments unused.
        #[allow(unused_variables, unused_mut, unused_assignments)]
        impl crate::check::Checked for $ty {
            fn check_values(&self, path: &crate::check::Path, context: crate::check::Context, found: &mut alloc::vec::Vec<crate::check::Deviation>) {
                let mut row = 0;
                $(
                    crate::check::check_field_values::<pfcp_table!(@type $vty $($raw)?), _, _>(
                        self, row, &self.$field, path, context, found,
                    );
                    $({
                        let $scope: &Self = self;
                        if $condition {
                            crate::check::condition_missing(self, row, path, context, found);
                        }
                    })?
                    $({
                        let $ascope: &Self = self;
                        if $absent {
                            crate::check::condition_absent(self, row, path, context, found);
                        }
                    })?
                    row += 1;
                )*
            }
        }

        pfcp_table!(@kind $kind $ty);

        #[cfg(feature = "tree")]
        // A table without rows leaves its arguments unused.
        #[allow(unused_variables, unused_mut, unused_assignments)]
        impl crate::tree::TreeScope for $ty {
            fn field_tree(&self, ie_type: u16, nth: usize) -> Option<oxirush_utils::tree::Value> {
                $(
                    if ie_type == <pfcp_table!(@type $vty $($raw)?) as crate::ie::IeType>::IE_TYPE {
                        return crate::tree::field_tree::<pfcp_table!(@type $vty $($raw)?), _>(&self.$field, nth);
                    }
                )*
                None
            }

            fn read_field(
                &mut self,
                ie_type: u16,
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
            ) -> Result<(), oxirush_utils::tree::Refused> {
                $(
                    if ie_type == <pfcp_table!(@type $vty $($raw)?) as crate::ie::IeType>::IE_TYPE {
                        return crate::tree::read_field::<pfcp_table!(@type $vty $($raw)?), _>(&mut self.$field, value, reading);
                    }
                )*
                Ok(())
            }
        }
    } };

    // ── The parts of a row ──────────────────────────────────────────────────

    (@type raw $raw:literal) => { crate::values::Raw<$raw> };
    (@type $vty:ident) => { $vty };
    (@type_static raw $raw:literal) => { crate::values::Raw<$raw> };
    (@type_static $vty:ident) => { $vty };
    (@type_any raw $raw:literal) => { crate::values::Raw<$raw> };
    (@type_any $vty:ident) => { $vty };
    // A row that is there once is a field of its value, in place, but a grouped IE of `Cb`
    // or `Ob`, large and rare, which is boxed.
    (@field [] Cb ($t:ty)) => { Option<alloc::boxed::Box<$t>> };
    (@field [] Ob ($t:ty)) => { Option<alloc::boxed::Box<$t>> };
    (@field [] $p:ident ($t:ty)) => { Option<$t> };
    (@field [* $($max:literal)?] $p:ident ($t:ty)) => { alloc::vec::Vec<$t> };
    (@presence M) => { crate::table::Presence::Mandatory };
    (@presence C) => { crate::table::Presence::Conditional };
    (@presence O) => { crate::table::Presence::Optional };
    (@presence Cb) => { crate::table::Presence::Conditional };
    (@presence Ob) => { crate::table::Presence::Optional };
    (@repeat) => { crate::table::Repeat::Once };
    (@repeat *) => { crate::table::Repeat::Any };
    (@repeat * $max:literal) => { crate::table::Repeat::AtMost($max) };
    // Each value of a field: that of a field there once, or those of a list.
    (@each [] ($t:ty) $f:expr, |$value:ident| $body:block) => {
        if let Some($value) = crate::table::FieldValues::<$t>::first(&$f) $body
    };
    (@each [* $($max:literal)?] ($t:ty) $f:expr, |$value:ident| $body:block) => {
        for $value in crate::table::FieldValues::<$t>::values(&$f) $body
    };
    (@checked) => { false };
    (@checked $($scope:ident)+) => { true };
    (@place [] $p:ident ($t:ty) $f:expr, $body:expr) => {
        pfcp_table!(@place_once $p ($t) $f, $body)
    };
    (@place_once Cb ($t:ty) $f:expr, $body:expr) => {
        pfcp_table!(@placing $f, crate::table::decode_boxed(&mut $f, $body))
    };
    (@place_once Ob ($t:ty) $f:expr, $body:expr) => {
        pfcp_table!(@placing $f, crate::table::decode_boxed(&mut $f, $body))
    };
    (@place_once $p:ident ($t:ty) $f:expr, $body:expr) => {
        pfcp_table!(@placing $f, crate::ie::Listed::decode_into(&mut $f, $body))
    };
    // A row there once that has its value repeats it; one that has none takes it when it
    // decodes.
    (@placing $f:expr, $decoded:expr) => {
        match $f.is_some() {
            true => crate::ie::Placing::Repeated,
            false if $decoded => crate::ie::Placing::Placed,
            false => crate::ie::Placing::Malformed,
        }
    };
    (@place [* $($max:literal)?] $p:ident ($t:ty) $f:expr, $body:expr) => {
        if pfcp_table!(@full [$($max)?] $f) {
            crate::ie::Placing::Repeated
        } else if <$t as crate::ie::Listed>::decode_push(&mut $f, $body) {
            crate::ie::Placing::Placed
        } else {
            crate::ie::Placing::Malformed
        }
    };
    // A list of values larger than this is sized before it is filled.
    (@large [] ($t:ty)) => { false };
    (@large [* $($max:literal)?] ($t:ty)) => { core::mem::size_of::<$t>() > 64 };
    (@reserve [] $f:expr, $n:expr) => { let _ = $n; };
    (@reserve [* $($max:literal)?] $f:expr, $n:expr) => { $f.reserve_exact($n) };
    // What a field takes beyond its own size: a list its entries, a box its value.
    (@held [* $($max:literal)?] $p:ident ($t:ty) $f:expr) => {
        $f.capacity() * core::mem::size_of::<$t>() + $f.iter().map(crate::ie::Listed::held).sum::<usize>()
    };
    (@held [] Cb ($t:ty) $f:expr) => { pfcp_table!(@held_box ($t) $f) };
    (@held [] Ob ($t:ty) $f:expr) => { pfcp_table!(@held_box ($t) $f) };
    (@held [] $p:ident ($t:ty) $f:expr) => { $f.as_ref().map_or(0, crate::ie::Listed::held) };
    (@held_box ($t:ty) $f:expr) => {
        $f.as_ref().map_or(0, |value| core::mem::size_of::<$t>() + crate::table::Scope::held(&**value))
    };
    (@full [] $f:expr) => { false };
    (@full [$max:literal] $f:expr) => { $f.len() >= $max };

    // ── A message, or the content of a grouped IE ───────────────────────────

    (@kind group $ty:ident) => {
        impl crate::ie::Codec for $ty {
            fn decode(octets: &[u8]) -> Option<Self> {
                crate::table::decode_scope(octets).ok()
            }

            fn encode(&self, out: &mut alloc::vec::Vec<u8>) -> Result<(), crate::Error> {
                crate::table::encode_scope(self, out)
            }

            fn encoded_len(&self) -> usize {
                crate::table::Scope::encoded_len(self)
            }
        }

        impl crate::ie::Listed for $ty {
            // A grouped IE is large: it is decoded in its place, and not moved there.
            fn decode_into(slot: &mut Option<Self>, octets: &[u8]) -> bool {
                let scope = slot.insert(Self::default());
                if crate::table::decode_scope_into(scope, octets).is_err() {
                    *slot = None;
                    return false;
                }
                true
            }

            fn decode_push(list: &mut alloc::vec::Vec<Self>, octets: &[u8]) -> bool {
                list.push(Self::default());
                let last = list.len() - 1;
                if crate::table::decode_scope_into(&mut list[last], octets).is_err() {
                    list.pop();
                    return false;
                }
                true
            }

            #[cfg(feature = "endpoint")]
            fn held(&self) -> usize {
                crate::table::Scope::held(self)
            }

            fn check_in(&self, path: &crate::check::Path, context: crate::check::Context, found: &mut alloc::vec::Vec<crate::check::Deviation>) {
                crate::check::check_scope(self, path, context, found);
            }
        }

        impl crate::check::Rules for $ty {
            /// Its table on the interfaces that it has, as the receiver of a response: the
            /// IEs of any, and those that all need.
            fn check(&self, path: &crate::check::Path, found: &mut alloc::vec::Vec<crate::check::Deviation>) {
                let interfaces = <Self as crate::table::Scope>::table().interfaces();
                crate::check::check_scope(self, path, crate::check::Context::on(interfaces), found);
            }
        }

        #[cfg(feature = "serde")]
        oxirush_utils::impl_serde!($ty);

        #[cfg(feature = "tree")]
        impl oxirush_utils::tree::Tree for $ty {
            const NAME: &'static str = <$ty as crate::ie::IeType>::TYPE_NAME;

            fn to_tree(&self) -> oxirush_utils::tree::Value {
                crate::tree::scope_to_tree(self)
            }

            fn from_tree(
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
            ) -> Result<Self, oxirush_utils::tree::Refused> {
                crate::tree::scope_from_tree(value, reading)
            }
        }
    };
    (@kind message $ty:ident) => {};

    // The constructors: `new()` with the mandatory rows of every interface, or one for each
    // interface that the table lists, with the mandatory rows of that interface.
    (@ctors [] $ty:ident { $($rows:tt)* }) => {
        pfcp_table!(@new new * $ty "The scope with its mandatory IEs, which each interface of its table has alike." [] [] $($rows)*);
    };
    (@ctors [$($by:ident)+] $ty:ident $rows:tt) => {
        pfcp_table!(@each [$($by)+] $ty $rows);
    };
    (@each [] $ty:ident $rows:tt) => {};
    (@each [$on:ident $($more:ident)*] $ty:ident $rows:tt) => {
        pfcp_table!(@ctor $on $ty $rows);
        pfcp_table!(@each [$($more)*] $ty $rows);
    };
    (@ctor SXA $ty:ident { $($rows:tt)* }) => { pfcp_table!(@new new_sxa SXA $ty "The scope with its mandatory IEs on Sxa." [] [] $($rows)*); };
    (@ctor SXB $ty:ident { $($rows:tt)* }) => { pfcp_table!(@new new_sxb SXB $ty "The scope with its mandatory IEs on Sxb." [] [] $($rows)*); };
    (@ctor SXC $ty:ident { $($rows:tt)* }) => { pfcp_table!(@new new_sxc SXC $ty "The scope with its mandatory IEs on Sxc." [] [] $($rows)*); };
    (@ctor N4 $ty:ident { $($rows:tt)* }) => { pfcp_table!(@new new_n4 N4 $ty "The scope with its mandatory IEs on N4." [] [] $($rows)*); };
    (@ctor N4MB $ty:ident { $($rows:tt)* }) => { pfcp_table!(@new new_n4mb N4MB $ty "The scope with its mandatory IEs on N4mb." [] [] $($rows)*); };
    // A constructor, with the fields of the mandatory rows of `$on` (`*` for any interface),
    // which a muncher collects.
    (@new $name:ident $on:tt $ty:ident $doc:literal [$($arg:tt)*] [$( ($f:ident [$($m:tt)*] ($ft:ty)) )*]) => {
        impl $ty {
            #[doc = $doc]
            #[allow(clippy::too_many_arguments)]
            pub fn $name($($arg)*) -> Self {
                #[allow(unused_mut)]
                let mut scope = Self::default();
                $( crate::table::FieldValues::<$ft>::add(&mut scope.$f, $f); )*
                scope
            }
        }
    };
    (@new $name:ident $on:tt $ty:ident $doc:literal [$($arg:tt)*] [$($set:tt)*] $field:ident : $row:literal M $(* $($max:literal)?)? $vty:ident $($raw:literal)? [$($i:ident)*] , $($rest:tt)*) => {
        pfcp_table!(@in $on [$($i)*] $name $ty $doc [$($arg)*] [$($set)*] ($field [$(* $($max)?)?] (pfcp_table!(@type $vty $($raw)?))) $($rest)*);
    };
    (@new $name:ident $on:tt $ty:ident $doc:literal [$($arg:tt)*] [$($set:tt)*] $field:ident : $row:literal $p:ident $(* $($max:literal)?)? $vty:ident $($raw:literal)? [$($i:ident)*] , $($rest:tt)*) => {
        pfcp_table!(@new $name $on $ty $doc [$($arg)*] [$($set)*] $($rest)*);
    };
    // A mandatory row is an argument where its interfaces have `$on`.
    (@in * [$($i:ident)*] $name:ident $ty:ident $doc:literal [$($arg:tt)*] [$($set:tt)*] ($field:ident [$($m:tt)*] ($t:ty)) $($rest:tt)*) => {
        pfcp_table!(@new $name * $ty $doc [$($arg)* $field: $t,] [$($set)* ($field [$($m)*] ($t))] $($rest)*);
    };
    (@in SXA [SXA $($i:ident)*] $name:ident $ty:ident $doc:literal [$($arg:tt)*] [$($set:tt)*] ($field:ident [$($m:tt)*] ($t:ty)) $($rest:tt)*) => {
        pfcp_table!(@new $name SXA $ty $doc [$($arg)* $field: $t,] [$($set)* ($field [$($m)*] ($t))] $($rest)*);
    };
    (@in SXB [SXB $($i:ident)*] $name:ident $ty:ident $doc:literal [$($arg:tt)*] [$($set:tt)*] ($field:ident [$($m:tt)*] ($t:ty)) $($rest:tt)*) => {
        pfcp_table!(@new $name SXB $ty $doc [$($arg)* $field: $t,] [$($set)* ($field [$($m)*] ($t))] $($rest)*);
    };
    (@in SXC [SXC $($i:ident)*] $name:ident $ty:ident $doc:literal [$($arg:tt)*] [$($set:tt)*] ($field:ident [$($m:tt)*] ($t:ty)) $($rest:tt)*) => {
        pfcp_table!(@new $name SXC $ty $doc [$($arg)* $field: $t,] [$($set)* ($field [$($m)*] ($t))] $($rest)*);
    };
    (@in N4 [N4 $($i:ident)*] $name:ident $ty:ident $doc:literal [$($arg:tt)*] [$($set:tt)*] ($field:ident [$($m:tt)*] ($t:ty)) $($rest:tt)*) => {
        pfcp_table!(@new $name N4 $ty $doc [$($arg)* $field: $t,] [$($set)* ($field [$($m)*] ($t))] $($rest)*);
    };
    (@in N4MB [N4MB $($i:ident)*] $name:ident $ty:ident $doc:literal [$($arg:tt)*] [$($set:tt)*] ($field:ident [$($m:tt)*] ($t:ty)) $($rest:tt)*) => {
        pfcp_table!(@new $name N4MB $ty $doc [$($arg)* $field: $t,] [$($set)* ($field [$($m)*] ($t))] $($rest)*);
    };
    (@in $on:tt [$other:ident $($i:ident)*] $name:ident $ty:ident $doc:literal [$($arg:tt)*] [$($set:tt)*] $row:tt $($rest:tt)*) => {
        pfcp_table!(@in $on [$($i)*] $name $ty $doc [$($arg)*] [$($set)*] $row $($rest)*);
    };
    (@in $on:tt [] $name:ident $ty:ident $doc:literal [$($arg:tt)*] [$($set:tt)*] $row:tt $($rest:tt)*) => {
        pfcp_table!(@new $name $on $ty $doc [$($arg)*] [$($set)*] $($rest)*);
    };
}

/// The values that a table of clause 8.2 names: a variant each, and `Other` for a value that
/// the table has as spare or reserved, or does not have, kept as it is. A field of `bits`
/// bits, or a whole octet whose other bits are spare.
///
/// ```text
/// pub enum Gate "Table 8.2.7-1 and Table 8.2.7-2" bits 2 {
///     0 Open "OPEN",
///     1 Closed "CLOSED",
/// }
/// ```
macro_rules! pfcp_enum {
    ($(
        $(#[$meta:meta])*
        pub enum $ty:ident $table:literal bits $bits:literal $(reserved [$($reserved:literal),*])?
            $(read [$($from:literal ..= $to:literal as $target:literal),+])? {
            $( $value:literal $variant:ident $name:literal ),* $(,)?
        }
    )*) => {$(
        $(#[$meta])*
        ///
        /// Two values are equal when their numbers are: `Other` of a number that the table
        /// names is the variant of that name, which [`from_value`](Self::from_value) gives.
        #[derive(Debug, Clone, Copy)]
        #[non_exhaustive]
        pub enum $ty {
            $(
                #[doc = concat!(stringify!($value), ": ", $name, ".")]
                $variant,
            )*
            /// A value that the table has as spare or reserved, or does not have.
            Other(u8),
        }

        impl PartialEq for $ty {
            fn eq(&self, other: &Self) -> bool {
                self.value() == other.value()
            }
        }

        impl Eq for $ty {}

        impl core::hash::Hash for $ty {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                self.value().hash(state);
            }
        }

        impl crate::values::Narrowable for $ty {
            const BITS: u32 = $bits;
            fn from_value(value: u8) -> Self {
                Self::from_value(value)
            }
            fn value(self) -> u8 {
                self.value()
            }
        }

        impl $ty {
            /// The tables of the values.
            pub const TABLE: &'static str = $table;
            /// The values that the tables name, with their names.
            pub const NAMES: &'static [(u8, &'static str)] = &[$(($value, $name)),*];
            /// The width of the field, in bits.
            pub const BITS: u32 = $bits;
            /// The values that the tables reserve: a receiver takes the IE as incorrect
            /// (§7.6.8), where it ignores a spare one.
            pub const RESERVED: &'static [u8] = &[$($($reserved),*)?];
            /// The values that a sender does not send and a receiver reads as another, as
            /// the tables say: from, to, and the value that they are read as.
            pub const READ_AS: &'static [(u8, u8, u8)] = &[$($(($from, $to, $target)),+)?];

            /// The variant of a number.
            pub const fn from_value(value: u8) -> Self {
                match value {
                    $( $value => Self::$variant, )*
                    other => Self::Other(other),
                }
            }

            /// The number.
            pub const fn value(self) -> u8 {
                match self {
                    $( Self::$variant => $value, )*
                    Self::Other(value) => value,
                }
            }

            /// The value as a receiver takes it: a value that the table has a sender not
            /// send, and a receiver read as another, is that other (§7.6.8).
            pub const fn effective(self) -> Self {
                match self.value() {
                    $($( $from..=$to => Self::from_value($target), )+)?
                    _ => self,
                }
            }

            /// The name that the table gives the value: `None` for `Other`.
            pub const fn name(self) -> Option<&'static str> {
                match Self::from_value(self.value()) {
                    $( Self::$variant => Some($name), )*
                    Self::Other(_) => None,
                }
            }

            /// The name, or the number of a value that the table does not name.
            #[cfg(feature = "tree")]
            pub(crate) fn tree(self) -> oxirush_utils::tree::Value {
                match self.name() {
                    Some(name) => oxirush_utils::tree::text(name),
                    None => oxirush_utils::tree::unsigned(self.value().into()),
                }
            }

            /// A name of the table in any spelling, or a number up to `upper`.
            #[cfg(feature = "tree")]
            pub(crate) fn read_tree(
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
                upper: u8,
            ) -> Result<Self, oxirush_utils::tree::Refused> {
                const NAMES: &[&str] = &[$($name),*];
                const VALUES: &[u8] = &[$($value),*];
                if value.is_number() {
                    return Ok(Self::from_value(reading.unsigned(value, 0, upper.into())? as u8));
                }
                Ok(Self::from_value(VALUES[reading.named(value, NAMES)?]))
            }
        }

        impl Default for $ty {
            /// The value 0.
            fn default() -> Self {
                Self::from_value(0)
            }
        }

        impl From<u8> for $ty {
            fn from(value: u8) -> Self {
                Self::from_value(value)
            }
        }

        impl From<$ty> for u8 {
            fn from(value: $ty) -> u8 {
                value.value()
            }
        }

        impl core::fmt::Display for $ty {
            /// The name, or the number of a value that the table does not name.
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                match self.name() {
                    Some(name) => f.write_str(name),
                    None => write!(f, "{}", self.value()),
                }
            }
        }

        /// A whole octet; a value of fewer bits, whose octet has spare bits, is a
        /// [`Narrow`](crate::Narrow) field.
        impl crate::values::Field for $ty {
            #[cfg(feature = "spec")]
            const OCTETS: Option<usize> = Some(1);
            fn read(octets: &mut &[u8]) -> Option<Self> {
                let (&first, rest) = octets.split_first()?;
                *octets = rest;
                Some(Self::from_value(first))
            }
            fn write(&self, out: &mut alloc::vec::Vec<u8>) {
                out.push(self.value());
            }
            fn size(&self) -> usize {
                1
            }
            fn check(&self, path: &crate::check::Path, clause: &'static str, found: &mut alloc::vec::Vec<crate::check::Deviation>) {
                if self.name().is_none() {
                    let value = self.value().into();
                    let kind = match (Self::RESERVED.contains(&self.value()), self.effective().value()) {
                        (true, _) => crate::check::DeviationKind::ReservedValue { value },
                        (false, read) if u32::from(read) != value => crate::check::DeviationKind::ReadAs { value, read: read.into() },
                        (false, _) => crate::check::DeviationKind::SpareValue { value },
                    };
                    found.push(crate::check::Deviation::new(path, clause, kind));
                }
            }
            #[cfg(feature = "tree")]
            fn to_tree(&self) -> oxirush_utils::tree::Value {
                self.tree()
            }
            #[cfg(feature = "tree")]
            fn from_tree(
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
            ) -> Result<Self, oxirush_utils::tree::Refused> {
                Self::read_tree(value, reading, u8::MAX)
            }
        }
    )*};
}

pub(crate) use {pfcp_bits, pfcp_enum, pfcp_ies, pfcp_layout, pfcp_messages, pfcp_table};
