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
                fields: pfcp_ies!(@fields $form $($($ty),+)?),
                tables: pfcp_ies!(@tables $form $($($ty),+)?),
            }, )*
        ];
        $( pfcp_ies!(@impls $num $name [pfcp_ies!(@length $form $(($fixed))?)] $($($ty),+)?); )*
    };
    (@impls $num:literal $name:literal [$fixed:expr] $($ty:ident),*) => {
        $(
            impl crate::ie::IeType for $ty<'_> {
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
        pub struct $ty<'a> {
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
            /// The octets after the fields, which a later release adds.
            pub extra: crate::octets::Octets<'a>,
        }

        impl $ty<'_> {
            /// The bits of the first octet that are flags.
            const FLAGS: $fk = 0 $( | pfcp_layout!(@fmask $bit $(, $width)?) )*;
            /// The names of its flags and fields.
            pub const FIELDS: &'static [&'static str] = &[$($($head_name,)*)? $($flag_name,)* $($field_name),*];
            /// The clause of the layout.
            pub const CLAUSE: &'static str = $clause;

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

        impl<'a> crate::ie::Codec<'a> for $ty<'a> {
            #[allow(unused_variables)]
            fn decode(octets: &'a [u8]) -> Option<Self> {
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
                    extra: crate::octets::Octets::wire(rest),
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

        impl<'a> crate::octets::IntoOwned for $ty<'a> {
            type Owned = $ty<'static>;
            fn into_owned(self) -> $ty<'static> {
                $ty { $($($head: self.$head,)*)? $($flag: self.$flag,)* spare: self.spare, $($field: self.$field,)* extra: self.extra.into_owned() }
            }
        }

        impl crate::check::Check for $ty<'_> {
            fn check(&self, path: &crate::check::Path<'_>, found: &mut alloc::vec::Vec<crate::check::Deviation>) {
                if let Some(field) = self.inconsistent() {
                    found.push(crate::check::Deviation::new(path, $clause, crate::check::DeviationKind::Inconsistent { field }));
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

        #[cfg(feature = "tree")]
        impl oxirush_utils::tree::Tree for $ty<'_> {
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
                    members.put("extra", oxirush_utils::tree::octets(&self.extra));
                }
                members.finish()
            }

            fn from_tree(
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
            ) -> Result<Self, oxirush_utils::tree::Refused> {
                const NAMES: &[&str] = &[$($($head_name,)*)? $($flag_name,)* "Spare", $($field_name,)* "extra"];
                let read = reading.members(value, NAMES)?;
                let mut at = 0;
                $($(
                    let $head = reading.optional(&read, at, <$hkind as crate::values::Field>::from_tree)?.unwrap_or_default();
                    at += 1;
                )*)?
                $(
                    let $flag = pfcp_layout!(@fget reading, read, at $(, $width $(as $fkind)?)?);
                    at += 1;
                )*
                let spare = reading
                    .optional(&read, at, |value, reading| reading.unsigned(value, 0, <$fk>::MAX.into()))?
                    .unwrap_or(0) as $fk;
                at += 1;
                $(
                    let $field = reading.optional(&read, at, <$kind $(<$param>)? as crate::values::Field>::from_tree)?;
                    at += 1;
                )*
                let extra = reading.optional(&read, at, |value, reading| reading.octets(value))?;
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
    (@fget $reading:ident, $read:ident, $at:ident) => {
        $reading.optional(&$read, $at, |value, reading| reading.boolean(value))?.unwrap_or(false)
    };
    (@fget $reading:ident, $read:ident, $at:ident, $width:literal) => {
        $reading.optional(&$read, $at, |value, reading| reading.unsigned(value, 0, (1 << $width) - 1))?.unwrap_or(0) as u8
    };
    (@fget $reading:ident, $read:ident, $at:ident, $width:literal as $kind:ident) => {
        $reading
            .optional(&$read, $at, |value, reading| $kind::read_tree(value, reading, ((1u16 << $width) - 1) as u8))?
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
/// bits are spare and kept, and so is how many of the `N` octets a decoded value had.
///
/// ```text
/// pub struct ApplyAction "8.2.26" octets 2 min 1 {
///     drop "DROP": 0 1 1, forw "FORW": 0 2 1, edrt "EDRT": 1 1 1,
/// }
/// ```
macro_rules! pfcp_bits {
    (
        $(#[$meta:meta])*
        pub struct $ty:ident $clause:literal octets $n:literal min $min:literal {
            $( $field:ident $name:literal : $octet:literal $low:literal $width:tt $(+ $octet2:literal $low2:literal $width2:tt)? $(as $kind:ident)? ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $ty<'a> {
            $(
                #[doc = concat!("The ", $name, " field.")]
                pub $field: pfcp_bits!(@type $width [$($kind)? $(+ $octet2 $low2 $width2)?]),
            )*
            /// The bits of each octet that no field has, which are spare.
            pub spare: [u8; $n],
            /// How many of the octets of the fields the value has: the first ones of a
            /// later release are absent from a sender of an earlier one.
            pub present: u8,
            /// The octets after them, which a later release adds.
            pub extra: crate::octets::Octets<'a>,
        }

        impl Default for $ty<'_> {
            fn default() -> Self {
                Self { $( $field: Default::default(), )* spare: [0; $n], present: $n, extra: Default::default() }
            }
        }

        impl $ty<'_> {
            /// The clause of the layout.
            pub const CLAUSE: &'static str = $clause;
            /// The names of its flags and fields.
            pub const FIELDS: &'static [&'static str] = &[$($name),*];
            /// Whether the tree is the value of the field alone: one field, not a flag.
            #[cfg(feature = "tree")]
            const BARE: bool = { let widths: &[u32] = &[$($width),*]; widths.len() == 1 && widths[0] > 1 };
            /// The bits of each octet that a field has.
            const MASKS: [u8; $n] = {
                let mut masks = [0u8; $n];
                $( pfcp_bits!(@mask masks, $octet, $low, $width [$($kind)? $(+ $octet2 $low2 $width2)?]); )*
                masks
            };

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

        impl<'a> crate::ie::Codec<'a> for $ty<'a> {
            fn decode(octets: &'a [u8]) -> Option<Self> {
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
                    extra: crate::octets::Octets::wire(&octets[present..]),
                })
            }

            fn encode(&self, out: &mut alloc::vec::Vec<u8>) -> Result<(), crate::Error> {
                let (octets, used) = self.octets();
                out.extend_from_slice(&octets[..used]);
                out.extend_from_slice(&self.extra);
                Ok(())
            }

            fn encoded_len(&self) -> usize {
                self.octets().1 + self.extra.len()
            }
        }

        impl<'a> crate::octets::IntoOwned for $ty<'a> {
            type Owned = $ty<'static>;
            fn into_owned(self) -> $ty<'static> {
                $ty { $( $field: self.$field, )* spare: self.spare, present: self.present, extra: self.extra.into_owned() }
            }
        }

        impl crate::check::Check for $ty<'_> {
            fn check(&self, path: &crate::check::Path<'_>, found: &mut alloc::vec::Vec<crate::check::Deviation>) {
                if self.spare.iter().any(|spare| *spare != 0) {
                    found.push(crate::check::Deviation::new(path, "8.1.2", crate::check::DeviationKind::SpareBits));
                }
                $( pfcp_bits!(@check [$($kind)? $(+ $octet2 $low2 $width2)?] self.$field, path, found); )*
            }
        }

        /// The flags that are set and the fields, with `Spare`, `length` (the octets of
        /// the fields that the value has, when it lacks some) and `extra` where they are
        /// not what a sender of this release writes.
        #[cfg(feature = "tree")]
        impl oxirush_utils::tree::Tree for $ty<'_> {
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
                    members.put("extra", oxirush_utils::tree::octets(&self.extra));
                }
                members.finish()
            }

            fn from_tree(
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
            ) -> Result<Self, oxirush_utils::tree::Refused> {
                const NAMES: &[&str] = &[$($name,)* "Spare", "length", "extra"];
                let mut bits = Self::default();
                if Self::BARE && !value.is_object() {
                    $( bits.$field = pfcp_bits!(@get $width [$($kind)? $(+ $octet2 $low2 $width2)?] value, reading)?; )*
                    return Ok(bits);
                }
                let read = reading.members(value, NAMES)?;
                let mut at = 0;
                $(
                    if let Some(value) = reading.optional(&read, at, |value, reading| pfcp_bits!(@get $width [$($kind)? $(+ $octet2 $low2 $width2)?] value, reading))? {
                        bits.$field = value;
                    }
                    at += 1;
                )*
                if let Some(spare) = reading.optional(&read, at, |value, reading| reading.octet_array::<$n>(value))? {
                    bits.spare = spare;
                }
                if let Some(present) = reading.optional(&read, at + 1, |value, reading| reading.unsigned(value, $min, $n))? {
                    bits.present = present as u8;
                }
                bits.extra = reading
                    .optional(&read, at + 2, |value, reading| reading.octets(value))?
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
        pub enum Body<'a> {
            $(
                #[doc = concat!("Message type ", stringify!($code), ".")]
                $ty(alloc::boxed::Box<crate::registry::$ty<'a>>),
            )*
            /// A message type that Table 7.3-1 does not have, with the octets after its
            /// header (§7.6.4).
            Other {
                /// The message type.
                message_type: u8,
                /// The octets of its IEs.
                octets: crate::octets::Octets<'a>,
            },
        }

        $(
            impl<'a> From<crate::registry::$ty<'a>> for Body<'a> {
                fn from(body: crate::registry::$ty<'a>) -> Self {
                    Self::$ty(alloc::boxed::Box::new(body))
                }
            }
        )*

        impl<'a> crate::octets::IntoOwned for Body<'a> {
            type Owned = Body<'static>;
            fn into_owned(self) -> Body<'static> {
                match self {
                    $( Self::$ty(body) => Body::$ty(crate::octets::IntoOwned::into_owned(body)), )*
                    Self::Other { message_type, octets } => Body::Other { message_type, octets: octets.into_owned() },
                }
            }
        }

        impl<'a> Body<'a> {
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
            #[allow(dead_code)]
            pub(crate) fn names() -> [&'static str; [$($code),*].len()] {
                [$( crate::registry::$ty::table().name ),*]
            }

            pub(crate) fn decode(message_type: u8, octets: &'a [u8]) -> Result<Self, crate::ie::IeFault> {
                Ok(match message_type {
                    $( $code => {
                        // The message is decoded in its box, and not moved there.
                        let mut body = alloc::boxed::Box::<crate::registry::$ty<'a>>::default();
                        crate::table::decode_scope_sized(&mut *body, octets, true)?;
                        Self::$ty(body)
                    } )*
                    other => Self::Other { message_type: other, octets: crate::octets::Octets::wire(octets) },
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

            pub(crate) fn check(&self, path: &crate::check::Path<'_>, context: crate::check::Context, found: &mut alloc::vec::Vec<crate::check::Deviation>) {
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
                    $( $code if kind.is_ok() => Self::$ty(alloc::boxed::Box::new(crate::tree::scope_from_tree(value, reading)?)), )*
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
/// `raw N` for an IE type that the crate keeps as octets. A field that several rows
/// share, which the wire does not tell apart, lists them after `roles`, each with its
/// presence and its interfaces.
macro_rules! pfcp_table {
    (
        $(#[$meta:meta])*
        $kind:ident $ty:ident = $code:literal, $name:literal, $id:literal {
            $( $field:ident : $row:literal $p:ident $(* $($max:literal)?)? $vty:ident $($raw:literal)?
                [$($interface:ident)*] $(roles [$($role:literal $rp:ident [$($ri:ident)*]),*])? , )*
        }
    ) => { pastey::paste! {
        $(#[$meta])*
        #[derive(Debug, Clone, Default, PartialEq, Eq)]
        pub struct $ty<'a> {
            $(
                #[doc = concat!("The ", $row, " IE.")]
                pub $field: pfcp_table!(@field [$(* $($max)?)?] $p (pfcp_table!(@type $vty $($raw)?))),
            )*
            /// The IEs that the scope keeps as octets, in the order of the wire.
            pub raw: alloc::vec::Vec<crate::ie::RawIe<'a>>,
            /// The order of the wire, when it is not that of the table.
            pub order: alloc::vec::Vec<crate::ie::Placed>,
        }

        pub(crate) static [<$ty:snake:upper _TABLE>]: crate::table::Table = crate::table::Table {
            id: $id,
            name: $name,
            code: $code,
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
                },
            )*],
        };

        impl<'a> $ty<'a> {
            /// The table of the scope.
            pub fn table() -> &'static crate::table::Table {
                &[<$ty:snake:upper _TABLE>]
            }

            $(
                #[doc = concat!("Builder: add the ", $row, " IE.")]
                pub fn [<with_ $field>](mut self, value: pfcp_table!(@type $vty $($raw)?)) -> Self {
                    pfcp_table!(@set [$(* $($max)?)?] $p (pfcp_table!(@type $vty $($raw)?)) self.$field, value);
                    self
                }
            )*
        }

        pfcp_table!(@new $ty [] [] $( $field : $row $p $(* $($max)?)? $vty $($raw)? [$($interface)*] , )*);

        // A table without rows leaves its arguments unused.
        #[allow(unused_variables, unused_mut, unused_assignments)]
        impl<'a> crate::table::Scope<'a> for $ty<'a> {
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

            #[allow(unused_variables)]
            fn presize(&mut self, octets: &[u8]) {
                $( let mut [<count_ $field>] = 0usize; )*
                for ie in crate::framing::ies(octets).flatten() {
                    $(
                        if ie.ie_type == <pfcp_table!(@type_any $vty $($raw)?) as crate::ie::IeType>::IE_TYPE {
                            [<count_ $field>] += 1;
                            continue;
                        }
                    )*
                }
                $( pfcp_table!(@reserve [$(* $($max)?)?] self.$field, [<count_ $field>]); )*
            }

            fn place(&mut self, ie_type: u16, body: &'a [u8]) -> crate::ie::Placing {
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
                        let Some(value) = pfcp_table!(@nth [$(* $($max)?)?] $p (pfcp_table!(@type $vty $($raw)?)) self.$field, nth) else {
                            return Ok(false);
                        };
                        crate::ie::encode_value(value, out)?;
                        return Ok(true);
                    }
                )*
                Ok(false)
            }

            fn encoded_len(&self) -> usize {
                let mut length = 0;
                $( pfcp_table!(@each [$(* $($max)?)?] $p (pfcp_table!(@type $vty $($raw)?)) self.$field, |nth, value| {
                    let _ = nth;
                    length += 4 + crate::ie::Codec::encoded_len(value);
                }); )*
                for ie in &self.raw {
                    length += 4 + 2 * usize::from(ie.enterprise_id.is_some()) + ie.octets.len();
                }
                length
            }

            fn encode_fields(&self, out: &mut alloc::vec::Vec<u8>) -> Result<(), crate::Error> {
                $( pfcp_table!(@each [$(* $($max)?)?] $p (pfcp_table!(@type $vty $($raw)?)) self.$field, |nth, value| {
                    let _ = nth;
                    crate::ie::encode_value(value, out)?;
                }); )*
                Ok(())
            }

            fn count(&self, ie_type: u16) -> usize {
                $(
                    if ie_type == <pfcp_table!(@type $vty $($raw)?) as crate::ie::IeType>::IE_TYPE {
                        return pfcp_table!(@count [$(* $($max)?)?] self.$field);
                    }
                )*
                0
            }

            fn decodes(&self, ie_type: u16, octets: &[u8]) -> bool {
                $(
                    if ie_type == <pfcp_table!(@type $vty $($raw)?) as crate::ie::IeType>::IE_TYPE {
                        return <pfcp_table!(@type_any $vty $($raw)?) as crate::ie::Codec<'_>>::decode(octets).is_some();
                    }
                )*
                false
            }

            fn raw(&self) -> &[crate::ie::RawIe<'a>] { &self.raw }
            fn raw_mut(&mut self) -> &mut alloc::vec::Vec<crate::ie::RawIe<'a>> { &mut self.raw }
            fn order(&self) -> &[crate::ie::Placed] { &self.order }
            fn order_mut(&mut self) -> &mut alloc::vec::Vec<crate::ie::Placed> { &mut self.order }
        }

        // A table without rows leaves its arguments unused.
        #[allow(unused_variables, unused_mut, unused_assignments)]
        impl<'a> crate::check::Checked for $ty<'a> {
            fn check_values(&self, path: &crate::check::Path<'_>, context: crate::check::Context, found: &mut alloc::vec::Vec<crate::check::Deviation>) {
                let table = <Self as crate::table::Scope<'a>>::table();
                let mut row = 0;
                $(
                    let count = pfcp_table!(@count [$(* $($max)?)?] self.$field);
                    if count > 0 {
                        crate::check::check_row(table.id, &table.rows[row], count, path, context, found);
                        pfcp_table!(@each [$(* $($max)?)?] $p (pfcp_table!(@type $vty $($raw)?)) self.$field, |nth, value| {
                            let at = crate::check::Path::Row { parent: path, row: $row, nth: pfcp_table!(@position [$(* $($max)?)?] nth) };
                            crate::check::check_field(value, &at, pfcp_table!(@presence $p), context, found);
                        });
                    }
                    row += 1;
                )*
            }
        }

        impl<'a> crate::octets::IntoOwned for $ty<'a> {
            type Owned = $ty<'static>;
            fn into_owned(self) -> $ty<'static> {
                $ty {
                    $( $field: crate::octets::IntoOwned::into_owned(self.$field), )*
                    raw: crate::octets::IntoOwned::into_owned(self.raw),
                    order: self.order,
                }
            }
        }

        pfcp_table!(@kind $kind $ty);

        #[cfg(feature = "tree")]
        // A table without rows leaves its arguments unused.
        #[allow(unused_variables, unused_mut, unused_assignments)]
        impl<'a> crate::tree::TreeScope for $ty<'a> {
            fn field_tree(&self, ie_type: u16, nth: usize) -> Option<oxirush_utils::tree::Value> {
                $(
                    if ie_type == <pfcp_table!(@type $vty $($raw)?) as crate::ie::IeType>::IE_TYPE {
                        return pfcp_table!(@nth [$(* $($max)?)?] $p (pfcp_table!(@type $vty $($raw)?)) self.$field, nth).map(oxirush_utils::tree::Tree::to_tree);
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
                        let value = <pfcp_table!(@type $vty $($raw)?) as oxirush_utils::tree::Tree>::from_tree(value, reading)?;
                        pfcp_table!(@set [$(* $($max)?)?] $p (pfcp_table!(@type $vty $($raw)?)) self.$field, value);
                        return Ok(());
                    }
                )*
                Ok(())
            }
        }
    } };

    // ── The parts of a row ──────────────────────────────────────────────────

    (@type raw $raw:literal) => { crate::values::Raw<'a, $raw> };
    (@type $vty:ident) => { $vty<'a> };
    (@type_static raw $raw:literal) => { crate::values::Raw<'static, $raw> };
    (@type_static $vty:ident) => { $vty<'static> };
    (@type_any raw $raw:literal) => { crate::values::Raw<'_, $raw> };
    (@type_any $vty:ident) => { $vty<'_> };
    // A row that is there once is a field of its value, mandatory ones in place, and the
    // others as the slot of their type: a grouped IE, large and rare, is boxed.
    (@field [] M ($t:ty)) => { Option<$t> };
    (@field [] Ci ($t:ty)) => { Option<$t> };
    (@field [] Oi ($t:ty)) => { Option<$t> };
    (@field [] $p:ident ($t:ty)) => { <$t as crate::ie::Listed<'a>>::Slot };
    (@field [* $($max:literal)?] $p:ident ($t:ty)) => { <$t as crate::ie::Listed<'a>>::List };
    (@presence M) => { crate::table::Presence::Mandatory };
    (@presence C) => { crate::table::Presence::Conditional };
    (@presence O) => { crate::table::Presence::Optional };
    // A conditional or optional grouped IE that most messages have stays in place.
    (@presence Ci) => { crate::table::Presence::Conditional };
    (@presence Oi) => { crate::table::Presence::Optional };
    (@repeat) => { crate::table::Repeat::Once };
    (@repeat *) => { crate::table::Repeat::Any };
    (@repeat * $max:literal) => { crate::table::Repeat::AtMost($max) };
    (@set [] M ($t:ty) $f:expr, $value:expr) => { $f = Some($value) };
    (@set [] Ci ($t:ty) $f:expr, $value:expr) => { $f = Some($value) };
    (@set [] Oi ($t:ty) $f:expr, $value:expr) => { $f = Some($value) };
    (@set [] $p:ident ($t:ty) $f:expr, $value:expr) => { <$t as crate::ie::Listed>::slot_set(&mut $f, $value) };
    (@set [* $($max:literal)?] $p:ident ($t:ty) $f:expr, $value:expr) => { $f.push($value) };
    (@nth [] M ($t:ty) $f:expr, $nth:expr) => { $f.as_ref().filter(|_| $nth == 0) };
    (@nth [] Ci ($t:ty) $f:expr, $nth:expr) => { $f.as_ref().filter(|_| $nth == 0) };
    (@nth [] Oi ($t:ty) $f:expr, $nth:expr) => { $f.as_ref().filter(|_| $nth == 0) };
    (@nth [] $p:ident ($t:ty) $f:expr, $nth:expr) => { <$t as crate::ie::Listed>::slot_get(&$f).filter(|_| $nth == 0) };
    (@nth [* $($max:literal)?] $p:ident ($t:ty) $f:expr, $nth:expr) => { $f.get($nth) };
    (@position [] $nth:ident) => {{ let _ = $nth; None }};
    (@position [* $($max:literal)?] $nth:ident) => { Some($nth) };
    (@count [] $f:expr) => { usize::from($f.is_some()) };
    (@count [* $($max:literal)?] $f:expr) => { $f.len() };
    (@each [] M ($t:ty) $f:expr, |$nth:ident, $value:ident| $body:block) => {
        if let Some($value) = $f.as_ref() { let $nth = 0; $body }
    };
    (@each [] Ci ($t:ty) $f:expr, |$nth:ident, $value:ident| $body:block) => {
        if let Some($value) = $f.as_ref() { let $nth = 0; $body }
    };
    (@each [] Oi ($t:ty) $f:expr, |$nth:ident, $value:ident| $body:block) => {
        if let Some($value) = $f.as_ref() { let $nth = 0; $body }
    };
    (@each [] $p:ident ($t:ty) $f:expr, |$nth:ident, $value:ident| $body:block) => {
        if let Some($value) = <$t as crate::ie::Listed>::slot_get(&$f) { let $nth = 0; $body }
    };
    (@each_unused [] $f:expr, |$nth:ident, $value:ident| $body:block) => {
        if let Some($value) = &$f { let $nth = 0; $body }
    };
    (@each [* $($max:literal)?] $p:ident ($t:ty) $f:expr, |$nth:ident, $value:ident| $body:block) => {
        for ($nth, $value) in $f.iter().enumerate() $body
    };
    (@place [] $p:ident ($t:ty) $f:expr, $body:expr) => {
        pfcp_table!(@place_once $p ($t) $f, $body)
    };
    (@place_once Ci ($t:ty) $f:expr, $body:expr) => { pfcp_table!(@place_once M ($t) $f, $body) };
    (@place_once Oi ($t:ty) $f:expr, $body:expr) => { pfcp_table!(@place_once M ($t) $f, $body) };
    (@place_once M ($t:ty) $f:expr, $body:expr) => {
        match $f.is_some() {
            true => crate::ie::Placing::Repeated,
            false if crate::ie::Codec::decode_into(&mut $f, $body) => crate::ie::Placing::Placed,
            false => crate::ie::Placing::Malformed,
        }
    };
    (@place_once $p:ident ($t:ty) $f:expr, $body:expr) => {
        match $f.is_some() {
            true => crate::ie::Placing::Repeated,
            false if <$t as crate::ie::Listed>::decode_slot(&mut $f, $body) => crate::ie::Placing::Placed,
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
    (@full [] $f:expr) => { false };
    (@full [$max:literal] $f:expr) => { $f.len() >= $max };

    // ── A message, or the content of a grouped IE ───────────────────────────

    (@kind group $ty:ident) => {
        impl<'a> crate::ie::Codec<'a> for $ty<'a> {
            fn decode(octets: &'a [u8]) -> Option<Self> {
                crate::table::decode_scope(octets).ok()
            }

            // A grouped IE is large: it is decoded in its place, and not moved there.
            fn decode_into(slot: &mut Option<Self>, octets: &'a [u8]) -> bool {
                let scope = slot.insert(Self::default());
                if crate::table::decode_scope_into(scope, octets).is_err() {
                    *slot = None;
                    return false;
                }
                true
            }

            fn encode(&self, out: &mut alloc::vec::Vec<u8>) -> Result<(), crate::Error> {
                crate::table::encode_scope(self, out)
            }

            fn encoded_len(&self) -> usize {
                crate::table::Scope::encoded_len(self)
            }
        }

        impl<'a> crate::ie::Listed<'a> for $ty<'a> {
            type List = alloc::vec::Vec<Self>;
            type Slot = Option<alloc::boxed::Box<Self>>;

            fn decode_slot(slot: &mut Self::Slot, octets: &'a [u8]) -> bool {
                let scope = slot.insert(alloc::boxed::Box::default());
                if crate::table::decode_scope_into(&mut **scope, octets).is_err() {
                    *slot = None;
                    return false;
                }
                true
            }

            fn slot_get(slot: &Self::Slot) -> Option<&Self> {
                slot.as_deref()
            }

            fn slot_set(slot: &mut Self::Slot, value: Self) {
                *slot = Some(alloc::boxed::Box::new(value));
            }

            fn decode_push(list: &mut Self::List, octets: &'a [u8]) -> bool {
                list.push(Self::default());
                let last = list.len() - 1;
                if crate::table::decode_scope_into(&mut list[last], octets).is_err() {
                    list.pop();
                    return false;
                }
                true
            }
        }

        impl crate::check::Check for $ty<'_> {
            /// Its table on N4, as the receiver of a response.
            fn check(&self, path: &crate::check::Path<'_>, found: &mut alloc::vec::Vec<crate::check::Deviation>) {
                crate::check::check_scope(self, path, crate::check::Context::on(crate::table::Interfaces::N4), found);
            }

            fn check_in(&self, path: &crate::check::Path<'_>, context: crate::check::Context, found: &mut alloc::vec::Vec<crate::check::Deviation>) {
                crate::check::check_scope(self, path, context, found);
            }
        }

        #[cfg(feature = "tree")]
        impl oxirush_utils::tree::Tree for $ty<'_> {
            const NAME: &'static str = <$ty<'static> as crate::ie::IeType>::TYPE_NAME;

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

    // `new()`, with the fields of the mandatory rows, which a muncher collects.
    (@new $ty:ident [$($arg:tt)*] [$( ($f:ident [$($m:tt)*] ($ft:ty)) )*]) => {
        impl<'a> $ty<'a> {
            /// The scope with its mandatory IEs.
            #[allow(clippy::too_many_arguments)]
            pub fn new($($arg)*) -> Self {
                #[allow(unused_mut)]
                let mut scope = Self::default();
                $( pfcp_table!(@set [$($m)*] M ($ft) scope.$f, $f); )*
                scope
            }
        }
    };
    // A mandatory row is an argument of `new()` where N4 has it.
    (@new $ty:ident [$($arg:tt)*] [$($set:tt)*] $field:ident : $row:literal M $(* $($max:literal)?)? $vty:ident $($raw:literal)? [$($i:ident)*] , $($rest:tt)*) => {
        pfcp_table!(@n4 [$($i)*] $ty [$($arg)*] [$($set)*] ($field [$(* $($max)?)?] (pfcp_table!(@type $vty $($raw)?))) $($rest)*);
    };
    (@new $ty:ident [$($arg:tt)*] [$($set:tt)*] $field:ident : $row:literal $p:ident $(* $($max:literal)?)? $vty:ident $($raw:literal)? [$($i:ident)*] , $($rest:tt)*) => {
        pfcp_table!(@new $ty [$($arg)*] [$($set)*] $($rest)*);
    };
    (@n4 [N4 $($i:ident)*] $ty:ident [$($arg:tt)*] [$($set:tt)*] ($field:ident [$($m:tt)*] ($t:ty)) $($rest:tt)*) => {
        pfcp_table!(@new $ty [$($arg)* $field: $t,] [$($set)* ($field [$($m)*] ($t))] $($rest)*);
    };
    (@n4 [$other:ident $($i:ident)*] $ty:ident [$($arg:tt)*] [$($set:tt)*] $row:tt $($rest:tt)*) => {
        pfcp_table!(@n4 [$($i)*] $ty [$($arg)*] [$($set)*] $row $($rest)*);
    };
    (@n4 [] $ty:ident [$($arg:tt)*] [$($set:tt)*] $row:tt $($rest:tt)*) => {
        pfcp_table!(@new $ty [$($arg)*] [$($set)*] $($rest)*);
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
        pub enum $ty:ident $table:literal bits $bits:literal $(reserved [$($reserved:literal),*])? {
            $( $value:literal $variant:ident $name:literal ),* $(,)?
        }
    )*) => {$(
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum $ty {
            $(
                #[doc = concat!(stringify!($value), ": ", $name, ".")]
                $variant,
            )*
            /// A value that the table has as spare or reserved, or does not have.
            Other(u8),
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
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self.name() {
                    Some(name) => f.write_str(name),
                    None => write!(f, "{}", self.value()),
                }
            }
        }

        /// A whole octet: a value with a spare bit set is `Other`.
        impl crate::values::Field for $ty {
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
            fn check(&self, path: &crate::check::Path<'_>, clause: &'static str, found: &mut alloc::vec::Vec<crate::check::Deviation>) {
                if self.name().is_none() {
                    let value = self.value().into();
                    let kind = match Self::RESERVED.contains(&self.value()) {
                        true => crate::check::DeviationKind::ReservedValue { value },
                        false => crate::check::DeviationKind::SpareValue { value },
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
