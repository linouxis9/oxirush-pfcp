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
            }, )*
        ];
        $( $( $(
            impl crate::ie::IeType for $ty<'_> {
                const IE_TYPE: u16 = $num;
                const TYPE_NAME: &'static str = $name;
            }
        )+ )? )*
    };
    (@form fixed) => { crate::registry::Form::Fixed };
    (@form variable) => { crate::registry::Form::Variable };
    (@form extendable) => { crate::registry::Form::Extendable };
    (@form grouped) => { crate::registry::Form::Grouped };
    (@fixed) => { None };
    (@fixed $fixed:literal) => { Some($fixed) };
}

/// A value of a layout of clause 8.2: an octet of flags, then fields, each present when
/// its condition over the flags holds, then the octets that a later release adds
/// ("present only if explicitly specified"), which the value keeps.
///
/// ```text
/// pub struct FTeid "8.2.3" {
///     flags { chid "CHID": 4, ch "CH": 3, v6 "V6": 2, v4 "V4": 1 }
///     teid "TEID": u32 if !ch,
///     ipv4 "IPv4 address": Ipv4Addr if v4 && !ch,
/// }
/// ```
macro_rules! pfcp_layout {
    (
        $(#[$meta:meta])*
        pub struct $ty:ident $clause:literal {
            flags { $( $flag:ident $flag_name:literal : $bit:literal ),* $(,)? }
            $( $field:ident $field_name:literal : $kind:ident if $cond:expr ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Default, PartialEq, Eq)]
        pub struct $ty<'a> {
            $(
                #[doc = concat!("The ", $flag_name, " flag, bit ", stringify!($bit), " of the first octet.")]
                pub $flag: bool,
            )*
            /// The other bits of the first octet, which are spare: zero from a sender.
            pub spare: u8,
            $(
                #[doc = concat!("The ", $field_name, " field.")]
                pub $field: Option<$kind>,
            )*
            /// The octets after the fields, which a later release adds.
            pub extra: crate::octets::Octets<'a>,
        }

        impl $ty<'_> {
            /// The bits of the first octet that are flags.
            const FLAGS: u8 = 0 $( | 1 << ($bit - 1) )*;
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
                let (&first, mut rest) = octets.split_first()?;
                $( let $flag = first & 1 << ($bit - 1) != 0; )*
                $(
                    let $field = match $cond {
                        true => Some(<$kind as crate::values::Field>::read(&mut rest)?),
                        false => None,
                    };
                )*
                Some(Self {
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
                out.push(self.spare & !Self::FLAGS $( | u8::from(self.$flag) << ($bit - 1) )*);
                $(
                    if let Some(field) = &self.$field {
                        crate::values::Field::write(field, out);
                    }
                )*
                out.extend_from_slice(&self.extra);
                Ok(())
            }

            fn encoded_len(&self) -> usize {
                1 $( + self.$field.as_ref().map_or(0, crate::values::Field::size) )* + self.extra.len()
            }
        }

        impl<'a> crate::octets::IntoOwned for $ty<'a> {
            type Owned = $ty<'static>;
            fn into_owned(self) -> $ty<'static> {
                $ty { $($flag: self.$flag,)* spare: self.spare, $($field: self.$field,)* extra: self.extra.into_owned() }
            }
        }

        #[cfg(feature = "tree")]
        impl oxirush_utils::tree::Tree for $ty<'_> {
            const NAME: &'static str = <Self as crate::ie::IeType>::TYPE_NAME;

            fn to_tree(&self) -> oxirush_utils::tree::Value {
                let mut members = oxirush_utils::tree::Members::new();
                $( if self.$flag { members.put($flag_name, oxirush_utils::tree::Value::Bool(true)); } )*
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
                const NAMES: &[&str] = &[$($flag_name,)* "Spare", $($field_name,)* "extra"];
                let read = reading.members(value, NAMES)?;
                let mut at = 0;
                $(
                    let $flag = reading
                        .optional(&read, at, |value, reading| reading.boolean(value))?
                        .unwrap_or(false);
                    at += 1;
                )*
                let spare = reading
                    .optional(&read, at, |value, reading| reading.unsigned(value, 0, 255))?
                    .unwrap_or(0) as u8;
                at += 1;
                $(
                    let $field = reading.optional(&read, at, <$kind as crate::values::Field>::from_tree)?;
                    at += 1;
                )*
                let extra = reading.optional(&read, at, |value, reading| reading.octets(value))?;
                let value = Self { $($flag,)* spare, $($field,)* extra: extra.map(crate::octets::Octets::from).unwrap_or_default() };
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
                pub $field: pfcp_table!(@field (pfcp_table!(@type $vty $($raw)?)) $(* $($max)?)?),
            )*
            /// The IEs that the scope keeps as octets, in the order of the wire.
            pub raw: alloc::vec::Vec<crate::ie::RawIe<'a>>,
            /// The order of the wire, when it is not that of the table.
            pub order: alloc::vec::Vec<crate::ie::Placed>,
        }

        static [<$ty:snake:upper _TABLE>]: crate::table::Table = crate::table::Table {
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
                    pfcp_table!(@set [$(* $($max)?)?] self.$field, value);
                    self
                }
            )*
        }

        pfcp_table!(@new $ty [] [] $( $field : $row $p $(* $($max)?)? $vty $($raw)? [$($interface)*] , )*);

        impl<'a> crate::table::Scope<'a> for $ty<'a> {
            fn table() -> &'static crate::table::Table {
                &[<$ty:snake:upper _TABLE>]
            }

            #[allow(unused_assignments)]
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
                        return pfcp_table!(@place [$(* $($max)?)?] self.$field, body);
                    }
                )*
                crate::ie::Placing::Unexpected
            }

            fn emit(&self, ie_type: u16, nth: usize, out: &mut alloc::vec::Vec<u8>) -> Result<bool, crate::Error> {
                $(
                    if ie_type == <pfcp_table!(@type $vty $($raw)?) as crate::ie::IeType>::IE_TYPE {
                        let Some(value) = pfcp_table!(@nth [$(* $($max)?)?] self.$field, nth) else {
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
                $( pfcp_table!(@each [$(* $($max)?)?] self.$field, |nth, value| {
                    let _ = nth;
                    length += 4 + crate::ie::Codec::encoded_len(value);
                }); )*
                for ie in &self.raw {
                    length += 4 + 2 * usize::from(ie.enterprise_id.is_some()) + ie.octets.len();
                }
                length
            }

            fn encode_fields(&self, out: &mut alloc::vec::Vec<u8>) -> Result<(), crate::Error> {
                $( pfcp_table!(@each [$(* $($max)?)?] self.$field, |nth, value| {
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

        impl crate::check::Checked for $ty<'_> {
            fn check_values(&self, path: &str, found: &mut alloc::vec::Vec<crate::check::Deviation>) {
                $(
                    pfcp_table!(@each [$(* $($max)?)?] self.$field, |nth, value| {
                        let at = crate::check::at(path, $row, pfcp_table!(@position [$(* $($max)?)?] nth));
                        crate::check::Check::check(value, &at, found);
                    });
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
        impl<'a> crate::tree::TreeScope for $ty<'a> {
            fn field_tree(&self, ie_type: u16, nth: usize) -> Option<oxirush_utils::tree::Value> {
                $(
                    if ie_type == <pfcp_table!(@type $vty $($raw)?) as crate::ie::IeType>::IE_TYPE {
                        return pfcp_table!(@nth [$(* $($max)?)?] self.$field, nth).map(oxirush_utils::tree::Tree::to_tree);
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
                        pfcp_table!(@set [$(* $($max)?)?] self.$field, value);
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
    (@field ($t:ty)) => { Option<$t> };
    (@field ($t:ty) * $($max:literal)?) => { alloc::vec::Vec<$t> };
    (@presence M) => { crate::table::Presence::Mandatory };
    (@presence C) => { crate::table::Presence::Conditional };
    (@presence O) => { crate::table::Presence::Optional };
    (@repeat) => { crate::table::Repeat::Once };
    (@repeat *) => { crate::table::Repeat::Any };
    (@repeat * $max:literal) => { crate::table::Repeat::AtMost($max) };
    (@set [] $f:expr, $value:expr) => { $f = Some($value) };
    (@set [* $($max:literal)?] $f:expr, $value:expr) => { $f.push($value) };
    (@nth [] $f:expr, $nth:expr) => { $f.as_ref().filter(|_| $nth == 0) };
    (@nth [* $($max:literal)?] $f:expr, $nth:expr) => { $f.get($nth) };
    (@position [] $nth:ident) => {{ let _ = $nth; None }};
    (@position [* $($max:literal)?] $nth:ident) => { Some($nth) };
    (@count [] $f:expr) => { usize::from($f.is_some()) };
    (@count [* $($max:literal)?] $f:expr) => { $f.len() };
    (@each [] $f:expr, |$nth:ident, $value:ident| $body:block) => {
        if let Some($value) = &$f { let $nth = 0; $body }
    };
    (@each [* $($max:literal)?] $f:expr, |$nth:ident, $value:ident| $body:block) => {
        for ($nth, $value) in $f.iter().enumerate() $body
    };
    (@place [] $f:expr, $body:expr) => {
        match $f.is_some() {
            true => crate::ie::Placing::Repeated,
            false if crate::ie::Codec::decode_into(&mut $f, $body) => crate::ie::Placing::Placed,
            false => crate::ie::Placing::Malformed,
        }
    };
    (@place [* $($max:literal)?] $f:expr, $body:expr) => {
        if pfcp_table!(@full [$($max)?] $f) {
            crate::ie::Placing::Repeated
        } else if crate::ie::Codec::decode_push(&mut $f, $body) {
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

            fn decode_push(list: &mut alloc::vec::Vec<Self>, octets: &'a [u8]) -> bool {
                list.push(Self::default());
                let last = list.len() - 1;
                if crate::table::decode_scope_into(&mut list[last], octets).is_err() {
                    list.pop();
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

        impl crate::check::Check for $ty<'_> {
            fn check(&self, path: &str, found: &mut alloc::vec::Vec<crate::check::Deviation>) {
                crate::check::check_scope(self, path, found);
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
    (@new $ty:ident [$($arg:tt)*] [$( ($f:ident [$($m:tt)*]) )*]) => {
        impl<'a> $ty<'a> {
            /// The scope with its mandatory IEs.
            #[allow(clippy::too_many_arguments)]
            pub fn new($($arg)*) -> Self {
                #[allow(unused_mut)]
                let mut scope = Self::default();
                $( pfcp_table!(@set [$($m)*] scope.$f, $f); )*
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
        pfcp_table!(@new $ty [$($arg)* $field: $t,] [$($set)* ($field [$($m)*])] $($rest)*);
    };
    (@n4 [$other:ident $($i:ident)*] $ty:ident [$($arg:tt)*] [$($set:tt)*] $row:tt $($rest:tt)*) => {
        pfcp_table!(@n4 [$($i)*] $ty [$($arg)*] [$($set)*] $row $($rest)*);
    };
    (@n4 [] $ty:ident [$($arg:tt)*] [$($set:tt)*] $row:tt $($rest:tt)*) => {
        pfcp_table!(@new $ty [$($arg)*] [$($set)*] $($rest)*);
    };
}

pub(crate) use {pfcp_ies, pfcp_layout, pfcp_table};
