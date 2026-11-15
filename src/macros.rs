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
                members: pfcp_ies!(@members $form $($($ty),+)?),
                scalar: crate::registry::one(pfcp_ies!(@fields $form $($($ty),+)?)),
                tables: pfcp_ies!(@tables $form $($($ty),+)?),
            }, )*
        ];

        /// The names of the flags and fields of the figure of `ie_type` that the crate lays
        /// out, and how it lays them out, which the test `spec` compares with the figure:
        /// for that test alone.
        #[cfg(feature = "spec")]
        #[doc(hidden)]
        pub fn ie_type_layout(ie_type: u16) -> (&'static [&'static str], Option<&'static crate::fields::Layout>) {
            match ie_type {
                $( $num => (pfcp_ies!(@fields $form $($($ty),+)?), pfcp_ies!(@layout $form $($($ty),+)?)), )*
                _ => (&[], None),
            }
        }
        $( pfcp_ies!(@impls $form $num $name [pfcp_ies!(@length $form $(($fixed))?)] $($($ty),+)?); )*

        /// What the tree of a value of `ie_type` takes: none for a grouped IE.
        #[cfg(feature = "tree")]
        pub(crate) fn takes_of(ie_type: u16) -> Option<&'static oxirush_utils::tree::Takes> {
            match ie_type {
                $( $num => pfcp_ies!(@takes $form $($($ty),+)?), )*
                _ => None,
            }
        }

        /// The tree of the value of `ie_type` that `octets` are, of the content of the table
        /// `table` for a grouped IE, or of its first: `None` for octets that are no such
        /// value, and for a table of another type.
        #[cfg(feature = "tree")]
        pub(crate) fn value_tree(
            ie_type: u16,
            table: Option<&'static crate::table::Table>,
            octets: &[u8],
        ) -> Option<oxirush_utils::tree::Value> {
            match ie_type {
                $( $num => pfcp_ies!(@value_tree $form table octets $($($ty),+)?), )*
                _ => None,
            }
        }
    };
    (@impls $form:ident $num:literal $name:literal [$fixed:expr] $($ty:ident),*) => {
        $(
            impl crate::ie::IeType for $ty {
                const IE_TYPE: u16 = $num;
                const TYPE_NAME: &'static str = $name;
                const FIXED: Option<u16> = $fixed;
            }

            impl crate::table::Content for $ty {
                const TABLE: Option<&'static crate::table::Table> = pfcp_ies!(@content $form $ty);
            }
        )*
    };
    (@content grouped $ty:ident) => { pastey::paste! { Some(&[<$ty:snake:upper _TABLE>]) } };
    (@content $form:ident $ty:ident) => { None };
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
    (@takes grouped $($ty:ident),+) => { None };
    (@takes $form:ident $ty:ident) => { Some($ty::TAKES) };
    (@value_tree grouped $table:ident $octets:ident $($ty:ident),+) => { pastey::paste! {{
        $(
            if $table.is_none_or(|table| core::ptr::eq(table, &[<$ty:snake:upper _TABLE>])) {
                return <$ty as crate::ie::Codec>::decode($octets).map(|value| oxirush_utils::tree::Tree::to_tree(&value));
            }
        )+
        None
    }} };
    (@value_tree $form:ident $table:ident $octets:ident $ty:ident) => {
        match $table {
            Some(_) => None,
            None => <$ty as crate::ie::Codec>::decode($octets).map(|value| oxirush_utils::tree::Tree::to_tree(&value)),
        }
    };
    (@members grouped $($ty:ident),+) => { &[] };
    (@members $form:ident $ty:ident) => { $ty::MEMBERS };
    (@layout grouped $($ty:ident),+) => { None };
    (@layout $form:ident $ty:ident) => { $ty::LAYOUT };
    (@layout $form:ident) => { None };
    (@tables grouped $($ty:ident),+) => { pastey::paste! { &[$(&[<$ty:snake:upper _TABLE>]),+] } };
    (@tables $form:ident $($ty:ident),*) => { &[] };
}

/// A value of a layout of clause 8.2: fields that are always there, then an octet of
/// flags and fields each present when its condition over the flags holds, then the octets
/// that a later release adds ("present only if explicitly specified"), which the value
/// keeps. A value of fields alone has no flags, and the tree of a value of one field
/// alone is that field while it has no unknown octets. A field of a length that the flags
/// give, `[length]` after its kind, is read from that many octets. Each field is written
/// by [`put`](crate::fields::put), which refuses one that its bits cannot say. A layout
/// that is a part of a value, of a second figure of its clause, and no IE, says `part` and
/// its name: it is a field of that value after its length of two octets. A `check`
/// block adds the rules of its clause, and a `placed` block those that its place in a
/// table gives ([`Rules::check_placed`](crate::check::Rules::check_placed)).
///
/// ```text
/// pub struct FTeid "8.2.3" {
///     flags(u8) { chid "CHID": 4, ch "CH": 3, v6 "V6": 2, v4 "V4": 1 }
///     teid "TEID": u32 if !ch,
///     ipv4 "IPv4 address": Ipv4Addr if v4 && !ch,
/// }
/// pub struct Mbr "8.2.8" { fields { ul_mbr "UL MBR": U40, dl_mbr "DL MBR": U40 } }
/// ```
macro_rules! pfcp_layout {
    ($($value:tt)*) => {
        oxirush_utils::layout! { [crate::ie::Codec, crate::check::Rules, crate::ie::IeType, crate::check::Deviation, crate::Error, crate::fields::field_error] $($value)* }
    };
}

/// A value of octets of bits: flags of one bit and fields of a few, each at its octet
/// (from 0), its lowest bit (from 1) and its width, in at most `N` octets of which the
/// first `MIN` are always there; then the octets that a later release adds. The other
/// bits are spare and kept, and so is how many of the `N` octets a decoded value had. A
/// value of a table that only a flag gives meaning to, `if flag`, is checked where the
/// flag is set. The rules of its clause on which flags go together follow it.
///
/// ```text
/// pub struct ApplyAction "8.2.26" octets 2 min 1 {
///     drop "DROP": 0 1 1, forw "FORW": 0 2 1, edrt "EDRT": 1 1 1,
/// }
/// check(action, path, found) { ... }
/// ```
macro_rules! pfcp_bits {
    ($($value:tt)*) => {
        oxirush_utils::bits! { [crate::ie::Codec, crate::check::Rules, crate::ie::IeType, crate::check::Deviation, crate::Error, crate::fields::field_error] $($value)* }
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
                    $( Self::$ty(body) => oxirush_utils::tables::Scope::encoded_len(&**body), )*
                    Self::Other { octets, .. } => octets.len(),
                }
            }

            /// The octets that the body takes beyond its own size: its box, and what its
            /// IEs hold ([`Listed::held`](crate::ie::Listed::held)).
            #[cfg(feature = "endpoint")]
            pub(crate) fn held(&self) -> usize {
                match self {
                    $( Self::$ty(body) => core::mem::size_of::<crate::registry::$ty>() + oxirush_utils::tables::Scope::held(&**body), )*
                    Self::Other { .. } => 0,
                }
            }

            /// The body as its receiver reads its octets ([`crate::check::as_read`]).
            pub(crate) fn as_read(&self, context: crate::check::Context, found: &mut alloc::vec::Vec<crate::check::Deviation>) -> Option<Self> {
                let path = crate::check::Path::Root("/pfcp");
                match self {
                    $( Self::$ty(body) => crate::check::as_read(&**body, &path, context, found).map(Self::from), )*
                    Self::Other { .. } => None,
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
                    $( Self::$ty(body) => crate::paths::scope_to_tree(&**body), )*
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
                    $( $code => Self::$ty(alloc::boxed::Box::new(crate::paths::scope_from_tree(value, reading)?)), )*
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
/// presence and its interfaces, which are the row's; its own are those where a constructor
/// takes it: where one of its rows is mandatory. A row whose condition the scope alone shows ends with
/// `absent(|scope| condition)`, where `check()` reports it there, and `if |scope|
/// condition`, where it reports it missing. A table whose rows are the scope above rows
/// with a condition on its IEs begins with `@ function;`, which checks those conditions
/// from it ([`crate::across`]).
macro_rules! pfcp_table {
    ($($table:tt)*) => {
        oxirush_utils::table! {
            {proto: crate::Pfcp, table: table, ie: ie, check: check, paths: paths, error: crate::Error, ctors: pfcp_ctors}
            $($table)*
        }
    };
}

/// The constructors of a table by interface, which [`table!`](oxirush_utils::table) has the
/// protocol write: `new_sxa()` to `new_n4mb()`, each with the mandatory rows of its interface.
macro_rules! pfcp_ctors {
    (@ctors $fam:tt [$($by:ident)+] $ty:ident $rows:tt) => {
        pfcp_ctors!(@each $fam [$($by)+] $ty $rows);
    };
    (@each $fam:tt [] $ty:ident $rows:tt) => {};
    (@each $fam:tt [$on:ident $($more:ident)*] $ty:ident $rows:tt) => {
        pfcp_ctors!(@ctor $fam $on $ty $rows);
        pfcp_ctors!(@each $fam [$($more)*] $ty $rows);
    };
    (@ctor $fam:tt SXA $ty:ident { $($rows:tt)* }) => { oxirush_utils::table!(@new $fam new_sxa SXA $ty "The scope with its mandatory IEs on Sxa." [] [] $($rows)*); };
    (@ctor $fam:tt SXB $ty:ident { $($rows:tt)* }) => { oxirush_utils::table!(@new $fam new_sxb SXB $ty "The scope with its mandatory IEs on Sxb." [] [] $($rows)*); };
    (@ctor $fam:tt SXC $ty:ident { $($rows:tt)* }) => { oxirush_utils::table!(@new $fam new_sxc SXC $ty "The scope with its mandatory IEs on Sxc." [] [] $($rows)*); };
    (@ctor $fam:tt N4 $ty:ident { $($rows:tt)* }) => { oxirush_utils::table!(@new $fam new_n4 N4 $ty "The scope with its mandatory IEs on N4." [] [] $($rows)*); };
    (@ctor $fam:tt N4MB $ty:ident { $($rows:tt)* }) => { oxirush_utils::table!(@new $fam new_n4mb N4MB $ty "The scope with its mandatory IEs on N4mb." [] [] $($rows)*); };
    (@in $fam:tt SXA [SXA $($i:ident)*] $name:ident $ty:ident $doc:literal [$($arg:tt)*] [$($set:tt)*] ($field:ident [$($m:tt)*] ($t:ty)) $($rest:tt)*) => {
        oxirush_utils::table!(@new $fam $name SXA $ty $doc [$($arg)* $field: $t,] [$($set)* ($field [$($m)*] ($t))] $($rest)*);
    };
    (@in $fam:tt SXB [SXB $($i:ident)*] $name:ident $ty:ident $doc:literal [$($arg:tt)*] [$($set:tt)*] ($field:ident [$($m:tt)*] ($t:ty)) $($rest:tt)*) => {
        oxirush_utils::table!(@new $fam $name SXB $ty $doc [$($arg)* $field: $t,] [$($set)* ($field [$($m)*] ($t))] $($rest)*);
    };
    (@in $fam:tt SXC [SXC $($i:ident)*] $name:ident $ty:ident $doc:literal [$($arg:tt)*] [$($set:tt)*] ($field:ident [$($m:tt)*] ($t:ty)) $($rest:tt)*) => {
        oxirush_utils::table!(@new $fam $name SXC $ty $doc [$($arg)* $field: $t,] [$($set)* ($field [$($m)*] ($t))] $($rest)*);
    };
    (@in $fam:tt N4 [N4 $($i:ident)*] $name:ident $ty:ident $doc:literal [$($arg:tt)*] [$($set:tt)*] ($field:ident [$($m:tt)*] ($t:ty)) $($rest:tt)*) => {
        oxirush_utils::table!(@new $fam $name N4 $ty $doc [$($arg)* $field: $t,] [$($set)* ($field [$($m)*] ($t))] $($rest)*);
    };
    (@in $fam:tt N4MB [N4MB $($i:ident)*] $name:ident $ty:ident $doc:literal [$($arg:tt)*] [$($set:tt)*] ($field:ident [$($m:tt)*] ($t:ty)) $($rest:tt)*) => {
        oxirush_utils::table!(@new $fam $name N4MB $ty $doc [$($arg)* $field: $t,] [$($set)* ($field [$($m)*] ($t))] $($rest)*);
    };
    (@in $fam:tt $on:tt [$other:ident $($i:ident)*] $name:ident $ty:ident $doc:literal [$($arg:tt)*] [$($set:tt)*] $row:tt $($rest:tt)*) => {
        pfcp_ctors!(@in $fam $on [$($i)*] $name $ty $doc [$($arg)*] [$($set)*] $row $($rest)*);
    };
    (@in $fam:tt $on:tt [] $name:ident $ty:ident $doc:literal [$($arg:tt)*] [$($set:tt)*] $row:tt $($rest:tt)*) => {
        oxirush_utils::table!(@new $fam $name $on $ty $doc [$($arg)*] [$($set)*] $($rest)*);
    };
}

/// The values that a table of clause 8.2 names: a variant each, and `Other` for a value that
/// the table has as spare or reserved, or does not have, kept as it is. A field of `bits`
/// bits, or a whole octet whose other bits are spare. `reserved [..]` lists the values that
/// the table reserves, and `rejected [from ..= to]` gives those that a note of the table
/// has its receiver reject, which are reserved in effect (§7.6.8).
///
/// ```text
/// pub enum Gate "Table 8.2.7-1 and Table 8.2.7-2" bits 2 {
///     0 Open "OPEN",
///     1 Closed "CLOSED",
/// }
/// ```
macro_rules! pfcp_enum {
    ($($value:tt)*) => {
        oxirush_utils::named_values! { $($value)* }
    };
}

pub(crate) use {
    pfcp_bits, pfcp_ctors, pfcp_enum, pfcp_ies, pfcp_layout, pfcp_messages, pfcp_table,
};
