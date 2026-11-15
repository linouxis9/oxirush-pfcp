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
            $(@ $across:path ;)?
            $( $field:ident : $row:literal $p:ident $(* $($max:literal)?)? $vty:ident
                [$($interface:ident)*] $(roles [$($role:literal $rp:ident $(* $($rmax:literal)?)? [$($ri:ident)*]),*])?
                $(absent(|$ascope:ident| $absent:expr))? $(if |$scope:ident| $condition:expr)? , )*
        }
    ) => { pastey::paste! {
        $(#[$meta])*
        #[derive(Debug, Clone, Default, PartialEq, Eq)]
        pub struct $ty {
            $(
                #[doc = concat!("The ", $row, " IE.")]
                pub $field: pfcp_table!(@field [$(* $($max)?)?] $p ($vty)),
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
        // A field holds as many IEs as its roles allow.
        const _: () = {$(
            let roles: &[crate::table::Role] = pfcp_table!(@roles $row $p [$(* $($max)?)?] [$($interface)*] $([$($role $rp [$(* $($rmax)?)?] [$($ri)*]),*])?);
            assert!(
                crate::table::capacity(roles) == crate::table::capacity(&[pfcp_table!(@role $row $p [$(* $($max)?)?] [])]),
                concat!("the field of ", $row, " holds other than its roles")
            );
        )*};

        pub(crate) static [<$ty:snake:upper _TABLE>]: crate::table::Table = crate::table::Table {
            id: $id,
            name: $name,
            code: $code,
            constructors: crate::table::Interfaces(0 $(| crate::table::Interfaces::$by.0)*),
            rows: &[$(
                crate::table::Row {
                    name: $row,
                    ie_type: <$vty as crate::ie::IeType>::IE_TYPE,
                    roles: pfcp_table!(@roles $row $p [$(* $($max)?)?] [$($interface)*] $([$($role $rp [$(* $($rmax)?)?] [$($ri)*]),*])?),
                    content: <$vty as crate::table::Content>::TABLE,
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
                pub fn [<with_ $field>](mut self, value: $vty) -> Self {
                    crate::table::FieldValues::<$vty>::add(&mut self.$field, value);
                    self
                }
            )*
        }

        pfcp_table!(@ctors [$($by)*] $ty { $( $field : $row $p $(* $($max)?)? $vty [$($interface)*] , )* });

        // A table without rows leaves its arguments unused.
        #[allow(unused_variables, unused_mut, unused_assignments)]
        impl oxirush_utils::tables::Scope for $ty {
            type P = crate::Pfcp;
            fn table() -> &'static crate::table::Table {
                &[<$ty:snake:upper _TABLE>]
            }

            #[allow(unused_assignments, unused_variables, unused_mut)]
            fn position(ie_type: u16) -> Option<usize> {
                let mut at = 0;
                $(
                    if ie_type == <$vty as crate::ie::IeType>::IE_TYPE {
                        return Some(at);
                    }
                    at += 1;
                )*
                None
            }

            const PRESIZE: bool = false $( || pfcp_table!(@large [$(* $($max)?)?] ($vty)) )*;

            // Only the IEs that can be values are counted: not one of a null length, nor
            // one whose IEs run past it, which the scope keeps as octets.
            #[allow(unused_variables)]
            fn presize(&mut self, octets: &[u8]) {
                $( let mut [<count_ $field>] = 0usize; )*
                for ie in crate::framing::ies(octets).flatten() {
                    $(
                        if pfcp_table!(@large [$(* $($max)?)?] ($vty))
                            && ie.ie_type == <$vty as crate::ie::IeType>::IE_TYPE
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
                    if ie_type == <$vty as crate::ie::IeType>::IE_TYPE {
                        return pfcp_table!(@place [$(* $($max)?)?] $p ($vty) self.$field, body);
                    }
                )*
                crate::ie::Placing::Unexpected
            }

            fn emit(&self, ie_type: u16, nth: usize, out: &mut alloc::vec::Vec<u8>) -> Result<bool, crate::Error> {
                $(
                    if ie_type == <$vty as crate::ie::IeType>::IE_TYPE {
                        return crate::table::emit_field::<$vty, _>(&self.$field, nth, out);
                    }
                )*
                Ok(false)
            }

            fn encoded_len(&self) -> usize {
                let mut length = 0;
                $( pfcp_table!(@each [$(* $($max)?)?] ($vty) self.$field, |value| {
                    length += 4 + crate::ie::Codec::encoded_len(value);
                }); )*
                for ie in &self.raw {
                    length += 4 + 2 * usize::from(ie.enterprise_id.is_some()) + ie.octets.len();
                }
                length
            }

            fn encode_fields(&self, out: &mut alloc::vec::Vec<u8>) -> Result<(), crate::Error> {
                $( pfcp_table!(@each [$(* $($max)?)?] ($vty) self.$field, |value| {
                    crate::ie::encode_value(value, out)?;
                }); )*
                Ok(())
            }

            #[cfg(feature = "endpoint")]
            fn held(&self) -> usize {
                let mut held = self.raw.capacity() * core::mem::size_of::<crate::ie::RawIe>()
                    + self.order.capacity() * core::mem::size_of::<crate::ie::Placed>();
                $( held += pfcp_table!(@held [$(* $($max)?)?] $p ($vty) self.$field); )*
                held
            }

            fn count(&self, ie_type: u16) -> usize {
                $(
                    if ie_type == <$vty as crate::ie::IeType>::IE_TYPE {
                        return crate::table::FieldValues::<$vty>::values(&self.$field).len();
                    }
                )*
                0
            }

            fn clear(&mut self, ie_type: u16) {
                $(
                    if ie_type == <$vty as crate::ie::IeType>::IE_TYPE {
                        self.$field = Default::default();
                        return;
                    }
                )*
            }

            fn decodes(&self, ie_type: u16, octets: &[u8]) -> bool {
                $(
                    if ie_type == <$vty as crate::ie::IeType>::IE_TYPE {
                        return <$vty as crate::ie::Codec>::decode(octets).is_some();
                    }
                )*
                false
            }

            fn plain(&self) -> bool {
                self.raw.is_empty() $( && pfcp_table!(@plain [$(* $($max)?)?] ($vty) self.$field) )*
            }

            fn is_empty(&self) -> bool {
                self.raw.is_empty() $( && crate::table::FieldValues::<$vty>::values(&self.$field).is_empty() )*
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
                // The conditions read the scope as its receiver on the interface takes it:
                // without the values of the rows that the interface does not have.
                const CONDITIONS: bool = false $( || pfcp_table!(@checked $($scope)? $($ascope)?) )*;
                let mut off = 0u64;
                if CONDITIONS {
                    let (rows, mut row) = (<Self as oxirush_utils::tables::Scope>::table().rows, 0);
                    $(
                        if !crate::table::FieldValues::<$vty>::values(&self.$field).is_empty() && !rows[row].roles.iter().any(|role| role.interfaces.has(context.interface)) {
                            off |= 1 << row;
                        }
                        row += 1;
                    )*
                }
                let taken = crate::check::taken(self, off);
                let view: &Self = taken.as_ref().unwrap_or(self);
                let mut row = 0;
                $(
                    crate::check::check_field_values::<$vty, _, _>(
                        self, row, &self.$field, path, context, found,
                    );
                    $({
                        let $scope: &Self = view;
                        if $condition {
                            crate::check::condition_missing(self, row, path, context, found);
                        }
                    })?
                    $({
                        let $ascope: &Self = view;
                        if $absent {
                            crate::check::condition_absent(self, row, path, context, found);
                        }
                    })?
                    row += 1;
                )*
                $( $across(self, path, context, found); )?
            }
        }

        pfcp_table!(@kind $kind $ty);

        #[cfg(feature = "tree")]
        // A table without rows leaves its arguments unused.
        #[allow(unused_variables, unused_mut, unused_assignments)]
        impl crate::paths::TreeScope for $ty {
            fn field_tree(&self, ie_type: u16, nth: usize) -> Option<oxirush_utils::tree::Value> {
                $(
                    if ie_type == <$vty as crate::ie::IeType>::IE_TYPE {
                        return crate::paths::field_tree::<$vty, _>(&self.$field, nth);
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
                    if ie_type == <$vty as crate::ie::IeType>::IE_TYPE {
                        return crate::paths::read_field::<$vty, _>(&mut self.$field, value, reading);
                    }
                )*
                Ok(())
            }
        }
    } };

    // ── The parts of a row ──────────────────────────────────────────────────

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
    // The roles of a row: the row itself, or the rows that share its field.
    (@roles $row:literal $p:ident [$($repeat:tt)*] [$($interface:ident)*]) => {
        &[pfcp_table!(@role $row $p [$($repeat)*] [$($interface)*])]
    };
    (@roles $row:literal $p:ident $repeat:tt $interfaces:tt [$($role:literal $rp:ident [$($rrepeat:tt)*] [$($ri:ident)*]),*]) => {
        &[$(pfcp_table!(@role $role $rp [$($rrepeat)*] [$($ri)*])),*]
    };
    (@role $name:literal $p:ident [$($repeat:tt)*] [$($interface:ident)*]) => {
        crate::table::Role {
            name: $name,
            presence: pfcp_table!(@presence $p),
            repeat: pfcp_table!(@repeat $($repeat)*),
            interfaces: crate::table::Interfaces(0 $(| crate::table::Interfaces::$interface.0)*),
        }
    };
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
        $f.as_ref().map_or(0, |value| core::mem::size_of::<$t>() + oxirush_utils::tables::Scope::held(&**value))
    };
    // Whether a field reads as it is: as many values as the row takes, each plain.
    (@plain [] ($t:ty) $f:expr) => { crate::table::FieldValues::<$t>::values(&$f).iter().all(crate::ie::Listed::plain) };
    (@plain [* $($max:literal)?] ($t:ty) $f:expr) => { !pfcp_table!(@over [$($max)?] $f) && $f.iter().all(crate::ie::Listed::plain) };
    (@over [] $f:expr) => { false };
    (@over [$max:literal] $f:expr) => { $f.len() > $max };
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
                oxirush_utils::tables::Scope::encoded_len(self)
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
                oxirush_utils::tables::Scope::held(self)
            }

            fn check_in(&self, path: &crate::check::Path, context: crate::check::Context, found: &mut alloc::vec::Vec<crate::check::Deviation>) {
                crate::check::check_scope(self, path, context, found);
            }

            /// Of a grouped IE that has an IE: one of a null length reads as none.
            fn plain(&self) -> bool {
                oxirush_utils::tables::Scope::plain(self) && !oxirush_utils::tables::Scope::is_empty(self)
            }
        }

        impl crate::check::Rules for $ty {
            /// Its table on the interfaces that it has, as the receiver of a response: the
            /// IEs of any, and those that all need; as its receiver reads it
            /// ([`crate::check::as_read`]).
            fn check(&self, path: &crate::check::Path, found: &mut alloc::vec::Vec<crate::check::Deviation>) {
                let interfaces = <Self as oxirush_utils::tables::Scope>::table().interfaces();
                let context = crate::check::Context::on(interfaces);
                let read = crate::check::as_read(self, path, context, found);
                crate::check::check_scope(read.as_ref().unwrap_or(self), path, context, found);
            }
        }

        #[cfg(feature = "tree")]
        impl oxirush_utils::tree::Tree for $ty {
            const NAME: &'static str = <$ty as crate::ie::IeType>::TYPE_NAME;

            fn to_tree(&self) -> oxirush_utils::tree::Value {
                crate::paths::scope_to_tree(self)
            }

            fn from_tree(
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
            ) -> Result<Self, oxirush_utils::tree::Refused> {
                crate::paths::scope_from_tree(value, reading)
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
    (@new $name:ident $on:tt $ty:ident $doc:literal [$($arg:tt)*] [$($set:tt)*] $field:ident : $row:literal M $(* $($max:literal)?)? $vty:ident [$($i:ident)*] , $($rest:tt)*) => {
        pfcp_table!(@in $on [$($i)*] $name $ty $doc [$($arg)*] [$($set)*] ($field [$(* $($max)?)?] ($vty)) $($rest)*);
    };
    (@new $name:ident $on:tt $ty:ident $doc:literal [$($arg:tt)*] [$($set:tt)*] $field:ident : $row:literal $p:ident $(* $($max:literal)?)? $vty:ident [$($i:ident)*] , $($rest:tt)*) => {
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

pub(crate) use {pfcp_bits, pfcp_enum, pfcp_ies, pfcp_layout, pfcp_messages, pfcp_table};
