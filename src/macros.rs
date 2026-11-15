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
    ($($ies:tt)*) => {
        oxirush_utils::ies! { {proto: crate::Pfcp, table: table, ie: ie} $($ies)* }
    };
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
    ($($messages:tt)*) => {
        oxirush_utils::messages! {
            {proto: crate::Pfcp, table: table, ie: ie, check: check, paths: paths, message: message, registry: registry, error: crate::Error}
            $($messages)*
        }
    };
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
