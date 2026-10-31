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

//! What `check()` finds: each way in which a message is not as TS 29.244 has a sender
//! construct it, with the path of the IE and the clause that it breaks.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::ie::VENDOR;
use crate::registry::type_name;
use crate::table::{Presence, Repeat, Scope};

/// One deviation: where, which clause, and what.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deviation {
    /// The path of the IE in the tree of the message: `/pfcp/Create PDR/0/PDI`.
    pub path: String,
    /// The clause or the table that the message breaks.
    pub clause: &'static str,
    /// What is wrong.
    pub kind: DeviationKind,
}

/// What a deviation is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviationKind {
    /// A mandatory IE is not there (§7.6.6).
    MandatoryMissing {
        /// Its IE type.
        ie_type: u16,
    },
    /// A mandatory IE is there, and its value does not decode as its type (§7.6.8).
    MandatoryIncorrect {
        /// Its IE type.
        ie_type: u16,
    },
    /// An optional or conditional IE whose value does not decode as its type: the
    /// receiver takes it as absent (§7.6.8).
    Incorrect {
        /// Its IE type.
        ie_type: u16,
    },
    /// An IE that is there more times than its table allows: the receiver handles the
    /// first ones (§7.6.10).
    Repeated {
        /// Its IE type.
        ie_type: u16,
    },
    /// An IE of a known type that its table does not have: the receiver discards it
    /// (§7.6.9).
    Unexpected {
        /// Its IE type.
        ie_type: u16,
    },
    /// An IE type that Table 8.1.2-1 does not have (§8.1.2).
    UnknownType {
        /// Its IE type.
        ie_type: u16,
    },
    /// A vendor IE with the Enterprise ID of 3GPP, or none (§8.1.1).
    VendorId,
    /// Spare bits that are not zero (§8.1.2).
    SpareBits,
    /// A value that its table has as spare or reserved (§7.6.8).
    SpareValue {
        /// The value.
        value: u32,
    },
    /// A field that is there where the flags of its IE do not have it, or the reverse.
    Inconsistent {
        /// The field.
        field: &'static str,
    },
    /// A rule of the clause, in words.
    Rule(&'static str),
}

impl Deviation {
    /// A deviation at `path`.
    pub fn new(path: &str, clause: &'static str, kind: DeviationKind) -> Self {
        Self { path: path.into(), clause, kind }
    }

    /// The Cause that a receiver answers a request with for it (Table 8.2.1-1): `None`
    /// for a deviation that the receiver ignores.
    pub fn cause(&self) -> Option<u8> {
        match self.kind {
            DeviationKind::MandatoryMissing { .. } => Some(66),
            DeviationKind::MandatoryIncorrect { .. } => Some(69),
            _ => None,
        }
    }
}

impl fmt::Display for Deviation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = |ie_type: u16| type_name(ie_type).unwrap_or("an IE of no release");
        match &self.kind {
            DeviationKind::MandatoryMissing { ie_type } => write!(f, "the mandatory {} is missing", name(*ie_type)),
            DeviationKind::MandatoryIncorrect { ie_type } => write!(f, "the mandatory {} does not decode", name(*ie_type)),
            DeviationKind::Incorrect { ie_type } => write!(f, "{} does not decode, and is taken as absent", name(*ie_type)),
            DeviationKind::Repeated { ie_type } => write!(f, "{} is there more times than its table allows", name(*ie_type)),
            DeviationKind::Unexpected { ie_type } => write!(f, "{} is no IE of this table", name(*ie_type)),
            DeviationKind::UnknownType { ie_type } => write!(f, "IE type {ie_type} is in no table of Release 19"),
            DeviationKind::VendorId => write!(f, "a vendor IE without an Enterprise ID of a vendor"),
            DeviationKind::SpareBits => write!(f, "spare bits are not zero"),
            DeviationKind::SpareValue { value } => write!(f, "{value} is a spare value"),
            DeviationKind::Inconsistent { field } => write!(f, "{field} disagrees with the flags of its IE"),
            DeviationKind::Rule(rule) => write!(f, "{rule}"),
        }?;
        write!(f, " (TS 29.244 {}), at {}", self.clause, self.path)
    }
}

/// What a value checks of itself: its flags, its fields and its values.
pub trait Check {
    /// Add what is wrong with the value to `found`, at `path`.
    fn check(&self, path: &str, found: &mut Vec<Deviation>) {
        let _ = (path, found);
    }
}

/// What the table macro writes: the check of each value of the fields of a scope.
pub(crate) trait Checked {
    fn check_values(&self, path: &str, found: &mut Vec<Deviation>);
}

/// The path of the `nth` IE of a row: a row that is a list has its position.
pub(crate) fn at(path: &str, row: &str, nth: Option<usize>) -> String {
    match nth {
        Some(nth) => format!("{path}/{row}/{nth}"),
        None => format!("{path}/{row}"),
    }
}

/// Check a scope against its table: its mandatory IEs, the IEs that repeat or that it
/// cannot have, then each of its values.
pub(crate) fn check_scope<S: Scope + Checked>(scope: &S, path: &str, found: &mut Vec<Deviation>) {
    let table = S::table();
    for row in table.rows {
        // A row that N4 does not have is mandatory on the interfaces that have it.
        let mandatory = row.presence == Presence::Mandatory && row.interfaces.has(crate::table::Interfaces::N4);
        let values = scope.count(row.ie_type);
        let raw = scope.raw().iter().filter(|ie| ie.ie_type == row.ie_type && !ie.octets.is_empty());
        let (mut repeated, mut incorrect) = (0, 0);
        for ie in raw {
            match scope.decodes(ie.ie_type, &ie.octets) {
                true => repeated += 1,
                false => incorrect += 1,
            }
        }
        let here = format!("{path}/{}", row.name);
        if mandatory && values == 0 {
            let kind = match incorrect {
                0 => DeviationKind::MandatoryMissing { ie_type: row.ie_type },
                _ => DeviationKind::MandatoryIncorrect { ie_type: row.ie_type },
            };
            found.push(Deviation::new(&here, table.id, kind));
        } else if incorrect > 0 {
            found.push(Deviation::new(&here, "7.6.8", DeviationKind::Incorrect { ie_type: row.ie_type }));
        }
        let allowed = match row.repeat {
            Repeat::Once => 1,
            Repeat::Any => usize::MAX,
            Repeat::AtMost(most) => usize::from(most),
        };
        if repeated > 0 || values > allowed {
            found.push(Deviation::new(&here, "7.6.10", DeviationKind::Repeated { ie_type: row.ie_type }));
        }
    }
    for ie in scope.raw() {
        if table.row_of(ie.ie_type).is_some() {
            continue;
        }
        let name = crate::tree_name(ie.ie_type, None);
        let here = format!("{path}/{name}");
        let kind = match ie.ie_type {
            VENDOR.. if ie.enterprise_id.is_none_or(|id| id == 10415) => DeviationKind::VendorId,
            VENDOR.. => continue,
            known if type_name(known).is_some() => DeviationKind::Unexpected { ie_type: known },
            unknown => DeviationKind::UnknownType { ie_type: unknown },
        };
        let clause = match kind {
            DeviationKind::Unexpected { .. } => "7.6.9",
            DeviationKind::VendorId => "8.1.1",
            _ => "8.1.2",
        };
        found.push(Deviation::new(&here, clause, kind));
    }
    scope.check_values(path, found);
}
