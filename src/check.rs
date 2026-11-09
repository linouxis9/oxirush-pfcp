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

//! What `check()` finds: each way in which a message breaks TS 29.244, with its path in
//! the tree of the message, the clause that it breaks and the Cause with which a receiver
//! answers a request for it.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::enums::CauseValue;
use crate::ie::VENDOR;
use crate::registry::ie_type_info;
use crate::table::{Interfaces, Presence, Row, Scope};

/// One deviation: where, which clause, what, and the Cause of the answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deviation {
    /// Where the deviation is, as a path of the tree of the message, which `paths::select`
    /// takes: the IE, at its position in the list
    /// of its row (`/pfcp/Create PDR/0/PDI`); the row, for what the row has as a whole (a
    /// mandatory IE missing, more IEs than it allows, an interface without it); a field of
    /// the header (`/SEID`); `/message` for the message type; and `/pfcp` for the IEs
    /// together. A name with a `/` has it written `~1`: `/pfcp/APN~1DNN`.
    pub path: String,
    /// The clause or the table that the message breaks.
    pub clause: &'static str,
    /// What is wrong.
    pub kind: DeviationKind,
    /// The Cause with which the receiver of a request answers it (§7.6, Table 8.2.1-1):
    /// `None` for a deviation that the receiver ignores, and in a response.
    pub cause: Option<CauseValue>,
    /// The IE type of the IE at `path`, when the deviation is in its value.
    pub(crate) ie_type: Option<u16>,
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
    /// A conditional IE is not there where the scope shows that its condition holds
    /// (§7.6.6): the rows that say so in [`Row::checked`](crate::Row::checked).
    ConditionalMissing {
        /// Its IE type.
        ie_type: u16,
    },
    /// A mandatory IE, or a conditional one where the scope shows that its condition
    /// holds, of a null length: the sender's deviation, which its receiver does not treat
    /// as an error (§8.1.2), as a null length removes an IE of a rule that an update
    /// changes (§5.6.3).
    NullLength {
        /// Its IE type.
        ie_type: u16,
    },
    /// A conditional IE that is there, and whose value does not decode as its type: a
    /// verifiable conditional IE of a semantically invalid value (§7.6.8), which the
    /// receiver of a request answers with "Mandatory IE incorrect".
    ConditionalIncorrect {
        /// Its IE type.
        ie_type: u16,
    },
    /// An optional IE whose value does not decode as its type: the receiver takes it as
    /// absent (§7.6.8).
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
    /// An IE that is there where the condition that its table writes beside it, and that
    /// the scope shows, has it absent: "shall not be present if", "shall be absent", "shall
    /// not be present together". The receiver has no Cause for it (§7.6).
    Excluded {
        /// Its IE type.
        ie_type: u16,
    },
    /// An IE that its table has, but not on the interface (the Appl. columns): its
    /// receiver discards it whole (§7.6.9), and nothing that it holds is told.
    NotOnInterface {
        /// Its IE type.
        ie_type: u16,
    },
    /// An IE in a response with a rejection Cause, which only the Cause, the Node ID, the
    /// Offending IE, the Load and Overload Control Information and the Failed Rule ID may
    /// accompany (§7.2.3.2), and a row whose condition names that Cause: the address of
    /// the new SMF of a redirection (§5.22.2).
    WithRejection {
        /// Its IE type.
        ie_type: u16,
    },
    /// An IE whose Length is not the length of its content (§7.6.7, §8.1.1): it does not
    /// frame, nor do the IEs after it, and the receiver of a request answers "Invalid
    /// length" with its type. One that runs past the grouped IE that holds it is told at
    /// that grouped IE, which its receiver cannot read.
    InvalidLength {
        /// Its IE type.
        ie_type: u16,
    },
    /// An IE of a fixed length (Table 8.1.2-1) that has another.
    FixedLength {
        /// Its IE type.
        ie_type: u16,
        /// Its length.
        length: usize,
    },
    /// An IE type that Table 8.1.2-1 does not have (§8.1.2).
    UnknownType {
        /// Its IE type.
        ie_type: u16,
    },
    /// A message type that Table 7.3-1 does not have (§7.6.4).
    UnknownMessage {
        /// The message type.
        message_type: u8,
    },
    /// A message type that Table 7.3-1 does not have on the interface (§7.6.5).
    MessageNotOnInterface {
        /// The message type.
        message_type: u8,
    },
    /// A rule that one message creates, updates or removes more than once: two rules of one
    /// Rule ID in an establishment (§5.2.1), two changes of one rule in a modification
    /// (§6.3.3.2).
    RuleChangedTwice {
        /// The type of the rule: `PDR`, `FAR`, `URR`, `QER`, `BAR`, `MAR` or `SRR`.
        rule: &'static str,
        /// Its ID.
        id: u32,
    },
    /// A vendor IE with the Enterprise ID of 3GPP, or none (§8.1.1).
    VendorId,
    /// Spare bits that are not zero (§8.1.2), and a reserved bit that its clause has the
    /// sender set to 0, as bit 3 of Reporting Frequency (§8.2.168).
    SpareBits,
    /// A value that its table has as spare, or does not have: the receiver ignores it
    /// (§7.6.8).
    SpareValue {
        /// The value.
        value: u32,
    },
    /// A value that its table has a sender not send, and a receiver read as another: a
    /// Gate of 2 as CLOSED, a Metric of 101 as 0 (§7.6.8).
    ReadAs {
        /// The value.
        value: u32,
        /// The value that the receiver takes.
        read: u32,
    },
    /// A value that its table reserves: the receiver takes the IE as incorrect (§7.6.8).
    ReservedValue {
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
    /// A deviation at `path`, that the receiver ignores.
    pub fn new(path: impl fmt::Display, clause: &'static str, kind: DeviationKind) -> Self {
        Self {
            path: format!("{path}"),
            clause,
            kind,
            cause: None,
            ie_type: None,
        }
    }

    /// The IE type that the Offending IE of the answer carries, with its Cause: the IE
    /// that is missing, or whose value is incorrect (§7.6.6, §7.6.8).
    pub fn offending_ie(&self) -> Option<u16> {
        let ie_type = match self.kind {
            DeviationKind::MandatoryMissing { ie_type }
            | DeviationKind::MandatoryIncorrect { ie_type }
            | DeviationKind::ConditionalMissing { ie_type }
            | DeviationKind::ConditionalIncorrect { ie_type }
            | DeviationKind::InvalidLength { ie_type }
            | DeviationKind::FixedLength { ie_type, .. } => Some(ie_type),
            _ => self.ie_type,
        };
        self.cause.and(ie_type)
    }
}

impl fmt::Display for Deviation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name =
            |ie_type: u16| ie_type_info(ie_type).map_or("an IE of no release", |info| info.name);
        match &self.kind {
            DeviationKind::MandatoryMissing { ie_type } => {
                write!(f, "the mandatory {} is missing", name(*ie_type))
            }
            DeviationKind::MandatoryIncorrect { ie_type } => {
                write!(f, "the mandatory {} does not decode", name(*ie_type))
            }
            DeviationKind::ConditionalMissing { ie_type } => {
                write!(f, "{} is missing where its condition holds", name(*ie_type))
            }
            DeviationKind::ConditionalIncorrect { ie_type } => {
                write!(f, "the conditional {} does not decode", name(*ie_type))
            }
            DeviationKind::NullLength { ie_type } => {
                write!(
                    f,
                    "{} has a null length where it needs its value",
                    name(*ie_type)
                )
            }
            DeviationKind::Incorrect { ie_type } => write!(
                f,
                "{} does not decode, and is taken as absent",
                name(*ie_type)
            ),
            DeviationKind::Repeated { ie_type } => write!(
                f,
                "{} is there more times than its table allows",
                name(*ie_type)
            ),
            DeviationKind::Unexpected { ie_type } => {
                write!(f, "{} is no IE of this table", name(*ie_type))
            }
            DeviationKind::NotOnInterface { ie_type } => {
                write!(f, "{} is not on this interface", name(*ie_type))
            }
            DeviationKind::Excluded { ie_type } => {
                write!(
                    f,
                    "{} is there where its condition has it absent",
                    name(*ie_type)
                )
            }
            DeviationKind::WithRejection { ie_type } => {
                write!(f, "{} accompanies a rejection", name(*ie_type))
            }
            DeviationKind::InvalidLength { ie_type } => {
                write!(
                    f,
                    "{} has a Length that is not the length of its content",
                    name(*ie_type)
                )
            }
            DeviationKind::FixedLength { ie_type, length } => {
                write!(
                    f,
                    "{} has {length} octets, and its length is fixed",
                    name(*ie_type)
                )
            }
            DeviationKind::UnknownType { ie_type } => {
                write!(f, "IE type {ie_type} is in no table of Release 19")
            }
            DeviationKind::UnknownMessage { message_type } => write!(
                f,
                "message type {message_type} is in no table of Release 19"
            ),
            DeviationKind::MessageNotOnInterface { message_type } => {
                write!(f, "message type {message_type} is not on this interface")
            }
            DeviationKind::RuleChangedTwice { rule, id } => {
                write!(f, "the message changes {rule} {id} more than once")
            }
            DeviationKind::VendorId => {
                write!(f, "a vendor IE without an Enterprise ID of a vendor")
            }
            DeviationKind::SpareBits => write!(f, "spare bits are not zero"),
            DeviationKind::SpareValue { value } => write!(f, "{value} is a spare value"),
            DeviationKind::ReservedValue { value } => write!(f, "{value} is a reserved value"),
            DeviationKind::ReadAs { value, read } => {
                write!(f, "{value} is no value to send, and is read as {read}")
            }
            DeviationKind::Inconsistent { field } => {
                write!(f, "{field} disagrees with the flags of its IE")
            }
            DeviationKind::Rule(rule) => write!(f, "{rule}"),
        }?;
        write!(f, " (TS 29.244 {}), at {}", self.clause, self.path)?;
        if let Some(cause) = self.cause {
            write!(f, ": the answer is \"{cause}\"")?;
        }
        Ok(())
    }
}

/// What a value checks of itself, at its place in a message: what [`Check`] gives. The
/// module is private, and a caller does not name it.
pub trait Rules {
    /// Add what is wrong with the value to `found`, at `path`.
    fn check(&self, path: &Path<'_>, found: &mut Vec<Deviation>) {
        let _ = (path, found);
    }
}

/// What a value checks of itself: its flags, its fields and its values. A grouped IE
/// checks its table, on its own on the interfaces of the table: the IEs that each of
/// them needs are mandatory.
pub trait Check: Rules {
    /// How the value breaks its clause: each deviation at its path below the value, `""`
    /// for the value itself.
    fn deviations(&self) -> Vec<Deviation> {
        let mut found = Vec::new();
        self.check(&Path::Root(""), &mut found);
        found
    }
}

impl<T: Rules> Check for T {}

/// Where a check is: the interface, and how the receiver takes the mandatory IEs of the
/// scope (§7.2.3.2: those of a conditional grouped IE as conditional, those of an
/// optional one as optional).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Context {
    pub(crate) interface: Interfaces,
    pub(crate) view: Presence,
    /// In a request that the receiver answers with a Cause: not a Heartbeat Request.
    pub(crate) request: bool,
    /// The Cause of a response that rejects the request, at the message level.
    pub(crate) rejected: Option<CauseValue>,
}

impl Context {
    /// The message level of a message on `interface`, which no receiver answers.
    pub(crate) fn on(interface: Interfaces) -> Self {
        Self {
            interface,
            view: Presence::Mandatory,
            request: false,
            rejected: None,
        }
    }

    /// The context of the IEs of a grouped IE of the row of presence `presence`.
    pub(crate) fn within(self, presence: Presence) -> Self {
        let view = match (self.view, presence) {
            (_, Presence::Optional) | (Presence::Optional, _) => Presence::Optional,
            (Presence::Mandatory, Presence::Mandatory) => Presence::Mandatory,
            _ => Presence::Conditional,
        };
        Self {
            view,
            rejected: None,
            ..self
        }
    }

    /// The Cause of an answer to a mandatory IE of the scope that is missing, or that is
    /// there and incorrect.
    fn cause(self, missing: bool) -> Option<CauseValue> {
        match (self.request, self.view, missing) {
            (false, ..) | (_, Presence::Optional, _) => None,
            (true, Presence::Mandatory, true) => Some(CauseValue::MandatoryIeMissing),
            (true, Presence::Conditional, true) => Some(CauseValue::ConditionalIeMissing),
            (true, _, false) => Some(CauseValue::MandatoryIeIncorrect),
        }
    }

    /// The Cause of an answer to a request of an IE or a Message Length that is not the
    /// length of what it counts (§7.6.3, §7.6.7): of any IE, as the IEs after it do not
    /// frame.
    pub(crate) fn invalid_length(self) -> Option<CauseValue> {
        self.request.then_some(CauseValue::InvalidLength)
    }

    /// The Cause of an answer to a conditional IE of the scope that is missing where its
    /// condition holds (§7.6.6).
    fn conditional_cause(self) -> Option<CauseValue> {
        match (self.request, self.view) {
            (true, Presence::Mandatory | Presence::Conditional) => {
                Some(CauseValue::ConditionalIeMissing)
            }
            _ => None,
        }
    }
}

/// What the table macro writes: the check of each value of the fields of a scope.
pub(crate) trait Checked {
    fn check_values(&self, path: &Path<'_>, context: Context, found: &mut Vec<Deviation>);
}

/// Where an IE is in the tree of its message: written only for a deviation.
#[derive(Debug, Clone, Copy)]
pub enum Path<'a> {
    /// The message level, or a path written already.
    Root(&'a str),
    /// The IE of a row in a scope: a row that is a list has its position.
    Row {
        /// The scope.
        parent: &'a Path<'a>,
        /// The name of the row.
        row: &'static str,
        /// The position in a list.
        nth: Option<usize>,
    },
}

impl fmt::Display for Path<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root(path) => f.write_str(path),
            Self::Row {
                parent,
                row,
                nth: Some(nth),
            } => write!(f, "{parent}/{}/{nth}", Segment(row)),
            Self::Row {
                parent,
                row,
                nth: None,
            } => write!(f, "{parent}/{}", Segment(row)),
        }
    }
}

/// A name as a segment of a path writes it: `~0` for its `~` and `~1` for its `/`, as a
/// JSON pointer (RFC 6901) and the paths of oxirush-utils have them.
struct Segment<'a>(&'a str);

impl fmt::Display for Segment<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut rest = self.0;
        while let Some(at) = rest.find(['~', '/']) {
            f.write_str(&rest[..at])?;
            f.write_str(if rest[at..].starts_with('~') {
                "~0"
            } else {
                "~1"
            })?;
            rest = &rest[at + 1..];
        }
        f.write_str(rest)
    }
}

/// Check a value of a row of a scope: itself, and its length against Table 8.1.2-1.
pub(crate) fn check_field<T: crate::ie::Listed + crate::ie::IeType>(
    value: &T,
    path: &Path<'_>,
    presence: Presence,
    context: Context,
    found: &mut Vec<Deviation>,
) {
    let from = found.len();
    value.check_in(path, context.within(presence), found);
    if let Some(fixed) = T::FIXED {
        let length = value.encoded_len();
        if length != usize::from(fixed) {
            found.push(Deviation::new(
                path,
                "8.1.2",
                DeviationKind::FixedLength {
                    ie_type: T::IE_TYPE,
                    length,
                },
            ));
        }
    }
    if found.len() > from {
        value_deviations(&mut found[from..], path, T::IE_TYPE, presence, context);
    }
}

/// The deviations of the value of an IE itself, not those of the IEs of a grouped one,
/// which their own rows answer: each gets the IE type, and a value that is semantically
/// invalid (a reserved value, a length, fields that disagree with their flags, a rule of
/// its clause) the Cause of a mandatory or verifiable conditional IE (§7.6.8). A spare
/// value or spare bits are ignored.
#[cold]
#[inline(never)]
fn value_deviations(
    found: &mut [Deviation],
    path: &Path<'_>,
    ie_type: u16,
    presence: Presence,
    context: Context,
) {
    let here = format!("{path}");
    for deviation in found.iter_mut().filter(|deviation| deviation.path == here) {
        deviation.ie_type = Some(ie_type);
        let invalid = matches!(
            deviation.kind,
            DeviationKind::ReservedValue { .. }
                | DeviationKind::FixedLength { .. }
                | DeviationKind::Inconsistent { .. }
                | DeviationKind::Rule(_)
        );
        if invalid && presence != Presence::Optional {
            deviation.cause = context.cause(false);
        }
    }
}

/// Check the values of the row at `at` of a scope: the row, then each value, at its
/// position in the tree, which the IEs of the row that the scope keeps as octets share.
#[inline(always)]
pub(crate) fn check_field_values<
    T: crate::ie::Listed + crate::ie::IeType,
    F: crate::table::FieldValues<T>,
    S: Scope,
>(
    scope: &S,
    at: usize,
    field: &F,
    path: &Path<'_>,
    context: Context,
    found: &mut Vec<Deviation>,
) {
    let values = field.values();
    if values.is_empty() {
        return;
    }
    let table = S::table();
    let row = &table.rows[at];
    if !check_row(table.id, row, values.len(), path, context, found) {
        // The receiver discards each IE of the row, whatever it holds (§7.6.9).
        return;
    }
    // Of the values alone, their positions; with kept IEs of the row, theirs in the tree.
    let kept = scope.raw().iter().any(|ie| ie.ie_type == row.ie_type);
    let positions = match kept {
        false => Vec::new(),
        true => crate::table::value_positions(scope, row),
    };
    for (nth, value) in values.iter().enumerate() {
        let nth = match kept {
            false => row.is_list().then_some(nth),
            true => Some(positions[nth]),
        };
        let here = Path::Row {
            parent: path,
            row: row.name,
            nth,
        };
        check_field(value, &here, presence(row, context), context, found);
    }
}

/// The presence of a row on the interface of the context. One that the interface does not
/// have is taken as optional: its IEs are discarded (§7.6.9), and what they break has no
/// Cause.
fn presence(row: &Row, context: Context) -> Presence {
    row.on(context.interface)
        .and_then(|on| on.presence)
        .unwrap_or(Presence::Optional)
}

/// The IEs that a response with a rejection Cause may have (§7.2.3.2): Cause, Node ID,
/// Offending IE, Load Control Information, Overload Control Information, Failed Rule ID.
const WITH_REJECTION: [u16; 6] = [19, 60, 40, 51, 54, 114];

/// The rows that a response with a rejection Cause may have besides, as many IEs of each
/// as there are rows of that Cause, by their table, their IE type and the Cause that their
/// condition names: the address of the new SMF of a redirection, which a row of the
/// Alternative SMF IP Address of a Session Report Response is (Table 7.5.9.1-1, §5.22.2);
/// the other is the address kept for the session.
const WITH_CAUSE: [(&str, u16, CauseValue, usize); 1] =
    [("7.5.9.1-1", 178, CauseValue::RedirectionRequested, 1)];

/// How many IEs of a row a response with the rejection Cause `cause` may have.
fn with_rejection(table: &str, row: &Row, cause: CauseValue) -> usize {
    if WITH_REJECTION.contains(&row.ie_type) {
        return usize::MAX;
    }
    WITH_CAUSE
        .iter()
        .find(|(id, ie_type, of, _)| *id == table && *ie_type == row.ie_type && *of == cause)
        .map_or(0, |(.., most)| *most)
}

/// The IEs of a row that a message needs on the interface ([`Row::on`]), in the context.
#[inline]
fn mandatory(row: &Row, context: Context) -> usize {
    let needed = row.on(context.interface).map_or(0, |on| on.needed);
    match context.rejected {
        // The Cause and the Node ID follow their rows; the others may be missing.
        Some(_) => needed.min(usize::from(matches!(row.ie_type, 19 | 60))),
        None => needed,
    }
}

/// Check a row that has `count` values, or IEs kept as octets alone when 0: whether the
/// interface has it, whether a rejection may carry it, and whether the table allows that
/// many. Whether the interface has it.
#[inline]
pub(crate) fn check_row(
    table: &'static str,
    row: &Row,
    count: usize,
    path: &Path<'_>,
    context: Context,
    found: &mut Vec<Deviation>,
) -> bool {
    let rejected = context
        .rejected
        .is_some_and(|cause| count.max(1) > with_rejection(table, row, cause));
    let on = row.on(context.interface);
    // The receiver discards each IE of a row that is not on the interface (§7.6.9).
    let off = on.is_none();
    let over = on.is_some_and(|on| !on.most.allows(count));
    if rejected || off || over {
        row_deviations(table, row, [rejected, off, over], path, found);
    }
    !off
}

#[cold]
#[inline(never)]
fn row_deviations(
    table: &'static str,
    row: &Row,
    [rejected, off, over]: [bool; 3],
    path: &Path<'_>,
    found: &mut Vec<Deviation>,
) {
    let here = || Path::Row {
        parent: path,
        row: row.name,
        nth: None,
    };
    if rejected {
        found.push(Deviation::new(
            here(),
            "7.2.3.2",
            DeviationKind::WithRejection {
                ie_type: row.ie_type,
            },
        ));
    }
    if off {
        found.push(Deviation::new(
            here(),
            table,
            DeviationKind::NotOnInterface {
                ie_type: row.ie_type,
            },
        ));
    }
    if over {
        found.push(Deviation::new(
            here(),
            "7.6.10",
            DeviationKind::Repeated {
                ie_type: row.ie_type,
            },
        ));
    }
}

/// Check a scope against its table: its mandatory IEs on the interface, the IEs that it
/// keeps as octets (repeated, incorrect, of no row of the table, of no release), then
/// each row that has values, and each value.
pub(crate) fn check_scope<S: Scope + Checked>(
    scope: &S,
    path: &Path<'_>,
    context: Context,
    found: &mut Vec<Deviation>,
) {
    let table = S::table();
    for row in table.rows {
        let needed = mandatory(row, context);
        if scope.count(row.ie_type) < needed {
            mandatory_missing(scope, row, needed, path, context, found);
        }
    }
    if !scope.raw().is_empty() {
        raw_deviations(scope, path, context, found);
    }
    scope.check_values(path, context, found);
}

/// A mandatory row that has fewer values than it needs: missing, there and incorrect, or
/// there with a null length, which its receiver takes (§8.1.2). Of a row there once, the
/// first IE is the one handled (§7.6.10).
#[cold]
#[inline(never)]
fn mandatory_missing<S: Scope>(
    scope: &S,
    row: &Row,
    needed: usize,
    path: &Path<'_>,
    context: Context,
    found: &mut Vec<Deviation>,
) {
    let mut kept = scope.raw().iter().filter(|ie| ie.ie_type == row.ie_type);
    // An IE of the row that does not frame, or whose IEs do not, is told as such
    // ([`raw_deviations`]).
    if kept
        .clone()
        .any(|ie| !ie.frames() || unframed_within(row, &ie.octets).is_some())
    {
        return;
    }
    let (nulls, incorrect) = match row.is_list() {
        false => match kept.next() {
            Some(ie) if ie.octets.is_empty() => (1, false),
            Some(_) => (0, true),
            None => (0, false),
        },
        _ => kept.fold((0, false), |(nulls, incorrect), ie| {
            match ie.octets.is_empty() {
                true => (nulls + 1, incorrect),
                false => (nulls, incorrect || !scope.decodes(ie.ie_type, &ie.octets)),
            }
        }),
    };
    if scope.count(row.ie_type) + nulls >= needed {
        let kind = DeviationKind::NullLength {
            ie_type: row.ie_type,
        };
        let at = Path::Row {
            parent: path,
            row: row.name,
            nth: None,
        };
        found.push(Deviation::new(at, S::table().id, kind));
        return;
    }
    // Missing where its table has it, or there and incorrect (§7.6.8).
    let (clause, kind) = match incorrect {
        false => (
            S::table().id,
            DeviationKind::MandatoryMissing {
                ie_type: row.ie_type,
            },
        ),
        true => (
            "7.6.8",
            DeviationKind::MandatoryIncorrect {
                ie_type: row.ie_type,
            },
        ),
    };
    let mut deviation = Deviation::new(
        Path::Row {
            parent: path,
            row: row.name,
            nth: None,
        },
        clause,
        kind,
    );
    deviation.cause = context.cause(!incorrect);
    found.push(deviation);
}

/// The IEs that a scope keeps as octets: of no row, repeated (§7.6.10), or incorrect
/// (§7.6.8): a conditional one semantically invalid, an optional one taken as absent. Of a
/// row there once, the first IE is the one handled, and the others are repetitions; an IE
/// of a null length is no error (§8.1.2). A row of kept IEs alone is checked as one of
/// values ([`check_row`]): on the interface, and in a rejection (§7.2.3.2).
#[cold]
#[inline(never)]
fn raw_deviations<S: Scope>(
    scope: &S,
    path: &Path<'_>,
    context: Context,
    found: &mut Vec<Deviation>,
) {
    let table = S::table();
    let raws = scope.raw();
    let positions = crate::table::kept_positions(scope);
    // The rows of the kept IEs met so far: a few, whatever the number of the IEs.
    let mut handled: alloc::collections::BTreeSet<u16> = alloc::collections::BTreeSet::new();
    for (at, ie) in raws.iter().enumerate() {
        let Some(row) = table.row_of(ie.ie_type) else {
            let here = kept_path(scope, &positions, at, path);
            if !ie.frames() {
                found.push(invalid_length(here, ie.ie_type, context));
                continue;
            }
            let (clause, kind) = match ie.ie_type {
                VENDOR.. if ie.enterprise_id.is_none_or(|id| id == 10415) => {
                    ("8.1.1", DeviationKind::VendorId)
                }
                VENDOR.. => continue,
                known if ie_type_info(known).is_some() => {
                    ("7.6.9", DeviationKind::Unexpected { ie_type: known })
                }
                unknown => ("8.1.2", DeviationKind::UnknownType { ie_type: unknown }),
            };
            found.push(Deviation::new(here, clause, kind));
            continue;
        };
        let alone = handled.insert(row.ie_type) && scope.count(row.ie_type) == 0;
        if alone {
            check_row(table.id, row, 0, path, context, found);
        }
        let here = || Path::Row {
            parent: path,
            row: row.name,
            nth: positions[at],
        };
        // One that does not frame, whose receiver frames the IEs after it amiss, of the
        // interface or not
        if !ie.frames() {
            found.push(invalid_length(here(), ie.ie_type, context));
            continue;
        }
        // The receiver discards each IE of a row that is not on the interface, which its
        // row tells (§7.6.9).
        if row.on(context.interface).is_none() {
            continue;
        }
        let first = match row.is_list() {
            false => alone,
            true => !ie.octets.is_empty() && !scope.decodes(ie.ie_type, &ie.octets),
        };
        // A grouped IE that its receiver handles, whose IEs run past it (§7.6.7).
        if let Some(inner) = first.then(|| unframed_within(row, &ie.octets)).flatten() {
            found.push(invalid_length(here(), inner, context));
            continue;
        }
        let deviation = match (first, ie.octets.is_empty()) {
            // A null length says what its row allows it to (§5.6.3).
            (true, true) => continue,
            // An incorrect mandatory IE is reported as such.
            (true, false) if mandatory(row, context) > scope.count(row.ie_type) => continue,
            // One of a mandatory list beyond those that it needs, or a verifiable
            // conditional IE: semantically invalid, as one that decodes and breaks a rule
            // (§7.6.8). An optional one is taken as absent.
            (true, false) => {
                let ie_type = row.ie_type;
                let kind = match presence(row, context) {
                    Presence::Mandatory => DeviationKind::MandatoryIncorrect { ie_type },
                    Presence::Conditional => DeviationKind::ConditionalIncorrect { ie_type },
                    Presence::Optional => DeviationKind::Incorrect { ie_type },
                };
                let mut deviation = Deviation::new(here(), "7.6.8", kind);
                if !matches!(deviation.kind, DeviationKind::Incorrect { .. }) {
                    deviation.cause = context.cause(false);
                }
                deviation
            }
            (false, true) if row.is_list() => continue,
            (false, _) => Deviation::new(
                here(),
                "7.6.10",
                DeviationKind::Repeated {
                    ie_type: row.ie_type,
                },
            ),
        };
        found.push(deviation);
    }
}

/// The IE whose Length runs past the grouped IE of `row` whose content is `octets`
/// (§7.6.7): the first whose Length runs past the others, or the grouped IE itself where
/// fewer octets than an IE header are left. `None` for an IE of another row, and for IEs
/// that frame.
fn unframed_within(row: &Row, octets: &[u8]) -> Option<u16> {
    row.content?;
    crate::framing::ies(octets).find_map(|ie| match ie.err()? {
        crate::ie::IeFault::Length { ie_type, .. } => Some(ie_type),
        crate::ie::IeFault::HeaderCut { .. } => Some(row.ie_type),
    })
}

/// The scope as its receiver reads its octets, which `check()` checks: `None` for a scope
/// that is as they read ([`Scope::plain`]). One whose octets do not decode, as the Length
/// of an IE that it keeps as octets does not frame, has those Lengths told in `found`
/// ([`unframed`]), and is read with them cleared. One that does not encode is taken with
/// them cleared.
pub(crate) fn as_read<S: Scope + Clone>(
    scope: &S,
    path: &Path<'_>,
    context: Context,
    found: &mut Vec<Deviation>,
) -> Option<S> {
    if scope.plain() {
        return None;
    }
    if let Some(read) = crate::table::reread(scope) {
        return Some(read);
    }
    unframed(scope, path, context, found);
    let mut cleared = scope.clone();
    for ie in cleared.raw_mut() {
        ie.length = None;
    }
    Some(crate::table::reread(&cleared).unwrap_or(cleared))
}

/// The IEs that a scope keeps as octets whose Length is not that of their content, which do
/// not frame (§7.6.7), each at its path.
fn unframed<S: Scope>(scope: &S, path: &Path<'_>, context: Context, found: &mut Vec<Deviation>) {
    let positions = crate::table::kept_positions(scope);
    for (at, ie) in scope.raw().iter().enumerate() {
        if !ie.frames() {
            let here = kept_path(scope, &positions, at, path);
            found.push(invalid_length(here, ie.ie_type, context));
        }
    }
}

/// The path of the IE `at` that a scope keeps as octets: at the position of its row, or
/// by its name in the tree and its position among those of its type there.
fn kept_path<S: Scope>(
    scope: &S,
    positions: &[Option<usize>],
    at: usize,
    path: &Path<'_>,
) -> String {
    let (table, raws) = (S::table(), scope.raw());
    let ie = &raws[at];
    if let Some(row) = table.row_of(ie.ie_type) {
        let here = Path::Row {
            parent: path,
            row: row.name,
            nth: positions[at],
        };
        return format!("{here}");
    }
    let name = crate::tree_name(ie.ie_type, Some(table));
    let same = |other: &&crate::ie::RawIe| other.ie_type == ie.ie_type;
    let name = Segment(&name);
    match raws.iter().filter(same).count() {
        1 => format!("{path}/{name}"),
        _ => format!("{path}/{name}/{}", raws[..at].iter().filter(same).count()),
    }
}

/// The deviation of an IE at `path` that does not frame, of `ie_type`.
fn invalid_length(path: impl fmt::Display, ie_type: u16, context: Context) -> Deviation {
    let mut deviation = Deviation::new(path, "7.6.7", DeviationKind::InvalidLength { ie_type });
    deviation.cause = context.invalid_length();
    deviation
}

/// The scope as its receiver takes it, which the conditions of its table read: without
/// the values of the rows of `off`, by their positions, which its interface does not have
/// and which it discards (§7.6.9). `None` for the scope as it is.
#[cold]
pub(crate) fn taken<S: Scope + Clone>(scope: &S, off: u64) -> Option<S> {
    if off == 0 {
        return None;
    }
    let mut taken = scope.clone();
    let rows = S::table().rows.iter().enumerate();
    for (_, row) in rows.filter(|(at, _)| off >> at & 1 == 1) {
        taken.clear(row.ie_type);
    }
    Some(taken)
}

/// Whether each interface of the context has a row, which the condition beside it then
/// needs.
fn on_each(row: &Row, context: Context) -> bool {
    row.on(context.interface)
        .is_some_and(|on| on.presence.is_some())
}

/// A C row that is not there where the condition that its table writes beside it holds
/// (§7.6.6), on the interface: missing, or of a null length (§8.1.2). One that is there
/// and incorrect is answered as such.
pub(crate) fn condition_missing<S: Scope>(
    scope: &S,
    at: usize,
    path: &Path<'_>,
    context: Context,
    found: &mut Vec<Deviation>,
) {
    let table = S::table();
    let row = &table.rows[at];
    let mut kept = scope.raw().iter().filter(|ie| ie.ie_type == row.ie_type);
    let null = match kept.next() {
        _ if scope.count(row.ie_type) > 0 || !on_each(row, context) => return,
        Some(ie) if ie.octets.is_empty() => true,
        Some(_) => return,
        None => false,
    };
    let kind = match null {
        true => DeviationKind::NullLength {
            ie_type: row.ie_type,
        },
        false => DeviationKind::ConditionalMissing {
            ie_type: row.ie_type,
        },
    };
    let mut deviation = Deviation::new(
        Path::Row {
            parent: path,
            row: row.name,
            nth: None,
        },
        table.id,
        kind,
    );
    if !null {
        deviation.cause = context.conditional_cause();
    }
    found.push(deviation);
}

/// A row that is there, on the interface, where the condition that its table writes beside
/// it has it absent: an IE of a null length too.
pub(crate) fn condition_absent<S: Scope>(
    scope: &S,
    at: usize,
    path: &Path<'_>,
    context: Context,
    found: &mut Vec<Deviation>,
) {
    let table = S::table();
    let row = &table.rows[at];
    let there =
        scope.count(row.ie_type) > 0 || scope.raw().iter().any(|ie| ie.ie_type == row.ie_type);
    if !there || row.on(context.interface).is_none() {
        return;
    }
    let at = Path::Row {
        parent: path,
        row: row.name,
        nth: None,
    };
    let kind = DeviationKind::Excluded {
        ie_type: row.ie_type,
    };
    found.push(Deviation::new(at, table.id, kind));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name is written in a path as oxirush-utils' paths read it: `~0` for `~`, `~1` for
    /// `/`, the name of each row and of each IE type among them; within 10 s, as the writing
    /// steps over each `~` and `/`.
    #[test]
    fn a_name_is_a_segment_of_a_path() {
        let segment = |name: &'static str| crate::ends(move || format!("{}", Segment(name)));
        assert_eq!(segment("APN/DNN"), "APN~1DNN");
        assert_eq!(segment("a~/b/"), "a~0~1b~1");
        #[cfg(feature = "tree")]
        {
            let tables = crate::IE_TYPES.iter().flat_map(|info| info.tables.iter());
            let rows = tables.flat_map(|table| table.rows.iter().map(|row| row.name));
            let types = crate::IE_TYPES.iter().map(|info| info.name);
            for name in rows.chain(types) {
                assert_eq!(segment(name), oxirush_utils::tree::escape(name), "{name}");
            }
        }
    }
}
