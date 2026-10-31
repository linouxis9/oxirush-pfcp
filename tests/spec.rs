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

//! The crate against the document that it follows, TS 29.244 V19.6.0: the fixtures of
//! `tests/spec`, which `extract.py` writes from the document, with the errata of
//! `errata.tsv` applied. Every message type, IE type, table and row of clause 7, figure of
//! clause 8.2 and table of values is compared, and each test fails on anything that is
//! missing or different, with the whole list.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use oxirush_pfcp::*;

/// The lines of a fixture, without its comments, as their cells.
fn records(text: &'static str) -> Vec<Vec<&'static str>> {
    text.lines().filter(|line| !line.starts_with('#') && !line.is_empty()).map(|line| line.split('\t').collect()).collect()
}

/// A name in any case, with its letters and digits only.
fn key(name: &str) -> String {
    name.chars().filter(char::is_ascii_alphanumeric).map(|c| c.to_ascii_lowercase()).collect()
}

/// The errata of the document, each applied where it says, once.
struct Errata {
    list: Vec<(&'static str, &'static str, &'static str, &'static str, &'static str)>,
    used: Vec<Cell<bool>>,
}

impl Errata {
    fn new() -> Self {
        let list: Vec<_> = records(include_str!("spec/errata.tsv"))
            .into_iter()
            .map(|cells| (cells[0], cells[1], cells[2], cells[3], cells[4]))
            .collect();
        let used = list.iter().map(|_| Cell::new(false)).collect();
        Self { list, used }
    }

    /// The value that the crate takes where the document says `value`.
    fn apply<'v>(&self, kind: &str, place: &str, value: &'v str) -> &'v str
    where
        'static: 'v,
    {
        for ((_, k, at, document, taken), used) in self.list.iter().zip(&self.used) {
            if *k == kind && *at == place && *document == value {
                used.set(true);
                return taken;
            }
        }
        value
    }

    /// The errata that found nothing to apply to.
    fn unused(&self, kinds: &[&str]) -> Vec<String> {
        self.list
            .iter()
            .zip(&self.used)
            .filter(|((_, kind, ..), used)| kinds.contains(kind) && !used.get())
            .map(|((name, kind, at, document, _), _)| format!("erratum {name}: no {kind} at {at} says {document:?}"))
            .collect()
    }
}

fn interfaces(names: &str) -> Interfaces {
    Interfaces(names.split_whitespace().fold(0, |bits, name| {
        bits | match name {
            "Sxa" => Interfaces::SXA.0,
            "Sxb" => Interfaces::SXB.0,
            "Sxc" => Interfaces::SXC.0,
            "N4" => Interfaces::N4.0,
            "N4mb" => Interfaces::N4MB.0,
            other => panic!("no interface {other}"),
        }
    }))
}

fn presence(letter: &str) -> Presence {
    match letter {
        "M" => Presence::Mandatory,
        "C" => Presence::Conditional,
        "O" => Presence::Optional,
        other => panic!("no presence {other}"),
    }
}

fn report(problems: Vec<String>) {
    assert!(problems.is_empty(), "{} differences from TS 29.244 V19.6.0:\n{}", problems.len(), problems.join("\n"));
}

/// Table 7.3-1: each message type, its name and its interfaces.
#[test]
fn message_types() {
    let errata = Errata::new();
    let mut problems = Vec::new();
    let mut seen = BTreeSet::new();
    for cells in records(include_str!("spec/message-types.tsv")) {
        let value: u8 = cells[0].parse().unwrap();
        seen.insert(value);
        let name = errata.apply("message-name", cells[0], cells[1]);
        let Some(info) = message_type_info(value) else {
            problems.push(format!("message type {value} {name}: not in the crate"));
            continue;
        };
        if info.name() != name {
            problems.push(format!("message type {value}: {:?} in the crate, {name:?} in the document", info.name()));
        }
        if info.interfaces != interfaces(cells[2]) {
            problems.push(format!("message type {value}: interfaces {:?}, {} in the document", info.interfaces, cells[2]));
        }
    }
    for info in MESSAGE_TYPES {
        if !seen.contains(&info.message_type) {
            problems.push(format!("message type {}: not in the document", info.message_type));
        }
    }
    problems.extend(errata.unused(&["message-name"]));
    report(problems);
}

/// Table 8.1.2-1: each IE type, its name, its form, its reference and its length.
#[test]
fn ie_types() {
    let errata = Errata::new();
    let mut problems = Vec::new();
    let mut seen = BTreeSet::new();
    for cells in records(include_str!("spec/ie-types.tsv")) {
        let Ok(ie_type) = cells[0].parse::<u16>() else { continue };
        let name = cells[1];
        if ["reserved", "spare", "can be used"].iter().any(|word| name.to_lowercase().starts_with(word)) {
            if ie_type_info(ie_type).is_some() {
                problems.push(format!("IE type {ie_type}: {name} in the document, and the crate has it"));
            }
            continue;
        }
        seen.insert(ie_type);
        let Some(info) = ie_type_info(ie_type) else {
            problems.push(format!("IE type {ie_type} {name}: not in the crate"));
            continue;
        };
        if info.name != name {
            problems.push(format!("IE type {ie_type}: {:?} in the crate, {name:?} in the document", info.name));
        }
        let reference = errata.apply("ie-type-reference", cells[0], cells[2]);
        let (form, places) = reference.split_once('/').unwrap_or((reference, ""));
        let place = places.split(',').next().unwrap().trim();
        // An IE type of several tables, one for each place, names each of them.
        for other in places.split(',').skip(1).map(str::trim) {
            let table = other.strip_prefix("Table ").unwrap_or(other);
            if !info.tables.iter().any(|known| known.id == table) {
                problems.push(format!("IE type {ie_type} {name}: {other} in the document, and the crate has no such table of it"));
            }
        }
        let (grouped, clause) = match place.split_once(' ') {
            Some(("Table", table)) => (true, table),
            Some(("Clause", clause)) => (false, clause),
            _ => (false, ""),
        };
        let expected = match (grouped, form.split_whitespace().next()) {
            (true, Some("Extendable")) => Some(Form::Grouped),
            (false, Some("Extendable")) => Some(Form::Extendable),
            (false, Some("Fixed")) => Some(Form::Fixed),
            (false, Some("Variable")) => Some(Form::Variable),
            _ => None,
        };
        if expected != Some(info.form) {
            problems.push(format!("IE type {ie_type} {name}: {:?} in the crate, {reference:?} in the document", info.form));
        }
        if info.clause != clause {
            problems.push(format!("IE type {ie_type} {name}: clause {} in the crate, {reference:?} in the document", info.clause));
        }
        let length = errata.apply("ie-type-length", cells[0], cells.get(3).copied().unwrap_or(""));
        let fixed = length.parse::<u16>().ok();
        if info.fixed != fixed {
            problems.push(format!("IE type {ie_type} {name}: length {:?} in the crate, {length:?} in the document", info.fixed));
        }
    }
    for info in IE_TYPES {
        if !seen.contains(&info.ie_type) {
            problems.push(format!("IE type {} {}: not in the document", info.ie_type, info.name));
        }
    }
    problems.extend(errata.unused(&["ie-type-reference", "ie-type-length"]));
    report(problems);
}

/// The IE type of the cell "IE Type" of a row: its name in Table 8.1.2-1, or, for a name
/// that several IE types share with what they add ("Usage Report (Session Report
/// Request)", "TSC Management Information IE within ..."), the one whose table is
/// nearest to the table of the row.
fn ie_type_of(cell: &str, table: &str) -> Option<u16> {
    let names = || IE_TYPES.iter().filter(|info| !info.name.is_empty());
    if let Some(info) = names().find(|info| key(info.name) == key(cell)) {
        return Some(info.ie_type);
    }
    let base = |name: &str| {
        let name = name.split(" (").next().unwrap();
        let cut = [" IE within ", " within ", " in "].iter().filter_map(|word| name.find(word)).min();
        key(&name[..cut.unwrap_or(name.len())])
    };
    let common = |a: &str, b: &str| a.split('.').zip(b.split('.')).take_while(|(x, y)| x == y).count();
    names()
        .filter(|info| base(info.name) == key(cell))
        .max_by_key(|info| common(info.clause.split('-').next().unwrap(), table.split('-').next().unwrap()))
        .map(|info| info.ie_type)
}

/// A table of the document: its title, the IE type that it says, and its rows (name,
/// presence, interfaces, IE type, and whether its comment lets several IEs of it be
/// there).
type DocumentTable = (&'static str, &'static str, Vec<(&'static str, &'static str, &'static str, &'static str, &'static str)>);

/// A row of the crate: the field that has it, its name, presence, interfaces and IE type,
/// and whether a row of the document is it.
type CrateRow = (usize, &'static str, Presence, Interfaces, u16, Cell<bool>);

/// The tables of clause 7: each row, with its name, its presence, its interfaces and its
/// IE type, in the order of the table; a field that rows of one IE type share has them
/// as its roles.
#[test]
fn tables() {
    let errata = Errata::new();
    let mut problems = Vec::new();
    // The tables of the document, after their errata, with the rows of "Same IEs" tables.
    let mut document: BTreeMap<&str, DocumentTable> = BTreeMap::new();
    let mut current = "";
    let mut same = Vec::new();
    for cells in records(include_str!("spec/tables.tsv")) {
        match cells[0] {
            "table" => {
                current = errata.apply("table-number", cells[2], cells[1]);
                if document.insert(current, (cells[2], cells[4], Vec::new())).is_some() {
                    problems.push(format!("Table {current}: twice in the document"));
                }
            }
            "same" => same.push((cells[1], cells[2])),
            _ => {
                let rows = &mut document.get_mut(current).unwrap().2;
                let place = format!("{current}/{}", if cells[2].is_empty() { (rows.len() + 1).to_string() } else { cells[2].into() });
                let name = errata.apply("row-name", &place, cells[2]);
                let place = format!("{current}/{}", if name.is_empty() { (rows.len() + 1).to_string() } else { name.into() });
                let numbered = format!("{current}/{}", rows.len() + 1);
                let ie_type = errata.apply("row-ie-type", &place, errata.apply("row-ie-type", &numbered, cells[5]));
                let interfaces = errata.apply("row-interfaces", &place, cells[4]);
                let several = errata.apply("row-repeat", &place, cells[6]);
                rows.push((name, cells[3], interfaces, ie_type, several));
            }
        }
    }
    for (table, like) in same {
        let rows = document[like].2.clone();
        document.get_mut(table).unwrap().2 = rows;
    }
    let crate_tables: BTreeMap<&str, &Table> = MESSAGE_TYPES
        .iter()
        .map(|info| info.table)
        .chain(IE_TYPES.iter().flat_map(|info| info.tables.iter().copied()))
        .map(|table| (table.id, table))
        .collect();
    for (id, table) in &crate_tables {
        // Version Not Supported Response has no IE and no table: its clause stands for one.
        let clause_only = table.rows.is_empty() && !id.contains('-');
        if !document.contains_key(id) && !clause_only {
            problems.push(format!("Table {id} {}: not in the document", table.name));
        }
    }
    let messages: BTreeMap<&str, u8> = MESSAGE_TYPES.iter().map(|info| (info.table.id, info.message_type)).collect();
    for (id, (title, ie_type, rows)) in &document {
        let Some(table) = crate_tables.get(id) else {
            problems.push(format!("Table {id} {title}: not in the crate"));
            continue;
        };
        // A table of a grouped IE says its type; that of a message ends with its name.
        match (ie_type.parse::<u16>(), messages.get(id)) {
            (Ok(ie_type), None) if ie_type == table.code => {}
            (Err(_), Some(_)) if key(title).ends_with(&key(table.name.trim_start_matches("PFCP "))) => {}
            _ => problems.push(format!("Table {id} {title} (IE type {ie_type:?}): {} {} in the crate", table.code, table.name)),
        }
        // The rows of the crate, a role each, with the field that has it.
        let mut entries: Vec<CrateRow> = Vec::new();
        for (field, row) in table.rows.iter().enumerate() {
            if row.roles.is_empty() {
                entries.push((field, row.name, row.presence, row.interfaces, row.ie_type, Cell::new(false)));
            }
            for role in row.roles {
                entries.push((field, role.name, role.presence, role.interfaces, row.ie_type, Cell::new(false)));
            }
        }
        let mut first_of_field = vec![usize::MAX; table.rows.len()];
        for (at, (name, p, ifs, ie_type, several)) in rows.iter().enumerate() {
            let Some(entry) = entries.iter().find(|entry| !entry.5.get() && entry.1 == *name) else {
                problems.push(format!("Table {id}, row {name:?}: not in the crate"));
                continue;
            };
            entry.5.set(true);
            first_of_field[entry.0] = first_of_field[entry.0].min(at);
            if entry.2 != presence(p) {
                problems.push(format!("Table {id}, row {name:?}: {:?} in the crate, {p} in the document", entry.2));
            }
            if entry.3 != interfaces(ifs) {
                problems.push(format!("Table {id}, row {name:?}: interfaces {:?} in the crate, {ifs:?} in the document", entry.3));
            }
            // A field that rows share is a list of their IEs; another is a list where its
            // comment lets several IEs be there.
            let field = &table.rows[entry.0];
            if field.roles.is_empty() && (field.repeat != Repeat::Once) != (*several == "several") {
                problems.push(format!("Table {id}, row {name:?}: {:?} in the crate, {several} in the document", field.repeat));
            }
            match ie_type_of(ie_type, id) {
                Some(number) if number == entry.4 => {}
                found => problems.push(format!(
                    "Table {id}, row {name:?}: IE type {} in the crate, {ie_type:?} ({found:?}) in the document",
                    entry.4
                )),
            }
        }
        for entry in entries.iter().filter(|entry| !entry.5.get()) {
            problems.push(format!("Table {id}, row {:?}: not in the document", entry.1));
        }
        let found: Vec<usize> = first_of_field.into_iter().filter(|at| *at != usize::MAX).collect();
        if !found.windows(2).all(|pair| pair[0] <= pair[1]) {
            problems.push(format!("Table {id}: the fields are not in the order of the table"));
        }
    }
    problems.extend(errata.unused(&["table-number", "row-name", "row-ie-type", "row-interfaces", "row-repeat"]));
    report(problems);
}

/// An enumeration of the crate: its tables, the values that they name, and those that
/// they reserve.
type Enumeration = (&'static str, &'static [(u8, &'static str)], &'static [u8]);

/// The tables of clause 8.2 that name values: each is an enumeration of the crate with
/// the same values and names; and those of bits name flags of their IE type.
#[test]
fn value_tables() {
    let enumerations: &[Enumeration] = &[
        (CauseValue::TABLE, CauseValue::NAMES, CauseValue::RESERVED),
        (SourceInterfaceValue::TABLE, SourceInterfaceValue::NAMES, SourceInterfaceValue::RESERVED),
        (Gate::TABLE, Gate::NAMES, Gate::RESERVED),
        (RedirectAddressType::TABLE, RedirectAddressType::NAMES, RedirectAddressType::RESERVED),
        (DestinationInterfaceValue::TABLE, DestinationInterfaceValue::NAMES, DestinationInterfaceValue::RESERVED),
        (TimerUnit::TABLE, TimerUnit::NAMES, TimerUnit::RESERVED),
        (NodeIdType::TABLE, NodeIdType::NAMES, NodeIdType::RESERVED),
        (NodeType::TABLE, NodeType::NAMES, NodeType::RESERVED),
        (FlowDirection::TABLE, FlowDirection::NAMES, FlowDirection::RESERVED),
        (TimeUnit::TABLE, TimeUnit::NAMES, TimeUnit::RESERVED),
        (OuterHeaderRemovalDescription::TABLE, OuterHeaderRemovalDescription::NAMES, OuterHeaderRemovalDescription::RESERVED),
        (HeaderType::TABLE, HeaderType::NAMES, HeaderType::RESERVED),
        (PdnTypeValue::TABLE, PdnTypeValue::NAMES, PdnTypeValue::RESERVED),
        (RuleIdType::TABLE, RuleIdType::NAMES, RuleIdType::RESERVED),
        (BaseTimeIntervalType::TABLE, BaseTimeIntervalType::NAMES, BaseTimeIntervalType::RESERVED),
        (InterfaceTypeValue::TABLE, InterfaceTypeValue::NAMES, InterfaceTypeValue::RESERVED),
        (SteeringFunctionalityValue::TABLE, SteeringFunctionalityValue::NAMES, SteeringFunctionalityValue::RESERVED),
        (SteeringModeValue::TABLE, SteeringModeValue::NAMES, SteeringModeValue::RESERVED),
        (PriorityValue::TABLE, PriorityValue::NAMES, PriorityValue::RESERVED),
        (AccessType::TABLE, AccessType::NAMES, AccessType::RESERVED),
        (AvailabilityStatus::TABLE, AvailabilityStatus::NAMES, AvailabilityStatus::RESERVED),
        (RatTypeValue::TABLE, RatTypeValue::NAMES, RatTypeValue::RESERVED),
        (TransportModeValue::TABLE, TransportModeValue::NAMES, TransportModeValue::RESERVED),
        (ReportingUrgencyValue::TABLE, ReportingUrgencyValue::NAMES, ReportingUrgencyValue::RESERVED),
        (MediaTransportProtocolValue::TABLE, MediaTransportProtocolValue::NAMES, MediaTransportProtocolValue::RESERVED),
        (RtpHeaderExtensionTypeValue::TABLE, RtpHeaderExtensionTypeValue::NAMES, RtpHeaderExtensionTypeValue::RESERVED),
        (PayloadFormat::TABLE, PayloadFormat::NAMES, PayloadFormat::RESERVED),
        (FormatField::TABLE, FormatField::NAMES, FormatField::RESERVED),
        (JobType::TABLE, JobType::NAMES, JobType::RESERVED),
        (MeasurementType::TABLE, MeasurementType::NAMES, MeasurementType::RESERVED),
        (ActionValue::TABLE, ActionValue::NAMES, ActionValue::RESERVED),
        (ConditionValue::TABLE, ConditionValue::NAMES, ConditionValue::RESERVED),
        (SignalingMethod::TABLE, SignalingMethod::NAMES, SignalingMethod::RESERVED),
        (FailureCause::TABLE, FailureCause::NAMES, FailureCause::RESERVED),
        (TransferringMethod::TABLE, TransferringMethod::NAMES, TransferringMethod::RESERVED),
        (RemainingDataReportingIndicationValue::TABLE, RemainingDataReportingIndicationValue::NAMES, RemainingDataReportingIndicationValue::RESERVED),
    ];
    let mut document: BTreeMap<&str, Vec<(&str, &str)>> = BTreeMap::new();
    for cells in records(include_str!("spec/value-tables.tsv")) {
        document.entry(cells[0]).or_default().push((cells[2], cells[3]));
    }
    let mut problems = Vec::new();
    let mut covered = BTreeSet::new();
    for (tables, names, reserved) in enumerations {
        for table in tables.split(" and ") {
            let table = table.strip_prefix("Table ").unwrap();
            covered.insert(table);
            let Some(rows) = document.get(table) else {
                problems.push(format!("Table {table}: not in the document"));
                continue;
            };
            let rows: Vec<(u8, &str)> = rows.iter().map(|(value, name)| (value.parse().unwrap(), *name)).collect();
            let named: Vec<(u8, &str)> = rows.iter().filter(|(_, name)| *name != "<reserved>").copied().collect();
            let kept: Vec<u8> = rows.iter().filter(|(_, name)| *name == "<reserved>").map(|(value, _)| *value).collect();
            if named != *names {
                problems.push(format!("Table {table}: {names:?} in the crate, {named:?} in the document"));
            }
            if kept != *reserved {
                problems.push(format!("Table {table}: reserved {reserved:?} in the crate, {kept:?} in the document"));
            }
        }
    }
    for (table, rows) in &document {
        if covered.contains(table) {
            continue;
        }
        // A table of bits names flags of the IE type of its clause.
        let clause = table.split(['-', '.']).take(3).collect::<Vec<_>>().join(".");
        let Some(info) = IE_TYPES.iter().find(|info| info.clause == clause) else {
            problems.push(format!("Table {table}: no IE type of clause {clause} in the crate"));
            continue;
        };
        if !rows.iter().all(|(bit, _)| bit.contains('/')) {
            problems.push(format!("Table {table}: no enumeration in the crate"));
            continue;
        }
        for (bit, name) in rows {
            if !info.fields.iter().any(|field| key(field) == key(name)) {
                problems.push(format!("Table {table}, bit {bit} {name:?}: no flag of {} in the crate", info.name));
            }
        }
    }
    report(problems);
}

/// The names of a figure that a field of the crate stands for, and whether it was found.
type Mapped = (Vec<&'static str>, Cell<bool>);

/// The figures of clause 8.2: each flag and field of a figure is one of the IE type in the
/// crate, by its name, and each of the crate is in the figure; `fields.tsv` says where a
/// field of the crate stands for several names of the figure, and which names a table of
/// bits stands for, whose bits are flags of the crate (as `value_tables` checks).
#[test]
fn layouts() {
    let errata = Errata::new();
    let mut mapping: BTreeMap<(&str, &str), Mapped> = BTreeMap::new();
    for cells in records(include_str!("spec/fields.tsv")) {
        let names = cells[2].split(" | ").filter(|name| !name.is_empty()).collect();
        if mapping.insert((cells[0], cells[1]), (names, Cell::new(false))).is_some() {
            panic!("fields.tsv: {} {} twice", cells[0], cells[1]);
        }
    }
    let mut figures: BTreeMap<&str, (Vec<&str>, Vec<&str>)> = BTreeMap::new();
    for cells in records(include_str!("spec/layouts.tsv")) {
        let entry = figures.entry(cells[0]).or_default();
        entry.0.push(errata.apply("figure-type", cells[0], cells[1]));
        for name in cells.get(2).map_or("", |names| names).split(" | ").filter(|name| !name.is_empty()) {
            entry.1.push(errata.apply("figure-field", cells[0], name));
        }
    }
    // The bits that the tables of bits of each clause name.
    let mut bits: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for cells in records(include_str!("spec/value-tables.tsv")) {
        if cells[2].contains('/') {
            let clause = cells[0].split(['-', '.']).take(3).collect::<Vec<_>>().join(".");
            bits.entry(clause).or_default().push(cells[3]);
        }
    }
    let mut problems = Vec::new();
    for info in IE_TYPES.iter().filter(|info| info.tables.is_empty()) {
        let Some((types, names)) = figures.remove(info.clause) else {
            problems.push(format!("IE type {} {}: no figure of clause {} in the document", info.ie_type, info.name, info.clause));
            continue;
        };
        if types.iter().any(|ie_type| ie_type.parse() != Ok(info.ie_type)) {
            problems.push(format!("clause {}: the figure has type {types:?}, and the crate {}", info.clause, info.ie_type));
        }
        let covered: Vec<Cell<bool>> = names.iter().map(|_| Cell::new(false)).collect();
        let cover = |name: &str| match names.iter().zip(&covered).find(|(known, used)| !used.get() && key(known) == key(name)) {
            Some((_, used)) => {
                used.set(true);
                true
            }
            None => false,
        };
        let table_bits = bits.get(info.clause).map(Vec::as_slice).unwrap_or_default();
        let fields = info
            .fields
            .iter()
            .filter(|field| !field.starts_with("Spare") && !table_bits.iter().any(|bit| key(bit) == key(field)))
            .copied();
        for field in fields.chain(core::iter::once("*")) {
            let listed = mapping.get(&(info.clause, field));
            if let Some((_, used)) = listed {
                used.set(true);
            }
            let wanted = match listed {
                Some((names, _)) => names.clone(),
                None if field == "*" => Vec::new(),
                None => vec![field],
            };
            for name in wanted {
                if !cover(name) {
                    problems.push(format!("clause {} {}: {field:?} is {name:?}, which the figure does not have", info.clause, info.name));
                }
            }
        }
        for (name, used) in names.iter().zip(&covered) {
            if !used.get() {
                problems.push(format!("clause {} {}: {name:?} of the figure is no field of the crate", info.clause, info.name));
            }
        }
    }
    for (clause, (types, _)) in figures {
        problems.push(format!("clause {clause}: a figure of type {types:?} that no IE type of the crate has"));
    }
    for ((clause, field), (_, used)) in &mapping {
        if !used.get() {
            problems.push(format!("fields.tsv: {clause} {field} is no field of the crate"));
        }
    }
    problems.extend(errata.unused(&["figure-type", "figure-field"]));
    report(problems);
}

/// The requirements of clause 6: each heading of the clause has its rows in
/// `requirements.tsv`, one for each sentence that says "shall" or "should", and each row
/// says what checks it; a test that it names exists.
#[test]
fn requirements() {
    let headings: Vec<(&str, usize)> = records(include_str!("spec/clause-6.tsv"))
        .into_iter()
        .map(|cells| (cells[0], cells[2].parse().unwrap()))
        .collect();
    let mut rows: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    let mut problems = Vec::new();
    let sources = test_sources();
    for cells in records(include_str!("spec/requirements.tsv")) {
        let [clause, n, requirement, by] = cells[..] else {
            problems.push(format!("requirements.tsv: {cells:?} has not four cells"));
            continue;
        };
        rows.entry(clause).or_default().push(n.parse().unwrap());
        if requirement.is_empty() {
            problems.push(format!("requirement {clause}/{n}: no text"));
        }
        match by.split_once(' ') {
            Some(("test", name)) if sources.iter().any(|source| source.contains(&format!("fn {name}("))) => {}
            Some(("test", name)) => problems.push(format!("requirement {clause}/{n}: no test {name}")),
            Some(("planned", name)) if name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') => {}
            Some(("application:" | "informative:", reason)) if !reason.is_empty() => {}
            _ => problems.push(format!("requirement {clause}/{n}: {by:?} says nothing that checks it")),
        }
    }
    for (clause, count) in &headings {
        let expected: Vec<usize> = if *count == 0 { vec![0] } else { (1..=*count).collect() };
        match rows.remove(clause) {
            Some(found) if found == expected => {}
            found => problems.push(format!("clause {clause}: rows {found:?}, and the document has {count} requirements")),
        }
    }
    for clause in rows.keys() {
        problems.push(format!("requirements.tsv: clause {clause} is no heading of clause 6"));
    }
    report(problems);
}

/// The sources of the tests of the crate: its tests and its modules.
fn test_sources() -> Vec<String> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = Vec::new();
    let mut directories = vec![root.join("tests"), root.join("src")];
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                directories.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                sources.push(std::fs::read_to_string(path).unwrap());
            }
        }
    }
    sources
}

/// The interfaces on which each table is: of a message, the Appl. columns of Table 7.3-1;
/// of a grouped IE, those of the rows of its type, on which their scopes are.
fn applicable() -> BTreeMap<&'static str, Interfaces> {
    let mut on: BTreeMap<&'static str, Interfaces> = MESSAGE_TYPES.iter().map(|info| (info.table.id, info.interfaces)).collect();
    let tables: Vec<&'static Table> = MESSAGE_TYPES.iter().map(|info| info.table).chain(IE_TYPES.iter().flat_map(|info| info.tables.iter().copied())).collect();
    loop {
        let mut changed = false;
        for table in &tables {
            let Some(&scope) = on.get(table.id) else { continue };
            for row in table.rows {
                let Some(info) = ie_type_info(row.ie_type) else { continue };
                for inner in info.tables {
                    let here = on.entry(inner.id).or_insert(Interfaces(0));
                    let more = Interfaces(here.0 | (scope.0 & row.interfaces.0));
                    if more != *here {
                        *here = more;
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            return on;
        }
    }
}

/// A table whose mandatory IEs differ between the interfaces that it is on has a
/// constructor for each of them, and the others one `new()` (§4, the Appl. columns).
#[test]
fn constructors_by_interface() {
    let mut problems = Vec::new();
    let on = applicable();
    let tables: Vec<&'static Table> = MESSAGE_TYPES.iter().map(|info| info.table).chain(IE_TYPES.iter().flat_map(|info| info.tables.iter().copied())).collect();
    for table in tables {
        let scope = on.get(table.id).copied().unwrap_or(Interfaces(0));
        let each: Vec<Interfaces> = [Interfaces::SXA, Interfaces::SXB, Interfaces::SXC, Interfaces::N4, Interfaces::N4MB].into_iter().filter(|interface| scope.has(*interface)).collect();
        let mandatory = |interface: Interfaces| -> Vec<&str> {
            table.rows.iter().filter(|row| row.presence == Presence::Mandatory && row.interfaces.has(interface)).map(|row| row.name).collect()
        };
        let differ = each.windows(2).any(|pair| mandatory(pair[0]) != mandatory(pair[1]));
        let expected = if differ { scope } else { Interfaces(0) };
        if table.constructors != expected {
            problems.push(format!("{} {}: constructors {:?}, and its interfaces {:?} need {:?}", table.id, table.name, table.constructors, scope, expected));
        }
    }
    report(problems);
}

/// How many octets a row of a figure has, by its label: `6 to 9`, `m to (m+3)`, `6-11`,
/// one octet `q`; `None` for a length that the IE gives.
fn octets_of_label(label: &str) -> Option<usize> {
    let label = label.replace(' ', "");
    if let Some((from, to)) = label.split_once("to").or_else(|| label.split_once('-')) {
        if let (Ok(from), Ok(to)) = (from.parse::<usize>(), to.parse::<usize>()) {
            return Some(to + 1 - from);
        }
        let to = to.strip_prefix('(').and_then(|to| to.strip_suffix(')'))?;
        let (base, more) = to.split_once('+')?;
        return (base == from).then(|| more.parse::<usize>().ok().map(|more| more + 1)).flatten();
    }
    (label.parse::<usize>().is_ok() || label.chars().all(|c| c.is_ascii_lowercase()) && label.len() == 1).then_some(1)
}

/// The figures of clause 8.2, place by place: each field of bits of the crate has the
/// octet, the lowest bit and the bits of its cell in the figure, or the octet and the bit
/// of its line in a table of bits of its clause; each field of octets of a fixed number
/// has as many as its row of the figure; and the fields of octets come in the order of
/// the rows of the figure.
#[test]
fn figure_places() {
    let errata = Errata::new();
    let mut places: BTreeMap<&str, Vec<(&str, &str, u8, u8)>> = BTreeMap::new();
    for cells in records(include_str!("spec/figures.tsv")) {
        let name = errata.apply("figure-field", cells[0], cells[2]);
        let octets = errata.apply("figure-octets", &format!("{}/{}", cells[0], cells[1]), cells[1]);
        places.entry(cells[0]).or_default().push((octets, name, cells[3].parse().unwrap(), cells[4].parse().unwrap()));
    }
    let mut table_bits: BTreeMap<String, Vec<(usize, u8, &str)>> = BTreeMap::new();
    for cells in records(include_str!("spec/value-tables.tsv")) {
        if let Some((octet, bit)) = cells[2].split_once('/') {
            let clause = cells[0].split(['-', '.']).take(3).collect::<Vec<_>>().join(".");
            table_bits.entry(clause).or_default().push((octet.parse().unwrap(), bit.parse().unwrap(), cells[3]));
        }
    }
    let mut mapped: BTreeMap<(&str, &str), Vec<&str>> = BTreeMap::new();
    for cells in records(include_str!("spec/fields.tsv")) {
        mapped.insert((cells[0], cells[1]), cells[2].split(" | ").collect());
    }
    let mut problems = Vec::new();
    let mut checked = 0;
    for info in IE_TYPES {
        let Some(layout) = info.layout else { continue };
        let figure = places.get(info.clause).map(Vec::as_slice).unwrap_or_default();
        // Each field of bits
        let mut names: Vec<&str> = layout.bits.iter().map(|bits| bits.name).collect();
        names.dedup();
        for name in names {
            let crate_places: Vec<(String, u8, u8)> = layout.bits.iter().filter(|bits| bits.name == name).map(|bits| ((bits.octet + 5).to_string(), bits.bit, bits.width)).collect();
            // The cells of bits are in rows of one octet; a field of octets of the same name
            // is another.
            let in_figure: Vec<(String, u8, u8)> = figure
                .iter()
                .filter(|(octets, known, _, width)| key(known) == key(name) && (*width < 8 || octets_of_label(octets) == Some(1)))
                .map(|(octets, _, bit, width)| (octets.to_string(), *bit, *width))
                .collect();
            let in_table: Vec<(String, u8, u8)> = table_bits
                .get(info.clause)
                .into_iter()
                .flatten()
                .filter(|(_, _, known)| key(known) == key(name))
                .map(|(octet, bit, _)| (octet.to_string(), *bit, 1))
                .collect();
            let document = if in_figure.is_empty() { in_table } else { in_figure };
            checked += 1;
            if document.is_empty() {
                problems.push(format!("clause {} {}: {name:?} is in no cell of the figure, nor in a table of bits", info.clause, info.name));
            } else if document != crate_places {
                problems.push(format!("clause {} {}: {name:?} at (octet, bit, bits) {crate_places:?} in the crate, {document:?} in the document", info.clause, info.name));
            }
        }
        // Each field of octets: its octets, and its order
        let mut last = 0;
        for member in layout.head.iter().chain(layout.fields) {
            let wanted: Vec<&str> = mapped.get(&(info.clause, member.name)).cloned().unwrap_or_else(|| vec![member.name]);
            let Some(row) = figure.iter().position(|(_, known, _, width)| *width == 8 && wanted.iter().any(|name| key(known) == key(name))) else { continue };
            checked += 1;
            if row < last {
                problems.push(format!("clause {} {}: {:?} comes before a field that the figure has before it", info.clause, info.name, member.name));
            }
            last = row;
            let (label, _, _, width) = figure[row];
            if let (Some(octets), Some(rows), 8, true) = (member.octets, octets_of_label(label), width, wanted.len() == 1)
                && octets != rows
            {
                problems.push(format!("clause {} {}: {:?} has {octets} octets in the crate, and its row {label:?}", info.clause, info.name, member.name));
            }
        }
    }
    problems.extend(errata.unused(&["figure-octets"]));
    report(problems);
    assert!(checked > 800, "{checked} places checked");
}

/// The conditions of the fields of clause 8.2: each sentence that makes a field there, or
/// not, as a flag is set or not (`conditions.tsv`) is a term of the condition of the
/// field in the crate, of the same sense: "If CH is set, the TEID shall not be present"
/// is `!ch` in the condition of TEID.
#[test]
fn figure_conditions() {
    let errata = Errata::new();
    let mut sentences: BTreeMap<&str, Vec<(&str, &str, &str, &str)>> = BTreeMap::new();
    for cells in records(include_str!("spec/conditions.tsv")) {
        sentences.entry(cells[0]).or_default().push((cells[1], cells[2], cells[3], cells[4]));
    }
    let mut labels: BTreeMap<(&str, String), &str> = BTreeMap::new();
    for cells in records(include_str!("spec/figures.tsv")) {
        labels.insert((cells[0], key(cells[1])), cells[2]);
    }
    let mut mapped: BTreeMap<&str, Vec<(&str, Vec<&str>)>> = BTreeMap::new();
    for cells in records(include_str!("spec/fields.tsv")) {
        mapped.entry(cells[0]).or_default().push((cells[1], cells[2].split(" | ").collect()));
    }
    let mut problems = Vec::new();
    let mut checked = 0;
    for info in IE_TYPES {
        let Some(layout) = info.layout else { continue };
        for (flag, set, field, there) in sentences.get(info.clause).into_iter().flatten() {
            let Some(bits) = layout.bits.iter().find(|bits| key(bits.name) == key(flag)) else { continue };
            // The field by its name, by the name in brackets of its octets, by the label of
            // its octets, or by a name of the figure that it stands for
            let named = field.split_once('(').and_then(|(_, rest)| rest.strip_suffix(')')).unwrap_or(field);
            let label = field.strip_prefix("Octets ").or_else(|| field.strip_prefix("Octet ")).map(|label| key(label.trim_matches('"')));
            let by_label = label.and_then(|label| labels.get(&(info.clause, label)).copied());
            let member = layout.fields.iter().find(|member| {
                let names = mapped.get(info.clause).into_iter().flatten().find(|(name, _)| *name == member.name).map(|(_, names)| names.clone()).unwrap_or_default();
                [named, by_label.unwrap_or("\0")].iter().any(|name| key(member.name) == key(name) || names.iter().any(|known| key(known) == key(name)))
            });
            let Some(member) = member else { continue };
            let positive = (*set == "set") == (*there == "present");
            let term = if positive { bits.ident.to_string() } else { format!("!{}", bits.ident) };
            let terms: Vec<String> = member.condition.replace(' ', "").split(['&', '|', '(', ')']).filter(|term| !term.is_empty()).map(String::from).collect();
            checked += 1;
            let sense = errata.apply("condition", &format!("{}/{}", info.clause, member.name), &term);
            if !terms.iter().any(|known| *known == sense) {
                problems.push(format!("clause {} {}: {:?} is there `if {}`, and the document has it {there} where {flag} is {set}", info.clause, info.name, member.name, member.condition));
            }
        }
    }
    problems.extend(errata.unused(&["condition"]));
    report(problems);
    assert!(checked >= 150, "{checked} conditions checked");
}

/// The errata that no fixture holds as the document has them, each checked for what it
/// says: the table of a caption is found, the figures of the clauses of a heading without
/// its style are found, and the row whose comment names another table is of the table
/// that the erratum gives.
#[test]
fn notes() {
    let mut problems = Vec::new();
    let tables: BTreeSet<&str> = records(include_str!("spec/tables.tsv")).into_iter().filter(|cells| cells[0] == "table").map(|cells| cells[1]).collect();
    let figures: BTreeSet<&str> = records(include_str!("spec/layouts.tsv")).into_iter().map(|cells| cells[0]).collect();
    let mut checked = 0;
    for cells in records(include_str!("spec/errata.tsv")) {
        let (name, kind, at, crate_has) = (cells[0], cells[1], cells[2], cells[4]);
        match kind {
            "table-caption" => {
                if !tables.contains(at) {
                    problems.push(format!("erratum {name}: no table {at} in the fixtures"));
                }
            }
            "heading" => {
                for clause in at.split_whitespace() {
                    if !figures.contains(clause) {
                        problems.push(format!("erratum {name}: no figure of clause {clause} in the fixtures"));
                    }
                }
            }
            "row-table" => {
                let (table, row) = at.split_once('/').unwrap();
                let rows = MESSAGE_TYPES.iter().map(|info| info.table).find(|known| known.id == table).map_or(&[][..], |known| known.rows);
                let of = rows.iter().find(|known| known.name == row).and_then(|known| ie_type_info(known.ie_type)).map(|info| info.clause);
                if of != crate_has.strip_prefix("Table ") {
                    problems.push(format!("erratum {name}: the row {row} of Table {table} is of {of:?} in the crate"));
                }
            }
            _ => continue,
        }
        checked += 1;
    }
    assert_eq!(checked, 4);
    report(problems);
}
