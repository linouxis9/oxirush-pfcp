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

//! go-pfcp beside the crate, on the messages of a corpus. tests/go-pfcp/ reads each message
//! with go-pfcp, and the test compares what it read with what the crate reads:
//!
//! - `message`: the message that one decodes and the other refuses;
//! - `framing`: the IEs of the message, and of each grouped IE that both read as grouped,
//!   by their type, Length and Enterprise ID, in their order, and where they stop framing;
//! - `grouped`: an IE that one reads as grouped and the other as a value;
//! - `value`: the value of an IE that one decodes and the other does not, or of a type
//!   that one has and the other does not;
//! - `told`: a message that both read and of which check() tells a deviation that its
//!   receiver answers with a Cause, by the kind of the deviation.
//!
//! Each difference is one of the rows of tests/go-pfcp-differences.tsv, which says which
//! side the specification supports, and why. A message, a scope or a value that go-pfcp
//! refuses by a panic is refused, whatever the crate reads, and is no difference.
//!
//! ```sh
//! python3 tests/go-pfcp/corpus.py /tmp/corpus.tsv fuzz/seeds/messages /tmp/vectors.tsv
//! (cd tests/go-pfcp && go build -o /tmp/go-pfcp .) && /tmp/go-pfcp < /tmp/corpus.tsv > /tmp/readings.jsonl
//! PFCP_GO_CORPUS=/tmp/corpus.tsv PFCP_GO_READINGS=/tmp/readings.jsonl \
//!     cargo test --release --all-features --test go_pfcp -- --ignored --nocapture
//! ```

use oxirush_pfcp::framing::{self, IeSlice};
use oxirush_pfcp::{Form, IeFault, Interfaces, Message, VENDOR, ie_type_info, message_type_info};
use serde_json::Value;
use std::collections::BTreeMap;

/// A difference: what it is about, the IE type or `message` that it is of, and what each
/// side reads.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Difference {
    aspect: &'static str,
    subject: String,
    ours: String,
    theirs: String,
    /// The octets of the value that differs, which the report prints of its first case.
    octets: String,
}

/// A row of tests/go-pfcp-differences.tsv: a difference, its clause, the side that the
/// specification supports (`crate`, `go-pfcp`, `both` or `neither`) and why. A subject `*`
/// is any, and `>=N` an IE type of N or above.
struct Row {
    aspect: String,
    subject: String,
    ours: String,
    theirs: String,
    clause: String,
    side: String,
}

fn rows() -> Vec<Row> {
    let text = include_str!("go-pfcp-differences.tsv");
    let lines = text
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty());
    lines
        .map(|line| {
            let fields: Vec<&str> = line.split('\t').collect();
            assert_eq!(fields.len(), 7, "a row of seven fields: {line}");
            Row {
                aspect: fields[0].into(),
                subject: fields[1].into(),
                ours: fields[2].into(),
                theirs: fields[3].into(),
                clause: fields[4].into(),
                side: fields[5].into(),
            }
        })
        .collect()
}

impl Row {
    fn matches(&self, difference: &Difference) -> bool {
        let from = |least: &str| {
            let (least, subject) = (least.parse::<u16>(), difference.subject.parse::<u16>());
            matches!((least, subject), (Ok(least), Ok(subject)) if subject >= least)
        };
        let subject = match self.subject.strip_prefix(">=") {
            Some(least) => from(least),
            None => self.subject == "*" || self.subject == difference.subject,
        };
        self.aspect == difference.aspect
            && subject
            && self.ours == difference.ours
            && self.theirs == difference.theirs
    }
}

/// Whether go-pfcp refused the octets by a panic, which tests/go-pfcp/ catches and gives
/// as its error.
fn panicked(error: &str) -> bool {
    error.starts_with("panic: ")
}

/// An error of go-pfcp without its numbers, which name the octets of one message.
fn go_error(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        match c {
            '0'..='9' if out.ends_with('N') => {}
            '0'..='9' => out.push('N'),
            c => out.push(c),
        }
    }
    out
}

/// The name of a variant of an enum, as `{:?}` writes it.
fn variant(value: &impl core::fmt::Debug) -> String {
    let text = format!("{value:?}");
    let end = text.find([' ', '{', '(']).unwrap_or(text.len());
    text[..end].to_string()
}

/// Compare the IEs of a scope, `message` or a `grouped IE`, and, where `ends`, where they
/// stop framing. Where both stop at the same IE, the reasons are not compared. go-pfcp
/// stops a scope at a grouped IE whose own IEs do not frame, which the crate keeps as
/// octets and reads on after: that is told at the scope where the crate reads on.
fn compare_ies(
    scope: &str,
    ours: framing::Ies<'_>,
    theirs: &[Value],
    their_fault: Option<&str>,
    ends: bool,
    found: &mut Vec<Difference>,
) {
    let mut framed = Vec::new();
    let mut fault = None;
    for ie in ours {
        match ie {
            Ok(ie) => framed.push(ie),
            Err(error) => {
                fault = Some(error);
                break;
            }
        }
    }
    let framing = |ours: &str, theirs: &str| Difference {
        aspect: "framing",
        subject: scope.into(),
        ours: ours.into(),
        theirs: theirs.into(),
        octets: String::new(),
    };
    let common = framed.len().min(theirs.len());
    for (ours, theirs) in framed.iter().zip(theirs) {
        let their_ie = (
            theirs["type"].as_u64().unwrap() as u16,
            theirs["length"].as_u64().unwrap() as u16,
            theirs["enterprise_id"].as_u64().map(|id| id as u16),
        );
        let our_ie = (ours.ie_type, ours.length, ours.enterprise_id);
        if our_ie != their_ie {
            return found.push(framing(&format!("{our_ie:?}"), &format!("{their_ie:?}")));
        }
        compare_ie(ours, theirs, found);
    }
    if !ends {
        return;
    }
    let (more, their_more) = (framed.len() > common, theirs.len() > common);
    // go-pfcp stopped the scope at its last IE, a grouped one whose IEs do not frame
    let within = their_fault.is_some()
        && !their_more
        && theirs.last().is_some_and(|last| last["fault"].is_string());
    let difference = match (more, their_more, their_fault) {
        (false, false, _) => None,
        (true, false, Some(_)) if within => Some((
            "frames another IE",
            "stops after a grouped IE whose IEs do not frame",
        )),
        (true, false, Some(fault)) if panicked(fault) => None,
        (true, false, Some(fault)) => {
            let next = framed[common];
            let short = next.ie_type >= VENDOR && next.enterprise_id.is_none();
            let theirs = if short {
                "stops at a vendor IE too short for its Enterprise ID".to_string()
            } else {
                format!("stops: {}", go_error(fault))
            };
            return found.push(framing("frames another IE", &theirs));
        }
        (true, false, None) => Some(("frames another IE", "ends")),
        (false, true, _) => match fault {
            Some(IeFault::Length { ie_type, .. })
                if theirs[common]["type"].as_u64() == Some(u64::from(ie_type)) =>
            {
                Some((
                    "stops at an IE whose Length runs past its scope",
                    "takes it, without the octets that it lacks",
                ))
            }
            Some(_) => Some(("stops", "frames another IE")),
            None => Some(("ends", "frames another IE")),
        },
        (true, true, _) => unreachable!("both frame the IEs that one has"),
    };
    if let Some((ours, theirs)) = difference {
        found.push(framing(ours, theirs));
    }
}

/// Compare one IE that both frame alike.
fn compare_ie(ours: &IeSlice<'_>, theirs: &Value, found: &mut Vec<Difference>) {
    let info = ie_type_info(ours.ie_type);
    let subject = ours.ie_type.to_string();
    let grouped = info.is_some_and(|info| matches!(info.form, Form::Grouped));
    let their_grouped = theirs["grouped"].as_bool().unwrap();
    let side = |grouped: bool| {
        if grouped {
            "reads IEs in it"
        } else {
            "reads a value"
        }
    };
    if grouped != their_grouped {
        found.push(Difference {
            aspect: "grouped",
            subject,
            ours: side(grouped).into(),
            theirs: side(their_grouped).into(),
            octets: String::new(),
        });
        return;
    }
    if grouped {
        let empty = Vec::new();
        let ies = theirs["ies"].as_array().unwrap_or(&empty);
        return compare_ies(
            "grouped IE",
            ours.ies(),
            ies,
            theirs["fault"].as_str(),
            true,
            found,
        );
    }
    let value = ours.value;
    // An IE of a null length has no value to read, which is no error (§8.1.2)
    if value.is_empty() {
        return;
    }
    let ours = match info {
        None => "has no such type",
        Some(info) if info.tree_of(value, None).is_some() => "decodes",
        Some(_) => "keeps it as octets",
    };
    let theirs = match &theirs["value"] {
        Value::Null => "has no accessor".to_string(),
        Value::String(text) if text.is_empty() => "decodes".to_string(),
        // A value that go-pfcp refuses by a panic is refused, whatever the crate reads
        Value::String(text) if panicked(text) => return,
        Value::String(text) => format!("refuses: {}", go_error(text)),
        other => panic!("a value of {other}"),
    };
    // A value that neither reads, or of a type that one of them lacks, is no difference
    let alike = match (ours, &theirs[..]) {
        ("decodes", "decodes") | ("has no such type", "has no accessor") => true,
        ("keeps it as octets", theirs) => {
            theirs.starts_with("refuses: ") || theirs == "has no accessor"
        }
        _ => false,
    };
    if !alike {
        found.push(Difference {
            aspect: "value",
            subject,
            ours: ours.into(),
            theirs,
            octets: hex::encode(value),
        });
    }
}

/// What differs between the crate and go-pfcp's `reading` of `octets`.
fn compare(octets: &[u8], reading: &Value) -> Vec<Difference> {
    let mut found = Vec::new();
    let parse = reading["parse"].as_str().unwrap();
    let decoded = Message::decode(octets);
    let message = |ours: String, theirs: String| Difference {
        aspect: "message",
        subject: "message".into(),
        ours,
        theirs,
        octets: String::new(),
    };
    match (&decoded, parse.is_empty()) {
        (Ok(_), false) if panicked(parse) => {}
        (Ok(_), false) => found.push(message("decodes".into(), go_error(parse))),
        (Err(error), true) => found.push(message(
            format!("refuses: {}", variant(error)),
            "accepts".into(),
        )),
        _ => {}
    }
    let empty = Vec::new();
    let ies = reading["ies"].as_array().unwrap_or(&empty);
    // go-pfcp reads the octets after the header whatever the Message Length says: where it
    // does not frame them, that is told once, and the IEs are compared within it
    let ignored = |ours: &str| Difference {
        aspect: "framing",
        subject: "message".into(),
        ours: ours.into(),
        theirs: "reads the octets after the header, whatever the Message Length".into(),
        octets: String::new(),
    };
    let length = octets
        .get(2..4)
        .map(|length| 4 + usize::from(u16::from_be_bytes([length[0], length[1]])));
    match framing::message_ies(octets) {
        Ok((_, _, ours)) if length.is_some_and(|length| length < octets.len()) => {
            found.push(ignored("ends at the Message Length"));
            compare_ies("message", ours, ies, None, false, &mut found);
        }
        Ok((_, _, ours)) => compare_ies(
            "message",
            ours,
            ies,
            reading["fault"].as_str(),
            true,
            &mut found,
        ),
        Err(oxirush_pfcp::Error::MessageLength { .. }) => found.push(ignored(
            "stops at a Message Length that runs past the octets",
        )),
        Err(_) if ies.is_empty() && reading["fault"].is_string() => {}
        Err(error) => found.push(Difference {
            aspect: "framing",
            subject: "message".into(),
            ours: format!("stops: {}", variant(&error)),
            theirs: "frames IEs".into(),
            octets: String::new(),
        }),
    }
    if let (Ok(message), true) = (&decoded, parse.is_empty()) {
        let own = message_type_info(message.body.message_type())
            .map_or(Interfaces::N4, |info| info.interfaces);
        let interface = if own.has(Interfaces::N4) {
            Interfaces::N4
        } else {
            own
        };
        let mut kinds: Vec<String> = message
            .check(interface)
            .iter()
            .filter(|deviation| deviation.cause.is_some())
            .map(|deviation| variant(&deviation.kind))
            .collect();
        kinds.sort();
        kinds.dedup();
        for kind in kinds {
            found.push(Difference {
                aspect: "told",
                subject: "message".into(),
                ours: kind,
                theirs: "accepts".into(),
                octets: String::new(),
            });
        }
    }
    found
}

/// Each row has a difference of an aspect that the test makes, a clause and a side.
#[test]
fn the_rows_of_the_differences_are_whole() {
    let aspects = ["message", "framing", "grouped", "value", "told"];
    for row in rows() {
        assert!(
            aspects.contains(&&row.aspect[..]),
            "the aspect {}",
            row.aspect
        );
        assert!(
            !row.clause.is_empty() && !row.subject.is_empty(),
            "{} {}",
            row.aspect,
            row.ours
        );
        assert!(
            ["crate", "go-pfcp", "both", "neither"].contains(&&row.side[..]),
            "the side {}",
            row.side
        );
    }
}

/// Every difference of the corpus that `PFCP_GO_CORPUS` names, as go-pfcp read it into
/// `PFCP_GO_READINGS`, is a row of tests/go-pfcp-differences.tsv.
#[test]
#[ignore = "needs the readings of go-pfcp: PFCP_GO_CORPUS and PFCP_GO_READINGS"]
fn go_pfcp_reads_as_the_crate_or_as_a_row_says() {
    let corpus = std::env::var("PFCP_GO_CORPUS").expect("PFCP_GO_CORPUS names the corpus");
    let readings =
        std::env::var("PFCP_GO_READINGS").expect("PFCP_GO_READINGS names go-pfcp's readings");
    let corpus = std::fs::read_to_string(corpus).unwrap();
    let readings = std::fs::read_to_string(readings).unwrap();
    let rows = rows();
    // Each difference, how many times, and the message and octets of its first case
    let mut seen = BTreeMap::<Difference, (usize, String, String)>::new();
    let mut messages = 0;
    for (line, reading) in corpus.lines().zip(readings.lines()) {
        let (name, octets) = line.split_once('\t').unwrap();
        let reading: Value = serde_json::from_str(reading).unwrap();
        assert_eq!(reading["name"], name, "the readings follow the corpus");
        messages += 1;
        for mut difference in compare(&hex::decode(octets).unwrap(), &reading) {
            let octets = core::mem::take(&mut difference.octets);
            seen.entry(difference)
                .or_insert_with(|| (0, name.to_string(), octets))
                .0 += 1;
        }
    }
    assert_eq!(
        messages,
        corpus.lines().count(),
        "a reading for each message"
    );
    assert_eq!(
        messages,
        readings.lines().count(),
        "a message for each reading"
    );
    let mut unknown = Vec::new();
    println!("{messages} messages");
    for (difference, (count, first, octets)) in &seen {
        let row = rows.iter().find(|row| row.matches(difference));
        let side = row.map_or("NO ROW", |row| &row.side[..]);
        let clause = row.map_or("", |row| &row.clause[..]);
        println!(
            "{count:>6}  {}\t{}\t{}\t{}\t{clause}\t{side}\t(first: {first} {octets})",
            difference.aspect, difference.subject, difference.ours, difference.theirs
        );
        if row.is_none() {
            unknown.push(difference);
        }
    }
    for row in &rows {
        if !seen.keys().any(|difference| row.matches(difference)) {
            println!(
                "no difference of the row {}\t{}\t{}\t{}",
                row.aspect, row.subject, row.ours, row.theirs
            );
        }
    }
    assert!(
        unknown.is_empty(),
        "{} differences without a row: {unknown:#?}",
        unknown.len()
    );
}
