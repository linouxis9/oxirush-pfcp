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

//! Context for [`Message::check_with`](crate::Message::check_with): what the sender and
//! the receiver of a message know and the message does not carry.

use alloc::vec::Vec;

use crate::check::{Deviation, DeviationKind, Path};
use crate::message::Body;
use crate::table::Row;
use crate::{CpFunctionFeatures, UpFunctionFeatures};

/// Context that one message does not carry, for
/// [`Message::check_with`](crate::Message::check_with). Every part is optional: a part
/// that is `None` is not checked, and [`Message::check`](crate::Message::check) uses none.
///
/// ```
/// use oxirush_pfcp::{Known, UpFunctionFeatures};
///
/// // The UP function announced NORP only when the association was set up.
/// let features = UpFunctionFeatures {
///     norp: true,
///     ..Default::default()
/// };
/// let known = Known::default().with_up_features(&features);
/// assert!(known.up_features.is_some() && known.cp_features.is_none());
/// ```
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct Known<'a> {
    /// The UP Function Features that the UP function announced in the association setup
    /// or in its last association update. Pass the default value for a UP function that
    /// sent no UP Function Features IE.
    pub up_features: Option<&'a UpFunctionFeatures>,
    /// The CP Function Features that the CP function announced, in the same way. An
    /// association setup message is checked against its own CP Function Features IE
    /// instead, and so is an association update that carries one.
    pub cp_features: Option<&'a CpFunctionFeatures>,
}

impl<'a> Known<'a> {
    /// Sets the features that the UP function announced.
    pub fn with_up_features(self, features: &'a UpFunctionFeatures) -> Self {
        Self {
            up_features: Some(features),
            ..self
        }
    }

    /// Sets the features that the CP function announced.
    pub fn with_cp_features(self, features: &'a CpFunctionFeatures) -> Self {
        Self {
            cp_features: Some(features),
            ..self
        }
    }
}

/// Which function announces the features of a row.
const UP: bool = false;
const CP: bool = true;

/// The rows of clause 7 that require an announced feature, such as "This IE may be
/// present if the UP function supports the NORP feature": the table, the row, the
/// function that announces the features, the features (any one of them allows the IE),
/// and `several` when the feature is only required for more than one instance of the IE.
/// The test `spec` compares this list with the rows extracted from the specification.
macro_rules! rows {
    ($($table:literal $row:literal $whose:ident [$($feature:literal),+] $($several:ident)?;)*) => {
        #[doc(hidden)]
        pub const ROWS: &[(&str, &str, bool, &[&str], bool)] = &[
            $(($table, $row, $whose, &[$($feature),+], rows!(@several $($several)?)),)*
        ];
    };
    (@several several) => { true };
    (@several) => { false };
}

rows! {
    "7.4.4.1-1" "Alternative SMF IP Address" CP ["SSET", "MPAS"];
    "7.4.4.1-1" "SMF Set ID" CP ["MPAS"];
    "7.4.4.2-1" "Alternative SMF IP Address" CP ["SSET", "MPAS"];
    "7.4.4.2-1" "SMF Set ID" CP ["MPAS"];
    "7.4.4.3-1" "Alternative SMF IP Address" CP ["SSET", "MPAS"];
    "7.4.4.3-1" "SMF Set ID" CP ["MPAS"];
    "7.5.2.1-1" "DSCP to PPI Control Information" UP ["EPPPI"];
    "7.5.2.2-2" "UE IP address" UP ["IP6PL"] several;
    "7.5.2.2-2" "Traffic Endpoint ID" UP ["MTE"] several;
    "7.5.2.3-2" "Extended Transport Level Marking" UP ["PSITLM"];
    "7.5.2.3-2" "Header Handling Control Rule" UP ["USHPH"];
    "7.5.2.3-2" "On-path N6 Connection Information" UP ["CONUDP", "UDPOPT"];
    "7.5.2.4-1" "Number of Reports" UP ["NORP"];
    "7.5.2.4-1" "Exempted Application ID for Quota Action" UP ["QUASF"];
    "7.5.2.4-1" "Exempted SDF Filter for Quota Action" UP ["QUASF"];
    "7.5.2.6-1" "Suggested Buffering Packets Count" UP ["UDBC"];
    "7.5.2.6-1" "DL Buffering Duration" UP ["DBDM"];
    "7.5.2.6-1" "DL Buffering Suggested Packet Count" UP ["DBDM"];
    "7.5.2.7-1" "UE IP address" UP ["IP6PL"] several;
    "7.5.2.7-1" "QFI" UP ["MTE"];
    "7.5.2.9-1" "Direct Reporting Information" UP ["DRQOS"];
    "7.5.3.2-1" "UE IP Address" UP ["IP6PL"] several;
    "7.5.3.5-1" "UE IP Address" UP ["IP6PL"] several;
    "7.5.4.11-1" "Suggested Buffering Packets Count" UP ["UDBC"];
    "7.5.4.11-1" "DL Buffering Duration" UP ["DBDM"];
    "7.5.4.11-1" "DL Buffering Suggested Packet Count" UP ["DBDM"];
    "7.5.4.13-1" "UE IP address" UP ["IP6PL"] several;
    "7.5.4.13-1" "QFI" UP ["MTE"];
    "7.5.4.18-1" "Direct Reporting Information" UP ["DRTSC"];
    "7.5.5.1-1" "Packet Rate Status Report" UP ["CIOT"];
    "7.5.5.5-1" "UE IP Address" UP ["IP6PL"] several;
    "7.5.7.1-1" "Packet Rate Status Report" UP ["CIOT"];
    "7.5.8.2-1" "DL Data Packets Size" UP ["MT-EDT"];
    "7.5.9.2-1" "DL Buffering Duration" UP ["DLBD"];
    "7.5.9.2-1" "Suggested Buffering Packets Count" UP ["UDBC"];
}

/// Defines `NAMED`, the features that the rows use, and `announced`, which reads each of
/// them from the features IEs. The position of a feature in `NAMED` is its bit in the
/// mask that [`lacking`] returns.
macro_rules! named {
    (up { $($up:ident $up_name:literal),* } cp { $($cp:ident $cp_name:literal),* }) => {
        const NAMED: &[(bool, &str)] = &[$((UP, $up_name),)* $((CP, $cp_name),)*];

        fn announced(
            up: Option<&UpFunctionFeatures>,
            cp: Option<&CpFunctionFeatures>,
        ) -> [Option<bool>; NAMED.len()] {
            [$(up.map(|features| features.$up),)* $(cp.map(|features| features.$cp),)*]
        }
    };
}

named! {
    up { epppi "EPPPI", ip6pl "IP6PL", mte "MTE", psitlm "PSITLM", ushph "USHPH", conudp "CONUDP", udpopt "UDPOPT", norp "NORP", quasf "QUASF", udbc "UDBC", dbdm "DBDM", drqos "DRQOS", drtsc "DRTSC", ciot "CIOT", mt_edt "MT-EDT", dlbd "DLBD" }
    cp { sset "SSET", mpas "MPAS" }
}

/// Returns the features of `NAMED` that are known to be missing for a message with
/// `body`, one bit each. A function whose features are unknown has no bit set.
///
/// An association setup carries all the CP features of its sender, so it is checked
/// against its own CP Function Features IE, and a setup without the IE announces none.
/// An association update carries the IE only when the features changed: otherwise the
/// known features apply.
pub(crate) fn lacking(body: &Body, known: &Known<'_>) -> u32 {
    let none = CpFunctionFeatures::default();
    let cp = match body {
        Body::AssociationSetupRequest(setup) => setup.cp_function_features.as_ref().or(Some(&none)),
        Body::AssociationSetupResponse(setup) => {
            setup.cp_function_features.as_ref().or(Some(&none))
        }
        Body::AssociationUpdateRequest(update) => {
            update.cp_function_features.as_ref().or(known.cp_features)
        }
        _ => known.cp_features,
    };
    let announced = announced(known.up_features, cp);
    (0..NAMED.len()).fold(0, |lacking, bit| {
        lacking | u32::from(announced[bit] == Some(false)) << bit
    })
}

/// Reports a row with `count` values when none of the features that allow it, or that
/// allow more than one instance of it, was announced.
#[inline(never)]
pub(crate) fn check_row(
    table: &'static str,
    row: &Row,
    count: usize,
    lacking: u32,
    path: &Path<'_>,
    found: &mut Vec<Deviation>,
) {
    let of = |entry: &&(&str, &str, bool, &[&str], bool)| entry.0 == table && entry.1 == row.name;
    for (_, _, whose, features, several) in ROWS.iter().filter(of) {
        let lacks = |feature: &&str| {
            let bit = NAMED.iter().position(|named| named == &(*whose, *feature));
            bit.is_some_and(|bit| lacking >> bit & 1 == 1)
        };
        if count > usize::from(*several) && features.iter().all(lacks) {
            let ie_type = row.ie_type;
            let kind = match several {
                true => DeviationKind::Repeated { ie_type },
                false => DeviationKind::Excluded { ie_type },
            };
            let here = Path::Row {
                parent: path,
                row: row.name,
                nth: None,
            };
            found.push(Deviation::new(here, table, kind));
        }
    }
}
