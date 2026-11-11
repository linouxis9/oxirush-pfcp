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
//! the receiver of a message know and the message does not carry. The request that a
//! response answers, and the features that the two functions announced.

use alloc::vec::Vec;

use crate::check::{Deviation, DeviationKind, Path};
use crate::ie::IeType;
use crate::message::{Body, Message, is_request};
use crate::table::{Interfaces, Row};
use crate::{
    CpFunctionFeatures, CreatePdr, CreateTrafficEndpoint, CreatedBridgeRouterInfo, CreatedPdr,
    CreatedTrafficEndpoint, FTeid, FiveGsUserPlaneNodeId, MappedN6IpAddress, Pdi, PortNumber,
    UeIpAddress, UpFunctionFeatures, UpdatedPdr,
};

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
/// assert!(known.up_features.is_some() && known.request.is_none());
/// ```
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct Known<'a> {
    /// The request that the message answers, when the message is a response.
    pub request: Option<&'a Message>,
    /// The state of the session of the message, before the message.
    pub session: Option<&'a crate::SessionRules>,
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
    /// Sets the request that the message answers.
    pub fn with_request(self, request: &'a Message) -> Self {
        Self {
            request: Some(request),
            ..self
        }
    }

    /// Sets the state of the session of the message, before the message.
    pub fn with_session(self, session: &'a crate::SessionRules) -> Self {
        Self {
            session: Some(session),
            ..self
        }
    }

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

/// What a request asks the UP function to allocate for a PDR or a traffic endpoint, or
/// what a response returns for one: a local F-TEID, a UE IP address or prefix, a mapped
/// N6 IP address.
type Allocated = [bool; 3];

/// The rows of a Created PDR, a Created Traffic Endpoint and an Updated PDR that return
/// an allocation, in the order of [`Allocated`]: the name and the IE type of each.
const ALLOCATED: [(&str, u16); 3] = [
    ("F-TEID", FTeid::IE_TYPE),
    ("UE IP Address", UeIpAddress::IE_TYPE),
    ("Mapped N6 IP Address", MappedN6IpAddress::IE_TYPE),
];

/// Returns what a PDI or a traffic endpoint asks the UP function to allocate: CH in its
/// F-TEID, CHV4 or CHV6 in a UE IP address, CHV4 in its mapped N6 IP address.
fn asks(
    teid: &Option<FTeid>,
    addresses: &[UeIpAddress],
    mapped: Option<&MappedN6IpAddress>,
) -> Allocated {
    [
        teid.as_ref().is_some_and(|teid| teid.ch),
        addresses.iter().any(|address| address.chv4 || address.chv6),
        mapped.is_some_and(|mapped| mapped.chv4),
    ]
}

/// What each Create PDR asks, with its PDR ID.
fn asked_pdrs(pdrs: &[CreatePdr]) -> Vec<(Option<u32>, Allocated)> {
    let asked = |pdr: &CreatePdr| {
        let pdi = pdr.pdi.as_ref().map(asked_pdi).unwrap_or_default();
        (pdr.pdr_id.as_ref().map(|id| id.value.into()), pdi)
    };
    pdrs.iter().map(asked).collect()
}

fn asked_pdi(pdi: &Pdi) -> Allocated {
    let mapped = pdi.mapped_n6_ip_address.as_ref();
    asks(&pdi.local_f_teid, &pdi.ue_ip_address, mapped)
}

/// What each Create Traffic Endpoint asks, with its Traffic Endpoint ID.
fn asked_endpoints(endpoints: &[CreateTrafficEndpoint]) -> Vec<(Option<u32>, Allocated)> {
    let asked = |endpoint: &CreateTrafficEndpoint| {
        let id = endpoint.traffic_endpoint_id.as_ref();
        let mapped = endpoint.mapped_n6_ip_address.as_ref();
        let asked = asks(&endpoint.local_f_teid, &endpoint.ue_ip_address, mapped);
        (id.map(|id| id.value.into()), asked)
    };
    endpoints.iter().map(asked).collect()
}

/// What each Created PDR returns, with its PDR ID.
fn returned_pdrs(pdrs: &[CreatedPdr]) -> Vec<(Option<u32>, Allocated)> {
    let returned = |pdr: &CreatedPdr| {
        // An entry that keeps IEs as octets is taken as complete: its paths would not
        // be those of its tree.
        let kept = !crate::table::Scope::raw(pdr).is_empty();
        let has = [
            kept || !pdr.f_teid.is_empty(),
            kept || !pdr.ue_ip_address.is_empty(),
            kept || pdr.mapped_n6_ip_address.is_some(),
        ];
        (pdr.pdr_id.as_ref().map(|id| id.value.into()), has)
    };
    pdrs.iter().map(returned).collect()
}

/// What each Created Traffic Endpoint returns, with its Traffic Endpoint ID.
fn returned_endpoints(endpoints: &[CreatedTrafficEndpoint]) -> Vec<(Option<u32>, Allocated)> {
    let returned = |endpoint: &CreatedTrafficEndpoint| {
        let kept = !crate::table::Scope::raw(endpoint).is_empty();
        let has = [
            kept || !endpoint.f_teid.is_empty(),
            kept || !endpoint.ue_ip_address.is_empty(),
            kept || endpoint.mapped_n6_ip_address.is_some(),
        ];
        let id = endpoint.traffic_endpoint_id.as_ref();
        (id.map(|id| id.value.into()), has)
    };
    endpoints.iter().map(returned).collect()
}

fn at<'a>(parent: &'a Path<'a>, row: &'static str, nth: Option<usize>) -> Path<'a> {
    Path::Row { parent, row, nth }
}

/// Reports each PDR or traffic endpoint of `asked` that the response returns nothing
/// for: no IE of `row` with its ID among `returned`, or an IE without the allocation that
/// was asked. The IE of `row` "shall be present if the cause is set to "success" and the
/// UP function was requested to allocate a local F-TEID or a UE IP address/prefix or a
/// Mapped N6 IP address" (Tables 7.5.3.1-1 and 7.5.5.1-1), and inside it "If the UP
/// function allocates the F-TEID, this IE shall be present" (Tables 7.5.3.2-1, 7.5.3.5-1
/// and 7.5.5.5-1).
fn allocated(
    asked: &[(Option<u32>, Allocated)],
    returned: &[(Option<u32>, Allocated)],
    positions: impl Fn(usize) -> usize,
    row: &Row,
    table: &'static str,
    found: &mut Vec<Deviation>,
) {
    let inside = row.content.map_or(table, |content| content.id);
    let root = Path::Root("/pfcp");
    let missing = |ie_type| DeviationKind::ConditionalMissing { ie_type };
    for (id, asked) in asked.iter().filter(|(_, asked)| asked.contains(&true)) {
        let Some(nth) = returned.iter().position(|returned| returned.0 == *id) else {
            let here = at(&root, row.name, None);
            found.push(Deviation::new(here, table, missing(row.ie_type)));
            continue;
        };
        let here = at(&root, row.name, Some(positions(nth)));
        let rows = asked.iter().zip(returned[nth].1).zip(ALLOCATED);
        for ((asked, returned), (name, ie_type)) in rows {
            if *asked && !returned {
                found.push(Deviation::new(
                    at(&here, name, None),
                    inside,
                    missing(ie_type),
                ));
            }
        }
    }
}

/// Reports what a response breaks with respect to the request that it answers, on
/// `interface`: its message type, its Sequence Number, the SEID of a Session
/// Establishment Response and, when the response accepts the request, the IEs that return
/// what the request asked the UP function to allocate.
pub(crate) fn against(
    response: &Message,
    request: &Message,
    interface: Interfaces,
    found: &mut Vec<Deviation>,
) {
    use DeviationKind::Rule;
    let (asked, answers) = (request.body.message_type(), response.body.message_type());
    // A Version Not Supported Response answers a request of any type (§7.4.4.7).
    if !is_request(asked) || answers != asked + 1 && answers != 11 {
        let rule = Rule("the message is not the response to this request");
        found.push(Deviation::new("/message", "7.3", rule));
        return;
    }
    if response.header.sequence != request.header.sequence {
        let rule = Rule("the Sequence Number is not the one of the request");
        found.push(Deviation::new("/header/Sequence Number", "6.4", rule));
    }
    let cause = response.body.cause();
    let accepted = cause.is_some_and(|cause| cause.effective().value() == 1);
    // The row of an IE type in the response, when the interface has it.
    let table = response.body.table();
    let row = |ie_type: u16| {
        let row = table.and_then(|table| table.row_of(ie_type));
        row.filter(|row| row.on(interface).is_some())
    };
    match (&request.body, &response.body) {
        (
            Body::SessionEstablishmentRequest(request),
            Body::SessionEstablishmentResponse(answer),
        ) => {
            // "The Session Endpoint Identifier is set by the sending entity ... to the
            // SEID value provided by the corresponding receiving entity": the SEID of
            // the CP F-SEID. A response that rejects the request may use 0 (§7.2.2.4.2).
            let seid = request.cp_f_seid.as_ref().map(|seid| seid.seid);
            let zero = !accepted && response.header.seid == Some(0);
            if seid.is_some() && response.header.seid != seid && !zero {
                let rule = Rule("the SEID is not the one of the CP F-SEID of the request");
                found.push(Deviation::new("/header/SEID", "7.2.2.4.1", rule));
            }
            if !accepted {
                return;
            }
            let table = "7.5.3.1-1";
            if let Some(row) = row(CreatedPdr::IE_TYPE) {
                let (asked, returned) = (
                    asked_pdrs(&request.create_pdr),
                    returned_pdrs(&answer.created_pdr),
                );
                let positions = |nth| crate::table::place(&**answer, CreatedPdr::IE_TYPE, nth);
                allocated(&asked, &returned, positions, row, table, found);
            }
            if let Some(row) = row(CreatedTrafficEndpoint::IE_TYPE) {
                let asked = asked_endpoints(&request.create_traffic_endpoint);
                let returned = returned_endpoints(&answer.created_traffic_endpoint);
                let positions =
                    |nth| crate::table::place(&**answer, CreatedTrafficEndpoint::IE_TYPE, nth);
                allocated(&asked, &returned, positions, row, table, found);
            }
            // A Created Bridge/Router Info "shall be present if the UPF was requested to
            // provide Bridge/Router information", and its two IEs "If the BII bit or the
            // RII bit was set to "1" in the Create Bridge/Router Info IE" (Tables
            // 7.5.3.1-1 and 7.5.3.6-1).
            let bridge = request.create_bridge_router_info.as_ref();
            let bridge = bridge.filter(|info| info.bii || info.rii);
            if let (Some(asked), Some(row)) = (bridge, row(CreatedBridgeRouterInfo::IE_TYPE)) {
                let root = Path::Root("/pfcp");
                let here = at(&root, row.name, None);
                let missing = |ie_type| DeviationKind::ConditionalMissing { ie_type };
                // An IE of no length is read as absent (§8.1.2).
                let info = answer.created_bridge_router_info.as_deref();
                let Some(info) = info.filter(|info| crate::ie::Codec::encoded_len(*info) > 0)
                else {
                    found.push(Deviation::new(here, table, missing(row.ie_type)));
                    return;
                };
                // One that keeps IEs as octets is taken as complete.
                if !crate::table::Scope::raw(info).is_empty() {
                    return;
                }
                let port = at(&here, "Port Number", None);
                if info.port_number.is_none() {
                    let kind = missing(PortNumber::IE_TYPE);
                    found.push(Deviation::new(port, "7.5.3.6-1", kind));
                }
                if info.n5gs_user_plane_node_id.is_none() {
                    let node = at(&here, "5GS User Plane Node ID", None);
                    let kind = missing(FiveGsUserPlaneNodeId::IE_TYPE);
                    found.push(Deviation::new(node, "7.5.3.6-1", kind));
                }
                // "if the BII flag was set to 1 in the Create Bridge/Router Info IE ... it
                // shall be encoded as an Unsigned16 binary integer value in octets 7 and
                // 8. Octets 5 and 6 shall be set to all zeros" (§8.2.141).
                let port_number = info.port_number.as_ref();
                if asked.bii && port_number.is_some_and(|port| port.value > 0xffff) {
                    let rule = Rule("the Port Number of a bridge is more than 16 bits");
                    found.push(Deviation::new(port, "8.2.141", rule));
                }
            }
        }
        (Body::SessionModificationRequest(request), Body::SessionModificationResponse(answer))
            if accepted =>
        {
            let table = "7.5.5.1-1";
            if let Some(row) = row(CreatedPdr::IE_TYPE) {
                let (asked, returned) = (
                    asked_pdrs(&request.create_pdr),
                    returned_pdrs(&answer.created_pdr),
                );
                let positions = |nth| crate::table::place(&**answer, CreatedPdr::IE_TYPE, nth);
                allocated(&asked, &returned, positions, row, table, found);
            }
            if let Some(row) = row(CreatedTrafficEndpoint::IE_TYPE) {
                let mut asked = asked_endpoints(&request.create_traffic_endpoint);
                asked.extend(request.update_traffic_endpoint.iter().map(|endpoint| {
                    let id = endpoint.traffic_endpoint_id.as_ref();
                    let asked = asks(&endpoint.local_f_teid, &endpoint.ue_ip_address, None);
                    (id.map(|id| u32::from(id.value)), asked)
                }));
                let returned = returned_endpoints(&answer.created_updated_traffic_endpoint);
                let positions =
                    |nth| crate::table::place(&**answer, CreatedTrafficEndpoint::IE_TYPE, nth);
                allocated(&asked, &returned, positions, row, table, found);
            }
            // An Updated PDR "shall be present if a Update PDR is present in the
            // corresponding PFCP Session Modification Request and UP function is
            // requested to allocate a new F-TEID ... or the UP function is requested to
            // assign additional UE IP Address or Prefix". Which of its two F-TEID rows
            // returns the F-TEID depends on why it was asked, so only the Updated PDR
            // and its UE IP Address are checked.
            if let Some(row) = row(UpdatedPdr::IE_TYPE) {
                let asked = |pdr: &crate::UpdatePdr| {
                    let pdi = pdr.pdi.as_deref().map(asked_pdi).unwrap_or_default();
                    (pdr.pdr_id.as_ref().map(|id| id.value.into()), pdi)
                };
                let returned = |pdr: &UpdatedPdr| {
                    let kept = !crate::table::Scope::raw(pdr).is_empty();
                    let has = [true, kept || !pdr.ue_ip_address.is_empty(), true];
                    (pdr.pdr_id.as_ref().map(|id| id.value.into()), has)
                };
                let asked: Vec<_> = request.update_pdr.iter().map(asked).collect();
                let returned: Vec<_> = answer.updated_pdr.iter().map(returned).collect();
                let positions = |nth| crate::table::place(&**answer, UpdatedPdr::IE_TYPE, nth);
                allocated(&asked, &returned, positions, row, table, found);
            }
        }
        _ => {}
    }
}
