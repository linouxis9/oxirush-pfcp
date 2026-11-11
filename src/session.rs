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

//! The state of a PFCP session that [`Message::check_with`] needs: the rules that earlier
//! messages created, the SDF Filter IDs of its PDRs, and whether it is a bridge.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::check::{Deviation, DeviationKind};
use crate::ie::IeType;
use crate::message::{Body, Message};
use crate::table::{Scope, place};
use crate::{CreatePdr, Pdi, UpdatePdr};

/// The kinds of rules and other objects that a session creates by ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Pdr,
    Far,
    Urr,
    Qer,
    Bar,
    TrafficEndpoint,
    Mar,
    Srr,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Pdr => "PDR",
            Self::Far => "FAR",
            Self::Urr => "URR",
            Self::Qer => "QER",
            Self::Bar => "BAR",
            Self::TrafficEndpoint => "Traffic Endpoint",
            Self::Mar => "MAR",
            Self::Srr => "SRR",
        }
    }

    /// Whether `id` is a predefined rule (§8.2.54, §8.2.74, §8.2.75): the UP function is
    /// configured with it, so a session does not create it.
    fn predefined(self, id: u32) -> bool {
        matches!(self, Self::Far | Self::Urr | Self::Qer) && id & 0x8000_0000 != 0
    }
}

/// The state of one PFCP session, as the requests that its UP function accepted left it.
/// [`Message::check_with`] uses it to validate the next messages of the session.
///
/// Call [`apply`](Self::apply) with each request of the session and the response that
/// accepted it, in the order of the responses. A Session Establishment Request starts the
/// state; a Session Modification Request changes it.
///
/// ```
/// use oxirush_pfcp::*;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // The session has no FAR 7: the request removes a FAR that does not exist.
/// let modification = SessionModificationRequest::default().with_remove_far(RemoveFar::new(FarId::new(7)));
/// let request = Message::session(0x2001, 8, modification);
/// let rules = SessionRules::new();
/// let found = request.check_with(Interfaces::N4, &Known::default().with_session(&rules));
/// assert_eq!(found[0].path, "/pfcp/Remove FAR/0/FAR ID");
/// assert_eq!(found[0].to_string(), "the session has no FAR with this ID (TS 29.244 7.5.4.7-1), at /pfcp/Remove FAR/0/FAR ID");
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionRules {
    /// The rules and traffic endpoints of the session, by kind and ID.
    rules: BTreeSet<(Kind, u32)>,
    /// The SDF Filter IDs of the PDRs, with the PDR ID of each.
    filters: BTreeMap<u32, u16>,
    /// The traffic endpoints that have QFIs.
    with_qfis: BTreeSet<u8>,
    /// Whether the establishment set BII in its Create Bridge/Router Info.
    bridge: bool,
}

/// One rule of a request that creates, updates or removes it.
struct Op {
    kind: Kind,
    id: u32,
    change: Change,
    /// The path of its ID, and the clause of its table.
    at: String,
    clause: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Change {
    Create,
    Update,
    Remove,
}

/// An ID that a rule of the request refers to.
struct Ref {
    kind: Kind,
    id: u32,
    at: String,
    clause: &'static str,
}

/// What a request does to the session.
#[derive(Default)]
struct Request {
    ops: Vec<Op>,
    refs: Vec<Ref>,
    /// The SDF Filter IDs that each created or updated PDI sets, by PDR ID, with the path
    /// of each.
    filters: Vec<(u16, Vec<(u32, String)>)>,
    /// The traffic endpoints that the request creates or updates, and whether they have
    /// QFIs.
    qfis: Vec<(u8, bool)>,
    /// The PDIs that have QFIs and name traffic endpoints: the traffic endpoint IDs, and
    /// the path of the PDI.
    pdi_qfis: Vec<(Vec<u8>, String)>,
    bridge: bool,
}

impl Request {
    fn op(
        &mut self,
        kind: Kind,
        id: Option<u32>,
        change: Change,
        at: String,
        clause: &'static str,
    ) {
        if let Some(id) = id {
            self.ops.push(Op {
                kind,
                id,
                change,
                at,
                clause,
            });
        }
    }

    fn reference(&mut self, kind: Kind, id: Option<u32>, at: String, clause: &'static str) {
        if let Some(id) = id.filter(|id| !kind.predefined(*id)) {
            self.refs.push(Ref {
                kind,
                id,
                at,
                clause,
            });
        }
    }

    /// The SDF Filter IDs and the QFIs of the PDI of PDR `pdr`, at `at`.
    fn pdi(&mut self, pdr: Option<u16>, pdi: &Pdi, at: &str) {
        if !pdi.raw().is_empty() {
            return;
        }
        let clause = Pdi::table().id;
        for (nth, endpoint) in pdi.traffic_endpoint_id.iter().enumerate() {
            let here = format!("{at}/Traffic Endpoint ID/{nth}");
            self.reference(
                Kind::TrafficEndpoint,
                Some(endpoint.value.into()),
                here,
                clause,
            );
        }
        if !pdi.qfi.is_empty() && !pdi.traffic_endpoint_id.is_empty() {
            let endpoints = pdi.traffic_endpoint_id.iter().map(|id| id.value).collect();
            self.pdi_qfis.push((endpoints, String::from(at)));
        }
        let ids = pdi
            .sdf_filter
            .iter()
            .enumerate()
            .filter_map(|(nth, filter)| {
                let id = filter.sdf_filter_id?;
                Some((id, format!("{at}/SDF Filter/{nth}/SDF Filter ID")))
            });
        if let Some(pdr) = pdr {
            self.filters.push((pdr, ids.collect()));
        }
    }

    fn create_pdr(&mut self, nth: usize, pdr: &CreatePdr) {
        let at = format!("/pfcp/Create PDR/{nth}");
        let id = pdr.pdr_id.as_ref().map(|id| id.value);
        self.op(
            Kind::Pdr,
            id.map(u32::from),
            Change::Create,
            format!("{at}/PDR ID"),
            "5.2.1",
        );
        let clause = CreatePdr::table().id;
        self.rule_refs(
            &at,
            clause,
            pdr.far_id.as_ref().map(|id| id.value),
            pdr.urr_id.iter(),
            pdr.qer_id.iter(),
        );
        let mar = pdr.mar_id.as_ref().map(|id| u32::from(id.value));
        self.reference(Kind::Mar, mar, format!("{at}/MAR ID"), clause);
        if let Some(pdi) = &pdr.pdi {
            self.pdi(id, pdi, &format!("{at}/PDI"));
        }
    }

    fn update_pdr(&mut self, nth: usize, pdr: &UpdatePdr) {
        let at = format!("/pfcp/Update PDR/{nth}");
        let id = pdr.pdr_id.as_ref().map(|id| id.value);
        let clause = UpdatePdr::table().id;
        self.op(
            Kind::Pdr,
            id.map(u32::from),
            Change::Update,
            format!("{at}/PDR ID"),
            clause,
        );
        self.rule_refs(
            &at,
            clause,
            pdr.far_id.as_ref().map(|id| id.value),
            pdr.urr_id.iter(),
            pdr.qer_id.iter(),
        );
        if let Some(pdi) = &pdr.pdi {
            self.pdi(id, pdi, &format!("{at}/PDI"));
        }
    }

    /// The FAR ID, URR IDs and QER IDs of a PDR at `at`.
    fn rule_refs<'a>(
        &mut self,
        at: &str,
        clause: &'static str,
        far: Option<u32>,
        urrs: impl Iterator<Item = &'a crate::UrrId>,
        qers: impl Iterator<Item = &'a crate::QerId>,
    ) {
        self.reference(Kind::Far, far, format!("{at}/FAR ID"), clause);
        for (nth, urr) in urrs.enumerate() {
            self.reference(
                Kind::Urr,
                Some(urr.value),
                format!("{at}/URR ID/{nth}"),
                clause,
            );
        }
        for (nth, qer) in qers.enumerate() {
            self.reference(
                Kind::Qer,
                Some(qer.value),
                format!("{at}/QER ID/{nth}"),
                clause,
            );
        }
    }
}

/// Collects what a Session Establishment or Modification Request does to the session.
fn request_of(body: &Body) -> Option<Request> {
    let mut request = Request::default();
    // The rules of a list of `$list`, of `$kind`, by the ID field `$id`
    macro_rules! ops {
        ($body:ident, $change:expr, $( $list:ident $row:literal $kind:ident $id:ident ),* $(,)?) => {$(
            for (nth, rule) in entries(&**$body, &$body.$list) {
                let id = rule.$id.as_ref().map(|id| u32::from(id.value));
                let at = format!("/pfcp/{}/{nth}/{} ID", $row, Kind::$kind.name());
                let clause = match $change {
                    Change::Create => "5.2.1",
                    _ => rule_table(rule),
                };
                request.op(Kind::$kind, id, $change, at, clause);
            }
        )*};
    }
    macro_rules! bar {
        ($body:ident, $field:ident, $row:literal, $change:expr) => {
            // A BAR kept as octets, or one beside another kept as octets, has no path
            let whole = $body.$field.as_ref().filter(|rule| {
                let ie_type = rule_ie_type(&***rule);
                rule.raw().is_empty() && !$body.raw().iter().any(|ie| ie.ie_type == ie_type)
            });
            if let Some(rule) = whole {
                let id = rule.bar_id.as_ref().map(|id| u32::from(id.value));
                let clause = if $change == Change::Create {
                    "5.2.1"
                } else {
                    rule_table(&**rule)
                };
                request.op(
                    Kind::Bar,
                    id,
                    $change,
                    format!("/pfcp/{}/BAR ID", $row),
                    clause,
                );
            }
        };
    }
    match body {
        Body::SessionEstablishmentRequest(body) => {
            for (nth, pdr) in entries(&**body, &body.create_pdr) {
                request.create_pdr(nth, pdr);
            }
            ops!(body, Change::Create,
                create_far "Create FAR" Far far_id, create_urr "Create URR" Urr urr_id,
                create_qer "Create QER" Qer qer_id, create_traffic_endpoint "Create Traffic Endpoint" TrafficEndpoint traffic_endpoint_id,
                create_mar "Create MAR" Mar mar_id, create_srr "Create SRR" Srr srr_id,
            );
            bar!(body, create_bar, "Create BAR", Change::Create);
            request.bridge = body
                .create_bridge_router_info
                .as_ref()
                .is_some_and(|info| info.bii);
            far_refs(
                &mut request,
                entries(&**body, &body.create_far),
                "Create FAR",
            );
            urr_refs(
                &mut request,
                entries(&**body, &body.create_urr),
                "Create URR",
            );
            mar_refs(&mut request, entries(&**body, &body.create_mar));
            endpoints(
                &mut request,
                body.create_traffic_endpoint
                    .iter()
                    .map(|e| (&e.traffic_endpoint_id, !e.qfi.is_empty())),
            );
        }
        Body::SessionModificationRequest(body) => {
            for (nth, pdr) in entries(&**body, &body.create_pdr) {
                request.create_pdr(nth, pdr);
            }
            for (nth, pdr) in entries(&**body, &body.update_pdr) {
                request.update_pdr(nth, pdr);
            }
            ops!(body, Change::Create,
                create_far "Create FAR" Far far_id, create_urr "Create URR" Urr urr_id,
                create_qer "Create QER" Qer qer_id, create_traffic_endpoint "Create Traffic Endpoint" TrafficEndpoint traffic_endpoint_id,
                create_mar "Create MAR" Mar mar_id, create_srr "Create SRR" Srr srr_id,
            );
            ops!(body, Change::Update,
                update_far "Update FAR" Far far_id, update_urr "Update URR" Urr urr_id,
                update_qer "Update QER" Qer qer_id, update_traffic_endpoint "Update Traffic Endpoint" TrafficEndpoint traffic_endpoint_id,
                update_mar "Update MAR" Mar mar_id, update_srr "Update SRR" Srr srr_id,
            );
            ops!(body, Change::Remove,
                remove_pdr "Remove PDR" Pdr pdr_id, remove_far "Remove FAR" Far far_id,
                remove_urr "Remove URR" Urr urr_id, remove_qer "Remove QER" Qer qer_id,
                remove_traffic_endpoint "Remove Traffic Endpoint" TrafficEndpoint traffic_endpoint_id,
                remove_mar "Remove MAR" Mar mar_id, remove_srr "Remove SRR" Srr srr_id,
            );
            bar!(body, create_bar, "Create BAR", Change::Create);
            bar!(body, update_bar, "Update BAR", Change::Update);
            bar!(body, remove_bar, "Remove BAR", Change::Remove);
            far_refs(
                &mut request,
                entries(&**body, &body.create_far),
                "Create FAR",
            );
            far_refs(
                &mut request,
                entries(&**body, &body.update_far),
                "Update FAR",
            );
            urr_refs(
                &mut request,
                entries(&**body, &body.create_urr),
                "Create URR",
            );
            urr_refs(
                &mut request,
                entries(&**body, &body.update_urr),
                "Update URR",
            );
            mar_refs(&mut request, entries(&**body, &body.create_mar));
            endpoints(
                &mut request,
                body.create_traffic_endpoint
                    .iter()
                    .map(|e| (&e.traffic_endpoint_id, !e.qfi.is_empty())),
            );
            endpoints(
                &mut request,
                body.update_traffic_endpoint
                    .iter()
                    .filter(|e| !e.qfi.is_empty())
                    .map(|e| (&e.traffic_endpoint_id, true)),
            );
        }
        _ => return None,
    }
    Some(request)
}

/// The entries of `list`, a list of the scope `scope`, with the position of each in the
/// tree of the scope. An entry that keeps IEs as octets is left out: the paths below it
/// would not be those of its tree.
fn entries<'a, S: Scope, T: Scope + IeType>(
    scope: &'a S,
    list: &'a [T],
) -> impl Iterator<Item = (usize, &'a T)> + 'a {
    let whole = list
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.raw().is_empty());
    whole.map(move |(nth, entry)| (place(scope, T::IE_TYPE, nth), entry))
}

/// The IE type of a rule's group.
fn rule_ie_type<T: IeType>(_: &T) -> u16 {
    T::IE_TYPE
}

/// The clause of the table of a rule's group.
fn rule_table<T: crate::table::Scope>(_: &T) -> &'static str {
    T::table().id
}

/// The BAR ID of each FAR of a list.
fn far_refs<'a, T: FarLike + 'a>(
    request: &mut Request,
    fars: impl Iterator<Item = (usize, &'a T)>,
    row: &str,
) {
    for (nth, far) in fars {
        let at = format!("/pfcp/{row}/{nth}/BAR ID");
        request.reference(Kind::Bar, far.bar(), at, T::clause());
    }
}

/// The Linked URR IDs and the FAR ID for Quota Action of each URR of a list.
fn urr_refs<'a, T: UrrLike + 'a>(
    request: &mut Request,
    urrs: impl Iterator<Item = (usize, &'a T)>,
    row: &str,
) {
    for (nth, urr) in urrs {
        for (inner, linked) in urr.linked().iter().enumerate() {
            let at = format!("/pfcp/{row}/{nth}/Linked URR ID/{inner}");
            request.reference(Kind::Urr, Some(linked.value), at, T::clause());
        }
        let at = format!("/pfcp/{row}/{nth}/FAR ID for Quota Action");
        request.reference(Kind::Far, urr.quota_far(), at, T::clause());
    }
}

/// The FAR IDs of the access forwarding action information of each Create MAR.
fn mar_refs<'a>(request: &mut Request, mars: impl Iterator<Item = (usize, &'a crate::CreateMar)>) {
    let clause = crate::CreateMar::table().id;
    for (nth, mar) in mars {
        let accesses = [
            (
                "3GPP Access Forwarding Action Information",
                mar.n3gpp_access_forwarding_action_information
                    .as_deref()
                    .filter(|access| access.raw().is_empty())
                    .and_then(|access| access.far_id.as_ref()),
            ),
            (
                "Non-3GPP Access Forwarding Action Information",
                mar.non_3gpp_access_forwarding_action_information
                    .as_deref()
                    .filter(|access| access.raw().is_empty())
                    .and_then(|access| access.far_id.as_ref()),
            ),
        ];
        for (row, far) in accesses {
            let at = format!("/pfcp/Create MAR/{nth}/{row}/FAR ID");
            request.reference(Kind::Far, far.map(|id| id.value), at, clause);
        }
    }
}

fn endpoints<'a>(
    request: &mut Request,
    endpoints: impl Iterator<Item = (&'a Option<crate::TrafficEndpointId>, bool)>,
) {
    for (id, qfis) in endpoints {
        if let Some(id) = id {
            request.qfis.push((id.value, qfis));
        }
    }
}

/// A Create FAR or an Update FAR.
trait FarLike {
    fn bar(&self) -> Option<u32>;
    fn clause() -> &'static str;
}

/// A Create URR or an Update URR.
trait UrrLike {
    fn linked(&self) -> &[crate::LinkedUrrId];
    fn quota_far(&self) -> Option<u32>;
    fn clause() -> &'static str;
}

macro_rules! rule_like {
    ($($far:ident)*; $($urr:ident)*) => {
        $(impl FarLike for crate::$far {
            fn bar(&self) -> Option<u32> { self.bar_id.as_ref().map(|id| id.value.into()) }
            fn clause() -> &'static str { crate::$far::table().id }
        })*
        $(impl UrrLike for crate::$urr {
            fn linked(&self) -> &[crate::LinkedUrrId] { &self.linked_urr_id }
            fn quota_far(&self) -> Option<u32> { self.far_id_for_quota_action.as_ref().map(|id| id.value) }
            fn clause() -> &'static str { crate::$urr::table().id }
        })*
    };
}

rule_like!(CreateFar UpdateFar; CreateUrr UpdateUrr);

impl SessionRules {
    /// The state of a session that has no rule yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a request of the session that `response` accepted: a Session Establishment
    /// Request or a Session Modification Request. Other messages, and a response whose
    /// Cause does not accept the request, change nothing.
    pub fn apply(&mut self, request: &Message, response: &Message) {
        let accepted = response.body.cause().is_some_and(|cause| cause.accepts());
        let answers =
            request.body.message_type().checked_add(1) == Some(response.body.message_type());
        let Some(changes) = request_of(&request.body).filter(|_| accepted && answers) else {
            return;
        };
        if matches!(request.body, Body::SessionEstablishmentRequest(_)) {
            *self = Self {
                bridge: changes.bridge,
                ..Self::default()
            };
        }
        for op in &changes.ops {
            match op.change {
                Change::Create | Change::Update => {
                    self.rules.insert((op.kind, op.id));
                }
                Change::Remove => {
                    self.rules.remove(&(op.kind, op.id));
                    if op.kind == Kind::Pdr {
                        self.filters.retain(|_, pdr| u32::from(*pdr) != op.id);
                    }
                    if op.kind == Kind::TrafficEndpoint {
                        self.with_qfis.remove(&(op.id as u8));
                    }
                }
            }
        }
        for (pdr, ids) in &changes.filters {
            self.filters.retain(|_, of| of != pdr);
            self.filters.extend(ids.iter().map(|(id, _)| (*id, *pdr)));
        }
        for (endpoint, qfis) in &changes.qfis {
            match qfis {
                true => self.with_qfis.insert(*endpoint),
                false => self.with_qfis.remove(endpoint),
            };
        }
    }

    fn has(&self, kind: Kind, id: u32) -> bool {
        self.rules.contains(&(kind, id))
    }
}

/// Reports what `message` breaks of the state of its session.
pub(crate) fn check(
    message: &Message,
    rules: &SessionRules,
    request: Option<&Message>,
    found: &mut Vec<Deviation>,
) {
    use DeviationKind::Rule;
    if let Some(changes) = request_of(&message.body) {
        let removed = |kind, id| {
            changes
                .ops
                .iter()
                .any(|op| op.change == Change::Remove && op.kind == kind && op.id == id)
        };
        let created = |kind, id| {
            changes
                .ops
                .iter()
                .any(|op| op.change == Change::Create && op.kind == kind && op.id == id)
        };
        for op in &changes.ops {
            let (broken, text) = match op.change {
                Change::Create => (rules.has(op.kind, op.id), existing(op.kind)),
                _ => (!rules.has(op.kind, op.id), missing(op.kind)),
            };
            if broken && !op.kind.predefined(op.id) {
                found.push(Deviation::new(&op.at, op.clause, Rule(text)));
            }
        }
        // An ID refers to a rule of the session that the message does not remove, or to
        // one that the message creates.
        for reference in &changes.refs {
            let (kind, id) = (reference.kind, reference.id);
            let there = rules.has(kind, id) && !removed(kind, id) || created(kind, id);
            if !there {
                found.push(Deviation::new(
                    &reference.at,
                    reference.clause,
                    Rule(refers_to_nothing(kind)),
                ));
            }
        }
        // "It shall uniquely identify an SDF Filter among all the SDF Filters provisioned
        // for a given PFCP Session" (§8.2.5).
        let set: Vec<u16> = changes.filters.iter().map(|(pdr, _)| *pdr).collect();
        for (nth, (pdr, ids)) in changes.filters.iter().enumerate() {
            for (id, at) in ids {
                let earlier = rules.filters.get(id).is_some_and(|of| {
                    of != pdr && !set.contains(of) && !removed(Kind::Pdr, u32::from(*of))
                });
                let here = changes.filters[..nth]
                    .iter()
                    .any(|(other, ids)| other != pdr && ids.iter().any(|(other, _)| other == id));
                if earlier || here {
                    found.push(Deviation::new(
                        at,
                        "8.2.5",
                        Rule("another PDR of the session has this SDF Filter ID"),
                    ));
                }
            }
        }
        // A PDI has no QFI when its traffic endpoint has QFIs (Table 7.5.2.2-2).
        for (endpoints, at) in &changes.pdi_qfis {
            let with_qfis = |id: &u8| match changes
                .qfis
                .iter()
                .rev()
                .find(|(endpoint, _)| endpoint == id)
            {
                Some((_, qfis)) => *qfis,
                None => rules.with_qfis.contains(id),
            };
            let in_message = changes
                .qfis
                .iter()
                .any(|(endpoint, qfis)| *qfis && endpoints.contains(endpoint));
            if endpoints.iter().any(with_qfis) && !in_message {
                let kind = DeviationKind::Excluded {
                    ie_type: <crate::Qfi as crate::ie::IeType>::IE_TYPE,
                };
                found.push(Deviation::new(format!("{at}/QFI"), Pdi::table().id, kind));
            }
        }
    }
    // "if the BII flag was set to 1 in the Create Bridge/Router Info IE ... Octets 5 and
    // 6 shall be set to all zeros" (§8.2.142).
    let ports: Vec<(usize, Option<u32>)> = match &message.body {
        Body::SessionModificationRequest(body) => body
            .tsc_management_information
            .iter()
            .enumerate()
            .filter(|(_, tsc)| tsc.raw().is_empty())
            .map(|(nth, tsc)| {
                let nth = place(&**body, rule_ie_type(tsc), nth);
                (nth, tsc.nw_tt_port_number.as_ref().map(|port| port.value))
            })
            .collect(),
        Body::SessionModificationResponse(body) => body
            .tsc_management_information
            .iter()
            .enumerate()
            .filter(|(_, tsc)| tsc.raw().is_empty())
            .map(|(nth, tsc)| {
                let nth = place(&**body, rule_ie_type(tsc), nth);
                (nth, tsc.nw_tt_port_number.as_ref().map(|port| port.value))
            })
            .collect(),
        Body::SessionReportRequest(body) => body
            .tsc_management_information
            .iter()
            .enumerate()
            .filter(|(_, tsc)| tsc.raw().is_empty())
            .map(|(nth, tsc)| {
                let nth = place(&**body, rule_ie_type(tsc), nth);
                (nth, tsc.nw_tt_port_number.as_ref().map(|port| port.value))
            })
            .collect(),
        _ => Vec::new(),
    };
    for (nth, port) in ports {
        if rules.bridge && port.is_some_and(|port| port > 0xffff) {
            let at = format!("/pfcp/TSC Management Information/{nth}/NW-TT Port Number");
            found.push(Deviation::new(
                at,
                "8.2.142",
                Rule("the NW-TT Port Number of a bridge is more than 16 bits"),
            ));
        }
    }
    // A usage report is for a URR of the session. A modification response may report on
    // a URR that its request removes or creates.
    let created: Vec<u32> = request
        .and_then(|request| request_of(&request.body))
        .map(|changes| {
            changes
                .ops
                .iter()
                .filter(|op| op.kind == Kind::Urr && op.change == Change::Create)
                .map(|op| op.id)
                .collect()
        })
        .unwrap_or_default();
    let reports: Vec<(usize, Option<u32>, &'static str)> = match &message.body {
        Body::SessionModificationResponse(body) => body
            .usage_report
            .iter()
            .enumerate()
            .filter(|(_, report)| report.raw().is_empty())
            .map(|(nth, report)| {
                (
                    place(&**body, rule_ie_type(report), nth),
                    report.urr_id.as_ref().map(|id| id.value),
                    crate::UsageReportModification::table().id,
                )
            })
            .collect(),
        Body::SessionDeletionResponse(body) => body
            .usage_report
            .iter()
            .enumerate()
            .filter(|(_, report)| report.raw().is_empty())
            .map(|(nth, report)| {
                (
                    place(&**body, rule_ie_type(report), nth),
                    report.urr_id.as_ref().map(|id| id.value),
                    crate::UsageReportDeletion::table().id,
                )
            })
            .collect(),
        Body::SessionReportRequest(body) => body
            .usage_report
            .iter()
            .enumerate()
            .filter(|(_, report)| report.raw().is_empty())
            .map(|(nth, report)| {
                (
                    place(&**body, rule_ie_type(report), nth),
                    report.urr_id.as_ref().map(|id| id.value),
                    crate::UsageReport::table().id,
                )
            })
            .collect(),
        _ => Vec::new(),
    };
    for (nth, urr, clause) in reports {
        let Some(urr) = urr else { continue };
        if !rules.has(Kind::Urr, urr) && !created.contains(&urr) && !Kind::Urr.predefined(urr) {
            let at = format!("/pfcp/Usage Report/{nth}/URR ID");
            found.push(Deviation::new(
                at,
                clause,
                Rule("the usage report is for no URR of the session"),
            ));
        }
    }
}

/// The texts of the deviations, one per kind, as a `Rule` holds a static text.
macro_rules! texts {
    ($fn:ident, $($kind:ident $text:literal),* $(,)?) => {
        fn $fn(kind: Kind) -> &'static str {
            match kind { $(Kind::$kind => $text,)* }
        }
    };
}

texts!(existing,
    Pdr "the session already has a PDR with this ID", Far "the session already has a FAR with this ID",
    Urr "the session already has a URR with this ID", Qer "the session already has a QER with this ID",
    Bar "the session already has a BAR with this ID", TrafficEndpoint "the session already has a Traffic Endpoint with this ID",
    Mar "the session already has a MAR with this ID", Srr "the session already has an SRR with this ID",
);
texts!(missing,
    Pdr "the session has no PDR with this ID", Far "the session has no FAR with this ID",
    Urr "the session has no URR with this ID", Qer "the session has no QER with this ID",
    Bar "the session has no BAR with this ID", TrafficEndpoint "the session has no Traffic Endpoint with this ID",
    Mar "the session has no MAR with this ID", Srr "the session has no SRR with this ID",
);
texts!(refers_to_nothing,
    Pdr "the ID refers to no PDR of the session", Far "the ID refers to no FAR of the session",
    Urr "the ID refers to no URR of the session", Qer "the ID refers to no QER of the session",
    Bar "the ID refers to no BAR of the session", TrafficEndpoint "the ID refers to no Traffic Endpoint of the session",
    Mar "the ID refers to no MAR of the session", Srr "the ID refers to no SRR of the session",
);
