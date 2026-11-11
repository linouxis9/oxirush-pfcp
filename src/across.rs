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

//! The conditions of a row that the IEs of its own scope do not show, and that a scope
//! above it does: the tables of clause 7 that name an IE of the grouped IE or of the
//! message that holds theirs. Each is checked from the scope that holds both.

use alloc::vec::Vec;

use crate::check::{Context, Deviation, DeviationKind, Path};
use crate::enums::{PriorityValue, SteeringModeValue};
use crate::ie::IeType;
use crate::registry::*;
use crate::table::{Presence, Scope};
use crate::values::{MeasurementMethod, SubsequentTimeThreshold, SubsequentVolumeThreshold};
use crate::values_figures::{
    EventQuota, EventThreshold, SubsequentTimeQuota, SubsequentVolumeQuota,
};

/// The place of the value `nth` of the row of `ie_type` of `scope`, at `path`.
fn at<'a, S: Scope>(scope: &S, path: &'a Path<'a>, ie_type: u16, nth: usize) -> Path<'a> {
    let row = S::table().row_of(ie_type).expect("a row of the table");
    let kept = scope.raw().iter().any(|ie| ie.ie_type == ie_type);
    let nth = match kept {
        true => Some(crate::table::value_positions(scope, row)[nth]),
        false => row.is_list().then_some(nth),
    };
    Path::Row {
        parent: path,
        row: row.name,
        nth,
    }
}

/// Tell the row of `T` in the table of `S`, at `scope`, as there where a scope above it
/// has it absent, on an interface that has the row.
fn excluded<S: Scope, T: IeType>(scope: &Path<'_>, context: Context, found: &mut Vec<Deviation>) {
    let table = S::table();
    let Some(row) = table.row_of(T::IE_TYPE) else {
        return;
    };
    if row.on(context.interface).is_some() {
        let at = Path::Row {
            parent: scope,
            row: row.name,
            nth: None,
        };
        let kind = DeviationKind::Excluded {
            ie_type: T::IE_TYPE,
        };
        found.push(Deviation::new(at, table.id, kind));
    }
}

/// Tell the row of `T` in the table of `S`, at `scope`, as missing where a scope above it
/// has its condition hold (§7.6.6), on an interface that has the row.
fn missing<S: Scope, T: IeType>(scope: &Path<'_>, context: Context, found: &mut Vec<Deviation>) {
    let table = S::table();
    let Some(row) = table.row_of(T::IE_TYPE) else {
        return;
    };
    if row
        .on(context.interface)
        .is_some_and(|on| on.presence.is_some())
    {
        let at = Path::Row {
            parent: scope,
            row: row.name,
            nth: None,
        };
        let kind = DeviationKind::ConditionalMissing {
            ie_type: T::IE_TYPE,
        };
        let mut deviation = Deviation::new(at, table.id, kind);
        deviation.cause = context.conditional_cause();
        found.push(deviation);
    }
}

/// The subsequent thresholds and quotas of an Additional Monitoring Time "may be present
/// if" the measurement of their kind "is used" (Table 7.5.2.4-3), which the Measurement
/// Method of the URR above it says: one of another kind is told.
fn additional_monitoring_time<S: Scope>(
    urr: &S,
    method: &MeasurementMethod,
    times: &[AdditionalMonitoringTime],
    path: &Path<'_>,
    context: Context,
    found: &mut Vec<Deviation>,
) {
    for (nth, time) in times.iter().enumerate() {
        let here = at(urr, path, AdditionalMonitoringTime::IE_TYPE, nth);
        let context = context.within(Presence::Optional);
        type Time = AdditionalMonitoringTime;
        if !method.volum && time.subsequent_volume_threshold.is_some() {
            excluded::<Time, SubsequentVolumeThreshold>(&here, context, found);
        }
        if !method.volum && time.subsequent_volume_quota.is_some() {
            excluded::<Time, SubsequentVolumeQuota>(&here, context, found);
        }
        if !method.durat && time.subsequent_time_threshold.is_some() {
            excluded::<Time, SubsequentTimeThreshold>(&here, context, found);
        }
        if !method.durat && time.subsequent_time_quota.is_some() {
            excluded::<Time, SubsequentTimeQuota>(&here, context, found);
        }
        if !method.event && time.subsequent_event_threshold.is_some() {
            excluded::<Time, EventThreshold>(&here, context, found);
        }
        if !method.event && time.subsequent_event_quota.is_some() {
            excluded::<Time, EventQuota>(&here, context, found);
        }
    }
}

/// A Create URR: the Additional Monitoring Times by its Measurement Method.
pub(crate) fn create_urr(
    urr: &CreateUrr,
    path: &Path<'_>,
    context: Context,
    found: &mut Vec<Deviation>,
) {
    if let Some(method) = &urr.measurement_method {
        let times = &urr.additional_monitoring_time[..];
        additional_monitoring_time(urr, method, times, path, context, found);
    }
}

/// An Update URR that has a Measurement Method: its Additional Monitoring Time by it.
pub(crate) fn update_urr(
    urr: &UpdateUrr,
    path: &Path<'_>,
    context: Context,
    found: &mut Vec<Deviation>,
) {
    if let (Some(method), Some(time)) = (&urr.measurement_method, &urr.additional_monitoring_time) {
        let times = core::slice::from_ref(&**time);
        additional_monitoring_time(urr, method, times, path, context, found);
    }
}

/// A Create MAR: the Weight and the Priority of the forwarding action information of
/// each access, by its Steering Mode (Tables 7.5.2.8-2 and 7.5.2.8-3). The Weight "shall
/// be present if steering mode is set to "Load Balancing""; the Priority "shall be present
/// if the steering mode is set to "Active-Standby" or "Priority-based"", "may be present
/// if the steering mode is set to "Redundant"", has a value of its mode, and the two
/// accesses "shall set different values" (NOTE 2).
pub(crate) fn create_mar(
    mar: &CreateMar,
    path: &Path<'_>,
    context: Context,
    found: &mut Vec<Deviation>,
) {
    use SteeringModeValue::{ActiveStandby, LoadBalancing, PriorityBased, Redundant};
    let Some(mode) = mar
        .steering_mode
        .as_ref()
        .map(|mode| mode.steering_mode_value)
    else {
        return;
    };
    type Access3 = ThreeGppAccessForwardingActionInformation;
    type AccessN = NonThreeGppAccessForwardingActionInformation;
    let context = context.within(Presence::Conditional);
    let of_mode = |priority: PriorityValue| match mode {
        ActiveStandby => priority.value() <= 2,
        PriorityBased => matches!(priority.value(), 3 | 4),
        Redundant => matches!(priority.value(), 5 | 6),
        _ => true,
    };
    // One access: whether it has a Weight, and its Priority.
    let mut access = |here: Path<'_>,
                      weight: bool,
                      priority: Option<PriorityValue>,
                      n3gpp: bool| {
        match (n3gpp, mode == LoadBalancing && !weight) {
            (true, true) => missing::<Access3, crate::Weight>(&here, context, found),
            (false, true) => missing::<AccessN, crate::Weight>(&here, context, found),
            _ => {}
        }
        let needed = matches!(mode, ActiveStandby | PriorityBased);
        let allowed = needed || mode == Redundant;
        match (n3gpp, priority) {
            (true, None) if needed => missing::<Access3, crate::Priority>(&here, context, found),
            (false, None) if needed => missing::<AccessN, crate::Priority>(&here, context, found),
            (true, Some(_)) if !allowed => {
                excluded::<Access3, crate::Priority>(&here, context, found)
            }
            (false, Some(_)) if !allowed => {
                excluded::<AccessN, crate::Priority>(&here, context, found)
            }
            (_, Some(priority)) if !of_mode(priority) => {
                let at = Path::Row {
                    parent: &here,
                    row: "Priority",
                    nth: None,
                };
                let rule = "the Priority value is not allowed with the Steering Mode of its MAR";
                let mut deviation = Deviation::new(at, "7.5.2.8-2", DeviationKind::Rule(rule));
                deviation.cause = context.cause(false);
                deviation.ie_type = Some(crate::Priority::IE_TYPE);
                found.push(deviation);
            }
            _ => {}
        }
    };
    let n3gpp = mar.n3gpp_access_forwarding_action_information.as_deref();
    let non_3gpp = mar.non_3gpp_access_forwarding_action_information.as_deref();
    let priority = |priority: &Option<crate::Priority>| {
        priority.as_ref().map(|priority| priority.priority_value)
    };
    if let Some(access_3gpp) = n3gpp {
        let here = at(mar, path, Access3::IE_TYPE, 0);
        access(
            here,
            access_3gpp.weight.is_some(),
            priority(&access_3gpp.priority),
            true,
        );
    }
    if let Some(access_non_3gpp) = non_3gpp {
        let here = at(mar, path, AccessN::IE_TYPE, 0);
        access(
            here,
            access_non_3gpp.weight.is_some(),
            priority(&access_non_3gpp.priority),
            false,
        );
    }
    // "The 3GPP Access Forwarding Action Information and Non 3GPP Access Forwarding
    // Action Information shall set different values".
    let both = n3gpp
        .zip(non_3gpp)
        .and_then(|(first, second)| priority(&first.priority).zip(priority(&second.priority)));
    if both.is_some_and(|(first, second)| first == second) {
        let rule = "the two accesses of a MAR have the same Priority value";
        found.push(Deviation::new(path, "7.5.2.8-2", DeviationKind::Rule(rule)));
    }
}

/// The PDIs of the Create PDRs of a message whose Traffic Endpoint the message creates
/// with QFIs: their QFI "shall not be present if Traffic Endpoint ID is present and the
/// QFI(s) are included in the Traffic Endpoint" (Table 7.5.2.2-2).
fn pdi_qfis<S: Scope>(
    scope: &S,
    pdrs: &[CreatePdr],
    endpoints: &[CreateTrafficEndpoint],
    path: &Path<'_>,
    context: Context,
    found: &mut Vec<Deviation>,
) {
    let with_qfis = |id: &crate::TrafficEndpointId| {
        let same =
            |endpoint: &&CreateTrafficEndpoint| endpoint.traffic_endpoint_id.as_ref() == Some(id);
        endpoints
            .iter()
            .find(same)
            .is_some_and(|endpoint| !endpoint.qfi.is_empty())
    };
    for (nth, pdr) in pdrs.iter().enumerate() {
        let Some(pdi) = pdr.pdi.as_ref() else {
            continue;
        };
        if !pdi.qfi.is_empty() && pdi.traffic_endpoint_id.iter().any(with_qfis) {
            let above = at(scope, path, CreatePdr::IE_TYPE, nth);
            let here = at(pdr, &above, Pdi::IE_TYPE, 0);
            excluded::<Pdi, crate::Qfi>(&here, context.within(Presence::Mandatory), found);
        }
    }
}

/// A Session Establishment Request: the Tunnel Preference of each L2TP Tunnel
/// Information, which "shall be present if multiple L2TP Tunnel Information IEs are
/// included in the message" (Table 7.5.2.1-2), and the QFIs of its PDIs.
pub(crate) fn establishment(
    request: &SessionEstablishmentRequest,
    path: &Path<'_>,
    context: Context,
    found: &mut Vec<Deviation>,
) {
    let tunnels = &request.l2tp_tunnel_information;
    for (nth, tunnel) in tunnels.iter().enumerate() {
        if tunnels.len() > 1 && tunnel.tunnel_preference.is_none() {
            let here = at(request, path, L2tpTunnelInformation::IE_TYPE, nth);
            let context = context.within(Presence::Conditional);
            missing::<L2tpTunnelInformation, crate::TunnelPreference>(&here, context, found);
        }
    }
    let endpoints = &request.create_traffic_endpoint;
    pdi_qfis(
        request,
        &request.create_pdr,
        endpoints,
        path,
        context,
        found,
    );
}

/// A Session Modification Request: the QFIs of the PDIs of its Create PDRs.
pub(crate) fn modification(
    request: &SessionModificationRequest,
    path: &Path<'_>,
    context: Context,
    found: &mut Vec<Deviation>,
) {
    let endpoints = &request.create_traffic_endpoint;
    pdi_qfis(
        request,
        &request.create_pdr,
        endpoints,
        path,
        context,
        found,
    );
}
