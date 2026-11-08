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

//! The codec of a typed message from its table is lossless, its tree reads back, its paths
//! go through the engine of oxirush-utils, and `check()` names the clause of each
//! deviation. A module has the tests of a subject, and this one the helpers that they
//! share.

use std::net::Ipv4Addr;

use oxirush_pfcp::paths::{select, set};
use oxirush_pfcp::*;
use oxirush_utils::tree;

mod kept;
mod messages;
mod paths;
mod trees;
mod values;

/// A Session Establishment Request of an SMF: one uplink PDR whose F-TEID the UPF
/// chooses, one downlink PDR to the UE's address.
fn establishment() -> Message {
    let uplink = CreatePdr::new_n4(
        PdrId::new(1),
        Precedence::new(255),
        Pdi::new(SourceInterface::new(SourceInterfaceValue::Access))
            .with_local_f_teid(FTeid::choose_ipv4()),
    )
    .with_far_id(FarId::new(1))
    .with_urr_id(UrrId::new(1));
    let ue = UeIpAddress {
        v4: true,
        sd: true,
        ipv4: Some(Ipv4Addr::new(10, 45, 0, 2)),
        ..Default::default()
    };
    let downlink = CreatePdr::new_n4(
        PdrId::new(2),
        Precedence::new(255),
        Pdi::new(SourceInterface::new(SourceInterfaceValue::Core)).with_ue_ip_address(ue),
    )
    .with_far_id(FarId::new(2));
    let smf = Ipv4Addr::new(10, 0, 0, 1);
    let seid = FSeid::ipv4(0x1001, smf);
    let request = SessionEstablishmentRequest::new_n4(
        NodeId::Ipv4(smf),
        seid,
        uplink,
        CreateFar::new(
            FarId::new(1),
            ApplyAction {
                forw: true,
                ..Default::default()
            },
        ),
    )
    .with_create_pdr(downlink);
    Message::session(0, 7, request)
}

/// The kinds of the deviations of a value.
trait CheckKinds {
    fn check_kinds(&self) -> Vec<DeviationKind>;
}

impl<T: Check> CheckKinds for T {
    fn check_kinds(&self) -> Vec<DeviationKind> {
        let found = self.deviations();
        found.into_iter().map(|deviation| deviation.kind).collect()
    }
}
