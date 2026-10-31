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

//! What a node keeps: its requests, its answers, its peers and their sessions.

use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};
use core::time::Duration;

use super::RequestId;
use crate::values::NodeId;

/// An association with a peer (§6.2.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Association {
    /// The peer's Node ID, which identifies the association.
    pub node_id: NodeId<'static>,
    /// Its address.
    pub peer: SocketAddr,
    pub(crate) key: Vec<u8>,
}

/// A session: the peer, and its SEID once the node knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The peer's address.
    pub peer: SocketAddr,
    /// The peer's SEID: the SEID of the header of what goes to it.
    pub peer_seid: Option<u64>,
    pub(crate) node: Vec<u8>,
}

/// The load control information of a peer (§6.2.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadControl {
    /// Its Load Control Sequence Number.
    pub sequence: u32,
    /// Its Load Metric, a percentage.
    pub metric: u8,
}

/// The overload control information of a peer, while it holds (§6.2.4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverloadControl {
    /// The peer that sent it.
    pub peer: SocketAddr,
    /// Its Overload Control Sequence Number.
    pub sequence: u32,
    /// Its Overload Reduction Metric: the percentage of the requests to throttle.
    pub metric: u8,
    /// When its period of validity ends: `None` for never.
    pub until: Option<Duration>,
    /// What the "Loss" algorithm owes, in hundredths of a request.
    pub(crate) credit: u32,
}

/// Whose load or overload it is: of an address, or of a Node ID (§6.2.4.3.1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Scope {
    Address(IpAddr),
    Node(Vec<u8>),
}

/// A request of the node, until its response or its last retransmission.
#[derive(Debug, Clone)]
pub(crate) struct Outstanding {
    pub(crate) id: RequestId,
    pub(crate) to: SocketAddr,
    pub(crate) message_type: u8,
    pub(crate) octets: Vec<u8>,
    pub(crate) deadline: Duration,
    pub(crate) attempts: u8,
    pub(crate) priority: u8,
    /// A heartbeat of the node's own, whose response goes to no event.
    pub(crate) heartbeat: bool,
    /// The local SEID of an establishment.
    pub(crate) local_seid: Option<u64>,
}

/// A request that the node received: its octets, and its response once given.
#[derive(Debug, Clone)]
pub(crate) struct Answered {
    pub(crate) request: Vec<u8>,
    pub(crate) response: Option<Vec<u8>>,
    pub(crate) expires: Duration,
}
