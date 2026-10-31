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

//! A node takes any datagram from any peer, and its timers, without panicking: the first
//! octet picks the peer and how far the time moves, the rest is the datagram.
#![no_main]

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use oxirush_pfcp::NodeId;
use oxirush_pfcp::node::{Function, Node, NodeConfig};

fuzz_target!(|octets: &[u8]| {
    let mut node = Node::new(NodeConfig::new(NodeId::Ipv4(Ipv4Addr::LOCALHOST), Function::Up, 1));
    let mut now = Duration::ZERO;
    for datagram in octets.split(|octet| *octet == 0xa5) {
        let Some((first, datagram)) = datagram.split_first() else { continue };
        let peer = SocketAddr::new(Ipv4Addr::new(10, 0, 0, first & 3).into(), 8805);
        now += Duration::from_millis(u64::from(first >> 2) * 100);
        node.handle_datagram(now, peer, datagram);
        node.handle_timeout(now);
        while node.poll_transmit().is_some() {}
        while node.poll_event().is_some() {}
    }
});
