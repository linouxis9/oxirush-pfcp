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

//! What a datagram that the node rejects or discards costs it: a few times its size,
//! counted by an allocator of this test alone, and not the size of its decoded IEs.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use oxirush_pfcp::node::*;
use oxirush_pfcp::*;

struct Counting;

thread_local! {
    static ALLOCATED: Cell<usize> = const { Cell::new(0) };
    /// What is allocated and not freed yet.
    static HELD: Cell<isize> = const { Cell::new(0) };
}

// SAFETY: the allocations are the system's; the count is of this thread alone.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATED.with(|allocated| allocated.set(allocated.get() + layout.size()));
        HELD.with(|held| held.set(held.get() + layout.size() as isize));
        // SAFETY: as the caller of alloc has it.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        HELD.with(|held| held.set(held.get() - layout.size() as isize));
        // SAFETY: as the caller of dealloc has it.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCATED.with(|allocated| allocated.set(allocated.get() + size));
        HELD.with(|held| held.set(held.get() + size as isize - layout.size() as isize));
        // SAFETY: as the caller of realloc has it.
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// What `f` leaves allocated on this thread.
fn held(f: impl FnOnce()) -> isize {
    let before = HELD.with(Cell::get);
    f();
    HELD.with(Cell::get) - before
}

/// What `f` allocates on this thread.
fn allocated(f: impl FnOnce()) -> usize {
    let before = ALLOCATED.with(Cell::get);
    f();
    ALLOCATED.with(Cell::get) - before
}

const UPF: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 8805);
const HOST: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9)), 8805);

/// A message of `message_type` and `seid`, with `ies` and as many Create PDRs of 8
/// octets as a datagram holds.
fn flooded(message_type: u8, seid: Option<u64>, ies: &[u8]) -> Vec<u8> {
    let mut octets = vec![0x20 | u8::from(seid.is_some()), message_type, 0, 0];
    if let Some(seid) = seid {
        octets.extend(seid.to_be_bytes());
    }
    octets.extend([0, 0, 1, 0]);
    octets.extend(ies);
    while octets.len() + 8 <= 65_535 {
        octets.extend([0, 1, 0, 4, 0, 0, 0, 0]);
    }
    let length = (octets.len() - 4) as u16;
    octets[2..4].copy_from_slice(&length.to_be_bytes());
    octets
}

#[test]
fn what_is_rejected_unread_costs_little() {
    let mut upf = Node::new(NodeConfig::new(
        NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 2)),
        Function::Up,
        1,
    ));
    let node_id = [0, 60, 0, 5, 0, 10, 9, 9, 9];
    let cp_f_seid = [0, 57, 0, 13, 2, 0, 0, 0, 0, 0, 0, 0, 1, 10, 9, 9, 9];
    let cases = [
        // An establishment of a host without an association
        flooded(50, Some(0), &[node_id.as_slice(), &cp_f_seid].concat()),
        // A modification of a SEID that the node does not have
        flooded(52, Some(77), &[]),
        // A response to no request of the node
        flooded(51, Some(0), &[]),
    ];
    for octets in cases {
        let cost = allocated(|| {
            upf.handle_datagram(Duration::ZERO, HOST, &octets);
            while upf.poll_transmit().is_some() {}
            while upf.poll_event().is_some() {}
        });
        assert!(
            cost < 4 * octets.len(),
            "message type {}: {cost} octets for a datagram of {}",
            octets[1],
            octets.len()
        );
    }
    let _ = UPF;
}

/// An Association Setup Request of a host without an association, when `strangers` of
/// them wait already, is dropped before it is decoded.
#[test]
fn a_setup_beyond_the_strangers_costs_little() {
    let mut upf = Node::new(NodeConfig {
        strangers: 1,
        ..NodeConfig::new(NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 2)), Function::Up, 1)
    });
    let node_id = [0, 60, 0, 5, 0, 10, 9, 9, 8];
    let stamp = [0, 96, 0, 4, 0, 0, 0, 1];
    let waiting: SocketAddr = "10.9.9.8:8805".parse().unwrap();
    // One that waits: its header, of a Message Length of 21, its Node ID and its stamp
    let header = [0x20, 5, 0, 21, 0, 0, 1, 0];
    let octets = [header.as_slice(), &node_id, &stamp].concat();
    upf.handle_datagram(Duration::ZERO, waiting, &octets);
    assert!(matches!(upf.poll_event(), Some(Event::Request { .. })));
    let flood = flooded(5, None, &[node_id.as_slice(), &stamp].concat());
    let cost = allocated(|| {
        upf.handle_datagram(Duration::ZERO, HOST, &flood);
        while upf.poll_transmit().is_some() {}
        while upf.poll_event().is_some() {}
    });
    assert!(cost < 4 * flood.len(), "{cost} octets for {}", flood.len());
    assert_eq!(upf.counters().refused, 1);
}

/// What the node keeps of the requests that it rejects, to answer their retransmissions,
/// is not their octets: 200 rejected establishments of 64 KB from a host without an
/// association leave a few kilooctets each at most.
#[test]
fn what_is_kept_of_a_rejection_is_small() {
    let mut upf = Node::new(NodeConfig::new(
        NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 2)),
        Function::Up,
        1,
    ));
    let node_id = [0, 60, 0, 5, 0, 10, 9, 9, 9];
    let mut octets = flooded(50, Some(0), &node_id);
    let kept = held(|| {
        for sequence in 1..=200u32 {
            octets[12..15].copy_from_slice(&sequence.to_be_bytes()[1..]);
            upf.handle_datagram(Duration::ZERO, HOST, &octets);
            while upf.poll_transmit().is_some() {}
            while upf.poll_event().is_some() {}
        }
    });
    assert!(kept < 200 * 1024, "{kept} octets kept for 200 rejections");
    // A retransmission is answered still, from what the node kept
    upf.handle_datagram(Duration::ZERO, HOST, &octets);
    assert!(upf.poll_transmit().is_some());
    assert!(upf.poll_event().is_none());
}
