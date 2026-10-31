# oxirush-pfcp

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

PFCP in Rust, per 3GPP TS 29.244 V19.6.0 (Release 19): decode, build, check
and encode every message and IE of N4, Sxa, Sxb, Sxc and N4mb, and edit them
as JSON. `no_std`.

```rust
use std::net::Ipv4Addr;

use oxirush_pfcp::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // An SMF's Session Establishment Request: one uplink PDR, whose F-TEID the UPF
    // chooses, and its FAR. `new()` takes the mandatory IEs, `with_*()` adds the others
    let smf = Ipv4Addr::new(10, 0, 0, 1);
    let pdi = Pdi::new(SourceInterface::new(SourceInterfaceValue::Access)).with_local_f_teid(FTeid::choose_ipv4());
    let pdr = CreatePdr::new(PdrId::new(1), Precedence::new(255), pdi).with_far_id(FarId::new(1));
    let far = CreateFar::new(FarId::new(1), ApplyAction { forw: true, ..Default::default() });
    let cp_f_seid = FSeid { v4: true, seid: Some(0x1001), ipv4: Some(smf), ..Default::default() };
    let request = SessionEstablishmentRequest::new(NodeId::Ipv4(smf), cp_f_seid, pdr, far);
    let octets = Message { header: Header::session(0, 7), body: request.into() }.encode()?;
    println!("{}", hex::encode(&octets));

    // The UPF decodes it, and reads its IEs as typed fields
    let message = Message::decode(&octets)?;
    if let Body::SessionEstablishmentRequest(request) = &message.body {
        let pdi = request.create_pdr[0].pdi.as_ref().ok_or("no PDI")?;
        let from = pdi.source_interface.as_ref().ok_or("no Source Interface")?;
        println!("{message}: {} PDR, from {}", request.create_pdr.len(), from.interface_value);
    }

    // Nothing is wrong with it on N4; Sxa has no Precedence in a Create PDR
    println!("{} deviations on N4", message.check().len());
    for deviation in message.check_on(Interfaces::SXA) {
        println!("on Sxa: {deviation}");
    }
    Ok(())
}
```

```text
21320060000000000000000000000700003c0005000a0000010039000d0200000000000010010a00000100010024003800020001001d0004000000ff0002000a00140001000015000105006c0004000000010003000e006c000400000001002c00020200
PFCP Session Establishment Request (SEID 0x0, sequence 7): 1 PDR, from Access
0 deviations on N4
on Sxa: Precedence is not on this interface (TS 29.244 7.5.2.2-1), at /pfcp/Create PDR/0/Precedence
```

Each example is followed by its output.

## Installation

```toml
[dependencies]
oxirush-pfcp = { git = "https://github.com/linouxis9/oxirush-pfcp" }
hex = "0.4" # for the examples of this page
# With trees and JSON:
# oxirush-pfcp = { git = "https://github.com/linouxis9/oxirush-pfcp", features = ["serde"] }
```

| Feature | Adds | Dependencies |
|---------|------|--------------|
| `std` (default) | The standard library | |
| `tree` | A message and its IEs as trees, read and edited by path | `oxirush-utils` with `tree` |
| `serde` | `Serialize` and `Deserialize` for a message and each IE, through its tree. Turns on `tree` | `oxirush-utils` with `serde` |
| `node` | `Node`, a PFCP entity without I/O: delivery, heartbeat, associations, sessions, load and overload control | |
| `endpoint` | `Endpoint`, a `Node` on a Tokio UDP socket. Turns on `node` and `std` | `tokio` |

Without its default features the crate is `no_std` and needs an allocator;
`node` too. The minimum supported Rust version is 1.88.

## Read a message

A message is its header and its body, one variant of `Body` for each message
type of Table 7.3-1. Each body and each grouped IE is a struct with one field
for each row of its table: an `Option` for an IE that is there once, a list
for the rows that the table lets repeat. Each IE has its own type, with the
fields of its figure in clause 8.2, and an enumeration for each value that a
table of the clause names.

```rust
use oxirush_pfcp::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A UPF answers: the Cause, its Node ID, and the F-SEID that it chose
    let octets = hex::decode("2133002b000000000000100100000700003c0005000a00000200130001010039000d0200000000000020010a000002")?;
    let message = Message::decode(&octets)?;
    let Body::SessionEstablishmentResponse(response) = &message.body else { return Err("another message".into()) };
    let cause = response.cause.as_ref().ok_or("no Cause")?.value;
    let up_f_seid = response.up_f_seid.as_ref().ok_or("no F-SEID")?;
    println!("{message}: {cause} ({}), UP F-SEID {:#x} at {:?}", cause.value(), up_f_seid.seid.unwrap_or(0), up_f_seid.ipv4);
    println!("accepted: {}", cause == CauseValue::RequestAccepted);
    Ok(())
}
```

```text
PFCP Session Establishment Response (SEID 0x1001, sequence 7): Request accepted (success) (1), UP F-SEID 0x2001 at Some(10.0.0.2)
accepted: true
```

The decoder takes every IE type of the release, and keeps what it cannot read
in a field as octets, in its place: an IE of another release, a vendor IE, an
IE of a null length, an IE that repeats where its table has it once, and a
value that does not decode. Decoding then encoding gives the octets back, byte
for byte, in the order in which they came.

`framing::message_ies()` walks the IEs of a message as slices of its octets,
without decoding them, for a program that only needs a few.

## Check a message, and answer a faulty one

`check()` says each way in which a message is not as TS 29.244 has a sender
construct it on N4, and `check_on()` on another interface: the mandatory IEs
of the interface (§7.6.6), the IEs that do not decode (§7.6.8), that repeat
(§7.6.10), that the table or the interface does not have (§7.6.9), spare bits
and values, reserved values, the flags of each IE against its fields, and the
rules of the header. Each deviation names its path and its clause, and the
Cause with which a receiver answers a request for it (§7.6), with the IE type
that the Offending IE carries.

```rust
use std::net::Ipv4Addr;

use oxirush_pfcp::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A modification that creates PDR 3 and removes it, and a Create PDR without its PDR ID
    let mut pdr = CreatePdr::new(PdrId::new(3), Precedence::new(32), Pdi::new(SourceInterface::new(SourceInterfaceValue::Core)));
    let modification = SessionModificationRequest::default()
        .with_create_pdr(pdr.clone())
        .with_remove_pdr(RemovePdr::new(PdrId::new(3)));
    pdr.pdr_id = None;
    let request = Message { header: Header::session(0x2001, 8), body: modification.with_create_pdr(pdr).into() };
    for deviation in request.check() {
        println!("{deviation}");
    }

    // The answer to the first deviation that has a Cause
    let deviation = request.check().into_iter().find(|deviation| deviation.cause().is_some()).ok_or("none")?;
    let response = SessionModificationResponse {
        cause: deviation.cause().map(Cause::new),
        offending_ie: deviation.offending_ie().map(OffendingIe::new),
        ..Default::default()
    };
    let answer = Message { header: Header::session(0x1001, request.header.sequence), body: response.into() };
    println!("{answer}: {}", hex::encode(answer.encode()?));
    println!("{} deviations in the answer", answer.check().len());
    Ok(())
}
```

```text
the mandatory PDR ID is missing (TS 29.244 7.5.2.2-1), at /pfcp/Create PDR/1/PDR ID: the answer is "Conditional IE missing"
the message changes PDR 3 more than once (TS 29.244 6.3.3.2), at /pfcp
PFCP Session Modification Response (SEID 0x1001, sequence 8): 213500170000000000001001000008000013000143002800020038
0 deviations in the answer
```

A mandatory IE of a conditional grouped IE is answered with "Conditional IE
missing", as §7.2.3.2 says. `check()` checks one message: it does not know
the procedure, and it checks the conditions of the C rows that a message
alone shows.

## A message as JSON

With `tree`, a message is a tree that prints as JSON, and a tree is read back
into a message. An IE is under the name that its table gives it, a value by
the name that its table gives it, and an IE that the crate keeps as octets is
`{"octets": ...}`.

```rust
use oxirush_pfcp::Message;
use oxirush_pfcp::tree::tree;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let octets = hex::decode("2133002b000000000000100100000700003c0005000a00000200130001010039000d0200000000000020010a000002")?;
    let tree = Message::decode(&octets)?.to_tree();
    println!("{tree:#}");

    // A tree written by hand, with names in any case and spelling
    let written = tree!({
        "message": "PFCP Heartbeat Request",
        "Sequence Number": 9,
        "ies": {"recovery time stamp": 3_900_000_000u32}
    });
    let heartbeat = Message::from_tree(&written)?;
    println!("{heartbeat}: {}", hex::encode(heartbeat.encode()?));
    Ok(())
}
```

```json
{
  "message": "PFCP Session Establishment Response",
  "SEID": 4097,
  "Sequence Number": 7,
  "ies": {
    "Node ID": "10.0.0.2",
    "Cause": "Request accepted (success)",
    "UP F-SEID": {
      "V4": true,
      "SEID": 8193,
      "IPv4 address": "10.0.0.2"
    }
  }
}
```

```text
PFCP Heartbeat Request (sequence 9): 2001000c0000090000600004e8754700
```

**A tree is in the order of the tables.** Its IEs come in the order of the
rows of their table, whatever the order of the wire: §8.1.2 has a receiver
take the IEs of a message in any order, so two messages that differ only in
the order of their IEs have the same tree, and from a tree the crate encodes
them in the order of the table. The IEs of one type keep the order of the
wire among themselves, as a list does, since that order can mean something:
the first DNS Server Address is the primary one. The octets keep the order of
the wire: a test that sends IEs out of order writes them as octets, not as a
tree.

## Read and edit by path

`tree::select` and `tree::set` take paths on the tree of a message: `/pfcp`
stands for its IEs, a list has the positions of its entries, `*` stands for
each, and names go in any case.

```rust
use oxirush_pfcp::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let octets = hex::decode("2133002b000000000000100100000700003c0005000a00000200130001010039000d0200000000000020010a000002")?;
    let mut tree = Message::decode(&octets)?.to_tree();
    println!("{:?}", tree::select(&tree, "/pfcp/up f-seid/ipv4 address")?);
    tree::set(&mut tree, "/pfcp/Cause", "No resources available")?;
    let edited = Message::from_tree(&tree)?;
    println!("{}", hex::encode(edited.encode()?));
    Ok(())
}
```

```text
[String("10.0.0.2")]
2133002b000000000000100100000700003c0005000a000002001300014b0039000d0200000000000020010a000002
```

## Run a PFCP entity

With `node`, a `Node` is a PFCP entity on one local endpoint, without I/O:
datagrams and time go in, and datagrams to send, events and the next timer
come out. It numbers each request and sends it again after T1, up to N1
times; matches each response by its sequence number, its peer and its type;
answers a retransmitted request with the answer that it gave; answers
heartbeats; keeps the associations, the sessions and their SEIDs, the load
and overload of each peer; and throttles the requests to an overloaded peer.
Each decision is the caller's: a request of a peer is an event, which the
caller answers with `respond()`. What a peer does wrong is an event too.

```rust
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use oxirush_pfcp::node::{Event, Function, Node, NodeConfig};
use oxirush_pfcp::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let smf_id = NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 1));
    let upf_id = NodeId::Ipv4(Ipv4Addr::new(10, 0, 0, 2));
    let (smf_address, upf_address): (SocketAddr, SocketAddr) = ("10.0.0.1:8805".parse()?, "10.0.0.2:8805".parse()?);
    let mut smf = Node::new(NodeConfig::new(smf_id.clone(), Function::Cp, 3_900_000_000));
    let mut upf = Node::new(NodeConfig::new(upf_id.clone(), Function::Up, 3_900_000_000));
    let now = Duration::ZERO;

    // The SMF sets up an association: the node numbers the request, and arms T1
    let setup = AssociationSetupRequest::new(smf_id, RecoveryTimeStamp::new(3_900_000_000));
    smf.request(now, upf_address, Message { header: Header::node(0), body: setup.into() })?;
    let datagram = smf.poll_transmit().ok_or("nothing to send")?;
    println!("to {}: {} octets, again at {:?}", datagram.to, datagram.octets.len(), smf.poll_timeout());

    // The UPF takes the datagram, and its caller answers the request
    upf.handle_datagram(now, smf_address, &datagram.octets);
    while let Some(event) = upf.poll_event() {
        if let Event::Request { request, message } = event {
            println!("the UPF: {message}");
            let accepted = Cause::new(CauseValue::RequestAccepted);
            upf.respond(now, &request, AssociationSetupResponse::new(upf_id.clone(), accepted, RecoveryTimeStamp::new(3_900_000_000)))?;
        }
    }

    // The SMF takes the answer: the request is done, and the association is there
    let answer = upf.poll_transmit().ok_or("no answer")?;
    smf.handle_datagram(now, upf_address, &answer.octets);
    while let Some(event) = smf.poll_event() {
        match event {
            Event::Associated { peer, .. } => println!("the SMF: associated with {peer}"),
            Event::Response { message, .. } => println!("the SMF: {message}"),
            other => println!("the SMF: {other:?}"),
        }
    }
    println!("no more timer: {:?}", smf.poll_timeout());
    Ok(())
}
```

```text
to 10.0.0.2:8805: 25 octets, again at Some(3s)
the UPF: PFCP Association Setup Request (sequence 1)
the SMF: associated with 10.0.0.2:8805
the SMF: PFCP Association Setup Response (sequence 1)
no more timer: Some(60s)
```

The next timer is the first heartbeat to the UPF. `tests/node.rs` has each
procedure, and `tests/spec/requirements.tsv` says which requirement of clause
6 each test checks.

## On a Tokio socket

With `endpoint`, an `Endpoint` runs a node on a UDP socket, in a task of its
own: a request is a future of its response, and a request of a peer comes
through `incoming()`, with what answers it. Its queues are bounded, and
`statistics()` counts what they drop. A program that batches its datagrams
(`recvmmsg`, `sendmmsg`) drives a `Node` itself.

```rust
use std::net::Ipv4Addr;

use oxirush_pfcp::endpoint::Endpoint;
use oxirush_pfcp::node::{Function, NodeConfig};
use oxirush_pfcp::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        let config = |function| NodeConfig::new(NodeId::Ipv4(Ipv4Addr::LOCALHOST), function, 3_900_000_000);
        let smf = Endpoint::bind("127.0.0.1:0".parse()?, config(Function::Cp)).await?;
        let upf = Endpoint::bind("127.0.0.1:0".parse()?, config(Function::Up)).await?;

        // The UPF's node answers a heartbeat itself
        let heartbeat = HeartbeatRequest::new(RecoveryTimeStamp::new(3_900_000_000));
        let message = Message { header: Header::node(0), body: heartbeat.into() };
        let response = smf.request(upf.local_addr(), message).await?;
        println!("{response}");
        Ok(())
    })
}
```

```text
PFCP Heartbeat Response (sequence 1)
```

## How the crate follows TS 29.244

The crate is written from the tables of the document, and a test compares it
with them. `tests/spec/extract.py` takes from the pinned document, which it
checks by its SHA-256:

- Table 7.3-1, the message types;
- Table 8.1.2-1, the IE types;
- the 146 tables of clause 7, row by row;
- the 280 figures of clause 8.2, field by field;
- the 43 tables of values and of bits.

The test `spec` fails on anything that the crate lacks or has otherwise.
`tests/spec/errata.tsv` names 43 errata of the document, each with what the
crate takes instead, and the test fails on an erratum that the document no
longer has. `tests/spec/requirements.tsv` lists the 172 requirements of
clause 6, the procedures, each with the test that checks it, or why none in
the crate does.

## Performance

On one core of an AMD Ryzen 7 5700G, a Session Establishment Request of 16
PDRs (2,824 octets) decodes in about 6 µs and encodes in about 4 µs, and
`check()` takes about 3 µs without allocating. Against go-pfcp v0.0.24, in
instructions on the same messages, go-pfcp takes 2.9 to 4.6 times as many to
decode, 3 to 9.6 times as many to decode and read every value, and 5 to 9.4
times as many to encode. [`benches/`](benches/README.md) has the figures and
the method.

## Tests and fuzzing

The tests run the messages that Open5GS and free5GC sent in lab runs and
go-pfcp's test vectors through the codec, the check and the trees, each byte
for byte; the test `spec` compares the crate with the document, and
`tests/node.rs` has the procedures of clause 6. `fuzz/` has three
[cargo-fuzz](https://crates.io/crates/cargo-fuzz) targets: `decode`, `tree`
and `node`.

## Limits

- `check()` checks a message alone: the procedures, and the conditions of the
  C rows that need the state of a node, are the node's.
- A tree is in the order of the tables, as above.
- Release 19 only: an IE of a later release is kept as octets, and an IE whose
  layout an earlier release had otherwise is read by the layout of Release 19.

## License

Apache-2.0
