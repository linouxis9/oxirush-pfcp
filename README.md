# oxirush-pfcp

[![CI](https://github.com/linouxis9/oxirush-pfcp/actions/workflows/ci.yml/badge.svg)](https://github.com/linouxis9/oxirush-pfcp/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

PFCP, the protocol between the control plane and the user plane of 5G and 4G
networks (3GPP TS 29.244), in Rust: every message and IE of N4, N4mb, Sxa, Sxb
and Sxc, decoded, built, checked and edited as JSON, and a PFCP entity to run
on your own socket or on Tokio's. `no_std`.

```rust
use std::net::Ipv4Addr;

use oxirush_pfcp::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // An SMF's Session Establishment Request: one uplink PDR, whose F-TEID the UPF
    // chooses, and its FAR. `new()` takes the mandatory IEs, and `new_n4()` those of N4
    // where an interface has others; `with_*()` adds the others
    let smf = Ipv4Addr::new(10, 0, 0, 1);
    let pdi = Pdi::new(SourceInterface::new(SourceInterfaceValue::Access)).with_local_f_teid(FTeid::choose_ipv4());
    let pdr = CreatePdr::new_n4(PdrId::new(1), Precedence::new(255), pdi).with_far_id(FarId::new(1));
    let core = ForwardingParameters::new(DestinationInterface::new(DestinationInterfaceValue::Core));
    let far = CreateFar::new(FarId::new(1), ApplyAction { forw: true, ..Default::default() }).with_forwarding_parameters(core);
    let cp_f_seid = FSeid { v4: true, seid: Some(0x1001), ipv4: Some(smf), ..Default::default() };
    let request = SessionEstablishmentRequest::new_n4(NodeId::Ipv4(smf), cp_f_seid, pdr, far);
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
    println!("{} deviations on N4", message.check(Interfaces::N4).len());
    for deviation in message.check(Interfaces::SXA) {
        println!("on Sxa: {deviation}");
    }
    Ok(())
}
```

```text
21320069000000000000000000000700003c0005000a0000010039000d0200000000000010010a00000100010024003800020001001d0004000000ff0002000a00140001000015000105006c00040000000100030017006c000400000001002c0002020000040005002a000101
PFCP Session Establishment Request (SEID 0x0, sequence 7): 1 PDR, from Access
0 deviations on N4
on Sxa: Precedence is not on this interface (TS 29.244 7.5.2.2-1), at /pfcp/Create PDR/0/Precedence
```

Each example is followed by its output.

## Installation

The crate is not on crates.io yet: take it from GitHub.

```toml
[dependencies]
oxirush-pfcp = { git = "https://github.com/linouxis9/oxirush-pfcp" }
hex = "0.4" # for the examples of this page
# With JSON, and the PFCP entity on a Tokio socket:
# oxirush-pfcp = { git = "https://github.com/linouxis9/oxirush-pfcp", features = ["serde", "endpoint"] }
```

| Feature | Adds | Needs |
| ------- | ---- | ----- |
| `std`, the default | the standard library | |
| `tree` | a message and its IEs as trees, read and edited by path | `oxirush-utils` with `tree` |
| `serde` | `Serialize` and `Deserialize`, through the trees | `oxirush-utils` with `serde` |
| `node` | `Node`, a PFCP entity without I/O | no dependency |
| `endpoint` | `Endpoint`, a `Node` on a UDP socket | a Tokio runtime |

`serde` turns on `tree`, and `endpoint` turns on `node` and `std`. Without
its default features the crate is `no_std` and needs an allocator; so does
`node`.

The minimum supported Rust version is 1.88.

## Set up an association, from the SMF to the UPF

A `Node` is a PFCP entity on one local address: datagrams and time go in, and
datagrams to send, events and the next timer come out. It numbers each
request and sends it again after T1, up to N1 times; matches each response
by its sequence number, its peer and its type; answers a retransmitted
request with the answer that it gave; answers heartbeats; and keeps the
associations, the sessions and the load and overload of each peer. It
answers itself only what the clauses leave no choice in, as a request of a
peer without an association; every other request of a peer is an event,
which you answer with `respond()`.

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

The next timer is the first heartbeat to the UPF. A peer that does what its
clause forbids, as a response to no request, is an event too, and the node
still does what the clause says.

## Run a node on a socket

An `Endpoint` runs a node on a UDP socket, in a task of its own: a request of
a peer comes through `incoming()` with what answers it. A `Handle`, which
`handle()` gives and which clones, sends the node's requests, each a future of
its response, and reaches the node's state, from any task and while the
endpoint takes the peers' requests. Its queues are bounded, and
`statistics()` counts what they drop. A program that batches its datagrams (`recvmmsg`, `sendmmsg`)
drives a `Node` itself. A node sends its own requests to port 8805, and tells
its peers apart by their addresses; with `request_port: None`, for peers on
ports of their own, it sends them to the port that its peer sent from, and
tells its peers apart by their addresses and ports.

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
        let response = smf.handle().request(upf.local_addr(), message).await?;
        println!("{response}");
        Ok(())
    })
}
```

```text
PFCP Heartbeat Response (sequence 1)
```

## Decode a message and read its IEs

A message is its header and its body: one struct for each message type of
Table 7.3-1, with a field for each row of its table, an `Option` for an IE
that is there once and a list for the others. Each IE has its own type, with
the fields of its figure, and an enumeration for each value that a table
names.

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

What the crate cannot read in a field it keeps as octets, in its place: an IE
of another release, a vendor IE, an IE of a null length, a repetition, a value
that does not decode. Decoding then encoding gives the octets back, byte for
byte, in the order in which they came. `framing::message_ies()` walks the IEs
as slices, without decoding them.

## Check a message, and answer a faulty one

`check()` says each way in which a message is not as TS 29.244 has a sender
construct it on the interface that it names: N4, Sxa, Sxb, Sxc or N4mb, or a
set of them, as `Interfaces::SXA_SXB` of a combined SGW/PGW (§5.2.6), on which
a message may have the IEs of either and needs those that both need. It checks
the mandatory IEs, the conditional IEs whose condition the IEs beside them show
(the UP F-SEID of an accepted establishment, the Forwarding Parameters of a FAR
that forwards, the reports that a Report Type names, two IEs of which a NOTE of
their table needs one: `Row::checked` says which), the
IEs that do not decode, repeat, or are not of the table or the interface, spare
bits and values, reserved values, the flags of each IE with the rules of
clause 8.2 on which of them are set, together, with a value or the Cause of the
message, or always, and the rules of the header. Each deviation has its path, its clause, and the Cause with which a
receiver answers a request for it.

A table whose mandatory IEs differ between interfaces has a constructor for
each: `CreatePdr::new_sxa(pdr_id, pdi)` has no Precedence, which Sxa does not
have, and `CreatePdr::new_n4(pdr_id, precedence, pdi)` has it.

```rust
use std::net::Ipv4Addr;

use oxirush_pfcp::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A modification that creates PDR 3 and removes it, and a Create PDR without its PDR ID
    let mut pdr = CreatePdr::new_n4(PdrId::new(3), Precedence::new(32), Pdi::new(SourceInterface::new(SourceInterfaceValue::Core)))
        .with_far_id(FarId::new(3));
    let modification = SessionModificationRequest::default()
        .with_create_pdr(pdr.clone())
        .with_remove_pdr(RemovePdr::new(PdrId::new(3)));
    pdr.pdr_id = None;
    let request = Message { header: Header::session(0x2001, 8), body: modification.with_create_pdr(pdr).into() };
    for deviation in request.check(Interfaces::N4) {
        println!("{deviation}");
    }

    // The answer to the first deviation that has a Cause
    let deviation = request.check(Interfaces::N4).into_iter().find(|deviation| deviation.cause().is_some()).ok_or("none")?;
    let response = SessionModificationResponse {
        cause: deviation.cause().map(Cause::new),
        offending_ie: deviation.offending_ie().map(OffendingIe::new),
        ..Default::default()
    };
    let answer = Message { header: Header::session(0x1001, request.header.sequence), body: response.into() };
    println!("{answer}: {}", hex::encode(answer.encode()?));
    println!("{} deviations in the answer", answer.check(Interfaces::N4).len());
    Ok(())
}
```

```text
the mandatory PDR ID is missing (TS 29.244 7.5.2.2-1), at /pfcp/Create PDR/1/PDR ID: the answer is "Conditional IE missing"
the message changes PDR 3 more than once (TS 29.244 6.3.3.2), at /pfcp
PFCP Session Modification Response (SEID 0x1001, sequence 8): 213500170000000000001001000008000013000143002800020038
0 deviations in the answer
```

A mandatory IE inside a conditional grouped IE is answered with "Conditional
IE missing", as §7.2.3.2 says.

## A message as JSON

With `tree`, a message is a tree that prints as JSON, with the names of the
specification, and a tree is read back into a message. An IE that the crate
keeps as octets is `{"octets": ...}`. The tree, and serde's JSON, carry the
keys and passwords of a message in hexadecimal, as the Tunnel Password, the HMAC
Key of STAMP and the Shared Secret of OWAMP and TWAMP, which `Debug` hides: do
not log them.

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

A tree is in the order of the tables. A receiver takes the IEs of a message in
any order (§8.1.2), so two messages that differ only in that order have the
same tree, and a tree, in whatever order it writes them, encodes in the order of
the tables. The IEs of one type
keep their order, as a list does: the first DNS Server Address is the primary
one. To send IEs out of order, write the octets.

## Read and edit by path

`tree::select` and `tree::set` take paths on the tree of a message: `/pfcp`
stands for its IEs, a list has the positions of its entries, `*` stands for
each, and names go in any case. A row that a message lacks, or a member that a
value lacks of those that its tree may have (`IeTypeInfo::members`: its flags,
its fields, `Spare`, `length`, `unknown octets`), selects nothing; a name that
is none of them is an error, also below what a message lacks: a row, a flag or
a field, of what the tree of the field may hold (`tree::Below`), and an entry
past the end of a list. A field that its tree writes as a scalar or as an
object, as a value with spare bits or not, takes the same names in either
form: the member that the scalar is selects it.

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

## Limits

- `check()` checks one message: the procedures, and the conditions of the C
  rows that need the state of a node, are not its own. Nor are the conditions
  on the IEs of another scope, as the Weight of an access of a MAR, of the
  Steering Mode of the MAR (Table 7.5.2.8-2), or who sets a flag, as CH of an
  F-TEID, which only the CP function sets.
- `encode()` writes any value that a type can hold, so a test tool can send
  an invalid message.
- A tree is in the order of the tables, and the octets in the order of the
  wire.
- The tables, the figures and the values are those of TS 29.244 V19.6.0
  (Release 19). An IE of a later release stays octets, and an IE that an earlier
  release laid out otherwise is read as Release 19 lays it out.
- No message of a commercial UPF or SMF is among the test fixtures.
- A `Node` is one PFCP entity, with its own associations: an SMF of several
  entities is as many nodes, which do not share them. With MPAS, a node of
  `NodeConfig::other_entities` gives its caller a UPF's handover of a session
  to it, without the association, for the caller to check against the other
  entities of the SMF. A session that the caller then adopts is the node's to
  modify and delete, and the node heartbeats the UPF while it has one.

## Performance

On one core of an AMD Ryzen 7 5700G (Linux 7.0, Rust 1.88.0), at 5f9dd70 on
2026-11-01, for a Session Establishment Request of 16 PDRs, 16 FARs, 8 URRs and
a QER (2,824 octets, 347 IEs), in instructions of one round, which a shared
machine does not change as it changes times:

| Operation | Instructions | Allocations |
|-----------|--------------|-------------|
| `decode` | 97,864 | 15 |
| `encode` | 59,520 | 1 |
| `check` | 37,433 | 0 |
| `to_tree` | 580,030 | 899 |
| `from_tree` | 421,180 | 587 |

[`benches/`](https://github.com/linouxis9/oxirush-pfcp/blob/main/benches/README.md)
has every workload, with instructions and allocations, and how to run them.

### Against go-pfcp

The same messages, decoded, read and encoded by this crate and by go-pfcp
v0.0.24, in instructions on one core. A ratio is go-pfcp's over this crate's.

| Message | Decode | Decode, then read every value | Encode |
|---|---|---|---|
| Heartbeat Request (41 octets) | 2.9x | 3.6x | 4.7x |
| Session Establishment Request, 4 PDRs (820 octets) | 4.3x | 7.4x | 8.0x |
| Session Establishment Request, 16 PDRs (2,824 octets) | 4.4x | 8.8x | 8.0x |
| go-pfcp's own Session Establishment Request (2,110 octets) | 4.3x | 7.9x | 8.3x |

[`benches/`](https://github.com/linouxis9/oxirush-pfcp/blob/main/benches/README.md#against-go-pfcp)
has the figures and the method.

## Tests and fuzzing

```sh
cargo test --all-features
cargo +nightly fuzz run tree -- -max_total_time=60
```

The test `spec` compares the crate with TS 29.244 V19.6.0, as
`tests/spec/extract.py` takes it from the document: every message type and IE
type; every row of a table with its presence, its interfaces, its IE type and
how many IEs of it may be there; every flag and field of a figure with its
octet, its bits and its order, the octets of each field of a fixed length, and
the sentences that make a field there as a flag is set, but for the four
values that the crate reads by hand, as their figures follow a type or a
number (Node ID, FQ-CSID, MAC Addresses Detected and Removed), whose octets
the test `codec` compares with their figures; every table of values, and the
values that a receiver reads as another. `tests/spec/mutations.tsv` lists
changes of the crate that it must fail on, which `tests/spec/mutate.py` makes
in turn. `tests/spec/errata.tsv` names the 43 errata of the document that the
crate meets, and the 3 readings of the crate where the document names no
value, and `tests/spec/requirements.tsv` the 172 requirements of the
procedures: 107 with the test that checks it, and 65 that are the
application's, above the crate. `tests/spec/flag-rules.tsv` has the 58
sentences of clause 8.2 that say which flags of an IE are set, together, with
the value of another field or the Cause of the message, or always: 57 with the
rule of `check()` that checks it, and 1 that a value does not show alone. The test `spec` checks
these numbers.
`tests/captures` has 213 messages that Open5GS and free5GC sent in lab runs:
each decodes, encodes back to its octets, reads back from its tree, and is
checked on its interface. Three fuzz targets, `decode`, `tree` and `node`, run
in CI. [`tests/README.md`](tests/README.md) says what each test checks, and
what the crate finds in other implementations.

Each Rust block of this page is checked with what it prints
([`tests/readme.rs`](tests/readme.rs) says how).

A pull request comes with a test for what it changes. Sign off your commits
(`git commit -s`): by contributing you agree to the [Developer Certificate
of Origin](https://developercertificate.org/). [SECURITY.md](SECURITY.md)
says how to report a vulnerability.

## The OxiRush family

- [oxirush-utils](https://github.com/linouxis9/oxirush-utils): the 3GPP identities, and the JSON tree with its paths that the others share.
- [oxirush-aper](https://github.com/linouxis9/oxirush-aper): aligned PER, the runtime of the NGAP and S1AP codecs.
- [oxirush-nas](https://github.com/linouxis9/oxirush-nas): the NAS messages of 5GS and EPS.
- [oxirush-security](https://github.com/linouxis9/oxirush-security): NAS security, AKA and the derivation of keys.
- [oxirush-ngap](https://github.com/linouxis9/oxirush-ngap): NGAP, between a gNB and an AMF.
- [oxirush-s1ap](https://github.com/linouxis9/oxirush-s1ap): S1AP, between an eNB and an MME.
- [oxirush-gtp-u](https://github.com/linouxis9/oxirush-gtp-u): GTP-U tunnels, with a test UPF.
- [oxirush-pfcp](https://github.com/linouxis9/oxirush-pfcp): PFCP, between the control plane and the user plane.
- [oxirush-sctp](https://github.com/linouxis9/oxirush-sctp): SCTP sockets, which carry NGAP and S1AP.

## License

Copyright 2026 Valentin D'Emmanuele. Licensed under the Apache License,
Version 2.0: see [LICENSE](LICENSE).
