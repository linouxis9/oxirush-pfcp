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
    let cp_f_seid = FSeid::ipv4(0x1001, smf);
    let request = SessionEstablishmentRequest::new_n4(NodeId::Ipv4(smf), cp_f_seid, pdr, far);
    let octets = Message::session(0, 7, request).encode()?;
    println!("{}", hex::encode(&octets));

    // The UPF decodes it, and reads its IEs as typed fields
    let message = Message::decode(&octets)?;
    if let Body::SessionEstablishmentRequest(request) = &message.body {
        let pdi = request.create_pdr[0].pdi.as_ref().ok_or("no PDI")?;
        let from = pdi.source_interface.as_ref().ok_or("no Source Interface")?;
        println!("{message}: {} PDR, from {}", request.create_pdr.len(), from.interface_value);
    }

    // check() finds nothing in it on N4; Sxa has no Precedence in a Create PDR
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
| `tree` | a message and its IEs as trees, read and edited by path | `oxirush-utils` with `tree` |
| `serde` | `Serialize` and `Deserialize`, through the trees | `oxirush-utils` with `tree` |
| `node` | `Node`, a PFCP entity without I/O | no dependency |
| `endpoint` | `Endpoint`, a `Node` on a UDP socket | a Tokio runtime |

The crate is `no_std` with an allocator, but for `endpoint`. Rust 1.88 or later.

## Set up an association, from the SMF to the UPF

A `Node` is a PFCP entity without I/O: datagrams and time go in; datagrams,
events and the next timer come out. It numbers and retransmits requests, matches
responses, answers heartbeats and retransmitted requests, takes bundles (§6.5),
and keeps associations, sessions and the load of each peer. It rejects the
requests that the clauses tell it to reject, as a session request without an
association; every other request is an event that you answer with `respond()`.

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
    smf.request(now, upf_address, Message::node(0, setup))?;
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

The next timer is the first heartbeat to the UPF. What a peer does wrong is
an event too.

## Run a node on a socket

An `Endpoint` runs a node on a UDP socket, in a task of its own: the peers'
requests come through `incoming()`. A `Handle`, which clones, sends the node's
requests and reaches its state (`with`) from any task. A node sends its requests
to port 8805; with `request_port: None`, to the port that its peer sent from.

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
        let message = Message::node(0, heartbeat);
        let response = smf.handle().request(upf.handle().local_addr(), message).await?;
        println!("{response}");
        Ok(())
    })
}
```

```text
PFCP Heartbeat Response (sequence 1)
```

## Decode a message and read its IEs

A message is its header and its body: a struct for each message type, with a
field for each row of its table, each IE of its own type.

```rust
use oxirush_pfcp::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A UPF answers: the Cause, its Node ID, and the F-SEID that it chose
    let octets = hex::decode("2133002b000000000000100100000700003c0005000a00000200130001010039000d0200000000000020010a000002")?;
    let message = Message::decode(&octets)?;
    let Body::SessionEstablishmentResponse(response) = &message.body else { return Err("another message".into()) };
    let cause = response.cause.as_ref().ok_or("no Cause")?.value;
    let up_f_seid = response.up_f_seid.as_ref().ok_or("no F-SEID")?;
    println!("{message}: {cause} ({}), UP F-SEID {:#x} at {:?}", cause.value(), up_f_seid.seid, up_f_seid.ipv4);
    println!("accepted: {}", cause == CauseValue::RequestAccepted);
    Ok(())
}
```

```text
PFCP Session Establishment Response (SEID 0x1001, sequence 7): Request accepted (success) (1), UP F-SEID 0x2001 at Some(10.0.0.2)
accepted: true
```

An IE that the crate cannot read stays as octets, in its place: decoding then
encoding gives the octets back, byte for byte.

## Check a message, and answer a faulty one

`check()` lists what one message breaks of TS 29.244 on an interface, or on a
set of them, each deviation with its path in the tree, its clause and the Cause
of the answer: what it holds a message to, and what it does not, is in
[Limits of `check()`](#limits-of-check). A table whose mandatory IEs differ between interfaces has a constructor
for each, as `CreatePdr::new_sxa()` and `new_n4()`.

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
    let request = Message::session(0x2001, 8, modification.with_create_pdr(pdr));
    for deviation in request.check(Interfaces::N4) {
        println!("{deviation}");
    }

    // The answer to the first deviation that has a Cause
    let deviation = request.check(Interfaces::N4).into_iter().find(|deviation| deviation.cause.is_some()).ok_or("none")?;
    let response = SessionModificationResponse {
        cause: deviation.cause.map(Cause::new),
        offending_ie: deviation.offending_ie().map(OffendingIe::new),
        ..Default::default()
    };
    let answer = Message::session(0x1001, request.header.sequence, response);
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

## A message as JSON

With `tree`, a message is a tree that prints as JSON, with the names of the
specification, and reads back. The tree carries keys and passwords, as the
Tunnel Password, which `Debug` and the errors of a tree hide: do not log it.

```rust
use oxirush_pfcp::Message;
use oxirush_pfcp::tree;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let octets = hex::decode("2133002b000000000000100100000700003c0005000a00000200130001010039000d0200000000000020010a000002")?;
    let tree = Message::decode(&octets)?.to_tree();
    println!("{tree:#}");

    // A tree written by hand, with names in any case and spelling
    let written = tree!({
        "message": "PFCP Heartbeat Request",
        "header": {"Sequence Number": 9},
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
  "header": {
    "SEID": 4097,
    "Sequence Number": 7
  },
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

A tree lists the IEs in the order of the tables; the octets keep the order of
the wire.

## Read and edit by path

`paths::select` and `paths::set` take the same paths on the tree of a message,
in any case: `/pfcp` stands for its IEs, a list has the positions of its
entries, and `*` stands for each. The documentation of `paths` has their rules.

```rust
use oxirush_pfcp::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let octets = hex::decode("2133002b000000000000100100000700003c0005000a00000200130001010039000d0200000000000020010a000002")?;
    let mut tree = Message::decode(&octets)?.to_tree();
    println!("{:?}", paths::select(&tree, "/pfcp/up f-seid/ipv4 address")?);
    paths::set(&mut tree, "/pfcp/Cause", "No resources available")?;
    let edited = Message::from_tree(&tree)?;
    println!("{}", hex::encode(edited.encode()?));
    Ok(())
}
```

```text
[String("10.0.0.2")]
2133002b000000000000100100000700003c0005000a000002001300014b0039000d0200000000000020010a000002
```

## Limits of `check()`

`check()` holds one message to what TS 29.244 V19.6.0 says of its octets, on an
interface. A message in which it finds nothing is not thereby conformant.

It checks:

- the header (§7.2.2), the lengths and the framing (§7.6);
- the tables of clause 7: the IEs that a message and each grouped IE need, may
  have and may repeat on the interface, the IEs of a rejection, and the
  conditions of a row that the IEs of its own scope show, 77 rows
  (`Row::checked`);
- each value of clause 8.2 that the crate decodes: its figure, the sentences on
  which of its flags and fields go together, its tables of values, the ranges
  that its clause gives a value, what a note of a table or the place of the IE
  gives it (an Outer Header Creation of a Low Layer SSM, a bit that the CP
  function alone sets, a bit of a PDI alone), and these formats: UTF-8 of a
  UTF8String, base64 of a Metadata, a UUID of version 4 by its version and
  variant, the name and the value of an HTTP header field, the Operator
  Identifier of an APN/DNN by its three labels that end with `gprs`, and the
  addresses of a Redirect Information, in text, by its type.

It does not check:

- what one message does not show. A condition of clause 7 on the state of a
  session or of a node, on the features that the peers announced, on the request
  that a response answers, or on an IE of the scope above or beside the row's;
  a row that is there "if at least one" of its flags is set, whose IE of no flag
  is not told; and a row that "may be present if", which is not told where its
  condition does not hold. The procedures of clause 6 are a `Node`'s;
- 27 sentences of clause 8.2 on what the octets of a value do not show: 18 on
  the state of a session or on what its sender received (an SDF Filter ID that
  is unique in its session, the IMSI that the SMF received in a SUPI, the
  addresses of a PDU session of type IPv4v6), 4 on an IE of another message (a
  Port Number by the BII flag that created the bridge), and 5 on the format of
  another document (the range of an MBR of TS 36.413, the SST and SD of TS
  23.003, the JSON of a DNS Query/Response Filter of TS 29.571);
- a format that another document gives, beyond those above: the digits of an
  IMSI, an IMEI or an MSISDN, the syntax of a Flow Description, of a URL and of
  a SIP URI, and the content of a container or of a name that the UP function
  is configured with;
- a SEID of 0 in the header where the sender knows its peer's SEID: 0 is read as
  the SEID of a sender that does not know it yet (§7.2.2.4.2), which a message
  does not show, but in a Session Modification or Deletion Request and in a
  response that accepts;
- an IE, a value or octets of a later release: an IE type and a message type
  that V19.6.0 does not have are told as such, and the octets after the fields
  of a value are not told.

The media identifications of an SDF Filter and the additional fields of PFD
Contents are octets in a value and in a tree: `check()` alone reads them as
their figures lay them out.

## Limits

- `encode()` writes spare bits, reserved values, a false Length
  (`RawIe::length`) or Message Length (`Header::length`) and IEs that a table
  does not have, for a test tool, which `check()` tells; a false Length whose
  octets frame as other IEs is checked as them, as its receiver reads them. It
  refuses, each an `Error`:
  - a field that disagrees with the flags or the other fields of its IE, or
    whose octets would read as another value: missing before a later field or unknown octets, unknown
    octets after a field that runs to the end of the IE, or a field of the length
    that its flags give that is longer, or shorter with octets after it
    (`Inconsistent`);
  - a field or a header field too long for its bits or its length
    (`FieldLength`, `HeaderField`);
  - an IE or a message too long for its Length (`TooLong`, `MessageTooLong`).
- TS 29.244 V19.6.0: an IE of a later release stays octets.
- A `Node` is one PFCP entity. A request that names another's session or
  association, as another SMF of a set sends (§5.22), comes to the caller as
  `Received::stranger`.

## Performance

[`benches/`](https://github.com/linouxis9/oxirush-pfcp/blob/main/benches/README.md)
measures each workload, its time and its allocations, beside go-pfcp v0.0.24, with
the revision that its figures are of and how to take them.

## Tests

```sh
cargo test --all-features
cargo +nightly fuzz run tree -- -max_total_time=60
```

[`tests/README.md`](tests/README.md) says what each test checks against the
document and the lab captures, and what the crate finds in other
implementations. Each fuzz target of `fuzz/` says what it holds the crate to:
`differential` compares it with rs-pfcp 0.5.0, a codec written apart from it, on
the same octets: the messages that each decodes or refuses, the header, the IEs
at every level of the grouped IEs, and the values of ten IE types, each
difference one of the readings of rs-pfcp that the target names. Each Rust block of this page is checked with what it prints.
A pull request comes with a test for what it changes; sign off your commits
(`git commit -s`, the [Developer Certificate of
Origin](https://developercertificate.org/)). [SECURITY.md](SECURITY.md) says how
to report a vulnerability.

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
