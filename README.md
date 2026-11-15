# oxirush-pfcp

[![CI](https://github.com/linouxis9/oxirush-pfcp/actions/workflows/ci.yml/badge.svg)](https://github.com/linouxis9/oxirush-pfcp/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

PFCP (3GPP TS 29.244), between the control plane and the user plane of 5G and
4G cores: decode, build, check and encode every message and IE of N4, N4mb,
Sxa, Sxb and Sxc, edit them as JSON, and run a PFCP node on your own socket or
on Tokio. `no_std`.

```rust
use std::net::Ipv4Addr;

use oxirush_pfcp::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // An SMF builds a Session Establishment Request with one uplink PDR and its FAR.
    // The UPF chooses the F-TEID. `new()` takes the mandatory IEs (`new_n4()` when they
    // differ between interfaces) and `with_*()` adds the optional ones
    let smf = Ipv4Addr::new(10, 0, 0, 1);
    let pdi = Pdi::new(SourceInterface::new(SourceInterfaceValue::Access)).with_local_f_teid(FTeid::choose_ipv4());
    let pdr = CreatePdr::new_n4(PdrId::new(1), Precedence::new(255), pdi).with_far_id(FarId::new(1));
    let core = ForwardingParameters::new(DestinationInterface::new(DestinationInterfaceValue::Core));
    let far = CreateFar::new(FarId::new(1), ApplyAction { forw: true, ..Default::default() }).with_forwarding_parameters(core);
    let cp_f_seid = FSeid::ipv4(0x1001, smf);
    let request = SessionEstablishmentRequest::new_n4(NodeId::Ipv4(smf), cp_f_seid, pdr, far);
    let octets = Message::session(0, 7, request).encode()?;
    assert_eq!(
        hex::encode(&octets),
        "21320069000000000000000000000700003c0005000a0000010039000d0200000000000010010a00000100010024003800020001001d0004000000ff0002000a00140001000015000105006c00040000000100030017006c000400000001002c0002020000040005002a000101",
    );

    // The UPF decodes it and reads its IEs as typed fields
    let message = Message::decode(&octets)?;
    assert_eq!(message.to_string(), "PFCP Session Establishment Request (SEID 0x0, sequence 7)");
    let Body::SessionEstablishmentRequest(request) = &message.body else { return Err("another message".into()) };
    let pdi = request.create_pdr[0].pdi.as_ref().ok_or("no PDI")?;
    let from = pdi.source_interface.as_ref().ok_or("no Source Interface")?;
    assert_eq!(request.create_pdr.len(), 1);
    assert_eq!(from.interface_value, SourceInterfaceValue::Access);

    // check() reports nothing on N4. On Sxa, a Create PDR has no Precedence
    assert!(message.check(Interfaces::N4).is_empty());
    let on_sxa: Vec<String> = message.check(Interfaces::SXA).iter().map(ToString::to_string).collect();
    assert_eq!(on_sxa, ["Precedence is not on this interface (TS 29.244 7.5.2.2-1), at /pfcp/Create PDR/0/Precedence"]);
    Ok(())
}
```

Each example shows what it gives with `assert_eq!`, and runs as a test of the crate.

## Installation

```toml
[dependencies]
oxirush-pfcp = "0.1"
hex = "0.4" # only for the examples on this page
# With JSON and the Tokio endpoint:
# oxirush-pfcp = { version = "0.1", features = ["tree", "endpoint"] }
```

| Feature | Adds | Needs |
| ------- | ---- | ----- |
| `tree` | messages and IEs as JSON trees, with reads and edits by path | `oxirush-utils` with `tree` |
| `node` | `Node`, a PFCP node without I/O | nothing |
| `endpoint` | `Endpoint`, a `Node` on a UDP socket | a Tokio runtime |

The crate is `no_std` and needs an allocator. Only `endpoint` needs `std`.
It requires Rust 1.88 or later. Its values, tables and trees are written with
the `fields` and `tables` of oxirush-utils 0.3, a dependency of every build.

## Set up an association between an SMF and a UPF

A `Node` is a PFCP node without I/O. You give it datagrams and the current
time, and it gives you datagrams to send, events and the next timer. It assigns
sequence numbers, retransmits requests, matches responses, answers heartbeats
and retransmitted requests, handles bundled messages (§6.5), and tracks
associations, sessions and the load of each peer. It rejects the requests that
the specification says to reject, such as a session request without an
association. Every other request is an event that you answer with `respond()`.

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

    // The SMF sets up an association. The node assigns the sequence number and starts T1
    let setup = AssociationSetupRequest::new(smf_id, RecoveryTimeStamp::new(3_900_000_000));
    smf.request(now, upf_address, Message::node(0, setup))?;
    let datagram = smf.poll_transmit().ok_or("nothing to send")?;
    assert_eq!((datagram.to, datagram.octets.len()), (upf_address, 25));
    assert_eq!(smf.poll_timeout(), Some(Duration::from_secs(3)));

    // The UPF receives the datagram, and the application answers the request
    upf.handle_datagram(now, smf_address, &datagram.octets);
    let Some(Event::Request { request, message }) = upf.poll_event() else { return Err("no request".into()) };
    assert_eq!(message.to_string(), "PFCP Association Setup Request (sequence 1)");
    let accepted = Cause::new(CauseValue::RequestAccepted);
    upf.respond(now, &request, AssociationSetupResponse::new(upf_id, accepted, RecoveryTimeStamp::new(3_900_000_000)))?;

    // The SMF receives the response. The request is complete and the association exists
    let answer = upf.poll_transmit().ok_or("no answer")?;
    smf.handle_datagram(now, upf_address, &answer.octets);
    let mut events = Vec::new();
    while let Some(event) = smf.poll_event() {
        events.push(match event {
            Event::Associated { peer, .. } => format!("associated with {peer}"),
            Event::Response { message, .. } => message.to_string(),
            other => format!("{other:?}"),
        });
    }
    assert_eq!(events, ["associated with 10.0.0.2:8805", "PFCP Association Setup Response (sequence 1)"]);
    assert_eq!(smf.poll_timeout(), Some(Duration::from_secs(60)));
    Ok(())
}
```

The remaining timer is the first heartbeat to the UPF. Protocol errors of a
peer are reported as events too.

## Run a node on a socket

An `Endpoint` runs a node on a UDP socket in its own task. Requests from peers
arrive through `incoming()`. A `Handle` is cheap to clone: use it from any task
to send requests and to read the state of the node (`with`). A node sends its
requests to port 8805, or to the source port of its peer when `request_port` is
`None`.

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

        // The node of the UPF answers a heartbeat by itself
        let heartbeat = HeartbeatRequest::new(RecoveryTimeStamp::new(3_900_000_000));
        let message = Message::node(0, heartbeat);
        let response = smf.handle().request(upf.handle().local_addr(), message).await?;
        assert_eq!(response.to_string(), "PFCP Heartbeat Response (sequence 1)");
        Ok(())
    })
}
```

## Decode a message and read its IEs

A message has a header and a body. The body is a struct for each message type,
with one field for each row of its table in the specification. Each IE has its
own type.

```rust
use std::net::Ipv4Addr;

use oxirush_pfcp::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The response of a UPF: its Node ID, the Cause and the F-SEID that it chose
    let octets = hex::decode("2133002b000000000000100100000700003c0005000a00000200130001010039000d0200000000000020010a000002")?;
    let message = Message::decode(&octets)?;
    let Body::SessionEstablishmentResponse(response) = &message.body else { return Err("another message".into()) };
    let cause = response.cause.as_ref().ok_or("no Cause")?.value;
    let up_f_seid = response.up_f_seid.as_ref().ok_or("no F-SEID")?;
    assert_eq!(message.to_string(), "PFCP Session Establishment Response (SEID 0x1001, sequence 7)");
    assert_eq!(cause, CauseValue::RequestAccepted);
    assert_eq!((cause.to_string(), cause.value()), ("Request accepted (success)".into(), 1));
    assert_eq!((up_f_seid.seid, up_f_seid.ipv4), (0x2001, Some(Ipv4Addr::new(10, 0, 0, 2))));
    Ok(())
}
```

An IE that the crate cannot decode is kept as raw octets in its position, so
decoding a message and encoding it again returns the same bytes.

## Check a message, and answer a faulty one

`check()` validates one message against TS 29.244 on an interface, or on a set
of interfaces. Each deviation has the path of the IE, the clause that is broken
and the Cause to answer with. `check_with()` also validates a response against
its request, a message against the features that the two functions announced
(`Node::known()` gives them), and a message against the state of its session.
[Limits](#limits) says what they do not cover.

When the mandatory IEs of a table differ between interfaces, the struct has one
constructor for each, such as `CreatePdr::new_sxa()` and `new_n4()`.

```rust
use std::net::Ipv4Addr;

use oxirush_pfcp::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A modification that creates PDR 3 and also removes it, and a second Create PDR
    // without its PDR ID
    let mut pdr = CreatePdr::new_n4(PdrId::new(3), Precedence::new(32), Pdi::new(SourceInterface::new(SourceInterfaceValue::Core)))
        .with_far_id(FarId::new(3));
    let modification = SessionModificationRequest::default()
        .with_create_pdr(pdr.clone())
        .with_remove_pdr(RemovePdr::new(PdrId::new(3)));
    pdr.pdr_id = None;
    let request = Message::session(0x2001, 8, modification.with_create_pdr(pdr));
    let deviations: Vec<String> = request.check(Interfaces::N4).iter().map(ToString::to_string).collect();
    assert_eq!(deviations, [
        r#"the mandatory PDR ID is missing (TS 29.244 7.5.2.2-1), at /pfcp/Create PDR/1/PDR ID: the answer is "Conditional IE missing""#,
        "the message changes PDR 3 more than once (TS 29.244 6.3.3.2), at /pfcp",
    ]);

    // Build the response from the first deviation that has a Cause
    let deviation = request.check(Interfaces::N4).into_iter().find(|deviation| deviation.cause.is_some()).ok_or("none")?;
    let response = SessionModificationResponse {
        cause: deviation.cause.map(Cause::new),
        offending_ie: deviation.offending_ie().map(OffendingIe::new),
        ..Default::default()
    };
    let answer = Message::session(0x1001, request.header.sequence, response);
    assert_eq!(answer.to_string(), "PFCP Session Modification Response (SEID 0x1001, sequence 8)");
    assert_eq!(hex::encode(answer.encode()?), "213500170000000000001001000008000013000143002800020038");
    assert!(answer.check(Interfaces::N4).is_empty());
    Ok(())
}
```

## A message as JSON

With the `tree` feature, a message converts to a tree that prints as JSON and
uses the names of the specification, and a tree converts back to a message.
The tree contains keys and passwords, such as the Tunnel Password. `Debug` and
the tree errors hide them, but the tree itself does not: do not log it.

```rust
use oxirush_pfcp::Message;
use oxirush_pfcp::tree;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let octets = hex::decode("2133002b000000000000100100000700003c0005000a00000200130001010039000d0200000000000020010a000002")?;
    let tree = Message::decode(&octets)?.to_tree();
    assert_eq!(tree, tree!({
        "message": "PFCP Session Establishment Response",
        "header": {"SEID": 4097, "Sequence Number": 7},
        "ies": {
            "Node ID": "10.0.0.2",
            "Cause": "Request accepted (success)",
            "UP F-SEID": {"V4": true, "SEID": 8193, "IPv4 address": "10.0.0.2"}
        }
    }));

    // A tree written by hand: names match without case or punctuation
    let written = tree!({
        "message": "PFCP Heartbeat Request",
        "header": {"Sequence Number": 9},
        "ies": {"recovery time stamp": 3_900_000_000u32}
    });
    let heartbeat = Message::from_tree(&written)?;
    assert_eq!(heartbeat.to_string(), "PFCP Heartbeat Request (sequence 9)");
    assert_eq!(hex::encode(heartbeat.encode()?), "2001000c0000090000600004e8754700");
    Ok(())
}
```

A tree lists the IEs in the order of the tables of the specification. The
encoded message keeps the order in which the IEs were received.

## Read and edit by path

`paths::select` and `paths::set` read and change the tree of a message by path.
`/pfcp` is the list of IEs, a repeated IE is addressed by its position, and `*`
matches every entry. Names are not case sensitive. The documentation of `paths`
describes the syntax.

```rust
use oxirush_pfcp::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let octets = hex::decode("2133002b000000000000100100000700003c0005000a00000200130001010039000d0200000000000020010a000002")?;
    let mut tree = Message::decode(&octets)?.to_tree();
    assert_eq!(paths::select(&tree, "/pfcp/up f-seid/ipv4 address")?, [&tree!("10.0.0.2")]);
    paths::set(&mut tree, "/pfcp/Cause", "No resources available")?;
    let edited = Message::from_tree(&tree)?;
    assert_eq!(
        hex::encode(edited.encode()?),
        "2133002b000000000000100100000700003c0005000a000002001300014b0039000d0200000000000020010a000002",
    );
    Ok(())
}
```

One IE alone has its form in Table 8.1.2-1, `ie_type_info()`: `takes()` says
what the tree of its value takes, member by member, and `tree_of()` gives the
tree of its octets, those after the Length, as a message has it.

```rust
use oxirush_pfcp::ie_type_info;
use oxirush_pfcp::tree::Takes;
use oxirush_pfcp::tree;

fn main() {
    let pdn_type = ie_type_info(113).unwrap();
    let Some(Takes::Members(Some("PDN Type"), members)) = pdn_type.takes() else {
        panic!("PDN Type is written by its one field");
    };
    // A name of Table 8.2.79-1, or a number of its three bits.
    let ("PDN Type", Takes::OneOf([Takes::Named(names), Takes::Number(7)])) = members[0] else {
        panic!("{:?}", members[0]);
    };
    assert_eq!(names[0], "IPv4");
    assert_eq!(pdn_type.tree_of(&[1], None), Some(tree!("IPv4")));
}
```

## Limits

- `check()` follows TS 29.244 V19.6.0: IEs of a later release are kept as
  octets and reported as unknown.
- `check()` does not check what only the sender knows (its intent, what the
  UE supports), nor that UR-SEQN values increase: usage reports can arrive
  out of order.
- A SEID of 0 is accepted where the sender may not know its peer's SEID yet.
- `check()` does not look into a DNS Query/Response Filter or the content
  of containers.
- `encode()` writes malformed messages on purpose, for tests: it refuses
  only a value that would not decode back to itself.
- A `Node` is one PFCP entity: a request for a session of another SMF of its
  set (§5.22) reaches the application as `Received::stranger`.

## Performance

| Operation, a Session Establishment Request of 16 PDRs (2,824 octets) | Time | go-pfcp v0.0.24, time over this crate's |
|---|---|---|
| `decode` | 15.7 µs | 4.4x |
| `decode`, then read each value | 16.7 µs | 8.8x |
| `encode` | 7.4 µs | 12.2x |
| `check` | 32.2 µs | |
| `to_tree`, `from_tree` | 51.9 µs, 198.2 µs | |

Medians of ten rounds, the two in turns, on one core of an Intel Xeon
E5-2680 v4 (a KVM guest, Linux 7.0, Rust 1.100.0, Go 1.27.4), at cdf4a13 on
2026-11-15; the ten times of the two do not overlap.
[`benches/README.md`](benches/README.md) has the other messages, the
allocations, and the commands that reproduce each figure.

## Tests and fuzzing

```sh
cargo test --all-features
cargo run --example fuzz_dictionary > fuzz/pfcp.dict
cargo +nightly fuzz run tree -- -max_total_time=60 -dict=fuzz/pfcp.dict
```

[`tests/README.md`](tests/README.md) describes what each test checks against
the specification and against lab captures, and what the crate reports in
other implementations. The fuzz targets are in `fuzz/`. One of them,
`differential`, compares the crate with rs-pfcp 0.5.0, an independent codec, on
the same input.

A pull request comes with a test for what it changes. Sign off your commits
(`git commit -s`): by contributing you agree to the [Developer Certificate
of Origin](https://developercertificate.org/). [SECURITY.md](SECURITY.md)
says how to report a vulnerability.

## The OxiRush family

- [oxirush-utils](https://github.com/linouxis9/oxirush-utils): the 3GPP identities, the JSON tree with its paths, and the fields and tables that the codecs are laid out on.
- [oxirush-aper](https://github.com/linouxis9/oxirush-aper): aligned PER, the runtime of the NGAP and S1AP codecs.
- [oxirush-nas](https://github.com/linouxis9/oxirush-nas): the NAS messages of 5GS and EPS.
- [oxirush-security](https://github.com/linouxis9/oxirush-security): NAS security, AKA and the derivation of keys.
- [oxirush-ngap](https://github.com/linouxis9/oxirush-ngap): NGAP, between a gNB and an AMF.
- [oxirush-s1ap](https://github.com/linouxis9/oxirush-s1ap): S1AP, between an eNB and an MME.
- [oxirush-gtp-u](https://github.com/linouxis9/oxirush-gtp-u): GTP-U tunnels, with a user-plane test peer.
- [oxirush-pfcp](https://github.com/linouxis9/oxirush-pfcp): PFCP, between the control plane and the user plane.
- [oxirush-sctp](https://github.com/linouxis9/oxirush-sctp): SCTP sockets, which carry NGAP and S1AP.

## License

Copyright 2026 Valentin D'Emmanuele. Licensed under the Apache License,
Version 2.0: see [LICENSE](LICENSE).
