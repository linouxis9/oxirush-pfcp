// The Rust blocks of README.md, each as a function, with what the README shows under
// each: `../oxirush-aper/protocols/tests/readme.py` writes this file from the README and
// says how. Do not edit it.
#![cfg(all(feature = "serde", feature = "endpoint"))]
#![allow(unused)]

use std::cell::RefCell;

thread_local!(static PRINTED: RefCell<String> = const { RefCell::new(String::new()) });

// What a block prints is kept, to be compared with what the README shows. The line
// is written before it is kept, so that `?` in what is printed returns from the block.
macro_rules! print {
    ($($argument:tt)*) => {{
        let text = format!($($argument)*);
        PRINTED.with(|printed| printed.borrow_mut().push_str(&text))
    }};
}

macro_rules! println {
    () => {
        print!("\n")
    };
    ($($argument:tt)*) => {{
        let line = format!($($argument)*);
        print!("{line}\n")
    }};
}

/// What `block` prints.
fn printed(block: fn()) -> String {
    PRINTED.with(|printed| printed.borrow_mut().clear());
    block();
    PRINTED.with(|printed| printed.take())
}

#[test]
fn each_block_prints_what_the_readme_shows() {
    let mut differences = String::new();
    for (rank, (block, shown)) in (1..).zip(BLOCKS) {
        let printed = printed(*block);
        if printed != *shown {
            differences += &format!("the Rust block {rank} of README.md prints:\n{printed}");
            differences += &format!("and the README shows:\n{shown}\n");
        }
    }
    assert!(differences.is_empty(), "{differences}");
}

/// Each Rust block of README.md, by its rank, and what the README shows under it.
#[rustfmt::skip]
const BLOCKS: &[(fn(), &str)] = &[
    (block_1, r#"21320069000000000000000000000700003c0005000a0000010039000d0200000000000010010a00000100010024003800020001001d0004000000ff0002000a00140001000015000105006c00040000000100030017006c000400000001002c0002020000040005002a000101
PFCP Session Establishment Request (SEID 0x0, sequence 7): 1 PDR, from Access
0 deviations on N4
on Sxa: Precedence is not on this interface (TS 29.244 7.5.2.2-1), at /pfcp/Create PDR/0/Precedence
"#),
    (block_2, r#"to 10.0.0.2:8805: 25 octets, again at Some(3s)
the UPF: PFCP Association Setup Request (sequence 1)
the SMF: associated with 10.0.0.2:8805
the SMF: PFCP Association Setup Response (sequence 1)
no more timer: Some(60s)
"#),
    (block_3, r#"PFCP Heartbeat Response (sequence 1)
"#),
    (block_4, r#"PFCP Session Establishment Response (SEID 0x1001, sequence 7): Request accepted (success) (1), UP F-SEID 0x2001 at Some(10.0.0.2)
accepted: true
"#),
    (block_5, r#"the mandatory PDR ID is missing (TS 29.244 7.5.2.2-1), at /pfcp/Create PDR/1/PDR ID: the answer is "Conditional IE missing"
the message changes PDR 3 more than once (TS 29.244 6.3.3.2), at /pfcp
PFCP Session Modification Response (SEID 0x1001, sequence 8): 213500170000000000001001000008000013000143002800020038
0 deviations in the answer
"#),
    (block_6, r#"{
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
PFCP Heartbeat Request (sequence 9): 2001000c0000090000600004e8754700
"#),
    (block_7, r#"[String("10.0.0.2")]
2133002b000000000000100100000700003c0005000a000002001300014b0039000d0200000000000020010a000002
"#),
];

/// The Rust block 1 of README.md.
#[rustfmt::skip]
fn block_1() {
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
        println!("{}", hex::encode(&octets));

        // The UPF decodes it and reads its IEs as typed fields
        let message = Message::decode(&octets)?;
        if let Body::SessionEstablishmentRequest(request) = &message.body {
            let pdi = request.create_pdr[0].pdi.as_ref().ok_or("no PDI")?;
            let from = pdi.source_interface.as_ref().ok_or("no Source Interface")?;
            println!("{message}: {} PDR, from {}", request.create_pdr.len(), from.interface_value);
        }

        // check() reports nothing on N4. On Sxa, a Create PDR has no Precedence
        println!("{} deviations on N4", message.check(Interfaces::N4).len());
        for deviation in message.check(Interfaces::SXA) {
            println!("on Sxa: {deviation}");
        }
        Ok(())
    }

    main().unwrap();
}

/// The Rust block 2 of README.md.
#[rustfmt::skip]
fn block_2() {
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
        println!("to {}: {} octets, again at {:?}", datagram.to, datagram.octets.len(), smf.poll_timeout());

        // The UPF receives the datagram, and the application answers the request
        upf.handle_datagram(now, smf_address, &datagram.octets);
        while let Some(event) = upf.poll_event() {
            if let Event::Request { request, message } = event {
                println!("the UPF: {message}");
                let accepted = Cause::new(CauseValue::RequestAccepted);
                upf.respond(now, &request, AssociationSetupResponse::new(upf_id.clone(), accepted, RecoveryTimeStamp::new(3_900_000_000)))?;
            }
        }

        // The SMF receives the response. The request is complete and the association exists
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

    main().unwrap();
}

/// The Rust block 3 of README.md.
#[rustfmt::skip]
fn block_3() {
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
            println!("{response}");
            Ok(())
        })
    }

    main().unwrap();
}

/// The Rust block 4 of README.md.
#[rustfmt::skip]
fn block_4() {
    use oxirush_pfcp::*;

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        // The response of a UPF: its Node ID, the Cause and the F-SEID that it chose
        let octets = hex::decode("2133002b000000000000100100000700003c0005000a00000200130001010039000d0200000000000020010a000002")?;
        let message = Message::decode(&octets)?;
        let Body::SessionEstablishmentResponse(response) = &message.body else { return Err("another message".into()) };
        let cause = response.cause.as_ref().ok_or("no Cause")?.value;
        let up_f_seid = response.up_f_seid.as_ref().ok_or("no F-SEID")?;
        println!("{message}: {cause} ({}), UP F-SEID {:#x} at {:?}", cause.value(), up_f_seid.seid, up_f_seid.ipv4);
        println!("accepted: {}", cause == CauseValue::RequestAccepted);
        Ok(())
    }

    main().unwrap();
}

/// The Rust block 5 of README.md.
#[rustfmt::skip]
fn block_5() {
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
        for deviation in request.check(Interfaces::N4) {
            println!("{deviation}");
        }

        // Build the response from the first deviation that has a Cause
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

    main().unwrap();
}

/// The Rust block 6 of README.md.
#[rustfmt::skip]
fn block_6() {
    use oxirush_pfcp::Message;
    use oxirush_pfcp::tree;

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        let octets = hex::decode("2133002b000000000000100100000700003c0005000a00000200130001010039000d0200000000000020010a000002")?;
        let tree = Message::decode(&octets)?.to_tree();
        println!("{tree:#}");

        // A tree written by hand: names match without case or punctuation
        let written = tree!({
            "message": "PFCP Heartbeat Request",
            "header": {"Sequence Number": 9},
            "ies": {"recovery time stamp": 3_900_000_000u32}
        });
        let heartbeat = Message::from_tree(&written)?;
        println!("{heartbeat}: {}", hex::encode(heartbeat.encode()?));
        Ok(())
    }

    main().unwrap();
}

/// The Rust block 7 of README.md.
#[rustfmt::skip]
fn block_7() {
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

    main().unwrap();
}
