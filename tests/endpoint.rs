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

//! Two endpoints on the loopback: an SMF and a UPF that set up an association and a
//! session, and a request that no one answers.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use oxirush_pfcp::endpoint::*;
use oxirush_pfcp::node::*;
use oxirush_pfcp::*;

const ANY: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

fn config(function: Function) -> NodeConfig {
    NodeConfig { t1: Duration::from_millis(100), n1: 2, heartbeat: None, ..NodeConfig::new(NodeId::Ipv4(Ipv4Addr::LOCALHOST), function, 7) }
}

fn accepted() -> Cause {
    Cause::new(CauseValue::RequestAccepted)
}

#[tokio::test]
async fn an_smf_and_a_upf_set_up_an_association_and_a_session() {
    let smf = Endpoint::bind(ANY, config(Function::Cp)).await.unwrap();
    let mut upf = Endpoint::bind(ANY, config(Function::Up)).await.unwrap();
    let upf_address = upf.local_addr();

    // The UPF answers what comes
    let answering = tokio::spawn(async move {
        for _ in 0..2 {
            let incoming = upf.incoming().await.unwrap();
            match &incoming.message.body {
                Body::AssociationSetupRequest(_) => {
                    let response = AssociationSetupResponse::new(NodeId::Ipv4(Ipv4Addr::LOCALHOST), accepted(), RecoveryTimeStamp::new(7));
                    incoming.respond(response).await.unwrap();
                }
                Body::SessionEstablishmentRequest(_) => {
                    let seid = upf.new_session(incoming.request.from).await.unwrap();
                    let f_seid = FSeid { v4: true, seid: Some(seid), ipv4: Some(Ipv4Addr::LOCALHOST), ..Default::default() };
                    let response = SessionEstablishmentResponse::new(NodeId::Ipv4(Ipv4Addr::LOCALHOST), accepted()).with_up_f_seid(f_seid);
                    incoming.respond(response).await.unwrap();
                }
                other => panic!("{other:?}"),
            }
        }
        upf
    });

    let setup = AssociationSetupRequest::new(NodeId::Ipv4(Ipv4Addr::LOCALHOST), RecoveryTimeStamp::new(7));
    let response = smf.request(upf_address, Message { header: Header::node(0), body: setup.into() }).await.unwrap();
    assert_eq!(response.body.cause(), Some(CauseValue::RequestAccepted));

    let seid = smf.new_session(upf_address).await.unwrap();
    let f_seid = FSeid { v4: true, seid: Some(seid), ipv4: Some(Ipv4Addr::LOCALHOST), ..Default::default() };
    let pdr = CreatePdr::new_n4(PdrId::new(1), Precedence::new(1), Pdi::new(SourceInterface::new(SourceInterfaceValue::Access)));
    let far = CreateFar::new(FarId::new(1), ApplyAction { forw: true, ..Default::default() });
    let request = SessionEstablishmentRequest::new_n4(NodeId::Ipv4(Ipv4Addr::LOCALHOST), f_seid, pdr, far);
    let response = smf.request(upf_address, Message { header: Header::session(0, 0), body: request.into() }).await.unwrap();
    assert_eq!(response.header.seid, Some(seid), "to the SMF's SEID");
    let upf = answering.await.unwrap();
    assert_eq!(upf.statistics().incoming_dropped.load(std::sync::atomic::Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_request_without_an_answer_times_out_after_n1() {
    let smf = Endpoint::bind(ANY, config(Function::Cp)).await.unwrap();
    // A socket that takes the datagrams and answers none
    let silent = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    let heartbeat = Message { header: Header::node(0), body: HeartbeatRequest::new(RecoveryTimeStamp::new(7)).into() };
    let result = smf.request(silent.local_addr().unwrap(), heartbeat).await;
    assert_eq!(result, Err(EndpointError::Timeout));
    // The first and the N1 = 2 retransmissions, the same octets
    let mut buffer = [0; 64];
    let mut datagrams = Vec::new();
    while let Ok(Ok((length, _))) = tokio::time::timeout(Duration::from_millis(50), silent.recv_from(&mut buffer)).await {
        datagrams.push(buffer[..length].to_vec());
    }
    assert_eq!(datagrams.len(), 3);
    assert!(datagrams.windows(2).all(|pair| pair[0] == pair[1]));
}

fn setup(sequence: u32) -> Vec<u8> {
    let request = AssociationSetupRequest::new(NodeId::Ipv4(Ipv4Addr::LOCALHOST), RecoveryTimeStamp::new(1));
    Message { header: Header::node(sequence), body: request.into() }.encode().unwrap()
}

/// A request that the endpoint drops for a full queue comes in again with its
/// retransmission, and is answered then.
#[tokio::test]
async fn a_request_dropped_for_a_full_queue_comes_again() {
    use std::sync::atomic::Ordering;
    let queues = Queues { commands: 16, incoming: 1, events: 16 };
    let mut upf = Endpoint::bind_with(ANY, config(Function::Up), queues).await.unwrap();
    let peer = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    peer.send_to(&setup(1), upf.local_addr()).await.unwrap();
    peer.send_to(&setup(2), upf.local_addr()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(upf.statistics().incoming_dropped.load(Ordering::Relaxed), 1);
    assert_eq!(upf.incoming().await.unwrap().request.sequence, 1);
    peer.send_to(&setup(2), upf.local_addr()).await.unwrap();
    let second = tokio::time::timeout(Duration::from_millis(500), upf.incoming()).await.expect("the retransmission").unwrap();
    assert_eq!(second.request.sequence, 2);
    second.respond(AssociationSetupResponse::new(NodeId::Ipv4(Ipv4Addr::LOCALHOST), accepted(), RecoveryTimeStamp::new(7))).await.unwrap();
    let mut buffer = [0; 256];
    let (length, _) = tokio::time::timeout(Duration::from_millis(500), peer.recv_from(&mut buffer)).await.unwrap().unwrap();
    assert_eq!(Message::decode(&buffer[..length]).unwrap().header.sequence, 2);
}

/// An answer that does not encode, or that is not the request's response, is an error
/// of `respond`.
#[tokio::test]
async fn an_answer_that_does_not_encode_is_an_error() {
    let mut upf = Endpoint::bind(ANY, config(Function::Up)).await.unwrap();
    let peer = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    peer.send_to(&setup(5), upf.local_addr()).await.unwrap();
    let incoming = upf.incoming().await.unwrap();
    let broken = AlternativeSmfIpAddress { v4: true, ..Default::default() };
    let response = AssociationSetupResponse::new(NodeId::Ipv4(Ipv4Addr::LOCALHOST), accepted(), RecoveryTimeStamp::new(7)).with_alternative_smf_ip_address(broken);
    assert!(matches!(incoming.respond(response).await, Err(EndpointError::Node(NodeError::Encode(_)))));
    peer.send_to(&setup(6), upf.local_addr()).await.unwrap();
    let incoming = upf.incoming().await.unwrap();
    let wrong = HeartbeatResponse::new(RecoveryTimeStamp::new(7));
    assert_eq!(incoming.respond(wrong).await, Err(EndpointError::Node(NodeError::WrongResponse)));
}

/// A heartbeat interval beyond what an Instant holds is never, and the task goes on.
#[tokio::test]
async fn a_heartbeat_of_never() {
    let smf = Endpoint::bind(ANY, NodeConfig { heartbeat: Some(Duration::MAX), ..config(Function::Cp) }).await.unwrap();
    let mut upf = Endpoint::bind(ANY, config(Function::Up)).await.unwrap();
    let upf_address = upf.local_addr();
    let answering = tokio::spawn(async move {
        for _ in 0..2 {
            let incoming = upf.incoming().await.unwrap();
            let response = AssociationSetupResponse::new(NodeId::Ipv4(Ipv4Addr::LOCALHOST), accepted(), RecoveryTimeStamp::new(7));
            if matches!(incoming.message.body, Body::AssociationSetupRequest(_)) {
                incoming.respond(response).await.unwrap();
            }
        }
        upf
    });
    let request = AssociationSetupRequest::new(NodeId::Ipv4(Ipv4Addr::LOCALHOST), RecoveryTimeStamp::new(7));
    smf.request(upf_address, Message { header: Header::node(0), body: request.clone().into() }).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let heartbeat = Message { header: Header::node(0), body: HeartbeatRequest::new(RecoveryTimeStamp::new(7)).into() };
    assert!(smf.request(upf_address, heartbeat).await.is_ok());
    smf.request(upf_address, Message { header: Header::node(0), body: request.into() }).await.unwrap();
    answering.await.unwrap();
}

/// A request whose future the caller drops is sent no more.
#[tokio::test]
async fn a_dropped_request_is_cancelled() {
    let smf = Endpoint::bind(ANY, config(Function::Cp)).await.unwrap();
    let silent = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    let heartbeat = Message { header: Header::node(0), body: HeartbeatRequest::new(RecoveryTimeStamp::new(7)).into() };
    let _ = tokio::time::timeout(Duration::from_millis(10), smf.request(silent.local_addr().unwrap(), heartbeat)).await;
    let mut buffer = [0; 64];
    let mut count = 0;
    while let Ok(Ok(_)) = tokio::time::timeout(Duration::from_millis(250), silent.recv_from(&mut buffer)).await {
        count += 1;
    }
    assert_eq!(count, 1, "the first datagram only");
}

/// `close` frees the socket before it returns; an `Incoming` that the caller holds does
/// not keep the endpoint running.
#[tokio::test]
async fn close_frees_the_socket() {
    let mut upf = Endpoint::bind(ANY, config(Function::Up)).await.unwrap();
    let address = upf.local_addr();
    let peer = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    peer.send_to(&setup(5), address).await.unwrap();
    let held = upf.incoming().await.unwrap();
    upf.close().await;
    let again = std::net::UdpSocket::bind(address);
    assert!(again.is_ok(), "{again:?}");
    let response = AssociationSetupResponse::new(NodeId::Ipv4(Ipv4Addr::LOCALHOST), accepted(), RecoveryTimeStamp::new(7));
    assert_eq!(held.respond(response).await, Err(EndpointError::Closed));
}
