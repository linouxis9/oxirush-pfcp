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

fn accepted() -> Cause<'static> {
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
    let pdr = CreatePdr::new(PdrId::new(1), Precedence::new(1), Pdi::new(SourceInterface::new(SourceInterfaceValue::Access)));
    let far = CreateFar::new(FarId::new(1), ApplyAction { forw: true, ..Default::default() });
    let request = SessionEstablishmentRequest::new(NodeId::Ipv4(Ipv4Addr::LOCALHOST), f_seid, pdr, far);
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
