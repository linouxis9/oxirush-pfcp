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
    NodeConfig {
        t1: Duration::from_millis(100),
        n1: 2,
        heartbeat: None,
        // Each endpoint on a port of its own.
        request_port: None,
        ..NodeConfig::new(NodeId::Ipv4(Ipv4Addr::LOCALHOST), function, 7)
    }
}

fn accepted() -> Cause {
    Cause::new(CauseValue::RequestAccepted)
}

#[tokio::test]
async fn an_smf_and_a_upf_set_up_an_association_and_a_session() {
    let smf_endpoint = Endpoint::bind(ANY, config(Function::Cp)).await.unwrap();
    let smf = smf_endpoint.handle();
    let mut upf = Endpoint::bind(ANY, config(Function::Up)).await.unwrap();
    let upf_address = upf.local_addr();
    let upf_handle = upf.handle();

    // The UPF answers what comes
    let answering = tokio::spawn(async move {
        for _ in 0..2 {
            let incoming = upf.incoming().await.unwrap();
            match &incoming.message.body {
                Body::AssociationSetupRequest(_) => {
                    let response = AssociationSetupResponse::new(
                        NodeId::Ipv4(Ipv4Addr::LOCALHOST),
                        accepted(),
                        RecoveryTimeStamp::new(7),
                    );
                    incoming.respond(response).await.unwrap();
                }
                Body::SessionEstablishmentRequest(_) => {
                    let seid = upf_handle.with(|node| node.new_session()).await.unwrap();
                    let f_seid = FSeid {
                        v4: true,
                        seid: Some(seid),
                        ipv4: Some(Ipv4Addr::LOCALHOST),
                        ..Default::default()
                    };
                    let response = SessionEstablishmentResponse::new(
                        NodeId::Ipv4(Ipv4Addr::LOCALHOST),
                        accepted(),
                    )
                    .with_up_f_seid(f_seid);
                    incoming.respond(response).await.unwrap();
                }
                other => panic!("{other:?}"),
            }
        }
        upf
    });

    // Each step within its bound: a node that does not associate, or does not answer, fails
    // the test, and does not hang it.
    let setup =
        AssociationSetupRequest::new(NodeId::Ipv4(Ipv4Addr::LOCALHOST), RecoveryTimeStamp::new(7));
    let response = within(smf.request(
        upf_address,
        Message {
            header: Header::node(0),
            body: setup.into(),
        },
    ))
    .await
    .unwrap();
    assert_eq!(response.body.cause(), Some(CauseValue::RequestAccepted));

    let seid = smf.with(|node| node.new_session()).await.unwrap();
    let f_seid = FSeid {
        v4: true,
        seid: Some(seid),
        ipv4: Some(Ipv4Addr::LOCALHOST),
        ..Default::default()
    };
    let pdr = CreatePdr::new_n4(
        PdrId::new(1),
        Precedence::new(1),
        Pdi::new(SourceInterface::new(SourceInterfaceValue::Access)),
    );
    let far = CreateFar::new(
        FarId::new(1),
        ApplyAction {
            forw: true,
            ..Default::default()
        },
    );
    let request =
        SessionEstablishmentRequest::new_n4(NodeId::Ipv4(Ipv4Addr::LOCALHOST), f_seid, pdr, far);
    let response = within(smf.request(
        upf_address,
        Message {
            header: Header::session(0, 0),
            body: request.into(),
        },
    ))
    .await
    .unwrap();
    assert_eq!(response.header.seid, Some(seid), "to the SMF's SEID");
    let upf = within(answering).await.unwrap();
    assert_eq!(
        upf.statistics()
            .incoming_dropped
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

/// Poll a future once, and drop it: a caller that cancels it before the task of the
/// endpoint runs.
async fn once<F: std::future::Future>(future: F) -> Option<F::Output> {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|context| {
        std::task::Poll::Ready(match future.as_mut().poll(context) {
            std::task::Poll::Ready(output) => Some(output),
            std::task::Poll::Pending => None,
        })
    })
    .await
}

/// Answer an Association Setup Request, a Node Report Request and a Session
/// Establishment Request of the peer.
async fn answer(handle: &Handle, incoming: Incoming) {
    let node_id = NodeId::Ipv4(Ipv4Addr::LOCALHOST);
    let result = match &incoming.message.body {
        Body::AssociationSetupRequest(_) => {
            let response =
                AssociationSetupResponse::new(node_id, accepted(), RecoveryTimeStamp::new(7));
            incoming.respond(response).await
        }
        Body::NodeReportRequest(_) => {
            incoming
                .respond(NodeReportResponse::new(node_id, accepted()))
                .await
        }
        Body::SessionEstablishmentRequest(_) => {
            let seid = handle.with(|node| node.new_session()).await.unwrap();
            let f_seid = FSeid {
                v4: true,
                seid: Some(seid),
                ipv4: Some(Ipv4Addr::LOCALHOST),
                ..Default::default()
            };
            let response =
                SessionEstablishmentResponse::new(node_id, accepted()).with_up_f_seid(f_seid);
            incoming.respond(response).await
        }
        other => panic!("{other:?}"),
    };
    result.unwrap();
}

/// Each endpoint waits for the response of its own request while it answers the peer's,
/// which waits for it: a handle beside the incoming requests.
#[tokio::test]
async fn both_ways_at_once() {
    let mut smf = Endpoint::bind(ANY, config(Function::Cp)).await.unwrap();
    let mut upf = Endpoint::bind(ANY, config(Function::Up)).await.unwrap();
    let (smf_address, upf_address) = (smf.local_addr(), upf.local_addr());
    let node_id = NodeId::Ipv4(Ipv4Addr::LOCALHOST);
    let (smf_handle, upf_handle) = (smf.handle(), upf.handle());
    let setup = AssociationSetupRequest::new(node_id.clone(), RecoveryTimeStamp::new(7));
    let setup = smf_handle.request(
        upf_address,
        Message {
            header: Header::node(0),
            body: setup.into(),
        },
    );
    tokio::pin!(setup);
    loop {
        tokio::select! {
            response = &mut setup => {
                assert_eq!(response.unwrap().body.cause(), Some(CauseValue::RequestAccepted));
                break;
            }
            Some(incoming) = upf.incoming() => answer(&upf_handle, incoming).await,
        }
    }
    // The UPF's Node Report and the SMF's establishment, at once
    let report = NodeReportRequest::new(
        node_id.clone(),
        NodeReportType {
            uprr: true,
            ..Default::default()
        },
    );
    let report = upf_handle.request(
        smf_address,
        Message {
            header: Header::node(0),
            body: report.into(),
        },
    );
    let seid = smf_handle.with(|node| node.new_session()).await.unwrap();
    let f_seid = FSeid {
        v4: true,
        seid: Some(seid),
        ipv4: Some(Ipv4Addr::LOCALHOST),
        ..Default::default()
    };
    let pdr = CreatePdr::new_n4(
        PdrId::new(1),
        Precedence::new(1),
        Pdi::new(SourceInterface::new(SourceInterfaceValue::Access)),
    );
    let far = CreateFar::new(
        FarId::new(1),
        ApplyAction {
            forw: true,
            ..Default::default()
        },
    );
    let establishment = smf_handle.request(
        upf_address,
        Message {
            header: Header::session(0, 0),
            body: SessionEstablishmentRequest::new_n4(node_id, f_seid, pdr, far).into(),
        },
    );
    tokio::pin!(report, establishment);
    let (mut reported, mut established) = (false, false);
    while !(reported && established) {
        tokio::select! {
            response = &mut report, if !reported => {
                assert_eq!(response.unwrap().body.cause(), Some(CauseValue::RequestAccepted));
                reported = true;
            }
            response = &mut establishment, if !established => {
                assert_eq!(response.unwrap().header.seid, Some(seid));
                established = true;
            }
            Some(incoming) = upf.incoming() => answer(&upf_handle, incoming).await,
            Some(incoming) = smf.incoming() => answer(&smf_handle, incoming).await,
        }
    }
    // The state of the node, and its lists, through a handle
    let state = smf_handle
        .with(move |node| {
            let associations = node.associations().count();
            let sessions: Vec<u64> = node.sessions().map(|(seid, _)| seid).collect();
            let listed = (node.loads().count(), node.overloads().count());
            (
                node.association(upf_address).is_some(),
                associations,
                sessions,
                listed,
                node.counters(),
            )
        })
        .await
        .unwrap();
    assert_eq!(state, (true, 1, vec![seid], (0, 0), Counters::default()));
    smf_handle
        .with(|node| node.reserve_sequence())
        .await
        .unwrap()
        .unwrap();
    assert!(
        smf_handle
            .with(move |node| node.end_association(upf_address))
            .await
            .unwrap()
    );
    assert!(
        smf_handle
            .with(move |node| node.session(seid).is_none())
            .await
            .unwrap()
    );
    assert!(matches!(smf.event().await, Some(Event::Associated { .. })));
    assert!(matches!(smf.event().await, Some(Event::Released { .. })));
    smf.close().await;
    assert_eq!(
        smf_handle.with(|node| node.counters()).await,
        Err(EndpointError::Closed),
        "a handle of an endpoint that has ended"
    );
}

/// A probe answers through its Incoming any number of times: the first alone changes
/// the node.
#[tokio::test]
async fn a_probe_answers_twice() {
    let mut upf = Endpoint::bind(ANY, config(Function::Up)).await.unwrap();
    let peer = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    peer.send_to(&setup(4), upf.local_addr()).await.unwrap();
    let mut incoming = upf.incoming().await.unwrap();
    let answer = Message {
        header: Header::node(4),
        body: AssociationSetupResponse::new(
            NodeId::Ipv4(Ipv4Addr::LOCALHOST),
            accepted(),
            RecoveryTimeStamp::new(7),
        )
        .into(),
    };
    for _ in 0..2 {
        incoming
            .respond_message(answer.clone(), Delivery::Send)
            .await
            .unwrap();
    }
    let peer_address = peer.local_addr().unwrap();
    let handle = upf.handle();
    let associated = handle.with(move |node| node.association(peer_address).is_some());
    assert!(associated.await.unwrap());
    assert!(matches!(upf.event().await, Some(Event::Associated { .. })));
    let quiet = tokio::time::timeout(Duration::from_millis(100), upf.event()).await;
    assert!(quiet.is_err(), "one association: {quiet:?}");
}

#[tokio::test]
async fn a_request_without_an_answer_times_out_after_n1() {
    let smf_endpoint = Endpoint::bind(ANY, config(Function::Cp)).await.unwrap();
    let smf = smf_endpoint.handle();
    // A socket that takes the datagrams and answers none
    let silent = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    let heartbeat = Message {
        header: Header::node(0),
        body: HeartbeatRequest::new(RecoveryTimeStamp::new(7)).into(),
    };
    // Within its bound: a node whose timer does not run fails the test, and does not hang it.
    let result = within(smf.request(silent.local_addr().unwrap(), heartbeat)).await;
    assert_eq!(result, Err(EndpointError::Timeout));
    // The first and the N1 = 2 retransmissions, the same octets
    let mut buffer = [0; 64];
    let mut datagrams = Vec::new();
    while let Ok(Ok((length, _))) =
        tokio::time::timeout(Duration::from_millis(50), silent.recv_from(&mut buffer)).await
    {
        datagrams.push(buffer[..length].to_vec());
    }
    assert_eq!(datagrams.len(), 3);
    assert!(datagrams.windows(2).all(|pair| pair[0] == pair[1]));
}

fn setup(sequence: u32) -> Vec<u8> {
    let request =
        AssociationSetupRequest::new(NodeId::Ipv4(Ipv4Addr::LOCALHOST), RecoveryTimeStamp::new(1));
    Message {
        header: Header::node(sequence),
        body: request.into(),
    }
    .encode()
    .unwrap()
}

/// A request that the endpoint drops for a full queue comes in again with its
/// retransmission, and is answered then.
#[tokio::test]
async fn a_request_dropped_for_a_full_queue_comes_again() {
    use std::sync::atomic::Ordering;
    let queues = Queues {
        commands: 16,
        incoming: 1,
        events: 16,
    };
    let mut upf = Endpoint::bind_with(ANY, config(Function::Up), queues)
        .await
        .unwrap();
    let peer = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    peer.send_to(&setup(1), upf.local_addr()).await.unwrap();
    peer.send_to(&setup(2), upf.local_addr()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(upf.statistics().incoming_dropped.load(Ordering::Relaxed), 1);
    assert_eq!(upf.incoming().await.unwrap().request.sequence, 1);
    peer.send_to(&setup(2), upf.local_addr()).await.unwrap();
    let second = tokio::time::timeout(Duration::from_millis(500), upf.incoming())
        .await
        .expect("the retransmission")
        .unwrap();
    assert_eq!(second.request.sequence, 2);
    second
        .respond(AssociationSetupResponse::new(
            NodeId::Ipv4(Ipv4Addr::LOCALHOST),
            accepted(),
            RecoveryTimeStamp::new(7),
        ))
        .await
        .unwrap();
    let mut buffer = [0; 256];
    let (length, _) = tokio::time::timeout(Duration::from_millis(500), peer.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        Message::decode(&buffer[..length]).unwrap().header.sequence,
        2
    );
}

/// What the node drops to bound what it keeps is in the statistics of the endpoint.
#[tokio::test]
async fn a_request_refused_by_a_full_node_is_counted() {
    use std::sync::atomic::Ordering;
    let upf_config = NodeConfig {
        capacity: 1,
        ..config(Function::Up)
    };
    let mut upf = Endpoint::bind(ANY, upf_config).await.unwrap();
    let peer = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    peer.send_to(&setup(1), upf.local_addr()).await.unwrap();
    let first = upf.incoming().await.unwrap();
    peer.send_to(&setup(2), upf.local_addr()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let statistics = upf.statistics();
    assert_eq!(statistics.requests_refused.load(Ordering::Relaxed), 1);
    assert_eq!(statistics.answers_evicted.load(Ordering::Relaxed), 0);
    drop(first);
}

/// A request whose Incoming the caller drops unanswered is forgotten: its retransmission
/// comes again.
#[tokio::test]
async fn a_dropped_incoming_is_forgotten() {
    let mut upf = Endpoint::bind(ANY, config(Function::Up)).await.unwrap();
    let peer = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    peer.send_to(&setup(9), upf.local_addr()).await.unwrap();
    drop(upf.incoming().await.unwrap());
    peer.send_to(&setup(9), upf.local_addr()).await.unwrap();
    let again = tokio::time::timeout(Duration::from_millis(500), upf.incoming())
        .await
        .expect("the retransmission, as a new request")
        .unwrap();
    assert_eq!(again.request.sequence, 9);
}

/// An answer that the caller cancels while it waits for room, or that a probe sends in
/// vain, leaves its request unanswered: the Incoming dropped, its retransmission comes
/// again.
#[tokio::test]
async fn an_answer_in_vain_leaves_its_request_unanswered() {
    let queues = Queues {
        commands: 1,
        incoming: 16,
        events: 16,
    };
    let mut upf = Endpoint::bind_with(ANY, config(Function::Up), queues)
        .await
        .unwrap();
    let handle = upf.handle();
    let peer = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    let answer = || {
        AssociationSetupResponse::new(
            NodeId::Ipv4(Ipv4Addr::LOCALHOST),
            accepted(),
            RecoveryTimeStamp::new(7),
        )
    };
    peer.send_to(&setup(1), upf.local_addr()).await.unwrap();
    let incoming = upf.incoming().await.unwrap();
    // A command that fills the queue, which the task has not taken yet, and the answer,
    // which waits for room, cancelled
    assert!(once(handle.with(|node| node.counters())).await.is_none());
    assert!(once(incoming.respond(answer())).await.is_none());
    peer.send_to(&setup(1), upf.local_addr()).await.unwrap();
    let mut again = tokio::time::timeout(Duration::from_millis(500), upf.incoming())
        .await
        .expect("the retransmission, as a request")
        .unwrap();
    assert_eq!(again.request.sequence, 1);
    // A probe's answer that does not encode: a priority of more than 4 bits
    let broken = Message {
        header: Header {
            priority: Some(16),
            ..Header::node(1)
        },
        body: answer().into(),
    };
    assert!(again.respond_message(broken, Delivery::Send).await.is_err());
    drop(again);
    peer.send_to(&setup(1), upf.local_addr()).await.unwrap();
    let last = tokio::time::timeout(Duration::from_millis(500), upf.incoming())
        .await
        .expect("the retransmission, again")
        .unwrap();
    last.respond(answer()).await.unwrap();
}

/// An answer that does not encode, or that is not the request's response, is an error
/// of `respond`.
#[tokio::test]
async fn an_answer_that_does_not_encode_is_an_error() {
    let mut upf = Endpoint::bind(ANY, config(Function::Up)).await.unwrap();
    let peer = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    peer.send_to(&setup(5), upf.local_addr()).await.unwrap();
    let incoming = upf.incoming().await.unwrap();
    let broken = AlternativeSmfIpAddress {
        v4: true,
        ..Default::default()
    };
    let response = AssociationSetupResponse::new(
        NodeId::Ipv4(Ipv4Addr::LOCALHOST),
        accepted(),
        RecoveryTimeStamp::new(7),
    )
    .with_alternative_smf_ip_address(broken);
    assert!(matches!(
        incoming.respond(response).await,
        Err(EndpointError::Node(NodeError::Encode(_)))
    ));
    peer.send_to(&setup(6), upf.local_addr()).await.unwrap();
    let incoming = upf.incoming().await.unwrap();
    let wrong = HeartbeatResponse::new(RecoveryTimeStamp::new(7));
    assert_eq!(
        incoming.respond(wrong).await,
        Err(EndpointError::Node(NodeError::WrongResponse))
    );
}

/// A heartbeat interval beyond what an Instant holds is never, and the task goes on.
#[tokio::test]
async fn a_heartbeat_of_never() {
    let smf_endpoint = Endpoint::bind(
        ANY,
        NodeConfig {
            heartbeat: Some(Duration::MAX),
            ..config(Function::Cp)
        },
    )
    .await
    .unwrap();
    let smf = smf_endpoint.handle();
    let mut upf = Endpoint::bind(ANY, config(Function::Up)).await.unwrap();
    let upf_address = upf.local_addr();
    let answering = tokio::spawn(async move {
        for _ in 0..2 {
            let incoming = upf.incoming().await.unwrap();
            let response = AssociationSetupResponse::new(
                NodeId::Ipv4(Ipv4Addr::LOCALHOST),
                accepted(),
                RecoveryTimeStamp::new(7),
            );
            if matches!(incoming.message.body, Body::AssociationSetupRequest(_)) {
                incoming.respond(response).await.unwrap();
            }
        }
        upf
    });
    let request =
        AssociationSetupRequest::new(NodeId::Ipv4(Ipv4Addr::LOCALHOST), RecoveryTimeStamp::new(7));
    smf.request(
        upf_address,
        Message {
            header: Header::node(0),
            body: request.clone().into(),
        },
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let heartbeat = Message {
        header: Header::node(0),
        body: HeartbeatRequest::new(RecoveryTimeStamp::new(7)).into(),
    };
    assert!(smf.request(upf_address, heartbeat).await.is_ok());
    smf.request(
        upf_address,
        Message {
            header: Header::node(0),
            body: request.into(),
        },
    )
    .await
    .unwrap();
    answering.await.unwrap();
}

/// A request whose future the caller drops is sent no more.
#[tokio::test]
async fn a_dropped_request_is_cancelled() {
    let smf_endpoint = Endpoint::bind(ANY, config(Function::Cp)).await.unwrap();
    let smf = smf_endpoint.handle();
    let silent = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    let heartbeat = Message {
        header: Header::node(0),
        body: HeartbeatRequest::new(RecoveryTimeStamp::new(7)).into(),
    };
    let _ = tokio::time::timeout(
        Duration::from_millis(10),
        smf.request(silent.local_addr().unwrap(), heartbeat),
    )
    .await;
    let mut buffer = [0; 64];
    let mut count = 0;
    while let Ok(Ok(_)) =
        tokio::time::timeout(Duration::from_millis(250), silent.recv_from(&mut buffer)).await
    {
        count += 1;
    }
    assert_eq!(count, 1, "the first datagram only");
}

/// A request whose future the caller drops once it is queued, before the task takes it,
/// is cancelled all the same: it is not sent.
#[tokio::test]
async fn a_request_dropped_before_the_task_takes_it_is_cancelled() {
    let smf_endpoint = Endpoint::bind(ANY, config(Function::Cp)).await.unwrap();
    let smf = smf_endpoint.handle();
    let silent = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    let heartbeat = Message {
        header: Header::node(0),
        body: HeartbeatRequest::new(RecoveryTimeStamp::new(7)).into(),
    };
    let mut buffer = [0; 64];
    for _ in 0..20 {
        assert!(
            once(smf.request(silent.local_addr().unwrap(), heartbeat.clone()))
                .await
                .is_none()
        );
        // T1 is 100 ms: a request that the node kept would come again
        let mut count = 0;
        while let Ok(Ok(_)) =
            tokio::time::timeout(Duration::from_millis(150), silent.recv_from(&mut buffer)).await
        {
            count += 1;
        }
        assert_eq!(count, 0, "sent {count} times");
    }
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
    let response = AssociationSetupResponse::new(
        NodeId::Ipv4(Ipv4Addr::LOCALHOST),
        accepted(),
        RecoveryTimeStamp::new(7),
    );
    assert_eq!(held.respond(response).await, Err(EndpointError::Closed));
}

/// What `future` gives within 5 seconds: a test whose message does not come fails, and
/// does not wait for ever.
async fn within<F: std::future::Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("within 5 seconds")
}

/// §5.22.3 bullets 5 and 6: an entity of an SMF of MPAS takes over a session that a UP
/// function, which holds its association with another entity of the SMF, hands over to it,
/// a stranger's request. Its caller adopts the session through the handle, and answers the
/// report to the UP function's SEID; the UP function's next report of the session comes
/// in, and the entity's modification of it goes to the UP function.
#[tokio::test]
async fn an_entity_of_the_smf_takes_a_session_over() {
    let mut smf = Endpoint::bind(ANY, config(Function::Cp)).await.unwrap();
    let handle = smf.handle();
    let upf = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    let upf_address = upf.local_addr().unwrap();
    let report = |seid, sequence, report_type, old: Option<FSeid>| {
        let mut report = SessionReportRequest::new(report_type);
        report.old_cp_f_seid = old;
        Message {
            header: Header::session(seid, sequence),
            body: report.into(),
        }
        .encode()
        .unwrap()
    };
    let old = FSeid {
        v4: true,
        seid: Some(0x1234),
        ipv4: Some(Ipv4Addr::new(10, 0, 0, 9)),
        ..Default::default()
    };
    let handover = ReportType {
        uisr: true,
        ..Default::default()
    };
    upf.send_to(&report(0, 9, handover, Some(old)), smf.local_addr())
        .await
        .unwrap();
    let mut incoming = within(smf.incoming()).await.unwrap();
    assert!(incoming.request.stranger);
    // The caller takes the session over, with the UP function's SEID that the SMF knows, at
    // a local SEID that no other call gave
    let local = handle.with(|node| node.new_session()).await.unwrap();
    assert_ne!(handle.with(|node| node.new_session()).await.unwrap(), local);
    let adopt = move |node: &mut Node| node.adopt_session(local, upf_address, 0x66);
    handle.with(adopt).await.unwrap().unwrap();
    assert_eq!(handle.with(adopt).await.unwrap(), Err(NodeError::SeidInUse));
    incoming.request.seid = Some(local);
    let cp_f_seid = FSeid {
        v4: true,
        seid: Some(local),
        ipv4: Some(Ipv4Addr::LOCALHOST),
        ..Default::default()
    };
    incoming
        .respond(SessionReportResponse::new(accepted()).with_cp_f_seid(cp_f_seid))
        .await
        .unwrap();
    let mut buffer = vec![0; 65_535];
    let (length, _) = within(upf.recv_from(&mut buffer)).await.unwrap();
    let answer = Message::decode(&buffer[..length]).unwrap();
    assert_eq!(answer.header.seid, Some(0x66));
    // The UP function's next report, to the session's SEID
    let downlink = ReportType {
        dldr: true,
        ..Default::default()
    };
    upf.send_to(&report(local, 10, downlink, None), smf.local_addr())
        .await
        .unwrap();
    let incoming = within(smf.incoming()).await.unwrap();
    assert_eq!(incoming.request.seid, Some(local));
    // The entity's modification goes to the UP function
    let modification = tokio::spawn({
        let handle = handle.clone();
        async move {
            handle
                .session_request(local, SessionModificationRequest::default())
                .await
        }
    });
    let (length, _) = within(upf.recv_from(&mut buffer)).await.unwrap();
    let request = Message::decode(&buffer[..length]).unwrap();
    assert!(matches!(request.body, Body::SessionModificationRequest(_)));
    assert_eq!(request.header.seid, Some(0x66));
    let response = Message {
        header: Header::session(local, request.header.sequence),
        body: SessionModificationResponse::new(accepted()).into(),
    };
    upf.send_to(&response.encode().unwrap(), smf.local_addr())
        .await
        .unwrap();
    let response = within(modification).await.unwrap().unwrap();
    assert_eq!(response.body.cause(), Some(CauseValue::RequestAccepted));
    drop(incoming);
}

/// Queues of no entry are of one, as a node takes its zeroes: the endpoint runs, and its
/// requests come in.
#[tokio::test]
async fn queues_of_no_entry_hold_one() {
    let queues = Queues {
        commands: 0,
        incoming: 0,
        events: 0,
    };
    let mut upf = Endpoint::bind_with(ANY, config(Function::Up), queues)
        .await
        .unwrap();
    let peer = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    peer.send_to(&setup(1), upf.local_addr()).await.unwrap();
    let incoming = within(upf.incoming()).await.unwrap();
    assert_eq!(incoming.request.sequence, 1);
    assert!(
        within(upf.handle().with(|node| node.counters()))
            .await
            .is_ok()
    );
}
