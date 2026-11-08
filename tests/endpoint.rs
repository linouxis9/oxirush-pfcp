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
    let upf_address = upf.handle().local_addr();
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
                    let seid = upf_handle.with(|node, _| node.new_session()).await.unwrap();
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

    let seid = smf.with(|node, _| node.new_session()).await.unwrap();
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
    assert_eq!(upf.handle().statistics().incoming_dropped, 0);
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
            let seid = handle.with(|node, _| node.new_session()).await.unwrap();
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
    let (smf_address, upf_address) = (smf.handle().local_addr(), upf.handle().local_addr());
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
    let seid = smf_handle.with(|node, _| node.new_session()).await.unwrap();
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
        .with(move |node, _| {
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
        .with(|node, _| node.reserve_sequence())
        .await
        .unwrap()
        .unwrap();
    assert!(
        smf_handle
            .with(move |node, _| node.end_association(upf_address))
            .await
            .unwrap()
    );
    assert!(
        smf_handle
            .with(move |node, _| node.session(seid).is_none())
            .await
            .unwrap()
    );
    assert!(matches!(smf.event().await, Some(Event::Associated { .. })));
    assert!(matches!(smf.event().await, Some(Event::Released { .. })));
    smf.close().await;
    assert_eq!(
        smf_handle.with(|node, _| node.counters()).await,
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
    peer.send_to(&setup(4), upf.handle().local_addr())
        .await
        .unwrap();
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
    let associated = handle.with(move |node, _| node.association(peer_address).is_some());
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
    assert_eq!(result, Err(EndpointError::Failed(Failure::Timeout)));
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

/// An endpoint on a socket of both families sends to an IPv4 address at its IPv4-mapped
/// address, and takes the response that comes from it as from the IPv4 address. A system
/// whose sockets of IPv6 take no IPv4 has nothing to test.
#[tokio::test]
async fn an_endpoint_of_both_families_reaches_an_ipv4_peer() {
    let any_v6: SocketAddr = "[::]:0".parse().unwrap();
    let both = std::net::UdpSocket::bind(any_v6).and_then(|socket| {
        let probe = std::net::UdpSocket::bind(ANY)?;
        let mapped = SocketAddr::new(
            Ipv4Addr::LOCALHOST.to_ipv6_mapped().into(),
            probe.local_addr()?.port(),
        );
        socket.send_to(&[0], mapped)
    });
    if both.is_err() {
        return;
    }
    let smf_endpoint = Endpoint::bind(any_v6, config(Function::Cp)).await.unwrap();
    let smf = smf_endpoint.handle();
    let upf = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    let upf_address = upf.local_addr().unwrap();
    let request = smf.request(upf_address, heartbeat());
    tokio::pin!(request);
    let mut buffer = [0; 64];
    let (length, from) = tokio::select! {
        received = upf.recv_from(&mut buffer) => received.unwrap(),
        result = &mut request => panic!("{result:?}"),
    };
    let heartbeat = Message::decode(&buffer[..length]).unwrap();
    let response = Message {
        header: heartbeat.header,
        body: HeartbeatResponse::new(RecoveryTimeStamp::new(1)).into(),
    };
    upf.send_to(&response.encode().unwrap(), from)
        .await
        .unwrap();
    let response = within(request).await.unwrap();
    assert!(matches!(response.body, Body::HeartbeatResponse(_)));
    assert_eq!(smf.statistics().send_errors, 0);
}

fn heartbeat() -> Message {
    Message {
        header: Header::node(0),
        body: HeartbeatRequest::new(RecoveryTimeStamp::new(7)).into(),
    }
}

/// A request that the caller sends through `Handle::with`, at the node's time, which the
/// closure is given: its response, and its timeout, come as events.
#[tokio::test]
async fn the_events_of_a_request_sent_with_the_node() {
    let mut smf = Endpoint::bind(ANY, config(Function::Cp)).await.unwrap();
    let upf = Endpoint::bind(ANY, config(Function::Up)).await.unwrap();
    let silent = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let now = smf.handle().with(|_, now| now).await.unwrap();
    assert!(now >= Duration::from_millis(20), "{now:?}");
    for (to, answered) in [
        (upf.handle().local_addr(), true),
        (silent.local_addr().unwrap(), false),
    ] {
        let heartbeat = Message {
            header: Header::node(0),
            body: HeartbeatRequest::new(RecoveryTimeStamp::new(7)).into(),
        };
        let handle = smf.handle();
        let sent = handle.with(move |node, now| node.request(now, to, heartbeat));
        let sent = sent.await.unwrap().unwrap();
        let ended = loop {
            match within(smf.event()).await.unwrap() {
                Event::Response { request, message } => {
                    assert!(matches!(message.body, Body::HeartbeatResponse(_)));
                    break (request, true);
                }
                Event::Failed {
                    request,
                    failure: Failure::Timeout,
                    ..
                } => break (request, false),
                _ => {}
            }
        };
        assert_eq!(ended, (sent, answered));
    }
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

/// An Association Setup Request of `pools` UE IP address Pool Informations, each of one
/// IE of a null length: a few octets each, which decode into a grouped IE each.
fn setup_of_pools(sequence: u32, pools: usize) -> Vec<u8> {
    let mut request =
        AssociationSetupRequest::new(NodeId::Ipv4(Ipv4Addr::LOCALHOST), RecoveryTimeStamp::new(1));
    request
        .raw
        .extend((0..pools).map(|_| RawIe::new(233, [0, 177, 0, 0])));
    Message {
        header: Header::node(sequence),
        body: request.into(),
    }
    .encode()
    .unwrap()
}

/// The incoming queue holds requests up to the octets that they take decoded, as well as
/// up to their number: a datagram that decodes into far more than its octets is dropped
/// while the queue holds as much, and comes in again when the caller has taken the others.
/// Each datagram goes once the endpoint has read the one before, so that no system's
/// receive buffer drops one first.
#[tokio::test]
async fn the_incoming_queue_is_bounded_by_what_its_requests_take() {
    let queues = Queues {
        incoming_octets: 64 << 10,
        ..Queues::default()
    };
    let mut upf = Endpoint::bind_with(ANY, config(Function::Up), queues)
        .await
        .unwrap();
    let handle = upf.handle();
    let address = handle.local_addr();
    let peer = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    // 1,000 grouped IEs of 8 octets: 8 kB, a datagram that macOS sends too (9,216 octets
    // at most), and some 300 kB decoded
    let large = |sequence| setup_of_pools(sequence, 1_000);
    for (received, datagram) in (1..).zip([large(1), large(2), large(3), setup(4)]) {
        peer.send_to(&datagram, address).await.unwrap();
        let read = statistics_once(&handle, |statistics| statistics.received == received).await;
        assert_eq!(read.received, received);
    }
    let dropped = statistics_once(&handle, |statistics| statistics.incoming_dropped == 3).await;
    assert_eq!(dropped.incoming_dropped, 3);
    let first = within(upf.incoming()).await.unwrap().request.sequence;
    assert_eq!(first, 1);
    peer.send_to(&large(2), address).await.unwrap();
    let again = within(upf.incoming()).await.unwrap();
    assert_eq!(again.request.sequence, 2);
}

/// Requests that take little fill the queue by what each takes: sixteen Association Setup
/// Requests, each under a kibibyte decoded with its place in the queue, fit in 64 KiB.
#[tokio::test]
async fn small_requests_fill_the_queue_by_what_each_takes() {
    let queues = Queues {
        incoming_octets: 64 << 10,
        ..Queues::default()
    };
    let mut upf = Endpoint::bind_with(ANY, config(Function::Up), queues)
        .await
        .unwrap();
    let address = upf.handle().local_addr();
    let peer = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    for sequence in 1..=16 {
        peer.send_to(&setup(sequence), address).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(upf.handle().statistics().incoming_dropped, 0);
    let mut queued = Vec::new();
    for sequence in 1..=16 {
        let incoming = within(upf.incoming()).await.unwrap();
        assert_eq!(incoming.request.sequence, sequence);
        queued.push(incoming);
    }
}

/// A request that the endpoint drops for a full queue comes in again with its
/// retransmission, and is answered then.
#[tokio::test]
async fn a_request_dropped_for_a_full_queue_comes_again() {
    let queues = Queues {
        commands: 16,
        incoming: 1,
        events: 16,
        ..Queues::default()
    };
    let mut upf = Endpoint::bind_with(ANY, config(Function::Up), queues)
        .await
        .unwrap();
    let peer = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    peer.send_to(&setup(1), upf.handle().local_addr())
        .await
        .unwrap();
    peer.send_to(&setup(2), upf.handle().local_addr())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(upf.handle().statistics().incoming_dropped, 1);
    assert_eq!(upf.incoming().await.unwrap().request.sequence, 1);
    peer.send_to(&setup(2), upf.handle().local_addr())
        .await
        .unwrap();
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

/// What the node drops to bound what it keeps is in its counters, through a handle.
#[tokio::test]
async fn a_request_refused_by_a_full_node_is_counted() {
    let upf_config = NodeConfig {
        capacity: 1,
        ..config(Function::Up)
    };
    let mut upf = Endpoint::bind(ANY, upf_config).await.unwrap();
    let peer = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    peer.send_to(&setup(1), upf.handle().local_addr())
        .await
        .unwrap();
    let first = upf.incoming().await.unwrap();
    peer.send_to(&setup(2), upf.handle().local_addr())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let counters = upf.handle().with(|node, _| node.counters()).await.unwrap();
    assert_eq!((counters.refused, counters.evicted), (1, 0));
    drop(first);
}

/// A request whose Incoming the caller drops unanswered is forgotten: its retransmission
/// comes again.
#[tokio::test]
async fn a_dropped_incoming_is_forgotten() {
    let mut upf = Endpoint::bind(ANY, config(Function::Up)).await.unwrap();
    let peer = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    peer.send_to(&setup(9), upf.handle().local_addr())
        .await
        .unwrap();
    drop(upf.incoming().await.unwrap());
    peer.send_to(&setup(9), upf.handle().local_addr())
        .await
        .unwrap();
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
        ..Queues::default()
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
    peer.send_to(&setup(1), upf.handle().local_addr())
        .await
        .unwrap();
    let incoming = upf.incoming().await.unwrap();
    // A command that fills the queue, which the task has not taken yet, and the answer,
    // which waits for room, cancelled
    assert!(once(handle.with(|node, _| node.counters())).await.is_none());
    assert!(once(incoming.respond(answer())).await.is_none());
    peer.send_to(&setup(1), upf.handle().local_addr())
        .await
        .unwrap();
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
    peer.send_to(&setup(1), upf.handle().local_addr())
        .await
        .unwrap();
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
    peer.send_to(&setup(5), upf.handle().local_addr())
        .await
        .unwrap();
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
    peer.send_to(&setup(6), upf.handle().local_addr())
        .await
        .unwrap();
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
    let upf_address = upf.handle().local_addr();
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
    let address = upf.handle().local_addr();
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

/// The statistics of an endpoint once `condition` holds of them, or after five seconds.
async fn statistics_once(handle: &Handle, condition: impl Fn(&Statistics) -> bool) -> Statistics {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let statistics = handle.statistics();
        if condition(&statistics) || tokio::time::Instant::now() >= deadline {
            return statistics;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
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
    upf.send_to(
        &report(0, 9, handover, Some(old)),
        smf.handle().local_addr(),
    )
    .await
    .unwrap();
    let incoming = within(smf.incoming()).await.unwrap();
    assert!(incoming.request.stranger);
    // The caller takes the session over, with the UP function's SEID that the SMF knows, at
    // a local SEID that no other call gave
    let local = handle.with(|node, _| node.new_session()).await.unwrap();
    assert_ne!(
        handle.with(|node, _| node.new_session()).await.unwrap(),
        local
    );
    let adopt = move |node: &mut Node, _| node.adopt_session(local, upf_address, 0x66);
    handle.with(adopt).await.unwrap().unwrap();
    assert_eq!(handle.with(adopt).await.unwrap(), Err(NodeError::SeidInUse));
    let cp_f_seid = FSeid {
        v4: true,
        seid: Some(local),
        ipv4: Some(Ipv4Addr::LOCALHOST),
        ..Default::default()
    };
    let answer = SessionReportResponse::new(accepted()).with_cp_f_seid(cp_f_seid);
    incoming.respond_as(local, answer).await.unwrap();
    let mut buffer = vec![0; 65_535];
    let (length, _) = within(upf.recv_from(&mut buffer)).await.unwrap();
    let answer = Message::decode(&buffer[..length]).unwrap();
    assert_eq!(answer.header.seid, Some(0x66));
    // The UP function's next report, to the session's SEID
    let downlink = ReportType {
        dldr: true,
        ..Default::default()
    };
    upf.send_to(
        &report(local, 10, downlink, None),
        smf.handle().local_addr(),
    )
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
    upf.send_to(&response.encode().unwrap(), smf.handle().local_addr())
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
        incoming_octets: 0,
        events: 0,
    };
    let mut upf = Endpoint::bind_with(ANY, config(Function::Up), queues)
        .await
        .unwrap();
    let peer = tokio::net::UdpSocket::bind(ANY).await.unwrap();
    peer.send_to(&setup(1), upf.handle().local_addr())
        .await
        .unwrap();
    let incoming = within(upf.incoming()).await.unwrap();
    assert_eq!(incoming.request.sequence, 1);
    assert!(
        within(upf.handle().with(|node, _| node.counters()))
            .await
            .is_ok()
    );
}
