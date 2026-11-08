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

//! Two endpoints on the loopback, an SMF and a UPF, with short timers and queues of two
//! entries, under steps that the input picks: the SMF sends a Heartbeat or an Association
//! Setup Request, which it waits for or leaves; the UPF takes the next request and answers
//! it, answers it with the body of another response, or drops it unanswered; a stranger
//! sends the fuzzer's octets to either; time passes; the UPF ends.
//!
//! Nothing panics, in the tasks of the endpoints too. An endpoint that has not ended still
//! does what its handle asks, whatever came to it. A response that the SMF gets is the
//! response of its request. Each endpoint ends when it is closed, and then each request
//! that waited for its response ends: none hangs.
#![no_main]

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::LazyLock;
use std::time::Duration;

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use oxirush_pfcp::endpoint::{Endpoint, Incoming, Queues};
use oxirush_pfcp::node::{Function, NodeConfig};
use oxirush_pfcp::*;
use tokio::task::JoinHandle;
use tokio::time::timeout;

const ANY: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
/// Longer than anything the endpoints do here: a step that takes it hangs.
const BOUND: Duration = Duration::from_secs(5);

static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
});

#[derive(Arbitrary, Debug)]
enum Step {
    /// The SMF sends a request to the UPF: a Heartbeat Request, or an Association Setup
    /// Request
    Request { setup: bool },
    /// The UPF takes the next request: it answers it, answers it with the body of another
    /// response, or drops it
    Take { answer: u8 },
    /// A stranger sends octets to the UPF, or to the SMF
    Stranger { to_smf: bool, octets: Vec<u8> },
    /// Some milliseconds pass
    Wait(u8),
    /// The UPF ends
    Close,
}

fn config(function: Function) -> NodeConfig {
    NodeConfig {
        t1: Duration::from_millis(5),
        n1: 2,
        heartbeat: None,
        keep: Duration::from_millis(50),
        request_port: None,
        ..NodeConfig::new(NodeId::Ipv4(Ipv4Addr::LOCALHOST), function, 7)
    }
}

const QUEUES: Queues = Queues {
    commands: 2,
    incoming: 2,
    incoming_octets: 4096,
    events: 2,
};

/// The answer that `answer` picks to a request: its response, the body of another
/// response, or none.
async fn take(incoming: Incoming, answer: u8) {
    let stamp = RecoveryTimeStamp::new(7);
    let setup = AssociationSetupResponse::new(
        NodeId::Ipv4(Ipv4Addr::LOCALHOST),
        Cause::new(CauseValue::RequestAccepted),
        stamp.clone(),
    );
    let heartbeat = HeartbeatResponse::new(stamp);
    let is_setup = matches!(incoming.message.body, Body::AssociationSetupRequest(_));
    // An answer that is not the response of its request is refused; nothing else is
    // asked of it here
    let _ = match (answer % 3, is_setup) {
        (0, true) | (1, false) => incoming.respond(setup).await,
        (0, false) | (1, true) => incoming.respond(heartbeat).await,
        _ => Ok(()),
    };
}

/// Whether `response` is the response of a request of the SMF.
fn answers(setup: bool, response: &Message) -> bool {
    match setup {
        true => matches!(response.body, Body::AssociationSetupResponse(_)),
        false => matches!(response.body, Body::HeartbeatResponse(_)),
    }
}

fuzz_target!(|steps: Vec<Step>| {
    RUNTIME.block_on(async {
        let smf = Endpoint::bind_with(ANY, config(Function::Cp), QUEUES)
            .await
            .expect("a socket");
        let mut upf = Some(
            Endpoint::bind_with(ANY, config(Function::Up), QUEUES)
                .await
                .expect("a socket"),
        );
        let smf_handle = smf.handle();
        let upf_address = upf
            .as_ref()
            .map(|upf| upf.handle().local_addr())
            .expect("the UPF");
        let smf_address = smf_handle.local_addr();
        let stranger = UdpSocket::bind(ANY).expect("a socket");
        let mut requests: Vec<(bool, JoinHandle<Result<Message, endpoint::EndpointError>>)> =
            Vec::new();

        for step in steps.iter().take(32) {
            match step {
                Step::Request { setup } => {
                    let message = match setup {
                        true => Message::node(
                            0,
                            AssociationSetupRequest::new(
                                NodeId::Ipv4(Ipv4Addr::LOCALHOST),
                                RecoveryTimeStamp::new(7),
                            ),
                        ),
                        false => Message::node(0, HeartbeatRequest::new(RecoveryTimeStamp::new(7))),
                    };
                    let handle = smf_handle.clone();
                    requests.push((
                        *setup,
                        tokio::spawn(async move { handle.request(upf_address, message).await }),
                    ));
                    tokio::task::yield_now().await;
                }
                Step::Take { answer } => {
                    if let Some(upf) = upf.as_mut()
                        && let Ok(Some(incoming)) =
                            timeout(Duration::from_millis(10), upf.incoming()).await
                    {
                        take(incoming, *answer).await;
                    }
                }
                Step::Stranger { to_smf, octets } => {
                    let to = if *to_smf { smf_address } else { upf_address };
                    let _ = stranger.send_to(octets, to);
                    tokio::task::yield_now().await;
                }
                Step::Wait(milliseconds) => {
                    tokio::time::sleep(Duration::from_millis(u64::from(milliseconds % 16))).await
                }
                Step::Close => {
                    if let Some(upf) = upf.take() {
                        timeout(BOUND, upf.close())
                            .await
                            .expect("the UPF ends when it is closed");
                    }
                }
            }
        }

        // An endpoint that has not ended does what its handle asks.
        timeout(BOUND, smf_handle.with(|_, _| ()))
            .await
            .expect("the SMF answers its handle")
            .expect("the SMF runs");
        if let Some(upf) = &upf {
            timeout(BOUND, upf.handle().with(|_, _| ()))
                .await
                .expect("the UPF answers its handle")
                .expect("the UPF runs");
        }

        // Each endpoint ends when it is closed, and each request then ends.
        if let Some(upf) = upf.take() {
            timeout(BOUND, upf.close())
                .await
                .expect("the UPF ends when it is closed");
        }
        timeout(BOUND, smf.close())
            .await
            .expect("the SMF ends when it is closed");
        for (setup, request) in requests {
            let ended = timeout(BOUND, request)
                .await
                .expect("a request ends once its endpoint has")
                .expect("a request does not panic");
            if let Ok(response) = ended {
                assert!(
                    answers(setup, &response),
                    "a response that is not that of its request: {response:?}"
                );
            }
        }
    });
});
