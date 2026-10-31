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

//! A [`Node`] on a Tokio UDP socket: one task that owns both, which the [`Endpoint`]
//! drives through bounded channels. A request is a future of its response; the requests
//! of the peers come in through [`Endpoint::incoming`], each with what answers it; the
//! other events through [`Endpoint::events`].
//!
//! A queue that is full drops what comes, and counts it in [`Statistics`]: a request of a
//! peer that the caller does not take is retransmitted by the peer, and answered when the
//! caller has room. A caller that batches its datagrams (`recvmmsg`, `sendmmsg`) drives a
//! [`Node`] itself.

use std::collections::BTreeMap;
use std::vec;
use std::vec::Vec;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

use crate::message::{Body, Message};
use crate::node::{Event, Inbound, Node, NodeConfig, NodeError, RequestId};

/// The largest datagram that the endpoint takes.
const DATAGRAM: usize = 65_535;

/// How many entries each queue of the endpoint holds.
#[derive(Debug, Clone, Copy)]
pub struct Queues {
    /// The commands of the caller to the task.
    pub commands: usize,
    /// The requests of the peers to the caller.
    pub incoming: usize,
    /// The other events to the caller.
    pub events: usize,
}

impl Default for Queues {
    fn default() -> Self {
        Self { commands: 1024, incoming: 1024, events: 1024 }
    }
}

/// What the endpoint dropped or could not send, since it started.
#[derive(Debug, Default)]
pub struct Statistics {
    /// Requests of peers dropped for a full incoming queue.
    pub incoming_dropped: AtomicU64,
    /// Events dropped for a full event queue.
    pub events_dropped: AtomicU64,
    /// Datagrams that the socket did not send.
    pub send_errors: AtomicU64,
    /// Datagrams received.
    pub received: AtomicU64,
    /// Datagrams sent.
    pub sent: AtomicU64,
}

/// Why a request of the endpoint has no response.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EndpointError {
    /// No response after N1 retransmissions (§6.4).
    Timeout,
    /// The node did not send it.
    Node(NodeError),
    /// The task of the endpoint has ended.
    Closed,
}

impl core::fmt::Display for EndpointError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Timeout => write!(f, "no response after N1 retransmissions"),
            Self::Node(error) => write!(f, "not sent: {error:?}"),
            Self::Closed => write!(f, "the endpoint has ended"),
        }
    }
}

impl std::error::Error for EndpointError {}

/// A request of a peer, with what answers it.
#[derive(Debug)]
pub struct Incoming {
    /// The request.
    pub message: Message<'static>,
    /// Who sent it, and what the answer takes from it.
    pub request: Inbound,
    commands: mpsc::Sender<Command>,
}

impl Incoming {
    /// Answer the request: its sequence number, priority and SEID come from it.
    ///
    /// # Errors
    ///
    /// The task of the endpoint has ended.
    pub async fn respond(self, body: impl Into<Body<'static>>) -> Result<(), EndpointError> {
        let command = Command::Respond { request: self.request, body: body.into() };
        self.commands.send(command).await.map_err(|_| EndpointError::Closed)
    }
}

enum Command {
    Request { to: SocketAddr, message: Message<'static>, reply: oneshot::Sender<Result<Message<'static>, EndpointError>> },
    SessionRequest { local_seid: u64, body: Body<'static>, reply: oneshot::Sender<Result<Message<'static>, EndpointError>> },
    Respond { request: Inbound, body: Body<'static> },
    NewSession { peer: SocketAddr, reply: oneshot::Sender<u64> },
    SendRaw { to: SocketAddr, octets: Vec<u8> },
}

impl core::fmt::Debug for Command {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Command")
    }
}

/// A node on a UDP socket, run by a task of its own.
#[derive(Debug)]
pub struct Endpoint {
    local: SocketAddr,
    commands: mpsc::Sender<Command>,
    incoming: mpsc::Receiver<Incoming>,
    events: mpsc::Receiver<Event>,
    statistics: Arc<Statistics>,
}

impl Endpoint {
    /// Bind a socket to `address` and run a node of `config` on it, with the queues of
    /// [`Queues::default`].
    ///
    /// # Errors
    ///
    /// The socket does not bind.
    pub async fn bind(address: SocketAddr, config: NodeConfig) -> io::Result<Self> {
        Self::bind_with(address, config, Queues::default()).await
    }

    /// Bind a socket to `address` and run a node of `config` on it, with `queues`.
    ///
    /// # Errors
    ///
    /// The socket does not bind.
    pub async fn bind_with(address: SocketAddr, config: NodeConfig, queues: Queues) -> io::Result<Self> {
        let socket = UdpSocket::bind(address).await?;
        let local = socket.local_addr()?;
        let (commands, command_rx) = mpsc::channel(queues.commands);
        let (incoming_tx, incoming) = mpsc::channel(queues.incoming);
        let (events_tx, events) = mpsc::channel(queues.events);
        let statistics = Arc::new(Statistics::default());
        let task = Task {
            socket,
            node: Node::new(config),
            start: Instant::now(),
            commands: command_rx,
            responder: commands.downgrade(),
            incoming: incoming_tx,
            events: events_tx,
            pending: BTreeMap::new(),
            statistics: statistics.clone(),
        };
        tokio::spawn(task.run());
        Ok(Self { local, commands, incoming, events, statistics })
    }

    /// The address of the socket.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// What the endpoint dropped and sent.
    pub fn statistics(&self) -> &Statistics {
        &self.statistics
    }

    /// Send a request to `to`, and wait for its response.
    ///
    /// # Errors
    ///
    /// No response after N1 retransmissions, a request that the node does not send
    /// (no association, throttled), and an endpoint that has ended.
    pub async fn request(&self, to: SocketAddr, message: Message<'static>) -> Result<Message<'static>, EndpointError> {
        let (reply, response) = oneshot::channel();
        self.commands.send(Command::Request { to, message, reply }).await.map_err(|_| EndpointError::Closed)?;
        response.await.map_err(|_| EndpointError::Closed)?
    }

    /// Send a session request to the session of `local_seid`, and wait for its response.
    ///
    /// # Errors
    ///
    /// As [`request`](Self::request), and a session that the node does not have.
    pub async fn session_request(&self, local_seid: u64, body: impl Into<Body<'static>>) -> Result<Message<'static>, EndpointError> {
        let (reply, response) = oneshot::channel();
        let command = Command::SessionRequest { local_seid, body: body.into(), reply };
        self.commands.send(command).await.map_err(|_| EndpointError::Closed)?;
        response.await.map_err(|_| EndpointError::Closed)?
    }

    /// A new local SEID for a session with `peer` (see [`Node::new_session`]).
    ///
    /// # Errors
    ///
    /// The endpoint has ended.
    pub async fn new_session(&self, peer: SocketAddr) -> Result<u64, EndpointError> {
        let (reply, seid) = oneshot::channel();
        self.commands.send(Command::NewSession { peer, reply }).await.map_err(|_| EndpointError::Closed)?;
        seid.await.map_err(|_| EndpointError::Closed)
    }

    /// Send octets as they are, for a probe (see [`Node::send_raw`]).
    ///
    /// # Errors
    ///
    /// The endpoint has ended.
    pub async fn send_raw(&self, to: SocketAddr, octets: Vec<u8>) -> Result<(), EndpointError> {
        self.commands.send(Command::SendRaw { to, octets }).await.map_err(|_| EndpointError::Closed)
    }

    /// The next request of a peer: `None` once the endpoint has ended.
    pub async fn incoming(&mut self) -> Option<Incoming> {
        self.incoming.recv().await
    }

    /// The next other event: associations, restarts, violations.
    pub async fn event(&mut self) -> Option<Event> {
        self.events.recv().await
    }

    /// The receiver of the other events, for a caller that selects over it.
    pub fn events(&mut self) -> &mut mpsc::Receiver<Event> {
        &mut self.events
    }
}

type Reply = oneshot::Sender<Result<Message<'static>, EndpointError>>;

struct Task {
    socket: UdpSocket,
    node: Node,
    start: Instant,
    commands: mpsc::Receiver<Command>,
    /// The commands of the answers: weak, so that the task ends with the endpoint.
    responder: mpsc::WeakSender<Command>,
    incoming: mpsc::Sender<Incoming>,
    events: mpsc::Sender<Event>,
    pending: BTreeMap<RequestId, Reply>,
    statistics: Arc<Statistics>,
}

impl Task {
    async fn run(mut self) {
        let mut buffer = vec![0; DATAGRAM];
        loop {
            self.flush().await;
            let wake = self.node.poll_timeout().map(|at| self.start + at);
            tokio::select! {
                received = self.socket.recv_from(&mut buffer) => {
                    if let Ok((length, from)) = received {
                        self.statistics.received.fetch_add(1, Ordering::Relaxed);
                        let now = self.start.elapsed();
                        self.node.handle_datagram(now, from, &buffer[..length]);
                    }
                }
                command = self.commands.recv() => {
                    // The endpoint ended: so does the task.
                    let Some(command) = command else { return };
                    self.command(command);
                }
                () = sleep_until(wake) => {
                    let now = self.start.elapsed();
                    self.node.handle_timeout(now);
                }
            }
        }
    }

    fn command(&mut self, command: Command) {
        let now = self.start.elapsed();
        match command {
            Command::Request { to, message, reply } => match self.node.request(now, to, message) {
                Ok(id) => {
                    self.pending.insert(id, reply);
                }
                Err(error) => {
                    let _ = reply.send(Err(EndpointError::Node(error)));
                }
            },
            Command::SessionRequest { local_seid, body, reply } => match self.node.session_request(now, local_seid, body) {
                Ok(id) => {
                    self.pending.insert(id, reply);
                }
                Err(error) => {
                    let _ = reply.send(Err(EndpointError::Node(error)));
                }
            },
            Command::Respond { request, body } => {
                let _ = self.node.respond(now, &request, body);
            }
            Command::NewSession { peer, reply } => {
                let _ = reply.send(self.node.new_session(peer));
            }
            Command::SendRaw { to, octets } => self.node.send_raw(to, 0, octets),
        }
    }

    /// Send what the node has to send, and give its events out.
    async fn flush(&mut self) {
        while let Some(transmit) = self.node.poll_transmit() {
            match self.socket.send_to(&transmit.octets, transmit.to).await {
                Ok(_) => self.statistics.sent.fetch_add(1, Ordering::Relaxed),
                Err(_) => self.statistics.send_errors.fetch_add(1, Ordering::Relaxed),
            };
        }
        while let Some(event) = self.node.poll_event() {
            match event {
                Event::Response { request, message } => {
                    if let Some(reply) = self.pending.remove(&request) {
                        let _ = reply.send(Ok(message));
                    }
                }
                Event::Timeout { request, .. } => {
                    if let Some(reply) = self.pending.remove(&request) {
                        let _ = reply.send(Err(EndpointError::Timeout));
                    }
                }
                Event::Request { request, message } => {
                    let Some(commands) = self.responder.upgrade() else { continue };
                    let incoming = Incoming { message, request, commands };
                    if self.incoming.try_send(incoming).is_err() {
                        self.statistics.incoming_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
                other => {
                    if self.events.try_send(other).is_err() {
                        self.statistics.events_dropped.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    }
}

/// Sleep until `wake`, or for ever.
async fn sleep_until(wake: Option<Instant>) {
    match wake {
        Some(wake) => tokio::time::sleep_until(wake.into()).await,
        None => std::future::pending().await,
    }
}
