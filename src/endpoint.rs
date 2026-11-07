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

//! A [`Node`] on a Tokio UDP socket: one task that owns both. The [`Endpoint`] owns the
//! task and takes what comes: the requests of the peers through
//! [`incoming`](Endpoint::incoming), each with what answers it, and the other events
//! through [`event`](Endpoint::event). A [`Handle`], which it gives and which clones,
//! sends the node's requests and reaches its state, from any task and while the
//! endpoint takes the peers' requests:
//!
//! ```no_run
//! # use oxirush_pfcp::{endpoint::Endpoint, node::{Function, NodeConfig}, *};
//! # async fn run(mut endpoint: Endpoint, smf: std::net::SocketAddr, seid: u64) {
//! let handle = endpoint.handle();
//! let report = handle.session_request(seid, SessionReportRequest::default());
//! tokio::pin!(report);
//! loop {
//!     tokio::select! {
//!         response = &mut report => break,
//!         Some(incoming) = endpoint.incoming() => { /* answer it */ }
//!     }
//! }
//! # }
//! ```
//!
//! A queue that is full drops what comes, and counts it in [`Statistics`]: a request of a
//! peer that the caller does not take is forgotten by the node, so that its
//! retransmission comes in again when the caller has room, and so is one whose
//! [`Incoming`] the caller drops unanswered. A request whose future the caller drops is
//! cancelled ([`Node::cancel`]). A caller that batches its datagrams (`recvmmsg`,
//! `sendmmsg`) drives a [`Node`] itself.

use std::boxed::Box;
use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use std::vec;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::message::{Body, Message};
use crate::node::{Delivery, Event, Failure, Inbound, Node, NodeConfig, NodeError, RequestId};

/// The largest datagram that the endpoint takes.
const DATAGRAM: usize = 65_535;

/// How many entries each queue of the endpoint holds: at least one, which a queue of
/// none is taken as.
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
        Self {
            commands: 1024,
            incoming: 1024,
            events: 1024,
        }
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
    /// Errors of the socket when it received.
    pub receive_errors: AtomicU64,
    /// Datagrams received.
    pub received: AtomicU64,
    /// Datagrams sent.
    pub sent: AtomicU64,
    /// Answers that the node dropped before `keep` to make room:
    /// [`Counters::evicted`](crate::node::Counters::evicted).
    pub answers_evicted: AtomicU64,
    /// Requests that the node dropped, full of requests that wait for their answer:
    /// [`Counters::refused`](crate::node::Counters::refused).
    pub requests_refused: AtomicU64,
}

/// Why a request of the endpoint has no response.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EndpointError {
    /// No response after N1 retransmissions (§6.4).
    Timeout,
    /// The request ended without its response.
    Failed(Failure),
    /// The node did not send it.
    Node(NodeError),
    /// The task of the endpoint has ended.
    Closed,
}

impl core::fmt::Display for EndpointError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::Timeout => write!(f, "no response after N1 retransmissions"),
            Self::Failed(failure) => write!(f, "{failure}"),
            Self::Node(error) => write!(f, "not sent: {error}"),
            Self::Closed => write!(f, "the endpoint has ended"),
        }
    }
}

impl std::error::Error for EndpointError {}

/// A request of a peer, with what answers it. It does not keep the endpoint running, and
/// one dropped unanswered is forgotten ([`Node::forget`]): its retransmission comes again.
#[derive(Debug)]
pub struct Incoming {
    /// The request.
    pub message: Message,
    /// Who sent it, and what the answer takes from it.
    pub request: Inbound,
    commands: mpsc::WeakSender<Command>,
    forgets: mpsc::UnboundedSender<Inbound>,
    answered: bool,
}

impl Drop for Incoming {
    fn drop(&mut self) {
        if !self.answered {
            let _ = self.forgets.send(self.request.clone());
        }
    }
}

impl Incoming {
    /// Answer the request, once: its sequence number, priority and SEID come from it
    /// ([`Node::respond`]).
    ///
    /// # Errors
    ///
    /// A body that is not the response of the request or that does not encode, and an
    /// endpoint that has ended.
    pub async fn respond(mut self, body: impl Into<Body>) -> Result<(), EndpointError> {
        let request = self.request.clone();
        let body = body.into();
        // Answered once the node has the answer: cancelled or failed, the Incoming
        // dropped forgets its request, which the task also does of a failed answer.
        let answered = self
            .command(move |reply| Command::Respond {
                request,
                body,
                reply,
            })
            .await;
        self.answered = answered.is_ok();
        answered
    }

    /// Answer the request with a message as it is, for a probe, any number of times
    /// ([`Node::respond_message`]): the first alone changes the node.
    ///
    /// # Errors
    ///
    /// A message that does not encode, and an endpoint that has ended.
    pub async fn respond_message(
        &mut self,
        message: Message,
        delivery: Delivery,
    ) -> Result<(), EndpointError> {
        let request = self.request.clone();
        let answered = self
            .command(move |reply| Command::RespondMessage {
                request,
                message,
                delivery,
                reply,
            })
            .await;
        self.answered |= answered.is_ok();
        answered
    }

    async fn command(
        &self,
        command: impl FnOnce(oneshot::Sender<Result<(), NodeError>>) -> Command,
    ) -> Result<(), EndpointError> {
        let commands = self.commands.upgrade().ok_or(EndpointError::Closed)?;
        let (reply, done) = oneshot::channel();
        commands
            .send(command(reply))
            .await
            .map_err(|_| EndpointError::Closed)?;
        drop(commands);
        done.await
            .map_err(|_| EndpointError::Closed)?
            .map_err(EndpointError::Node)
    }
}

type Reply = oneshot::Sender<Result<Message, EndpointError>>;

/// What the node does for a [`Handle`], on its state.
type OnNode = Box<dyn FnOnce(&mut Node) + Send>;

enum Command {
    Request {
        to: SocketAddr,
        message: Message,
        token: u64,
        reply: Reply,
    },
    SessionRequest {
        local_seid: u64,
        body: Body,
        token: u64,
        reply: Reply,
    },
    Respond {
        request: Inbound,
        body: Body,
        reply: oneshot::Sender<Result<(), NodeError>>,
    },
    RespondMessage {
        request: Inbound,
        message: Message,
        delivery: Delivery,
        reply: oneshot::Sender<Result<(), NodeError>>,
    },
    On(OnNode),
}

impl core::fmt::Debug for Command {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("Command")
    }
}

/// A node on a UDP socket, run by a task of its own, which the endpoint owns: dropping
/// it ends the task soon after, and [`close`](Self::close) ends it, and frees its socket,
/// before it returns. A [`Handle`] reaches the node meanwhile.
#[derive(Debug)]
pub struct Endpoint {
    handle: Handle,
    incoming: mpsc::Receiver<Incoming>,
    events: mpsc::Receiver<Event>,
    /// Dropped, it ends the task.
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

/// What reaches the node of an [`Endpoint`]: its requests and its state, from any task.
/// It clones, and does not keep the endpoint running: once the endpoint has ended, each
/// method gives [`EndpointError::Closed`].
#[derive(Debug, Clone)]
pub struct Handle {
    local: SocketAddr,
    commands: mpsc::Sender<Command>,
    cancels: mpsc::UnboundedSender<u64>,
    tokens: Arc<AtomicU64>,
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
    pub async fn bind_with(
        address: SocketAddr,
        config: NodeConfig,
        queues: Queues,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(address).await?;
        let local = socket.local_addr()?;
        // A channel of no entry is none to tokio: one, as the node takes its zeroes.
        let (commands, command_rx) = mpsc::channel(queues.commands.max(1));
        let (incoming_tx, incoming) = mpsc::channel(queues.incoming.max(1));
        let (events_tx, events) = mpsc::channel(queues.events.max(1));
        let (forgetting, forgets) = mpsc::unbounded_channel();
        let (cancels, cancelled) = mpsc::unbounded_channel();
        let (stop, stopped) = oneshot::channel();
        let statistics = Arc::new(Statistics::default());
        let task = Task {
            socket,
            node: Node::new(config),
            start: Instant::now(),
            commands: command_rx,
            responder: commands.downgrade(),
            forgets,
            forgetting,
            cancelled,
            incoming: incoming_tx,
            events: events_tx,
            pending: BTreeMap::new(),
            tokens: BTreeMap::new(),
            statistics: statistics.clone(),
        };
        let task = tokio::spawn(task.run(stopped));
        let handle = Handle {
            local,
            commands,
            cancels,
            tokens: Arc::new(AtomicU64::new(0)),
            statistics,
        };
        Ok(Self {
            handle,
            incoming,
            events,
            stop,
            task,
        })
    }

    /// End the task of the endpoint, and wait until it has freed its socket. A request of
    /// a [`Handle`] that waits for its response, and the answer of an [`Incoming`], end
    /// with [`EndpointError::Closed`].
    pub async fn close(self) {
        let Self { stop, task, .. } = self;
        drop(stop);
        let _ = task.await;
    }

    /// What reaches the node: its requests and its state, beside the requests of the
    /// peers that the endpoint takes.
    pub fn handle(&self) -> Handle {
        self.handle.clone()
    }

    /// The address of the socket.
    pub fn local_addr(&self) -> SocketAddr {
        self.handle.local
    }

    /// What the endpoint dropped and sent.
    pub fn statistics(&self) -> &Statistics {
        &self.handle.statistics
    }

    /// The next request of a peer: `None` once the endpoint has ended.
    pub async fn incoming(&mut self) -> Option<Incoming> {
        self.incoming.recv().await
    }

    /// The next other event: associations, restarts, retransmissions, violations.
    pub async fn event(&mut self) -> Option<Event> {
        self.events.recv().await
    }

    /// The receiver of the other events, for a caller that selects over it.
    pub fn events(&mut self) -> &mut mpsc::Receiver<Event> {
        &mut self.events
    }
}

/// Cancels the request of its token when the future of the request is dropped before its
/// response.
struct Cancel<'a> {
    token: u64,
    cancels: &'a mpsc::UnboundedSender<u64>,
    done: bool,
}

impl Drop for Cancel<'_> {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.cancels.send(self.token);
        }
    }
}

impl Handle {
    /// The address of the socket.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// What the endpoint dropped and sent.
    pub fn statistics(&self) -> &Statistics {
        &self.statistics
    }

    /// Send a request to `to`, and wait for its response ([`Node::request`]). Dropping
    /// the future cancels the request: it is sent no more.
    ///
    /// # Errors
    ///
    /// No response after N1 retransmissions, a request that ends without its response,
    /// a request that the node does not send (no association, throttled), and an
    /// endpoint that has ended.
    pub async fn request(
        &self,
        to: SocketAddr,
        message: Message,
    ) -> Result<Message, EndpointError> {
        self.send_request(|token, reply| Command::Request {
            to,
            message,
            token,
            reply,
        })
        .await
    }

    /// Send a session request to the session of `local_seid`, and wait for its response
    /// ([`Node::session_request`]). Dropping the future cancels the request.
    ///
    /// # Errors
    ///
    /// As [`request`](Self::request), and a session that the node does not have.
    pub async fn session_request(
        &self,
        local_seid: u64,
        body: impl Into<Body>,
    ) -> Result<Message, EndpointError> {
        let body = body.into();
        self.send_request(|token, reply| Command::SessionRequest {
            local_seid,
            body,
            token,
            reply,
        })
        .await
    }

    async fn send_request(
        &self,
        command: impl FnOnce(u64, Reply) -> Command,
    ) -> Result<Message, EndpointError> {
        let token = self.tokens.fetch_add(1, Ordering::Relaxed);
        // A future dropped once its command is queued is dropped in the await of its
        // response, whose receiver, the awaited future, drops before the guard: the reply
        // is closed before the cancel is queued. Whenever the task sees the cancel, the
        // command's `reply.is_closed()` is then true, and the request is not sent.
        let mut cancel = Cancel {
            token,
            cancels: &self.cancels,
            done: false,
        };
        let (reply, response) = oneshot::channel();
        self.commands
            .send(command(token, reply))
            .await
            .map_err(|_| EndpointError::Closed)?;
        let response = response.await.map_err(|_| EndpointError::Closed);
        cancel.done = true;
        response?
    }

    /// Do `with` on the node, in the task of the endpoint, and give what it returns: its
    /// state ([`Node::sessions`], [`Node::association`], [`Node::counters`]), a new local
    /// SEID ([`Node::new_session`]), an adopted session, the end of one, a probe's
    /// sequence number or octets. The response of a request that `with` sends comes as an
    /// [`Event::Response`]: [`request`](Self::request) waits for its own.
    ///
    /// ```no_run
    /// # async fn run(handle: oxirush_pfcp::endpoint::Handle) -> Result<(), oxirush_pfcp::endpoint::EndpointError> {
    /// let seid = handle.with(|node| node.new_session()).await?;
    /// let sessions = handle.with(|node| node.sessions().count()).await?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// The endpoint has ended.
    pub async fn with<T: Send + 'static>(
        &self,
        with: impl FnOnce(&mut Node) -> T + Send + 'static,
    ) -> Result<T, EndpointError> {
        let (reply, answer) = oneshot::channel();
        let command = Command::On(Box::new(move |node| {
            let _ = reply.send(with(node));
        }));
        self.commands
            .send(command)
            .await
            .map_err(|_| EndpointError::Closed)?;
        answer.await.map_err(|_| EndpointError::Closed)
    }
}

struct Task {
    socket: UdpSocket,
    node: Node,
    start: Instant,
    commands: mpsc::Receiver<Command>,
    /// The commands of the answers: weak, so that they do not keep the task.
    responder: mpsc::WeakSender<Command>,
    /// The requests whose Incoming the caller dropped unanswered.
    forgets: mpsc::UnboundedReceiver<Inbound>,
    forgetting: mpsc::UnboundedSender<Inbound>,
    /// The tokens of the requests whose futures the caller dropped.
    cancelled: mpsc::UnboundedReceiver<u64>,
    incoming: mpsc::Sender<Incoming>,
    events: mpsc::Sender<Event>,
    /// The requests that wait for their responses, with their tokens, and the requests of
    /// the tokens.
    pending: BTreeMap<RequestId, (Reply, u64)>,
    tokens: BTreeMap<u64, RequestId>,
    statistics: Arc<Statistics>,
}

impl Task {
    async fn run(mut self, mut stopped: oneshot::Receiver<()>) {
        let mut buffer = vec![0; DATAGRAM];
        loop {
            self.flush().await;
            // A time beyond what an Instant holds is never.
            let wake = self
                .node
                .poll_timeout()
                .and_then(|at| self.start.checked_add(at));
            tokio::select! {
                // The endpoint ended: so does the task.
                _ = &mut stopped => return,
                received = self.socket.recv_from(&mut buffer) => {
                    match received {
                        Ok((length, from)) => {
                            self.statistics.received.fetch_add(1, Ordering::Relaxed);
                            let now = self.start.elapsed();
                            self.node.handle_datagram(now, from, &buffer[..length]);
                            let counters = self.node.counters();
                            self.statistics.answers_evicted.store(counters.evicted, Ordering::Relaxed);
                            self.statistics.requests_refused.store(counters.refused, Ordering::Relaxed);
                        }
                        Err(_) => {
                            self.statistics.receive_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Some(request) = self.forgets.recv() => self.node.forget(&request),
                Some(token) = self.cancelled.recv() => {
                    if let Some(id) = self.tokens.remove(&token) {
                        self.pending.remove(&id);
                        self.node.cancel(self.start.elapsed(), id);
                    }
                }
                command = self.commands.recv() => {
                    let Some(command) = command else { return };
                    self.command(command);
                }
                () = sleep_until(wake) => self.node.handle_timeout(self.start.elapsed()),
            }
        }
    }

    fn command(&mut self, command: Command) {
        let now = self.start.elapsed();
        match command {
            // A future dropped once it queued its request, before the task took it: its
            // cancel came first and found nothing, and the request is not sent.
            Command::Request { reply, .. } | Command::SessionRequest { reply, .. }
                if reply.is_closed() => {}
            Command::Request {
                to,
                message,
                token,
                reply,
            } => {
                let sent = self.node.request(now, to, message);
                self.pending_or(sent, token, reply);
            }
            Command::SessionRequest {
                local_seid,
                body,
                token,
                reply,
            } => {
                let sent = self.node.session_request(now, local_seid, body);
                self.pending_or(sent, token, reply);
            }
            Command::Respond {
                request,
                body,
                reply,
            } => {
                let result = self.node.respond(now, &request, body);
                // An Incoming answered in vain is gone: its retransmission comes again.
                if result.is_err() {
                    self.node.forget(&request);
                }
                let _ = reply.send(result);
            }
            Command::RespondMessage {
                request,
                message,
                delivery,
                reply,
            } => {
                let _ = reply.send(self.node.respond_message(now, &request, message, delivery));
            }
            Command::On(on) => on(&mut self.node),
        }
    }

    /// A request that the node sent waits for its response; one that it did not has its
    /// error.
    fn pending_or(&mut self, sent: Result<RequestId, NodeError>, token: u64, reply: Reply) {
        match sent {
            Ok(id) => {
                self.pending.insert(id, (reply, token));
                self.tokens.insert(token, id);
            }
            Err(error) => {
                let _ = reply.send(Err(EndpointError::Node(error)));
            }
        }
    }

    /// The reply of a request that ends, which no cancel finds after.
    fn reply(&mut self, id: RequestId) -> Option<Reply> {
        let (reply, token) = self.pending.remove(&id)?;
        self.tokens.remove(&token);
        Some(reply)
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
                    if let Some(reply) = self.reply(request) {
                        let _ = reply.send(Ok(message));
                    }
                }
                Event::Timeout { request, .. } => {
                    if let Some(reply) = self.reply(request) {
                        let _ = reply.send(Err(EndpointError::Timeout));
                    }
                }
                Event::Failed {
                    request, failure, ..
                } => {
                    if let Some(reply) = self.reply(request) {
                        let _ = reply.send(Err(EndpointError::Failed(failure)));
                    }
                }
                Event::Request { request, message } => {
                    let incoming = Incoming {
                        message,
                        request,
                        commands: self.responder.clone(),
                        forgets: self.forgetting.clone(),
                        answered: false,
                    };
                    if let Err(dropped) = self.incoming.try_send(incoming) {
                        // Its retransmission comes in again: the Incoming forgets it.
                        let _ = dropped;
                        self.statistics
                            .incoming_dropped
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
                other => {
                    if self.events.try_send(other).is_err() {
                        self.statistics
                            .events_dropped
                            .fetch_add(1, Ordering::Relaxed);
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

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::task::{Context, Wake, Waker};

    use super::*;
    use crate::{HeartbeatRequest, RecoveryTimeStamp};

    /// What the receiver of the cancels sees when a cancel comes: whether the reply of the
    /// request is closed then. Its waker runs in the send of the cancel.
    struct Probe {
        reply: Mutex<Option<Reply>>,
        closed: Mutex<Option<bool>>,
    }

    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            let closed = self.reply.lock().unwrap().as_ref().map(Reply::is_closed);
            *self.closed.lock().unwrap() = closed;
        }
    }

    /// A request whose future is dropped after it queued its command closes its reply
    /// before its cancel goes: whenever the task sees the cancel, the command that it
    /// takes after has a closed reply, and is not sent.
    #[test]
    fn a_dropped_request_closes_its_reply_before_it_cancels() {
        let (commands, mut queued) = mpsc::channel(1);
        let (cancels, mut cancelled) = mpsc::unbounded_channel();
        let handle = Handle {
            local: SocketAddr::from(([127, 0, 0, 1], 0)),
            commands,
            cancels,
            tokens: Arc::new(AtomicU64::new(0)),
            statistics: Arc::new(Statistics::default()),
        };
        let heartbeat = Message {
            header: crate::Header::node(0),
            body: HeartbeatRequest::new(RecoveryTimeStamp::new(7)).into(),
        };
        let to = SocketAddr::from(([127, 0, 0, 1], 8805));
        let mut request = Box::pin(handle.request(to, heartbeat));
        let mut context = Context::from_waker(Waker::noop());
        assert!(request.as_mut().poll(&mut context).is_pending());
        let Ok(Command::Request { reply, .. }) = queued.try_recv() else {
            panic!("no request queued");
        };
        let probe = Arc::new(Probe {
            reply: Mutex::new(Some(reply)),
            closed: Mutex::new(None),
        });
        let waker = Waker::from(probe.clone());
        assert!(
            cancelled
                .poll_recv(&mut Context::from_waker(&waker))
                .is_pending()
        );
        drop(request);
        assert_eq!(cancelled.try_recv(), Ok(0));
        assert_eq!(
            *probe.closed.lock().unwrap(),
            Some(true),
            "the reply was open when the cancel came"
        );
    }
}
