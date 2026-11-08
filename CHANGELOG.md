# Changelog

All notable changes to `oxirush-pfcp` are recorded here.

## 0.1.0 - unreleased

The first version, of TS 29.244 V19.6.0 (2026-06):

- Every message and IE type of N4, N4mb, Sxa, Sxb and Sxc, decoded and encoded back byte
  for byte, and built with `new()` and `with_*()`; a message of its body with
  `Message::node` and `Message::session`.
- `check()`: how a message breaks the tables and clauses on an interface, each deviation
  with its path, its clause and the Cause of the answer; `deviations()` of a value on its
  own. `Row::presence_on` gives the presence of a row on an interface, or on a set of
  them, and `None` where it is not: its IEs have no Cause there (§7.6.9).
- With `tree`, a message as a tree that prints as JSON, read and edited by path, on
  oxirush-utils 0.2; with `serde`, serialized as its tree. A tree writes each field that
  its value always has; it leaves out a flag that is not set and a field that its flags
  do not have.
- With `node`, `Node`, a PFCP entity without I/O: delivery and retransmission (§6.4),
  heartbeat, associations, sessions, load and overload control, and bundles (§6.5). A
  request that names another's session or association, as another SMF of a set sends
  (§5.22), goes to the caller as `Received::stranger`, and the one of SEID 0 that hands a
  session over is answered as one of the adopted session (`respond_as`); one that says
  its priority has it in `Received::priority`. An IPv4 peer that a socket of both
  families gives at its IPv4-mapped address is its IPv4 address.
- With `endpoint`, `Endpoint`, a node on a Tokio UDP socket, and its `Handle`.
- A request that ends without its response says why in a `Failure`, a timeout one of
  them: `Event::Failed`, `EndpointError::Failed`.
- `no_std` with an allocator, but for `endpoint`; Rust 1.88.
