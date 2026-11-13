# Changelog

All notable changes to `oxirush-pfcp` are recorded here.

## 0.1.0 - unreleased

The first version. It implements TS 29.244 V19.6.0 (2026-06):

- Decodes and encodes every message and IE type of N4, N4mb, Sxa, Sxb and Sxc,
  byte for byte, and builds them with `new()` and `with_*()`.
- `check()` validates one message against the IE tables of clause 7 and the
  values of clause 8.2 on an interface. Each deviation has its path, its clause
  and the Cause to answer with.
- `check_with()` also validates a response against its request, a message
  against the features that the two functions announced, and a message against
  the state of its session (`SessionRules`).
- With `tree`, a message converts to a tree that prints as JSON and can be read
  and edited by path. Any format of serde writes the tree.
- With `node`, `Node` is a PFCP node without I/O: delivery and retransmission,
  heartbeats, associations, sessions, load and overload control, and bundles.
- With `endpoint`, `Endpoint` runs a node on a Tokio UDP socket.
- `no_std` with an allocator, except for `endpoint`. Rust 1.88 or later.
