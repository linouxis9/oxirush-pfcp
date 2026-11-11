# Changelog

All notable changes to `oxirush-pfcp` are recorded here.

## 0.1.0 - unreleased

The first version, of TS 29.244 V19.6.0 (2026-06):

- Every message and IE type of N4, N4mb, Sxa, Sxb and Sxc, decoded and encoded
  back byte for byte, and built with `new()` and `with_*()`.
- `check()`: what one message breaks of the tables of clause 7 and of the values
  of clause 8.2 on an interface, each deviation with its path, its clause and
  the Cause of the answer.
- With `tree`, a message as a tree that prints as JSON, read and edited by path;
  with `serde`, serialized as its tree.
- With `node`, `Node`, a PFCP entity without I/O: delivery and retransmission,
  heartbeat, associations, sessions, load and overload control, and bundles.
- With `endpoint`, `Endpoint`, a node on a Tokio UDP socket.
- `no_std` with an allocator, but for `endpoint`; Rust 1.88.
