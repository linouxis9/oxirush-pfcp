# Changelog

All notable changes to `oxirush-pfcp` are recorded here.

## Unreleased

### Added

- `request_of()`: the request that a response of Table 7.3-1 answers, which is the type
  before it, as 50, the Session Establishment Request, of 51. It is `None` for a
  request, for 11, the Version Not Supported Response, which answers a message of any
  type, and for a type that the table does not have.
- The test `go_pfcp` and the weekly workflow `go-pfcp`: go-pfcp v0.0.24 reads the
  messages of the fuzz corpora and go-pfcp's vectors out of process, and each difference
  from decode() and check() is a row of `tests/go-pfcp-differences.tsv`, with its clause
  and the side that the clause supports.

### Removed

- The fuzz target `differential`, which compared the crate with rs-pfcp 0.5.0. It
  failed the scheduled runs on panics and strict readings of rs-pfcp, not on the crate.
  The tests compare the crate with go-pfcp.

## 0.1.0 - 2026-11-16

The first version. It implements TS 29.244 V19.6.0 (2026-06):

- Decodes and encodes every message and IE type of N4, N4mb, Sxa, Sxb and Sxc,
  byte for byte, and builds them with `new()` and `with_*()`. `encode_into()`
  appends a message to a buffer that the caller uses again.
- `check()` validates one message against the IE tables of clause 7 and the
  values of clause 8.2 on an interface. Each deviation has its path, its clause
  and the Cause to answer with.
- `check_with()` also validates a response against its request, a message
  against the features that the two functions announced, and a message against
  the state of its session (`SessionRules`).
- With `tree`, a message converts to a tree that prints as JSON and can be read
  and edited by path. Any format of serde writes the tree. `IeTypeInfo::takes()`
  says what the tree of the value of an IE type takes, member by member
  (`tree::Takes` of oxirush-utils), and `IeTypeInfo::tree_of()` gives the tree
  of one IE from its octets.
- With `node`, `Node` is a PFCP node without I/O: delivery and retransmission,
  heartbeats, associations, sessions, load and overload control, and bundles.
- With `endpoint`, `Endpoint` runs a node on a Tokio UDP socket.
- `no_std` with an allocator, except for `endpoint`. Rust 1.88 or later.
