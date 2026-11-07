# Changelog

All notable changes to `oxirush-pfcp` are recorded here.

## 0.1.0 - unreleased

The first version, of TS 29.244 V19.6.0 (2026-06).

- Every message of Table 7.3-1 and every IE type of Table 8.1.2-1, decoded
  and encoded back byte for byte: an IE that its table does not have, a
  repeated one and a value that does not decode are kept as their octets, in
  their place. A message is built with `new()`, or `new_sxa()` to
  `new_n4mb()` where the mandatory IEs of the interfaces differ, and
  `with_*()`.
- `check(interface)`: what a message breaks of its tables and of its values,
  the rules of clause 8.2 on which flags are set, together, with a value or
  always, on an interface or a set of them, with the clause, and the Cause
  and the Offending IE that its receiver answers with (§7.6).
- `tree` and `serde`: a message as a tree, read and edited by path, and as
  JSON.
- `node`: a PFCP entity without I/O, for an SMF, a UPF or a test tool:
  reliable delivery (§6.4), with the peers' retransmissions of the requests
  that it holds as events, heartbeat, associations, sessions, load and
  overload control and message priority, and what a peer does wrong as an
  event. A deletion whose usage reports follow keeps its session until the
  last of them (§5.2.2.3.1). What it keeps of its peers is bounded, and what
  it drops counted.
  With `SmfSet`, the requests that the SMF sets of §5.22 let come from another
  SMF of a set go to the caller, and a release keeps what MPAS keeps; with
  `other_entities`, a handover to another PFCP entity of the same SMF too,
  which then controls the session that it adopts.
- `endpoint`: a node on a Tokio UDP socket. The `Endpoint` takes the peers'
  requests and the events, and a `Handle`, which clones, sends the node's
  requests and reaches its state, from any task.
- `no_std` with an allocator. The minimum supported Rust version is 1.88.
- The test `spec` compares the crate with the fixtures that
  `tests/spec/extract.py` takes from the document.
