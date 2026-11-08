# Changelog

All notable changes to `oxirush-pfcp` are recorded here.

## 0.1.0 - unreleased

The first version, of TS 29.244 V19.6.0 (2026-06):

- Every message and IE type of N4, N4mb, Sxa, Sxb and Sxc, decoded and encoded back byte
  for byte, and built with `new()` and `with_*()`; a message of its body with
  `Message::node` and `Message::session`. `IE_TYPES` and `ie_type_info()` give the clause
  and the members of each IE type. A field that a value always has is a plain field, as
  the SEID of an F-SEID, and one that its flags have or not an `Option`. `FSeid::ipv4()`
  and `FSeid::ipv6()` build an F-SEID of one address, as `FTeid::ipv4()` an F-TEID.
- `check()`: how a message breaks the tables and clauses on an interface, each deviation
  with its path, its clause and the Cause of the answer; `deviations()` of a value on its
  own. `Row::on` gives what a row is on an interface, or on a set of them: its presence,
  the IEs that a message needs and how many it may have, and `None` where it is not: its
  IEs have no Cause there (§7.6.9). A field that rows share, which the wire does not tell
  apart, has them in `Row::roles`, each with its presence, its interfaces and how many IEs
  of it may be there. A field that its clause encodes as another IE is checked as that IE:
  the Destination Interface of a Remote GTP-U Peer, and the QFIs of a PMF Control
  Information, which are `SixBits` as a QFI is.
- With `tree`, a message as a tree that prints as JSON, on oxirush-utils 0.2, whose
  `tree` the crate exports at its root, and read and edited by path (`paths::select`,
  `paths::set`); with `serde`, serialized as its tree. What a message lacks selects
  nothing, whatever the path names below it: a misspelt name below a value or a field
  that is not there is not told, and `set` writes a value that a message lacks whole. An
  error of `Message::from_tree` is at a path that `paths::select` takes. A tree writes
  each field that its value always has; it leaves out a flag that is not set and a field
  that its flags do not have.
- With `node`, `Node`, a PFCP entity without I/O: delivery and retransmission (§6.4),
  heartbeat, associations, sessions, load and overload control, and bundles (§6.5). A
  request that names another's session or association, as another SMF of a set sends
  (§5.22), goes to the caller as `Received::stranger`, and the one of SEID 0 that hands a
  session over is answered as one of the adopted session (`respond_as`); one that says
  its priority has it in `Received::priority`. An IPv4 peer that a socket of both
  families gives at its IPv4-mapped address is its IPv4 address. A probe's answer
  (`respond_message`) changes the node as its peer reads the octets sent.
- With `endpoint`, `Endpoint`, a node on a Tokio UDP socket, and its `Handle`.
- A request that ends without its response says why in a `Failure`, a timeout one of
  them: `Event::Failed`, `EndpointError::Failed`.
- `no_std` with an allocator, but for `endpoint`; Rust 1.88.
