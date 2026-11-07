# Changelog

All notable changes to `oxirush-pfcp` are recorded here.

## 0.1.0 - unreleased

The first version, of TS 29.244 V19.6.0 (2026-06): every message and IE type, decoded and
encoded back byte for byte; `check()`, with the clause and the Cause of each deviation;
trees, paths and serde; `Node`, a PFCP entity without I/O; `Endpoint`, a node on a Tokio
socket. `no_std` with an allocator; Rust 1.88.

What the node decides itself changed before the release:

- A request that names a session or an association that is not its sender's, as another
  SMF of a set sends (§5.22), goes to the caller as `Inbound::stranger`. The node no
  longer answers those of set members "No established PFCP Association" itself, and
  `SmfSet`, `NodeConfig::smf_set` and `NodeConfig::other_entities` are gone.
- The node reads its own BUNDL and MPAS from the features that the caller writes in its
  association messages: `NodeConfig::bundling` is gone.
- A session that the caller adopts is routed; the holder of its association heartbeats
  its peer.
