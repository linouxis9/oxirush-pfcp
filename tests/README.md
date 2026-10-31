# The tests of oxirush-pfcp

`cargo test --all-features` runs them all.

| Test | What it checks |
|---|---|
| `spec` | The crate against TS 29.244 V19.6.0: every message type, IE type, table row, figure and table of values, and the requirements of clause 6 (`spec/`) |
| `captures` | The 213 messages of the lab runs (`captures/`): each decodes, encodes back byte for byte, has a tree that reads back, and is checked on its interface |
| `check` | What `check()` and `check_on()` find, with the clause and the Cause of each |
| `node` | The procedures of clause 6 on a `Node`: one test for each requirement of `spec/requirements.tsv` that names it |
| `endpoint` | Two endpoints on the loopback, and a request that times out |
| `codec` | The codec, the trees and paths, the IEs that a scope keeps as octets, and the vectors of `PFCP_VECTORS` |
| `serde` | A message and an IE as JSON through serde |
| `readme` | Each Rust block of the README prints what the README shows |

## The document

`spec/extract.py` writes the fixtures of `spec/` from TS 29.244 V19.6.0, which it checks by
its SHA-256 (`--fetch` takes it from the 3GPP archive). `spec/errata.tsv` names the
errata of the document that the crate meets, and what it takes instead; `spec/fields.tsv`
where one field of the crate stands for several names of a figure.

## The lab runs

`captures/messages.tsv` has the PFCP messages of seven lab runs on 2026-10-31, taken on
the loopback of an isolated network namespace, each with its run, its number in the run,
its addresses and its interface:

| Runs | Peer | Interface |
|---|---|---|
| 5GS lifecycle, handover, UPF restart | Open5GS 157f611a (SMF and UPF) | N4 |
| EPS lifecycle, handover | Open5GS 157f611a (SGW-C and SGW-U; SMF and UPF as PGW-C and PGW-U) | Sxa, Sxb |
| 5GS lifecycle, handover | free5GC 3b34a08e (SMF and go-upf) | N4 |

## go-pfcp's vectors

`go-pfcp-vectors.py` takes the 41 vectors of go-pfcp's message tests, which are not
committed, for `PFCP_VECTORS`:

```sh
python3 tests/go-pfcp-vectors.py "$(go mod download -json github.com/wmnsk/go-pfcp@v0.0.24 | jq -r .Dir)" /tmp/vectors.tsv
PFCP_VECTORS=/tmp/vectors.tsv cargo test --all-features --test codec other_vectors -- --nocapture
```

Each decodes and encodes back byte for byte, and its tree reads back. 16 of them have
their IEs in another order than their tables', which their trees put in that order.

## What the crate finds in others

Each of these is against TS 29.244 V19.6.0, at the version named.

**Open5GS 157f611a.** The SMF, as the PGW-C of EPS, sends Create BAR on Sxb in its
Session Establishment Request; Table 7.5.2.1-1 has Create BAR on Sxa and N4 only.
`smf_sess_add_by_apn()` (`src/smf/context.c`) gives each session a BAR, and
`smf_n4_build_session_establishment_request()` (`src/smf/n4-build.c`) sends it whatever
the interface. The test `captures` expects it.

**go-pfcp v0.0.24**, in its test vectors:

- The UE IP address Pool Identity has a length of one octet, and §8.2.128 has two: the
  IE does not decode, in UE IP address Pool Information, Create PDR and UE IP Address
  Usage Information.
- SMF Set ID has no spare octet before its FQDN, which §8.2.131 has
  (`ie/smf-set-id.go`).
- IE 198 is a TSN Bridge ID of a MAC address, six octets, where V19.6.0 has the 5GS User
  Plane Node ID of eight (`ie/tsn-bridge-id.go`).
- Spare bits are set: Usage Report Trigger (octet 7, bits 8 and 7), QER Control
  Indications (bits 2 and 3), Outer Header Removal (octet 6, bit 2).
- IEs that their tables do not have: Measurement Method in GTP-U Path QoS Control
  Information, Redundant Transmission Parameters (IE 255) in Create FAR and Update FAR,
  Access Availability Control Information in Session Report, Time Offset Threshold and
  Cumulative rateRatio Threshold in Clock Drift Report, Packet Rate Status in Update QER,
  Application ID, Provide ATSSS Control Information and Created Bridge/Router Info where
  they are, and IE type 116, which no table of Release 19 has.
- Access Type 3, which Table 8.2.153-1 has as spare.
- Session Modification Requests that create, update and remove one rule (§6.3.3.2), two
  Session Establishment Requests without Node ID, CP F-SEID, Create PDR and Create FAR,
  and a Heartbeat Request without its Recovery Time Stamp.

**tshark 4.6.4** names IE type 170 "Unknown" while it dissects it as a MAR ID, and stops
at the one-octet Pool Identity length of go-pfcp's vector.

These are recorded, and reported to no one.
