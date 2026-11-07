# The tests of oxirush-pfcp

`cargo test --all-features` runs them all.

| Test | What it checks |
|---|---|
| `spec` | The crate against TS 29.244 V19.6.0: every message type and IE type; every row of a table, with its presence, interfaces, IE type and repetition, and its bound; every flag and field of a figure, with its octet, bits, order and width, and the conditions that the sentences of its clause give, but for the four values read by hand, which `codec` compares; the sentences of clause 8.2 on which flags are set, together, with the value of another field or always, each with the rule that checks it (`spec/flag-rules.tsv`); every table of values, and the values that a receiver reads as another; the constructors by interface; and the requirements of clause 6 (`spec/`) |
| `captures` | The 213 messages of the lab runs (`captures/`): each decodes, encodes back byte for byte, has a tree that reads back, and is checked on its interface |
| `check` | What `check()` finds on each interface, with the clause and the Cause of each |
| `node` | The procedures of clause 6 on a `Node`: one test for each requirement of `spec/requirements.tsv` that names it |
| `endpoint` | Two endpoints on the loopback: a setup and a session, both ways at once through a `Handle`, a probe that answers twice, a request that times out, a full queue and a full node, an `Incoming` dropped or answered in vain, an answer that does not encode, a heartbeat of never, a request dropped before and after the task takes it, `close()` |
| `src/endpoint.rs` | Through `Handle::request`, that a request dropped once queued closes its reply before its cancel goes, as the waker of the cancels sees it |
| `allocation` | What the node allocates and keeps of what it rejects unread: the datagrams of hosts without an association, and their rejections |
| `codec` | The codec, the trees and paths, the IEs that a scope keeps as octets, the octets of the four values read by hand against their figures (Node ID, FQ-CSID, MAC Addresses Detected and Removed), and the vectors of `PFCP_VECTORS` |
| `serde` | A message and an IE as JSON through serde |
| `readme` | Each Rust block of the README prints what the README shows |

## The document

`spec/extract.py` writes the fixtures of `spec/` from TS 29.244 V19.6.0, which it checks by
its SHA-256 (`--fetch` takes it from the 3GPP archive): CI writes them again and fails
when they differ. The places of a figure are those of its cells by their widths, against
the row of bit numbers. `spec/errata.tsv` names the errata of the document that the crate
meets, and what it takes instead; `spec/fields.tsv` where one field of the crate stands
for several names of a figure.

`spec/mutations.tsv` has changes of the crate that the test `spec` must fail on: a value,
a list, an interface, a bit, a condition, an order, a width, a constructor. `spec/mutate.py`
makes each in a copy of the crate and runs the test, which CI does too:

```sh
python3 tests/spec/mutate.py
```

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
PFCP_VECTORS=/tmp/vectors.tsv cargo test --all-features --test codec other_vectors -- --ignored --nocapture
```

Each decodes and encodes back byte for byte, and its tree reads back. 16 of them have
their IEs in another order than their tables', which their trees put in that order.

## What the crate finds in others

Each of these is against TS 29.244 V19.6.0, at the version named.

**Open5GS 157f611a.** The SMF, as the PGW-C of EPS, sends Create BAR on Sxb in its
Session Establishment Request; Table 7.5.2.1-1 has Create BAR on Sxa and N4 only.
`smf_sess_add_by_apn()` (`src/smf/context.c`) gives each session a BAR, and
`smf_n4_build_session_establishment_request()` (`src/smf/n4-build.c`) sends it whatever
the interface. The SMF that restores a session to a UPF that restarted, with the RESTI
flag, gives the header of its Session Establishment Request the UPF's SEID from before
the restart, which the UPF no longer has, where §7.2.2.4.2 has SEID 0:
`smf_5gc_pfcp_send_session_establishment_request()` (`src/smf/pfcp-path.c`) sets
`h.seid = sess->upf_n4_seid`. The UPF's first usage report of a URR without ISTM, as
that of a deletion, has no Start Time, which Tables 7.5.5.2-1, 7.5.7.2-1 and 7.5.8.3-1
have but of the start or stop of traffic and of MAC addresses: the time that a URR starts
is set by `upf_sess_urr_acc_timers_setup()` (`src/upf/context.c`), which
`upf_n4_handle_create_urr()` (`src/upf/n4-handler.c`) calls for a URR of ISTM alone, and
`ogs_pfcp_build_session_deletion_response()` (`lib/pfcp/build.c`) leaves a start time of
0 out. The test `captures` expects the three.

**go-pfcp v0.0.24**, in its test vectors, which `go-pfcp-deviations.tsv` lists as the
test `codec` expects them (`other_vectors_round_trip`, with `--ignored` and
`PFCP_VECTORS`):

- The UE IP address Pool Identity has a length of one octet, and §8.2.128 has two: the
  IE does not decode, in UE IP address Pool Information, Create PDR and UE IP Address
  Usage Information.
- SMF Set ID has no spare octet before its FQDN, which §8.2.131 has
  (`ie/smf-set-id.go`).
- IE 198 is a TSN Bridge ID of a MAC address, six octets, where V19.6.0 has the 5GS User
  Plane Node ID of eight (`ie/tsn-bridge-id.go`).
- Spare bits are set: Usage Report Trigger (octet 7, bits 8 and 7), QER Control
  Indications (bits 2 and 3), Outer Header Removal (octet 6, bit 2), and bits 8 and 7 of
  the octets of the Paging Policy Indication value and of the QFI of Downlink Data
  Service Information, which §8.2.27 has spare
  (`NewDownlinkDataServiceInformation(true, true, 0xff, 0xff)` in
  `message/session-report-request_test.go`).
- The GTP-U Path QoS Control Information of a periodic QoS Report Trigger has a
  Measurement Method where Table 7.4.4.1.3-1 has the Measurement Period, which periodic
  reporting needs, and an Association Setup Response of CP Function Features of MPAS
  (`NewCPFunctionFeatures(0x3f)`) has no SMF Set ID, which Table 7.4.4.2-1 then has.
- Reporting Frequency has bit 3 set, SESRL of an earlier release, which §8.2.168
  reserves, "set to "0" by the sender" (`NewReportingFrequency(1, 1, 1)` in
  `message/session-establishment-request_test.go` and
  `message/session-modification-request_test.go`).
- IEs that their tables do not have: Measurement Method in GTP-U Path QoS Control
  Information, Redundant Transmission Parameters (IE 255) in Create FAR and Update FAR,
  Access Availability Control Information in Session Report, Time Offset Threshold and
  Cumulative rateRatio Threshold in Clock Drift Report, Packet Rate Status in Update QER,
  Application ID, Provide ATSSS Control Information and Created Bridge/Router Info where
  they are, and IE type 116, which no table of Release 19 has.
- Access Type 3, which Table 8.2.153-1 has as spare.
- Transport Level Marking of 0x1111, whose mask, the second octet, §8.2.12 has "set to
  "0xFC"" (`ie.NewTransportLevelMarking(0x1111)` in the tests of `message/`), in
  Forwarding Parameters, Duplicating Parameters and their updates, and as the DSCP of
  GTP-U Path QoS Control Information and of QoS Information.
- Session Establishment Requests with a SEID other than 0 in their header, where the
  peer's SEID is not known yet (§7.2.2.4.2).
- Session Report Requests with a SEID other than 0 in their header and an Old CP F-SEID,
  which §7.2.2.4.2 and Table 7.5.8.1-1 have only when the SEID is 0, to move the session
  to another SMF of the set.
- QoS Monitoring Measurement has PLMF, a packet delay measurement failure, with the
  three packet delays, which §8.2.171 has without them (`NewQoSMonitoringMeasurement(0x0f,
  ...)` in `message/session-report-request_test.go`).
- Session Modification Requests that create, update and remove one rule (§6.3.3.2), two
  Session Establishment Requests without Node ID, CP F-SEID, Create PDR and Create FAR,
  and a Heartbeat Request without its Recovery Time Stamp.

**tshark 4.6.4** names IE type 170 "Unknown" while it dissects it as a MAR ID, and stops
at the one-octet Pool Identity length of go-pfcp's vector.

These are recorded, and reported to no one.
