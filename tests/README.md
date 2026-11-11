# The tests of oxirush-pfcp

`cargo test --all-features` runs them all: the test `spec` needs the feature `spec`, which
gives it the layout of each value as the crate reads it.

| Test | What it checks |
|---|---|
| `spec` | The crate against TS 29.244 V19.6.0: every message type and IE type; every row of a table, with its presence, interfaces, IE type and repetition, and its bound; every flag and field of a figure, with its octet, bits, order and width, and the conditions that the sentences of its clause give, on a flag or on the value of another field, each of which has its flag and its field in the crate or fails the test, those of the media identification of an SDF Filter with the reader of its figure, but for the four values read by hand, which `codec` compares; the sentences of clause 8.2 on which flags are set, together, with the field of another flag, with the value of another field or the Cause of the message, or always, each with the rule that checks it (`spec/flag-rules.tsv`), and those that bound the value of a field, likewise (`spec/range-rules.tsv`); every table of values, with the values that it reserves or that a note of it has rejected, and the values that a receiver reads as another; the constructors by interface; and the requirements of clause 6 (`spec/`) |
| `captures` | The 213 messages of the lab runs (`captures/`): each decodes, encodes back byte for byte, has a tree that reads back, and is checked on its interface; and `check(m)` is `check(Message::decode(m.encode()))` of each, and of each with one of its IEs, at every level, written as its octets, of a null length, or after one of a null length; one written as its octets changes nothing of what `check()` finds; the same of the messages of a fuzz corpus (`PFCP_CORPUS`, below) |
| `check` | What `check()` finds on each interface, with the clause and the Cause of each, a module of `check/` for each subject: `tables`, the IEs that a scope needs, may have, repeats and keeps as octets; `conditions`, those that the IEs of a scope show; `reading`, a message as its receiver reads its octets; `values`, the fields, flags and values of clause 8.2; `header`, its flags and the SEID; `rejections`, a rejection and the Causes of the answers; `interfaces`, the Appl. columns |
| `node` | The procedures of clause 6 on a `Node`, a module of `node/` for each clause: `delivery` (§6.4, §7.6), `associations` (§6.2), `controls` (§6.2.3, §6.2.4), `sessions` (§6.3, §5.22) and `bundles` (§6.5); one test for each requirement of `spec/requirements.tsv` that names it |
| `endpoint` | Two endpoints on the loopback: a setup and a session, both ways at once through a `Handle`, a request sent through `Handle::with`, a probe that answers twice, a request that times out, a queue full of entries or of octets and a full node, an `Incoming` dropped or answered in vain, an answer that does not encode, a heartbeat of never, a request dropped before and after the task takes it, `close()` |
| `src/endpoint.rs` | Through `Handle::request`, that a request dropped once queued closes its reply before its cancel goes, as the waker of the cancels sees it; what a request takes in the incoming queue |
| `allocation` | What the node allocates and keeps of what it rejects unread: the datagrams of hosts without an association, and their rejections; and what a decoded message takes at most, per octet, the figure of SECURITY.md: 242.6 times, found by search over the lists of grouped IEs of every table, with one to three levels of grouped IEs in each entry |
| `codec` | A module of `codec/` for each subject: `paths`, what `select` and `set` take; `trees`, the tree of a message and of its values; `kept`, the IEs that a scope keeps as octets; `values`, the fields against their figures, the octets of the four values read by hand among them (Node ID, FQ-CSID, MAC Addresses Detected and Removed); `messages`, headers, lengths, framing, and the vectors of `PFCP_VECTORS` |
| `serde` | A message and an IE as JSON through serde |
| `readme` | Each Rust block of the README prints what the README shows |

## The document

`spec/extract.py` writes the fixtures of `spec/` from TS 29.244 V19.6.0, which it checks by
its SHA-256 (`--fetch` takes it from the 3GPP archive): CI writes them again and fails
when they differ. The places of a figure are those of its cells by their widths, against
the row of bit numbers. `spec/errata.tsv` names the errata of the document that the crate
meets, and what it takes instead; `spec/fields.tsv` where one field of the crate stands
for several names of a figure.

The inventory of the document that the test `spec` holds the crate to:

- `spec/errata.tsv`: the errata of the document that the crate meets, and the readings of
  the crate where the document names no value;
- `spec/requirements.tsv`: each requirement of the procedures of clause 6, with the test
  of `node` that checks it, or why it is the application's, above the crate;
- `spec/flag-rules.tsv`: each sentence of clause 8.2 that says which flags of an IE are
  set, together, with the field of another flag, with the value of another field or the
  Cause of the message, or always, with the rule of `check()` that checks it, or why a value does not show it alone;
- `spec/row-conditions.tsv`: each row of a table of clause 7 whose comment has the IE
  there by a flag of its own or by an IE beside it, which `check()` tells in a message
  that has the row at its place;
- `spec/range-rules.tsv`: each sentence of clause 8.2 that bounds the value of a field,
  with the rule of `check()` that checks it, or why no value of the field breaks it;
- the octets of the four values that the crate reads by hand, as their figures follow a
  type or a number (Node ID, FQ-CSID, MAC Addresses Detected and Removed), which the test
  `codec` compares with their figures.

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

## A corpus of the fuzz targets

`PFCP_CORPUS` names a directory of messages, a corpus of the fuzz targets `decode`,
`tree`, `check` or `differential`: of each of them, and of each with one of its IEs, at
every level, written as its octets, of a null length, or after one of a null length,
`check(m)` is `check(Message::decode(m.encode()))` on every interface.

```sh
PFCP_CORPUS=fuzz/corpus/decode cargo test --release --all-features --test captures -- --ignored
```

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
0 out. The APN/DNN of each Session Establishment Request, on N4 and on Sxb, is the labels
of the Network Identifier alone, `internet`, where §8.2.117 has "the full APN/DNN with
both the APN/DNN Network Identifier and APN/DNN Operator Identifier" (TS 23.003 clauses
9.1.1 and 9.1.2, `internet.mnc070.mcc999.gprs`): `smf_n4_build_session_establishment_request()`
(`src/smf/n4-build.c`) builds it from `sess->session.name`, with `ogs_fqdn_build()`. The
test `captures` expects the four.

**free5GC 3b34a08e** (smf 796a2de8). The SMF gives each Update Forwarding Parameters of
a Session Modification Request a PFCPSMReq-Flags, whose SNDEM it sets where an end
marker is to be sent: without one the IE has no flag (`0031 0001 00`), where Table
7.5.4.3-2 has it "included if at least one of the flags is set to "1"".
`farToUpdateFAR()` (`internal/pfcp/message/build.go`) writes
`PFCPSMReqFlags: &pfcpType.PFCPSMReqFlags{Sndem: far.ForwardingParameters.SendEndMarker}`
whatever the flag. The test `captures` expects it in seven messages.

**go-pfcp v0.0.24**, in its test vectors, which `go-pfcp-deviations.tsv` lists as the
test `codec` expects them (`other_vectors_round_trip`, with `--ignored` and
`PFCP_VECTORS`):

- The UE IP address Pool Identity has a length of one octet, and §8.2.128 has two: the
  IE does not decode, in UE IP address Pool Information, Create PDR and UE IP Address
  Usage Information.
- SMF Set ID has no spare octet before its FQDN, which §8.2.131 has
  (`ie/smf-set-id.go`): the length of the first label is read as the spare octet, and
  the rest is no labels of RFC 1035.
- PDIs with a Traffic Endpoint ID and the Local F-TEID, Network Instance and UE IP
  address that Table 7.5.2.2-2 then has absent, and an SDF Filter beside an Ethernet
  Packet Filter, which its NOTE 3 has absent.
- IE 198 is a TSN Bridge ID of a MAC address, six octets, where V19.6.0 has the 5GS User
  Plane Node ID of eight (`ie/tsn-bridge-id.go`).
- Spare bits are set: Usage Report Trigger (octet 7, bits 8 and 7), QER Control
  Indications (bits 2 and 3), Outer Header Removal (octet 6, bit 2), and bits 8 and 7 of
  the octets of the Paging Policy Indication value and of the QFI of Downlink Data
  Service Information, which §8.2.27 has spare
  (`NewDownlinkDataServiceInformation(true, true, 0xff, 0xff)` in
  `message/session-report-request_test.go`), and bits 8 to 5 of the first octet of the
  Flow Label of SDF Filter, which §8.2.5 has spare (`NewSDFFilter(..., "ddd", ...)`).
- Additional Usage Reports Information has AURI with a Number of Additional Usage Reports
  other than 0, which §8.2.91 has the sender set to 0 and the receiver ignore when AURI
  says that more follow, as a spare bit, of no Cause:
  `NewAdditionalUsageReportsInformation(num)` (`ie/additional-usage-reports-information.go`)
  sets AURI for any number but 0.
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
- The UPF Instance ID of the Association Setup Request and Response is
  `11111111-2222-2222-3333-333344444444`, a UUID of version 2, where §8.2.175 has "a
  Universally Unique Identifier (UUID) version 4" (`ie.NewNFInstanceID(...)` in
  `message/association-setup-request_test.go`).
- Transport Level Marking of 0x1111, whose mask, the second octet, §8.2.12 has "set to
  "0xFC"" (`ie.NewTransportLevelMarking(0x1111)` in the tests of `message/`), in
  Forwarding Parameters, Duplicating Parameters and their updates, and as the DSCP of
  GTP-U Path QoS Control Information and of QoS Information.
- Session Establishment Requests with a SEID other than 0 in their header, where the
  peer's SEID is not known yet (§7.2.2.4.2).
- Their APN/DNN is `some.apn.example`, a Network Identifier without the Operator
  Identifier that §8.2.117 has with it (`ie.NewAPNDNN("some.apn.example")` in
  `message/session-establishment-request_test.go`).
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
