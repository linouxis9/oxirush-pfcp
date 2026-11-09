# Benchmarks of oxirush-pfcp

A package of its own, which the published crate does not have. `measure` runs one
workload on one message, ROUNDS times, and prints the time of a round; with the feature
`heap`, it counts the allocations of one round with dhat.

```sh
cargo build --release --features tree        # measure, with the workloads of the trees
taskset -c 1 target/release/measure decode ser-16 100000
cargo build --release --features heap,tree   # measure, counting the allocations of a round
target/release/measure decode ser-16 1
```

## The messages

- `heartbeat`: a Heartbeat Request with a Source IP Address, 41 octets.
- `ser-4` and `ser-16`: Session Establishment Requests the size of those of a lab:
  4 or 16 PDRs, as many FARs, half as many URRs and a QER, with the SMF's Node ID as an
  FQDN; 820 and 2,824 octets.
- `go-pfcp-ser`: the Session Establishment Request "Multiple IEs" of go-pfcp's tests,
  2,110 octets, with `PFCP_VECTORS` naming the file of go-pfcp's vectors
  (`tests/go-pfcp-vectors.py`).
- `captures`: the 213 messages of the lab runs, each once a round, with
  `PFCP_CAPTURES=tests/captures/messages.tsv`.

## The workloads

| Workload | What it does |
|---|---|
| `frame` | The IEs walked as slices (`framing`), without decoding |
| `decode` | `Message::decode` |
| `read` | `decode`, then each value that a program takes from the message read |
| `encode` | `Message::encode` of a decoded message |
| `check` | `Message::check` of a decoded message |
| `to_tree`, `from_tree` | The tree of a decoded message, and the message of its tree |

`compare/go-pfcp/` runs `decode`, `read` and `encode` with go-pfcp v0.0.24: `decode` is
`message.Parse`, which leaves each IE as octets until a value is asked; `read` is
`message.Parse`, then the same values through go-pfcp's accessors, the IEs of each
grouped IE taken once; `encode` is `MarshalTo` of the parsed message. It prints the
allocations that the Go runtime counts for a round.

```sh
cd compare/go-pfcp && go build -o go-pfcp . && cd ../..
taskset -c 1 compare/go-pfcp/go-pfcp read 100000 HEX
```

## At 637fadf

The time of a round, the median of five runs of about a second, the lower of two series,
and the allocations of a round, taken on 2026-11-09 at 637fadf with Rust 1.98.1 and
Go 1.27.3, on one core of an AMD Ryzen 7 5700G (Linux 7.0): `measure` of the feature
`tree` for the times, of `heap,tree` for the allocations, and go-pfcp of the same octets.
The machine was shared, and the other thread of the core busy at times: the times are
notes, and go-pfcp's were taken beside this crate's, under the same load; the allocations
are exact. A cell is the time of a round, then its allocations.

| Message | | `frame` | `decode` | `read` | `encode` | `check` | `to_tree` | `from_tree` |
|---|---|---|---|---|---|---|---|---|
| heartbeat | this crate | 0.03 µs, 0 | 0.05 µs, 1 | 0.05 µs, 1 | 0.04 µs, 1 | 0.07 µs, 0 | 0.36 µs, 16 | 0.50 µs, 13 |
| | go-pfcp |  | 0.19 µs, 5 | 0.18 µs, 5 | 0.23 µs, 2 |  |  |  |
| ser-4 | this crate | 0.95 µs, 0 | 2.5 µs, 22 | 2.6 µs, 22 | 1.3 µs, 1 | 5.4 µs, 0 | 14.0 µs, 288 | 20.7 µs, 305 |
| | go-pfcp |  | 8.7 µs, 128 | 18.2 µs, 292 | 12.3 µs, 2 |  |  |  |
| ser-16 | this crate | 3.5 µs, 0 | 8.2 µs, 70 | 8.6 µs, 70 | 4.1 µs, 1 | 16.6 µs, 0 | 46.4 µs, 965 | 67.8 µs, 1,055 |
| | go-pfcp |  | 31.4 µs, 441 | 65.8 µs, 1,043 | 46.7 µs, 2 |  |  |  |
| go-pfcp-ser | this crate | 2.1 µs, 0 | 5.8 µs, 60 | 5.9 µs, 60 | 3.3 µs, 1 | 54.2 µs, 324 | 41.8 µs, 860 | 56.8 µs, 697 |
| | go-pfcp |  | 20.3 µs, 261 | 37.6 µs, 526 | 29.7 µs, 2 |  |  |  |
| the 213 captures | this crate | 21.9 µs, 0 | 69.9 µs, 519 | 71.8 µs, 519 |  |  |  |  |

Decoding allocates the box of the message, each row that is a list, of one value too,
each conditional or optional grouped IE, and each octet string longer than 22 octets.
`encode` allocates once, as it computes the length first, and `check` allocates nothing
for a message without a deviation that keeps no IE as octets: one that keeps some, as
go-pfcp's does, is read again from its octets, an `encode` and a `decode` that its check
counts, and has deviations, whose paths it writes.
