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

## At 8c77e9e

The time of a round, the median of five runs of about a second, the lower of two series,
and the allocations of a round, taken on 2026-11-08 at 8c77e9e with Rust 1.98.1 and
Go 1.27.3, on one core of an AMD Ryzen 7 5700G (Linux 7.0). The machine was shared, and
the other thread of the core busy at times: the times are notes, and go-pfcp's were taken
beside this crate's, under the same load; the allocations are exact. A cell is the time
of a round, then its allocations.

| Message | | `frame` | `decode` | `read` | `encode` | `check` | `to_tree` | `from_tree` |
|---|---|---|---|---|---|---|---|---|
| heartbeat | this crate | 0.03 µs, 0 | 0.05 µs, 1 | 0.05 µs, 1 | 0.04 µs, 1 | 0.05 µs, 0 | 0.38 µs, 16 | 0.48 µs, 13 |
| | go-pfcp |  | 0.19 µs, 5 | 0.20 µs, 5 | 0.25 µs, 2 |  |  |  |
| ser-4 | this crate | 0.96 µs, 0 | 2.6 µs, 22 | 2.7 µs, 22 | 1.3 µs, 1 | 2.1 µs, 0 | 13.9 µs, 270 | 20.1 µs, 305 |
| | go-pfcp |  | 9.3 µs, 128 | 20.3 µs, 292 | 12.9 µs, 2 |  |  |  |
| ser-16 | this crate | 3.5 µs, 0 | 8.3 µs, 70 | 8.6 µs, 70 | 4.2 µs, 1 | 6.6 µs, 0 | 45.9 µs, 899 | 66.9 µs, 1,055 |
| | go-pfcp |  | 35.1 µs, 441 | 72.6 µs, 1,043 | 47.4 µs, 2 |  |  |  |
| go-pfcp-ser | this crate | 2.1 µs, 0 | 5.7 µs, 60 | 5.9 µs, 60 | 3.3 µs, 1 | 15.2 µs, 253 | 42.7 µs, 861 | 75.4 µs, 701 |
| | go-pfcp |  | 32.5 µs, 261 | 61.2 µs, 526 | 35.2 µs, 2 |  |  |  |
| the 213 captures | this crate | 34.1 µs, 0 | 146.7 µs, 519 | 148.4 µs, 519 |  |  |  |  |

Decoding allocates the box of the message, each row that is a list, of one value too,
each conditional or optional grouped IE, and each octet string longer than 22 octets.
`encode` allocates once, as it computes the length first, and `check` allocates nothing
for a message without a deviation (go-pfcp's has some, whose paths it writes).
