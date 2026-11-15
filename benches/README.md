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
| `encode_into` | `Message::encode_into` of a decoded message, into a buffer that is cleared and used again |
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

## At cdf4a13

The time of a round and the allocations of a round, taken on 2026-11-15 at cdf4a13
with Rust 1.100.0 and Go 1.27.4, on core 2 of an Intel Xeon E5-2680 v4 (Broadwell,
2.4 GHz; a KVM guest bound to NUMA node 0; Linux 7.0): `measure` of the feature `tree`
for the times, of `heap,tree` for the allocations, and go-pfcp of the same octets. Every
cell ran once a round, for about half a second, in turns with the others, ten rounds:
a time is the median of the ten. The ten runs of 33 of the 43 cells were within 15 % of
each other, and those of the others within 49 % (`encode` of go-pfcp-ser); for every
cell that go-pfcp has, its ten times and this crate's do not overlap. The allocations
are exact. A cell is the time of a round, then its allocations.

| Message | | `frame` | `decode` | `read` | `encode` | `check` | `to_tree` | `from_tree` |
|---|---|---|---|---|---|---|---|---|
| heartbeat | this crate | 0.07 µs, 0 | 0.09 µs, 1 | 0.09 µs, 1 | 0.08 µs, 1 | 0.17 µs, 0 | 0.59 µs, 7 | 1.0 µs, 15 |
| | go-pfcp |  | 0.41 µs, 5 | 0.41 µs, 5 | 0.48 µs, 2 |  |  |  |
| ser-4 | this crate | 2.1 µs, 0 | 4.4 µs, 22 | 4.5 µs, 22 | 2.4 µs, 1 | 11.1 µs, 12 | 13.1 µs, 113 | 63.5 µs, 307 |
| | go-pfcp |  | 19.0 µs, 128 | 39.4 µs, 292 | 24.2 µs, 2 |  |  |  |
| ser-16 | this crate | 7.5 µs, 0 | 15.7 µs, 70 | 16.7 µs, 70 | 7.4 µs, 1 | 32.2 µs, 12 | 51.9 µs, 364 | 198.2 µs, 1,057 |
| | go-pfcp |  | 68.7 µs, 441 | 146.6 µs, 1,043 | 91.0 µs, 2 |  |  |  |
| go-pfcp-ser | this crate | 4.5 µs, 0 | 10.5 µs, 60 | 10.7 µs, 60 | 7.4 µs, 1 | 117.2 µs, 358 | 51.6 µs, 352 | 181.7 µs, 699 |
| | go-pfcp |  | 44.0 µs, 261 | 78.6 µs, 526 | 59.4 µs, 2 |  |  |  |
| the 213 captures | this crate | 47.2 µs, 0 | 129.4 µs, 519 | 137.1 µs, 519 |  |  |  |  |

Decoding allocates the box of the message, each row that is a list, of one value too,
each conditional or optional grouped IE, and each octet string longer than 22 octets.
`encode` allocates once, as it computes the length first, and `check` allocates 12 times
for a message without a deviation that keeps no IE as octets (none for the heartbeat):
one that keeps some, as go-pfcp's does, is read again from its octets, an `encode` and a
`decode` that its check counts, and has deviations, whose paths it writes.
