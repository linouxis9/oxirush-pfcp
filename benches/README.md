# Benchmarks of oxirush-pfcp

A package of its own, which the published crate does not have. `measure` runs one
workload on one message, many times, for `perf stat`; the figures are the
instructions of one round, `(count of 2N rounds − count of N rounds) / N`, and the
times are notes. They were taken on one core of an AMD Ryzen 7 5700G (Linux 7.0,
Rust 1.88.0) on 2026-11-01, at 8a26de2, with N = 2,000.

```sh
cargo build --release                       # measure
cargo build --release --features heap      # measure, counting allocations with dhat
cargo build --release --features tree      # with the workloads of the trees
perf stat -e instructions:u taskset -c 1 target/release/measure decode ser-16 2000
```

`perf` counts the instructions of a user when `kernel.perf_event_paranoid` is at most
2 (`sudo sysctl kernel.perf_event_paranoid=2`), or as root; without it, `measure` still
prints the time of a round.

## The messages

- `heartbeat`: a Heartbeat Request with a Source IP Address, 41 octets.
- `ser-4` and `ser-16`: Session Establishment Requests the size of those of a lab:
  4 or 16 PDRs, as many FARs, half as many URRs and a QER, with the SMF's Node ID as an
  FQDN; 820 and 2,824 octets.
- `go-pfcp-ser`: the Session Establishment Request "Multiple IEs" of go-pfcp's tests,
  2,110 octets, with `PFCP_VECTORS` naming the file of go-pfcp's vectors.

## The workloads

| Workload | What it does |
|---|---|
| `frame` | The IEs walked as slices (`framing`), without decoding |
| `decode` | `Message::decode` |
| `read` | `decode`, then each value that a program takes from the message read |
| `encode` | `Message::encode` of a decoded message |
| `check` | `Message::check` of a decoded message |
| `to_tree`, `from_tree` | The tree of a decoded message, and the message of its tree |

Instructions of a round:

| Message | decode | encode | check | to_tree | from_tree |
|---|---|---|---|---|---|
| heartbeat | 747 | 654 | 284 | 5,762 | 5,040 |
| ser-4 | 28,900 | 16,444 | 11,069 | 161,708 | 124,057 |
| ser-16 | 97,864 | 59,520 | 37,433 | 580,030 | 421,180 |
| go-pfcp-ser | 61,862 | 36,252 | 91,487 | 514,447 | 322,591 |

Decoding allocates the box of the message, each list of grouped IEs, each conditional or
optional grouped IE, and each octet string longer than 22 octets: once for the heartbeat,
9 times for ser-4 and 15 times for ser-16. `encode` allocates once, as it computes the
length first, and `check` allocates nothing for a message without a deviation (go-pfcp's
has some, whose paths it writes).

## Against go-pfcp

`compare/go-pfcp/` runs the same workloads with go-pfcp v0.0.24: `decode` is
`message.Parse`, which leaves each IE as octets until a value is asked; `read` is
`message.Parse`, then the same values through go-pfcp's accessors, the IEs of each
grouped IE taken once; `encode` is `MarshalTo` of the parsed message.

```sh
cd compare/go-pfcp && go build -o go-pfcp . && cd ../..
sudo perf stat -e instructions:u taskset -c 1 compare/go-pfcp/go-pfcp read 1000 HEX
```

Instructions of a round, and go-pfcp's over this crate's:

| Message | decode | | read | | encode | |
|---|---|---|---|---|---|---|
| | this crate | go-pfcp | this crate | go-pfcp | this crate | go-pfcp |
| heartbeat | 747 | 2,169 (2.9x) | 761 | 2,703 (3.6x) | 654 | 3,065 (4.7x) |
| ser-4 | 28,900 | 124,082 (4.3x) | 30,232 | 223,004 (7.4x) | 16,444 | 131,142 (8.0x) |
| ser-16 | 97,864 | 427,883 (4.4x) | 102,660 | 899,808 (8.8x) | 59,520 | 473,962 (8.0x) |
| go-pfcp-ser | 61,862 | 264,900 (4.3x) | 62,661 | 492,027 (7.9x) | 36,252 | 300,655 (8.3x) |

go-pfcp's instructions vary from run to run with its collector, by up to a sixth for
`encode` between e669488 and 8a26de2. Times were not taken at 8a26de2, on a shared
machine. At 526bee4, on an idle
core, `read` of ser-16 took 6.5 µs here and 67 µs with go-pfcp, which allocates 1,043
times where this crate allocates 15 times.
