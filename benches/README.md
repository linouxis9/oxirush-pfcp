# Benchmarks of oxirush-pfcp

A package of its own, which the published crate does not have. `measure` runs one
workload on one message, many times, for `perf stat`; the figures are the
instructions of one round, `(count of 2N rounds − count of N rounds) / N`, and the
times are notes. They were taken on one core of an AMD Ryzen 7 5700G (Linux 7.0,
Rust 1.88.0) on 2026-10-31, at ed70497, with N = 2,000.

```sh
cargo build --release                       # measure
cargo build --release --features heap      # measure, counting allocations with dhat
cargo build --release --features tree      # with the workloads of the trees
perf stat -e instructions:u taskset -c 3 target/release/measure decode ser-16 2000
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
| heartbeat | 747 | 653 | 276 | 5,763 | 5,040 |
| ser-4 | 28,897 | 16,443 | 11,020 | 161,707 | 124,122 |
| ser-16 | 97,858 | 59,519 | 37,258 | 580,030 | 420,821 |
| go-pfcp-ser | 61,858 | 36,251 | 89,646 | 514,449 | 322,547 |

Decoding allocates the box of the message, each list of grouped IEs, each conditional or
optional grouped IE, and each octet string longer than 22 octets: once for the heartbeat,
9 times for ser-4 and 15 times for ser-16. `encode` allocates once, as it computes the
length first, and `check` allocates nothing for a message without a deviation (go-pfcp's
has some, whose paths it writes).

## Owned or borrowed

`captures`, with `PFCP_CAPTURES` naming `tests/captures/messages.tsv`, decodes the 213
messages of the lab runs in a round. At f0eea08, built with `--cfg pfcp_borrowed`, a
decoded octet string borrowed the datagram in place of being copied: that took 5.3% fewer instructions on
the captures (660,493 against 625,602 a round, both 425 allocations), 8.4% on go-pfcp's
Session Establishment Request and 7.0% on ser-16. The crate is owned since: its values
have no lifetime.

## Against go-pfcp

`compare/go-pfcp/` runs the same workloads with go-pfcp v0.0.24: `decode` is
`message.Parse`, which leaves each IE as octets until a value is asked; `read` is
`message.Parse`, then the same values through go-pfcp's accessors, the IEs of each
grouped IE taken once; `encode` is `MarshalTo` of the parsed message.

```sh
cd compare/go-pfcp && go build -o go-pfcp . && cd ../..
sudo perf stat -e instructions:u taskset -c 3 compare/go-pfcp/go-pfcp read 1000 HEX
```

Instructions of a round, and go-pfcp's over this crate's:

| Message | decode | | read | | encode | |
|---|---|---|---|---|---|---|
| | this crate | go-pfcp | this crate | go-pfcp | this crate | go-pfcp |
| heartbeat | 747 | 2,545 (3.4x) | 761 | 2,197 (2.9x) | 653 | 3,180 (4.9x) |
| ser-4 | 28,897 | 116,036 (4.0x) | 30,237 | 256,929 (8.5x) | 16,443 | 126,991 (7.7x) |
| ser-16 | 97,858 | 452,032 (4.6x) | 102,666 | 953,608 (9.3x) | 59,519 | 558,791 (9.4x) |
| go-pfcp-ser | 61,858 | 253,318 (4.1x) | 62,662 | 485,571 (7.7x) | 36,251 | 303,897 (8.4x) |

go-pfcp's instructions vary by some hundreds a round with its collector. Times were not
taken at ed70497: the machine was shared, at a load of 10 to 15. At 526bee4, on an idle
core, `read` of ser-16 took 6.5 µs here and 67 µs with go-pfcp, which allocates 1,043
times where this crate allocates 15 times.
