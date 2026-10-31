# Benchmarks of oxirush-pfcp

A package of its own, which the published crate does not have. `measure` runs one
workload on one message, many times, for `perf stat`; the figures are the
instructions of one round, `(count of 2N rounds − count of N rounds) / N`, and the
times are notes. They were taken on one core of an AMD Ryzen 7 5700G (Linux 7.0,
Rust 1.88.0) on 2026-10-31, at 526bee4.

```sh
cargo build --release                       # measure
cargo build --release --features heap      # measure, counting allocations with dhat
cargo build --release --features tree      # with the workloads of the trees
sudo perf stat -e instructions:u taskset -c 3 target/release/measure decode ser-16 1000
```

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
| heartbeat | 685 | 612 | 321 | 5,774 | 4,649 |
| ser-4 | 25,663 | 16,647 | 11,291 | 159,669 | 105,591 |
| ser-16 | 86,352 | 60,477 | 38,368 | 577,638 | 352,826 |
| go-pfcp-ser | 55,641 | 36,755 | 65,449 | 486,175 | 277,095 |

Decoding allocates the box of the message, each list of grouped IEs, each conditional or
optional grouped IE, and each octet string longer than 22 octets: once for the heartbeat,
9 times for ser-4 and 15 times for ser-16. `encode` allocates once, as it computes the
length first, and `check` allocates nothing for a message without a deviation.

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
| heartbeat | 685 | 1,988 (2.9x) | 695 | 2,080 (3.0x) | 612 | 3,055 (5.0x) |
| ser-4 | 25,663 | 111,510 (4.3x) | 27,039 | 230,357 (8.5x) | 16,647 | 137,295 (8.2x) |
| ser-16 | 86,352 | 399,189 (4.6x) | 91,293 | 876,326 (9.6x) | 60,477 | 498,044 (8.2x) |
| go-pfcp-ser | 55,641 | 255,760 (4.6x) | 56,469 | 479,572 (8.5x) | 36,755 | 346,318 (9.4x) |

The times of a round, as notes: `read` of ser-16 takes 6.5 µs here and 67 µs with
go-pfcp, which allocates 1,043 times where this crate allocates 15 times.
