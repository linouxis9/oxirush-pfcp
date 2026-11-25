# Contributing to oxirush-pfcp

## Tests

```sh
cargo test --all-features
```

[`tests/README.md`](tests/README.md) describes what each test checks against
the specification and against lab captures, and what the crate reports in
other implementations.

## Fuzzing

```sh
cargo run --example fuzz_dictionary > fuzz/pfcp.dict
cargo +nightly fuzz run tree -- -max_total_time=60 -dict=fuzz/pfcp.dict
```

`fuzz/` has seven [cargo-fuzz](https://crates.io/crates/cargo-fuzz) targets.
CI runs each for a minute at a push, an hour each day but Friday and
Sunday, and four hours on Friday.

## Benchmarks

[`benches/README.md`](benches/README.md) has the figures and the commands.

## Pull requests

A pull request comes with a test for what it changes. Sign off your commits
(`git commit -s`): by contributing you agree to the [Developer Certificate
of Origin](https://developercertificate.org/). [SECURITY.md](SECURITY.md)
says how to report a vulnerability.
