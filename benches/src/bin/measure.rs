//! `measure WORKLOAD MESSAGE ROUNDS`: a workload on a message, ROUNDS times, for `perf
//! stat`, which counts the instructions; with the feature `heap`, the allocations of one
//! round, by dhat. It prints the time of a round, which is a note and no measurement.

use std::hint::black_box;
use std::time::Instant;

use oxirush_pfcp::{IntoOwned, Message};
use oxirush_pfcp_benches::{frame, messages, read};

#[cfg(feature = "heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn run(workload: &str, octets: &[u8]) -> u64 {
    match workload {
        "frame" => frame(black_box(octets)),
        "decode" => {
            let message = Message::decode(black_box(octets)).unwrap();
            black_box(&message);
            0
        }
        "read" => read(&Message::decode(black_box(octets)).unwrap()),
        "owned" => {
            let message = Message::decode(black_box(octets)).unwrap().into_owned();
            black_box(&message);
            0
        }
        "encode" => unreachable!(),
        "sizes" => {
            use oxirush_pfcp::*;
            use std::mem::size_of;
            println!(
                "Octets {}, FTeid {}, Pdi {}, CreatePdr {}, SessionEstablishmentRequest {}, Message {}",
                size_of::<Octets<'_>>(),
                size_of::<FTeid<'_>>(),
                size_of::<Pdi<'_>>(),
                size_of::<CreatePdr<'_>>(),
                size_of::<SessionEstablishmentRequest<'_>>(),
                size_of::<Message<'_>>()
            );
            0
        }
        other => panic!("no workload {other}"),
    }
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let (workload, name, rounds) = (&arguments[1], &arguments[2], arguments[3].parse::<u64>().unwrap());
    let messages = messages();
    let (_, octets) = messages.iter().find(|(known, _)| known == name).expect("no such message");
    #[cfg(feature = "heap")]
    let _profiler = dhat::Profiler::builder().testing().build();
    #[cfg(feature = "heap")]
    {
        let before = dhat::HeapStats::get();
        black_box(run(workload, octets));
        let after = dhat::HeapStats::get();
        println!(
            "{workload} {name} {} octets: {} allocations, {} octets allocated",
            octets.len(),
            after.total_blocks - before.total_blocks,
            after.total_bytes - before.total_bytes
        );
        return;
    }
    #[allow(unreachable_code)]
    {
        let start = Instant::now();
        let mut sum = 0;
        if workload == "encode" {
            let message = Message::decode(octets).unwrap();
            for _ in 0..rounds {
                sum += black_box(black_box(&message).encode().unwrap()).len() as u64;
            }
        } else {
            for _ in 0..rounds {
                sum += run(workload, octets);
            }
        }
        let elapsed = start.elapsed();
        black_box(sum);
        eprintln!("{workload} {name}: {:.0} ns a round (a note)", elapsed.as_nanos() as f64 / rounds.max(1) as f64);
    }
}
