//! `measure WORKLOAD MESSAGE ROUNDS`: a workload on a message (frame, decode, read,
//! encode, check, and with the feature `tree` to_tree and from_tree), ROUNDS times, and the
//! time of a round, which is a note and no measurement; with the feature `heap`, the
//! allocations of one round, by dhat.

use std::hint::black_box;
#[cfg(not(feature = "heap"))]
use std::time::Instant;

use oxirush_pfcp::Message;
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
        "encode" | "check" | "to_tree" | "from_tree" => unreachable!(),
        "sizes" => {
            use oxirush_pfcp::*;
            use std::mem::size_of;
            println!(
                "Octets {}, FTeid {}, Pdi {}, CreatePdr {}, SessionEstablishmentRequest {}, Message {}",
                size_of::<Octets>(),
                size_of::<FTeid>(),
                size_of::<Pdi>(),
                size_of::<CreatePdr>(),
                size_of::<SessionEstablishmentRequest>(),
                size_of::<Message>()
            );
            0
        }
        other => panic!("no workload {other}"),
    }
}

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let (workload, name) = (&arguments[1], &arguments[2]);
    // The allocations are counted for one round.
    #[cfg(not(feature = "heap"))]
    let rounds = arguments[3].parse::<u64>().unwrap();
    let messages = messages();
    // `captures`: each message of PFCP_CAPTURES in a round.
    if name == "captures" {
        let captures: Vec<&Vec<u8>> = messages.iter().filter(|(known, _)| known.starts_with("capture:")).map(|(_, octets)| octets).collect();
        assert!(!captures.is_empty(), "PFCP_CAPTURES names no capture");
        #[cfg(feature = "heap")]
        {
            let _profiler = dhat::Profiler::builder().testing().build();
            let before = dhat::HeapStats::get();
            for octets in &captures {
                black_box(run(workload, octets));
            }
            let after = dhat::HeapStats::get();
            println!(
                "{workload} {} captures: {} allocations, {} octets allocated",
                captures.len(),
                after.total_blocks - before.total_blocks,
                after.total_bytes - before.total_bytes
            );
            return;
        }
        #[cfg(not(feature = "heap"))]
        {
            let start = Instant::now();
            let mut sum = 0;
            for _ in 0..rounds {
                for octets in &captures {
                    sum += run(workload, octets);
                }
            }
            black_box(sum);
            eprintln!("{workload} {} captures: {:.0} ns a round (a note)", captures.len(), start.elapsed().as_nanos() as f64 / rounds.max(1) as f64);
            return;
        }
    }
    let (_, octets) = messages.iter().find(|(known, _)| known == name).expect("no such message");
    #[cfg(feature = "heap")]
    let _profiler = dhat::Profiler::builder().testing().build();
    #[cfg(feature = "heap")]
    {
        let message = Message::decode(octets).unwrap();
        let before = dhat::HeapStats::get();
        match workload.as_str() {
            "encode" => drop(black_box(message.encode().unwrap())),
            "check" => drop(black_box(message.check(oxirush_pfcp::Interfaces::N4))),
            #[cfg(feature = "tree")]
            "to_tree" => drop(black_box(message.to_tree())),
            #[cfg(feature = "tree")]
            "from_tree" => {
                let tree = message.to_tree();
                let before = dhat::HeapStats::get();
                drop(black_box(Message::from_tree(&tree).unwrap()));
                let after = dhat::HeapStats::get();
                println!("from_tree {name}: {} allocations", after.total_blocks - before.total_blocks);
                return;
            }
            _ => drop(black_box(run(workload, octets))),
        }
        let after = dhat::HeapStats::get();
        println!(
            "{workload} {name} {} octets: {} allocations, {} octets allocated",
            octets.len(),
            after.total_blocks - before.total_blocks,
            after.total_bytes - before.total_bytes
        );
        return;
    }
    #[cfg(not(feature = "heap"))]
    {
        let start = Instant::now();
        let mut sum = 0;
        if workload == "encode" {
            let message = Message::decode(octets).unwrap();
            for _ in 0..rounds {
                sum += black_box(black_box(&message).encode().unwrap()).len() as u64;
            }
        } else if workload == "encode_into" {
            let message = Message::decode(octets).unwrap();
            let mut buffer = Vec::new();
            for _ in 0..rounds {
                buffer.clear();
                black_box(&message).encode_into(&mut buffer).unwrap();
                sum += black_box(&buffer).len() as u64;
            }
        } else if workload == "check" {
            let message = Message::decode(octets).unwrap();
            for _ in 0..rounds {
                sum += black_box(black_box(&message).check(oxirush_pfcp::Interfaces::N4)).len() as u64;
            }
        } else if workload == "to_tree" || workload == "from_tree" {
            #[cfg(feature = "tree")]
            {
                let message = Message::decode(octets).unwrap();
                let tree = message.to_tree();
                for _ in 0..rounds {
                    sum += match workload.as_str() {
                        "to_tree" => black_box(black_box(&message).to_tree()).is_object() as u64,
                        _ => black_box(Message::from_tree(black_box(&tree)).unwrap()).header.sequence as u64,
                    };
                }
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
