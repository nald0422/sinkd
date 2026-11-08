//! Compares [`regex_cost`] with Chrome's verdicts, for calibrating
//! `MAX_REGEX_COST`. The input is JSON from the extension's regex probe:
//! `[{"regex", "isCaseSensitive", "isSupported", "reason"}]`.
//!
//! `cargo run -p sinkhole-compiler --example regex_cost -- results.json`
#![allow(clippy::unwrap_used)]

use sinkhole_compiler::translate::{MAX_REGEX_COST, regex_cost};

fn main() {
    let path = std::env::args().nth(1).expect("results.json");
    let results: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut rows = Vec::new();
    for r in &results {
        let regex = r["regex"].as_str().unwrap();
        let cs = r["isCaseSensitive"].as_bool().unwrap();
        let ok = r["isSupported"].as_bool().unwrap();
        rows.push((regex_cost(regex, cs), ok, regex));
    }
    let max_ok = rows
        .iter()
        .filter(|r| r.1)
        .filter_map(|r| r.0.as_ref().ok())
        .max();
    let min_bad = rows
        .iter()
        .filter(|r| !r.1)
        .filter_map(|r| r.0.as_ref().ok())
        .min();
    println!("largest accepted estimate: {max_ok:?}; smallest refused estimate: {min_bad:?}");
    let false_accept = rows
        .iter()
        .filter(|r| !r.1 && r.0.as_ref().is_ok_and(|c| *c <= MAX_REGEX_COST))
        .count();
    let false_reject = rows
        .iter()
        .filter(|r| r.1 && r.0.as_ref().is_ok_and(|c| *c > MAX_REGEX_COST))
        .count();
    let syntax = rows.iter().filter(|r| r.0.is_err()).count();
    println!(
        "at MAX_REGEX_COST = {MAX_REGEX_COST}: {false_accept} refused by Chrome but kept, \\
         {false_reject} accepted by Chrome but dropped, {syntax} syntax rejections, of {}",
        rows.len()
    );
    let mut near: Vec<_> = rows
        .iter()
        .filter_map(|r| Some((*r.0.as_ref().ok()?, r.1, r.2)))
        .collect();
    near.sort();
    for (cost, ok, regex) in near.iter().filter(|r| (95..=130).contains(&r.0)) {
        println!(
            "{cost:>5} {} {}",
            if *ok { "ok " } else { "BAD" },
            &regex[..regex.len().min(90)]
        );
    }
}
