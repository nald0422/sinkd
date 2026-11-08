//! Parser coverage on real filter lists.
//!
//! ```text
//! cargo run --release -p sinkd-filters --example coverage -- \
//!     [--env chromium|firefox | --tokens a,b,c] [--examples N] [--show FEATURE] [--oracle] \
//!     <list.txt>...
//! ```
//!
//! For each list: how many lines became rules of each kind, and why the rest
//! were rejected, grouped by [`ParseError::feature`] with example lines.
//! `--show FEATURE` prints every rejected line for one feature. `--oracle`
//! also classifies every rule line with Brave's `adblock` crate and prints
//! where the two parsers disagree. The DNS section feeds the same lists to
//! the resolver's list builder and reports how many domains it would block.
//!
//! Lists are read from disk; fetching them is the caller's job.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use adblock::lists::{ParseOptions, ParsedLine, parse_filter};
use sinkd_filters::dns::{DnsAction, DnsFormat, DnsListBuilder, parse_dns_line};
use sinkd_filters::{Env, ParseError, ParsedList, Rule, parse_list};

struct Args {
    env: Env,
    examples: usize,
    show: Option<String>,
    oracle: bool,
    paths: Vec<String>,
}

fn args() -> Args {
    let mut out = Args {
        env: Env::chromium_mv3(),
        examples: 3,
        show: None,
        oracle: false,
        paths: Vec::new(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--env" => {
                out.env = match it.next().as_deref() {
                    Some("firefox") => Env::firefox(),
                    Some("chromium") => Env::chromium_mv3(),
                    other => panic!("unknown --env {other:?}"),
                }
            }
            "--tokens" => {
                out.env = Env::new(it.next().unwrap().split(',').filter(|t| !t.is_empty()))
            }
            "--examples" => out.examples = it.next().unwrap().parse().unwrap(),
            "--show" => out.show = it.next(),
            "--oracle" => out.oracle = true,
            _ => out.paths.push(a),
        }
    }
    assert!(!out.paths.is_empty(), "no lists given");
    out
}

struct List {
    name: String,
    text: String,
    parsed: ParsedList,
    elapsed: Duration,
}

/// Rule lines of a list as `(line number, text, our result)`: every line
/// that reached the rule parser. Joined continuation lines are skipped for
/// accepted rules, whose text is not kept.
fn rule_lines(list: &List) -> Vec<(usize, &str, Result<&Rule, &ParseError>)> {
    let lines: Vec<&str> = list.text.lines().collect();
    let mut out: Vec<_> = list
        .parsed
        .rules
        .iter()
        .filter(|r| !lines[r.line - 1].trim_end().ends_with(" \\"))
        .map(|r| (r.line, lines[r.line - 1].trim(), Ok(&r.rule)))
        .collect();
    out.extend(
        list.parsed
            .rejected
            .iter()
            .filter(|r| !r.text.starts_with("!#"))
            .map(|r| (r.line, r.text.as_str(), Err(&r.error))),
    );
    out.sort_by_key(|(line, ..)| *line);
    out
}

fn kind(rule: &Rule) -> &'static str {
    match rule {
        Rule::Network(n) if n.exception => "network-exception",
        Rule::Network(_) => "network",
        Rule::Cosmetic(c) if c.exception => "cosmetic-exception",
        Rule::Cosmetic(_) => "cosmetic",
        Rule::Scriptlet(_) => "scriptlet",
        Rule::ResponseHeader(_) => "response-header",
    }
}

/// Error messages with quoted parts elided, so `bad domain "x"` and
/// `bad domain "y"` group together. Unknown scriptlets group by name.
fn message_shape(error: &ParseError) -> String {
    let text = match error {
        ParseError::Unsupported { detail, feature } if feature == "scriptlet:unknown" => {
            return detail.clone();
        }
        ParseError::Unsupported { detail, .. } => detail.clone(),
        ParseError::Invalid(m) => m.clone(),
    };
    let mut out = String::new();
    let mut quoted = false;
    for c in text.chars() {
        if c == '"' {
            if !quoted {
                out.push_str("\"…\"");
            }
            quoted = !quoted;
        } else if !quoted {
            out.push(c);
        }
    }
    out
}

fn pct(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        0.0
    } else {
        100.0 * part as f64 / whole as f64
    }
}

fn clip(s: &str) -> String {
    const MAX: usize = 110;
    if s.chars().count() <= MAX {
        s.to_owned()
    } else {
        format!("{}…", s.chars().take(MAX).collect::<String>())
    }
}

fn main() {
    let args = args();
    let lists: Vec<List> = args
        .paths
        .iter()
        .map(|path| {
            let text = std::fs::read_to_string(path).unwrap();
            let start = Instant::now();
            let parsed = parse_list(&text, &args.env);
            let elapsed = start.elapsed();
            let name = std::path::Path::new(path)
                .file_stem()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            List {
                name,
                text,
                parsed,
                elapsed,
            }
        })
        .collect();

    println!("== Per list (env: {:?})\n", args.env);
    println!(
        "{:<18} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>8} {:>7}",
        "list", "lines", "rules", "unsupp", "invalid", "inactive", "include", "accepted", "ms"
    );
    let mut totals = [0usize; 6];
    for l in &lists {
        let unsupported = l
            .parsed
            .rejected
            .iter()
            .filter(|r| matches!(r.error, ParseError::Unsupported { .. }))
            .count();
        let invalid = l.parsed.rejected.len() - unsupported;
        let rules = l.parsed.rules.len();
        let row = [
            l.parsed.stats.lines,
            rules,
            unsupported,
            invalid,
            l.parsed.stats.excluded,
            l.parsed.includes.len(),
        ];
        for (t, v) in totals.iter_mut().zip(row) {
            *t += v;
        }
        println!(
            "{:<18} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7.2}% {:>7.1}",
            l.name,
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
            row[5],
            pct(rules, rules + l.parsed.rejected.len()),
            l.elapsed.as_secs_f64() * 1e3,
        );
    }
    let total_ms: f64 = lists.iter().map(|l| l.elapsed.as_secs_f64() * 1e3).sum();
    println!(
        "{:<18} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7} {:>7.2}% {:>7.1}",
        "TOTAL",
        totals[0],
        totals[1],
        totals[2],
        totals[3],
        totals[4],
        totals[5],
        pct(totals[1], totals[1] + totals[2] + totals[3]),
        total_ms,
    );

    let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
    for l in &lists {
        for r in &l.parsed.rules {
            *kinds.entry(kind(&r.rule)).or_default() += 1;
        }
    }
    println!("\nAccepted by kind:");
    for (k, n) in &kinds {
        println!("  {k:<20} {n:>7}");
    }

    // Rejections grouped by feature, then by message shape.
    type Example<'a> = (&'a str, usize, &'a str, String);
    let mut by_feature: BTreeMap<&str, Vec<Example<'_>>> = BTreeMap::new();
    for l in &lists {
        for r in &l.parsed.rejected {
            by_feature.entry(r.error.feature()).or_default().push((
                &l.name,
                r.line,
                &r.text,
                r.error.to_string(),
            ));
        }
    }
    let mut features: Vec<_> = by_feature.iter().collect();
    features.sort_by_key(|(f, v)| (std::cmp::Reverse(v.len()), *f));
    println!("\n== Rejected by feature\n");
    for (feature, items) in &features {
        println!("{:>6}  {feature}", items.len());
    }
    for (feature, items) in &features {
        println!("\n-- {feature} ({})", items.len());
        let mut shapes: BTreeMap<String, Vec<&Example<'_>>> = BTreeMap::new();
        for item in items.iter() {
            let error = lists
                .iter()
                .find(|l| l.name == item.0)
                .and_then(|l| l.parsed.rejected.iter().find(|r| r.line == item.1))
                .map(|r| message_shape(&r.error))
                .unwrap_or_default();
            shapes.entry(error).or_default().push(item);
        }
        let mut shapes: Vec<_> = shapes.into_iter().collect();
        shapes.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));
        for (shape, items) in shapes {
            println!("   {:>5} × {shape}", items.len());
            for (list, line, text, _) in items.iter().take(args.examples) {
                println!("           {list}:{line}  {}", clip(text));
            }
        }
    }

    if let Some(show) = &args.show {
        println!("\n== All rejected lines for {show}\n");
        for (list, line, text, error) in by_feature.get(show.as_str()).into_iter().flatten() {
            println!("{list}:{line}  {text}\n        {error}");
        }
    }

    if args.oracle {
        oracle(&lists, args.examples);
    }

    dns(&lists);
}

/// Classifies every rule line with adblock-rust and reports disagreements.
fn oracle(lists: &[List], examples: usize) {
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
    enum K {
        Network,
        Cosmetic,
        Rejected,
    }
    let mut matrix: BTreeMap<(K, K), usize> = BTreeMap::new();
    // (we reject, they accept) by our feature; (we accept, they reject) by our kind.
    let mut we_reject: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut they_reject: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut other_kind: Vec<String> = Vec::new();
    // Option names on network rules adblock-rust rejects, to see why.
    let mut their_options: BTreeMap<String, usize> = BTreeMap::new();
    for l in lists {
        for (line, text, ours) in rule_lines(l) {
            let o = match ours {
                Ok(Rule::Network(_)) => K::Network,
                Ok(_) => K::Cosmetic,
                Err(_) => K::Rejected,
            };
            let t = match parse_filter(text, true, ParseOptions::default()) {
                Ok(ParsedLine::Network(_)) => K::Network,
                Ok(ParsedLine::Cosmetic(_)) => K::Cosmetic,
                Err(_) => K::Rejected,
            };
            *matrix.entry((o, t)).or_default() += 1;
            let where_ = format!("{}:{line}  {}", l.name, clip(text));
            match (ours, t) {
                (Err(e), K::Network | K::Cosmetic) => {
                    we_reject
                        .entry(e.feature().to_owned())
                        .or_default()
                        .push(where_);
                }
                (Ok(rule), K::Rejected) => {
                    if let Rule::Network(_) = rule
                        && let Some((_, options)) = text.rsplit_once('$')
                    {
                        for option in options.split(',') {
                            let name = option.split('=').next().unwrap_or_default();
                            *their_options.entry(name.to_owned()).or_default() += 1;
                        }
                    }
                    they_reject.entry(kind(rule)).or_default().push(where_);
                }
                (Ok(_), t) if t != o => other_kind.push(format!("{where_}  (theirs: {t:?})")),
                _ => {}
            }
        }
    }
    println!("\n== Oracle (rows: sinkd, columns: adblock-rust)\n");
    println!(
        "{:<10} {:>9} {:>9} {:>9}",
        "", "Network", "Cosmetic", "Rejected"
    );
    for o in [K::Network, K::Cosmetic, K::Rejected] {
        let cell = |t| matrix.get(&(o, t)).copied().unwrap_or(0);
        println!(
            "{:<10} {:>9} {:>9} {:>9}",
            format!("{o:?}"),
            cell(K::Network),
            cell(K::Cosmetic),
            cell(K::Rejected)
        );
    }
    let mut rows: Vec<_> = we_reject.iter().collect();
    rows.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));
    println!("\nWe reject, adblock-rust accepts (by our feature):");
    for (feature, items) in rows {
        println!("  {:>5}  {feature}", items.len());
        for item in items.iter().take(examples) {
            println!("           {item}");
        }
    }
    println!("\nBoth accept, different kind:");
    for item in &other_kind {
        println!("           {item}");
    }
    println!("\nWe accept, adblock-rust rejects (by our kind):");
    for (k, items) in &they_reject {
        println!("  {:>5}  {k}", items.len());
        for item in items.iter().take(examples) {
            println!("           {item}");
        }
    }
    let mut options: Vec<_> = their_options.into_iter().collect();
    options.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    println!("\n  Options on those network rules (top 12):");
    for (name, n) in options.into_iter().take(12) {
        println!("  {n:>7}  {name}");
    }
}

/// What the resolver would load from the same lists.
fn dns(lists: &[List]) {
    let start = Instant::now();
    let mut builder = DnsListBuilder::new();
    for l in lists {
        builder.add_list(&l.text, DnsFormat::Auto, DnsAction::Block);
    }
    let (matcher, report) = builder.finish();
    let elapsed = start.elapsed();
    let invalid: Vec<String> = lists
        .iter()
        .flat_map(|l| l.text.lines().map(move |line| (l, line)))
        .filter_map(
            |(l, line)| match parse_dns_line(line, DnsFormat::Auto, DnsAction::Block) {
                Err(e @ ParseError::Invalid(_)) => {
                    Some(format!("{}  {}  ({e})", l.name, clip(line)))
                }
                _ => None,
            },
        )
        .collect();
    println!("\n== DNS (all lists, auto format, block)\n");
    println!("lines            {:>8}", report.lines);
    println!("block entries    {:>8}", report.block_entries);
    println!("allow entries    {:>8}", report.allow_entries);
    println!("badfiltered      {:>8}", report.badfiltered);
    println!("not DNS-able     {:>8}", report.rejected_total());
    println!(
        "matcher heap     {:>8.1} KiB",
        matcher.heap_bytes() as f64 / 1024.0
    );
    println!("load             {:>8.1} ms", elapsed.as_secs_f64() * 1e3);
    let mut rows: Vec<_> = report.rejected.iter().collect();
    rows.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
    println!("\nNot DNS-able, by reason:");
    for (feature, n) in rows {
        println!(
            "  {n:>7}  {feature:<28} e.g. {}",
            clip(report.examples.get(feature).map_or("", String::as_str))
        );
    }
    if !invalid.is_empty() {
        println!("\nInvalid for DNS (first 10 of {}):", invalid.len());
        for item in invalid.iter().take(10) {
            println!("  {item}");
        }
    }
}
