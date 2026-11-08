//! Writes seed corpora for the fuzz targets into the directory given
//! (default `corpus/`). Only the project's own lists and configs are used,
//! never the public filter lists, whose licenses would follow the files.

use std::fs;
use std::path::{Path, PathBuf};

use hickory_proto::op::{Edns, Message, OpCode, Query};
use hickory_proto::rr::rdata::{A, CNAME, HTTPS, SOA, SVCB};
use hickory_proto::rr::{Name, RData, Record, RecordType};

fn name(s: &str) -> Name {
    Name::from_ascii(s).expect("name")
}

fn query(qname: &str, kind: RecordType) -> Message {
    let mut m = Message::query();
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(name(qname), kind));
    m
}

fn write(dir: &Path, target: &str, n: usize, bytes: &[u8]) {
    let dir = dir.join(target);
    fs::create_dir_all(&dir).expect("corpus dir");
    fs::write(dir.join(format!("seed-{n:03}")), bytes).expect("seed");
}

fn main() {
    let out = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "corpus".into()));
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");

    // Queries: plain, EDNS with DO, other types, a zone transfer, a
    // NOTIFY, a response, and a cut-off packet.
    let mut queries = Vec::new();
    for (q, kind) in [
        ("ads.example.", RecordType::A),
        ("x.tracker.example.", RecordType::AAAA),
        ("ok.ads.example.", RecordType::HTTPS),
        ("localhost.", RecordType::A),
        ("use-application-dns.net.", RecordType::A),
        ("1.0.0.127.in-addr.arpa.", RecordType::PTR),
        ("www.example.com.", RecordType::AXFR),
    ] {
        queries.push(query(q, kind));
    }
    let mut edns = query("news.example.", RecordType::A);
    let mut e = Edns::new();
    e.set_max_payload(4096);
    e.set_dnssec_ok(true);
    edns.set_edns(e);
    queries.push(edns);
    let mut notify = query("example.", RecordType::SOA);
    notify.metadata.op_code = OpCode::Notify;
    queries.push(notify);
    let mut i = 0;
    for q in &queries {
        let bytes = q.to_vec().expect("query");
        write(&out, "dns_query", i, &bytes);
        i += 1;
    }
    let cut = queries[0].to_vec().expect("query");
    write(&out, "dns_query", i, &cut[..cut.len() / 2]);

    // Answers: a CNAME chain into a listed name, an HTTPS record with a
    // target, a negative answer with an SOA.
    let mut chain = query("metrics.shop.example.", RecordType::A).into_response();
    chain.add_answer(Record::from_rdata(
        name("metrics.shop.example."),
        300,
        RData::CNAME(CNAME(name("edge.cdn.example."))),
    ));
    chain.add_answer(Record::from_rdata(
        name("edge.cdn.example."),
        300,
        RData::CNAME(CNAME(name("x.tracker.example."))),
    ));
    chain.add_answer(Record::from_rdata(
        name("x.tracker.example."),
        60,
        RData::A(A::new(192, 0, 2, 7)),
    ));
    let mut https = query("www.example.com.", RecordType::HTTPS).into_response();
    https.add_answer(Record::from_rdata(
        name("www.example.com."),
        300,
        RData::HTTPS(HTTPS(SVCB::new(1, name("x.tracker.example."), Vec::new()))),
    ));
    let mut negative = query("Mixed.Case.Example.", RecordType::AAAA).into_response();
    negative.add_authority(Record::from_rdata(
        name("example."),
        900,
        RData::SOA(SOA::new(
            name("ns.example."),
            name("hostmaster.example."),
            1,
            3600,
            600,
            86400,
            900,
        )),
    ));
    for (n, m) in [chain, https, negative].iter().enumerate() {
        write(&out, "dns_answer", n, &m.to_vec().expect("answer"));
    }

    // Lists and configs of our own.
    let lists = [
        "testbed/lists/testbed.txt",
        "testbed/lists/testbed-privacy.txt",
        "extension/lists/surrogates-ads.txt",
        "extension/lists/surrogates-privacy.txt",
        "extension/lists/tracking-params.txt",
        "extension/e2e/fixtures/blocking.txt",
    ];
    let mut n = 0;
    for list in lists {
        let Ok(text) = fs::read_to_string(repo.join(list)) else {
            continue;
        };
        for target in ["filter_list", "compile", "explain"] {
            write(&out, target, n, text.as_bytes());
        }
        n += 1;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            write(&out, "filter_line", n, line.as_bytes());
            n += 1;
        }
    }
    let mut n = 0;
    for file in ["config/dev.toml"] {
        if let Ok(text) = fs::read_to_string(repo.join(file)) {
            write(&out, "config", n, text.as_bytes());
            n += 1;
        }
    }
    if let Ok(text) = fs::read_to_string(repo.join("config/dev-blocklist.txt")) {
        for (i, format) in [0u8, 1, 2, 3, 0x80].into_iter().enumerate() {
            let mut bytes = vec![format];
            bytes.extend_from_slice(text.as_bytes());
            write(&out, "dns_list", i, &bytes);
        }
    }
    for (i, d) in [
        "Example.COM.",
        "*.ads.example",
        "bücher.example",
        "xn--bcher-kva.example",
        "a..b",
        "_dmarc.example",
    ]
    .into_iter()
    .enumerate()
    {
        write(&out, "domain", i, d.as_bytes());
    }
    for (i, r) in [
        "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "POST / HTTP/1.0\r\n\r\n",
    ]
    .into_iter()
    .enumerate()
    {
        write(&out, "metrics_request", i, r.as_bytes());
    }
    println!("seeds written to {}", out.display());
}
