//! Names answered here instead of upstream.
//!
//! | names | answer | why |
//! |---|---|---|
//! | `localhost` and below | `127.0.0.1` / `::1`, NODATA for other types | RFC 6761 §6.3 |
//! | `1.0.0.127.in-addr.arpa`, `::1` reversed | PTR `localhost.` | RFC 6303 |
//! | `.invalid`; reverse zones of `0/8`, `127/8`, the broadcast address, the documentation networks | NXDOMAIN | they never exist (RFC 6761, RFC 6303) |
//! | reverse zones of private, CGNAT, link-local and ULA addresses; `.local`; `home.arpa` | NXDOMAIN, unless `special_names.forward_private` | RFC 6303, RFC 7793, RFC 6762 §22.1, RFC 8375; a public upstream cannot answer them, and asking leaks local names |
//! | `use-application-dns.net` | NXDOMAIN, unless allowlisted | Firefox's canary: it keeps Firefox on this resolver instead of its own DoH |
//! | `resolver.arpa` | NODATA | RFC 9462: no designated resolvers, so clients do not discover the upstream's encrypted resolver and bypass this one |

/// What a special name gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Special {
    Localhost,
    LoopbackReverse,
    /// Never exists. `zone` owns the SOA of the negative answer.
    Never {
        zone: &'static str,
    },
    /// Private to a network; forwarded only if configured.
    Private {
        zone: &'static str,
    },
    Canary,
    Ddr,
}

const CANARY: &str = "use-application-dns.net";
const DDR: &str = "resolver.arpa";

const NEVER: &[&str] = &[
    "invalid",
    "0.in-addr.arpa",
    "127.in-addr.arpa",
    "255.255.255.255.in-addr.arpa",
    "2.0.192.in-addr.arpa",
    "100.51.198.in-addr.arpa",
    "113.0.203.in-addr.arpa",
    "8.b.d.0.1.0.0.2.ip6.arpa",
    // ::/128, the unspecified address.
    "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
];

const PRIVATE: &[&str] = &[
    "10.in-addr.arpa",
    "168.192.in-addr.arpa",
    "254.169.in-addr.arpa",
    "d.f.ip6.arpa",
    "8.e.f.ip6.arpa",
    "9.e.f.ip6.arpa",
    "a.e.f.ip6.arpa",
    "b.e.f.ip6.arpa",
    "local",
    "home.arpa",
];

const LOOPBACK_V4: &str = "1.0.0.127.in-addr.arpa";
const LOOPBACK_V6: &str =
    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa";

/// 172.16.0.0/12 and 100.64.0.0/10 split on an octet boundary, so their
/// reverse zones are one per second octet.
const PRIVATE_RANGES: &[(&str, u8, u8, &[&str])] = &[
    ("172.in-addr.arpa", 16, 31, &ZONES_172),
    ("100.in-addr.arpa", 64, 127, &ZONES_100),
];

macro_rules! octet_zones {
    ($suffix:literal; $($n:literal)*) => { [$(concat!($n, ".", $suffix)),*] };
}

const ZONES_172: [&str; 16] = octet_zones!("172.in-addr.arpa";
    16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31);
const ZONES_100: [&str; 64] = octet_zones!("100.in-addr.arpa";
    64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87
    88 89 90 91 92 93 94 95 96 97 98 99 100 101 102 103 104 105 106 107 108 109 110 111
    112 113 114 115 116 117 118 119 120 121 122 123 124 125 126 127);

/// Whether `name` is `zone` or below it. Both lower case, no trailing dot.
fn in_zone(name: &str, zone: &str) -> bool {
    match name.strip_suffix(zone) {
        Some("") => true,
        Some(rest) => rest.ends_with('.'),
        None => false,
    }
}

/// Classifies a lower-case name without its trailing dot.
pub(crate) fn classify(name: &str) -> Option<Special> {
    if in_zone(name, "localhost") {
        return Some(Special::Localhost);
    }
    if name == LOOPBACK_V4 || name == LOOPBACK_V6 {
        return Some(Special::LoopbackReverse);
    }
    if in_zone(name, CANARY) {
        return Some(Special::Canary);
    }
    if in_zone(name, DDR) {
        return Some(Special::Ddr);
    }
    if let Some(&zone) = NEVER.iter().find(|zone| in_zone(name, zone)) {
        return Some(Special::Never { zone });
    }
    if let Some(&zone) = PRIVATE.iter().find(|zone| in_zone(name, zone)) {
        return Some(Special::Private { zone });
    }
    for &(parent, low, high, zones) in PRIVATE_RANGES {
        if !in_zone(name, parent) {
            continue;
        }
        let Some(rest) = name.strip_suffix(parent).and_then(|r| r.strip_suffix('.')) else {
            continue;
        };
        let octet = rest.rsplit('.').next().and_then(|o| o.parse::<u8>().ok());
        if let Some(octet) = octet.filter(|o| (low..=high).contains(o)) {
            return Some(Special::Private {
                zone: zones[usize::from(octet - low)],
            });
        }
    }
    None
}

/// The owner name for the SOA of a negative answer about a special name.
pub(crate) fn soa_owner(special: Special) -> &'static str {
    match special {
        Special::Localhost => "localhost",
        Special::LoopbackReverse => LOOPBACK_V4,
        Special::Never { zone } | Special::Private { zone } => zone,
        Special::Canary => CANARY,
        Special::Ddr => DDR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies() {
        use Special::*;
        let cases: &[(&str, Option<Special>)] = &[
            ("localhost", Some(Localhost)),
            ("app.localhost", Some(Localhost)),
            ("notlocalhost", None),
            ("localhost.example", None),
            ("1.0.0.127.in-addr.arpa", Some(LoopbackReverse)),
            (
                "2.0.0.127.in-addr.arpa",
                Some(Never {
                    zone: "127.in-addr.arpa",
                }),
            ),
            ("x.invalid", Some(Never { zone: "invalid" })),
            (
                "5.1.168.192.in-addr.arpa",
                Some(Private {
                    zone: "168.192.in-addr.arpa",
                }),
            ),
            (
                "4.3.2.10.in-addr.arpa",
                Some(Private {
                    zone: "10.in-addr.arpa",
                }),
            ),
            (
                "1.0.16.172.in-addr.arpa",
                Some(Private {
                    zone: "16.172.in-addr.arpa",
                }),
            ),
            (
                "1.0.31.172.in-addr.arpa",
                Some(Private {
                    zone: "31.172.in-addr.arpa",
                }),
            ),
            ("1.0.32.172.in-addr.arpa", None),
            ("1.0.15.172.in-addr.arpa", None),
            (
                "16.172.in-addr.arpa",
                Some(Private {
                    zone: "16.172.in-addr.arpa",
                }),
            ),
            (
                "1.0.64.100.in-addr.arpa",
                Some(Private {
                    zone: "64.100.in-addr.arpa",
                }),
            ),
            ("1.0.63.100.in-addr.arpa", None),
            ("8.8.8.8.in-addr.arpa", None),
            (
                "x.d.f.ip6.arpa",
                Some(Private {
                    zone: "d.f.ip6.arpa",
                }),
            ),
            ("printer.local", Some(Private { zone: "local" })),
            ("nas.home.arpa", Some(Private { zone: "home.arpa" })),
            ("use-application-dns.net", Some(Canary)),
            ("_dns.resolver.arpa", Some(Ddr)),
            ("example.com", None),
            ("in-addr.arpa", None),
        ];
        for (name, want) in cases {
            assert_eq!(classify(name), *want, "{name}");
        }
        assert_eq!(classify(LOOPBACK_V6), Some(LoopbackReverse), "::1 reversed");
        // An IPv6 reverse name has one label per nibble.
        let nibbles = |n: &str| n.trim_end_matches(".ip6.arpa").split('.').count();
        assert_eq!(nibbles(LOOPBACK_V6), 32);
        assert_eq!(nibbles(NEVER[NEVER.len() - 1]), 32);
    }

    #[test]
    fn every_zone_classifies_as_itself() {
        for zone in NEVER {
            assert!(
                matches!(classify(zone), Some(Special::Never { .. })),
                "{zone}"
            );
        }
        for zone in PRIVATE.iter().chain(&ZONES_172).chain(&ZONES_100) {
            assert_eq!(classify(zone), Some(Special::Private { zone }), "{zone}");
        }
    }
}
