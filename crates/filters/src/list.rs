//! Whole lists: comments, headers, line continuations and `!#` directives.

use serde::Serialize;

use crate::preprocess::{Env, Line, Lines};
use crate::{ParseError, Rule, parse_rule};

/// A rule and the (first) line it came from.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ParsedRule {
    pub line: usize,
    pub rule: Rule,
}

/// A line that did not become a rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rejected {
    pub line: usize,
    pub text: String,
    pub error: ParseError,
}

/// `!#include path`. Resolving it is the list loader's job (`sinkhole-lists`),
/// which keeps it beside the including list, as uBO does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Include {
    pub line: usize,
    pub path: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ListStats {
    pub lines: usize,
    pub comments: usize,
    /// Lines skipped because an `!#if` condition was false.
    pub excluded: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ParsedList {
    pub rules: Vec<ParsedRule>,
    pub rejected: Vec<Rejected>,
    pub includes: Vec<Include>,
    pub stats: ListStats,
}

/// Whether a (trimmed) line is a comment or a list header.
pub fn is_comment(line: &str) -> bool {
    match line.as_bytes() {
        [b'!', ..] => true,
        // `[Adblock Plus 2.0]`, but not AdGuard's `[$path=/x]example.com##…`.
        [b'[', .., b']'] => !line.contains('$'),
        // Hosts-style `# comment`, but not `##.ad` or `#@#.ad`.
        [b'#'] => true,
        [b'#', next, ..] => !matches!(next, b'#' | b'@' | b'?' | b'$' | b'%'),
        _ => false,
    }
}

/// Parses a filter list for the environment `env` (see [`Env`]).
pub fn parse_list(text: &str, env: &Env) -> ParsedList {
    let mut out = ParsedList::default();
    let mut lines = Lines::new(text, env);
    for (line_no, line) in lines.by_ref() {
        match line {
            Line::Text(line) if is_comment(&line) => out.stats.comments += 1,
            Line::Text(line) => match parse_rule(&line) {
                Ok(rule) => out.rules.push(ParsedRule {
                    line: line_no,
                    rule,
                }),
                Err(error) => out.rejected.push(Rejected {
                    line: line_no,
                    text: line.into_owned(),
                    error,
                }),
            },
            Line::Include(path) => out.includes.push(Include {
                line: line_no,
                path: path.to_owned(),
            }),
            Line::Excluded => out.stats.excluded += 1,
            Line::Directive => out.stats.comments += 1,
            Line::Invalid { text, message } => out.rejected.push(Rejected {
                line: line_no,
                text: text.into_owned(),
                error: ParseError::invalid(message),
            }),
        }
    }
    out.stats.lines = lines.lines_read();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> ParsedList {
        parse_list(text, &Env::new(["yes"]))
    }

    #[test]
    fn comments_and_headers() {
        let l =
            parse("[Adblock Plus 2.0]\n! Title: x\n# hosts comment\n#\n\n||ads.example^\n##.ad\n");
        assert_eq!(l.rules.len(), 2);
        assert_eq!(l.stats.comments, 4);
        assert_eq!(l.rules[0].line, 6);
        assert!(l.rejected.is_empty());
    }

    #[test]
    fn conditions() {
        let l = parse(
            "!#if yes\n||a.example^\n!#if !yes\n||b.example^\n!#else\n||c.example^\n!#endif\n!#else\n||d.example^\n!#endif\n||e.example^",
        );
        let hosts: Vec<_> = l
            .rules
            .iter()
            .filter_map(|r| match &r.rule {
                Rule::Network(n) => n.pattern.pure_hostname().map(str::to_owned),
                _ => None,
            })
            .collect();
        assert_eq!(hosts, ["a.example", "c.example", "e.example"]);
        assert_eq!(l.stats.excluded, 2);
        assert!(l.rejected.is_empty());
    }

    #[test]
    fn nested_condition_in_false_branch_stays_off() {
        let l = parse("!#if no\n!#if yes\n||a.example^\n!#endif\n!#endif");
        assert!(l.rules.is_empty());
    }

    #[test]
    fn unbalanced_directives_are_reported() {
        let l = parse("!#endif\n!#if yes\n||a.example^");
        assert_eq!(l.rejected.len(), 2);
        assert_eq!(l.rules.len(), 1);
        let l = parse("!#if (yes\n||a.example^\n!#endif");
        assert_eq!(l.rejected.len(), 1);
        assert!(l.rules.is_empty());
    }

    #[test]
    fn includes_only_when_active() {
        let l = parse("!#include sub.txt\n!#if no\n!#include other.txt\n!#endif");
        assert_eq!(
            l.includes,
            [Include {
                line: 1,
                path: "sub.txt".into()
            }]
        );
    }

    #[test]
    fn line_continuation() {
        let l = parse("example.com##+js(set, \\\n   a.b, \\\n   true)\n||x.example^");
        assert_eq!(l.rules.len(), 2, "{:?}", l.rejected);
        let Rule::Scriptlet(s) = &l.rules[0].rule else {
            panic!()
        };
        assert_eq!(s.calls[0].args, ["a.b", "true"]);
        assert_eq!(l.rules[1].line, 4);
    }

    #[test]
    fn rejected_lines_keep_their_text() {
        let l = parse("||a.example^$frobnicate");
        assert_eq!(l.rejected[0].line, 1);
        assert_eq!(l.rejected[0].text, "||a.example^$frobnicate");
        assert_eq!(l.rejected[0].error.feature(), "option:unknown");
    }

    #[test]
    fn windows_line_endings() {
        let l = parse("||a.example^\r\n##.ad\r\n");
        assert_eq!(l.rules.len(), 2);
    }
}
