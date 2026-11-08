//! Scriptlet rules in all three dialects:
//!
//! * uBO: `example.com##+js(set-constant, ads.enabled, false)`
//! * AdGuard: `example.com#%#//scriptlet('set-constant', 'ads.enabled', 'false')`
//! * ABP: `example.com#$#abort-on-property-read ads; json-prune ad`
//!
//! A list can only **select** one of the scriptlets bundled with the
//! extension and pass it string arguments. A name outside [`SCRIPTLETS`] is
//! rejected, and nothing a list says is ever executed as code.

use serde::Serialize;

use crate::ParseError;
use crate::domains::DomainSpec;

/// Which syntax a call was written in. Implementations use it where
/// dialects disagree on argument meaning (e.g. AdGuard's
/// `abort-current-inline-script` only looks at inline scripts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Dialect {
    Ublock,
    Adguard,
    Abp,
}

/// One scriptlet invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScriptletCall {
    /// Canonical name, one of [`SCRIPTLETS`].
    pub name: &'static str,
    pub args: Vec<String>,
    pub dialect: Dialect,
}

/// A scriptlet rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScriptletRule {
    /// Empty: every site (generic).
    pub domains: Vec<DomainSpec>,
    /// `#@#+js(…)` / `#@%#…`: stop the matching scriptlet on these sites.
    pub exception: bool,
    /// The calls, in order. Empty only for the `#@#+js()` exception, which
    /// stops every scriptlet on the matching sites.
    pub calls: Vec<ScriptletCall>,
}

/// A bundled scriptlet and the names lists may use for it.
#[derive(Debug)]
pub struct ScriptletSpec {
    pub name: &'static str,
    /// Other names: uBO short forms, AdGuard and ABP spellings. `.js`
    /// suffixes and AdGuard's `ubo-` prefix are stripped before lookup.
    pub aliases: &'static [&'static str],
    /// Fewer arguments is a malformed rule.
    pub min_args: usize,
}

/// The scriptlets sinkd ships.
pub const SCRIPTLETS: &[ScriptletSpec] = &[
    ScriptletSpec {
        name: "set-constant",
        aliases: &["set", "override-property-read"],
        min_args: 2,
    },
    ScriptletSpec {
        name: "abort-on-property-read",
        aliases: &["aopr"],
        min_args: 1,
    },
    ScriptletSpec {
        name: "abort-on-property-write",
        aliases: &["aopw"],
        min_args: 1,
    },
    ScriptletSpec {
        name: "abort-current-script",
        aliases: &["acs", "acis", "abort-current-inline-script"],
        min_args: 1,
    },
    ScriptletSpec {
        name: "prevent-setTimeout",
        aliases: &["no-setTimeout-if", "nostif", "setTimeout-defuser"],
        min_args: 0,
    },
    ScriptletSpec {
        name: "prevent-setInterval",
        aliases: &["no-setInterval-if", "nosiif", "setInterval-defuser"],
        min_args: 0,
    },
    ScriptletSpec {
        name: "prevent-fetch",
        aliases: &["no-fetch-if"],
        min_args: 0,
    },
    ScriptletSpec {
        name: "prevent-xhr",
        aliases: &["no-xhr-if"],
        min_args: 0,
    },
    ScriptletSpec {
        name: "json-prune",
        aliases: &[],
        min_args: 0,
    },
    ScriptletSpec {
        name: "remove-class",
        aliases: &["rc"],
        min_args: 1,
    },
    ScriptletSpec {
        name: "remove-attr",
        aliases: &["ra"],
        min_args: 1,
    },
    ScriptletSpec {
        name: "no-window-open-if",
        aliases: &["nowoif", "prevent-window-open", "window.open-defuser"],
        min_args: 0,
    },
    ScriptletSpec {
        name: "addEventListener-defuser",
        aliases: &["aeld", "prevent-addEventListener"],
        min_args: 0,
    },
    ScriptletSpec {
        name: "href-sanitizer",
        aliases: &[],
        min_args: 1,
    },
    ScriptletSpec {
        name: "set-local-storage-item",
        aliases: &[],
        min_args: 2,
    },
    ScriptletSpec {
        name: "nano-setInterval-booster",
        aliases: &["nano-sib", "adjust-setInterval"],
        min_args: 0,
    },
    ScriptletSpec {
        name: "nano-setTimeout-booster",
        aliases: &["nano-stb", "adjust-setTimeout"],
        min_args: 0,
    },
    ScriptletSpec {
        name: "remove-node-text",
        aliases: &["rmnt"],
        min_args: 2,
    },
    ScriptletSpec {
        name: "remove-cookie",
        aliases: &["cookie-remover"],
        min_args: 0,
    },
    ScriptletSpec {
        name: "nowebrtc",
        aliases: &[],
        min_args: 0,
    },
    ScriptletSpec {
        name: "abort-on-stack-trace",
        aliases: &["aost"],
        min_args: 2,
    },
    ScriptletSpec {
        name: "noeval",
        aliases: &["silent-noeval"],
        min_args: 0,
    },
];

/// Upper bounds that keep a hostile list from making the index huge.
const MAX_ARGS: usize = 32;
const MAX_ARG_LEN: usize = 4096;

/// Looks up a scriptlet by any of its names.
pub fn resolve(name: &str) -> Option<&'static ScriptletSpec> {
    let name = name.trim();
    let name = name.strip_prefix("ubo-").unwrap_or(name);
    let name = name.strip_suffix(".js").unwrap_or(name);
    SCRIPTLETS
        .iter()
        .find(|s| s.name == name || s.aliases.contains(&name))
}

fn call(name: &str, args: Vec<String>, dialect: Dialect) -> Result<ScriptletCall, ParseError> {
    let spec = resolve(name).ok_or_else(|| {
        ParseError::unsupported(
            "scriptlet:unknown",
            format!("{name:?} is not a bundled scriptlet"),
        )
    })?;
    if args.len() < spec.min_args {
        return Err(ParseError::invalid(format!(
            "{} needs at least {} argument(s)",
            spec.name, spec.min_args
        )));
    }
    if args.len() > MAX_ARGS || args.iter().any(|a| a.len() > MAX_ARG_LEN) {
        return Err(ParseError::invalid("scriptlet arguments too long"));
    }
    Ok(ScriptletCall {
        name: spec.name,
        args,
        dialect,
    })
}

/// The inside of uBO's `+js(…)`: `name, arg, 'quoted, arg', arg\, with comma`.
pub(crate) fn parse_ublock(inner: &str) -> Result<Vec<ScriptletCall>, ParseError> {
    if inner.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut parts = split_ublock_args(inner).into_iter();
    let name = parts.next().unwrap_or_default();
    Ok(vec![call(&name, parts.collect(), Dialect::Ublock)?])
}

/// Splits uBO arguments; whitespace around each is trimmed. An argument that
/// starts with a quote (`'`, `"` or a backtick) is quoted only if its first
/// unescaped closing quote is followed by a comma or the end: then it may
/// contain commas and `\q` is a literal quote. Otherwise the quote is plain
/// text (`'0x`, `"key":true`), as in uBO. Unquoted, `\,` is a literal comma.
fn split_ublock_args(s: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut rest = s;
    loop {
        rest = rest.trim_start();
        if let Some((arg, after)) = quoted_arg(rest) {
            args.push(arg);
            match after.strip_prefix(',') {
                Some(next) => {
                    rest = next;
                    continue;
                }
                None => return args,
            }
        }
        let mut arg = String::new();
        let mut next = None;
        let mut chars = rest.char_indices().peekable();
        while let Some((i, c)) = chars.next() {
            match c {
                '\\' if chars.peek().is_some_and(|&(_, n)| n == ',') => {
                    arg.push(',');
                    chars.next();
                }
                ',' => {
                    next = Some(i + 1);
                    break;
                }
                c => arg.push(c),
            }
        }
        args.push(arg.trim_end().to_owned());
        match next {
            Some(i) => rest = &rest[i..],
            None => return args,
        }
    }
}

/// A quoted argument at the start of `s` and the text after it (empty, or
/// starting with the comma), if the closing quote is followed by a comma or
/// the end.
fn quoted_arg(s: &str) -> Option<(String, &str)> {
    let q = s.chars().next().filter(|c| matches!(c, '\'' | '"' | '`'))?;
    let body = &s[1..];
    let mut arg = String::new();
    let mut chars = body.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' if chars.peek().is_some_and(|&(_, n)| n == q) => {
                arg.push(q);
                chars.next();
            }
            c if c == q => {
                let after = body[i + 1..].trim_start();
                return (after.is_empty() || after.starts_with(',')).then_some((arg, after));
            }
            c => arg.push(c),
        }
    }
    None
}

/// The text after AdGuard's `#%#`: `//scriptlet('name', 'arg', "arg")`.
pub(crate) fn parse_adguard(body: &str) -> Result<Vec<ScriptletCall>, ParseError> {
    let inner = body
        .strip_prefix("//scriptlet(")
        .and_then(|r| r.trim_end().strip_suffix(')'))
        .ok_or_else(|| ParseError::invalid("malformed //scriptlet(…)"))?;
    let mut args = Vec::new();
    let mut chars = inner.chars().peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        let Some(q) = chars.next() else { break };
        if q != '\'' && q != '"' {
            return Err(ParseError::invalid(
                "AdGuard scriptlet arguments must be quoted",
            ));
        }
        let mut arg = String::new();
        let mut closed = false;
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    if let Some(next) = chars.next() {
                        if next != q && next != '\\' {
                            arg.push('\\');
                        }
                        arg.push(next);
                    }
                }
                c if c == q => {
                    closed = true;
                    break;
                }
                c => arg.push(c),
            }
        }
        if !closed {
            return Err(ParseError::invalid(
                "unterminated AdGuard scriptlet argument",
            ));
        }
        args.push(arg);
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        match chars.next() {
            None => break,
            Some(',') => {}
            Some(_) => {
                return Err(ParseError::invalid(
                    "expected , between AdGuard scriptlet arguments",
                ));
            }
        }
    }
    let mut args = args.into_iter();
    let Some(name) = args.next() else {
        // `#@%#//scriptlet()`: AdGuard's "disable all scriptlets".
        return Ok(Vec::new());
    };
    Ok(vec![call(&name, args.collect(), Dialect::Adguard)?])
}

/// ABP snippets: `name arg 'arg with spaces'; name2 arg`.
pub(crate) fn parse_abp(body: &str) -> Result<Vec<ScriptletCall>, ParseError> {
    let mut calls = Vec::new();
    let mut tokens: Vec<String> = Vec::new();
    let mut token = String::new();
    let mut in_token = false;
    let mut quoted = false;
    let mut chars = body.chars();

    let mut finish_call = |tokens: &mut Vec<String>| -> Result<(), ParseError> {
        let mut it = std::mem::take(tokens).into_iter();
        if let Some(name) = it.next() {
            calls.push(call(&name, it.collect(), Dialect::Abp)?);
        }
        Ok(())
    };

    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                in_token = true;
                match chars.next() {
                    Some('n') => token.push('\n'),
                    Some('t') => token.push('\t'),
                    Some(other) => token.push(other),
                    None => {}
                }
            }
            '\'' => {
                quoted = !quoted;
                in_token = true;
            }
            c if quoted => token.push(c),
            c if c.is_whitespace() => {
                if in_token {
                    tokens.push(std::mem::take(&mut token));
                    in_token = false;
                }
            }
            ';' => {
                if in_token {
                    tokens.push(std::mem::take(&mut token));
                    in_token = false;
                }
                finish_call(&mut tokens)?;
            }
            c => {
                token.push(c);
                in_token = true;
            }
        }
    }
    if quoted {
        return Err(ParseError::invalid("unterminated quote in ABP snippet"));
    }
    if in_token {
        tokens.push(token);
    }
    finish_call(&mut tokens)?;
    if calls.is_empty() {
        return Err(ParseError::invalid("empty ABP snippet"));
    }
    Ok(calls)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(calls: &[ScriptletCall]) -> Vec<&str> {
        calls[0].args.iter().map(String::as_str).collect()
    }

    #[test]
    fn resolves_aliases() {
        for n in [
            "set",
            "set-constant",
            "set-constant.js",
            "ubo-set.js",
            "override-property-read",
        ] {
            assert_eq!(resolve(n).map(|s| s.name), Some("set-constant"), "{n}");
        }
        assert_eq!(
            resolve("nostif").map(|s| s.name),
            Some("prevent-setTimeout")
        );
        assert_eq!(
            resolve("no-fetch-if.js").map(|s| s.name),
            Some("prevent-fetch")
        );
        assert_eq!(
            resolve("acis").map(|s| s.name),
            Some("abort-current-script")
        );
        assert_eq!(
            resolve("prevent-window-open").map(|s| s.name),
            Some("no-window-open-if")
        );
        assert!(resolve("eval-anything").is_none());
        // Names are case-sensitive, as in uBO.
        assert!(resolve("Set-Constant").is_none());
    }

    #[test]
    fn ublock_arguments() {
        let c = parse_ublock("set, ads.enabled, false").unwrap();
        assert_eq!(c[0].name, "set-constant");
        assert_eq!(c[0].dialect, Dialect::Ublock);
        assert_eq!(args(&c), ["ads.enabled", "false"]);

        let c = parse_ublock("acs, document.write, /ad\\,s/").unwrap();
        assert_eq!(args(&c), ["document.write", "/ad,s/"]);

        let c = parse_ublock("set, x, 'a, b', \"it\\\"s\"").unwrap();
        assert_eq!(args(&c), ["x", "a, b", "it\"s"]);

        // `''` is uBO's empty-string value.
        let c = parse_ublock("set, x, ''").unwrap();
        assert_eq!(args(&c), ["x", ""]);

        let c = parse_ublock("json-prune").unwrap();
        assert!(c[0].args.is_empty());

        assert!(parse_ublock("").unwrap().is_empty());
    }

    /// A quote that does not close right before a comma or the end is text,
    /// as in uBO. Both cases are from uBO's own lists.
    #[test]
    fn ublock_quotes_that_are_text() {
        let c = parse_ublock("nostif, '0x").unwrap();
        assert_eq!(args(&c), ["'0x"]);
        let c = parse_ublock(r#"set, "enabled":true, "enabled":false"#).unwrap();
        assert_eq!(args(&c), [r#""enabled":true"#, r#""enabled":false"#]);
        let c = parse_ublock("set, 'x' y, z").unwrap();
        assert_eq!(args(&c), ["'x' y", "z"]);
        // A properly closed quote still protects commas.
        let c = parse_ublock("set, 'a, b' , c").unwrap();
        assert_eq!(args(&c), ["a, b", "c"]);
    }

    #[test]
    fn ublock_errors() {
        assert_eq!(
            parse_ublock("evil-eval, x").unwrap_err().feature(),
            "scriptlet:unknown"
        );
        assert!(matches!(
            parse_ublock("set, x"),
            Err(ParseError::Invalid(_))
        ));
        let many = format!("json-prune{}", ", a".repeat(40));
        assert!(matches!(parse_ublock(&many), Err(ParseError::Invalid(_))));
    }

    #[test]
    fn adguard_arguments() {
        let c = parse_adguard("//scriptlet('set-constant', 'ads.enabled', \"false\")").unwrap();
        assert_eq!(c[0].name, "set-constant");
        assert_eq!(c[0].dialect, Dialect::Adguard);
        assert_eq!(args(&c), ["ads.enabled", "false"]);

        let c = parse_adguard("//scriptlet('ubo-acis.js', 'eval', 'it\\'s,here')").unwrap();
        assert_eq!(c[0].name, "abort-current-script");
        assert_eq!(args(&c), ["eval", "it's,here"]);

        // Regex escapes survive.
        let c = parse_adguard("//scriptlet('prevent-fetch', '/ads\\.js/')").unwrap();
        assert_eq!(args(&c), ["/ads\\.js/"]);

        assert!(parse_adguard("//scriptlet()").unwrap().is_empty());
        assert!(matches!(
            parse_adguard("//scriptlet(set-constant, a, b)"),
            Err(ParseError::Invalid(_))
        ));
        assert!(matches!(
            parse_adguard("//scriptlet('set-constant', 'a' 'b')"),
            Err(ParseError::Invalid(_))
        ));
        assert!(matches!(
            parse_adguard("alert(1)"),
            Err(ParseError::Invalid(_))
        ));
    }

    #[test]
    fn abp_snippets() {
        let c = parse_abp("abort-on-property-read ads; json-prune 'a b' c").unwrap();
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].name, "abort-on-property-read");
        assert_eq!(args(&c), ["ads"]);
        assert_eq!(c[1].args, ["a b", "c"]);
        assert_eq!(c[1].dialect, Dialect::Abp);

        let c = parse_abp("override-property-read x\\;y ''").unwrap();
        assert_eq!(c[0].name, "set-constant");
        assert_eq!(args(&c), ["x;y", ""]);

        assert_eq!(
            parse_abp("hide-if-contains ad").unwrap_err().feature(),
            "scriptlet:unknown"
        );
        assert!(matches!(
            parse_abp("json-prune 'a"),
            Err(ParseError::Invalid(_))
        ));
        assert!(matches!(parse_abp("  ;  "), Err(ParseError::Invalid(_))));
    }
}
