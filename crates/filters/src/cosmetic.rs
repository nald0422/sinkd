//! Cosmetic rules and the `##`-family separators.
//!
//! One separator scan decides what a cosmetic line is: element hiding
//! (`##`), extended/procedural hiding (`#?#`), CSS injection (`#$#`, which ABP
//! also uses for snippets), AdGuard script rules (`#%#`), uBO scriptlets
//! (`##+js(…)`), uBO response-header removal (`##^responseheader(…)`) and
//! HTML filtering (`##^`, `$$`), which MV3 cannot do.
//!
//! Selectors end up inside a stylesheet the extension injects, so anything
//! that could escape a CSS rule block (`{`, `}`, `;`, comments) is rejected,
//! and `:style()` declarations cannot load resources (`url(` and friends).

use serde::Serialize;

use crate::domains::{DomainSpec, parse_domain_list, plausible_cosmetic_prefix};
use crate::scriptlet::{self, ScriptletRule};
use crate::{ParseError, Rule};

/// An element hiding, procedural or CSS injection rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CosmeticRule {
    /// Empty: generic (every site).
    pub domains: Vec<DomainSpec>,
    /// `#@#`: do not apply the identical selector on these sites.
    pub exception: bool,
    pub selector: Selector,
    pub action: CosmeticAction,
}

/// What to do with matched elements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum CosmeticAction {
    /// `display: none !important`.
    Hide,
    /// `:remove()`: take the element out of the DOM.
    Remove,
    /// `:style(…)` / `#$#sel { … }`: apply these (sanitized) declarations.
    Style(String),
    /// `:remove-attr(…)`
    RemoveAttr(String),
    /// `:remove-class(…)`
    RemoveClass(String),
}

/// A selector: plain CSS, or CSS interleaved with procedural operators that
/// the content script evaluates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Selector {
    pub steps: Vec<SelectorStep>,
}

impl Selector {
    /// The selector as CSS, if it has no procedural operators.
    pub fn as_css(&self) -> Option<&str> {
        match self.steps.as_slice() {
            [SelectorStep::Css(css)] => Some(css),
            _ => None,
        }
    }

    fn is_procedural(&self) -> bool {
        self.steps.iter().any(|s| matches!(s, SelectorStep::Op(_)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum SelectorStep {
    /// CSS text. After an operator it is relative (`> .child`).
    Css(String),
    Op(ProceduralOp),
}

/// Procedural operators, under their uBO names. ABP (`:-abp-*`) and AdGuard
/// (`:contains`, `:if`, `:if-not`, `:nth-ancestor`) spellings map onto these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "op", content = "arg", rename_all = "kebab-case")]
pub enum ProceduralOp {
    HasText(String),
    Has(Selector),
    Not(Selector),
    MatchesCss {
        /// `before` / `after` for `:matches-css-before()` etc.
        pseudo: Option<String>,
        arg: String,
    },
    MatchesAttr(String),
    MatchesPath(String),
    MatchesProp(String),
    MatchesMedia(String),
    MinTextLength(u32),
    Upward(Upward),
    Xpath(String),
    WatchAttr(String),
    Others,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Upward {
    Levels(u32),
    Selector(String),
}

/// `example.com##^responseheader(refresh)` (uBO): drop a response header
/// from the page's main document. DNR can do this with `modifyHeaders`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResponseHeaderRule {
    pub domains: Vec<DomainSpec>,
    pub exception: bool,
    /// Lowercase header name.
    pub header: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sep {
    Hide,
    Extended,
    CssInject,
    ExtendedCssInject,
    Js,
    Html,
}

/// Longest first, so `#@$?#` wins over `#@#` wins over `##`.
const SEPARATORS: &[(&str, Sep, bool)] = &[
    ("#@$?#", Sep::ExtendedCssInject, true),
    ("#$?#", Sep::ExtendedCssInject, false),
    ("#@%#", Sep::Js, true),
    ("#@$#", Sep::CssInject, true),
    ("#@?#", Sep::Extended, true),
    ("#@#", Sep::Hide, true),
    ("#%#", Sep::Js, false),
    ("#$#", Sep::CssInject, false),
    ("#?#", Sep::Extended, false),
    ("##", Sep::Hide, false),
    ("$@$", Sep::Html, true),
    ("$$", Sep::Html, false),
];

pub(crate) struct Found {
    start: usize,
    len: usize,
    sep: Sep,
    exception: bool,
}

/// The first separator-looking token in the line.
fn first_separator(line: &str) -> Option<Found> {
    line.bytes().enumerate().find_map(|(i, b)| {
        if b != b'#' && b != b'$' {
            return None;
        }
        SEPARATORS
            .iter()
            .find(|(tok, ..)| line[i..].starts_with(tok))
            .map(|&(tok, sep, exception)| Found {
                start: i,
                len: tok.len(),
                sep,
                exception,
            })
    })
}

/// Finds the cosmetic separator, if the line is a cosmetic rule. The first
/// separator-looking token decides: if what precedes it cannot be a domain
/// list, the line is a network rule (`||example.com/##`).
pub(crate) fn find_separator(line: &str) -> Option<Found> {
    first_separator(line).filter(|f| plausible_cosmetic_prefix(&line[..f.start]))
}

/// Cosmetic rules whose hostname list carries syntax sinkhole does not
/// implement: uBO's `example.com>>##…`, and `example.com/path##…`. Read as
/// network rules these could never match (`>` is not a URL character and a
/// request URL has no `#`), so they are reported rather than parsed as one.
/// `||example.com/##` is still a network rule: `||` is not a hostname.
pub(crate) fn unsupported_prefix(line: &str) -> Option<ParseError> {
    let found = first_separator(line)?;
    let prefix = &line[..found.start];
    if let Some(hosts) = prefix.strip_suffix(">>")
        && plausible_cosmetic_prefix(hosts)
    {
        return Some(ParseError::unsupported(
            "cosmetic-prefix:>>",
            "uBO's `hostname>>` prefix is not implemented",
        ));
    }
    let (hosts, _path) = prefix.split_once('/')?;
    (!hosts.is_empty() && plausible_cosmetic_prefix(hosts)).then(|| {
        ParseError::unsupported(
            "cosmetic-prefix:path",
            "cosmetic rules limited to a URL path are not implemented",
        )
    })
}

pub(crate) fn parse_cosmetic(line: &str, found: Found) -> Result<Rule, ParseError> {
    let domains = parse_prefix(&line[..found.start])?;
    let body = line[found.start + found.len..].trim();
    let exception = found.exception;
    if body.is_empty() {
        return Err(ParseError::invalid("empty cosmetic rule body"));
    }
    let scriptlet_rule = |calls: Vec<scriptlet::ScriptletCall>, domains: Vec<DomainSpec>| {
        if calls.is_empty() && !exception {
            return Err(ParseError::invalid("empty scriptlet call"));
        }
        // A scriptlet on every page is a large blast radius for one list
        // line, so (like Brave) only exceptions may be generic.
        if !exception && !domains.iter().any(|d| !d.negated) {
            return Err(ParseError::unsupported(
                "scriptlet:generic",
                "scriptlet rules must name the sites they run on",
            ));
        }
        Ok(Rule::Scriptlet(ScriptletRule {
            domains,
            exception,
            calls,
        }))
    };

    match found.sep {
        Sep::Html => Err(ParseError::unsupported(
            "html-filtering",
            "needs response-body access, which MV3 extensions do not have",
        )),
        Sep::Js => {
            if body.starts_with("//scriptlet(") {
                scriptlet_rule(scriptlet::parse_adguard(body)?, domains)
            } else {
                Err(ParseError::unsupported(
                    "arbitrary-js",
                    "lists may only select bundled scriptlets, never supply code",
                ))
            }
        }
        Sep::Hide => {
            if let Some(rest) = body.strip_prefix("+js(") {
                let inner = rest
                    .strip_suffix(')')
                    .ok_or_else(|| ParseError::invalid("unterminated +js("))?;
                scriptlet_rule(scriptlet::parse_ublock(inner)?, domains)
            } else if let Some(rest) = body.strip_prefix('^') {
                parse_response_header(rest, domains, exception)
            } else if body.ends_with('}') && body.contains('{') {
                // EasyList's `##selector { declarations }`: CSS injection in
                // AdGuard's form, under the plain separator.
                let (selector, action) = parse_css_injection(body)?;
                Ok(cosmetic(domains, exception, selector, action))
            } else {
                let (selector, action) = parse_selector(body)?;
                Ok(cosmetic(domains, exception, selector, action))
            }
        }
        Sep::Extended => {
            let (selector, action) = parse_selector(body)?;
            Ok(cosmetic(domains, exception, selector, action))
        }
        Sep::CssInject | Sep::ExtendedCssInject => {
            if body.ends_with('}') && body.contains('{') {
                let (selector, action) = parse_css_injection(body)?;
                Ok(cosmetic(domains, exception, selector, action))
            } else if found.sep == Sep::CssInject && !exception {
                // ABP uses `#$#` for snippets.
                scriptlet_rule(scriptlet::parse_abp(body)?, domains)
            } else {
                Err(ParseError::invalid("expected `selector { declarations }`"))
            }
        }
    }
}

fn cosmetic(
    domains: Vec<DomainSpec>,
    exception: bool,
    selector: Selector,
    action: CosmeticAction,
) -> Rule {
    Rule::Cosmetic(CosmeticRule {
        domains,
        exception,
        selector,
        action,
    })
}

fn parse_prefix(prefix: &str) -> Result<Vec<DomainSpec>, ParseError> {
    let prefix = prefix.trim();
    if prefix.is_empty() || prefix == "*" {
        return Ok(Vec::new());
    }
    // `*` among other entries means "everywhere", which is already implied.
    let items: Vec<&str> = crate::domains::split_items(prefix, b',')
        .into_iter()
        .filter(|i| i.trim() != "*")
        .collect();
    parse_domain_list(&items.join(","), b',', "cosmetic domain list")
}

fn parse_response_header(
    rest: &str,
    domains: Vec<DomainSpec>,
    exception: bool,
) -> Result<Rule, ParseError> {
    let Some(header) = rest
        .strip_prefix("responseheader(")
        .and_then(|r| r.strip_suffix(')'))
    else {
        return Err(ParseError::unsupported(
            "html-filtering",
            "needs response-body access, which MV3 extensions do not have",
        ));
    };
    let header = header.trim().to_ascii_lowercase();
    if header.is_empty()
        || !header
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err(ParseError::invalid(format!("bad header name {header:?}")));
    }
    if !domains.iter().any(|d| !d.negated) {
        return Err(ParseError::invalid(
            "responseheader rules must name the sites they apply to",
        ));
    }
    Ok(Rule::ResponseHeader(ResponseHeaderRule {
        domains,
        exception,
        header,
    }))
}

/// AdGuard `selector { declarations }` (`#$#`, `#$?#`).
fn parse_css_injection(body: &str) -> Result<(Selector, CosmeticAction), ParseError> {
    let open = body
        .find('{')
        .ok_or_else(|| ParseError::invalid("missing {"))?;
    let selector_src = body[..open].trim();
    let declarations = body[open + 1..body.len() - 1].trim();
    let (selector, action) = parse_selector(selector_src)?;
    if action != CosmeticAction::Hide {
        return Err(ParseError::invalid("action operator inside CSS injection"));
    }
    let compact: String = declarations
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let action = if matches!(compact.as_str(), "remove:true" | "remove:true;") {
        CosmeticAction::Remove
    } else {
        CosmeticAction::Style(sanitize_style(declarations)?)
    };
    Ok((selector, action))
}

/// Rejects declarations that could load resources or escape the rule block.
fn sanitize_style(declarations: &str) -> Result<String, ParseError> {
    const FORBIDDEN: &[&str] = &[
        "url(",
        "image(",
        "image-set(",
        "cross-fade(",
        "element(",
        "expression(",
        "@import",
        "javascript:",
        "-moz-binding",
        "behavior:",
        "\\",
        "{",
        "}",
        "/*",
        "<",
    ];
    let lower = declarations.to_ascii_lowercase();
    let compact: String = lower.chars().filter(|c| !c.is_whitespace()).collect();
    if let Some(bad) = FORBIDDEN.iter().find(|f| compact.contains(*f)) {
        return Err(ParseError::invalid(format!(
            "style declarations may not contain {bad:?}"
        )));
    }
    if declarations.trim().is_empty() {
        return Err(ParseError::invalid("empty style declarations"));
    }
    Ok(declarations.trim().to_owned())
}

/// Parses a cosmetic selector into CSS chunks and procedural operators, plus
/// a trailing action operator.
pub(crate) fn parse_selector(src: &str) -> Result<(Selector, CosmeticAction), ParseError> {
    let src = src.trim();
    if src.is_empty() {
        return Err(ParseError::invalid("empty selector"));
    }
    if src.contains("[-ext-") {
        return Err(ParseError::unsupported(
            "extcss-attribute-syntax",
            "AdGuard's legacy [-ext-…] syntax; use :has-text() etc.",
        ));
    }
    let bytes = src.as_bytes();
    let mut steps = Vec::new();
    let mut action = CosmeticAction::Hide;
    let mut action_seen = false;
    let mut css_start = 0;
    let mut quote: Option<u8> = None;
    let (mut brackets, mut parens) = (0usize, 0usize);
    let mut i = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'\\' => {
                i += 2;
                continue;
            }
            b'"' | b'\'' => quote = Some(b),
            b'[' => brackets += 1,
            b']' => brackets = brackets.saturating_sub(1),
            b'(' => parens += 1,
            b')' => parens = parens.saturating_sub(1),
            b':' if brackets == 0 && parens == 0 => {
                let name_end = i
                    + 1
                    + bytes[i + 1..]
                        .iter()
                        .take_while(|b| b.is_ascii_alphanumeric() || **b == b'-')
                        .count();
                if bytes.get(name_end) == Some(&b'(') {
                    let close = matching_paren(bytes, name_end)?;
                    let name = &src[i + 1..name_end];
                    let arg = &src[name_end + 1..close];
                    if let Some(item) = procedural(name, arg)? {
                        if action_seen {
                            return Err(ParseError::invalid("text after an action operator"));
                        }
                        push_css(&mut steps, &src[css_start..i])?;
                        match item {
                            Item::Op(op) => steps.push(SelectorStep::Op(op)),
                            Item::Action(a) => {
                                action = a;
                                action_seen = true;
                            }
                        }
                        i = close + 1;
                        css_start = i;
                        continue;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    if quote.is_some() || brackets != 0 || parens != 0 {
        return Err(ParseError::invalid(
            "unbalanced quotes, brackets or parentheses",
        ));
    }
    let tail = &src[css_start..];
    if action_seen && !tail.trim().is_empty() {
        return Err(ParseError::invalid("text after an action operator"));
    }
    push_css(&mut steps, tail)?;
    if steps.is_empty() {
        return Err(ParseError::invalid("operator without a selector"));
    }
    Ok((Selector { steps }, action))
}

fn push_css(steps: &mut Vec<SelectorStep>, chunk: &str) -> Result<(), ParseError> {
    // The first chunk is the base selector; whitespace there is meaningless.
    // Later chunks are relative (`:has-text(x) > span`), keep them as is.
    let chunk = if steps.is_empty() {
        chunk.trim()
    } else {
        chunk.trim_end()
    };
    if chunk.trim().is_empty() {
        return Ok(());
    }
    check_css(chunk)?;
    steps.push(SelectorStep::Css(chunk.to_owned()));
    Ok(())
}

/// Rejects CSS that could break out of the `selector { … }` block it is
/// placed into, or comment out what follows it.
fn check_css(css: &str) -> Result<(), ParseError> {
    let bytes = css.as_bytes();
    let mut quote = None;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) => {
                if b == b'\\' {
                    i += 1;
                } else if b == q {
                    quote = None;
                }
            }
            None => match b {
                b'\\' => i += 1,
                b'"' | b'\'' => quote = Some(b),
                b'{' | b'}' | b';' | b'<' => {
                    return Err(ParseError::invalid(format!(
                        "{:?} is not allowed in a selector",
                        b as char
                    )));
                }
                b'/' if bytes.get(i + 1) == Some(&b'*') => {
                    return Err(ParseError::invalid(
                        "comments are not allowed in a selector",
                    ));
                }
                b'@' if i == 0 => return Err(ParseError::invalid("at-rules are not selectors")),
                _ => {}
            },
        }
        i += 1;
    }
    Ok(())
}

/// Index of the `)` matching the `(` at `open`, skipping quoted text and
/// backslash escapes (so `:has-text(/\(/)` works).
fn matching_paren(bytes: &[u8], open: usize) -> Result<usize, ParseError> {
    let mut depth = 0usize;
    let mut quote = None;
    let mut i = open;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) if b == b'\\' => i += 1,
            Some(_) => {}
            None => match b {
                b'\\' => i += 1,
                b'"' | b'\'' => quote = Some(b),
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(i);
                    }
                }
                _ => {}
            },
        }
        i += 1;
    }
    Err(ParseError::invalid("unbalanced parentheses in selector"))
}

enum Item {
    Op(ProceduralOp),
    Action(CosmeticAction),
}

/// Interprets `:name(arg)`. `None` means it is ordinary CSS (`:nth-child`,
/// or `:has`/`:not` with a plain CSS argument).
fn procedural(name: &str, arg: &str) -> Result<Option<Item>, ParseError> {
    let op = |op| Ok(Some(Item::Op(op)));
    let text = || arg.to_owned();
    match name {
        "has-text" | "-abp-contains" | "contains" => op(ProceduralOp::HasText(text())),
        "has" | "not" if !is_procedural(arg) => Ok(None),
        "has" | "-abp-has" | "if" => op(ProceduralOp::Has(nested(arg)?)),
        "not" => op(ProceduralOp::Not(nested(arg)?)),
        "if-not" => op(ProceduralOp::Not(Selector {
            steps: vec![SelectorStep::Op(ProceduralOp::Has(nested(arg)?))],
        })),
        "is" | "where" if is_procedural(arg) => Err(ParseError::unsupported(
            "procedural:is",
            "procedural operators inside :is()/:where()",
        )),
        "matches-css" | "-abp-properties" => op(ProceduralOp::MatchesCss {
            pseudo: None,
            arg: text(),
        }),
        "matches-css-before" | "matches-css-after" => op(ProceduralOp::MatchesCss {
            pseudo: Some(name.trim_start_matches("matches-css-").to_owned()),
            arg: text(),
        }),
        "matches-attr" => op(ProceduralOp::MatchesAttr(text())),
        "matches-path" => op(ProceduralOp::MatchesPath(text())),
        "matches-prop" => op(ProceduralOp::MatchesProp(text())),
        "matches-media" => op(ProceduralOp::MatchesMedia(text())),
        "min-text-length" => {
            let n = arg.trim().parse().map_err(|_| {
                ParseError::invalid(format!(":min-text-length needs a number, got {arg:?}"))
            })?;
            op(ProceduralOp::MinTextLength(n))
        }
        "upward" | "nth-ancestor" => match arg.trim().parse::<u32>() {
            Ok(n) if (1..=256).contains(&n) => op(ProceduralOp::Upward(Upward::Levels(n))),
            _ if name == "upward"
                && !arg.trim().is_empty()
                && arg.trim().parse::<i64>().is_err() =>
            {
                check_css(arg)?;
                op(ProceduralOp::Upward(Upward::Selector(
                    arg.trim().to_owned(),
                )))
            }
            _ => Err(ParseError::invalid(format!(
                ":{name} needs 1-256 or a selector"
            ))),
        },
        "xpath" => op(ProceduralOp::Xpath(text())),
        "watch-attr" => op(ProceduralOp::WatchAttr(text())),
        "others" => {
            if !arg.trim().is_empty() {
                return Err(ParseError::invalid(":others() takes no argument"));
            }
            op(ProceduralOp::Others)
        }
        "remove" => {
            if !arg.trim().is_empty() {
                return Err(ParseError::invalid(":remove() takes no argument"));
            }
            Ok(Some(Item::Action(CosmeticAction::Remove)))
        }
        "style" => Ok(Some(Item::Action(CosmeticAction::Style(sanitize_style(
            arg,
        )?)))),
        "remove-attr" | "remove-class" => {
            if arg.trim().is_empty() {
                return Err(ParseError::invalid(format!(":{name}() needs an argument")));
            }
            Ok(Some(Item::Action(if name == "remove-attr" {
                CosmeticAction::RemoveAttr(text())
            } else {
                CosmeticAction::RemoveClass(text())
            })))
        }
        _ => Ok(None),
    }
}

fn nested(arg: &str) -> Result<Selector, ParseError> {
    match parse_selector(arg)? {
        (selector, CosmeticAction::Hide) => Ok(selector),
        _ => Err(ParseError::invalid(
            "action operator inside another operator",
        )),
    }
}

fn is_procedural(arg: &str) -> bool {
    parse_selector(arg).is_ok_and(|(s, a)| s.is_procedural() || a != CosmeticAction::Hide)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::HostPattern;
    use crate::parse_rule;

    fn cos(line: &str) -> CosmeticRule {
        match parse_rule(line) {
            Ok(Rule::Cosmetic(c)) => c,
            other => panic!("{line}: {other:?}"),
        }
    }

    fn err(line: &str) -> ParseError {
        parse_rule(line).expect_err(line)
    }

    fn css(s: &str) -> SelectorStep {
        SelectorStep::Css(s.into())
    }

    #[test]
    fn element_hiding() {
        let c = cos("example.com,~www.example.com##.ad-banner > div");
        assert_eq!(c.domains.len(), 2);
        assert!(!c.exception);
        assert_eq!(c.selector.as_css(), Some(".ad-banner > div"));
        assert_eq!(c.action, CosmeticAction::Hide);

        let c = cos("##div[class^=\"ad-\"]");
        assert!(c.domains.is_empty());
        let c = cos("example.com#@#.ad");
        assert!(c.exception);
        let c = cos("*##.ad");
        assert!(c.domains.is_empty());
        let c = cos("google.*##.ads");
        assert_eq!(c.domains[0].host, HostPattern::Entity("google".into()));
        let c = cos("###ad");
        assert_eq!(c.selector.as_css(), Some("#ad"));
    }

    #[test]
    fn native_has_and_not_stay_css() {
        assert_eq!(
            cos("##div:has(> .ad)").selector.as_css(),
            Some("div:has(> .ad)")
        );
        assert_eq!(
            cos("##div:not(.x):nth-child(2n+1)").selector.as_css(),
            Some("div:not(.x):nth-child(2n+1)")
        );
    }

    #[test]
    fn procedural_operators() {
        let c = cos("example.com##div.post:has-text(/Sponsored|Promoted/i):upward(2)");
        assert_eq!(
            c.selector.steps,
            [
                css("div.post"),
                SelectorStep::Op(ProceduralOp::HasText("/Sponsored|Promoted/i".into())),
                SelectorStep::Op(ProceduralOp::Upward(Upward::Levels(2))),
            ]
        );
        let c = cos("example.com#?#div:-abp-has(span:-abp-contains(Ad))");
        let SelectorStep::Op(ProceduralOp::Has(inner)) = &c.selector.steps[1] else {
            panic!("{c:?}")
        };
        assert_eq!(
            inner.steps[1],
            SelectorStep::Op(ProceduralOp::HasText("Ad".into()))
        );
        // Native :has with a procedural argument becomes procedural.
        let c = cos("example.com##div:has(> p:has-text(ad))");
        assert!(matches!(
            c.selector.steps[1],
            SelectorStep::Op(ProceduralOp::Has(_))
        ));
        let c = cos("example.com##.x:if-not(.y)");
        assert!(matches!(
            c.selector.steps[1],
            SelectorStep::Op(ProceduralOp::Not(_))
        ));
        let c = cos("example.com##div:matches-css-before(content: /ad/):min-text-length(20)");
        assert_eq!(
            c.selector.steps[1],
            SelectorStep::Op(ProceduralOp::MatchesCss {
                pseudo: Some("before".into()),
                arg: "content: /ad/".into()
            })
        );
        let c = cos("example.com##.x:upward(.card)");
        assert_eq!(
            c.selector.steps[1],
            SelectorStep::Op(ProceduralOp::Upward(Upward::Selector(".card".into())))
        );
        let c = cos("example.com##:xpath(//div[@id=\"ad\"])");
        assert_eq!(
            c.selector.steps,
            [SelectorStep::Op(ProceduralOp::Xpath(
                "//div[@id=\"ad\"]".into()
            ))]
        );
    }

    #[test]
    fn css_after_an_operator_is_relative() {
        let c = cos("example.com##.feed:has-text(ad) > span");
        assert_eq!(c.selector.steps[2], css(" > span"));
    }

    #[test]
    fn escaped_parens_in_arguments() {
        let c = cos("example.com##p:has-text(/\\(ad\\)/)");
        assert_eq!(
            c.selector.steps[1],
            SelectorStep::Op(ProceduralOp::HasText("/\\(ad\\)/".into()))
        );
    }

    #[test]
    fn actions() {
        assert_eq!(
            cos("example.com##.ad:remove()").action,
            CosmeticAction::Remove
        );
        assert_eq!(
            cos("example.com##body:style(overflow: auto !important)").action,
            CosmeticAction::Style("overflow: auto !important".into())
        );
        assert_eq!(
            cos("example.com##a:remove-attr(onclick)").action,
            CosmeticAction::RemoveAttr("onclick".into())
        );
        assert_eq!(
            cos("example.com##body:remove-class(noscroll)").action,
            CosmeticAction::RemoveClass("noscroll".into())
        );
        assert!(matches!(
            err("example.com##.ad:remove() > span"),
            ParseError::Invalid(_)
        ));
        assert!(matches!(
            err("example.com##:remove()"),
            ParseError::Invalid(_)
        ));
    }

    #[test]
    fn css_injection() {
        let c = cos("example.com#$#.ad { display: none !important; }");
        assert_eq!(
            c.action,
            CosmeticAction::Style("display: none !important;".into())
        );
        let c = cos("example.com#$?#div:has-text(ad) { remove: true; }");
        assert_eq!(c.action, CosmeticAction::Remove);
        assert!(c.selector.steps.len() == 2);
        assert!(cos("example.com#@$#.ad { color: red }").exception);

        // EasyList writes the same thing with `##`.
        let c = cos(r#"cyberchef.org###w > [style*="height"] {height: 100% !important}"#);
        assert_eq!(
            c.action,
            CosmeticAction::Style("height: 100% !important".into())
        );
        assert_eq!(c.selector.as_css(), Some(r#"#w > [style*="height"]"#));
        // The declarations are sanitized as for `#$#`.
        assert!(matches!(
            err("##.a{} body{background:red}"),
            ParseError::Invalid(_)
        ));
        assert!(matches!(
            err("x.com##.a {background: url(https://t.example/)}"),
            ParseError::Invalid(_)
        ));
    }

    #[test]
    fn unsupported_prefixes() {
        assert_eq!(
            err("f51rm.com>>##+js(nowoif, /^ [-\\d]/)").feature(),
            "cosmetic-prefix:>>"
        );
        assert_eq!(err("x.com>>##.ad").feature(), "cosmetic-prefix:>>");
        assert_eq!(
            err("igorslab.de/community/#@##extras, .entry-header").feature(),
            "cosmetic-prefix:path"
        );
        // Without whitespace this would parse as a network rule that can
        // never match.
        assert_eq!(
            err("nijie.info/ad_log.php#@#._banner_view").feature(),
            "cosmetic-prefix:path"
        );
        // A URL with `##` is still a network rule.
        assert!(matches!(
            parse_rule("||example.com/##"),
            Ok(Rule::Network(_))
        ));
    }

    #[test]
    fn ip_literal_hosts() {
        let c = cos("194.233.68.230###adsimgxatass");
        assert_eq!(
            c.domains[0].host,
            HostPattern::Ip("194.233.68.230".parse().unwrap())
        );
    }

    #[test]
    fn hostile_css_is_rejected() {
        assert!(matches!(
            err("##.a{} body{background:red"),
            ParseError::Invalid(_)
        ));
        assert!(matches!(err("##.a /* rest"), ParseError::Invalid(_)));
        assert!(matches!(err("##.a; .b"), ParseError::Invalid(_)));
        assert!(matches!(
            err("example.com##.a:style(background: url(https://t.example/x))"),
            ParseError::Invalid(_)
        ));
        assert!(matches!(
            err("example.com##.a:style(background:URL (x))"),
            ParseError::Invalid(_)
        ));
        assert!(matches!(
            err("example.com##.a:style(color: red} body{x:y)"),
            ParseError::Invalid(_)
        ));
        assert!(matches!(
            err("example.com##.a:style(background: u\\72l(x))"),
            ParseError::Invalid(_)
        ));
        assert!(matches!(
            err("example.com#$#.a { background-image: image-set(\"x\" 1x) }"),
            ParseError::Invalid(_)
        ));
        // Braces inside a quoted attribute value are fine.
        assert_eq!(
            cos("##a[title=\"{x}\"]").selector.as_css(),
            Some("a[title=\"{x}\"]")
        );
    }

    #[test]
    fn malformed_selectors() {
        assert!(matches!(err("example.com##"), ParseError::Invalid(_)));
        assert!(matches!(
            err("example.com##div[class"),
            ParseError::Invalid(_)
        ));
        assert!(matches!(
            err("example.com##div:has-text(x"),
            ParseError::Invalid(_)
        ));
        assert!(matches!(
            err("example.com##div:min-text-length(lots)"),
            ParseError::Invalid(_)
        ));
        assert!(matches!(
            err("example.com##div:upward(0)"),
            ParseError::Invalid(_)
        ));
        assert_eq!(
            err("example.com##div[-ext-has=\".ad\"]").feature(),
            "extcss-attribute-syntax"
        );
    }

    #[test]
    fn unsupported_syntaxes() {
        assert_eq!(
            err("example.com##^script:has-text(ad)").feature(),
            "html-filtering"
        );
        assert_eq!(
            err("example.com$$script[tag-content=\"ad\"]").feature(),
            "html-filtering"
        );
        assert_eq!(
            err("example.com#%#window.ads = false;").feature(),
            "arbitrary-js"
        );
        assert_eq!(
            err("example.com#@%#window.ads = false;").feature(),
            "arbitrary-js"
        );
    }

    #[test]
    fn response_headers() {
        let Ok(Rule::ResponseHeader(r)) = parse_rule("example.com##^responseheader(Refresh)")
        else {
            panic!()
        };
        assert_eq!(r.header, "refresh");
        assert!(matches!(
            err("##^responseheader(refresh)"),
            ParseError::Invalid(_)
        ));
    }

    #[test]
    fn scriptlets_must_name_their_sites() {
        assert_eq!(err("##+js(set, ads, false)").feature(), "scriptlet:generic");
        assert_eq!(
            err("~example.com##+js(set, ads, false)").feature(),
            "scriptlet:generic"
        );
        assert!(matches!(
            parse_rule("#@#+js(set, ads, false)"),
            Ok(Rule::Scriptlet(_))
        ));
        assert!(matches!(
            parse_rule("example.com##+js(set, ads, false)"),
            Ok(Rule::Scriptlet(_))
        ));
    }

    #[test]
    fn urls_with_hashes_are_network_rules() {
        assert!(matches!(
            parse_rule("||example.com/##ad"),
            Ok(Rule::Network(_))
        ));
        assert!(matches!(
            parse_rule("||example.com/#!/ads"),
            Ok(Rule::Network(_))
        ));
    }
}
