//! `!#` directives (uBO, AdGuard): `!#if` conditions and `!#include`.
//!
//! Lists gate rules on the blocker that reads them:
//!
//! ```text
//! !#if env_mv3 && !env_firefox
//! example.com##+js(set, ads, false)
//! !#endif
//! ```
//!
//! [`Env`] is the set of tokens that are true for a target. Unknown tokens
//! are false, which is what uBO does: a list written for some other blocker
//! keeps its gated sections to itself.
//!
//! [`Lines`] walks a list once, evaluating the conditions, joining continued
//! lines and surfacing `!#include`s. Every reader of lists goes through it,
//! so the browser rules and the resolver agree on which lines are live.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::str::Lines as StrLines;

/// The tokens that are true when compiling for a target.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Env {
    tokens: BTreeSet<String>,
}

impl Env {
    pub fn new<I, S>(tokens: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Env {
            tokens: tokens.into_iter().map(Into::into).collect(),
        }
    }

    /// Chromium MV3 extension. We present the capabilities of uBO Lite, the
    /// MV3 uBO build, because that is what we can actually do: scriptlets
    /// and user stylesheets, but no HTML filtering.
    pub fn chromium_mv3() -> Self {
        Env::new([
            "ext_ublock",
            "ext_ubol",
            "env_chromium",
            "env_mv3",
            "cap_user_stylesheet",
        ])
    }

    /// Firefox extension.
    pub fn firefox() -> Self {
        Env::new(["ext_ublock", "env_firefox", "cap_user_stylesheet"])
    }

    /// The DNS resolver. No token is true: no blocker's conventions name a
    /// DNS target, and the sections gated on a browser blocker hold rules a
    /// resolver could not apply anyway. `!#if !env_firefox` and the like
    /// still hold.
    pub fn dns() -> Self {
        Env::default()
    }

    pub fn is_set(&self, token: &str) -> bool {
        self.tokens.contains(token)
    }

    /// Evaluates a condition: tokens, `!`, `&&`, `||` and parentheses, with
    /// the usual precedence. `None` if it does not parse.
    pub fn eval(&self, expr: &str) -> Option<bool> {
        let tokens = tokenize(expr)?;
        let mut p = Parser {
            tokens: &tokens,
            pos: 0,
            env: self,
        };
        let value = p.or()?;
        (p.pos == tokens.len()).then_some(value)
    }
}

/// One logical line of a list, as [`Lines`] yields it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line<'a> {
    /// A live line that is not a directive: a rule or a comment. Trimmed,
    /// never empty, with any `" \"` continuations joined.
    Text(Cow<'a, str>),
    /// A live `!#include`, with its path trimmed.
    Include(&'a str),
    /// A line skipped because an `!#if` around it is false.
    Excluded,
    /// A `!#` line with no effect here: an unknown directive or vendor
    /// hint, or an `!#include` inside a false branch. Lists use them as
    /// comments.
    Directive,
    /// A malformed directive. `text` is the offending line.
    Invalid {
        text: Cow<'a, str>,
        message: &'static str,
    },
}

struct Frame {
    line: usize,
    parent_active: bool,
    condition: bool,
    in_else: bool,
}

impl Frame {
    fn active(&self) -> bool {
        self.parent_active && (self.condition != self.in_else)
    }
}

/// Iterates over the logical lines of a list, with their (first) 1-based
/// line numbers. Blank lines are skipped. An `!#if` left open at the end is
/// reported as [`Line::Invalid`] after the last line.
pub struct Lines<'a> {
    lines: std::iter::Enumerate<StrLines<'a>>,
    env: &'a Env,
    stack: Vec<Frame>,
    read: usize,
}

impl<'a> Lines<'a> {
    pub fn new(text: &'a str, env: &'a Env) -> Self {
        // A byte-order mark would otherwise glue itself to the first rule.
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        Lines {
            lines: text.lines().enumerate(),
            env,
            stack: Vec::new(),
            read: 0,
        }
    }

    /// Physical lines consumed so far, blank and continued ones included.
    pub fn lines_read(&self) -> usize {
        self.read
    }

    fn active(&self) -> bool {
        self.stack.last().is_none_or(Frame::active)
    }

    fn directive(&mut self, line_no: usize, line: &'a str, directive: &'a str) -> Option<Line<'a>> {
        let (name, arg) = directive
            .split_once(char::is_whitespace)
            .unwrap_or((directive, ""));
        let invalid = |message| {
            Some(Line::Invalid {
                text: Cow::Borrowed(line),
                message,
            })
        };
        let active = self.active();
        match name {
            "if" => {
                let condition = self.env.eval(arg);
                self.stack.push(Frame {
                    line: line_no,
                    parent_active: active,
                    condition: condition.unwrap_or(false),
                    in_else: false,
                });
                match condition {
                    Some(_) => None,
                    None => invalid("unparseable !#if condition (treated as false)"),
                }
            }
            "else" => match self.stack.last_mut() {
                Some(frame) if !frame.in_else => {
                    frame.in_else = true;
                    None
                }
                _ => invalid("!#else without a matching !#if"),
            },
            "endif" => match self.stack.pop() {
                Some(_) => None,
                None => invalid("!#endif without a matching !#if"),
            },
            "include" if active => match arg.trim() {
                "" => invalid("!#include without a path"),
                path => Some(Line::Include(path)),
            },
            _ => Some(Line::Directive),
        }
    }
}

impl<'a> Iterator for Lines<'a> {
    type Item = (usize, Line<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((index, first)) = self.lines.next() {
            let line_no = index + 1;
            self.read += 1;
            let first = first.trim();
            if first.is_empty() {
                continue;
            }
            if let Some(directive) = first.strip_prefix("!#") {
                match self.directive(line_no, first, directive) {
                    Some(line) => return Some((line_no, line)),
                    None => continue,
                }
            }
            // uBO line continuation: a line ending in " \" continues on the
            // next line, whose leading whitespace is dropped.
            let mut line = Cow::Borrowed(first);
            while line.ends_with(" \\") {
                let Some((_, next)) = self.lines.next() else {
                    break;
                };
                self.read += 1;
                let mut joined = line.into_owned();
                joined.truncate(joined.len() - 2);
                joined.push_str(next.trim());
                line = Cow::Owned(joined);
            }
            if !self.active() {
                return Some((line_no, Line::Excluded));
            }
            return Some((line_no, Line::Text(line)));
        }
        let frame = self.stack.pop()?;
        Some((
            frame.line,
            Line::Invalid {
                text: Cow::Borrowed("!#if"),
                message: "!#if without a matching !#endif",
            },
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok<'a> {
    Ident(&'a str),
    Not,
    And,
    Or,
    Open,
    Close,
}

fn tokenize(expr: &str) -> Option<Vec<Tok<'_>>> {
    let mut out = Vec::new();
    let mut rest = expr.trim_start();
    while !rest.is_empty() {
        let (tok, len) = if rest.starts_with("&&") {
            (Tok::And, 2)
        } else if rest.starts_with("||") {
            (Tok::Or, 2)
        } else if rest.starts_with('!') {
            (Tok::Not, 1)
        } else if rest.starts_with('(') {
            (Tok::Open, 1)
        } else if rest.starts_with(')') {
            (Tok::Close, 1)
        } else {
            let len = rest
                .bytes()
                .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .count();
            if len == 0 {
                return None;
            }
            (Tok::Ident(&rest[..len]), len)
        };
        out.push(tok);
        rest = rest[len..].trim_start();
    }
    Some(out)
}

struct Parser<'a> {
    tokens: &'a [Tok<'a>],
    pos: usize,
    env: &'a Env,
}

impl Parser<'_> {
    fn eat(&mut self, tok: &Tok<'_>) -> bool {
        if self.tokens.get(self.pos) == Some(tok) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn or(&mut self) -> Option<bool> {
        let mut value = self.and()?;
        while self.eat(&Tok::Or) {
            value |= self.and()?;
        }
        Some(value)
    }

    fn and(&mut self) -> Option<bool> {
        let mut value = self.unary()?;
        while self.eat(&Tok::And) {
            value &= self.unary()?;
        }
        Some(value)
    }

    fn unary(&mut self) -> Option<bool> {
        if self.eat(&Tok::Not) {
            return self.unary().map(|v| !v);
        }
        if self.eat(&Tok::Open) {
            let value = self.or()?;
            return self.eat(&Tok::Close).then_some(value);
        }
        match self.tokens.get(self.pos)? {
            Tok::Ident(name) => {
                self.pos += 1;
                Some(match *name {
                    "true" => true,
                    "false" => false,
                    name => self.env.is_set(name),
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluates_expressions() {
        let env = Env::new(["a", "b"]);
        assert_eq!(env.eval("a"), Some(true));
        assert_eq!(env.eval("c"), Some(false));
        assert_eq!(env.eval("!c"), Some(true));
        assert_eq!(env.eval("a && !b"), Some(false));
        assert_eq!(env.eval("c || b"), Some(true));
        assert_eq!(env.eval("!(a && c) && (b || c)"), Some(true));
        // && binds tighter than ||.
        assert_eq!(env.eval("a || c && c"), Some(true));
        assert_eq!(env.eval("false || true"), Some(true));
    }

    #[test]
    fn rejects_malformed() {
        let env = Env::default();
        assert_eq!(env.eval(""), None);
        assert_eq!(env.eval("a &&"), None);
        assert_eq!(env.eval("(a"), None);
        assert_eq!(env.eval("a b"), None);
        assert_eq!(env.eval("a == b"), None);
    }

    #[test]
    fn presets() {
        assert_eq!(
            Env::chromium_mv3().eval("env_mv3 && !env_firefox"),
            Some(true)
        );
        assert_eq!(Env::firefox().eval("env_chromium"), Some(false));
        assert_eq!(Env::chromium_mv3().eval("cap_html_filtering"), Some(false));
    }
}
