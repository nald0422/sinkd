//! Whole lists in; DNR rulesets, the resolver's domain set and a report out.
//!
//! 1. Every list is read through the shared preprocessor (`!#if` against
//!    the target's environment), and each rule is parsed once.
//! 2. `$badfilter` rules cancel their twins across all lists.
//! 3. Each network rule is translated ([`crate::translate`]) or reported.
//! 4. Rules that differ only in `requestDomains` are merged into one: the
//!    thousands of `||host^` lines in a list become a handful of DNR rules,
//!    which is what keeps a full list set inside Chrome's quotas. Parameter
//!    rules that differ only in the parameter merge the same way.
//! 5. Every rule is checked as Chrome would ([`crate::validate`]), quotas
//!    are applied, and rules are sorted and numbered, so the same lists
//!    always give byte-identical output.
//! 6. `$popup` rules, which DNR cannot apply, go the same way into rules
//!    for the tabs pages open ([`crate::translate::translate_popup`]); the
//!    extension checks those itself.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::Serialize;
use sinkd_core::Scope;
use sinkd_filters::dns::{DnsAction, DnsFormat, parse_dns_line};
use sinkd_filters::network::{Party, ResourceTypes};
use sinkd_filters::{Env, Line, Lines, NetworkRule, Rule, is_comment, parse_rule};

use crate::dnr::{self, ActionType};
use crate::page::{PageOutput, PageTarget};
use crate::translate::{
    Draft, Feature, Skip, Translated, priority, translate_network, translate_popup,
    translate_response_header,
};
use crate::validate::{self, MAX_REGEX_RULES};

/// One list to compile.
#[derive(Debug, Clone)]
pub struct ListInput {
    pub name: String,
    /// The ruleset its rules go to.
    pub ruleset: String,
    pub text: String,
}

/// A compiled DNR ruleset.
#[derive(Debug, Clone, PartialEq)]
pub struct Ruleset {
    pub id: String,
    pub rules: Vec<dnr::Rule>,
}

/// The resolver's share: names in the "domains" list format (`name` for
/// the name and everything below it, `*.name` for only what is below).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsSet {
    pub block: Vec<String>,
    pub allow: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Compiled {
    pub rulesets: Vec<Ruleset>,
    /// Per ruleset that has any, its rules for the tabs pages open
    /// (`$popup`), in DNR's shape but never given to Chrome.
    pub popups: Vec<Ruleset>,
    pub dns: DnsSet,
    /// Per ruleset, the hosts it names outright, for what the extension
    /// does outside DNR.
    pub hosts: BTreeMap<String, Hosts>,
    /// The page index and scriptlet files.
    pub page: PageOutput,
    pub report: Report,
}

/// Hosts a ruleset names outright, parents only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hosts {
    /// What its plain `||host^` block rules name, minus what an
    /// unrestricted `@@||host^` frees. The extension strips cookies and
    /// `Referer` from third-party requests to these when the ruleset is
    /// marked `trackers`, and in Firefox blocks names that are DNS aliases
    /// (CNAMEs) of them.
    pub block: Vec<String>,
    /// What an unrestricted `@@||host^` or a `@@||host^$cname` names:
    /// requests there are never blocked for their alias.
    pub exempt: Vec<String>,
    /// What a `@@||host^$document` names: pages where blocking is off, so
    /// no alias is blocked on them either.
    pub documents: Vec<String>,
}

/// A rule a target could not take.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rejection {
    pub list: String,
    pub line: usize,
    pub text: String,
    pub feature: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TargetReport {
    /// Source rules that made it into the output.
    pub translated: usize,
    /// Of those, rules that lost a part DNR has no name for.
    pub narrowed: usize,
    pub rejected: usize,
    pub by_feature: BTreeMap<String, usize>,
    pub entries: Vec<Rejection>,
}

impl TargetReport {
    fn reject(&mut self, list: &str, line: usize, text: &str, feature: String, reason: String) {
        self.rejected += 1;
        *self.by_feature.entry(feature.clone()).or_default() += 1;
        self.entries.push(Rejection {
            list: list.to_owned(),
            line,
            text: text.to_owned(),
            feature,
            reason,
        });
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ListReport {
    pub name: String,
    pub ruleset: String,
    pub lines: usize,
    /// Lines that are rules, not comments or directives.
    pub rules: usize,
    pub chrome_translated: usize,
    pub chrome_rejected: usize,
    pub dns_entries: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RulesetReport {
    pub id: String,
    /// DNR rules after merging.
    pub rules: usize,
    pub regex_rules: usize,
    /// Source rules translated into it.
    pub source_rules: usize,
}

/// Everything a build should know about what did not make it, and why.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Report {
    pub lists: Vec<ListReport>,
    pub rulesets: Vec<RulesetReport>,
    pub chrome: TargetReport,
    pub dns: TargetReport,
    /// Cosmetic and scriptlet rules, and page exceptions, for the
    /// extension's page index and scriptlet files.
    pub page: TargetReport,
    /// `$popup` rules, for the tabs pages open.
    pub popups: TargetReport,
    /// Rules for no output of this build: `$cname` exceptions, which only
    /// the resolver uses.
    pub later: BTreeMap<String, usize>,
    /// Badfilter cancellations, across lists.
    pub badfiltered: usize,
    /// Quota problems and the like.
    pub warnings: Vec<String>,
}

/// Compiles `lists`. `params_ruleset`, if set, receives every
/// `$removeparam` rule, so parameter stripping can be switched on its own.
pub fn compile(lists: &[ListInput], params_ruleset: Option<&str>) -> Compiled {
    let mut report = Report::default();
    let mut pending: Vec<(usize, usize, String, NetworkRule)> = Vec::new();
    let mut translated: Vec<(usize, usize, String, Result<Translated, Skip>)> = Vec::new();
    let mut badfilters = HashSet::new();
    let browser = Env::chromium_mv3();
    let ruleset_ids: BTreeSet<&str> = lists.iter().map(|l| l.ruleset.as_str()).collect();
    let mut page = PageTarget::new(ruleset_ids.iter().copied());

    for (index, list) in lists.iter().enumerate() {
        let mut lr = ListReport {
            name: list.name.clone(),
            ruleset: list.ruleset.clone(),
            ..ListReport::default()
        };
        let mut lines = Lines::new(&list.text, &browser);
        for (line_no, line) in lines.by_ref() {
            let text = match line {
                Line::Text(text) if is_comment(&text) => continue,
                Line::Text(text) => text,
                Line::Invalid { text, message } => {
                    lr.rules += 1;
                    report.chrome.reject(
                        &list.name,
                        line_no,
                        &text,
                        "invalid".into(),
                        message.into(),
                    );
                    continue;
                }
                Line::Include(_) | Line::Excluded | Line::Directive => continue,
            };
            lr.rules += 1;
            match parse_rule(&text) {
                // A page rule the parser cannot take (an unbundled
                // scriptlet, HTML filtering) is the page index's business,
                // not DNR's.
                Err(e) if is_page_rule(&text, e.feature()) => {
                    report.page.reject(
                        &list.name,
                        line_no,
                        &text,
                        e.feature().to_owned(),
                        e.to_string(),
                    );
                }
                Err(e) => {
                    report.chrome.reject(
                        &list.name,
                        line_no,
                        &text,
                        e.feature().to_owned(),
                        e.to_string(),
                    );
                }
                Ok(Rule::Network(rule)) if rule.options.badfilter => {
                    badfilters.insert(badfilter_key(&rule));
                }
                Ok(Rule::Network(rule)) => pending.push((index, line_no, text.into_owned(), rule)),
                Ok(Rule::ResponseHeader(rule)) => {
                    let result = translate_response_header(&rule);
                    translated.push((index, line_no, text.into_owned(), result));
                }
                Ok(Rule::Cosmetic(rule)) => match page.cosmetic(&list.ruleset, &rule) {
                    Ok(()) => report.page.translated += 1,
                    Err(e) => report
                        .page
                        .reject(&list.name, line_no, &text, e.feature, e.reason),
                },
                Ok(Rule::Scriptlet(rule)) => match page.scriptlet(&list.ruleset, &rule) {
                    Ok(()) => report.page.translated += 1,
                    Err(e) => report
                        .page
                        .reject(&list.name, line_no, &text, e.feature, e.reason),
                },
            }
        }
        lr.lines = lines.lines_read();
        report.lists.push(lr);
    }

    let mut named: BTreeMap<String, NamedHosts> = BTreeMap::new();
    let mut popup_drafts: BTreeMap<String, Vec<Draft>> = BTreeMap::new();
    for (index, line, text, rule) in pending {
        if badfilters.contains(&badfilter_key(&rule)) {
            report.badfiltered += 1;
            continue;
        }
        named
            .entry(lists[index].ruleset.clone())
            .or_default()
            .add(&rule);
        // `$generichide` and friends, and `$document` exceptions, also act
        // on the page.
        let o = &rule.options;
        let page_option = o.page.elemhide || o.page.generichide || o.page.specifichide;
        if rule.exception && (page_option || o.types.is_some()) {
            match page.page_exception(&lists[index].ruleset, &rule) {
                Err(e) => report
                    .page
                    .reject(&lists[index].name, line, &text, e.feature, e.reason),
                Ok(()) if page_option => report.page.translated += 1,
                Ok(()) => {}
            }
        }
        match translate_popup(&rule) {
            Some(Ok(draft)) => {
                report.popups.translated += 1;
                popup_drafts
                    .entry(lists[index].ruleset.clone())
                    .or_default()
                    .push(draft);
            }
            Some(Err(Skip::Rejected { feature, reason })) => {
                report
                    .popups
                    .reject(&lists[index].name, line, &text, feature, reason);
            }
            Some(Err(Skip::OtherTarget(_))) | None => {}
        }
        // A rule for tabs alone has nothing for DNR.
        if rule
            .options
            .types
            .is_some_and(|t| t.without(ResourceTypes::POPUP).is_empty())
        {
            continue;
        }
        translated.push((index, line, text, translate_network(&rule)));
    }

    let mut drafts: BTreeMap<String, Vec<Draft>> = BTreeMap::new();
    let mut sources: HashMap<String, usize> = HashMap::new();
    for (index, line, text, result) in translated {
        let list = &lists[index];
        match result {
            Ok(t) => {
                report.chrome.translated += 1;
                report.lists[index].chrome_translated += 1;
                // The popup part of a rule went to the popup rules.
                if t.narrowed.iter().any(|n| *n != "type:popup") {
                    report.chrome.narrowed += 1;
                }
                let ruleset = match (t.feature, params_ruleset) {
                    (Feature::Params, Some(params)) => params.to_owned(),
                    _ => list.ruleset.clone(),
                };
                *sources.entry(ruleset.clone()).or_default() += 1;
                drafts.entry(ruleset).or_default().push(t.draft);
            }
            Err(Skip::Rejected { feature, reason }) => {
                report.lists[index].chrome_rejected += 1;
                report
                    .chrome
                    .reject(&list.name, line, &text, feature, reason);
            }
            // Page exceptions were taken by the page target above.
            Err(Skip::OtherTarget("cosmetic")) => {}
            Err(Skip::OtherTarget(target)) => {
                *report.later.entry(target.into()).or_default() += 1;
            }
        }
    }

    // Every configured ruleset exists in the output, even if empty.
    let mut ids: BTreeSet<String> = lists.iter().map(|l| l.ruleset.clone()).collect();
    ids.extend(params_ruleset.map(str::to_owned));
    let mut rulesets = Vec::new();
    for id in ids {
        let rules = finish(drafts.remove(&id).unwrap_or_default(), &id, &mut report);
        report.rulesets.push(RulesetReport {
            id: id.clone(),
            rules: rules.len(),
            regex_rules: rules
                .iter()
                .filter(|r| r.condition.regex_filter.is_some())
                .count(),
            source_rules: sources.get(&id).copied().unwrap_or(0),
        });
        rulesets.push(Ruleset { id, rules });
    }
    let total: usize = rulesets.iter().map(|r| r.rules.len()).sum();
    if total > validate::GUARANTEED_STATIC_RULES {
        report.warnings.push(format!(
            "{total} static rules exceed the {} Chrome guarantees; the rest depend on the pool shared with other extensions",
            validate::GUARANTEED_STATIC_RULES
        ));
    }
    if rulesets.len() > validate::MAX_STATIC_RULESETS {
        report.warnings.push(format!(
            "{} rulesets exceed Chrome's limit of {}",
            rulesets.len(),
            validate::MAX_STATIC_RULESETS
        ));
    }

    let popups = popup_drafts
        .into_iter()
        .map(|(id, drafts)| {
            let rules = finish(drafts, &format!("{id} (popups)"), &mut report);
            Ruleset { id, rules }
        })
        .collect();

    let dns = dns_set(lists, &mut report);
    // In list order, then line order, however they were found.
    let order: HashMap<&str, usize> = lists
        .iter()
        .enumerate()
        .map(|(i, l)| (l.name.as_str(), i))
        .collect();
    for target in [
        &mut report.chrome,
        &mut report.dns,
        &mut report.page,
        &mut report.popups,
    ] {
        target
            .entries
            .sort_by_key(|e| (order.get(e.list.as_str()).copied(), e.line));
    }
    let hosts = named
        .into_iter()
        .map(|(ruleset, named)| (ruleset, named.finish()))
        .collect();
    Compiled {
        rulesets,
        popups,
        dns,
        hosts,
        page: page.finish(),
        report,
    }
}

/// [`Hosts`] while the rules are read.
#[derive(Default)]
struct NamedHosts {
    blocked: BTreeSet<String>,
    freed: BTreeSet<String>,
    uncloaked: BTreeSet<String>,
    documents: BTreeSet<String>,
}

impl NamedHosts {
    fn add(&mut self, rule: &NetworkRule) {
        if let Some(host) = tracker_host(rule) {
            let into = if rule.exception {
                &mut self.freed
            } else {
                &mut self.blocked
            };
            into.insert(host.to_owned());
        }
        let o = &rule.options;
        let whole_host = rule.exception
            && o.domains.is_empty()
            && o.to.is_empty()
            && o.denyallow.is_empty()
            && o.methods.is_empty()
            && o.header.is_none()
            && o.action.is_none();
        let Some(host) = rule.pattern.pure_hostname().filter(|_| whole_host) else {
            return;
        };
        if o.cname {
            self.uncloaked.insert(host.to_owned());
        }
        let document = o.types.is_some_and(|t| {
            t.without(ResourceTypes::POPUP | ResourceTypes::SUBDOCUMENT) == ResourceTypes::DOCUMENT
        });
        if document {
            self.documents.insert(host.to_owned());
        }
    }

    fn finish(self) -> Hosts {
        let blocked = self
            .blocked
            .into_iter()
            .filter(|h| !self.freed.contains(h))
            .collect();
        Hosts {
            block: without_subsumed(blocked),
            exempt: without_subsumed(&self.freed | &self.uncloaked),
            documents: without_subsumed(self.documents),
        }
    }
}

/// The host of `||host^` with nothing that narrows where it applies other
/// than `$third-party` and request types: a rule saying "this host is a
/// tracker", or, as an exception, "it is not".
fn tracker_host(rule: &NetworkRule) -> Option<&str> {
    let o = &rule.options;
    let plain = o.domains.is_empty()
        && o.to.is_empty()
        && o.denyallow.is_empty()
        && o.methods.is_empty()
        && o.header.is_none()
        && o.action.is_none()
        && !o.cname
        && o.party != Party::First
        && (!rule.exception || o.types.is_none() && o.party == Party::Any);
    if !plain {
        return None;
    }
    rule.pattern.pure_hostname().filter(|h| h.contains('.'))
}

/// Whether a rule that failed to parse is a cosmetic or scriptlet rule.
fn is_page_rule(text: &str, feature: &str) -> bool {
    feature.starts_with("scriptlet:")
        || feature.starts_with("cosmetic")
        || feature.starts_with("procedural")
        || feature == "html-filtering"
        || ["##", "#@#", "#?#", "#$#", "#%#"]
            .iter()
            .any(|sep| text.contains(sep))
}

/// What a `$badfilter` rule and its twin have in common.
fn badfilter_key(rule: &NetworkRule) -> String {
    let mut twin = rule.clone();
    twin.options.badfilter = false;
    serde_json::to_string(&twin).unwrap_or_default()
}

/// Merges, validates, applies the regex quota, sorts and numbers.
fn finish(drafts: Vec<Draft>, ruleset: &str, report: &mut Report) -> Vec<dnr::Rule> {
    let mut merged = merge(fold_params(drafts));
    merged.sort_by_cached_key(|d| serde_json::to_string(&d_json(d)).unwrap_or_default());
    let mut rules = Vec::with_capacity(merged.len());
    let mut regexes = 0;
    for draft in merged {
        if draft.condition.regex_filter.is_some() {
            regexes += 1;
            if regexes > MAX_REGEX_RULES {
                report.warnings.push(format!(
                    "{ruleset}: regex rule over the {MAX_REGEX_RULES} limit dropped: {:?}",
                    draft.condition.regex_filter
                ));
                continue;
            }
        }
        let rule = dnr::Rule {
            id: u32::try_from(rules.len() + 1).unwrap_or(u32::MAX),
            priority: draft.priority,
            action: draft.action,
            condition: draft.condition,
        };
        match validate::check(&rule) {
            Ok(()) => rules.push(rule),
            // A translation bug. Dropped rather than shipped, and loud.
            Err(why) => report
                .warnings
                .push(format!("{ruleset}: invalid rule dropped ({why}): {rule:?}")),
        }
    }
    rules
}

fn d_json(d: &Draft) -> (&u32, &dnr::Action, &dnr::Condition) {
    (&d.priority, &d.action, &d.condition)
}

/// The parameters a draft removes, if it is a `$removeparam` rule.
fn params_of(draft: &mut Draft) -> Option<&mut Vec<String>> {
    if draft.action.kind != ActionType::Redirect {
        return None;
    }
    Some(
        &mut draft
            .action
            .redirect
            .as_mut()?
            .transform
            .as_mut()?
            .query_transform
            .as_mut()?
            .remove_params,
    )
}

/// Makes parameter stripping survive Chrome's one-redirect-per-request
/// rule. When two redirect rules match, Chrome applies one, so two
/// `$removeparam` rules that both match a request would each lose the
/// other's parameters. (uBO's lists have `$removeparam=s_cid,document`
/// next to the generic list; on a page load it alone would win, and
/// `utm_source` would stay. A test against real lists caught this.)
///
/// - Generic rules (no condition but request types) are regrouped by type:
///   each type gets one rule removing every parameter any generic rule
///   removes for it. Exact, with nothing broadened.
/// - Rules limited to some sites or URLs take the generic parameters for
///   their types and a higher priority, so whichever wins removes them all.
fn fold_params(drafts: Vec<Draft>) -> Vec<Draft> {
    let is_generic = |c: &dnr::Condition| {
        *c == dnr::Condition {
            resource_types: c.resource_types.clone(),
            ..dnr::Condition::default()
        }
    };
    let types_of = |c: &dnr::Condition| {
        if c.resource_types.is_empty() {
            dnr::ResourceType::SUBRESOURCES.to_vec()
        } else {
            c.resource_types.clone()
        }
    };
    let (mut params, others): (Vec<Draft>, Vec<Draft>) = drafts
        .into_iter()
        .partition(|d| params_of(&mut d.clone()).is_some());
    let mut generic: BTreeMap<dnr::ResourceType, BTreeSet<String>> = BTreeMap::new();
    let mut specific = Vec::new();
    for mut draft in params.drain(..) {
        if is_generic(&draft.condition) {
            let names = params_of(&mut draft)
                .map(std::mem::take)
                .unwrap_or_default();
            for t in types_of(&draft.condition) {
                generic.entry(t).or_default().extend(names.iter().cloned());
            }
        } else {
            specific.push(draft);
        }
    }
    let mut out = others;
    // One generic rule per distinct parameter set, covering its types.
    let mut by_set: BTreeMap<BTreeSet<String>, Vec<dnr::ResourceType>> = BTreeMap::new();
    for (t, names) in &generic {
        by_set.entry(names.clone()).or_default().push(*t);
    }
    for (names, types) in by_set {
        out.push(param_draft(
            priority::MODIFY,
            dnr::Condition {
                resource_types: types,
                ..dnr::Condition::default()
            },
            names,
        ));
    }
    // Specific rules, split by type wherever the generic sets differ.
    for draft in specific {
        let own: BTreeSet<String> = params_of(&mut draft.clone())
            .map(|p| p.iter().cloned().collect())
            .unwrap_or_default();
        let mut by_set: BTreeMap<BTreeSet<String>, Vec<dnr::ResourceType>> = BTreeMap::new();
        for t in types_of(&draft.condition) {
            let mut names = own.clone();
            names.extend(generic.get(&t).into_iter().flatten().cloned());
            by_set.entry(names).or_default().push(t);
        }
        for (names, types) in by_set {
            let condition = dnr::Condition {
                resource_types: types,
                ..draft.condition.clone()
            };
            out.push(param_draft(priority::MODIFY_SPECIFIC, condition, names));
        }
    }
    out
}

fn param_draft(priority: u32, condition: dnr::Condition, names: BTreeSet<String>) -> Draft {
    Draft {
        priority,
        action: dnr::Action {
            redirect: Some(dnr::Redirect {
                transform: Some(dnr::UrlTransform {
                    query_transform: Some(dnr::QueryTransform {
                        remove_params: names.into_iter().collect(),
                    }),
                    ..dnr::UrlTransform::default()
                }),
                ..dnr::Redirect::default()
            }),
            ..dnr::Action::of(ActionType::Redirect)
        },
        condition,
    }
}

/// Merges drafts that differ only in their request domains, and parameter
/// rules that differ only in the parameters they remove.
fn merge(drafts: Vec<Draft>) -> Vec<Draft> {
    let mut by_domains: HashMap<Draft, BTreeSet<String>> = HashMap::new();
    let mut by_params: HashMap<Draft, BTreeSet<String>> = HashMap::new();
    let mut out = Vec::new();
    for mut draft in drafts {
        if !draft.condition.request_domains.is_empty() {
            let domains = std::mem::take(&mut draft.condition.request_domains);
            by_domains.entry(draft).or_default().extend(domains);
            continue;
        }
        let params = draft
            .action
            .redirect
            .as_mut()
            .and_then(|r| r.transform.as_mut())
            .and_then(|t| t.query_transform.as_mut())
            .map(|q| std::mem::take(&mut q.remove_params));
        match params {
            Some(params) => by_params.entry(draft).or_default().extend(params),
            None => out.push(draft),
        }
    }
    for (mut draft, domains) in by_domains {
        draft.condition.request_domains = without_subsumed(domains);
        out.push(draft);
    }
    for (mut draft, params) in by_params {
        if let Some(q) = draft
            .action
            .redirect
            .as_mut()
            .and_then(|r| r.transform.as_mut())
            .and_then(|t| t.query_transform.as_mut())
        {
            q.remove_params = params.into_iter().collect();
        }
        out.push(draft);
    }
    // Two identical rules from different lists are one rule.
    let mut seen = HashSet::new();
    out.retain(|d| seen.insert(d.clone()));
    out
}

/// `requestDomains` covers subdomains, so `a.ads.example` adds nothing
/// next to `ads.example`.
fn without_subsumed(domains: BTreeSet<String>) -> Vec<String> {
    let covered = |d: &str| {
        let mut rest = d;
        while let Some((_, parent)) = rest.split_once('.') {
            if domains.contains(parent) {
                return true;
            }
            rest = parent;
        }
        false
    };
    domains.iter().filter(|d| !covered(d)).cloned().collect()
}

/// The resolver's domain set, from the same lists read for DNS (`!#if`
/// against the DNS environment).
fn dns_set(lists: &[ListInput], report: &mut Report) -> DnsSet {
    let env = Env::dns();
    let mut block = BTreeSet::new();
    let mut allow = BTreeSet::new();
    let mut cancel = BTreeSet::new();
    let mut counts = vec![0; lists.len()];
    for (index, list) in lists.iter().enumerate() {
        for (line_no, line) in Lines::new(&list.text, &env) {
            let Line::Text(text) = line else {
                continue;
            };
            if is_comment(&text) {
                continue;
            }
            match parse_dns_line(&text, DnsFormat::Auto, DnsAction::Block) {
                Ok(rules) => {
                    for rule in rules {
                        let name = match rule.scope {
                            Scope::Subtree => rule.domain.to_string(),
                            Scope::Subdomains => format!("*.{}", rule.domain),
                        };
                        if rule.badfilter {
                            cancel
                                .insert((rule.action == DnsAction::Allow, rule.domain.to_string()));
                            continue;
                        }
                        counts[index] += 1;
                        report.dns.translated += 1;
                        match rule.action {
                            DnsAction::Block => block.insert(name),
                            DnsAction::Allow => allow.insert(name),
                        };
                    }
                }
                Err(e) => report.dns.reject(
                    &list.name,
                    line_no,
                    &text,
                    e.feature().to_owned(),
                    e.to_string(),
                ),
            }
        }
    }
    let keep = |allowing: bool, name: &String| {
        !cancel.contains(&(allowing, name.trim_start_matches("*.").to_owned()))
    };
    for (lr, count) in report.lists.iter_mut().zip(counts) {
        lr.dns_entries = count;
    }
    DnsSet {
        block: block.into_iter().filter(|n| keep(false, n)).collect(),
        allow: allow.into_iter().filter(|n| keep(true, n)).collect(),
    }
}

/// Whether any rule in the rulesets redirects to `path`.
pub fn uses_resource(rulesets: &[Ruleset], path: &str) -> bool {
    rulesets.iter().flat_map(|r| &r.rules).any(|rule| {
        rule.action.kind == ActionType::Redirect
            && rule
                .action
                .redirect
                .as_ref()
                .and_then(|r| r.extension_path.as_deref())
                == Some(path)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(name: &str, ruleset: &str, text: &str) -> ListInput {
        ListInput {
            name: name.into(),
            ruleset: ruleset.into(),
            text: text.into(),
        }
    }

    fn rules_json(c: &Compiled, id: &str) -> Vec<serde_json::Value> {
        c.rulesets
            .iter()
            .find(|r| r.id == id)
            .unwrap()
            .rules
            .iter()
            .map(|r| serde_json::to_value(r).unwrap())
            .collect()
    }

    #[test]
    fn host_rules_merge_into_one() {
        let c = compile(
            &[
                list(
                    "a",
                    "ads",
                    "||a.example^\n||b.example^\n||x.b.example^\n||c.example^$script\n",
                ),
                list("b", "ads", "||d.example^\n||a.example^\n"),
            ],
            None,
        );
        let rules = rules_json(&c, "ads");
        assert_eq!(rules.len(), 2, "{rules:#?}");
        let plain = rules
            .iter()
            .find(|r| r["condition"].get("resourceTypes").is_none())
            .unwrap();
        assert_eq!(
            plain["condition"]["requestDomains"],
            serde_json::json!(["a.example", "b.example", "d.example"])
        );
        assert_eq!(c.report.chrome.translated, 6);
        assert_eq!(c.report.rulesets[0].source_rules, 6);
        // IDs are 1..=n.
        let ids: Vec<_> = rules.iter().map(|r| r["id"].as_u64().unwrap()).collect();
        assert_eq!(ids, [1, 2]);
    }

    #[test]
    fn parameters_go_to_their_own_ruleset_and_merge() {
        let c = compile(
            &[
                list("ads", "ads", "||ads.example^\n$removeparam=fbclid\n"),
                list(
                    "params",
                    "params",
                    "$removeparam=gclid\n$removeparam=utm_source\n",
                ),
            ],
            Some("params"),
        );
        assert_eq!(rules_json(&c, "ads").len(), 1);
        let params = rules_json(&c, "params");
        assert_eq!(params.len(), 1, "{params:#?}");
        assert_eq!(
            params[0]["action"]["redirect"]["transform"]["queryTransform"]["removeParams"],
            serde_json::json!(["fbclid", "gclid", "utm_source"])
        );
    }

    #[test]
    fn parameter_rules_survive_one_redirect_per_request() {
        let c = compile(
            &[list(
                "params",
                "params",
                "$removeparam=utm_source\n$removeparam=s_cid,document\n||shop.example^$removeparam=ref_id\n",
            )],
            Some("params"),
        );
        let rules = rules_json(&c, "params");
        let find = |types: serde_json::Value, specific: bool| {
            rules
                .iter()
                .find(|r| {
                    r["condition"]["resourceTypes"] == types
                        && r["condition"].get("requestDomains").is_some() == specific
                })
                .unwrap_or_else(|| panic!("no rule for {types} in {rules:#?}"))
                ["action"]["redirect"]["transform"]["queryTransform"]["removeParams"]
                .clone()
        };
        // A page load gets one rule that removes both generic parameters.
        assert_eq!(
            find(serde_json::json!(["main_frame"]), false),
            serde_json::json!(["s_cid", "utm_source"])
        );
        assert_eq!(
            find(
                serde_json::json!(["sub_frame", "xmlhttprequest", "ping"]),
                false
            ),
            serde_json::json!(["utm_source"])
        );
        // The site's own rule outranks them and removes theirs too.
        assert_eq!(
            find(serde_json::json!(["main_frame"]), true),
            serde_json::json!(["ref_id", "s_cid", "utm_source"])
        );
        let specific = rules
            .iter()
            .find(|r| r["condition"].get("requestDomains").is_some())
            .unwrap();
        assert_eq!(specific["priority"], 2);
    }

    #[test]
    fn badfilter_cancels_across_lists() {
        let c = compile(
            &[
                list("a", "ads", "||gone.example/ads.js\n||kept.example/ads.js\n"),
                list("b", "ads", "||gone.example/ads.js$badfilter\n"),
            ],
            None,
        );
        let rules = rules_json(&c, "ads");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["condition"]["urlFilter"], "||kept.example/ads.js");
        assert_eq!(c.report.badfiltered, 1);
    }

    #[test]
    fn everything_unused_is_reported() {
        let c = compile(
            &[list(
                "a",
                "ads",
                "! comment\n||x.example^$popup,domain=vipbox.*\nexample.com##.ad\nexample.com##+js(set, a, 1)\n||y.example^$frobnicate\n!#if env_firefox\n||ff.example^\n!#endif\nexample.com##+js(no-such-scriptlet)\n",
            )],
            None,
        );
        assert_eq!(c.report.popups.by_feature["domain:entity"], 1);
        assert_eq!(c.report.chrome.by_feature.get("type:popup"), None);
        assert_eq!(c.report.chrome.by_feature["option:unknown"], 1);
        assert_eq!(c.report.page.translated, 2);
        assert_eq!(
            c.report.page.by_feature["scriptlet:unknown"], 1,
            "{:?}",
            c.report.page
        );
        let e = &c.report.popups.entries[0];
        assert_eq!(
            (e.list.as_str(), e.line, e.text.as_str()),
            ("a", 2, "||x.example^$popup,domain=vipbox.*")
        );
        assert_eq!(
            c.report.lists[0].rules, 5,
            "the firefox-only rule is excluded"
        );
        // The firefox-only rule is excluded for Chrome but kept for DNS,
        // whose environment has no firefox token either: both skip it.
        assert!(!c.dns.block.contains(&"ff.example".to_owned()));
    }

    #[test]
    fn popup_rules_go_to_the_rules_for_tabs() {
        let c = compile(
            &[list(
                "a",
                "ads",
                "||pop1.example^$popup\n||pop2.example^$popup\n@@||ok.example^$popup\n||both.example^$doc,popup\n||gone.example^$popup\n||gone.example^$popup,badfilter\n",
            )],
            None,
        );
        // Only the page-load half of `$doc,popup` is a DNR rule, and it
        // lost nothing: its popup half is a rule for tabs.
        let ads = &c.rulesets[0].rules;
        assert_eq!(ads.len(), 1);
        assert_eq!(ads[0].condition.request_domains, ["both.example"]);
        assert_eq!(c.report.chrome.rejected, 0);
        assert_eq!(c.report.chrome.narrowed, 0);

        assert_eq!(c.popups.len(), 1);
        let popups = &c.popups[0];
        assert_eq!(popups.id, "ads");
        // Plain host rules merge, as request rules do.
        let kinds: Vec<_> = popups.rules.iter().map(|r| r.action.kind).collect();
        assert_eq!(kinds.len(), 2, "{:?}", popups.rules);
        let block = popups
            .rules
            .iter()
            .find(|r| r.action.kind == ActionType::Block)
            .expect("a block rule");
        assert_eq!(
            block.condition.request_domains,
            ["both.example", "pop1.example", "pop2.example"]
        );
        assert_eq!(c.report.popups.translated, 4);
        assert_eq!(c.report.badfiltered, 1);
    }

    #[test]
    fn output_is_deterministic() {
        let lists = [
            list(
                "a",
                "ads",
                "||a.example^\n||b.example/x\n@@||c.example^$script\n||d.example^$third-party\n",
            ),
            list("b", "privacy", "||t.example^\n/track/*$image\n"),
        ];
        let one = compile(&lists, None);
        let two = compile(&lists, None);
        assert_eq!(one.rulesets, two.rulesets);
        assert_eq!(one.rulesets.len(), 2);
    }

    #[test]
    fn dns_set() {
        let c = compile(
            &[list(
                "a",
                "ads",
                "||ads.example^\n@@||ok.ads.example^\n||page.example/path\n0.0.0.0 hosts.example\n||gone.example^\n||gone.example^$badfilter\n",
            )],
            None,
        );
        assert_eq!(c.dns.block, ["ads.example", "hosts.example"]);
        assert_eq!(c.dns.allow, ["ok.ads.example"]);
        assert_eq!(c.report.dns.by_feature["dns:not-hostname"], 1);
    }

    #[test]
    fn tracker_hosts() {
        let c = compile(
            &[
                list(
                    "privacy",
                    "privacy",
                    "||t.example^$third-party\n||sub.t.example^\n||px.example^$image\n||own.example^$1p\n||path.example/x.gif\n||site.example^$domain=a.example\n||freed.example^\n",
                ),
                list(
                    "fixes",
                    "privacy",
                    "@@||freed.example^\n@@||px.example^$domain=b.example\n",
                ),
            ],
            None,
        );
        assert_eq!(c.hosts["privacy"].block, ["px.example", "t.example"]);
        assert_eq!(c.hosts["privacy"].exempt, ["freed.example"]);
    }

    #[test]
    fn hosts_exempt_from_uncloaking() {
        let c = compile(
            &[list(
                "unbreak",
                "unbreak",
                "@@||cdn.example^$cname\n@@||shop.example^$document\n@@||a.shop.example^$document\n@@||site.example^$document,domain=x.example\n@@||own.example^$cname,domain=y.example\n",
            )],
            None,
        );
        let hosts = &c.hosts["unbreak"];
        assert!(hosts.block.is_empty());
        assert_eq!(hosts.exempt, ["cdn.example"]);
        assert_eq!(hosts.documents, ["shop.example"]);
    }

    #[test]
    fn subsumed_domains_are_dropped() {
        let set: BTreeSet<String> = ["a.example", "x.a.example", "y.x.a.example", "b.example"]
            .map(String::from)
            .into();
        assert_eq!(without_subsumed(set), ["a.example", "b.example"]);
    }
}
