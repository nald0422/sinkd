//! One filter rule → Chrome declarativeNetRequest, or the reason it can't be.
//!
//! The rule of thumb is the parser's: never broaden. A rule that DNR cannot
//! express exactly is reported, not approximated with a wider match. The
//! one narrowing allowed is dropping request types DNR has no name for
//! (`popup`, `webrtc`) from a rule that has others; the rest of the rule
//! still applies exactly, and the drop is noted in the report.

use sinkd_filters::network::{
    Action as FilterAction, Anchor, ParamMatch, Party, ResourceTypes, StrictParty,
};
use sinkd_filters::{DomainSpec, HostPattern, NetworkRule, ResponseHeaderRule};

use crate::dnr::{
    Action, ActionType, Condition, DomainType, HeaderInfo, HeaderOperation, Method, QueryTransform,
    Redirect, ResourceType, UrlTransform,
};
use crate::resources;

/// Rule priorities. When rules of different priorities match, the highest
/// wins; this layout reproduces uBlock Origin's precedence.
pub mod priority {
    /// `$removeparam` and header edits: everything above cancels them.
    pub const MODIFY: u32 = 1;
    /// `$removeparam` limited to some sites or URLs. Chrome applies one
    /// redirect per request, so these outrank the generic ones and carry
    /// their parameters too (see `compile::fold_params`).
    pub const MODIFY_SPECIFIC: u32 = 2;
    /// `@@…$removeparam` (signed URLs, say) and other exceptions to
    /// modifying rules: they cancel the two above only, never a block.
    pub const MODIFY_EXCEPTION: u32 = 3;
    pub const BLOCK: u32 = 10;
    /// Plus the rule's own `$redirect=name:N` priority, 0–9. A redirect
    /// beats a plain block, as in uBO.
    pub const REDIRECT: u32 = 20;
    /// `@@…$redirect`: the request is blocked instead of redirected.
    pub const REDIRECT_EXCEPTION: u32 = 30;
    /// `@@` exceptions, including `@@…$document` (allowAllRequests).
    pub const ALLOW: u32 = 40;
    pub const IMPORTANT_BLOCK: u32 = 50;
    pub const IMPORTANT_REDIRECT: u32 = 60;
    pub const IMPORTANT_ALLOW: u32 = 70;
    /// Reserved for the extension's own switches (sites turned off).
    pub const USER: u32 = 1_000;
}

/// Which switchable feature a translated rule belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    /// Blocking, redirects, exceptions and header rules: they stay in the
    /// ruleset of the list they came from.
    Lists,
    /// `$removeparam`: the tracking-parameter ruleset.
    Params,
}

/// A DNR rule before it has an ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Draft {
    pub priority: u32,
    pub action: Action,
    pub condition: Condition,
}

/// A translated rule.
#[derive(Debug, Clone, PartialEq)]
pub struct Translated {
    pub draft: Draft,
    pub feature: Feature,
    /// Parts dropped because DNR cannot express them (`type:popup`).
    pub narrowed: Vec<&'static str>,
}

/// Why a rule produced no DNR rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skip {
    /// DNR cannot express it. `feature` groups the report.
    Rejected { feature: String, reason: String },
    /// It is for another target: `cosmetic` (the cosmetic index, M6) or
    /// `dns` (`$cname`, for the resolver).
    OtherTarget(&'static str),
}

fn reject(feature: impl Into<String>, reason: impl Into<String>) -> Skip {
    Skip::Rejected {
        feature: feature.into(),
        reason: reason.into(),
    }
}

/// Request types a parameter-stripping rule with no type option applies to:
/// navigations, where shared links carry tracking parameters, and the
/// background requests that report them.
const PARAM_TYPES: [ResourceType; 4] = [
    ResourceType::MainFrame,
    ResourceType::SubFrame,
    ResourceType::Xmlhttprequest,
    ResourceType::Ping,
];

/// Documents, for header rules (`$csp`, `$permissions`).
const DOCUMENT_TYPES: [ResourceType; 2] = [ResourceType::MainFrame, ResourceType::SubFrame];

/// Response headers `##^responseheader()` may remove, as in uBO: removing
/// others (CSP, CORS) would weaken a page's security.
const REMOVABLE_RESPONSE_HEADERS: [&str; 4] = ["location", "refresh", "report-to", "set-cookie"];

pub fn translate_network(rule: &NetworkRule) -> Result<Translated, Skip> {
    let o = &rule.options;
    if o.page.genericblock {
        return Err(reject(
            "option:genericblock",
            "DNR cannot tell generic block rules from specific ones at match time",
        ));
    }
    if o.page.elemhide || o.page.generichide || o.page.specifichide {
        return Err(Skip::OtherTarget("cosmetic"));
    }
    if o.cname {
        return Err(Skip::OtherTarget("dns"));
    }
    if o.header.is_some() {
        return Err(reject(
            "option:header",
            "matching on response headers is not translated yet",
        ));
    }
    match o.strict_party {
        StrictParty::Any => {}
        StrictParty::SameHost => {
            return Err(reject(
                "option:strict1p",
                "DNR compares parties by site, not by host",
            ));
        }
        StrictParty::OtherHost => {
            return Err(reject(
                "option:strict3p",
                "DNR compares parties by site, not by host",
            ));
        }
    }

    let mut narrowed = Vec::new();
    let types = o.types.unwrap_or(ResourceTypes::SUBRESOURCES);
    let dnr_types = resource_types(types);
    if types.intersects(ResourceTypes::POPUP) {
        narrowed.push("type:popup");
    }
    // WebRTC comes along with every broad set (no type option, `$all`,
    // `$~script`), and those always include `other`. Only a rule that lists
    // `webrtc` itself loses something.
    if types.intersects(ResourceTypes::WEBRTC) && !types.intersects(ResourceTypes::OTHER) {
        narrowed.push("type:webrtc");
    }
    if dnr_types.is_empty() {
        let feature = narrowed.first().copied().unwrap_or("type:none");
        return Err(reject(feature, "DNR has no such request type"));
    }
    let document_only = types.without(ResourceTypes::POPUP) == ResourceTypes::DOCUMENT;

    let mut condition = Condition::default();
    pattern(rule, &mut condition)?;
    let (include, exclude) = domains(&o.domains)?;
    if document_only && !(include.is_empty() && exclude.is_empty()) {
        return Err(reject(
            "option:document+domain",
            "for a page, $domain names the page itself; not translated",
        ));
    }
    condition.initiator_domains = include;
    condition.excluded_initiator_domains = exclude;
    let (to, not_to) = domains(&o.to)?;
    condition.request_domains.extend(to);
    condition.excluded_request_domains.extend(not_to);
    let (denyallow, negated) = domains(&o.denyallow)?;
    if !negated.is_empty() {
        return Err(reject("option:denyallow", "negated $denyallow entries"));
    }
    condition.excluded_request_domains.extend(denyallow);
    for m in &o.methods {
        let method = Method::parse(&m.method)
            .ok_or_else(|| reject("option:method", format!("DNR has no method {}", m.method)))?;
        if m.negated {
            condition.excluded_request_methods.push(method);
        } else {
            condition.request_methods.push(method);
        }
    }
    if !condition.request_methods.is_empty() {
        // `$method=get|~post` means "GET"; the negation adds nothing.
        condition.excluded_request_methods.clear();
    }
    condition.domain_type = match o.party {
        Party::Any => None,
        Party::First => Some(DomainType::FirstParty),
        Party::Third => Some(DomainType::ThirdParty),
    };
    if o.match_case && (condition.url_filter.is_some() || condition.regex_filter.is_some()) {
        condition.is_url_filter_case_sensitive = Some(true);
    }
    // A rule without `resourceTypes` matches every subresource, which is
    // also what a filter rule without type options means.
    let explicit_types = |condition: &mut Condition| {
        if dnr_types.as_slice() != ResourceType::SUBRESOURCES {
            condition.resource_types = dnr_types.clone();
        }
    };

    let important = o.important;
    let (priority, action, feature) = match (&o.action, rule.exception) {
        (None, false) => {
            explicit_types(&mut condition);
            let p = if important {
                priority::IMPORTANT_BLOCK
            } else {
                priority::BLOCK
            };
            (p, Action::of(ActionType::Block), Feature::Lists)
        }
        (None, true) => {
            let p = if important {
                priority::IMPORTANT_ALLOW
            } else {
                priority::ALLOW
            };
            if types.without(ResourceTypes::POPUP | ResourceTypes::SUBDOCUMENT)
                == ResourceTypes::DOCUMENT
            {
                // `@@…$document`: everything in the page and its frames.
                condition.resource_types = DOCUMENT_TYPES.to_vec();
                (p, Action::of(ActionType::AllowAllRequests), Feature::Lists)
            } else {
                explicit_types(&mut condition);
                (p, Action::of(ActionType::Allow), Feature::Lists)
            }
        }
        (
            Some(FilterAction::Redirect {
                rule_only: true, ..
            }),
            _,
        ) => {
            return Err(reject(
                "option:redirect-rule",
                "DNR cannot redirect only the requests another rule blocks",
            ));
        }
        (
            Some(FilterAction::Redirect {
                resource,
                priority: rp,
                ..
            }),
            false,
        ) => {
            let found = resources::find(resource).ok_or_else(|| {
                reject(
                    "redirect:unknown-resource",
                    format!("no bundled resource named {resource}"),
                )
            })?;
            explicit_types(&mut condition);
            let base = if important {
                priority::IMPORTANT_REDIRECT
            } else {
                priority::REDIRECT
            };
            let action = Action {
                redirect: Some(Redirect {
                    extension_path: Some(found.extension_path()),
                    ..Redirect::default()
                }),
                ..Action::of(ActionType::Redirect)
            };
            (base + (*rp).clamp(0, 9) as u32, action, Feature::Lists)
        }
        (Some(FilterAction::Redirect { resource, .. }), true) => {
            if !resource.is_empty() && resources::find(resource).is_none() {
                return Err(reject(
                    "redirect:unknown-resource",
                    format!("no bundled resource named {resource}"),
                ));
            }
            explicit_types(&mut condition);
            (
                priority::REDIRECT_EXCEPTION,
                Action::of(ActionType::Block),
                Feature::Lists,
            )
        }
        (Some(FilterAction::RemoveParam(param)), false) => {
            let transform = match param {
                ParamMatch::All => UrlTransform {
                    query: Some(String::new()),
                    ..UrlTransform::default()
                },
                ParamMatch::Name {
                    name,
                    negated: false,
                } => UrlTransform {
                    query_transform: Some(QueryTransform {
                        remove_params: vec![name.clone()],
                    }),
                    ..UrlTransform::default()
                },
                ParamMatch::Name { negated: true, .. } => {
                    return Err(reject(
                        "removeparam:negated",
                        "DNR can remove named parameters, not keep them",
                    ));
                }
                ParamMatch::Regex { .. } => {
                    return Err(reject(
                        "removeparam:regex",
                        "DNR removes parameters by exact name only",
                    ));
                }
            };
            if o.types.is_some() {
                condition.resource_types = dnr_types.clone();
            } else {
                condition.resource_types = PARAM_TYPES.to_vec();
            }
            let action = Action {
                redirect: Some(Redirect {
                    transform: Some(transform),
                    ..Redirect::default()
                }),
                ..Action::of(ActionType::Redirect)
            };
            (priority::MODIFY, action, Feature::Params)
        }
        (Some(FilterAction::RemoveParam(param)), true) => {
            // DNR cannot spare one parameter, so an exception for a named
            // one spares them all on those URLs: less stripping, never less
            // blocking.
            if !matches!(param, ParamMatch::All) {
                narrowed.push("removeparam:all-parameters");
            }
            condition.resource_types = match o.types {
                Some(_) => dnr_types.clone(),
                None => PARAM_TYPES.to_vec(),
            };
            (
                priority::MODIFY_EXCEPTION,
                Action::of(ActionType::Allow),
                Feature::Params,
            )
        }
        (Some(FilterAction::Csp(Some(policy))), false) => {
            header_rule(&mut condition, &o.types, &dnr_types);
            let action = append_response("content-security-policy", policy);
            (priority::MODIFY, action, Feature::Lists)
        }
        (Some(FilterAction::Permissions(Some(policy))), false) => {
            header_rule(&mut condition, &o.types, &dnr_types);
            let action = append_response("permissions-policy", policy);
            (priority::MODIFY, action, Feature::Lists)
        }
        (Some(FilterAction::Csp(_) | FilterAction::Permissions(_)), true) => {
            header_rule(&mut condition, &o.types, &dnr_types);
            (
                priority::MODIFY_EXCEPTION,
                Action::of(ActionType::Allow),
                Feature::Lists,
            )
        }
        (Some(FilterAction::Csp(None) | FilterAction::Permissions(None)), false) => {
            // The parser refuses these; nothing to translate.
            return Err(reject("option:csp", "$csp needs a value"));
        }
        (Some(FilterAction::RemoveHeader { name, request }), false) => {
            if o.types.is_some() {
                condition.resource_types = dnr_types.clone();
            } else {
                condition.resource_types = all_types();
            }
            let header = vec![HeaderInfo {
                header: name.clone(),
                operation: HeaderOperation::Remove,
                value: None,
            }];
            let mut action = Action::of(ActionType::ModifyHeaders);
            if *request {
                action.request_headers = header;
            } else {
                action.response_headers = header;
            }
            (priority::MODIFY, action, Feature::Lists)
        }
        (Some(FilterAction::RemoveHeader { .. }), true) => {
            condition.resource_types = match o.types {
                Some(_) => dnr_types.clone(),
                None => all_types(),
            };
            (
                priority::MODIFY_EXCEPTION,
                Action::of(ActionType::Allow),
                Feature::Lists,
            )
        }
        (Some(FilterAction::UrlSkip { .. }), _) => {
            return Err(reject(
                "option:urlskip",
                "needs URL decoding, which DNR cannot do",
            ));
        }
        (Some(FilterAction::Cookie(_)), _) => {
            return Err(reject(
                "option:cookie",
                "cookie rules arrive with milestone 7",
            ));
        }
    };
    Ok(Translated {
        draft: Draft {
            priority,
            action,
            condition,
        },
        feature,
        narrowed,
    })
}

/// A `$popup` rule as a rule for the tabs pages open, or `None` if the rule
/// has nothing to say about them.
///
/// DNR cannot act on a tab a page opens, so the extension checks such tabs
/// itself, against these, and closes the ones they block. They are kept in
/// DNR's shape so one matcher reads both, and the pattern translates as it
/// does for a request. `$domain` names the page that opened the tab, which
/// is the navigation's initiator; `$third-party` compares the two. A tab is
/// closed or left alone, so only blocks and exceptions mean anything.
pub fn translate_popup(rule: &NetworkRule) -> Option<Result<Draft, Skip>> {
    let o = &rule.options;
    if !o.types.is_some_and(|t| t.intersects(ResourceTypes::POPUP)) {
        return None;
    }
    Some(popup_draft(rule))
}

fn popup_draft(rule: &NetworkRule) -> Result<Draft, Skip> {
    let o = &rule.options;
    if o.action.is_some() {
        return Err(reject(
            "popup:action",
            "a tab is closed or left alone; nothing else applies to it",
        ));
    }
    if o.header.is_some() || !o.methods.is_empty() {
        return Err(reject(
            "popup:option",
            "a new tab has no response headers or method to match yet",
        ));
    }
    if o.strict_party != StrictParty::Any {
        return Err(reject(
            "popup:strict-party",
            "parties are compared by site, not by host",
        ));
    }
    let mut condition = Condition {
        resource_types: vec![ResourceType::MainFrame],
        ..Condition::default()
    };
    pattern(rule, &mut condition)?;
    let (include, exclude) = domains(&o.domains)?;
    condition.initiator_domains = include;
    condition.excluded_initiator_domains = exclude;
    let (to, not_to) = domains(&o.to)?;
    condition.request_domains.extend(to);
    condition.excluded_request_domains.extend(not_to);
    let (denyallow, negated) = domains(&o.denyallow)?;
    if !negated.is_empty() {
        return Err(reject("option:denyallow", "negated $denyallow entries"));
    }
    condition.excluded_request_domains.extend(denyallow);
    condition.domain_type = match o.party {
        Party::Any => None,
        Party::First => Some(DomainType::FirstParty),
        Party::Third => Some(DomainType::ThirdParty),
    };
    if o.match_case && (condition.url_filter.is_some() || condition.regex_filter.is_some()) {
        condition.is_url_filter_case_sensitive = Some(true);
    }
    let (priority, kind) = match (rule.exception, o.important) {
        (false, false) => (priority::BLOCK, ActionType::Block),
        (false, true) => (priority::IMPORTANT_BLOCK, ActionType::Block),
        (true, false) => (priority::ALLOW, ActionType::Allow),
        (true, true) => (priority::IMPORTANT_ALLOW, ActionType::Allow),
    };
    Ok(Draft {
        priority,
        action: Action::of(kind),
        condition,
    })
}

/// `example.com##^responseheader(refresh)`: remove a header from the page's
/// response.
pub fn translate_response_header(rule: &ResponseHeaderRule) -> Result<Translated, Skip> {
    if rule.exception {
        return Err(reject(
            "responseheader:exception",
            "a DNR exception would also cancel blocking",
        ));
    }
    if !REMOVABLE_RESPONSE_HEADERS.contains(&rule.header.as_str()) {
        return Err(reject(
            "responseheader:unsafe",
            format!("removing {} is not allowed", rule.header),
        ));
    }
    let (include, exclude) = domains(&rule.domains)?;
    if include.is_empty() {
        return Err(reject("responseheader:generic", "needs at least one site"));
    }
    let mut action = Action::of(ActionType::ModifyHeaders);
    action.response_headers = vec![HeaderInfo {
        header: rule.header.clone(),
        operation: HeaderOperation::Remove,
        value: None,
    }];
    Ok(Translated {
        draft: Draft {
            priority: priority::MODIFY,
            action,
            condition: Condition {
                request_domains: include,
                excluded_request_domains: exclude,
                resource_types: DOCUMENT_TYPES.to_vec(),
                ..Condition::default()
            },
        },
        feature: Feature::Lists,
        narrowed: Vec::new(),
    })
}

fn append_response(header: &str, value: &str) -> Action {
    let mut action = Action::of(ActionType::ModifyHeaders);
    action.response_headers = vec![HeaderInfo {
        header: header.to_owned(),
        operation: HeaderOperation::Append,
        value: Some(value.to_owned()),
    }];
    action
}

/// Header rules apply to documents unless the rule names types.
fn header_rule(condition: &mut Condition, types: &Option<ResourceTypes>, dnr: &[ResourceType]) {
    condition.resource_types = match types {
        Some(_) => dnr.to_vec(),
        None => DOCUMENT_TYPES.to_vec(),
    };
}

fn all_types() -> Vec<ResourceType> {
    let mut all = vec![ResourceType::MainFrame];
    all.extend(ResourceType::SUBRESOURCES);
    all
}

/// The DNR types for a set of filter types, in DNR order. `popup` and
/// `webrtc` have no DNR equivalent and are left out, and `other` takes in
/// the types only DNR names. So a rule naming every subresource type is the
/// same as one naming none.
fn resource_types(types: ResourceTypes) -> Vec<ResourceType> {
    let mut out = Vec::new();
    if types.contains(ResourceTypes::DOCUMENT) {
        out.push(ResourceType::MainFrame);
    }
    if types.contains(ResourceTypes::SUBRESOURCES) {
        out.extend(ResourceType::SUBRESOURCES);
        return out;
    }
    let map = [
        (ResourceTypes::SUBDOCUMENT, ResourceType::SubFrame),
        (ResourceTypes::STYLESHEET, ResourceType::Stylesheet),
        (ResourceTypes::SCRIPT, ResourceType::Script),
        (ResourceTypes::IMAGE, ResourceType::Image),
        (ResourceTypes::FONT, ResourceType::Font),
        (ResourceTypes::OBJECT, ResourceType::Object),
        (ResourceTypes::XMLHTTPREQUEST, ResourceType::Xmlhttprequest),
        (ResourceTypes::PING, ResourceType::Ping),
        (ResourceTypes::MEDIA, ResourceType::Media),
        (ResourceTypes::WEBSOCKET, ResourceType::Websocket),
    ];
    for (filter, dnr) in map {
        if types.contains(filter) {
            out.push(dnr);
        }
    }
    // `other` is whatever has no name of its own, which includes the types
    // only DNR names.
    if types.contains(ResourceTypes::OTHER) {
        out.extend([
            ResourceType::CspReport,
            ResourceType::Webtransport,
            ResourceType::Webbundle,
            ResourceType::Other,
        ]);
    }
    out.sort_unstable();
    out
}

/// Sets the URL part of `condition` from the rule's pattern.
fn pattern(rule: &NetworkRule, condition: &mut Condition) -> Result<(), Skip> {
    use sinkd_filters::network::UrlPattern;
    match &rule.pattern {
        UrlPattern::Regex { source } => {
            check_regex(source, rule.options.match_case)?;
            condition.regex_filter = Some(source.clone());
        }
        p if p.matches_everything() => {}
        p => {
            let o = &rule.options;
            // `||host^` is exactly "this host and its subdomains", which is
            // what `requestDomains` means; such rules then merge into one.
            // With `$to` or `$denyallow` the request domains are already
            // spoken for, so the host stays in the URL filter.
            if let Some(host) = p.pure_hostname()
                && o.to.is_empty()
                && o.denyallow.is_empty()
            {
                condition.request_domains.push(host.to_owned());
                return Ok(());
            }
            let UrlPattern::Wildcard {
                anchor,
                body,
                end_anchor,
            } = p
            else {
                return Ok(());
            };
            let mut filter = String::with_capacity(body.len() + 3);
            filter.push_str(match anchor {
                Anchor::None => "",
                Anchor::Start => "|",
                Anchor::Hostname => "||",
            });
            // DNR URL filters are ASCII; URLs arrive percent-encoded.
            for c in body.chars() {
                if c.is_ascii() {
                    filter.push(c);
                } else {
                    let mut buf = [0; 4];
                    for b in c.encode_utf8(&mut buf).bytes() {
                        filter.push_str(&format!("%{b:02X}"));
                    }
                }
            }
            if *end_anchor {
                filter.push('|');
            }
            if filter.starts_with("||*") {
                return Err(reject("pattern:wildcard-host", "DNR refuses ||* filters"));
            }
            if !matches!(filter.as_str(), "" | "|" | "||") {
                condition.url_filter = Some(filter);
            }
        }
    }
    Ok(())
}

/// Chrome compiles `regexFilter` with RE2: no lookaround, no backreferences
/// (regex-syntax accepts the same language), repetition counts up to 1000,
/// and at most 2 KB of compiled program. A rule over that limit does not
/// just fail on its own: in testing, one such rule kept the whole
/// extension from loading. So the program size is estimated
/// ([`regex_cost`]) and anything near the limit is refused.
fn check_regex(source: &str, case_sensitive: bool) -> Result<(), Skip> {
    if !source.is_ascii() {
        return Err(reject("regex:non-ascii", "non-ASCII regular expression"));
    }
    match regex_cost(source, case_sensitive) {
        Err(reason) => Err(reject("regex:unsupported-syntax", reason)),
        Ok(cost) if cost > MAX_REGEX_COST => Err(reject(
            "regex:too-large",
            format!("compiles to about {cost} instructions; Chrome allows about {MAX_REGEX_COST}"),
        )),
        Ok(_) => Ok(()),
    }
}

/// Estimated RE2 instructions Chrome accepts, with a margin. Calibrated
/// against Chrome's own `isRegexSupported` on the 360 regex rules of the
/// default lists and on synthetic patterns: everything Chrome refused
/// scored 115 or more. The end-to-end test re-checks every regex in a
/// build with Chrome itself.
pub const MAX_REGEX_COST: u64 = 100;

/// RE2's limit on `{n,m}`.
const MAX_REPEAT: u32 = 1_000;

/// Estimates how many instructions RE2 compiles `source` into, the
/// quantity Chrome's 2 KB limit bounds. `Err` with a reason if RE2 would
/// not accept the syntax at all.
///
/// The model matches what Chrome's verdicts show: RE2 works on bytes here
/// (`.` is one byte class), and case-insensitive ASCII costs nothing extra
/// (RE2 marks a byte range as case-folding instead of doubling it, so
/// `[a-zA-Z]` is one range). The pattern is parsed as bytes; for a
/// case-insensitive rule, class ranges are folded before they are counted.
pub fn regex_cost(source: &str, case_sensitive: bool) -> Result<u64, String> {
    use regex_syntax::hir::{Class, Hir, HirKind};
    let hir = regex_syntax::ParserBuilder::new()
        .unicode(false)
        .utf8(false)
        .build()
        .parse(source)
        .map_err(|e| {
            e.to_string()
                .lines()
                .last()
                .unwrap_or("unsupported syntax")
                .trim()
                .to_owned()
        })?;
    // One instruction per byte range, joined by splits. In a
    // case-insensitive rule, an upper-case range whose lower-case twin is
    // also in the class costs nothing: RE2 emits one case-folding range.
    let class_cost = |ranges: Vec<(u8, u8)>| -> u64 {
        let mut ranges = ranges;
        if !case_sensitive {
            let all = ranges.clone();
            let covered = |lo: u8, hi: u8| all.iter().any(|&(s, e)| s <= lo && hi <= e);
            ranges.retain(|&(s, e)| {
                let upper = s >= b'A' && e <= b'Z';
                !(upper && covered(s + 32, e + 32))
            });
        }
        (2 * ranges.len()).saturating_sub(1) as u64
    };
    fn cost(hir: &Hir, class_cost: &dyn Fn(Vec<(u8, u8)>) -> u64) -> Result<u64, String> {
        let cost = |h: &Hir| cost(h, class_cost);
        Ok(match hir.kind() {
            HirKind::Empty => 0,
            HirKind::Literal(lit) => lit.0.len() as u64,
            HirKind::Class(Class::Bytes(class)) => class_cost(
                class
                    .ranges()
                    .iter()
                    .map(|r| (r.start(), r.end()))
                    .collect(),
            ),
            HirKind::Class(Class::Unicode(class)) => class_cost(
                class
                    .ranges()
                    .iter()
                    .map(|r| {
                        let byte = |c: char| u8::try_from(u32::from(c)).unwrap_or(u8::MAX);
                        (byte(r.start()), byte(r.end()))
                    })
                    .collect(),
            ),
            HirKind::Look(_) => 1,
            HirKind::Repetition(rep) => {
                if rep.min > MAX_REPEAT || rep.max.is_some_and(|m| m > MAX_REPEAT) {
                    return Err(format!("repetition count over {MAX_REPEAT}"));
                }
                let one = cost(&rep.sub)?;
                let min = u64::from(rep.min);
                match rep.max {
                    // Each optional copy adds a split.
                    Some(max) => min * one + u64::from(max - rep.min) * (one + 1),
                    None => min.max(1) * one + 1,
                }
            }
            // Chrome compiles without captures unless it substitutes.
            HirKind::Capture(cap) => cost(&cap.sub)?,
            HirKind::Concat(subs) => subs.iter().map(cost).sum::<Result<u64, _>>()?,
            HirKind::Alternation(subs) => {
                subs.iter().map(cost).sum::<Result<u64, _>>()? + subs.len() as u64 - 1
            }
        })
    }
    cost(&hir, &class_cost)
}

/// Splits `$domain`-style lists into included and excluded hostnames.
fn domains(specs: &[DomainSpec]) -> Result<(Vec<String>, Vec<String>), Skip> {
    let mut include = Vec::new();
    let mut exclude = Vec::new();
    for spec in specs {
        let host = match &spec.host {
            HostPattern::Domain(d) => d.clone(),
            HostPattern::Ip(std::net::IpAddr::V4(ip)) => ip.to_string(),
            HostPattern::Ip(_) => {
                return Err(reject("domain:ipv6", "IPv6 literals are not translated"));
            }
            HostPattern::Entity(e) => {
                return Err(reject(
                    "domain:entity",
                    format!("{e}.* (any public suffix) has no DNR equivalent"),
                ));
            }
            HostPattern::Regex(_) => {
                return Err(reject("domain:regex", "DNR domain lists take names only"));
            }
        };
        if spec.negated {
            exclude.push(host);
        } else {
            include.push(host);
        }
    }
    Ok((include, exclude))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sinkd_filters::{Rule, parse_rule};

    fn net(line: &str) -> NetworkRule {
        match parse_rule(line).unwrap_or_else(|e| panic!("{line}: {e}")) {
            Rule::Network(n) => n,
            other => panic!("{line}: not a network rule: {other:?}"),
        }
    }

    fn ok(line: &str) -> Translated {
        translate_network(&net(line)).unwrap_or_else(|e| panic!("{line}: {e:?}"))
    }

    fn json(line: &str) -> serde_json::Value {
        let t = ok(line);
        serde_json::json!({
            "priority": t.draft.priority,
            "action": t.draft.action,
            "condition": t.draft.condition,
        })
    }

    fn rejected(line: &str) -> String {
        match translate_network(&net(line)) {
            Err(Skip::Rejected { feature, .. }) => feature,
            other => panic!("{line}: expected a rejection, got {other:?}"),
        }
    }

    #[test]
    fn host_rules_use_request_domains() {
        assert_eq!(
            json("||ads.example^"),
            serde_json::json!({
                "priority": 10,
                "action": {"type": "block"},
                "condition": {"requestDomains": ["ads.example"]}
            })
        );
        // With options, the host still goes in requestDomains.
        assert_eq!(
            json("||ads.example^$script,third-party,domain=a.com|~b.a.com")["condition"],
            serde_json::json!({
                "requestDomains": ["ads.example"],
                "initiatorDomains": ["a.com"],
                "excludedInitiatorDomains": ["b.a.com"],
                "resourceTypes": ["script"],
                "domainType": "thirdParty"
            })
        );
        // With $to, the host is part of the URL filter.
        assert_eq!(
            json("||cdn.example^$to=x.com")["condition"],
            serde_json::json!({"urlFilter": "||cdn.example^", "requestDomains": ["x.com"]})
        );
    }

    #[test]
    fn url_patterns() {
        assert_eq!(
            json("||example.com/ads/*.js|$match-case")["condition"],
            serde_json::json!({"urlFilter": "||example.com/ads/*.js|", "isUrlFilterCaseSensitive": true})
        );
        assert_eq!(
            json("/banner/ads-")["condition"]["urlFilter"],
            "/banner/ads-"
        );
        assert_eq!(
            json("|https://x.example/a")["condition"]["urlFilter"],
            "|https://x.example/a"
        );
        assert_eq!(
            json("||example.com/ä")["condition"]["urlFilter"],
            "||example.com/%C3%A4"
        );
        // A pattern that matches everything has no URL filter.
        assert_eq!(
            json("*$script,domain=a.com")["condition"],
            serde_json::json!({"initiatorDomains": ["a.com"], "resourceTypes": ["script"]})
        );
        assert_eq!(
            json(r"/^https?:\/\/ad\d+\.example\//$image")["condition"]["regexFilter"],
            r"^https?:\/\/ad\d+\.example\/"
        );
    }

    #[test]
    fn regexes_must_be_re2() {
        assert_eq!(
            rejected(r"/^https?:\/\/(?!good)\w+\.ads\./"),
            "regex:unsupported-syntax"
        );
        assert_eq!(rejected(r"/(a)\1/"), "regex:unsupported-syntax");
    }

    #[test]
    fn types() {
        assert_eq!(
            json("||x.example^$~script")["condition"]["resourceTypes"]
                .as_array()
                .unwrap()
                .len(),
            ResourceType::SUBRESOURCES.len() - 1
        );
        assert_eq!(
            json("||x.example^$document")["condition"]["resourceTypes"],
            serde_json::json!(["main_frame"])
        );
        let all = ok("||x.example^$all");
        assert_eq!(all.draft.condition.resource_types.len(), 15);
        assert_eq!(all.narrowed, ["type:popup"]);
        assert!(ok("||x.example^").narrowed.is_empty());
        assert!(ok("||x.example^$~script").narrowed.is_empty());
        assert_eq!(rejected("||x.example^$popup"), "type:popup");
        assert_eq!(rejected("||x.example^$webrtc"), "type:webrtc");
        let mixed = ok("||x.example^$popup,script");
        assert_eq!(mixed.draft.condition.resource_types, [ResourceType::Script]);
        assert_eq!(mixed.narrowed, ["type:popup"]);
    }

    #[test]
    fn exceptions_and_priorities() {
        assert_eq!(json("@@||ok.example^$script")["priority"], 40);
        assert_eq!(json("@@||ok.example^$script")["action"]["type"], "allow");
        let doc = json("@@||ok.example^$document");
        assert_eq!(doc["action"]["type"], "allowAllRequests");
        assert_eq!(
            doc["condition"]["resourceTypes"],
            serde_json::json!(["main_frame", "sub_frame"])
        );
        assert_eq!(json("||x.example^$important")["priority"], 50);
        assert_eq!(json("@@||x.example^$important")["priority"], 70);
        assert_eq!(
            rejected("@@||x.example^$genericblock"),
            "option:genericblock"
        );
        assert_eq!(
            translate_network(&net("@@||x.example^$generichide")),
            Err(Skip::OtherTarget("cosmetic"))
        );
        assert_eq!(rejected("||x.example^$strict3p"), "option:strict3p");
        assert_eq!(rejected("||x.example^$domain=example.*"), "domain:entity");
    }

    #[test]
    fn redirects() {
        let r = json(
            "||www.googletagservices.com/tag/js/gpt.js$script,redirect=googletagservices.com/gpt.js:5",
        );
        assert_eq!(r["priority"], 25);
        assert_eq!(
            r["action"],
            serde_json::json!({"type": "redirect", "redirect": {"extensionPath": "/war/googletagservices_gpt.js"}})
        );
        assert_eq!(
            rejected("||x.example^$script,redirect=noop-1s.mp4"),
            "redirect:unknown-resource"
        );
        assert_eq!(
            rejected("||x.example^$script,redirect-rule=noop.js"),
            "option:redirect-rule"
        );
        // An exception to a redirect blocks instead.
        let e = json("@@||x.example^$script,redirect=noop.js");
        assert_eq!(
            (e["priority"].clone(), e["action"]["type"].clone()),
            (30.into(), "block".into())
        );
    }

    #[test]
    fn parameters_and_headers() {
        let t = ok("$removeparam=fbclid");
        assert_eq!(t.feature, Feature::Params);
        assert_eq!(
            json("$removeparam=fbclid"),
            serde_json::json!({
                "priority": 1,
                "action": {"type": "redirect", "redirect": {"transform": {"queryTransform": {"removeParams": ["fbclid"]}}}},
                "condition": {"resourceTypes": ["main_frame", "sub_frame", "xmlhttprequest", "ping"]}
            })
        );
        assert_eq!(
            json("||x.example^$removeparam")["action"]["redirect"]["transform"],
            serde_json::json!({"query": ""})
        );
        assert_eq!(rejected("$removeparam=/^utm_/"), "removeparam:regex");
        assert_eq!(rejected("$removeparam=~keep"), "removeparam:negated");
        let csp = json("||x.example^$csp=script-src 'self'");
        assert_eq!(
            csp["action"]["responseHeaders"],
            serde_json::json!([{"header": "content-security-policy", "operation": "append", "value": "script-src 'self'"}])
        );
        assert_eq!(
            csp["condition"]["resourceTypes"],
            serde_json::json!(["main_frame", "sub_frame"])
        );
        // Exceptions to modifying rules cancel only modifications.
        let e = json("@@||x.example^$csp");
        assert_eq!(
            (e["priority"].clone(), e["action"]["type"].clone()),
            (3.into(), "allow".into())
        );
        let signed = ok("@@*X-Amz-Signature=$removeparam");
        assert_eq!(signed.feature, Feature::Params);
        assert_eq!(signed.draft.priority, priority::MODIFY_EXCEPTION);
        assert_eq!(
            signed.draft.condition.url_filter.as_deref(),
            Some("X-Amz-Signature=")
        );
        assert_eq!(
            ok("@@||x.example^$removeparam=gclid").narrowed,
            ["removeparam:all-parameters"]
        );
    }

    #[test]
    fn response_header_rules() {
        let Rule::ResponseHeader(r) = parse_rule("example.com##^responseheader(refresh)").unwrap()
        else {
            panic!()
        };
        let t = translate_response_header(&r).unwrap();
        assert_eq!(t.draft.condition.request_domains, ["example.com"]);
        let Rule::ResponseHeader(r) =
            parse_rule("example.com##^responseheader(content-security-policy)").unwrap()
        else {
            panic!()
        };
        assert!(matches!(
            translate_response_header(&r),
            Err(Skip::Rejected { feature, .. }) if feature == "responseheader:unsafe"
        ));
    }

    #[test]
    fn popup_rules_become_rules_for_new_tabs() {
        let popup = |line: &str| translate_popup(&net(line));
        let tab = |line: &str| {
            popup(line)
                .unwrap_or_else(|| panic!("{line}: no popup rule"))
                .unwrap()
        };
        // Requests only: nothing for tabs.
        assert!(popup("||ads.example^").is_none());
        assert!(popup("||ads.example^$script").is_none());

        let d = tab("||pop.example^$popup");
        assert_eq!(d.action.kind, ActionType::Block);
        assert_eq!(d.priority, priority::BLOCK);
        assert_eq!(d.condition.request_domains, ["pop.example"]);
        assert_eq!(d.condition.resource_types, [ResourceType::MainFrame]);

        // `$domain` names the page that opened the tab: the initiator.
        let d = tab("*$popup,third-party,domain=a.example|~b.a.example");
        assert_eq!(d.condition.initiator_domains, ["a.example"]);
        assert_eq!(d.condition.excluded_initiator_domains, ["b.a.example"]);
        assert_eq!(d.condition.domain_type, Some(DomainType::ThirdParty));
        assert_eq!(d.condition.url_filter, None);

        assert_eq!(
            tab("/click?adv=$popup").condition.url_filter.as_deref(),
            Some("/click?adv=")
        );
        let allow = tab("@@||accounts.example^$popup");
        assert_eq!(allow.action.kind, ActionType::Allow);
        assert_eq!(allow.priority, priority::ALLOW);
        assert_eq!(
            tab("||x.example^$popup,important").priority,
            priority::IMPORTANT_BLOCK
        );

        // A page load and a tab: the request rule takes one, this the other.
        assert_eq!(tab("||x.example^$doc,popup").action.kind, ActionType::Block);
        assert!(matches!(
            popup("||x.example^$popup,domain=vipbox.*"),
            Some(Err(Skip::Rejected { feature, .. })) if feature == "domain:entity"
        ));
    }
}
