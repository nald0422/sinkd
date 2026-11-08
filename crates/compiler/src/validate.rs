//! The checks Chrome applies when it loads a static ruleset, and its quotas.
//!
//! Chrome skips an invalid rule with a warning (for unpacked extensions)
//! rather than refusing the ruleset, so a translation bug would surface as
//! a silently missing rule. Every emitted rule passes these checks, which
//! mirror the errors in Chromium's `indexed_rule.cc`.

use std::collections::HashSet;

use crate::dnr::{ActionType, HeaderOperation, ResourceType, Rule};

/// Static rules Chrome guarantees an extension, across its enabled
/// rulesets. Beyond it, rules come from a pool shared by all extensions
/// (`GUARANTEED_MINIMUM_STATIC_RULES`).
pub const GUARANTEED_STATIC_RULES: usize = 30_000;
/// The shared pool's size, the most a single extension can ever get
/// (`GLOBAL_STATIC_RULE_LIMIT`).
pub const GLOBAL_STATIC_RULES: usize = 330_000;
/// Regex rules per ruleset (`MAX_NUMBER_OF_REGEX_RULES`).
pub const MAX_REGEX_RULES: usize = 1_000;
/// Static rulesets per extension, and how many can be enabled at once.
pub const MAX_STATIC_RULESETS: usize = 100;
pub const MAX_ENABLED_STATIC_RULESETS: usize = 50;

/// Why Chrome would skip a rule.
pub fn check(rule: &Rule) -> Result<(), String> {
    let c = &rule.condition;
    let a = &rule.action;
    if rule.id < 1 {
        return Err("id must be at least 1".into());
    }
    if rule.priority < 1 {
        return Err("priority must be at least 1".into());
    }
    if let Some(filter) = &c.url_filter {
        if filter.is_empty() {
            return Err("empty urlFilter".into());
        }
        if !filter.is_ascii() {
            return Err("non-ASCII urlFilter".into());
        }
        if filter.starts_with("||*") {
            return Err("urlFilter starts with ||*".into());
        }
    }
    if c.url_filter.is_some() && c.regex_filter.is_some() {
        return Err("both urlFilter and regexFilter".into());
    }
    if c.regex_filter.as_ref().is_some_and(String::is_empty) {
        return Err("empty regexFilter".into());
    }
    for (name, list) in [
        ("initiatorDomains", &c.initiator_domains),
        ("excludedInitiatorDomains", &c.excluded_initiator_domains),
        ("requestDomains", &c.request_domains),
        ("excludedRequestDomains", &c.excluded_request_domains),
    ] {
        for d in list {
            if d.is_empty() || !d.is_ascii() || d.bytes().any(|b| b.is_ascii_uppercase()) {
                return Err(format!("{name}: {d:?} is not a lowercase ASCII domain"));
            }
            if d.contains(['*', '/', ':']) {
                return Err(format!("{name}: {d:?} is not a plain domain"));
            }
        }
    }
    if !c.resource_types.is_empty() && !c.excluded_resource_types.is_empty() {
        return Err("both resourceTypes and excludedResourceTypes".into());
    }
    let methods: HashSet<_> = c.request_methods.iter().collect();
    if c.excluded_request_methods
        .iter()
        .any(|m| methods.contains(m))
    {
        return Err("a method is both included and excluded".into());
    }
    match a.kind {
        ActionType::AllowAllRequests => {
            if c.resource_types.is_empty()
                || c.resource_types
                    .iter()
                    .any(|t| !matches!(t, ResourceType::MainFrame | ResourceType::SubFrame))
            {
                return Err("allowAllRequests needs resourceTypes of main_frame/sub_frame".into());
            }
        }
        ActionType::Redirect => {
            let Some(r) = &a.redirect else {
                return Err("redirect without a redirect".into());
            };
            let set = [
                r.url.is_some(),
                r.extension_path.is_some(),
                r.transform.is_some(),
                r.regex_substitution.is_some(),
            ];
            if set.iter().filter(|&&s| s).count() != 1 {
                return Err("a redirect needs exactly one target".into());
            }
            if r.extension_path
                .as_ref()
                .is_some_and(|p| !p.starts_with('/'))
            {
                return Err("extensionPath must start with /".into());
            }
            if r.regex_substitution.is_some() && c.regex_filter.is_none() {
                return Err("regexSubstitution needs a regexFilter".into());
            }
            if let Some(t) = &r.transform {
                if let Some(q) = &t.query
                    && !(q.is_empty() || q.starts_with('?'))
                {
                    return Err("transform.query must be empty or start with ?".into());
                }
                if let Some(qt) = &t.query_transform
                    && qt.remove_params.is_empty()
                {
                    return Err("empty queryTransform".into());
                }
            }
        }
        ActionType::ModifyHeaders => {
            if a.request_headers.is_empty() && a.response_headers.is_empty() {
                return Err("modifyHeaders without headers".into());
            }
            for (request, h) in a
                .request_headers
                .iter()
                .map(|h| (true, h))
                .chain(a.response_headers.iter().map(|h| (false, h)))
            {
                let token = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
                if h.header.is_empty() || !h.header.bytes().all(token) {
                    return Err(format!("invalid header name {:?}", h.header));
                }
                match (h.operation, &h.value) {
                    (HeaderOperation::Remove, Some(_)) => {
                        return Err("remove takes no value".into());
                    }
                    (HeaderOperation::Set | HeaderOperation::Append, None) => {
                        return Err("set/append need a value".into());
                    }
                    (HeaderOperation::Append, _) if request => {
                        return Err("append is not allowed on request headers here".into());
                    }
                    _ => {}
                }
            }
        }
        ActionType::Block | ActionType::Allow | ActionType::UpgradeScheme => {
            if a.redirect.is_some()
                || !a.request_headers.is_empty()
                || !a.response_headers.is_empty()
            {
                return Err("extra fields for this action".into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnr::{Action, Condition, HeaderInfo, Redirect};

    fn rule(action: Action, condition: Condition) -> Rule {
        Rule {
            id: 1,
            priority: 1,
            action,
            condition,
        }
    }

    #[test]
    fn catches_what_chrome_rejects() {
        let block = Action::of(ActionType::Block);
        let ok = rule(block.clone(), Condition::default());
        assert!(check(&ok).is_ok());
        let bad = [
            rule(
                block.clone(),
                Condition {
                    url_filter: Some(String::new()),
                    ..Condition::default()
                },
            ),
            rule(
                block.clone(),
                Condition {
                    url_filter: Some("||*x".into()),
                    ..Condition::default()
                },
            ),
            rule(
                block.clone(),
                Condition {
                    url_filter: Some("ä".into()),
                    ..Condition::default()
                },
            ),
            rule(
                block.clone(),
                Condition {
                    request_domains: vec!["Ads.example".into()],
                    ..Condition::default()
                },
            ),
            rule(
                block.clone(),
                Condition {
                    resource_types: vec![ResourceType::Script],
                    excluded_resource_types: vec![ResourceType::Image],
                    ..Condition::default()
                },
            ),
            rule(
                Action::of(ActionType::AllowAllRequests),
                Condition {
                    resource_types: vec![ResourceType::Script],
                    ..Condition::default()
                },
            ),
            rule(Action::of(ActionType::Redirect), Condition::default()),
            rule(
                Action {
                    redirect: Some(Redirect {
                        extension_path: Some("war/x".into()),
                        ..Redirect::default()
                    }),
                    ..Action::of(ActionType::Redirect)
                },
                Condition::default(),
            ),
            rule(Action::of(ActionType::ModifyHeaders), Condition::default()),
            rule(
                Action {
                    response_headers: vec![HeaderInfo {
                        header: "bad header".into(),
                        operation: HeaderOperation::Remove,
                        value: None,
                    }],
                    ..Action::of(ActionType::ModifyHeaders)
                },
                Condition::default(),
            ),
        ];
        for r in bad {
            assert!(check(&r).is_err(), "{r:?}");
        }
    }
}
