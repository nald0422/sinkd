//! Chrome's declarativeNetRequest rule format, as JSON.
//!
//! Field names and values follow the extension API reference
//! (`chrome.declarativeNetRequest.Rule`). Empty lists are left out: Chrome
//! rejects a rule whose `initiatorDomains` or `resourceTypes` is present but
//! empty.

use serde::{Deserialize, Serialize};

/// One rule in a static ruleset.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Rule {
    pub id: u32,
    pub priority: u32,
    pub action: Action,
    pub condition: Condition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ActionType {
    Block,
    Allow,
    AllowAllRequests,
    UpgradeScheme,
    Redirect,
    ModifyHeaders,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Action {
    #[serde(rename = "type")]
    pub kind: ActionType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect: Option<Redirect>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_headers: Vec<HeaderInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response_headers: Vec<HeaderInfo>,
}

impl Action {
    pub fn of(kind: ActionType) -> Self {
        Action {
            kind,
            redirect: None,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Redirect {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transform: Option<UrlTransform>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex_substitution: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UrlTransform {
    /// `""` clears the query string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_transform: Option<QueryTransform>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryTransform {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove_params: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HeaderOperation {
    Append,
    Set,
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderInfo {
    pub header: String,
    pub operation: HeaderOperation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

/// Request types, as DNR names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    MainFrame,
    SubFrame,
    Stylesheet,
    Script,
    Image,
    Font,
    Object,
    Xmlhttprequest,
    Ping,
    CspReport,
    Media,
    Websocket,
    Webtransport,
    Webbundle,
    Other,
}

impl ResourceType {
    /// What a rule without `resourceTypes` matches: everything but the
    /// top-level document.
    pub const SUBRESOURCES: [ResourceType; 14] = [
        ResourceType::SubFrame,
        ResourceType::Stylesheet,
        ResourceType::Script,
        ResourceType::Image,
        ResourceType::Font,
        ResourceType::Object,
        ResourceType::Xmlhttprequest,
        ResourceType::Ping,
        ResourceType::CspReport,
        ResourceType::Media,
        ResourceType::Websocket,
        ResourceType::Webtransport,
        ResourceType::Webbundle,
        ResourceType::Other,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Method {
    Connect,
    Delete,
    Get,
    Head,
    Options,
    Patch,
    Post,
    Put,
    Other,
}

impl Method {
    pub fn parse(upper: &str) -> Option<Method> {
        Some(match upper {
            "CONNECT" => Method::Connect,
            "DELETE" => Method::Delete,
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            "OPTIONS" => Method::Options,
            "PATCH" => Method::Patch,
            "POST" => Method::Post,
            "PUT" => Method::Put,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DomainType {
    FirstParty,
    ThirdParty,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_filter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex_filter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_url_filter_case_sensitive: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub initiator_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_initiator_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_request_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_types: Vec<ResourceType>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_resource_types: Vec<ResourceType>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request_methods: Vec<Method>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded_request_methods: Vec<Method>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_type: Option<DomainType>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_like_chrome_expects() {
        let rule = Rule {
            id: 1,
            priority: 20,
            action: Action {
                redirect: Some(Redirect {
                    extension_path: Some("/war/noop.js".into()),
                    ..Redirect::default()
                }),
                ..Action::of(ActionType::Redirect)
            },
            condition: Condition {
                url_filter: Some("||ads.example^".into()),
                resource_types: vec![ResourceType::Script, ResourceType::SubFrame],
                domain_type: Some(DomainType::ThirdParty),
                request_methods: vec![Method::Get],
                ..Condition::default()
            },
        };
        let json = serde_json::to_string(&rule).unwrap();
        assert_eq!(
            json,
            r#"{"id":1,"priority":20,"action":{"type":"redirect","redirect":{"extensionPath":"/war/noop.js"}},"condition":{"urlFilter":"||ads.example^","resourceTypes":["script","sub_frame"],"requestMethods":["get"],"domainType":"thirdParty"}}"#
        );
        let back: Rule = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rule);
        assert_eq!(
            serde_json::to_string(&ActionType::AllowAllRequests).unwrap(),
            r#""allowAllRequests""#
        );
        assert_eq!(
            serde_json::to_string(&ResourceType::Xmlhttprequest).unwrap(),
            r#""xmlhttprequest""#
        );
    }
}
