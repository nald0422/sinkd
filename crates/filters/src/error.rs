use serde::Serialize;

/// Why a line did not become a rule.
///
/// The split matters for the compiler's report: `Unsupported` is a known
/// feature sinkhole chose not to implement (or a target cannot express), while
/// `Invalid` is a malformed rule. Either way the rule is dropped, never
/// applied in a broadened form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ParseError {
    /// Recognized syntax that is deliberately not supported. `feature` is a
    /// stable key for grouping in reports, e.g. `option:replace` or
    /// `html-filtering`.
    #[error("unsupported {feature}: {detail}")]
    Unsupported { feature: String, detail: String },
    /// Malformed rule.
    #[error("invalid rule: {0}")]
    Invalid(String),
}

impl ParseError {
    pub(crate) fn unsupported(feature: impl Into<String>, detail: impl Into<String>) -> Self {
        ParseError::Unsupported {
            feature: feature.into(),
            detail: detail.into(),
        }
    }

    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        ParseError::Invalid(message.into())
    }

    /// The grouping key for reports: the feature for unsupported rules,
    /// `invalid` otherwise.
    pub fn feature(&self) -> &str {
        match self {
            ParseError::Unsupported { feature, .. } => feature,
            ParseError::Invalid(_) => "invalid",
        }
    }
}
