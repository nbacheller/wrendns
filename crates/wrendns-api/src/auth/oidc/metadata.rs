//! The provider's discovery document (REQ: API-004, ADR-951): read strictly, with the transport
//! rules. One document gives everything the flow needs, including `end_session_endpoint`, so
//! discovery is fetched once. Pure.

use serde_json::Value;

/// What the flow uses from the discovery document.
#[derive(Debug, Clone)]
pub(super) struct Metadata {
    pub(super) authorization_endpoint: String,
    pub(super) token_endpoint: String,
    pub(super) jwks_uri: String,
    /// RP-initiated logout, when the provider offers it at a permitted URL.
    pub(super) end_session_endpoint: Option<String>,
    /// `id_token_signing_alg_values_supported`, when listed.
    pub(super) id_token_algs: Option<Vec<String>>,
    /// `token_endpoint_auth_methods_supported`, when listed.
    pub(super) token_auth_methods: Option<Vec<String>>,
}

/// Where the discovery document of `issuer` is.
pub(super) fn url_of(issuer: &str) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    )
}

/// The document, read against the configured issuer (ADR-951, "Discovery and transport"):
/// its `issuer` must be exactly that. When the issuer is HTTPS, `authorization_endpoint`,
/// `token_endpoint` and `jwks_uri` must be HTTPS too, or the document is refused. An
/// `end_session_endpoint` that isn't HTTPS in that case is dropped, so no logout is offered.
pub(super) fn parse(doc: &Value, configured_issuer: &str) -> Result<Metadata, String> {
    let text = |name: &str| doc.get(name).and_then(Value::as_str).map(str::to_owned);
    if text("issuer").as_deref() != Some(configured_issuer) {
        return Err("the discovery document's issuer isn't the configured issuer".into());
    }
    let https = configured_issuer.starts_with("https://");
    let endpoint = |name: &str| -> Result<String, String> {
        let url = text(name).ok_or_else(|| format!("the discovery document has no {name}"))?;
        if https && !url.starts_with("https://") {
            return Err(format!("{name} isn't HTTPS, though the issuer is"));
        }
        Ok(url)
    };
    Ok(Metadata {
        authorization_endpoint: endpoint("authorization_endpoint")?,
        token_endpoint: endpoint("token_endpoint")?,
        jwks_uri: endpoint("jwks_uri")?,
        end_session_endpoint: text("end_session_endpoint")
            .filter(|url| !https || url.starts_with("https://")),
        id_token_algs: list(doc, "id_token_signing_alg_values_supported")?,
        token_auth_methods: list(doc, "token_endpoint_auth_methods_supported")?,
    })
}

/// An optional list of strings; present but mistyped is refused.
fn list(doc: &Value, name: &str) -> Result<Option<Vec<String>>, String> {
    match doc.get(name) {
        None => Ok(None),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect::<Option<Vec<String>>>()
            .map(Some)
            .ok_or_else(|| format!("{name} isn't a list of strings")),
        Some(_) => Err(format!("{name} isn't a list")),
    }
}
