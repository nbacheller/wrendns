//! Claims checks for `OpenID` Connect ID tokens and MCP access tokens (REQ: API-004, AGT-008,
//! ADR-951). Pure: the caller passes `now` (Unix seconds), so tests can pin the clock. Every
//! date is a whole JSON number; a string, a fraction or a negative value is refused, never
//! skipped.

use serde_json::Value;

/// An ID token's `iat` and `nbf` may be this many seconds in the future (ADR-951 decision 4).
/// `exp` has no leeway for ID tokens, as before this change.
const FUTURE_SKEW: u64 = 60;
/// MCP access tokens keep their `exp` and `nbf` leeway of 60 seconds.
const ACCESS_LEEWAY: u64 = 60;

/// A `NumericDate` claim: `None` when absent, an error when it isn't a whole number of seconds.
pub(super) fn date(claims: &Value, name: &str) -> Result<Option<u64>, String> {
    match claims.get(name) {
        None => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("`{name}` isn't a whole number of seconds")),
    }
}

/// What an ID token must match.
pub(super) struct IdCheck<'a> {
    pub(super) issuer: &'a str,
    pub(super) client_id: &'a str,
    pub(super) nonce: &'a str,
    pub(super) now: u64,
}

/// ID-token claims (OIDC Core §3.1.3.7): `iss` is exactly the configured issuer; `aud` holds
/// only `client_id`; `azp`, when present, is `client_id` (and required with several audiences);
/// `sub` is a string; `exp` is in the future (no leeway); `iat` is present and not far ahead;
/// `nbf`, when present, is not far ahead; the nonce is the flow's.
pub(super) fn id_token(claims: &Value, want: &IdCheck<'_>) -> Result<(), String> {
    match claims.get("iss") {
        Some(Value::String(iss)) if iss == want.issuer => {}
        Some(Value::String(_)) => return Err("issued by another provider".into()),
        _ => return Err("the issuer isn't a string".into()),
    }
    let auds: Vec<&str> = match claims.get("aud") {
        Some(Value::String(aud)) => vec![aud.as_str()],
        Some(Value::Array(list)) => list
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<&str>>>()
            .ok_or("the audience isn't a string")?,
        _ => return Err("no audience".into()),
    };
    // Any audience other than this client is refused, even alongside it: a token meant for
    // another relying party is not ours to accept.
    if auds.is_empty() || auds.iter().any(|aud| *aud != want.client_id) {
        return Err("not issued for this client alone".into());
    }
    match claims.get("azp") {
        None if auds.len() > 1 => return Err("azp is required with several audiences".into()),
        None => {}
        Some(Value::String(azp)) if azp == want.client_id => {}
        Some(_) => return Err("azp isn't this client".into()),
    }
    if claims
        .get("sub")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err("no subject".into());
    }
    let exp = date(claims, "exp")?.ok_or("no expiry")?;
    if want.now >= exp {
        return Err("expired".into());
    }
    let iat = date(claims, "iat")?.ok_or("no issue time")?;
    if iat > want.now.saturating_add(FUTURE_SKEW) {
        return Err("issued in the future".into());
    }
    if date(claims, "nbf")?.is_some_and(|nbf| nbf > want.now.saturating_add(FUTURE_SKEW)) {
        return Err("not valid yet".into());
    }
    match claims.get("nonce") {
        Some(Value::String(nonce)) if nonce == want.nonce => Ok(()),
        _ => Err("the nonce doesn't match this sign-in".into()),
    }
}

/// MCP access-token claims, as before this change: `iss` (a trailing slash ignored), `aud`
/// (a string or an array) containing the resource's audience, `exp` and `nbf` with 60 s leeway.
pub(super) fn access_token(
    claims: &Value,
    issuer: &str,
    audience: &str,
    now: u64,
) -> Result<(), String> {
    match claims.get("iss").and_then(Value::as_str) {
        Some(iss) if iss.trim_end_matches('/') == issuer.trim_end_matches('/') => {}
        _ => return Err("issued by another provider".into()),
    }
    let for_us = match claims.get("aud") {
        Some(Value::String(aud)) => aud == audience,
        Some(Value::Array(list)) => list.iter().any(|aud| aud.as_str() == Some(audience)),
        _ => false,
    };
    if !for_us {
        return Err(format!("not issued for {audience}"));
    }
    let exp = date(claims, "exp")?.ok_or("no expiry")?;
    if exp.saturating_add(ACCESS_LEEWAY) < now {
        return Err("expired".into());
    }
    if date(claims, "nbf")?.is_some_and(|nbf| nbf > now.saturating_add(ACCESS_LEEWAY)) {
        return Err("not valid yet".into());
    }
    Ok(())
}
