//! This binary's identity (REQ: OPS-004, CLU-010; ADR-046), stamped at build time by
//! `build.rs`, plus how it was installed (from `WRENDNS_INSTALL`, which the image, the Helm
//! chart, and the systemd unit set).

/// `0.1.0` for a release, `0.1.0-edge.47` for a main build, `0.1.0-dev` for a local build (the crate
/// version with a `-dev` suffix; peers read it as that version, ADR-948).
pub(crate) const VERSION: &str = env!("WRENDNS_BUILD_VERSION");
pub(crate) const COMMIT: &str = env!("WRENDNS_BUILD_COMMIT");
pub(crate) const DATE: &str = env!("WRENDNS_BUILD_DATE");
/// `stable`, `edge`, or `dev`.
pub(crate) const CHANNEL: &str = env!("WRENDNS_BUILD_CHANNEL");
pub(crate) const TARGET: &str = env!("WRENDNS_BUILD_TARGET");
/// Everything on one line, for `--version`.
pub(crate) const LINE: &str = env!("WRENDNS_VERSION_LINE");

/// `native`, `container`, or `helm`.
pub(crate) fn install_type() -> &'static str {
    match std::env::var("WRENDNS_INSTALL").ok().as_deref() {
        Some("helm") => "helm",
        Some("container") => "container",
        Some("native") => "native",
        _ if std::path::Path::new("/.dockerenv").exists()
            || std::env::var_os("KUBERNETES_SERVICE_HOST").is_some() =>
        {
            "container"
        }
        _ => "native",
    }
}

/// The build as the API shows it.
pub(crate) fn api() -> wrendns_api::model::BuildInfo {
    wrendns_api::model::BuildInfo {
        version: VERSION.into(),
        commit: COMMIT.into(),
        date: DATE.into(),
        channel: CHANNEL.into(),
        target: TARGET.into(),
        install: install_type().into(),
    }
}
