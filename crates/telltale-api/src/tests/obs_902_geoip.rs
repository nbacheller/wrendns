//! REQ: OBS-902 (T26.4, T26.5, ADR-959) - the GeoIP routes and the world view over HTTP: who may
//! fetch and delete the database, the status everyone sees, and the world view's states.

use std::net::IpAddr;

use axum::body::Body;
use axum::http::{Request, StatusCode};

use super::obs_901_map::{bearer_for, get_with, part, setup};
use super::*;
use crate::map::AnswerPrefix;
use crate::model::GeoipStatus;

fn status(enabled: bool, state: &str) -> GeoipStatus {
    GeoipStatus {
        enabled,
        state: state.to_owned(),
        source_month: Some("2026-11".into()),
        updated_at: Some("2026-11-17T10:00:00.000Z".into()),
        rows: 600_000,
        size_bytes: 4_000_000,
        next_check_at: None,
        last_error: None,
        old: false,
        attribution: "IP geolocation by DB-IP.com (CC BY 4.0)".into(),
    }
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn req(method: &str, uri: &str, bearer: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap()
}

/// ADR-959 section 2: everyone who sees the map sees the status; only an admin fetches or
/// deletes, and no agent does, whatever its scopes. Unsigned requests get nothing.
#[tokio::test]
async fn obs_902_geoip_admin_only() {
    let (app, fake) = app();
    *fake.geoip.lock().unwrap() = Some((status(true, "ready"), Vec::new()));
    let viewer = bearer_for(&app, "vic", auth::Role::Viewer, "read");
    let operator = bearer_for(&app, "oscar", auth::Role::Operator, "write");

    // Status: viewers and operators read it.
    for who in [&viewer, &operator, &app.bearer] {
        let (s, _, v) = send(&app, get_with("/api/v1/map/geoip", who)).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["state"], "ready");
        assert_eq!(v["sourceMonth"], "2026-11");
        assert_eq!(v["rows"], 600_000);
        assert!(v["attribution"].as_str().unwrap().contains("DB-IP.com"));
    }
    let (s, _, _) = send(
        &app,
        Request::get("/api/v1/map/geoip")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Update now and Delete: not a viewer, not an operator.
    for who in [&viewer, &operator] {
        let (s, _, _) = send(&app, req("POST", "/api/v1/map/geoip/update", who)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "update");
        let (s, _, _) = send(&app, req("DELETE", "/api/v1/map/geoip", who)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "delete");
    }
    assert!(
        fake.seen
            .lock()
            .unwrap()
            .iter()
            .all(|l| !l.starts_with("geoip"))
    );

    // Agents: the status is config:read; the actions have no scope at all, an admin's own token
    // minted for an agent included.
    let token = |name: &str, scopes: &str| {
        Request::post("/api/v1/tokens")
            .header("cookie", &app.cookie)
            .header("x-csrf-token", &app.csrf)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"name":"{name}","kind":"agent","scopes":[{scopes}]}}"#
            )))
            .unwrap()
    };
    let (s, _, v) = send(
        &app,
        token(
            "bot",
            r#""config:read","config:write:map","analytics:read","cluster:admin","ops:cache""#,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let agent = v["token"].as_str().unwrap().to_owned();
    let (s, _, v) = send(&app, get_with("/api/v1/map/geoip", &agent)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _, v) = send(&app, req("POST", "/api/v1/map/geoip/update", &agent)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let (s, _, v) = send(&app, req("DELETE", "/api/v1/map/geoip", &agent)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(
        fake.seen
            .lock()
            .unwrap()
            .iter()
            .all(|l| !l.starts_with("geoip"))
    );

    // An admin does both, each answered with the status and audited.
    let (s, _, v) = send(&app, req("POST", "/api/v1/map/geoip/update", &app.bearer)).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    assert_eq!(v["state"], "ready");
    let (s, _, v) = send(&app, req("DELETE", "/api/v1/map/geoip", &app.bearer)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let seen = fake.seen.lock().unwrap().clone();
    assert!(seen.contains(&"geoip update".to_owned()), "{seen:?}");
    assert!(seen.contains(&"geoip delete".to_owned()), "{seen:?}");
    for action in ["map.geoip.update", "map.geoip.delete"] {
        let audit = app
            .auth
            .state()
            .audit_page(None, 20, Some(action), None)
            .unwrap();
        assert_eq!(audit.len(), 1, "{action}: {audit:?}");
    }

    // A backend with no database (a resolver pod) answers 404 to the status.
    *fake.geoip.lock().unwrap() = None;
    let (s, _, _) = send(&app, get_with("/api/v1/map/geoip", &viewer)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

/// The world view over HTTP: off, missing, address not recorded (with upstream markers), and an
/// answer placed by the database.
#[tokio::test]
async fn obs_902_world_over_http() {
    let (app, fake) = app();
    setup(&fake, true);
    // Off.
    *fake.geoip.lock().unwrap() = Some((status(false, "off"), Vec::new()));
    let (s, _, v) = get(&app, "/api/v1/map/world").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (v["available"].clone(), v["reason"].clone()),
        (false.into(), "geoip_off".into())
    );
    // Missing.
    *fake.geoip.lock().unwrap() = Some((status(true, "missing"), Vec::new()));
    let (_, _, v) = get(&app, "/api/v1/map/world").await;
    assert_eq!(v["reason"], "geoip_missing");
    // Ready, answers not recorded: the upstream's marker, labelled by the reason.
    {
        let mut m = fake.map.lock().unwrap();
        m.1.parts[0].upstreams[0].ip = Some(ip("93.184.216.34"));
    }
    *fake.geoip.lock().unwrap() = Some((
        status(true, "ready"),
        vec![(ip("93.184.216.0"), "US".to_owned())],
    ));
    let (_, _, v) = get(&app, "/api/v1/map/world").await;
    assert_eq!(v["available"], false);
    assert_eq!(v["reason"], "address_not_recorded");
    assert_eq!(v["markers"][0]["name"], "quad9");
    assert_eq!(v["markers"][0]["cc"], "US");
    assert_eq!(v["homeCountry"], "NL");
    // Recorded: regions.
    {
        let mut m = fake.map.lock().unwrap();
        m.1.parts[0].answers_recorded = true;
        m.1.parts[0].answers = vec![AnswerPrefix {
            addr: ip("93.184.216.34"),
            weighted: 120,
            sampled: 24,
            slow: 12,
        }];
    }
    let (_, _, v) = get(&app, "/api/v1/map/world").await;
    assert_eq!(v["available"], true, "{v}");
    assert!(v.get("reason").is_none());
    assert_eq!(v["regions"][0]["cc"], "US");
    assert_eq!(v["regions"][0]["count"], 120);
    assert_eq!(v["regions"][0]["health"], "yellow");
    assert_eq!(v["unlocated"]["count"], 180);
    // The routes are in the OpenAPI document.
    let (_, _, v) = send(
        &app,
        Request::get("/api/v1/openapi.json")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    for (p, m) in [
        ("/api/v1/map/geoip", "get"),
        ("/api/v1/map/geoip", "delete"),
        ("/api/v1/map/geoip/update", "post"),
    ] {
        assert!(v["paths"][p][m].is_object(), "{m} {p}");
    }
    let _ = part("x");
}
