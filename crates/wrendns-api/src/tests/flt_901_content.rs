//! REQ: FLT-901, FLT-902, AGT-001, AGT-007 (T24.29, ADR-994) — content categories over HTTP and MCP:
//! the catalog, a group's content (validation, the confirmation a heavy selection needs, the
//! node's budget), and the rule that an agent plans a content change and only an operator-approved
//! plan applies.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use super::*;
use crate::categories_api::GroupContentInfo;

const MIB: u64 = 1024 * 1024;

fn group(name: &str, content: Option<GroupContentInfo>) -> GroupInfo {
    GroupInfo {
        name: name.into(),
        priority: 0,
        lists: None,
        block_mode: "null_ip".into(),
        block_ttl_seconds: 60,
        paused_until_unix_seconds: None,
        networks: Vec::new(),
        color: "#3b82f6".into(),
        queries_24h: 0,
        blocked_24h: 0,
        devices_this_hour: 0,
        blocked_services: Vec::new(),
        schedules: Vec::new(),
        schedules_on: Vec::new(),
        safe_search: false,
        youtube_restrict: None,
        rebinding_protection: false,
        block_answer_ips: Vec::new(),
        rewrites: Vec::new(),
        dns64: false,
        dns64_prefix: None,
        filter_aaaa: false,
        upstreams: None,
        content,
        safe_search_engines: Vec::new(),
        sources: Vec::new(),
        filter_scope: String::new(),
    }
}

fn level(l: &str, cats: &[&str]) -> GroupContentInfo {
    GroupContentInfo {
        level: l.into(),
        categories: cats.iter().map(|c| (*c).to_owned()).collect(),
        ..GroupContentInfo::default()
    }
}

fn with_groups(fake: &Fake) {
    *fake.cat_groups.lock().unwrap() = vec![
        group("default", None),
        group("kids", Some(level("enhanced", &["adult"]))),
    ];
}

async fn put(app: &TestApp, bearer: &str, uri: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::put(uri)
        .header("authorization", format!("Bearer {bearer}"))
        .header("x-wrendns-reason", "testing")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let (s, _, v) = send(app, req).await;
    (s, v)
}

/// An agent token with `scopes`, made by the admin's session.
async fn agent(app: &TestApp, scopes: &[&str]) -> String {
    let req = Request::post("/api/v1/tokens")
        .header("cookie", &app.cookie)
        .header("x-csrf-token", &app.csrf)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"name": "helper", "kind": "agent", "scopes": scopes}).to_string(),
        ))
        .unwrap();
    let (_, _, v) = send(app, req).await;
    v["token"].as_str().unwrap().to_owned()
}

/// REQ: FLT-901 — the catalog: groups with categories, sources with licences, the presets, what
/// is not offered and why, and what the groups select.
#[tokio::test]
async fn flt_901_categories_lists_the_catalog_and_what_groups_select() {
    let (app, fake) = app();
    with_groups(&fake);
    let (s, _, v) = get(&app, "/api/v1/categories").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["catalogVersion"], "2026-11-26");
    let groups = v["groups"].as_array().unwrap();
    assert!(groups.len() >= 7);
    // The aggregate's group carries its notice and the link to the publisher's table of sources.
    let pt = groups.iter().find(|g| g["id"] == "packettale").unwrap();
    assert!(
        pt["note"].as_str().unwrap().contains("mixed licences"),
        "{pt}"
    );
    assert_eq!(pt["noteUrl"], "https://blocklist.packettale.com/sources.md");
    assert_eq!(pt["categories"].as_array().unwrap().len(), 5);
    assert!(
        groups[0].get("note").is_none(),
        "a group with no notice has none"
    );
    let adult = groups
        .iter()
        .flat_map(|g| g["categories"].as_array().unwrap())
        .find(|c| c["id"] == "adult")
        .unwrap();
    assert_eq!(adult["groups"], json!(["kids"]), "kids select it");
    // A source names its licence and its link; the CC BY-SA one carries its attribution.
    let src = v["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "hagezi-nsfw")
        .unwrap();
    assert_eq!(src["licence"], "GPL-3.0");
    assert!(src["licenceUrl"].as_str().unwrap().starts_with("https://"));
    assert_eq!(
        src["state"]["state"], "pending",
        "selected, not downloaded yet"
    );
    assert!(
        v["attributions"][0]
            .as_str()
            .unwrap()
            .contains("CC BY-SA 4.0")
    );
    assert!(v["notOffered"].as_array().unwrap().len() >= 15);
    assert_eq!(v["presets"][0]["id"], "basic");
    // What the groups select: the kids group's adult source; distinct sources cost once.
    let kids = v["selections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["group"] == "kids")
        .unwrap();
    assert_eq!(kids["sources"], json!(["hagezi-nsfw"]));
    assert_eq!(v["total"]["entries"], 85_282);
    // A group's content, and a viewer's read.
    let (s, _, v) = get(&app, "/api/v1/groups/kids/content").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["content"]["level"], "enhanced");
    assert_eq!(v["summary"], "Enhanced (1 of 25)");
    assert_eq!(
        get(&app, "/api/v1/groups/nobody/content").await.0,
        StatusCode::NOT_FOUND
    );
}

/// REQ: FLT-901 — a content write is checked against the catalog (422 with the field), and a
/// valid one reaches the backend as a whole group entry with the new content and the cost.
#[tokio::test]
async fn flt_901_put_content_validates() {
    let (app, fake) = app();
    with_groups(&fake);
    let (s, v) = put(
        &app,
        &app.bearer,
        "/api/v1/groups/kids/content",
        json!({"categories": ["adult", "no-such"]}),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["code"], "invalid_config");
    assert!(
        v["detail"]
            .as_str()
            .unwrap()
            .contains("content.categories[1]"),
        "{v}"
    );
    // A bundle of services belongs in `blockedServices`, an unknown tier is refused.
    let (s, v) = put(
        &app,
        &app.bearer,
        "/api/v1/groups/kids/content",
        json!({"categories": ["ai"]}),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(
        v["detail"].as_str().unwrap().contains("blocked_services"),
        "{v}"
    );
    let (s, v) = put(
        &app,
        &app.bearer,
        "/api/v1/groups/kids/content",
        json!({"tiers": {"gambling": "huge"}}),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let (s, v) = put(
        &app,
        &app.bearer,
        "/api/v1/groups/kids/content",
        json!({"level": "loud"}),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(
        put(
            &app,
            &app.bearer,
            "/api/v1/groups/nobody/content",
            json!({"level": "basic"})
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    // A valid change: fields left out keep their value; the write carries the new content.
    let (s, v) = put(
        &app,
        &app.bearer,
        "/api/v1/groups/kids/content",
        json!({"categories": ["adult", "gambling"], "ads": true}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["applied"], true);
    assert!(v["budget"]["entries"].as_u64().unwrap() > 85_282, "{v}");
    assert_eq!(v["confirmationRequired"], false);
    let seen = fake.seen.lock().unwrap().clone();
    let w = seen
        .iter()
        .find(|l| l.starts_with("managed Group kids"))
        .unwrap();
    assert!(w.contains("\"level\":\"enhanced\""), "level kept: {w}");
    assert!(
        w.contains("\"gambling\"") && w.contains("\"ads\":true"),
        "{w}"
    );
}

/// REQ: FLT-901 — a heavy selection asks for a confirmation that states the daily download; a dry
/// run says so instead of refusing.
#[tokio::test]
async fn flt_901_heavy_requires_confirm() {
    let (app, fake) = app();
    with_groups(&fake);
    let body = json!({"categories": ["adult", "nrd"]});
    let (s, v) = put(
        &app,
        &app.bearer,
        "/api/v1/groups/kids/content",
        body.clone(),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "confirm_required");
    assert!(v["detail"].as_str().unwrap().contains("MB a day"), "{v}");
    // A dry run reports it without failing.
    let (s, v) = put(
        &app,
        &app.bearer,
        "/api/v1/groups/kids/content?dryRun=true",
        body.clone(),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["confirmationRequired"], true);
    assert_eq!(v["applied"], false);
    assert!(v["heavyDailyDownloadBytes"].as_u64().unwrap() >= 40_000_000);
    // Confirmed, it applies.
    let (s, v) = put(
        &app,
        &app.bearer,
        "/api/v1/groups/kids/content?confirm=true",
        body,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // The budget endpoint prices a proposal without changing anything.
    let (s, _, v) = get(
        &app,
        "/api/v1/categories/budget?group=kids&level=enhanced&categories=adult%2Cnrd",
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["confirmationRequired"], true);
    assert_eq!(v["heavyAdded"], json!(["hagezi-nrd7"]));
    assert_eq!(v["total"]["overBudgetAlone"], json!(["hagezi-nrd7"]));
}

/// REQ: FLT-901 — an injected 128 MiB node takes Basic and refuses NRD 7 days with the reason; a
/// 256 MiB node allows it with a warning (after the confirmation).
#[tokio::test]
async fn flt_901_over_budget_refused_on_small_node() {
    let (app, fake) = app();
    with_groups(&fake);
    fake.cat_memory
        .store(128 * MIB, std::sync::atomic::Ordering::SeqCst);
    // Basic ran on a 128 MiB container at a peak of 71 MiB (design 2.4): over the half the rule
    // allows, so the node refuses it; from 192 MiB it passes.
    let (s, v) = put(
        &app,
        &app.bearer,
        "/api/v1/groups/kids/content",
        json!({"level": "basic"}),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["code"], "budget_refused");
    fake.cat_memory
        .store(192 * MIB, std::sync::atomic::Ordering::SeqCst);
    let (s, v) = put(
        &app,
        &app.bearer,
        "/api/v1/groups/kids/content",
        json!({"level": "basic"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "Basic passes on 192 MiB: {v}");
    fake.cat_memory
        .store(128 * MIB, std::sync::atomic::Ordering::SeqCst);
    let (s, v) = put(
        &app,
        &app.bearer,
        "/api/v1/groups/kids/content?confirm=true",
        json!({"categories": ["nrd"], "level": "enhanced"}),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["code"], "budget_refused");
    assert!(v["detail"].as_str().unwrap().contains("128 MiB"), "{v}");
    fake.cat_memory
        .store(512 * MIB, std::sync::atomic::Ordering::SeqCst);
    let (s, v) = put(
        &app,
        &app.bearer,
        "/api/v1/groups/kids/content?confirm=true",
        json!({"categories": ["nrd"], "level": "enhanced"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "allowed with a warning on 512 MiB: {v}");
    assert_eq!(v["budget"]["overBudget"], true);
    assert_eq!(v["budget"]["refused"], false);
}

/// REQ: FLT-901 (ADR-994 item 8) — an agent token may plan (dry-run) a content change and never
/// apply it, whatever its scopes; changing `content` through `PUT /groups/{name}` is the same; a
/// heavy selection is refused to an agent even as a plan.
#[tokio::test]
async fn flt_901_agent_rest_put_content_403() {
    let (app, fake) = app();
    with_groups(&fake);
    let token = agent(&app, &["config:read", "config:write:groups"]).await;
    let (s, v) = put(
        &app,
        &token,
        "/api/v1/groups/kids/content",
        json!({"level": "basic"}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["code"], "agent_not_allowed");
    // As a plan (dry run) a light change is fine.
    let (s, v) = put(
        &app,
        &token,
        "/api/v1/groups/kids/content?dryRun=true",
        json!({"level": "basic"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // A heavy selection is refused even as a plan.
    let (s, v) = put(
        &app,
        &token,
        "/api/v1/groups/kids/content?dryRun=true",
        json!({"categories": ["nrd"], "level": "enhanced"}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["code"], "agent_not_allowed");
    // `PUT /groups/{name}` with a changed `content` is the same refusal; an unchanged one (or none:
    // the group keeps what it has) is a plain group write.
    let (s, v) = put(
        &app,
        &token,
        "/api/v1/groups/kids",
        json!({"block_mode": "nxdomain", "content": {"level": "basic"}}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(v["code"], "agent_not_allowed");
    let (s, v) = put(
        &app,
        &token,
        "/api/v1/groups/kids",
        json!({"block_mode": "nxdomain"}),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::OK,
        "content left out is kept, not changed: {v}"
    );
    let seen = fake.seen.lock().unwrap().clone();
    let w = seen
        .iter()
        .rev()
        .find(|l| l.starts_with("managed Group kids"))
        .unwrap();
    // The body goes on without `content`: the backend keeps the entry's own (the files' or the
    // stored one), never the effective group's, which can be derived (recheck items 2 and 3).
    assert!(
        !w.contains("content"),
        "content is left to the backend: {w}"
    );
    // An operator's write is the same call as the agent's, and works.
    let (s, v) = put(
        &app,
        &app.bearer,
        "/api/v1/groups/kids/content",
        json!({"level": "basic"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

async fn mcp(app: &TestApp, bearer: &str, id: u64, name: &str, args: Value) -> Value {
    let req = Request::post("/mcp")
        .header("authorization", format!("Bearer {bearer}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(Body::from(
            json!({"jsonrpc": "2.0", "id": id, "method": "tools/call",
                   "params": {"name": name, "arguments": args}})
            .to_string(),
        ))
        .unwrap();
    let (_, _, v) = send(app, req).await;
    v["result"].clone()
}

/// REQ: FLT-901, AGT-007 (ADR-994 item 8) — `plan_set_group_content` makes a plan that is
/// `pending` even with `require_approval` off, `apply_plan` of it answers 403 `agent_not_allowed`
/// until an operator approves it, and the approved plan applies (through the same write the agent
/// is refused over REST).
#[tokio::test]
async fn flt_901_agent_apply_unapproved_content_plan_403() {
    let (app, fake) = app();
    with_groups(&fake);
    assert!(!app.auth.agents().require_approval(), "approval is off");
    let token = agent(&app, &["config:read", "config:write:groups"]).await;
    // The catalog and the group are readable tools.
    let r = mcp(&app, &token, 1, "categories_list", json!({})).await;
    assert_eq!(r["isError"], false, "{r}");
    assert!(
        r["structuredContent"]["categories"]["groups"].is_array(),
        "{r}"
    );
    let r = mcp(
        &app,
        &token,
        2,
        "get_group_content",
        json!({"group": "kids", "level": "basic"}),
    )
    .await;
    assert_eq!(r["isError"], false, "{r}");
    assert_eq!(
        r["structuredContent"]["content"]["content"]["level"],
        "enhanced"
    );
    assert!(r["structuredContent"]["proposal"]["total"]["entries"].is_number());
    // Planning: pending whatever require_approval says.
    let r = mcp(
        &app,
        &token,
        3,
        "plan_set_group_content",
        json!({"group": "kids", "level": "basic", "reason": "kids should get the basic filter"}),
    )
    .await;
    assert_eq!(r["isError"], false, "{r}");
    assert_eq!(r["structuredContent"]["state"], "pending", "{r}");
    let plan = r["structuredContent"]["planId"]
        .as_str()
        .unwrap()
        .to_owned();
    // Applying it before an operator approved: 403 agent_not_allowed.
    let r = mcp(&app, &token, 4, "apply_plan", json!({"planId": plan})).await;
    assert_eq!(r["isError"], true, "{r}");
    assert_eq!(r["structuredContent"]["code"], "agent_not_allowed", "{r}");
    assert_eq!(r["structuredContent"]["status"], 403, "{r}");
    let writes = |fake: &Fake| {
        fake.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.starts_with("managed Group kids") && l.contains("\"level\":\"basic\""))
            .count()
    };
    assert_eq!(
        writes(&fake),
        1,
        "only the plan's dry run reached the backend"
    );
    // An operator approves it; the agent's apply then goes through.
    let req = Request::post(format!("/api/v1/plans/{plan}/approve"))
        .header("cookie", &app.cookie)
        .header("x-csrf-token", &app.csrf)
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let (s, _, v) = send(&app, req).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let r = mcp(&app, &token, 5, "apply_plan", json!({"planId": plan})).await;
    assert_eq!(r["isError"], false, "{r}");
    assert_eq!(r["structuredContent"]["state"], "applied", "{r}");
    assert_eq!(writes(&fake), 2, "the approved plan's replay was written");
}

/// REQ: FLT-901 — a heavy selection is refused at planning time for an agent.
#[tokio::test]
async fn flt_901_agent_heavy_refused() {
    let (app, fake) = app();
    with_groups(&fake);
    let token = agent(&app, &["config:read", "config:write:groups"]).await;
    let r = mcp(
        &app,
        &token,
        1,
        "plan_set_group_content",
        json!({"group": "kids", "level": "enhanced", "categories": ["nrd"], "reason": "new domains"}),
    )
    .await;
    assert_eq!(r["isError"], true, "{r}");
    assert!(r.to_string().contains("agent_not_allowed"), "{r}");
}

/// REQ: FLT-901 (T24.29) - a group whose config file sets `content` keeps it, whatever the entry's
/// source reads: saving the group's other fields stores an override (`source: "override"`), and
/// the content is still the file's (409 `set_by_file`, on both routes). The same content is not a
/// change.
#[tokio::test]
async fn flt_901_file_content_survives_an_override() {
    let (app, fake) = app();
    with_groups(&fake);
    *fake.cat_entries.lock().unwrap() = vec![crate::model::ConfigEntry {
        kind: "group".into(),
        name: "kids".into(),
        source: "override".into(),
        definition: Some(
            json!({"name": "kids", "content": {"level": "enhanced", "categories": ["adult"]}}),
        ),
        redacted: Vec::new(),
        credential_issues: Vec::new(),
        set_by_file: vec!["content".into()],
        answering: None,
    }];
    let (s, v) = put(
        &app,
        &app.bearer,
        "/api/v1/groups/kids/content",
        json!({"level": "basic"}),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "set_by_file");
    let (s, v) = put(
        &app,
        &app.bearer,
        "/api/v1/groups/kids",
        json!({"content": {"level": "basic"}}),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "set_by_file");
    // What the file says, sent back, is no change.
    let (s, v) = put(
        &app,
        &app.bearer,
        "/api/v1/groups/kids",
        json!({"block_mode": "nxdomain", "content": {"level": "enhanced", "categories": ["adult"]}}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = put(
        &app,
        &app.bearer,
        "/api/v1/groups/kids/content",
        json!({"level": "enhanced"}),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::OK,
        "the file's own content is no change: {v}"
    );
}

/// REQ: FLT-901 (T24.29) - a selection a node already refuses can be reduced: only a change that
/// asks for more is refused.
#[tokio::test]
async fn flt_901_refused_selection_can_be_reduced() {
    let (app, fake) = app();
    *fake.cat_groups.lock().unwrap() = vec![
        group("default", None),
        group("kids", Some(level("enhanced", &["adult", "nrd"]))),
        group("teens", Some(level("enhanced", &["adult"]))),
    ];
    fake.cat_memory
        .store(128 * MIB, std::sync::atomic::Ordering::SeqCst);
    let (s, v) = put(
        &app,
        &app.bearer,
        "/api/v1/groups/teens/content?confirm=true",
        json!({"level": "off"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "reducing is allowed: {v}");
    let (s, v) = put(
        &app,
        &app.bearer,
        "/api/v1/groups/teens/content?confirm=true",
        json!({"categories": ["adult", "gambling", "social"], "tiers": {"adult": "extended"}}),
    )
    .await;
    assert_ne!(s, StatusCode::OK, "asking for more stays refused: {v}");
}

/// REQ: FLT-902 - `level` left out of a group's content reads `off`, as in the TOML.
#[tokio::test]
async fn flt_902_content_level_defaults_to_off() {
    let (app, fake) = app();
    with_groups(&fake);
    let (s, v) = put(
        &app,
        &app.bearer,
        "/api/v1/groups/default",
        json!({"content": {"categories": ["adult"]}}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

/// REQ: API-010 (ADR-040) - a write runs to its end when the client hangs up first (a page
/// reloading right after Apply): the change is not left stored and not applied.
#[tokio::test]
async fn api_010_a_write_survives_the_client_hanging_up() {
    let (app, fake) = app();
    with_groups(&fake);
    fake.slow_ms.store(150, std::sync::atomic::Ordering::SeqCst);
    let req = Request::put("/api/v1/groups/kids")
        .header("authorization", format!("Bearer {}", app.bearer))
        .header("x-wrendns-reason", "testing")
        .header("content-type", "application/json")
        .body(Body::from(json!({"block_mode": "nxdomain"}).to_string()))
        .unwrap();
    // The client gives up after 20 ms: the request future is dropped.
    let hung_up = tokio::time::timeout(
        std::time::Duration::from_millis(20),
        app.router.clone().oneshot(req),
    )
    .await;
    assert!(hung_up.is_err(), "the write was still running");
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert_eq!(
        *fake.slow_done.lock().unwrap(),
        vec!["kids".to_owned()],
        "the write ran to its end"
    );
}
