// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{
    config::{Config, Credential},
    db::now,
};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, SqlitePool};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub config: Arc<Config>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/openapi.json", get(openapi))
        .route("/v1/printer-enrollments/exchange", post(exchange))
        .route(
            "/v1/tenants/{tenant}/printer-enrollments",
            post(create_enrollment),
        )
        .route("/v1/tenants/{tenant}/printer-agents", get(list_agents))
        .route(
            "/v1/tenants/{tenant}/printer-agents/{agent}/revoke",
            post(revoke_agent),
        )
        .route("/v1/tenants/{tenant}/printers", get(list_printers))
        .route("/v1/tenants/{tenant}/print-jobs", post(create_job))
        .route("/v1/tenants/{tenant}/print-jobs/{job}", get(get_job))
        .route(
            "/v1/tenants/{tenant}/print-jobs/{job}/cancel",
            post(cancel_job),
        )
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            state.config.max_request_bytes,
        ))
        .with_state(state)
}

async fn openapi() -> Json<Value> {
    Json(json!({
        "openapi":"3.1.0",
        "info":{"title":"mb-print-cloud API","version":env!("CARGO_PKG_VERSION")},
        "paths":{
            "/v1/tenants/{tenant}/printer-enrollments":{"post":{"security":[{"bearerAuth":[]}],"responses":{"201":{"description":"Enrollment code created"}}}},
            "/v1/printer-enrollments/exchange":{"post":{"security":[],"responses":{"200":{"description":"Agent credential issued"},"410":{"description":"Code expired or consumed"}}}},
            "/v1/tenants/{tenant}/printer-agents":{"get":{"security":[{"bearerAuth":[]}],"responses":{"200":{"description":"Agents"}}}},
            "/v1/tenants/{tenant}/printer-agents/{agent}/revoke":{"post":{"security":[{"bearerAuth":[]}],"responses":{"200":{"description":"Agent revoked"}}}},
            "/v1/tenants/{tenant}/printers":{"get":{"security":[{"bearerAuth":[]}],"responses":{"200":{"description":"Published printers"}}}},
            "/v1/tenants/{tenant}/print-jobs":{"post":{"security":[{"bearerAuth":[]}],"parameters":[{"name":"Idempotency-Key","in":"header","required":true,"schema":{"type":"string","maxLength":255}}],"responses":{"202":{"description":"Job stored"},"409":{"description":"Idempotency conflict"}}}},
            "/v1/tenants/{tenant}/print-jobs/{job}":{"get":{"security":[{"bearerAuth":[]}],"responses":{"200":{"description":"Job state"}}}},
            "/v1/tenants/{tenant}/print-jobs/{job}/cancel":{"post":{"security":[{"bearerAuth":[]}],"responses":{"200":{"description":"Cancellation requested"}}}}
        },
        "components":{"securitySchemes":{"bearerAuth":{"type":"http","scheme":"bearer"}}}
    }))
}

#[derive(Debug)]
pub enum ApiError {
    Unauthorized,
    Forbidden,
    NotFound,
    Bad(&'static str),
    Conflict(&'static str),
    Gone,
    RateLimited,
    Internal(anyhow::Error),
}
impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(e.into())
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", None),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden", None),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", None),
            Self::Bad(m) => (StatusCode::BAD_REQUEST, "invalid_request", Some(m)),
            Self::Conflict(m) => (StatusCode::CONFLICT, "conflict", Some(m)),
            Self::Gone => (StatusCode::GONE, "expired_or_consumed", None),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", None),
            Self::Internal(e) => {
                tracing::error!(error_class=%e.root_cause(),"request failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal", None)
            }
        };
        (status, Json(json!({"error":code,"message":message}))).into_response()
    }
}

static ENROLLMENT_ATTEMPTS: OnceLock<Mutex<VecDeque<Instant>>> = OnceLock::new();
fn limit_enrollment_exchange() -> Result<(), ApiError> {
    let now = Instant::now();
    let mut attempts = ENROLLMENT_ATTEMPTS
        .get_or_init(|| Mutex::new(VecDeque::new()))
        .lock()
        .map_err(|_| ApiError::Internal(anyhow::anyhow!("rate limiter unavailable")))?;
    while attempts
        .front()
        .is_some_and(|time| now.duration_since(*time) > Duration::from_secs(60))
    {
        attempts.pop_front();
    }
    if attempts.len() >= 30 {
        return Err(ApiError::RateLimited);
    }
    attempts.push_back(now);
    Ok(())
}

fn hash(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}
fn random_secret(bytes: usize) -> String {
    let mut raw = vec![0; bytes];
    rand::rng().fill_bytes(&mut raw);
    URL_SAFE_NO_PAD.encode(raw)
}
fn authorize<'a>(
    config: &'a Config,
    headers: &HeaderMap,
    tenant: Uuid,
    permission: &str,
) -> Result<&'a Credential, ApiError> {
    if tenant != config.tenant.id {
        return Err(ApiError::NotFound);
    }
    let value = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;
    let presented = hash(value.as_bytes());
    let credential = config
        .credentials
        .iter()
        .find(|c| {
            let Ok(stored) = hex_decode(&c.token_sha256) else {
                return false;
            };
            stored.as_slice().ct_eq(&presented).into()
        })
        .ok_or(ApiError::Unauthorized)?;
    if !credential.permissions.iter().any(|p| p == permission) {
        return Err(ApiError::Forbidden);
    }
    Ok(credential)
}
fn hex_decode(value: &str) -> Result<Vec<u8>, ()> {
    if value.len() != 64 {
        return Err(());
    };
    (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EnrollmentBody {
    display_name: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnrollmentCreated {
    agent_id: Uuid,
    code: String,
    expires_at: i64,
}
async fn create_enrollment(
    State(s): State<AppState>,
    Path(tenant): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<EnrollmentBody>,
) -> Result<(StatusCode, Json<EnrollmentCreated>), ApiError> {
    let actor = authorize(&s.config, &headers, tenant, "manage-printers")?
        .subject
        .clone();
    let name = body.display_name.trim();
    if name.is_empty() || name.len() > 120 {
        return Err(ApiError::Bad(
            "displayName must contain 1 to 120 characters",
        ));
    }
    let id = Uuid::new_v4();
    let secret = random_secret(16);
    let code = format!("{id}.{secret}");
    let expiry = now() + 600;
    sqlx::query("INSERT INTO printer_agents(id,tenant_id,display_name,state,enrollment_hash,enrollment_expires_at,created_by,created_at) VALUES(?,?,?,'pending',?,?,?,?)")
        .bind(id.to_string()).bind(tenant.to_string()).bind(name).bind(hash(secret.as_bytes()).to_vec()).bind(expiry).bind(actor).bind(now()).execute(&s.pool).await?;
    Ok((
        StatusCode::CREATED,
        Json(EnrollmentCreated {
            agent_id: id,
            code,
            expires_at: expiry,
        }),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeBody {
    code: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExchangeResponse {
    agent_id: Uuid,
    token: String,
    agent_url: String,
}
async fn exchange(
    State(s): State<AppState>,
    Json(body): Json<ExchangeBody>,
) -> Result<Json<ExchangeResponse>, ApiError> {
    limit_enrollment_exchange()?;
    let (id, secret) = body.code.split_once('.').ok_or(ApiError::Gone)?;
    let id = Uuid::parse_str(id).map_err(|_| ApiError::Gone)?;
    let mut tx = s.pool.begin().await?;
    let row=sqlx::query_as::<_,(Vec<u8>,i64)>("SELECT enrollment_hash,enrollment_expires_at FROM printer_agents WHERE id=? AND state='pending' AND enrollment_consumed_at IS NULL").bind(id.to_string()).fetch_optional(&mut *tx).await?.ok_or(ApiError::Gone)?;
    if row.1 <= now() || !bool::from(row.0.as_slice().ct_eq(&hash(secret.as_bytes()))) {
        return Err(ApiError::Gone);
    }
    let token_secret = random_secret(32);
    let token = format!("{id}.{token_secret}");
    let changed=sqlx::query("UPDATE printer_agents SET state='active',enrollment_hash=NULL,enrollment_consumed_at=? WHERE id=? AND state='pending'").bind(now()).bind(id.to_string()).execute(&mut *tx).await?.rows_affected();
    if changed != 1 {
        return Err(ApiError::Gone);
    }
    sqlx::query("INSERT INTO agent_tokens(agent_id,tenant_id,token_hash,created_at) SELECT id,tenant_id,?,? FROM printer_agents WHERE id=?").bind(hash(token_secret.as_bytes()).to_vec()).bind(now()).bind(id.to_string()).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(ExchangeResponse {
        agent_id: id,
        token,
        agent_url: s.config.public_agent_url.clone(),
    }))
}

#[derive(Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
struct AgentView {
    id: String,
    display_name: String,
    state: String,
    software_version: Option<String>,
    protocol_version: Option<i64>,
    last_connected_at: Option<i64>,
    last_heartbeat_at: Option<i64>,
}
async fn list_agents(
    State(s): State<AppState>,
    Path(tenant): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Vec<AgentView>>, ApiError> {
    authorize(&s.config, &headers, tenant, "manage-printers")?;
    Ok(Json(sqlx::query_as("SELECT id,display_name,state,software_version,protocol_version,last_connected_at,last_heartbeat_at FROM printer_agents WHERE tenant_id=? ORDER BY created_at").bind(tenant.to_string()).fetch_all(&s.pool).await?))
}
async fn revoke_agent(
    State(s): State<AppState>,
    Path((tenant, agent)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    authorize(&s.config, &headers, tenant, "manage-printers")?;
    let mut tx = s.pool.begin().await?;
    let changed=sqlx::query("UPDATE printer_agents SET state='revoked',revoked_at=? WHERE id=? AND tenant_id=? AND state<>'revoked'").bind(now()).bind(agent.to_string()).bind(tenant.to_string()).execute(&mut *tx).await?.rows_affected();
    if changed != 1 {
        return Err(ApiError::NotFound);
    }
    sqlx::query("UPDATE agent_tokens SET revoked_at=? WHERE agent_id=? AND tenant_id=?")
        .bind(now())
        .bind(agent.to_string())
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE printers SET enabled=0,online=0,updated_at=? WHERE agent_id=? AND tenant_id=?",
    )
    .bind(now())
    .bind(agent.to_string())
    .bind(tenant.to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"agentId":agent,"state":"revoked"})))
}

#[derive(Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
struct PrinterView {
    id: String,
    agent_id: String,
    display_name: String,
    model: String,
    enabled: bool,
    online: bool,
    last_seen_at: Option<i64>,
}
async fn list_printers(
    State(s): State<AppState>,
    Path(tenant): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Vec<PrinterView>>, ApiError> {
    authorize(&s.config, &headers, tenant, "print")?;
    Ok(Json(sqlx::query_as("SELECT id,agent_id,display_name,model,enabled,online,last_seen_at FROM printers WHERE tenant_id=? ORDER BY display_name").bind(tenant.to_string()).fetch_all(&s.pool).await?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SubmitJob {
    printer_id: Uuid,
    #[serde(default = "source")]
    source: String,
    request: Value,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ValidatedPrintRequest {
    document: Value,
    model: String,
    #[serde(default)]
    dpi: Option<u16>,
    #[serde(default)]
    rotation: u16,
    #[serde(default)]
    #[serde(rename = "fit")]
    _fit: bool,
    #[serde(default = "density")]
    density: u8,
    #[serde(default = "copies")]
    copies: u16,
    #[serde(default = "payload_limit")]
    payload_limit: usize,
}
const fn density() -> u8 {
    6
}
const fn copies() -> u16 {
    1
}
const fn payload_limit() -> usize {
    512
}
fn source() -> String {
    "api".into()
}
#[derive(Serialize, FromRow)]
#[serde(rename_all = "camelCase")]
pub struct JobView {
    id: String,
    printer_id: String,
    agent_id: String,
    state: String,
    terminal_outcome: Option<String>,
    progress: Option<i64>,
    action: Option<String>,
    bytes_sent: i64,
    total_bytes: i64,
    write_may_have_occurred: bool,
    cancellation_requested_at: Option<i64>,
    error_code: Option<String>,
    created_at: i64,
    delivered_at: Option<i64>,
    started_at: Option<i64>,
    terminal_at: Option<i64>,
}
const JOB_BY_ID: &str = "SELECT id,printer_id,agent_id,state,terminal_outcome,progress,action,bytes_sent,total_bytes,write_may_have_occurred,cancellation_requested_at,error_code,created_at,delivered_at,started_at,terminal_at FROM print_jobs WHERE id=? AND tenant_id=?";
async fn create_job(
    State(s): State<AppState>,
    Path(tenant): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<SubmitJob>,
) -> Result<(StatusCode, Json<JobView>), ApiError> {
    let subject = authorize(&s.config, &headers, tenant, "print")?
        .subject
        .clone();
    let key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| (1..=255).contains(&v.len()))
        .ok_or(ApiError::Bad("Idempotency-Key is required"))?;
    if body.source.is_empty() || body.source.len() > 40 {
        return Err(ApiError::Bad("source is invalid"));
    }
    let request =
        serde_json::to_vec(&body.request).map_err(|_| ApiError::Bad("request is invalid"))?;
    if request.len() > s.config.max_request_bytes {
        return Err(ApiError::Bad("request is too large"));
    }
    let validated: ValidatedPrintRequest =
        serde_json::from_slice(&request).map_err(|_| ApiError::Bad("request is invalid"))?;
    if validated.model.is_empty()
        || validated.document.get("version").and_then(Value::as_u64) != Some(4)
        || !validated
            .document
            .get("media")
            .is_some_and(Value::is_object)
        || !matches!(validated.rotation, 0 | 90 | 180 | 270)
        || !(1..=8).contains(&validated.density)
        || validated.copies == 0
        || validated.copies > 100
        || validated.payload_limit == 0
        || validated.payload_limit > s.config.max_request_bytes
        || validated.dpi == Some(0)
    {
        return Err(ApiError::Bad("print request is invalid"));
    }
    let digest = hash(&request);
    let semantic = hash(
        &serde_json::to_vec(
            &json!({"printerId":body.printer_id,"source":body.source,"request":body.request}),
        )
        .unwrap(),
    );
    let mut tx = s.pool.begin().await?;
    if let Some((existing_id,existing_digest))=sqlx::query_as::<_,(String,Vec<u8>)>("SELECT id,request_digest FROM print_jobs WHERE tenant_id=? AND submitted_by=? AND idempotency_key=?").bind(tenant.to_string()).bind(&subject).bind(key).fetch_optional(&mut *tx).await? {
        if existing_digest!=semantic{return Err(ApiError::Conflict("Idempotency-Key was reused with another request"))}
        let row=sqlx::query_as::<_,JobView>(JOB_BY_ID).bind(existing_id).bind(tenant.to_string()).fetch_one(&mut *tx).await?; tx.commit().await?; return Ok((StatusCode::ACCEPTED,Json(row)));
    }
    let printer = sqlx::query_as::<_, (String, bool, String)>(
        "SELECT agent_id,enabled,model FROM printers WHERE id=? AND tenant_id=?",
    )
    .bind(body.printer_id.to_string())
    .bind(tenant.to_string())
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError::NotFound)?;
    if !printer.1 {
        return Err(ApiError::Conflict("printer is disabled"));
    }
    if validated.model != printer.2 {
        return Err(ApiError::Bad("request model does not match printer"));
    }
    let id = Uuid::new_v4();
    let created = now();
    sqlx::query("INSERT INTO print_jobs(id,tenant_id,submitted_by,source,agent_id,printer_id,request,payload_digest,idempotency_key,request_digest,state,created_at,delete_payload_at) VALUES(?,?,?,?,?,?,?,?,?,?,'queued',?,?)")
        .bind(id.to_string()).bind(tenant.to_string()).bind(subject).bind(body.source).bind(&printer.0).bind(body.printer_id.to_string()).bind(request).bind(digest.to_vec()).bind(key).bind(semantic.to_vec()).bind(created).bind(created+604800).execute(&mut *tx).await?;
    let row = sqlx::query_as::<_, JobView>(JOB_BY_ID)
        .bind(id.to_string())
        .bind(tenant.to_string())
        .fetch_one(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((StatusCode::ACCEPTED, Json(row)))
}
async fn get_job(
    State(s): State<AppState>,
    Path((tenant, job)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<JobView>, ApiError> {
    authorize(&s.config, &headers, tenant, "print")?;
    Ok(Json(
        sqlx::query_as::<_, JobView>(JOB_BY_ID)
            .bind(job.to_string())
            .bind(tenant.to_string())
            .fetch_optional(&s.pool)
            .await?
            .ok_or(ApiError::NotFound)?,
    ))
}
async fn cancel_job(
    State(s): State<AppState>,
    Path((tenant, job)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<JobView>, ApiError> {
    let subject = authorize(&s.config, &headers, tenant, "print")?
        .subject
        .clone();
    let changed=sqlx::query("UPDATE print_jobs SET cancellation_requested_at=?,cancellation_requested_by=?,state=CASE WHEN state='queued' THEN 'cancelled-before-send' ELSE state END,terminal_outcome=CASE WHEN state='queued' THEN 'cancelled-before-send' ELSE terminal_outcome END,terminal_at=CASE WHEN state='queued' THEN ? ELSE terminal_at END WHERE id=? AND tenant_id=? AND terminal_at IS NULL")
        .bind(now()).bind(subject).bind(now()).bind(job.to_string()).bind(tenant.to_string()).execute(&s.pool).await?.rows_affected();
    if changed != 1 {
        return Err(ApiError::Conflict("job is already terminal or unknown"));
    }
    get_job(State(s), Path((tenant, job)), headers).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt as _;
    use tempfile::TempDir;
    use tower::ServiceExt as _;

    async fn fixture() -> (TempDir, AppState, String) {
        let directory = tempfile::tempdir().unwrap();
        let token = "test-administrator-token-with-enough-entropy".to_owned();
        let config = Config::template(
            directory.path().join("cloud.sqlite3"),
            format!("{:x}", Sha256::digest(token.as_bytes())),
        );
        let pool = crate::db::open(&config.database_path).await.unwrap();
        (
            directory,
            AppState {
                pool,
                config: Arc::new(config),
            },
            token,
        )
    }

    async fn json(response: Response) -> Value {
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
    }

    #[tokio::test]
    async fn enrollment_is_single_use_and_tenant_scoped() {
        let (_directory, state, token) = fixture().await;
        let tenant = state.config.tenant.id;
        let app = router(state.clone());
        let request = Request::post(format!("/v1/tenants/{tenant}/printer-enrollments"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"displayName":"Packing desk"}"#))
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let code = json(response).await["code"].as_str().unwrap().to_owned();

        for expected in [StatusCode::OK, StatusCode::GONE] {
            let response = app
                .clone()
                .oneshot(
                    Request::post("/v1/printer-enrollments/exchange")
                        .header("content-type", "application/json")
                        .body(Body::from(json!({"code":code}).to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }

        let response = app
            .oneshot(
                Request::get(format!("/v1/tenants/{}/printer-agents", Uuid::new_v4()))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn job_idempotency_replays_exactly_and_conflicts_on_change() {
        let (_directory, state, token) = fixture().await;
        let tenant = state.config.tenant.id;
        let agent = Uuid::new_v4();
        let printer = Uuid::new_v4();
        let timestamp = now();
        sqlx::query("INSERT INTO printer_agents(id,tenant_id,display_name,state,enrollment_consumed_at,created_by,created_at) VALUES(?,?,?,'active',?,?,?)")
            .bind(agent.to_string()).bind(tenant.to_string()).bind("agent").bind(timestamp).bind("test").bind(timestamp).execute(&state.pool).await.unwrap();
        sqlx::query("INSERT INTO printers(id,tenant_id,agent_id,display_name,model,enabled,online,created_at,updated_at) VALUES(?,?,?,?,?,1,0,?,?)")
            .bind(printer.to_string()).bind(tenant.to_string()).bind(agent.to_string()).bind("desk").bind("m110").bind(timestamp).bind(timestamp).execute(&state.pool).await.unwrap();
        let app = router(state);
        let submit = |copies| {
            Request::post(format!("/v1/tenants/{tenant}/print-jobs"))
                .header("authorization", format!("Bearer {token}"))
                .header("idempotency-key", "order-42")
                .header("content-type", "application/json")
                .body(Body::from(json!({"printerId":printer,"request":{"document":{"version":4,"media":{}},"model":"m110","copies":copies}}).to_string()))
                .unwrap()
        };
        let first = app.clone().oneshot(submit(1)).await.unwrap();
        assert_eq!(first.status(), StatusCode::ACCEPTED);
        let first_id = json(first).await["id"].clone();
        let replay = app.clone().oneshot(submit(1)).await.unwrap();
        assert_eq!(replay.status(), StatusCode::ACCEPTED);
        assert_eq!(json(replay).await["id"], first_id);
        let conflict = app.oneshot(submit(2)).await.unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
    }
}
