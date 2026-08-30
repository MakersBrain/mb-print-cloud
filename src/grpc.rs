// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{
    api::AppState,
    db::now,
    observability::{JobCounts, JobEvent, duration_ms, job_event},
};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{collections::HashSet, pin::Pin, time::Duration};
use subtle::ConstantTimeEq;
use tokio::sync::mpsc;
use tokio_stream::{Stream, wrappers::ReceiverStream};
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub mod wire {
    tonic::include_proto!("makersbrain.print.agent.v1");
}
use wire::{
    AgentMessage, BrokerMessage, agent_message, broker_message,
    printer_agent_service_server::PrinterAgentService,
};

#[derive(Clone)]
pub struct Broker {
    pub state: AppState,
}
type Output = Pin<Box<dyn Stream<Item = Result<BrokerMessage, Status>> + Send>>;

#[tonic::async_trait]
impl PrinterAgentService for Broker {
    type SessionStream = Output;
    async fn session(
        &self,
        request: Request<tonic::Streaming<AgentMessage>>,
    ) -> Result<Response<Self::SessionStream>, Status> {
        let token = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("missing bearer token"))?
            .to_owned();
        let (token_agent, secret) = token
            .split_once('.')
            .ok_or_else(|| Status::unauthenticated("invalid bearer token"))?;
        let token_agent = Uuid::parse_str(token_agent)
            .map_err(|_| Status::unauthenticated("invalid bearer token"))?;
        let tenant = authenticate(&self.state, token_agent, secret).await?;
        let mut inbound = request.into_inner();
        let first = tokio::time::timeout(Duration::from_secs(10), inbound.next())
            .await
            .map_err(|_| Status::deadline_exceeded("agent hello timeout"))?
            .ok_or_else(|| Status::invalid_argument("agent hello required"))??;
        let Some(agent_message::Payload::Hello(hello)) = first.payload else {
            return Err(Status::invalid_argument("agent hello required"));
        };
        if hello.protocol_version != 1 {
            return Err(Status::failed_precondition("unsupported protocol version"));
        }
        if hello.agent_id != token_agent.to_string() {
            return Err(Status::permission_denied("agent identity mismatch"));
        }
        publish(&self.state, &tenant, token_agent, &hello).await?;
        for job in &hello.jobs {
            update_job(&self.state, token_agent, job, false).await?;
        }
        let (sender, receiver) = mpsc::channel(16);
        sender
            .send(Ok(BrokerMessage {
                payload: Some(broker_message::Payload::Hello(wire::BrokerHello {
                    protocol_version: 1,
                    heartbeat_seconds: 15,
                    max_request_bytes: self.state.config.max_request_bytes as u64,
                })),
            }))
            .await
            .map_err(|_| Status::unavailable("stream closed"))?;
        let state = self.state.clone();
        tokio::spawn(async move {
            session_loop(state, token_agent, inbound, sender).await;
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }
}

async fn authenticate(state: &AppState, id: Uuid, secret: &str) -> Result<String, Status> {
    let row=sqlx::query("SELECT t.tenant_id,t.token_hash FROM agent_tokens t JOIN printer_agents a ON a.id=t.agent_id WHERE t.agent_id=? AND t.revoked_at IS NULL AND a.state='active'").bind(id.to_string()).fetch_optional(&state.pool).await.map_err(internal)?.ok_or_else(||Status::unauthenticated("invalid bearer token"))?;
    let tenant: String = row.get(0);
    let stored: Vec<u8> = row.get(1);
    let actual: [u8; 32] = Sha256::digest(secret.as_bytes()).into();
    if !bool::from(stored.as_slice().ct_eq(&actual)) {
        return Err(Status::unauthenticated("invalid bearer token"));
    }
    sqlx::query("UPDATE agent_tokens SET last_used_at=? WHERE agent_id=?")
        .bind(now())
        .bind(id.to_string())
        .execute(&state.pool)
        .await
        .map_err(internal)?;
    Ok(tenant)
}

async fn publish(
    state: &AppState,
    tenant: &str,
    agent: Uuid,
    hello: &wire::AgentHello,
) -> Result<(), Status> {
    let mut tx = state.pool.begin().await.map_err(internal)?;
    sqlx::query("UPDATE printer_agents SET protocol_version=?,software_version=?,last_connected_at=?,last_heartbeat_at=?,last_error_code=NULL WHERE id=? AND tenant_id=? AND state='active'").bind(hello.protocol_version as i64).bind(&hello.software_version).bind(now()).bind(now()).bind(agent.to_string()).bind(tenant).execute(&mut *tx).await.map_err(internal)?;
    sqlx::query(
        "UPDATE printers SET enabled=0,online=0,updated_at=? WHERE agent_id=? AND tenant_id=?",
    )
    .bind(now())
    .bind(agent.to_string())
    .bind(tenant)
    .execute(&mut *tx)
    .await
    .map_err(internal)?;
    for p in &hello.printers {
        let id = Uuid::parse_str(&p.printer_id)
            .map_err(|_| Status::invalid_argument("invalid printer id"))?;
        if p.name.is_empty() || p.name.len() > 120 || p.model.is_empty() || p.model.len() > 120 {
            return Err(Status::invalid_argument("invalid printer publication"));
        }
        sqlx::query("INSERT INTO printers(id,tenant_id,agent_id,display_name,model,enabled,online,created_at,updated_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name,model=excluded.model,enabled=excluded.enabled,online=excluded.online,updated_at=excluded.updated_at,last_seen_at=excluded.last_seen_at WHERE printers.agent_id=excluded.agent_id AND printers.tenant_id=excluded.tenant_id")
            .bind(id.to_string()).bind(tenant).bind(agent.to_string()).bind(&p.name).bind(&p.model).bind(p.enabled).bind(p.enabled).bind(now()).bind(now()).bind(now()).execute(&mut *tx).await.map_err(internal)?;
    }
    tx.commit().await.map_err(internal)
}

async fn session_loop(
    state: AppState,
    agent: Uuid,
    mut inbound: tonic::Streaming<AgentMessage>,
    sender: mpsc::Sender<Result<BrokerMessage, Status>>,
) {
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut outstanding: Option<String> = None;
    let mut offered = HashSet::new();
    let mut cancellations = HashSet::new();
    loop {
        tokio::select! {
            message=inbound.next()=>match message {
                Some(Ok(message))=>if handle_agent(&state,agent,message,&mut outstanding).await.is_err(){break},
                _=>break,
            },
            _=tick.tick()=>{
                let active=sqlx::query_scalar::<_,i64>("SELECT count(*) FROM printer_agents WHERE id=? AND state='active'").bind(agent.to_string()).fetch_one(&state.pool).await.unwrap_or(0)==1;
                if !active{break}
                if outstanding.is_none()
                    && let Ok(rows)=sqlx::query_as::<_,(String,String,Vec<u8>,Vec<u8>)>("SELECT id,printer_id,request,payload_digest FROM print_jobs WHERE agent_id=? AND state IN ('queued','delivered','running') AND cancellation_requested_at IS NULL AND request IS NOT NULL ORDER BY created_at LIMIT 32").bind(agent.to_string()).fetch_all(&state.pool).await
                    && let Some((id,printer,request,digest))=rows.into_iter().find(|row|!offered.contains(&row.0)) {
                        let message=BrokerMessage{payload:Some(broker_message::Payload::PrintJob(wire::PrintJob{job_id:id.clone(),printer_id:printer,request_json:request,sha256:hex(&digest)}))};
                        if sender.send(Ok(message)).await.is_err(){break}
                        if let Ok(job_id) = Uuid::parse_str(&id) {
                            job_event(job_id, JobEvent::Offered, "queued", None, None, JobCounts::default());
                        }
                        offered.insert(id.clone()); outstanding=Some(id);
                }
                if let Ok(ids)=sqlx::query_scalar::<_,String>("SELECT id FROM print_jobs WHERE agent_id=? AND state IN ('delivered','running') AND cancellation_requested_at IS NOT NULL").bind(agent.to_string()).fetch_all(&state.pool).await {
                    for id in ids { if cancellations.insert(id.clone()) && sender.send(Ok(BrokerMessage{payload:Some(broker_message::Payload::CancelJob(wire::CancelJob{job_id:id}))})).await.is_err(){break} }
                }
            }
        }
    }
    let _ = sqlx::query("UPDATE printers SET online=0,updated_at=? WHERE agent_id=?")
        .bind(now())
        .bind(agent.to_string())
        .execute(&state.pool)
        .await;
}

async fn handle_agent(
    state: &AppState,
    agent: Uuid,
    message: AgentMessage,
    outstanding: &mut Option<String>,
) -> Result<(), Status> {
    match message.payload {
        Some(agent_message::Payload::Heartbeat(h)) => {
            sqlx::query("UPDATE printer_agents SET last_heartbeat_at=? WHERE id=?")
                .bind(now())
                .bind(agent.to_string())
                .execute(&state.pool)
                .await
                .map_err(internal)?;
            for job in h.jobs {
                update_job(state, agent, &job, false).await?;
            }
        }
        Some(agent_message::Payload::PrinterStatus(p)) => {
            let online = p.status == "online" || p.status == "ready";
            sqlx::query("UPDATE printers SET online=?,last_seen_at=?,updated_at=? WHERE id=? AND agent_id=? AND enabled=1").bind(online).bind(now()).bind(now()).bind(p.printer_id).bind(agent.to_string()).execute(&state.pool).await.map_err(internal)?;
        }
        Some(agent_message::Payload::JobReceived(r)) => {
            let row = sqlx::query_as::<_, (Vec<u8>, String)>(
                "SELECT payload_digest,state FROM print_jobs WHERE id=? AND agent_id=?",
            )
            .bind(&r.job_id)
            .bind(agent.to_string())
            .fetch_optional(&state.pool)
            .await
            .map_err(internal)?
            .ok_or_else(|| Status::not_found("job not found"))?;
            if hex(&row.0) != r.sha256 {
                return Err(Status::invalid_argument("job digest mismatch"));
            }
            if row.1 == "queued" {
                let changed = sqlx::query("UPDATE print_jobs SET state='delivered',delivered_at=? WHERE id=? AND agent_id=? AND state='queued'").bind(now()).bind(&r.job_id).bind(agent.to_string()).execute(&state.pool).await.map_err(internal)?.rows_affected();
                if changed == 1
                    && let Ok(job_id) = Uuid::parse_str(&r.job_id)
                {
                    job_event(
                        job_id,
                        JobEvent::Delivered,
                        "delivered",
                        None,
                        None,
                        JobCounts::default(),
                    );
                }
            }
            if outstanding.as_deref() == Some(&r.job_id) {
                *outstanding = None;
            }
        }
        Some(agent_message::Payload::JobProgress(p)) => {
            if let Some(j) = p.job {
                update_job(state, agent, &j, false).await?
            }
        }
        Some(agent_message::Payload::JobResult(r)) => {
            if let Some(j) = r.job {
                update_job(state, agent, &j, true).await?
            }
        }
        Some(agent_message::Payload::Hello(_)) | None => {
            return Err(Status::invalid_argument("unexpected message"));
        }
    }
    Ok(())
}

async fn update_job(
    state: &AppState,
    agent: Uuid,
    job: &wire::JobStatus,
    result: bool,
) -> Result<(), Status> {
    let terminal = result || job.terminal;
    let valid = matches!(
        job.state.as_str(),
        "queued"
            | "running"
            | "cancel-requested"
            | "cancelled-before-send"
            | "cancelled-partial"
            | "outcome-unknown"
            | "completed"
            | "failed"
    );
    if !valid {
        return Err(Status::invalid_argument("invalid job state"));
    }
    let cloud_state = if terminal {
        job.state.as_str()
    } else if job.state == "queued" {
        "delivered"
    } else {
        "running"
    };
    let updated_at = now();
    let changed = sqlx::query("UPDATE print_jobs SET state=?,terminal_outcome=CASE WHEN ? THEN ? ELSE terminal_outcome END,action=?,last_completed_action=MAX(last_completed_action,?),action_count=MAX(action_count,?),bytes_sent=MAX(bytes_sent,?),total_bytes=MAX(total_bytes,?),write_may_have_occurred=(write_may_have_occurred OR ?),error_code=NULLIF(?,''),started_at=CASE WHEN ?='running' THEN COALESCE(started_at,?) ELSE started_at END,terminal_at=CASE WHEN ? THEN COALESCE(terminal_at,?) ELSE terminal_at END WHERE id=? AND agent_id=? AND terminal_at IS NULL")
        .bind(cloud_state).bind(terminal).bind(if terminal{Some(job.state.as_str())}else{None}).bind(&job.state).bind(job.last_completed_action).bind(job.action_count as i64).bind(job.bytes_sent as i64).bind(job.total_bytes as i64).bind(job.potentially_accepted_write).bind(&job.error_code).bind(cloud_state).bind(updated_at).bind(terminal).bind(updated_at).bind(&job.job_id).bind(agent.to_string()).execute(&state.pool).await.map_err(internal)?.rows_affected();
    if changed == 1
        && let Ok(job_id) = Uuid::parse_str(&job.job_id)
    {
        let elapsed = if terminal {
            sqlx::query_scalar::<_, i64>(
                "SELECT created_at FROM print_jobs WHERE id=? AND agent_id=?",
            )
            .bind(&job.job_id)
            .bind(agent.to_string())
            .fetch_optional(&state.pool)
            .await
            .map_err(internal)?
            .map(|created_at| duration_ms(created_at, updated_at))
        } else {
            None
        };
        job_event(
            job_id,
            if terminal {
                JobEvent::Terminal
            } else {
                JobEvent::Progress
            },
            cloud_state,
            terminal.then_some(job.state.as_str()),
            elapsed,
            JobCounts {
                action_count: job.action_count,
                bytes_sent: job.bytes_sent,
                total_bytes: job.total_bytes,
            },
        );
    }
    Ok(())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn internal(_error: sqlx::Error) -> Status {
    tracing::error!(error_code = "database");
    Status::internal("broker failure")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protobuf_contract_matches_the_agent_checkout_when_present() {
        let local = include_str!("../proto/makersbrain/print/agent/v1/agent.proto");
        let agent =
            std::path::Path::new("../mb-printer-cli/proto/makersbrain/print/agent/v1/agent.proto");
        if agent.is_file() {
            let normalize = |value: &str| value.split_whitespace().collect::<String>();
            assert_eq!(
                normalize(local),
                normalize(&std::fs::read_to_string(agent).unwrap())
            );
        }
    }

    #[tokio::test]
    async fn agent_progress_keeps_action_boundary_fields_for_the_json_api() {
        let directory = tempfile::tempdir().unwrap();
        let config =
            crate::config::Config::template(directory.path().join("cloud.sqlite3"), "a".repeat(64));
        let pool = crate::db::open(&config.database_path).await.unwrap();
        let tenant = config.tenant.id.to_string();
        let agent = Uuid::new_v4();
        let printer = Uuid::new_v4();
        let job_id = Uuid::new_v4();
        sqlx::query("INSERT INTO printer_agents(id,tenant_id,display_name,state,created_by,created_at) VALUES(?,?,?,'active','test',?)").bind(agent.to_string()).bind(&tenant).bind("agent").bind(now()).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO printers(id,tenant_id,agent_id,display_name,model,enabled,online,created_at,updated_at) VALUES(?,?,?,?,?,1,1,?,?)").bind(printer.to_string()).bind(&tenant).bind(agent.to_string()).bind("printer").bind("m110").bind(now()).bind(now()).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO print_jobs(id,tenant_id,submitted_by,source,agent_id,printer_id,payload_digest,idempotency_key,request_digest,state,created_at,delete_payload_at) VALUES(?,?,?,?,?,?,X'00','key',X'00','delivered',?,?)").bind(job_id.to_string()).bind(&tenant).bind("test").bind("test").bind(agent.to_string()).bind(printer.to_string()).bind(now()).bind(now()+60).execute(&pool).await.unwrap();
        let state = AppState {
            pool: pool.clone(),
            config: std::sync::Arc::new(config),
        };
        update_job(
            &state,
            agent,
            &wire::JobStatus {
                job_id: job_id.to_string(),
                state: "running".into(),
                terminal: false,
                last_completed_action: 7,
                bytes_sent: 128,
                total_bytes: 256,
                potentially_accepted_write: true,
                error_code: String::new(),
                action_count: 12,
            },
            false,
        )
        .await
        .unwrap();
        let row = sqlx::query_as::<_, (i64, i64, i64, i64)>("SELECT last_completed_action,action_count,bytes_sent,total_bytes FROM print_jobs WHERE id=?").bind(job_id.to_string()).fetch_one(&pool).await.unwrap();
        assert_eq!(row, (7, 12, 128, 256));
    }
}
