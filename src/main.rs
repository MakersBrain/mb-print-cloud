// SPDX-License-Identifier: AGPL-3.0-or-later
mod api;
mod config;
mod db;
mod grpc;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Parser, Subcommand};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Init {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        database: Option<PathBuf>,
    },
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    match Cli::parse().command {
        Command::Init {
            config: path,
            database,
        } => {
            if path.exists() {
                anyhow::bail!("refusing to overwrite existing config")
            }
            let mut raw = [0u8; 32];
            rand::rng().fill_bytes(&mut raw);
            let token = format!("mbpc_{}", URL_SAFE_NO_PAD.encode(raw));
            let digest = format!("{:x}", Sha256::digest(token.as_bytes()));
            let database = database.unwrap_or_else(|| path.with_extension("sqlite3"));
            let generated = config::Config::template(database, digest);
            config::save(&path, &generated)?;
            println!("tenant_id={}", generated.tenant.id);
            println!("api_token={token}");
            println!("The API token is shown once; store it securely.");
        }
        Command::Serve { config: path } => {
            let config = Arc::new(config::load(&path)?);
            let pool = db::open(&config.database_path).await?;
            sqlx::query("UPDATE printers SET online=0")
                .execute(&pool)
                .await?;
            sqlx::query(
                "UPDATE print_jobs SET request=NULL WHERE terminal_at IS NOT NULL AND delete_payload_at<=?",
            )
            .bind(db::now())
            .execute(&pool)
            .await?;
            let state = api::AppState {
                pool,
                config: config.clone(),
            };
            let api_listener = tokio::net::TcpListener::bind(config.api_listen).await?;
            let broker = grpc::Broker {
                state: state.clone(),
            };
            let api = axum::serve(api_listener, api::router(state));
            let grpc = tonic::transport::Server::builder()
                .add_service(
                    grpc::wire::printer_agent_service_server::PrinterAgentServiceServer::new(
                        broker,
                    ),
                )
                .serve(config.grpc_listen);
            tracing::info!(api=%config.api_listen,grpc=%config.grpc_listen,"mb-print-cloud ready");
            tokio::select! { result=api=>result?, result=grpc=>result?, _=tokio::signal::ctrl_c()=>{} }
        }
    }
    Ok(())
}
