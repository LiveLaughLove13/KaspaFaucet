use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, Json},
    routing::{get, post},
    Router,
};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_addresses::Address;
use kaspa_hashes::Hash;
use kaspa_consensus_core::network::{NetworkId, NetworkType};
use kaspa_utils::hex::ToHex;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tracing::{info, warn, error};
use tracing_subscriber;

mod config;
mod faucet;
mod rate_limiter;

use config::Config;
use faucet::Faucet;
use rate_limiter::RateLimiter;

 fn format_kas_from_sompi(amount_sompi: u64) -> String {
     const SOMPI_PER_KAS: u64 = 100_000_000;
     let whole = amount_sompi / SOMPI_PER_KAS;
     let frac = amount_sompi % SOMPI_PER_KAS;
     format!("{}.{:08}", whole, frac)
 }

#[derive(Serialize)]
struct StatusResponse {
    active: bool,
    balance_kas: String,
    next_claim_seconds: u64,
}

#[derive(Deserialize)]
struct ClaimRequest {
    address: String,
}

#[derive(Serialize)]
struct ClaimResponse {
    transaction_id: String,
    amount_kas: String,
    next_claim_seconds: u64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

impl From<anyhow::Error> for ErrorResponse {
    fn from(err: anyhow::Error) -> Self {
        ErrorResponse { error: err.to_string() }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config = Config::load()?;
    info!("Loaded config: {:?}", config);

    // Connect to Kaspa node
    let client = connect_to_kaspad(&config.kaspad_url).await?;
    let network_id = client.get_network_id().await?;
    if network_id != NetworkId::new(NetworkType::Testnet12) {
        anyhow::bail!("Node is not on testnet-12");
    }

    // Initialize faucet
    let faucet = Arc::new(RwLock::new(Faucet::new(
        config.faucet_private_key.clone(),
        config.amount_per_claim,
        config.claim_interval_seconds,
    )));

    // Initialize rate limiter
    let rate_limiter = Arc::new(RateLimiter::new());

    // Build router
    let app = Router::new()
        .route("/", get(|| async { Html("<h1>Kaspa Testnet-12 Faucet</h1>") }))
        .route("/status", get(status_handler))
        .route("/claim", post(claim_handler))
        .layer(CorsLayer::permissive())
        .with_state((client, faucet, rate_limiter, config));

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    info!("Faucet listening on http://{}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

async fn connect_to_kaspad(url: &str) -> anyhow::Result<GrpcClient> {
    let grpc_url = if url.starts_with("grpc://") {
        url.to_string()
    } else {
        format!("grpc://{}", url.replace("http://", "").replace("https://", ""))
    };

    let client = GrpcClient::connect(&grpc_url).await?;
    Ok(client)
}

async fn status_handler(
    State((client, faucet, _, config)): State<(GrpcClient, Arc<RwLock<Faucet>>, Arc<RateLimiter>, Config)>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let balance = client.get_balance().await.map_err(|e| {
        error!("Failed to get balance: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let faucet_read = faucet.read().await;
    Ok(Json(StatusResponse {
        active: true,
        balance_kas: format_kas_from_sompi(balance),
        next_claim_seconds: faucet_read.claim_interval_seconds,
    }))
}

async fn claim_handler(
    State((client, faucet, rate_limiter, config)): State<(GrpcClient, Arc<RwLock<Faucet>>, Arc<RateLimiter>, Config)>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    Json(payload): Json<ClaimRequest>,
) -> Result<Json<ClaimResponse>, StatusCode> {
    let ip = addr.ip().to_string();
    info!("Claim request from IP: {}, address: {}", ip, payload.address);

    // Validate address
    let address = payload.address.parse::<Address>().map_err(|e| {
        warn!("Invalid address: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    // Rate limit check
    if !rate_limiter.try_claim(&ip) {
        warn!("Rate limit exceeded for IP: {}", ip);
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // Perform faucet send
    let mut faucet_write = faucet.write().await;
    let tx_id = match faucet_write.send(&client, &address, config.amount_per_claim).await {
        Ok(id) => id,
        Err(e) => {
            error!("Faucet send failed: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    Ok(Json(ClaimResponse {
        transaction_id: tx_id.to_hex(),
        amount_kas: format_kas_from_sompi(config.amount_per_claim),
        next_claim_seconds: faucet_write.claim_interval_seconds,
    }))
}
