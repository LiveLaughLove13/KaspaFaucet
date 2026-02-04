use axum::{
    extract::ConnectInfo,
    http::StatusCode,
    response::Html,
    routing::{get, post},
    Extension, Json, Router,
};
use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::{
    sign::sign_with_multiple_v2,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{SignableTransaction, Transaction, TransactionInput, TransactionOutput, UtxoEntry},
};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode, RpcTransaction};
use kaspa_txscript::standard::pay_to_address_script;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, str::FromStr, sync::Arc};
use tokio::time::Duration;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tracing::{error, info, warn};

pub mod config;
pub mod rate_limiter;

use config::Config;

const INDEX_HTML: &str = include_str!("../static/index.html");

fn format_kas_from_sompi(amount_sompi: u64) -> String {
    const SOMPI_PER_KAS: u64 = 100_000_000;
    let whole = amount_sompi / SOMPI_PER_KAS;
    let frac = amount_sompi % SOMPI_PER_KAS;
    format!("{}.{}", whole, format!("{:08}", frac))
}

#[derive(Serialize)]
struct StatusResponse {
    active: bool,
    faucet_address: String,
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

#[derive(Clone)]
struct AppState {
    client: GrpcClient,
    faucet_address: Address,
    faucet_private_key: [u8; 32],
    amount_per_claim: u64,
    claim_interval_seconds: u64,
    rate_limiter: Arc<rate_limiter::RateLimiter>,
}

pub async fn router_from_config(config: Config) -> anyhow::Result<Router> {
    let faucet_private_key = secp256k1::SecretKey::from_str(&config.faucet_private_key)
        .map_err(|e| anyhow::anyhow!("Invalid faucet_private_key (expected 32-byte hex): {e}"))?;
    let faucet_private_key_bytes = faucet_private_key.secret_bytes();

    let public_key = secp256k1::PublicKey::from_secret_key_global(&faucet_private_key);
    let (x_only_public_key, _) = public_key.x_only_public_key();
    let faucet_address = Address::new(Prefix::Mainnet, Version::PubKey, &x_only_public_key.serialize());

    let grpc_url = if config.kaspad_url.starts_with("grpc://") {
        config.kaspad_url.clone()
    } else {
        format!(
            "grpc://{}",
            config
                .kaspad_url
                .replace("http://", "")
                .replace("https://", "")
        )
    };

    let client = match GrpcClient::connect_with_args(
        NotificationMode::Direct,
        grpc_url.clone(),
        None,
        true,
        None,
        false,
        Some(500_000),
        Default::default(),
    )
    .await
    {
        Ok(c) => {
            c.start(None).await;
            c
        }
        Err(e) => {
            warn!("connect_with_args failed, falling back to connect(): {:?}", e);
            let c = GrpcClient::connect(grpc_url).await?;
            c.start(None).await;
            c
        }
    };

    let _info = client.get_info().await?;

    let rate_limiter = Arc::new(rate_limiter::RateLimiter::new(Duration::from_secs(
        config.claim_interval_seconds,
    )));

    let state = AppState {
        client,
        faucet_address,
        faucet_private_key: faucet_private_key_bytes,
        amount_per_claim: config.amount_per_claim,
        claim_interval_seconds: config.claim_interval_seconds,
        rate_limiter,
    };

    let static_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static");

    let app = Router::new()
        .route("/", get(|| async { Html(INDEX_HTML) }))
        .nest_service("/static", ServeDir::new(static_dir))
        .route("/status", get(status_handler))
        .route("/claim", post(claim_handler))
        .layer(CorsLayer::permissive())
        .layer(Extension(state));

    Ok(app)
}

async fn status_handler(Extension(state): Extension<AppState>) -> Result<Json<StatusResponse>, StatusCode> {
    let balance = state
        .client
        .get_balance_by_address(state.faucet_address.clone())
        .await
        .map_err(|e| {
            error!("Failed to get balance: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(StatusResponse {
        active: true,
        faucet_address: state.faucet_address.to_string(),
        balance_kas: format_kas_from_sompi(balance),
        next_claim_seconds: state.claim_interval_seconds,
    }))
}

async fn claim_handler(
    Extension(state): Extension<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<ClaimRequest>,
) -> Result<Json<ClaimResponse>, StatusCode> {
    let ip = addr.ip().to_string();
    info!("Claim request from IP: {}, address: {}", ip, payload.address);

    if !payload.address.starts_with("kaspa:") {
        warn!("Invalid address prefix (expected kaspa:): {}", payload.address);
        return Err(StatusCode::BAD_REQUEST);
    }

    let destination: Address = payload.address.as_str().try_into().map_err(|e| {
        warn!("Invalid address: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    if !state.rate_limiter.try_claim(&ip) {
        warn!("Rate limit exceeded for IP: {}", ip);
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let tx_id = submit_faucet_transaction(
        &state.client,
        &state.faucet_address,
        &destination,
        state.amount_per_claim,
        &state.faucet_private_key,
    )
    .await
    .map_err(|e| {
        error!("Faucet send failed: {e:?}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(ClaimResponse {
        transaction_id: tx_id.to_string(),
        amount_kas: format_kas_from_sompi(state.amount_per_claim),
        next_claim_seconds: state.claim_interval_seconds,
    }))
}

async fn submit_faucet_transaction(
    client: &GrpcClient,
    faucet_address: &Address,
    destination: &Address,
    amount: u64,
    private_key: &[u8; 32],
) -> anyhow::Result<kaspa_rpc_core::RpcTransactionId> {
    let utxos = client
        .get_utxos_by_addresses(vec![faucet_address.clone()])
        .await
        .map_err(|e| anyhow::anyhow!("get_utxos_by_addresses failed: {e}"))?;

    if utxos.is_empty() {
        anyhow::bail!("Faucet has no UTXOs. Fund address {faucet_address} first.");
    }

    const FEE_PER_INPUT_SOMPI: u64 = 2000;
    const DUST_SOMPI: u64 = 1000;
    const MAX_INPUTS: usize = 200;

    let mut utxos = utxos;
    utxos.sort_by_key(|e| std::cmp::Reverse(e.utxo_entry.amount));

    let mut selected = Vec::new();
    let mut total_in: u64 = 0;

    for entry in utxos.into_iter() {
        if selected.len() >= MAX_INPUTS {
            anyhow::bail!(
                "Faucet UTXO set is too fragmented: would exceed {} inputs to fund the claim+fee. Consolidate funds to larger UTXOs.",
                MAX_INPUTS
            );
        }
        let value = entry.utxo_entry.amount;
        selected.push(entry);
        total_in = total_in.saturating_add(value);

        let fee = (selected.len() as u64 + 1) * FEE_PER_INPUT_SOMPI;
        if total_in >= amount.saturating_add(fee) {
            break;
        }
    }

    let fee = (selected.len() as u64 + 1) * FEE_PER_INPUT_SOMPI;
    if total_in < amount.saturating_add(fee) {
        anyhow::bail!(
            "Insufficient faucet funds. Have {total_in} sompi, need {} sompi",
            amount + fee
        );
    }

    let mut change = total_in - amount - fee;
    if change > 0 && change < DUST_SOMPI {
        change = 0;
    }

    let inputs = selected
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let outpoint = e.outpoint.into();
            TransactionInput::new(outpoint, vec![], i as u64, 1)
        })
        .collect::<Vec<_>>();

    let mut outputs = Vec::new();
    outputs.push(TransactionOutput::new(amount, pay_to_address_script(destination)));
    if change > 0 {
        outputs.push(TransactionOutput::new(change, pay_to_address_script(faucet_address)));
    }

    let tx = Transaction::new(0, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let entries = selected.into_iter().map(|e| UtxoEntry::from(e.utxo_entry)).collect::<Vec<_>>();
    let signable_tx = SignableTransaction::with_entries(tx, entries);
    let signed_tx = sign_with_multiple_v2(signable_tx, std::slice::from_ref(private_key)).fully_signed()?;

    let rpc_transaction: RpcTransaction = signed_tx.tx.as_ref().into();
    let tx_id = client.submit_transaction(rpc_transaction, false).await?;
    Ok(tx_id)
}
