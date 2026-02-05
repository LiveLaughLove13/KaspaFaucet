use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{Html, Json},
    routing::{get, post},
    Router,
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
use std::{
    collections::HashMap,
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::net::TcpListener;
use tower_http::{cors::CorsLayer, limit::RequestBodyLimitLayer, services::ServeDir};
use tracing::{error, info, warn};

mod config;
mod rate_limiter;

use config::Config;

const INDEX_HTML: &str = include_str!("../static/index.html");

fn format_kas_from_sompi(amount_sompi: u64) -> String {
    const SOMPI_PER_KAS: u64 = 100_000_000;
    let whole = amount_sompi / SOMPI_PER_KAS;
    let frac = amount_sompi % SOMPI_PER_KAS;
    format!("{}.{:08}", whole, frac)
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

// Maximum address length to prevent DoS
const MAX_ADDRESS_LENGTH: usize = 200;
// Maximum JSON request body size (10KB)
const MAX_REQUEST_BODY_SIZE: usize = 10 * 1024;
// Transaction deduplication window (prevent duplicate transactions within 5 minutes)
const TX_DEDUP_WINDOW: Duration = Duration::from_secs(300);

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
    // Track recent transactions to prevent duplicates (key: "ip:address", value: timestamp)
    recent_transactions: Arc<Mutex<HashMap<String, Instant>>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config = Config::load()?;
    info!("Loaded config: {:?}", config);
    if config.amount_per_claim < 1_000 {
        anyhow::bail!(
            "Invalid amount_per_claim: {}. This value is in sompi (1 KAS = 100000000 sompi). Example: for 1 KAS use 100000000.",
            config.amount_per_claim
        );
    }
    let port = config.port;

    let faucet_private_key = secp256k1::SecretKey::from_str(&config.faucet_private_key)
        .map_err(|e| anyhow::anyhow!("Invalid faucet_private_key (expected 32-byte hex): {e}"))?;
    let faucet_private_key_bytes = faucet_private_key.secret_bytes();

    let public_key = secp256k1::PublicKey::from_secret_key_global(&faucet_private_key);
    let (x_only_public_key, _) = public_key.x_only_public_key();
    let faucet_address = Address::new(
        Prefix::Mainnet,
        Version::PubKey,
        &x_only_public_key.serialize(),
    );

    // Connect to kaspad
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
    info!("Connecting to kaspad at: {}", grpc_url);

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
            warn!(
                "connect_with_args failed, falling back to connect(): {:?}",
                e
            );
            let c = GrpcClient::connect(grpc_url).await?;
            c.start(None).await;
            c
        }
    };

    let info = client.get_info().await?;
    info!("Connected to kaspad: {:?}", info);

    // Enhanced rate limiter with IP and address tracking
    let rate_limiter = Arc::new(rate_limiter::RateLimiter::new(Duration::from_secs(
        config.claim_interval_seconds,
    )));

    // Transaction deduplication map
    let recent_transactions = Arc::new(Mutex::new(HashMap::new()));

    let state = AppState {
        client,
        faucet_address,
        faucet_private_key: faucet_private_key_bytes,
        amount_per_claim: config.amount_per_claim,
        claim_interval_seconds: config.claim_interval_seconds,
        rate_limiter,
        recent_transactions,
    };

    // Build router with security layers
    let app = Router::new()
        .route("/", get(|| async { Html(INDEX_HTML) }))
        .nest_service("/static", ServeDir::new("static"))
        .route("/status", get(status_handler))
        .route("/claim", post(claim_handler))
        // Limit request body size to prevent DoS
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_SIZE))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Faucet listening on http://{}", addr);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn status_handler(State(state): State<AppState>) -> Result<Json<StatusResponse>, StatusCode> {
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
    State(state): State<AppState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<ClaimRequest>,
) -> Result<Json<ClaimResponse>, StatusCode> {
    // Extract real IP address (handle proxies)
    let ip = extract_real_ip(&addr, &headers);
    info!(
        "Claim request from IP: {}, address: {}",
        ip, payload.address
    );

    // Input validation: check address length
    if payload.address.len() > MAX_ADDRESS_LENGTH {
        warn!("Address too long: {} characters", payload.address.len());
        return Err(StatusCode::BAD_REQUEST);
    }

    // Trim and normalize address
    let address_str = payload.address.trim();
    if address_str.is_empty() {
        warn!("Empty address provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    // Mainnet address prefix check (fast fail + clearer error in logs)
    if !address_str.starts_with("kaspa:") {
        warn!("Invalid address prefix (expected kaspa:): {}", address_str);
        return Err(StatusCode::BAD_REQUEST);
    }

    // Parse and validate address
    // The Address parsing will validate the format and network
    // Since we already checked for "kaspa:" prefix, this ensures mainnet
    let destination: Address = address_str.try_into().map_err(|e| {
        warn!("Invalid address format or network: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    // Check for duplicate transaction (same IP + address combination)
    {
        let mut recent_txs = state.recent_transactions.lock().unwrap();
        // Cleanup old entries
        let now = Instant::now();
        recent_txs.retain(|_, instant| now.duration_since(*instant) < TX_DEDUP_WINDOW);

        let key = format!("{}:{}", ip, address_str);
        if recent_txs.contains_key(&key) {
            warn!(
                "Duplicate transaction attempt detected: IP={}, address={}",
                ip, address_str
            );
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        recent_txs.insert(key, now);
    }

    // Check if address has received funds before (prevent new address spam)
    // This helps prevent abuse where users generate many new addresses
    let address_balance = state
        .client
        .get_balance_by_address(destination.clone())
        .await
        .map_err(|e| {
            warn!("Failed to check address balance: {}", e);
            // Don't fail the request if we can't check balance, but log it
        })
        .unwrap_or(0);

    // Rate limit check (enhanced with multiple layers of protection)
    let (allowed, reason) = state.rate_limiter.try_claim(&ip, address_str);
    if !allowed {
        warn!(
            "Rate limit exceeded for IP: {}, address: {} - Reason: {}",
            ip,
            address_str,
            reason.unwrap_or("unknown")
        );
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // Log address history for monitoring (new addresses vs existing ones)
    if address_balance == 0 {
        info!("New address claim: {} (no previous balance)", address_str);
    } else {
        info!(
            "Existing address claim: {} (balance: {} sompi)",
            address_str, address_balance
        );
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

/// Extract the real IP address from the request, handling proxies
fn extract_real_ip(addr: &SocketAddr, headers: &HeaderMap) -> String {
    // Check X-Forwarded-For header (use first IP if multiple)
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            // X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
            // We take the first one (the original client)
            if let Some(first_ip) = forwarded_str.split(',').next() {
                let ip_str = first_ip.trim();
                // Basic validation: check if it looks like an IP
                if ip_str.contains(':') || ip_str.matches('.').count() == 3 {
                    return ip_str.to_string();
                }
            }
        }
    }

    // Check X-Real-IP header
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            return ip_str.trim().to_string();
        }
    }

    // Fall back to direct connection IP
    addr.ip().to_string()
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
    outputs.push(TransactionOutput::new(
        amount,
        pay_to_address_script(destination),
    ));
    if change > 0 {
        outputs.push(TransactionOutput::new(
            change,
            pay_to_address_script(faucet_address),
        ));
    }

    let tx = Transaction::new(0, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let entries = selected
        .into_iter()
        .map(|e| UtxoEntry::from(e.utxo_entry))
        .collect::<Vec<_>>();
    let signable_tx = SignableTransaction::with_entries(tx, entries);
    let signed_tx =
        sign_with_multiple_v2(signable_tx, std::slice::from_ref(private_key)).fully_signed()?;

    let rpc_transaction: RpcTransaction = signed_tx.tx.as_ref().into();
    let tx_id = client.submit_transaction(rpc_transaction, false).await?;
    Ok(tx_id)
}
