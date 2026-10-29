use clap::Parser;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

mod auth;
mod config;
mod db;
mod handoff;
mod push;
mod server;
mod sip;

#[derive(Parser)]
#[command(name = "aria-gateway", about = "Aria SIP Push Gateway")]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "gateway.toml")]
    config: String,

    /// Override listen address
    #[arg(long)]
    listen: Option<String>,

    /// Start even with a missing, placeholder or short JWT secret. For local
    /// development and tests only; never in production. Also enabled by
    /// ARIA_GATEWAY_INSECURE_DEV_SECRET=1.
    #[arg(long)]
    insecure_dev_secret: bool,
}

/// Env var equivalent of `--insecure-dev-secret`.
const INSECURE_DEV_SECRET_ENV: &str = "ARIA_GATEWAY_INSECURE_DEV_SECRET";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let config = config::GatewayConfig::load(&cli.config)?;

    if let Err(e) = config.auth.check_jwt_secret() {
        let override_env = std::env::var(INSECURE_DEV_SECRET_ENV)
            .is_ok_and(|v| matches!(v.trim(), "1" | "true" | "yes"));
        if cli.insecure_dev_secret || override_env {
            tracing::warn!(
                "INSECURE: {e} — starting anyway because the dev override is set. \
                 Anyone who knows this secret can mint tokens for any user."
            );
        } else {
            anyhow::bail!(
                "refusing to start: {e}. Set auth.secret to a random value of at least \
                 {} characters (e.g. `openssl rand -hex 32`). For local development only, \
                 pass --insecure-dev-secret or set {INSECURE_DEV_SECRET_ENV}=1.",
                config::MIN_JWT_SECRET_LEN
            );
        }
    }

    let listen_addr = cli.listen.unwrap_or_else(|| config.server.listen.clone());

    tracing::info!("Aria Push Gateway v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("Public URL: {}", config.server.public_url);

    // Initialize database
    let db = db::Database::connect(&config.database.url).await?;
    db.migrate().await?;
    tracing::info!("Database ready");

    // Initialize SIP proxy manager
    let sip_proxy = Arc::new(sip::SipProxyManager::new());

    // Initialize push notification clients
    let push_manager = Arc::new(push::PushManager::new(&config.push)?);

    // Initialize call handoff manager
    let handoff = Arc::new(handoff::HandoffManager::new());

    // Restore active device registrations from database
    let devices = db.list_active_devices().await?;
    tracing::info!("Restoring {} device registrations", devices.len());
    for device in devices {
        // Register push token so incoming calls can send notifications
        push_manager.register_device(device.clone()).await;

        if let Err(e) = sip_proxy
            .register_device(
                device.id.clone(),
                device.sip_config(),
                push_manager.clone(),
                handoff.clone(),
            )
            .await
        {
            tracing::warn!("Failed to restore registration for {}: {}", device.id, e);
        }
    }

    let token_issuer_key = config.auth.resolve_token_issuer_key();
    config
        .auth
        .check_issuer_key(token_issuer_key.as_deref())
        .map_err(|e| anyhow::anyhow!("refusing to start: {e}"))?;
    match &token_issuer_key {
        None => tracing::warn!(
            "TOKEN_ISSUER_KEY is not set — POST /v1/auth/token will refuse every request"
        ),
        Some(key) if key.len() < 32 => tracing::warn!(
            "TOKEN_ISSUER_KEY is shorter than 32 characters — use a long random value"
        ),
        Some(_) => {}
    }

    // Build and start HTTP server
    let app = server::build_router(
        db.clone(),
        sip_proxy.clone(),
        push_manager.clone(),
        handoff.clone(),
        config.auth.secret.clone(),
        config.auth.token_expiry_secs,
        token_issuer_key,
    );

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!("Listening on {}", listen_addr);

    axum::serve(listener, app).await?;
    Ok(())
}
