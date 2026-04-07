use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize the tracing subscriber with env-filter.
///
/// RUST_LOG is respected but capped at `debug` to prevent `trace`-level
/// output from leaking sensitive runtime data (syscall args, memory
/// contents, etc.) in production.
pub fn init_tracing() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer();

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .with(tracing_subscriber::filter::LevelFilter::DEBUG)
        .init();
}
