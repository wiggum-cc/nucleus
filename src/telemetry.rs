use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Initialize the tracing subscriber with env-filter.
///
/// RUST_LOG is respected but capped at `debug` to prevent `trace`-level
/// output from leaking sensitive runtime data (syscall args, memory
/// contents, etc.) in production.
///
/// L12: The level cap is enforced by wrapping the env_filter with a max_level
/// directive, ensuring that even target-specific `RUST_LOG=trace` directives
/// are capped at debug.
pub fn init_tracing() {
    // When RUST_LOG is set, respect it exactly (user controls verbosity).
    // When unset, default to "info" with "nucleus=debug" for internal detail.
    // The global cap at DEBUG prevents trace-level leaks in either case (L12).
    let env_filter = match tracing_subscriber::EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(_) => tracing_subscriber::EnvFilter::new("info")
            .add_directive("nucleus=debug".parse().expect("valid tracing directive")),
    };
    let fmt_layer = tracing_subscriber::fmt::layer();

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(env_filter)
        .with(tracing_subscriber::filter::LevelFilter::DEBUG)
        .init();
}
