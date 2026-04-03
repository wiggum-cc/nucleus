use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::{trace::SdkTracerProvider, Resource};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Build an OTLP tracer if endpoint env vars are set.
fn build_otlp_tracer() -> anyhow::Result<Option<opentelemetry_sdk::trace::SdkTracer>> {
    let endpoint = std::env::var("NUCLEUS_OTLP_ENDPOINT")
        .ok()
        .or_else(|| std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok())
        .filter(|value| !value.trim().is_empty());

    if let Some(endpoint) = endpoint {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_protocol(Protocol::HttpBinary)
            .with_endpoint(endpoint.clone())
            .build()
            .map_err(|e| {
                anyhow::anyhow!("Failed to build OTLP exporter for {}: {}", endpoint, e)
            })?;

        let provider = SdkTracerProvider::builder()
            .with_resource(
                Resource::builder_empty()
                    .with_service_name("nucleus")
                    .build(),
            )
            .with_simple_exporter(exporter)
            .build();
        Ok(Some(provider.tracer("nucleus")))
    } else {
        Ok(None)
    }
}

/// Initialize tracing with optional OTLP export.
///
/// Uses a macro internally because tracing-subscriber layer types are not
/// object-safe and each combination produces a distinct concrete type.
macro_rules! init_subscriber {
    ($env_filter:expr, $fmt_layer:expr, $tracer:expr) => {
        if let Some(tracer) = $tracer {
            tracing_subscriber::registry()
                .with($env_filter)
                .with($fmt_layer)
                .with(tracing_opentelemetry::layer().with_tracer(tracer))
                .init();
        } else {
            tracing_subscriber::registry()
                .with($env_filter)
                .with($fmt_layer)
                .init();
        }
    };
}

/// Initialize the tracing subscriber with env-filter and optional OTLP export.
pub fn init_tracing() -> anyhow::Result<()> {
    let tracer = build_otlp_tracer()?;

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer();
    init_subscriber!(env_filter, fmt_layer, tracer);

    Ok(())
}
