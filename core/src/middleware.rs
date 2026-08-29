//! Axum middleware helpers.
//!
//! ## Middleware included
//!
//! ### `correlation_id_middleware`
//! Propagates (or generates) an `x-correlation-id` / `x-request-id` pair and
//! emits a structured tracing span per request.
//!
//! ### `metrics_layer` / `MetricsMiddleware`
//! Tower [`Layer`] that auto-instruments every HTTP request with three
//! Prometheus metrics from [`crate::metrics::Metrics`]:
//!
//! - `http_requests_total{method, route, status}` — counter
//! - `http_request_duration_seconds{method, route}` — histogram
//! - `http_requests_in_flight{method, route}` — gauge (RAII-tracked)
//!
//! Wire it into the Router **before** `TraceLayer` so it captures the
//! matched route pattern rather than the raw URI:
//!
//! ```ignore
//! let app = Router::new()
//!     ...
//!     .layer(MetricsLayer::new(Arc::clone(&metrics)))
//!     .layer(TraceLayer::new_for_http());
//! ```

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use serde_json;
use tower::{Layer, Service};
use tracing::{info, Span};
use uuid::Uuid;

use crate::metrics::Metrics;

// ── Correlation-ID middleware ────────────────────────────────────────────────

const CORRELATION_ID_HEADER: &str = "x-correlation-id";
const REQUEST_ID_HEADER: &str = "x-request-id";

pub async fn correlation_id_middleware(request: Request, next: Next) -> Response {
    let correlation_id = request
        .headers()
        .get(CORRELATION_ID_HEADER)
        .and_then(|h| h.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let request_id = Uuid::new_v4().to_string();

    let span = tracing::info_span!(
        "http_request",
        correlation_id = %correlation_id,
        request_id = %request_id,
        method = %request.method(),
        uri = %request.uri(),
    );

    let mut request = request;
    request.headers_mut().insert(
        HeaderName::from_static(CORRELATION_ID_HEADER),
        HeaderValue::from_str(&correlation_id).unwrap(),
    );
    request.headers_mut().insert(
        HeaderName::from_static(REQUEST_ID_HEADER),
        HeaderValue::from_str(&request_id).unwrap(),
    );

    let _enter = span.enter();
    let start = Instant::now();
    let method = request.method().clone();
    let uri = request.uri().clone();

    let mut response = next.run(request).await;

    let latency = start.elapsed();
    let status = response.status();

    info!(
        correlation_id = %correlation_id,
        request_id = %request_id,
        method = %method,
        uri = %uri,
        status = %status,
        latency_ms = latency.as_millis(),
        "Request completed"
    );

    response.headers_mut().insert(
        HeaderName::from_static(CORRELATION_ID_HEADER),
        HeaderValue::from_str(&correlation_id).unwrap(),
    );
    response.headers_mut().insert(
        HeaderName::from_static(REQUEST_ID_HEADER),
        HeaderValue::from_str(&request_id).unwrap(),
    );

    response
}

// ── Prometheus HTTP metrics layer ────────────────────────────────────────────

/// Tower [`Layer`] that records HTTP metrics for every request.
///
/// Clone is cheap — it only clones an `Arc`.
#[derive(Clone)]
pub struct MetricsLayer {
    metrics: Arc<Metrics>,
}

impl MetricsLayer {
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self { metrics }
    }
}

impl<S> Layer<S> for MetricsLayer {
    type Service = MetricsMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MetricsMiddleware {
            inner,
            metrics: Arc::clone(&self.metrics),
        }
    }
}

/// Tower [`Service`] wrapper that wraps each call with Prometheus bookkeeping.
#[derive(Clone)]
pub struct MetricsMiddleware<S> {
    inner: S,
    metrics: Arc<Metrics>,
}

impl<S> Service<Request<Body>> for MetricsMiddleware<S>
where
    S: Service<Request<Body>, Response = Response> + Send + Clone + 'static,
    S::Future: Send + 'static,
    S::Error: std::fmt::Display,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let metrics = Arc::clone(&self.metrics);
        let method = req.method().to_string();

        // Prefer the matched-route pattern (`/analyze/:id`) over the raw URI so
        // cardinality stays bounded.  Axum injects this via the
        // `axum::extract::MatchedPath` extension — fall back to the path
        // component of the URI when the extension is absent (e.g. 404 paths).
        let route = req
            .extensions()
            .get::<axum::extract::MatchedPath>()
            .map(|mp| mp.as_str().to_string())
            .unwrap_or_else(|| {
                let p = req.uri().path().to_string();
                // Truncate long unknown paths so we don't blow up cardinality.
                if p.len() > 64 { "unknown".to_string() } else { p }
            });

        // Increment the in-flight gauge; decrement it when the future drops.
        metrics
            .http_requests_in_flight
            .with_label_values(&[&method, &route])
            .inc();

        let start = Instant::now();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Always decrement in-flight when done (success or error).
            let _guard = InFlightGuard {
                metrics: Arc::clone(&metrics),
                method: method.clone(),
                route: route.clone(),
            };

            let result = inner.call(req).await;

            let elapsed = start.elapsed().as_secs_f64();
            let status = match &result {
                Ok(resp) => resp.status().as_u16().to_string(),
                Err(_) => "500".to_string(),
            };

            metrics
                .http_requests_total
                .with_label_values(&[&method, &route, &status])
                .inc();

            metrics
                .http_request_duration_seconds
                .with_label_values(&[&method, &route])
                .observe(elapsed);

            result
        })
    }
}

/// RAII guard that decrements `http_requests_in_flight` when dropped.
struct InFlightGuard {
    metrics: Arc<Metrics>,
    method: String,
    route: String,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.metrics
            .http_requests_in_flight
            .with_label_values(&[&self.method, &self.route])
            .dec();
    }
}

// ── Method-Not-Allowed normaliser ────────────────────────────────────────────

/// Intercept Axum's automatic `405 Method Not Allowed` responses and rewrite
/// them into the standard `{ "error": "METHOD_NOT_ALLOWED", "message": "…" }`
/// envelope so every error code — 404, 405, and application errors — looks
/// identical to the client.
///
/// Axum generates 405 internally (before reaching any handler) when the path
/// matches a route but the HTTP method does not.  This middleware runs
/// *after* the response is produced and normalises those bare 405 bodies.
pub async fn method_not_allowed_middleware(request: Request, next: Next) -> Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::Json;

    let method = request.method().clone();
    let uri = request.uri().clone();
    let response = next.run(request).await;

    if response.status() == StatusCode::METHOD_NOT_ALLOWED {
        tracing::debug!(
            method = %method,
            uri = %uri,
            "Method not allowed"
        );
        let body = Json(serde_json::json!({
            "error": "METHOD_NOT_ALLOWED",
            "message": format!("Method {} is not allowed for {}", method, uri.path())
        }));
        return (StatusCode::METHOD_NOT_ALLOWED, body).into_response();
    }

    response
}