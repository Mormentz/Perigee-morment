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
use tower::{Layer, Service};
use tracing::info;
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

// ── API Versioning Middleware ──────────────────────────────────────────────────

pub const DEFAULT_API_VERSION: &str = "v1";
pub const SUPPORTED_API_VERSIONS: &[&str] = &["v1", "1"];
pub const API_VERSION_HEADER: &str = "x-api-version";
pub const ACCEPT_VERSION_HEADER: &str = "accept-version";
pub const ALT_API_VERSION_HEADER: &str = "api-version";

/// Extracts and validates the requested API version from the URI path or headers.
///
/// Version resolution priority:
/// 1. URI path prefix (e.g. `/v1/...` -> `"v1"`, `/v2/...` -> `"v2"`)
/// 2. Header `X-API-Version`
/// 3. Header `Accept-Version`
/// 4. Header `Api-Version`
/// 5. Header `Accept` parameter (e.g. `version=1` or `vnd.perigee.v1`)
/// 6. Default to `DEFAULT_API_VERSION` ("v1")
pub async fn api_version_middleware(request: Request, next: Next) -> Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::Json;

    let path = request.uri().path().to_string();

    // Determine requested version
    let mut requested_version: Option<String> = None;

    // Check URI prefix (e.g. /v1/... or /v2/...)
    if path.starts_with("/v") {
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        if let Some(first_segment) = segments.first() {
            if first_segment.starts_with('v') && first_segment[1..].chars().all(|c| c.is_ascii_digit()) {
                requested_version = Some(first_segment.to_string());
            }
        }
    }

    // Check headers if no URI version prefix found
    if requested_version.is_none() {
        if let Some(val) = request.headers().get(API_VERSION_HEADER).and_then(|h| h.to_str().ok()) {
            requested_version = Some(val.trim().to_string());
        } else if let Some(val) = request.headers().get(ACCEPT_VERSION_HEADER).and_then(|h| h.to_str().ok()) {
            requested_version = Some(val.trim().to_string());
        } else if let Some(val) = request.headers().get(ALT_API_VERSION_HEADER).and_then(|h| h.to_str().ok()) {
            requested_version = Some(val.trim().to_string());
        } else if let Some(val) = request.headers().get("accept").and_then(|h| h.to_str().ok()) {
            if val.contains("vnd.perigee.v1") || val.contains("version=1") || val.contains("version=v1") {
                requested_version = Some("v1".to_string());
            } else if val.contains("vnd.perigee.v") {
                if let Some(pos) = val.find("vnd.perigee.v") {
                    let sub = &val[pos + 12..];
                    let ver: String = sub.chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
                    if !ver.is_empty() {
                        requested_version = Some(format!("v{}", ver));
                    }
                }
            }
        }
    }

    let version = requested_version.unwrap_or_else(|| DEFAULT_API_VERSION.to_string());
    let normalized = version.trim().to_lowercase();

    // Check if supported
    let is_supported = SUPPORTED_API_VERSIONS.iter().any(|&v| v == normalized || format!("v{}", v) == normalized);

    if !is_supported {
        tracing::warn!(
            version = %version,
            path = %path,
            "Unsupported API version requested"
        );

        let body = Json(serde_json::json!({
            "error": "UNSUPPORTED_API_VERSION",
            "message": format!(
                "API version '{}' is not supported. Supported versions: {}",
                version,
                SUPPORTED_API_VERSIONS.join(", ")
            )
        }));

        let mut res = (StatusCode::BAD_REQUEST, body).into_response();
        res.headers_mut().insert(
            HeaderName::from_static(API_VERSION_HEADER),
            HeaderValue::from_static("v1"),
        );
        return res;
    }

    let mut response = next.run(request).await;

    response.headers_mut().insert(
        HeaderName::from_static(API_VERSION_HEADER),
        HeaderValue::from_static("v1"),
    );

    response
}

#[cfg(test)]
mod version_middleware_tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    async fn test_app() -> Router {
        Router::new()
            .route("/health", get(|| async { "ok" }))
            .nest("/v1", Router::new().route("/health", get(|| async { "ok" })))
            .layer(axum::middleware::from_fn(api_version_middleware))
    }

    #[tokio::test]
    async fn test_default_version_header() {
        let app = test_app().await;
        let req = Request::builder().uri("/health").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get("x-api-version").unwrap().to_str().unwrap(),
            "v1"
        );
    }

    #[tokio::test]
    async fn test_uri_v1_version() {
        let app = test_app().await;
        let req = Request::builder().uri("/v1/health").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get("x-api-version").unwrap().to_str().unwrap(),
            "v1"
        );
    }

    #[tokio::test]
    async fn test_header_v1_version() {
        let app = test_app().await;
        let req = Request::builder()
            .uri("/health")
            .header("x-api-version", "v1")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get("x-api-version").unwrap().to_str().unwrap(),
            "v1"
        );
    }

    #[tokio::test]
    async fn test_unsupported_uri_version() {
        let app = test_app().await;
        let req = Request::builder().uri("/v2/health").body(Body::empty()).unwrap();
        let res = app.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            res.headers().get("x-api-version").unwrap().to_str().unwrap(),
            "v1"
        );
    }

    #[tokio::test]
    async fn test_unsupported_header_version() {
        let app = test_app().await;
        let req = Request::builder()
            .uri("/health")
            .header("x-api-version", "v2")
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            res.headers().get("x-api-version").unwrap().to_str().unwrap(),
            "v1"
        );
    }
}