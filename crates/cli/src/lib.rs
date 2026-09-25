//! Loopback-only simulation UI. No remote network client lives here.
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;
use std::sync::{Arc, Mutex};
use zrpc_client::{PrivateClient, Scenario, SimulationClient};

const MAX_BODY: usize = 16 * 1024; // Design §9 request bound.
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; worker-src 'none'";

#[derive(Clone)]
pub struct LocalSession {
    host: String,
    origin: String,
    bootstrap: Arc<Mutex<Option<String>>>,
    capability: String,
}

fn random_token() -> Result<String, &'static str> {
    let mut bytes = [0; 32]; // 256-bit local capability, using OS CSPRNG.
    getrandom::fill(&mut bytes).map_err(|_| "OS randomness unavailable")?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

impl LocalSession {
    pub fn new(address: std::net::SocketAddr) -> Result<Self, &'static str> {
        if address.ip() != std::net::Ipv4Addr::LOCALHOST || address.port() == 0 {
            return Err("dashboard requires an assigned 127.0.0.1 port");
        }
        Ok(Self {
            host: address.to_string(),
            origin: format!("http://{address}"),
            bootstrap: Arc::new(Mutex::new(Some(random_token()?))),
            capability: random_token()?,
        })
    }
    /// Deliver only to the deliberate local browser launch, never an application log.
    pub fn bootstrap_url(&self) -> Result<String, &'static str> {
        let guard = self
            .bootstrap
            .lock()
            .map_err(|_| "local session unavailable")?;
        Ok(format!(
            "{}/#{}",
            self.origin,
            guard.as_ref().ok_or("bootstrap consumed")?
        ))
    }
}

fn exactly(headers: &HeaderMap, name: &str, expected: &str) -> bool {
    let mut values = headers.get_all(name).iter();
    matches!((values.next(), values.next()), (Some(value), None) if value.as_bytes() == expected.as_bytes())
}
fn denied() -> Response {
    (StatusCode::FORBIDDEN, "local request rejected").into_response()
}

async fn boundary(State(session): State<LocalSession>, request: Request, next: Next) -> Response {
    let api = request.uri().path().starts_with("/api/");
    let headers = request.headers();
    let origin_ok = if api || headers.contains_key(header::ORIGIN) {
        exactly(headers, "origin", &session.origin)
    } else {
        true
    };
    let valid = exactly(headers, "host", &session.host)
        && origin_ok
        && !headers.contains_key(header::UPGRADE)
        && request.uri().query().is_none()
        && (!api || request.method() == Method::POST);
    let authorized = if api && request.uri().path() != "/api/bootstrap" {
        exactly(
            headers,
            "authorization",
            &format!("Bearer {}", session.capability),
        )
    } else {
        true
    };
    let mut response = if valid && authorized {
        next.run(request).await
    } else {
        denied()
    };
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    response
}

async fn bootstrap(State(session): State<LocalSession>, headers: HeaderMap) -> Response {
    let Ok(mut token) = session.bootstrap.lock() else {
        return denied();
    };
    let Some(expected) = token.as_ref() else {
        return denied();
    };
    if !exactly(&headers, "authorization", &format!("Bearer {expected}")) {
        return denied();
    }
    *token = None;
    Json(json!({"capability":session.capability,"mode":"simulation"})).into_response()
}
async fn query(headers: HeaderMap, body: Bytes) -> Response {
    if !exactly(&headers, "content-type", "application/json") {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "application/json required",
        )
            .into_response();
    }
    let scenario = headers
        .get("x-zrpc-scenario")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("fixture");
    let Ok(scenario) = scenario.parse::<Scenario>() else {
        return (StatusCode::BAD_REQUEST, "unknown simulation scenario").into_response();
    };
    Json(SimulationClient::query(&body, scenario)).into_response()
}
async fn status() -> impl IntoResponse {
    Json(PrivateClient::new().verify())
}
async fn index() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        include_str!("../../../ui/local/index.html"),
    )
}
async fn script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../../../ui/local/dist/app.js"),
    )
}
async fn style() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../../../ui/local/style.css"),
    )
}

pub fn dashboard(session: LocalSession) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(script))
        .route("/style.css", get(style))
        .route("/api/bootstrap", post(bootstrap))
        .route("/api/query", post(query))
        .route("/api/status", post(status))
        .fallback(|| async { (StatusCode::NOT_FOUND, "not found") })
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(session.clone(), boundary))
        .with_state(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use tower::ServiceExt;
    fn session() -> LocalSession {
        LocalSession::new("127.0.0.1:32123".parse().unwrap()).unwrap()
    }
    fn call(path: &str, host: &str, origin: &str, token: &str) -> Request {
        Request::builder()
            .method("POST")
            .uri(path)
            .header("host", host)
            .header("origin", origin)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}"#,
            ))
            .unwrap()
    }
    #[tokio::test]
    async fn ui_authorization_and_core_parity() {
        let state = session();
        let app = dashboard(state.clone());
        for (host, origin, token) in [
            (
                "evil.test:32123",
                state.origin.as_str(),
                state.capability.as_str(),
            ),
            (
                state.host.as_str(),
                "https://evil.test",
                state.capability.as_str(),
            ),
            (state.host.as_str(), state.origin.as_str(), ""),
            (state.host.as_str(), "null", state.capability.as_str()),
        ] {
            assert_eq!(
                app.clone()
                    .oneshot(call("/api/query", host, origin, token))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::FORBIDDEN
            );
        }
        let response = app
            .oneshot(call(
                "/api/query",
                &state.host,
                &state.origin,
                &state.capability,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(
            response
                .headers()
                .get("access-control-allow-origin")
                .is_none()
        );
        let body = to_bytes(response.into_body(), MAX_BODY).await.unwrap();
        let expected = SimulationClient::query(
            br#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}"#,
            "fixture".parse().unwrap(),
        );
        let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(result, serde_json::to_value(expected).unwrap());
    }
    #[tokio::test]
    async fn bootstrap_is_single_use_and_api_is_post_only() {
        let state = session();
        let app = dashboard(state.clone());
        let token = state.bootstrap.lock().unwrap().clone().unwrap();
        let first = app
            .clone()
            .oneshot(call("/api/bootstrap", &state.host, &state.origin, &token))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(
            app.clone()
                .oneshot(call("/api/bootstrap", &state.host, &state.origin, &token))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
        let mut request = call("/api/query", &state.host, &state.origin, &state.capability);
        *request.method_mut() = Method::GET;
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let mut request = call("/api/query", &state.host, &state.origin, &state.capability);
        request
            .headers_mut()
            .insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        assert_eq!(
            app.oneshot(request).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    #[tokio::test]
    async fn excessive_body_and_duplicate_host_are_rejected() {
        let state = session();
        let app = dashboard(state.clone());
        let mut request = call("/api/query", &state.host, &state.origin, &state.capability);
        *request.body_mut() = Body::from(vec![b' '; MAX_BODY + 1]);
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let mut request = call("/api/query", &state.host, &state.origin, &state.capability);
        request
            .headers_mut()
            .append(header::HOST, HeaderValue::from_static("evil.test"));
        assert_eq!(
            app.oneshot(request).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    #[test]
    fn refuses_public_bind_address() {
        assert!(LocalSession::new("0.0.0.0:3000".parse().unwrap()).is_err());
        assert!(LocalSession::new("[::1]:3000".parse().unwrap()).is_err());
    }
}
