use std::sync::OnceLock;

use futures::TryStreamExt;
use poem::endpoint::make;
use poem::{Body, Endpoint, Request, Response};
use reqwest::redirect::Policy;
use url::Url;

const DEFAULT_RRWEB_SERVER_URL: &str = "http://127.0.0.1:3000";
const WARPGATE_RRWEB_PREFIX: &str = "/@warpgate/rrweb";
const LEGACY_WARPGATE_RRWEB_PREFIX: &str = "/_warpgate/rrweb";

static CLIENT: OnceLock<std::result::Result<reqwest::Client, String>> = OnceLock::new();

pub fn endpoint() -> impl Endpoint {
    make(|req: Request| async move { proxy_request(req).await })
}

async fn proxy_request(mut req: Request) -> poem::Result<Response> {
    let original_uri = req.original_uri();
    let path = original_uri.path();
    let upstream_path = path
        .strip_prefix(WARPGATE_RRWEB_PREFIX)
        .or_else(|| path.strip_prefix(LEGACY_WARPGATE_RRWEB_PREFIX))
        .ok_or_else(|| poem::Error::from_status(poem::http::StatusCode::NOT_FOUND))?;

    if !is_allowed_request(req.method(), upstream_path) {
        return Err(poem::Error::from_status(
            poem::http::StatusCode::METHOD_NOT_ALLOWED,
        ));
    }

    let mut upstream_url = rrweb_server_url()?;
    upstream_url.set_path(upstream_path);
    upstream_url.set_query(original_uri.query());

    let client = CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .redirect(Policy::none())
                .build()
                .map_err(|_| {
                    tracing::error!("Unable to initialize rrweb proxy client");
                    "client initialization failed".to_owned()
                })
        })
        .as_ref()
        .map_err(|_| poem::Error::from_status(poem::http::StatusCode::INTERNAL_SERVER_ERROR))?;

    let mut upstream_request = client.request(req.method().clone(), upstream_url.as_str());
    for name in [
        poem::http::header::ACCEPT,
        poem::http::header::AUTHORIZATION,
        poem::http::header::CONTENT_TYPE,
        poem::http::header::COOKIE,
        poem::http::header::IF_NONE_MATCH,
    ] {
        for value in req.headers().get_all(&name) {
            upstream_request = upstream_request.header(name.clone(), value);
        }
    }
    for value in req.headers().get_all("last-event-id") {
        upstream_request = upstream_request.header("last-event-id", value);
    }

    if req.method() == poem::http::Method::POST {
        upstream_request = upstream_request.body(reqwest::Body::wrap_stream(
            req.take_body().into_bytes_stream(),
        ));
    }

    let upstream_response = upstream_request.send().await.map_err(|error| {
        tracing::error!(
            timeout = error.is_timeout(),
            "Request to the rrweb service failed"
        );
        poem::error::BadGateway(error)
    })?;

    let mut response = Response::builder().status(upstream_response.status());
    for name in [
        poem::http::header::CACHE_CONTROL,
        poem::http::header::CONTENT_TYPE,
        poem::http::header::ETAG,
        poem::http::header::LAST_MODIFIED,
        poem::http::header::RETRY_AFTER,
    ] {
        for value in upstream_response.headers().get_all(&name) {
            response = response.header(name.clone(), value.clone());
        }
    }

    Ok(response.body(Body::from_bytes_stream(
        upstream_response
            .bytes_stream()
            .map_err(std::io::Error::other),
    )))
}

fn rrweb_server_url() -> poem::Result<Url> {
    let value =
        std::env::var("RRWEB_SERVER_URL").unwrap_or_else(|_| DEFAULT_RRWEB_SERVER_URL.to_owned());
    let url = Url::parse(&value).map_err(|_| {
        tracing::error!("RRWEB_SERVER_URL must be an absolute HTTP(S) origin");
        poem::Error::from_status(poem::http::StatusCode::INTERNAL_SERVER_ERROR)
    })?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        tracing::error!(
            "RRWEB_SERVER_URL must be an absolute HTTP(S) origin without credentials or a path"
        );
        return Err(poem::Error::from_status(
            poem::http::StatusCode::INTERNAL_SERVER_ERROR,
        ));
    }
    Ok(url)
}

fn is_allowed_request(method: &poem::http::Method, path: &str) -> bool {
    match (method.as_str(), path) {
        ("GET", "/rrweb-recorder.js" | "/recording-controls.js" | "/api/sessions") => true,
        ("GET" | "POST", "/api/audit/events") => true,
        ("GET", "/api/audit/warpgate-events" | "/api/warpgate/sessions") => true,
        ("POST", "/api/sessions/start") => true,
        ("GET", _) if path.starts_with("/api/session-metadata/") => {
            is_session_path(&path["/api/session-metadata/".len()..])
        }
        ("GET", _) if path.starts_with("/api/sessions/") => {
            let suffix = &path["/api/sessions/".len()..];
            is_recording_filename(suffix)
                || suffix
                    .strip_suffix("/watch")
                    .is_some_and(is_session_path)
        }
        ("POST", _) if path.starts_with("/api/sessions/") => {
            let suffix = &path["/api/sessions/".len()..];
            suffix
                .strip_suffix("/events")
                .or_else(|| suffix.strip_suffix("/heartbeat"))
                .or_else(|| suffix.strip_suffix("/failures"))
                .or_else(|| suffix.strip_suffix("/stop"))
                .is_some_and(is_session_path)
        }
        _ => false,
    }
}

fn is_session_path(value: &str) -> bool {
    value.strip_prefix("session-").is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    })
}

fn is_recording_filename(value: &str) -> bool {
    value.strip_suffix(".json").is_some_and(is_session_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_expected_rrweb_routes_and_methods_are_forwarded() {
        assert!(is_allowed_request(
            &poem::http::Method::GET,
            "/rrweb-recorder.js"
        ));
        assert!(is_allowed_request(
            &poem::http::Method::GET,
            "/recording-controls.js"
        ));
        assert!(is_allowed_request(
            &poem::http::Method::GET,
            "/api/sessions"
        ));
        assert!(is_allowed_request(
            &poem::http::Method::GET,
            "/api/audit/events"
        ));
        assert!(is_allowed_request(
            &poem::http::Method::POST,
            "/api/audit/events"
        ));
        assert!(is_allowed_request(
            &poem::http::Method::GET,
            "/api/audit/warpgate-events"
        ));
        assert!(is_allowed_request(
            &poem::http::Method::GET,
            "/api/warpgate/sessions"
        ));
        assert!(is_allowed_request(
            &poem::http::Method::GET,
            "/api/sessions/session-123abc.json"
        ));
        assert!(is_allowed_request(
            &poem::http::Method::GET,
            "/api/sessions/session-123abc/watch"
        ));
        assert!(is_allowed_request(
            &poem::http::Method::POST,
            "/api/sessions/session-123abc/events"
        ));
        assert!(is_allowed_request(
            &poem::http::Method::POST,
            "/api/sessions/session-123abc/stop"
        ));
        assert!(is_allowed_request(
            &poem::http::Method::POST,
            "/api/sessions/session-123abc/heartbeat"
        ));
        assert!(is_allowed_request(
            &poem::http::Method::POST,
            "/api/sessions/session-123abc/failures"
        ));
        assert!(!is_allowed_request(&poem::http::Method::GET, "/admin"));
        assert!(!is_allowed_request(
            &poem::http::Method::POST,
            "/api/sessions"
        ));
        assert!(!is_allowed_request(
            &poem::http::Method::GET,
            "/api/sessions/../secret"
        ));
        assert!(!is_allowed_request(
            &poem::http::Method::GET,
            "/api/sessions/session-123abc/../watch"
        ));
        assert!(!is_allowed_request(
            &poem::http::Method::POST,
            "/api/sessions/session-123abc/watch"
        ));
        assert!(!is_allowed_request(
            &poem::http::Method::DELETE,
            "/api/sessions/session-123abc/heartbeat"
        ));
    }

    #[test]
    fn validates_session_and_recording_paths() {
        assert!(is_session_path("session-a1_b-c"));
        assert!(!is_session_path("session-"));
        assert!(!is_session_path("session-../secret"));
        assert!(is_recording_filename("session-a1.json"));
        assert!(!is_recording_filename("../session-a1.json"));
    }
}
