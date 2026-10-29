use std::fmt::Write;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use cookie::Cookie;
use data_encoding::BASE64;
use delegate::delegate;
use futures::{Stream, StreamExt, TryStreamExt};
use hmac::{Hmac, KeyInit, Mac};
use http::header::HeaderName;
use http::uri::{Authority, PathAndQuery, Scheme};
use http::{HeaderValue, StatusCode, Uri};
use poem::session::Session;
use poem::web::Data;
use poem::web::websocket::WebSocket;
use poem::{Body, FromRequest, IntoResponse, Request, Response};
use sha2::Sha256;
use tokio::sync::Mutex;
use tokio_tungstenite::{Connector, connect_async_tls_with_config, tungstenite};
use tracing::{debug, error, warn};
use url::{Url, form_urlencoded};
use warpgate_common::helpers::websocket::pump_websocket;
use warpgate_common::http_headers::{
    X_FORWARDED_FOR, X_FORWARDED_HOST, X_FORWARDED_PROTO, may_forward_header,
};
use warpgate_common::{TargetHTTPOptions, WarpgateError, try_block};
use warpgate_common_http::logging::{get_client_ip, log_request_result};
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization, SessionKeepalive,
};
use warpgate_core::is_ticket_session_valid;
use warpgate_core::logging::AuditEvent;
use warpgate_tls::{TlsMode, configure_tls_connector};
use warpgate_web::lookup_built_file;

use crate::client_cache::HttpClientCache;
use crate::common::{
    SESSION_COOKIE_NAME, SessionExt, rrweb_recording_session_id, rrweb_recording_session_owner,
};
use crate::session::SessionStore;
use crate::target_routes::{
    authorized_http_target_for_origin, http_target_allows_origin, http_target_origin,
};

static X_WARPGATE_USERNAME: HeaderName = HeaderName::from_static("x-warpgate-username");
static X_WARPGATE_AUTHENTICATION_TYPE: HeaderName =
    HeaderName::from_static("x-warpgate-authentication-type");
static X_WARPGATE_TARGET: HeaderName = HeaderName::from_static("x-warpgate-target");

trait SomeResponse {
    fn status(&self) -> http::StatusCode;
    fn headers(&self) -> &http::HeaderMap;
}

impl SomeResponse for reqwest::Response {
    delegate! {
        to self {
            fn status(&self) -> http::StatusCode;
            fn headers(&self) -> &http::HeaderMap;
        }
    }
}

impl<B> SomeResponse for http::Response<B> {
    delegate! {
        to self {
            fn status(&self) -> http::StatusCode;
            fn headers(&self) -> &http::HeaderMap;
        }
    }
}

trait SomeRequestBuilder {
    fn header<K: Into<HeaderName>, V>(self, k: K, v: V) -> Self
    where
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>;
}

impl SomeRequestBuilder for reqwest::RequestBuilder {
    fn header<K: Into<HeaderName>, V>(self, k: K, v: V) -> Self
    where
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        self.header(k, v)
    }
}

impl SomeRequestBuilder for http::request::Builder {
    fn header<K: Into<HeaderName>, V>(self, k: K, v: V) -> Self
    where
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        self.header(k, v)
    }
}

pub(crate) fn create_rrweb_recording_token(
    username: &str,
    authentication_type: &str,
    target: &str,
    recording_session_id: &str,
    warpgate_user_id: Option<&str>,
    warpgate_session_id: Option<&str>,
) -> Result<(String, u128)> {
    let secret = rrweb_signing_secret()?;

    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis()
        + 5 * 60 * 1000;

    let payload = serde_json::json!({
        "username": username,
        "authenticationType": authentication_type,
        "target": target,
        "recordingSessionId": recording_session_id,
        "warpgateUserId": warpgate_user_id,
        "warpgateSessionId": warpgate_session_id,
        "expiresAt": expires_at,
    });

    let payload_json = serde_json::to_string(&payload)?;

    let encoded_payload = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| anyhow::anyhow!("Invalid RRWEB_SIGNING_SECRET"))?;

    mac.update(encoded_payload.as_bytes());

    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    Ok((format!("{}.{}", encoded_payload, signature), expires_at))
}

pub(crate) fn rrweb_recording_session_id_for_context(
    owner: &str,
    target: &str,
    recording_context_id: &str,
) -> Result<String> {
    let secret = rrweb_signing_secret()?;
    derive_rrweb_recording_session_id(owner, target, recording_context_id, &secret)
}

fn derive_rrweb_recording_session_id(
    owner: &str,
    target: &str,
    recording_context_id: &str,
    secret: &str,
) -> Result<String> {
    let context_id = uuid::Uuid::parse_str(recording_context_id)
        .context("Invalid rrweb recording context identifier")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| anyhow::anyhow!("Invalid RRWEB_SIGNING_SECRET"))?;
    mac.update(b"rrweb-recording-session-v1\0");
    mac.update(owner.as_bytes());
    mac.update(b"\0");
    mac.update(target.as_bytes());
    mac.update(b"\0");
    mac.update(context_id.as_bytes());

    Ok(format!(
        "session-{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    ))
}

fn rrweb_signing_secret() -> Result<String> {
    if let Ok(secret) = std::env::var("RRWEB_SIGNING_SECRET") {
        anyhow::ensure!(
            secret.len() >= 32,
            "RRWEB_SIGNING_SECRET must contain at least 32 bytes"
        );
        return Ok(secret);
    }

    #[cfg(unix)]
    let sudo_home = std::env::var_os("SUDO_USER")
        .filter(|user| user != "root")
        .map(|user| std::path::PathBuf::from("/home").join(user));
    #[cfg(not(unix))]
    let sudo_home: Option<std::path::PathBuf> = None;

    let secret_path = if let Some(path) = std::env::var_os("RRWEB_SIGNING_SECRET_FILE") {
        std::path::PathBuf::from(path)
    } else if let Some(home) = &sudo_home {
        anyhow::ensure!(
            home.is_dir(),
            "SUDO_USER home directory does not exist: {}",
            home.display()
        );
        home.join(".config")
            .join("secureaccess")
            .join("rrweb-signing-secret")
    } else {
        let config_home = std::env::var_os("XDG_CONFIG_HOME")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".config"))
            })
            .context("Neither XDG_CONFIG_HOME nor HOME is set")?;
        config_home
            .join("secureaccess")
            .join("rrweb-signing-secret")
    };
    let secret_directory = secret_path
        .parent()
        .context("RRWEB signing-secret path has no parent directory")?;
    std::fs::create_dir_all(secret_directory)?;

    #[cfg(unix)]
    let sudo_owner = if sudo_home.is_some_and(|home| {
        secret_path
            == home
                .join(".config")
                .join("secureaccess")
                .join("rrweb-signing-secret")
    }) {
        let uid = std::env::var("SUDO_UID")
            .context("SUDO_UID is required to share the rrweb secret with the sudo user")?
            .parse::<libc::uid_t>()
            .context("SUDO_UID is not a valid user ID")?;
        let gid = std::env::var("SUDO_GID")
            .context("SUDO_GID is required to share the rrweb secret with the sudo user")?
            .parse::<libc::gid_t>()
            .context("SUDO_GID is not a valid group ID")?;
        Some((uid, gid))
    } else {
        None
    };

    #[cfg(unix)]
    if let Some((uid, gid)) = &sudo_owner {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(secret_directory, std::fs::Permissions::from_mode(0o700))?;
        chown_for_sudo_user(secret_directory, *uid, *gid)?;
    }

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let secret = match options.open(&secret_path) {
        Ok(mut file) => {
            use std::io::Write;
            let mut bytes = [0_u8; 32];
            getrandom::fill(&mut bytes).context("Unable to generate rrweb signing secret")?;
            let secret = URL_SAFE_NO_PAD.encode(bytes);
            file.write_all(secret.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))?;
            }
            #[cfg(unix)]
            if let Some((uid, gid)) = &sudo_owner {
                chown_for_sudo_user(&secret_path, *uid, *gid)?;
            }
            secret
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut stored_secret = String::new();
            for _ in 0..50 {
                stored_secret = std::fs::read_to_string(&secret_path)?.trim().to_owned();
                if stored_secret.len() >= 32 {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            stored_secret
        }
        Err(error) => return Err(error).context("Unable to create rrweb signing secret"),
    };

    anyhow::ensure!(
        secret.len() >= 32,
        "RRWEB signing secret at {} must contain at least 32 bytes",
        secret_path.display()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(unix)]
    if let Some((uid, gid)) = &sudo_owner {
        chown_for_sudo_user(&secret_path, *uid, *gid)?;
    }

    Ok(secret)
}

#[cfg(unix)]
fn chown_for_sudo_user(path: &std::path::Path, uid: libc::uid_t, gid: libc::gid_t) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .context("RRWEB signing-secret path contains a NUL byte")?;
    // SAFETY: `path` is valid and NUL-terminated for this call.
    let result = unsafe { libc::chown(path.as_ptr(), uid, gid) };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("Unable to set rrweb signing-secret ownership for sudo user");
    }
    Ok(())
}

fn strip_warpgate_internal_query_params(pq: &PathAndQuery) -> Result<PathAndQuery> {
    let Some(query) = pq.query() else {
        return Ok(pq.clone());
    };
    let query = form_urlencoded::parse(query.as_bytes())
        .filter(|(key, _)| {
            key != "warpgate-target" && key != "warpgate-ticket" && key != "warpgate-host"
        })
        .fold(
            form_urlencoded::Serializer::new(String::new()),
            |mut s, (k, v)| {
                s.append_pair(&k, &v);
                s
            },
        )
        .finish();
    let path = pq.path();
    let rebuilt = if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{query}")
    };
    Ok(PathAndQuery::from_str(&rebuilt)?)
}

fn inject_html_near_head(content: &mut String, injection: &str) {
    let lowercase = content.to_ascii_lowercase();
    if let Some(index) = lowercase.find("</head>") {
        content.insert_str(index, injection);
        return;
    }

    if let Some(head_start) = lowercase.find("<head")
        && let Some(head_end) = lowercase[head_start..].find('>')
    {
        content.insert_str(head_start + head_end + 1, injection);
        return;
    }

    content.insert_str(0, injection);
}

fn construct_uri(req: &Request, options: &TargetHTTPOptions, websocket: bool) -> Result<Uri> {
    let target_uri = Uri::try_from(options.url.clone())?;
    let source_uri = req.uri().clone();

    let configured_authority = target_uri
        .authority()
        .context("No authority in the URL")?
        .to_string();

    let authority = internal_target_host(&source_uri, options)?
        .unwrap_or(configured_authority)
        .parse::<Authority>()?;
    let path_and_query = strip_warpgate_internal_query_params(
        source_uri.path_and_query().context("No path in the URL")?,
    )?;
    let mut uri = http::uri::Builder::new()
        .authority(authority)
        .path_and_query(path_and_query);

    let scheme = match options.tls.mode {
        TlsMode::Disabled => &Scheme::HTTP,
        TlsMode::Preferred => target_uri.scheme().context("No scheme in the URL")?,
        TlsMode::Required => &Scheme::HTTPS,
    };
    uri = uri.scheme(scheme.clone());

    #[allow(clippy::unwrap_used)]
    if websocket {
        uri = uri.scheme(
            Scheme::from_str(if scheme == &Scheme::from_str("http").unwrap() {
                "ws"
            } else {
                "wss"
            })
            .unwrap(),
        );
    }

    Ok(uri.build()?)
}

fn internal_target_host(source_uri: &Uri, options: &TargetHTTPOptions) -> Result<Option<String>> {
    let Some(query) = source_uri.query() else {
        return Ok(None);
    };
    let Some((_, host)) =
        form_urlencoded::parse(query.as_bytes()).find(|(key, _)| key == "warpgate-host")
    else {
        return Ok(None);
    };

    let configured_origin =
        Url::parse(&http_target_origin(options).context("Invalid HTTP target origin")?)?;
    let host_url = Url::parse(&format!("{}://{}", configured_origin.scheme(), host))?;
    anyhow::ensure!(
        host_url.username().is_empty()
            && host_url.password().is_none()
            && host_url.path() == "/"
            && host_url.query().is_none()
            && host_url.fragment().is_none(),
        "Invalid internal Warpgate target host"
    );
    let candidate_origin = host_url.origin().ascii_serialization();
    anyhow::ensure!(
        http_target_allows_origin(options, &candidate_origin),
        "Internal Warpgate target host is outside the configured target scope"
    );
    let candidate_uri = Uri::try_from(host_url.as_str())?;
    let authority = candidate_uri
        .authority()
        .context("Internal Warpgate target host has no authority")?;
    Ok(Some(authority.to_string()))
}

fn copy_client_response<R: SomeResponse>(
    client_response: &R,
    server_response: &mut poem::Response,
) {
    let mut headers = client_response.headers().clone();
    for h in client_response.headers() {
        if !may_forward_header(h.0)
            && let http::header::Entry::Occupied(e) = headers.entry(h.0)
        {
            e.remove_entry();
        }
    }
    server_response.headers_mut().extend(headers);

    server_response.set_status(client_response.status());
}

fn rewrite_request<B: SomeRequestBuilder>(mut req: B, options: &TargetHTTPOptions) -> Result<B> {
    if let Some(ref headers) = options.headers {
        for (k, v) in headers {
            req = req.header(HeaderName::try_from(k)?, v);
        }
    }
    Ok(req)
}

fn rewrite_response(
    resp: &mut Response,
    _options: &TargetHTTPOptions,
    _source_uri: &Uri,
) -> Result<()> {
    let headers = resp.headers_mut();

    if let http::header::Entry::Occupied(mut entry) = headers.entry(http::header::SET_COOKIE) {
        for value in entry.iter_mut() {
            try_block!({
                let mut cookie = Cookie::parse(value.to_str()?)?;
                // Some apps clear a cookie by re-setting it with an expiration
                // in the past. We keep these as-is
                // https://github.com/warp-tech/warpgate/issues/2112
                if let Some(cookie::Expiration::DateTime(expires)) = cookie.expires()
                    && expires >= cookie::time::OffsetDateTime::now_utc()
                {
                    cookie.set_expires(cookie::Expiration::Session);
                }
                // the domain set by the target isn't going to match the actual host anyway
                // https://github.com/warp-tech/warpgate/issues/2048
                cookie.unset_domain();
                *value = cookie.to_string().parse()?;
            } catch (error: anyhow::Error) {
                warn!(?error, header=?value, "Failed to parse response cookie");
            });
        }
    }

    Ok(())
}

async fn rewrite_authorized_redirect(
    resp: &mut Response,
    ctx: &AuthenticatedRequestContext,
    current_target_name: &str,
    options: &TargetHTTPOptions,
    source_uri: &Uri,
) -> Result<()> {
    let Some(location) = resp.headers().get(http::header::LOCATION) else {
        return Ok(());
    };
    let destination = Url::parse(&source_uri.to_string())?.join(
        location
            .to_str()
            .context("Invalid redirect Location header")?,
    )?;
    let destination_origin = destination.origin().ascii_serialization();
    let target_name = if http_target_allows_origin(options, &destination_origin) {
        current_target_name.to_owned()
    } else if let Some(target_name) =
        authorized_http_target_for_origin(ctx, &destination_origin).await?
    {
        target_name
    } else {
        *resp = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body("Navigation blocked: destination is not an authorized Warpgate HTTP target");
        return Ok(());
    };

    let gateway_location =
        gateway_redirect_location(&destination, &target_name, current_target_name, options)?;
    resp.headers_mut().insert(
        http::header::LOCATION,
        HeaderValue::from_str(&gateway_location)?,
    );
    Ok(())
}

fn gateway_redirect_location(
    destination: &Url,
    target_name: &str,
    current_target_name: &str,
    current_options: &TargetHTTPOptions,
) -> Result<String> {
    let current_origin =
        http_target_origin(current_options).context("Unable to determine current target origin")?;
    let mut query = form_urlencoded::Serializer::new(String::new());
    for (key, value) in destination.query_pairs() {
        if key != "warpgate-target" && key != "warpgate-ticket" && key != "warpgate-host" {
            query.append_pair(&key, &value);
        }
    }
    if target_name != current_target_name {
        query.append_pair("warpgate-target", &target_name);
    }
    if target_name == current_target_name
        && destination.origin().ascii_serialization() != current_origin
    {
        let host = destination
            .host_str()
            .context("Redirect destination has no host")?;
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        let authority = destination
            .port()
            .map_or(host.clone(), |port| format!("{host}:{port}"));
        query.append_pair("warpgate-host", &authority);
    }
    let query = query.finish();
    let mut gateway_location = destination.path().to_owned();
    if !query.is_empty() {
        gateway_location.push('?');
        gateway_location.push_str(&query);
    }
    if let Some(fragment) = destination.fragment() {
        gateway_location.push('#');
        gateway_location.push_str(fragment);
    }
    Ok(gateway_location)
}

fn cookie_header_for_target(req: &Request) -> Result<Option<String>> {
    let mut cookies = Vec::new();

    for value in req.headers().get_all(http::header::COOKIE) {
        for cookie in Cookie::split_parse(value.to_str()?) {
            let cookie = cookie?;
            if cookie.name() != SESSION_COOKIE_NAME {
                cookies.push(cookie.stripped().to_string());
            }
        }
    }

    Ok((!cookies.is_empty()).then(|| cookies.join("; ")))
}

fn copy_server_request<B: SomeRequestBuilder>(req: &Request, mut target: B) -> Result<B> {
    for k in req.headers().keys() {
        if !may_forward_header(k) {
            continue;
        }
        if k == http::header::COOKIE {
            if let Some(value) = cookie_header_for_target(req)? {
                target = target.header(k.clone(), value);
            }
            continue;
        }
        target = target.header(
            k.clone(),
            req.headers()
                .get_all(k)
                .iter()
                .map(|v| v.to_str().map(|x| x.to_string()))
                .filter_map(|x| x.ok())
                .collect::<Vec<_>>()
                .join("; "),
        );
    }
    Ok(target)
}

fn inject_forwarding_headers<B: SomeRequestBuilder>(
    req: &Request,
    ctx: &AuthenticatedRequestContext,
    mut target: B,
) -> B {
    if let Some(host) = ctx.trusted_host_header(req) {
        target = target.header(X_FORWARDED_HOST.clone(), host);
    }
    target = target.header(X_FORWARDED_PROTO.clone(), ctx.trusted_proto(req).as_str());
    if let Some(addr) = req.remote_addr().as_socket_addr() {
        target = target.header(X_FORWARDED_FOR.clone(), addr.ip().to_string());
    }
    target
}

async fn inject_own_headers<B: SomeRequestBuilder>(req: &Request, mut target: B) -> Result<B> {
    let session = <&Session>::from_request_without_body(req).await?;
    if let Some(auth) = session.get_auth() {
        target = target.header(&X_WARPGATE_USERNAME, auth.username()).header(
            &X_WARPGATE_AUTHENTICATION_TYPE,
            match auth {
                SessionAuthorization::Ticket { .. } => "ticket",
                SessionAuthorization::User { .. } => "user",
            },
        );
    }
    Ok(target)
}

fn inject_target_header<B: SomeRequestBuilder>(target: B, target_name: &str) -> B {
    target.header(&X_WARPGATE_TARGET, target_name)
}

pub async fn proxy_normal_request(
    req: &Request,
    ctx: &AuthenticatedRequestContext,
    body: Body,
    target_name: &str,
    options: &TargetHTTPOptions,
    client_cache: &HttpClientCache,
) -> poem::Result<Response> {
    let uri = construct_uri(req, options, false)?;

    tracing::debug!("URI: {:?}", uri);
    let session = <&Session>::from_request_without_body(req).await?;
    let warpgate_user_id = session.get_auth().map(|auth| auth.user_id().to_string());
    let warpgate_session_id = session.get_session_id().map(|id| id.to_string());

    let (rrweb_username, rrweb_authentication_type, recording_session_id) = match session.get_auth()
    {
        Some(auth) => {
            let username = auth.username().to_string();
            let authentication_type = match &auth {
                SessionAuthorization::Ticket { .. } => "ticket",
                SessionAuthorization::User { .. } => "user",
            };
            let owner = rrweb_recording_session_owner(&auth);
            let recording_session_id = rrweb_recording_session_id(session, &owner);
            (
                username,
                authentication_type.to_owned(),
                recording_session_id,
            )
        }
        None => (
            "unknown".to_string(),
            "unknown".to_string(),
            rrweb_recording_session_id(session, "unknown"),
        ),
    };

    let rrweb_upstream_url = uri.to_string();
    let rrweb_target_origin =
        http_target_origin(options).context("Unable to determine current HTTP target origin")?;
    let ticket_watch = match &ctx.auth {
        RequestAuthorization::Session(SessionAuthorization::Ticket {
            ticket_id: Some(ticket_id),
            ..
        }) => Some((
            *ticket_id,
            ctx.services().db.clone(),
            warpgate_session_id.clone(),
        )),
        _ => None,
    };

    let client = client_cache.client_for(target_name, options).await?;

    let (authorization_header, uri) = extract_basic_auth(uri)?;

    let mut client_request = client.request(req.method().into(), uri.to_string());

    client_request = copy_server_request(req, client_request)?;
    client_request = inject_forwarding_headers(req, ctx, client_request);
    client_request = inject_own_headers(req, client_request).await?;
    client_request = inject_target_header(client_request, target_name);
    client_request = rewrite_request(client_request, options)?;
    if let Some(authorization_header) = authorization_header {
        client_request = client_request.header(http::header::AUTHORIZATION, authorization_header);
    }

    if req.headers().contains_key(http::header::CONTENT_LENGTH)
        || req.headers().contains_key(http::header::TRANSFER_ENCODING)
    {
        client_request = client_request.body(reqwest::Body::wrap_stream(body.into_bytes_stream()));
    }

    let client_request = client_request.build().context("Could not build request")?;
    let client_response = client
        .execute(client_request)
        .await
        .map_err(|e| anyhow::anyhow!("Could not execute request: {e}"))?;
    let status = client_response.status();

    let mut response: Response = "".into();

    copy_client_response(&client_response, &mut response);

    // The embedded UI can go in if the response is a usable HTML page - we for example
    // don't want to embed into a 404 page or a JS file - and it has something to show:
    // the session menu, the login banner, or both.
    let embed_ui = response.status() == StatusCode::OK
        && response
            .content_type()
            .is_some_and(|content_type| content_type.starts_with("text/html"))
        && ctx
            .parameters()
            .await
            .map(|p| p.show_session_menu || p.banner_text().is_some())
            .unwrap_or(true);
    let inject_rrweb = response.status() == StatusCode::OK
        && response
            .content_type()
            .is_some_and(|content_type| content_type.starts_with("text/html"));
    if inject_rrweb {
        response.headers_mut().append(
            http::header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("navigate-to 'self'; form-action 'self'"),
        );
    }

    copy_client_body(
        client_response,
        &mut response,
        embed_ui,
        inject_rrweb,
        &rrweb_username,
        &rrweb_authentication_type,
        target_name,
        &recording_session_id,
        warpgate_user_id.as_deref(),
        warpgate_session_id.as_deref(),
        &rrweb_target_origin,
        &rrweb_upstream_url,
        ticket_watch,
    )
    .await?;

    log_request_result(
        req.method(),
        req.original_uri(),
        get_client_ip(req, ctx.services()).await.as_deref(),
        status,
    );

    rewrite_response(&mut response, options, &uri)?;
    rewrite_authorized_redirect(&mut response, ctx, target_name, options, &uri).await?;
    Ok(response)
}

async fn copy_client_body(
    client_response: reqwest::Response,
    response: &mut Response,
    embed_ui: bool,
    inject_rrweb: bool,
    rrweb_username: &str,
    rrweb_authentication_type: &str,
    rrweb_target: &str,
    recording_session_id: &str,
    warpgate_user_id: Option<&str>,
    warpgate_session_id: Option<&str>,
    rrweb_target_origin: &str,
    rrweb_upstream_url: &str,
    ticket_watch: Option<(uuid::Uuid, sea_orm::DatabaseConnection, Option<String>)>,
) -> Result<()> {
    if embed_ui || inject_rrweb {
        copy_client_body_and_embed(
            client_response,
            response,
            inject_rrweb,
            rrweb_username,
            rrweb_authentication_type,
            rrweb_target,
            recording_session_id,
            warpgate_user_id,
            warpgate_session_id,
            rrweb_target_origin,
            rrweb_upstream_url,
        )
        .await?;

        return Ok(());
    }
    response.set_body(Body::from_bytes_stream(monitor_ticket_response_body(
        client_response.bytes_stream(),
        ticket_watch,
    )));
    Ok(())
}

fn monitor_ticket_response_body<S, B>(
    stream: S,
    ticket_watch: Option<(uuid::Uuid, sea_orm::DatabaseConnection, Option<String>)>,
) -> impl Stream<Item = Result<B, std::io::Error>> + Send + 'static
where
    S: Stream<Item = Result<B, reqwest::Error>> + Send + 'static,
    B: Send + 'static,
{
    let stream = Box::pin(stream.map_err(std::io::Error::other));
    futures::stream::unfold(
        (
            stream,
            ticket_watch,
            tokio::time::interval(Duration::from_secs(1)),
        ),
        |(mut stream, ticket_watch, mut interval)| async move {
            loop {
                if ticket_watch.is_none() {
                    return stream
                        .next()
                        .await
                        .map(|chunk| (chunk, (stream, ticket_watch, interval)));
                }

                tokio::select! {
                    chunk = stream.next() => {
                        return chunk.map(|chunk| (chunk, (stream, ticket_watch, interval)));
                    }
                    _ = interval.tick() => {
                        if let Some((ticket_id, db, session_id)) = &ticket_watch {
                            match is_ticket_session_valid(db, ticket_id).await {
                                Ok(true) => {}
                                Ok(false) => {
                                    AuditEvent::TicketSessionTerminated {
                                        ticket_id: *ticket_id,
                                        session_id: session_id.clone(),
                                        protocol: "HTTP".into(),
                                        reason: "ticket expired or was deleted".into(),
                                    }
                                    .emit();
                                    return None;
                                }
                                Err(error) => {
                                    warn!(
                                        %ticket_id,
                                        ?error,
                                        "Closing ticket-authorized HTTP response because ticket validity could not be verified"
                                    );
                                    AuditEvent::TicketSessionTerminated {
                                        ticket_id: *ticket_id,
                                        session_id: session_id.clone(),
                                        protocol: "HTTP".into(),
                                        reason: "ticket validity could not be verified".into(),
                                    }
                                    .emit();
                                    return None;
                                }
                            }
                        }
                    }
                }
            }
        },
    )
}

async fn copy_client_body_and_embed(
    client_response: reqwest::Response,
    response: &mut Response,
    inject_rrweb: bool,
    rrweb_username: &str,
    rrweb_authentication_type: &str,
    rrweb_target: &str,
    recording_session_id: &str,
    warpgate_user_id: Option<&str>,
    warpgate_session_id: Option<&str>,
    rrweb_target_origin: &str,
    rrweb_upstream_url: &str,
) -> Result<()> {
    let mut content = client_response.text().await?;

    let script_manifest = lookup_built_file("src/embed/index.ts")?;

    let mut inject = format!(
        r#"<script type="module" src="/@warpgate/{}"></script>"#,
        script_manifest.file
    );
    for css_file in script_manifest.css.unwrap_or_default() {
        let _ = write!(
            &mut inject,
            r#"<link rel="stylesheet" href="/@warpgate/{css_file}" />"#
        );
    }

    let mut rrweb_inject = String::new();

    if inject_rrweb {
        let username = rrweb_username
            .replace('&', "&amp;")
            .replace('"', "&quot;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");

        let authentication_type = rrweb_authentication_type
            .replace('&', "&amp;")
            .replace('"', "&quot;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");

        let target = rrweb_target
            .replace('&', "&amp;")
            .replace('"', "&quot;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");

        let upstream_url = rrweb_upstream_url
            .replace('&', "&amp;")
            .replace('"', "&quot;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");

        let recording_session_id_html = recording_session_id
            .replace('&', "&amp;")
            .replace('"', "&quot;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        let warpgate_session_id_html = warpgate_session_id
            .unwrap_or_default()
            .replace('&', "&amp;")
            .replace('"', "&quot;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        let target_origin = rrweb_target_origin
            .replace('&', "&amp;")
            .replace('"', "&quot;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        let (recording_token, _) = create_rrweb_recording_token(
            rrweb_username,
            rrweb_authentication_type,
            rrweb_target,
            recording_session_id,
            warpgate_user_id,
            warpgate_session_id,
        )?;

        rrweb_inject.push_str(&format!(
            r#"<script
src="/@warpgate/rrweb/rrweb-recorder.js"
data-warpgate-username="{username}"
data-warpgate-authentication-type="{authentication_type}"
data-warpgate-target="{target}"
data-upstream-url="{upstream_url}"
data-recording-token="{recording_token}"
data-recording-session-id="{recording_session_id_html}"
data-warpgate-session-id="{warpgate_session_id_html}"
data-target-origin="{target_origin}"
></script>"#
        ));
        rrweb_inject.push_str(&format!(
            r#"<script
src="/@warpgate/rrweb/recording-controls.js"
data-recording-token="{recording_token}"
data-recording-session-id="{recording_session_id_html}"
></script>"#
        ));
    }

    let all_inject = format!("{inject}{rrweb_inject}");
    inject_html_near_head(&mut content, &all_inject);

    response.headers_mut().remove(http::header::CONTENT_LENGTH);
    response
        .headers_mut()
        .remove(http::header::CONTENT_ENCODING);
    response.headers_mut().remove(http::header::CONTENT_TYPE);
    response
        .headers_mut()
        .remove(http::header::TRANSFER_ENCODING);
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        "text/html; charset=utf-8".parse()?,
    );
    response.set_body(content);
    Ok(())
}

pub async fn proxy_websocket_request(
    req: &Request,
    ws: WebSocket,
    ctx: &AuthenticatedRequestContext,
    target_name: &str,
    options: &TargetHTTPOptions,
) -> poem::Result<impl IntoResponse> {
    let uri = construct_uri(req, options, true)?;
    proxy_ws_inner(req, ws, uri.clone(), ctx, target_name, options)
        .await
        .map_err(|error| {
            tracing::error!(?uri, ?error, "WebSocket proxy failed");
            error
        })
}

/// Remove the username/password from the URL before using it for the Host header
fn extract_basic_auth(uri: Uri) -> anyhow::Result<(Option<HeaderValue>, Uri)> {
    let uri_authority = uri
        .authority()
        .ok_or(WarpgateError::NoHostInUrl)?
        .to_string();
    let parts = uri_authority.split('@').collect::<Vec<_>>();

    let host = parts.last().context("URL authority is empty")?;

    let uri = {
        let mut parts = uri.into_parts();
        parts.authority = Some(Authority::from_str(host)?);
        Uri::from_parts(parts)?
    };

    if parts.len() == 1 {
        return Ok((None, uri));
    }

    #[allow(clippy::indexing_slicing)] // checked
    let creds = parts[0];

    let auth_header = format!("Basic {}", BASE64.encode(creds.as_bytes()));

    let auth_value = HeaderValue::from_str(&auth_header)?;

    Ok((Some(auth_value), uri))
}

async fn proxy_ws_inner(
    req: &Request,
    ws: WebSocket,
    uri: Uri,
    ctx: &AuthenticatedRequestContext,
    target_name: &str,
    options: &TargetHTTPOptions,
) -> poem::Result<impl IntoResponse> {
    let session_middleware = Data::<&Arc<Mutex<SessionStore>>>::from_request_without_body(req)
        .await?
        .clone();
    let session = <&Session>::from_request_without_body(req).await?;
    let mut close_rx = session_middleware.lock().await.close_receiver_for(session);

    let keepalive_guard = Data::<&SessionKeepalive>::from_request_without_body(req)
        .await
        .ok()
        .map(|x| x.guard());
    let ticket_watch = match &ctx.auth {
        RequestAuthorization::Session(SessionAuthorization::Ticket {
            ticket_id: Some(ticket_id),
            ..
        }) => Some((
            *ticket_id,
            ctx.services().db.clone(),
            session.get_session_id().map(|id| id.to_string()),
        )),
        _ => None,
    };

    let (authorization_header, uri) = extract_basic_auth(uri)?;
    let mut client_request = http::request::Builder::new()
        .uri(uri.clone())
        .header(http::header::CONNECTION, "Upgrade")
        .header(http::header::UPGRADE, "websocket")
        .header(http::header::SEC_WEBSOCKET_VERSION, "13")
        .header(
            http::header::SEC_WEBSOCKET_KEY,
            tungstenite::handshake::client::generate_key(),
        )
        // tungstenite requires an explicit Host header
        .header(
            http::header::HOST,
            uri.authority()
                .ok_or(WarpgateError::NoHostInUrl)
                .context("no authority in the URL")?
                .to_string(),
        );

    if let Some(authorization_header) = authorization_header {
        client_request = client_request.header(http::header::AUTHORIZATION, authorization_header);
    }

    client_request = copy_server_request(req, client_request)?;
    client_request = inject_forwarding_headers(req, ctx, client_request);
    client_request = inject_own_headers(req, client_request).await?;
    client_request = rewrite_request(client_request, options)?;

    let tls_config = configure_tls_connector(!options.tls.verify, false, None)
        .await
        .map_err(poem::error::InternalServerError)?;
    let connector = Connector::Rustls(Arc::new(tls_config));

    let (client, client_response) = connect_async_tls_with_config(
        client_request
            .body(())
            .map_err(poem::error::InternalServerError)?,
        None,
        true,
        Some(connector),
    )
    .await
    .map_err(poem::error::BadGateway)?;

    tracing::info!("{:?} {:?} - WebSocket", client_response.status(), uri);

    let mut response = ws
        .on_upgrade(|socket| async move {
            let (client_sink, client_source) = client.split();
            let (server_sink, server_source) = socket.split();

            if let Err(error) = {
                let ticket_watch = async move {
                    if let Some((ticket_id, db, session_id)) = ticket_watch {
                        loop {
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            match is_ticket_session_valid(&db, &ticket_id).await {
                                Ok(true) => {}
                                Ok(false) => {
                                    AuditEvent::TicketSessionTerminated {
                                        ticket_id,
                                        session_id,
                                        protocol: "HTTP".into(),
                                        reason: "ticket expired or was deleted".into(),
                                    }
                                    .emit();
                                    break;
                                }
                                Err(error) => {
                                    warn!(
                                        %ticket_id,
                                        ?error,
                                        "Closing ticket-authorized WebSocket because ticket validity could not be verified"
                                    );
                                    AuditEvent::TicketSessionTerminated {
                                        ticket_id,
                                        session_id,
                                        protocol: "HTTP".into(),
                                        reason: "ticket validity could not be verified".into(),
                                    }
                                    .emit();
                                    break;
                                }
                            }
                        }
                    } else {
                        std::future::pending::<()>().await;
                    }
                };
                tokio::pin!(ticket_watch);

                let mut server_to_client =
                    tokio::spawn(pump_websocket(server_source, client_sink, |msg| {
                        Box::pin(async {
                            tracing::debug!("Server: {:?}", msg);
                            anyhow::Ok(msg)
                        })
                    }));

                let mut client_to_server =
                    tokio::spawn(pump_websocket(client_source, server_sink, |msg| {
                        Box::pin(async {
                            tracing::debug!("Client: {:?}", msg);
                            anyhow::Ok(msg)
                        })
                    }));

                let (server_finished, pump_result): (
                    bool,
                    Option<Result<anyhow::Result<()>, tokio::task::JoinError>>,
                ) = tokio::select! {
                    result = &mut server_to_client => {
                        (true, Some(result))
                    }
                    result = &mut client_to_server => {
                        (false, Some(result))
                    }
                    () = async {
                        match close_rx.as_mut() {
                            Some(close_rx) => {
                                let _ = close_rx.recv().await;
                            }
                            None => std::future::pending::<()>().await,
                        }
                    } => {
                        (false, None)
                    }
                    () = &mut ticket_watch => {
                        (false, None)
                    }
                };

                match pump_result {
                    Some(result) if server_finished => {
                        client_to_server.abort();
                        let _ = client_to_server.await;
                        result.context("server-to-client WebSocket pump task failed")??;
                    }
                    Some(result) => {
                        server_to_client.abort();
                        let _ = server_to_client.await;
                        result.context("client-to-server WebSocket pump task failed")??;
                    }
                    None => {
                        debug!("Closing WebSocket stream after HTTP session ended");
                        server_to_client.abort();
                        client_to_server.abort();
                        let _ = server_to_client.await;
                        let _ = client_to_server.await;
                    }
                }
                debug!("Closing Websocket stream");

                Ok::<_, anyhow::Error>(())
            } {
                error!(?error, "Websocket stream error");
            }

            drop(keepalive_guard);

            Ok::<_, anyhow::Error>(())
        })
        .into_response();

    copy_client_response(&client_response, &mut response);
    rewrite_response(&mut response, options, &uri)?;
    rewrite_authorized_redirect(&mut response, ctx, target_name, options, &uri).await?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forwarded_cookie_header(values: &[&str]) -> Option<String> {
        let mut request = Request::builder();
        for value in values {
            request = request.header(http::header::COOKIE, *value);
        }
        cookie_header_for_target(&request.finish()).unwrap()
    }

    #[test]
    fn request_cookie_header_omits_only_warpgate_session() {
        assert_eq!(
            forwarded_cookie_header(&[
                "target-session=one; warpgate-http-session=secret",
                "warpgate-http-session-extra=two; Warpgate-Http-Session=three",
            ]),
            Some(
                "target-session=one; warpgate-http-session-extra=two; Warpgate-Http-Session=three"
                    .to_string()
            )
        );
    }

    #[test]
    fn recording_context_ids_are_stable_and_isolated_by_owner_target_and_tab() {
        let secret = "test-signing-secret-with-at-least-32-bytes";
        let context_id = "77f905a2-25db-4b53-b269-d3f448b724e1";
        let recording_id =
            derive_rrweb_recording_session_id("user:alice", "docs", context_id, secret).unwrap();

        assert_eq!(
            recording_id,
            derive_rrweb_recording_session_id("user:alice", "docs", context_id, secret).unwrap()
        );
        assert_ne!(
            recording_id,
            derive_rrweb_recording_session_id("user:alice", "web", context_id, secret).unwrap()
        );
        assert_ne!(
            recording_id,
            derive_rrweb_recording_session_id("user:bob", "docs", context_id, secret).unwrap()
        );
        assert_ne!(
            recording_id,
            derive_rrweb_recording_session_id(
                "user:alice",
                "docs",
                "e1422283-fb0f-4f70-a53f-a54427c7f078",
                secret
            )
            .unwrap()
        );
        assert!(
            derive_rrweb_recording_session_id("user:alice", "docs", "invalid", secret).is_err()
        );
    }

    #[test]
    fn request_cookie_header_is_reserialized() {
        assert_eq!(
            forwarded_cookie_header(&[
                " first = value ; warpgate-http-session=secret; token=abc== "
            ]),
            Some("first=value; token=abc==".to_string())
        );
    }

    #[test]
    fn request_cookie_header_is_omitted_without_target_cookies() {
        assert_eq!(
            forwarded_cookie_header(&["warpgate-http-session=secret"]),
            None
        );
    }

    fn make_options(url: &str) -> TargetHTTPOptions {
        TargetHTTPOptions {
            url: url.to_string(),
            tls: Default::default(),
            headers: None,
            external_host: None,
        }
    }

    #[test]
    fn rewrite_response_strips_cookie_domain() {
        let mut resp = poem::Response::builder()
            .header(
                http::header::SET_COOKIE,
                "lsws_uid=abc; HttpOnly; Secure; Path=/; Domain=100.0.0.1",
            )
            .body(());

        let options = make_options("https://100.0.0.1:7080");
        let source_uri = Uri::try_from("https://100.0.0.1:7080/login.php").unwrap();

        rewrite_response(&mut resp, &options, &source_uri).unwrap();

        let cookie_headers: Vec<_> = resp
            .headers()
            .get_all(http::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();

        assert_eq!(cookie_headers.len(), 1);
        let cookie = Cookie::parse(cookie_headers[0].as_str()).unwrap();
        assert_eq!(cookie.name(), "lsws_uid");
        assert_eq!(cookie.value(), "abc");
        assert_eq!(cookie.domain(), None);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.secure(), Some(true));
    }

    fn rewrite_cookie(set_cookie: &str) -> Cookie<'static> {
        let mut resp = poem::Response::builder()
            .header(http::header::SET_COOKIE, set_cookie)
            .body(());
        let options = make_options("https://100.0.0.1:7080");
        let source_uri = Uri::try_from("https://100.0.0.1:7080/index.php").unwrap();
        rewrite_response(&mut resp, &options, &source_uri).unwrap();
        let cookie_headers: Vec<_> = resp
            .headers()
            .get_all(http::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert_eq!(cookie_headers.len(), 1);
        Cookie::parse(cookie_headers[0].clone()).unwrap()
    }

    #[test]
    fn rewrite_response_keeps_past_expiration() {
        // A past-dated deletion cookie would otherwise drop the live session
        // cookie and cause a login loop. https://github.com/warp-tech/warpgate/issues/2112
        let cookie =
            rewrite_cookie("lsws_uid=deleted; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(cookie.value(), "deleted");
        assert!(matches!(
            cookie.expires(),
            Some(cookie::Expiration::DateTime(_))
        ));
    }

    #[test]
    fn rewrite_response_removes_future_expiration() {
        // A genuine persistent cookie must keep the expiry the origin set.
        let cookie = rewrite_cookie("lsws_uid=abc; Path=/; Expires=Tue, 01 Jan 2999 00:00:00 GMT");
        assert_eq!(cookie.expires(), None);
    }

    fn strip(pq: &str) -> String {
        strip_warpgate_internal_query_params(&PathAndQuery::from_str(pq).unwrap())
            .unwrap()
            .to_string()
    }

    #[test]
    fn strip_reserved_query_params() {
        assert_eq!(strip("/"), "/");
        assert_eq!(strip("/?a=1&b=2"), "/?a=1&b=2");
        assert_eq!(strip("/?warpgate-target=es"), "/");
        assert_eq!(strip("/search?warpgate-target=es&q=x"), "/search?q=x");
        assert_eq!(strip("/?q=x&warpgate-ticket=abc"), "/?q=x");
        assert_eq!(strip("/?warpgate-target=a&warpgate-ticket=b"), "/");
        assert_eq!(
            strip("/wiki?warpgate-target=web-demo&warpgate-host=en.wikipedia.org&q=ai"),
            "/wiki?q=ai"
        );
    }

    #[test]
    fn authorized_redirect_is_routed_to_the_target_without_internal_param_leaks() {
        let destination = Url::parse(
            "https://wikipedia.org/path?q=one&warpgate-target=attacker&warpgate-ticket=fake#part",
        )
        .unwrap();
        assert_eq!(
            gateway_redirect_location(
                &destination,
                "target-b",
                "target-a",
                &make_options("https://www.wikipedia.org"),
            )
            .unwrap(),
            "/path?q=one&warpgate-target=target-b#part"
        );
        assert_eq!(
            gateway_redirect_location(
                &destination,
                "target-a",
                "target-a",
                &make_options("https://www.wikipedia.org"),
            )
            .unwrap(),
            "/path?q=one&warpgate-host=wikipedia.org#part"
        );
    }

    #[test]
    fn internal_target_host_is_limited_to_the_configured_host_and_bare_domain() {
        let options = make_options("https://www.wikipedia.org");
        let request = Uri::try_from(
            "https://gateway.test/wiki?warpgate-target=web-demo&warpgate-host=wikipedia.org",
        )
        .unwrap();
        assert_eq!(
            internal_target_host(&request, &options).unwrap(),
            Some("wikipedia.org".to_owned())
        );

        let sibling =
            Uri::try_from("https://gateway.test/wiki?warpgate-host=en.wikipedia.org").unwrap();
        assert!(internal_target_host(&sibling, &options).is_err());

        let malicious = Uri::try_from(
            "https://gateway.test/wiki?warpgate-host=www.wikipedia.org.attacker.example",
        )
        .unwrap();
        assert!(internal_target_host(&malicious, &options).is_err());

        let userinfo =
            Uri::try_from("https://gateway.test/wiki?warpgate-host=user%40en.wikipedia.org")
                .unwrap();
        assert!(internal_target_host(&userinfo, &options).is_err());
    }
}
