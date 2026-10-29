use std::collections::HashSet;
use std::io::SeekFrom;
use std::path::Path;
use std::time::{Duration, Instant};

use futures::stream::{SplitSink, SplitStream};
use futures::{SinkExt, StreamExt};
use poem::error::{InternalServerError, NotFoundError};
use poem::web::websocket::{Message, WebSocket, WebSocketStream};
use poem::web::{Data, Redirect, StaticFileRequest};
use poem::{IntoResponse, handler};
use poem_openapi::param::Query;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{
    ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect,
};
use serde::Serialize;
use time::OffsetDateTime;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, BufReader};
use tokio::sync::broadcast;
use tracing::error;
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_common_http::{AuthenticatedRequestContext, RequestAuthorization};
use warpgate_core::recordings::{LiveChunk, RecordingFile};
use warpgate_db_entities::Recording::{self, RecordingKind};
use warpgate_db_entities::{
    SecureAccessUserRole, Session, TargetRoleAssignment, User, UserRoleAssignment,
};

use super::{AuthenticatedContext, ClusterOrAdminContext};
use crate::api::cluster_proxy::{Owner, proxy_or_serve, proxy_or_serve_websocket, session_owner};
use crate::api::common::{require_admin_permission, require_cluster_or_admin_permission};

pub struct Api;

#[derive(ApiResponse)]
enum GetRecordingResponse {
    #[oai(status = 200)]
    Ok(Json<Recording::Model>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(Clone, Debug, Serialize, Object)]
#[oai(rename = "RecordingListItem", rename_all = "camelCase")]
struct RecordingListItem {
    id: Uuid,
    name: String,
    started: OffsetDateTime,
    ended: Option<OffsetDateTime>,
    session_id: Uuid,
    kind: RecordingKind,
    metadata: String,
    generation: i32,
    username: Option<String>,
    user_id: Option<Uuid>,
    target: Option<String>,
    protocol: String,
    recording_status: String,
    storage_bytes: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Object)]
#[oai(rename = "RecordingsPage", rename_all = "camelCase")]
struct RecordingsPage {
    items: Vec<RecordingListItem>,
    offset: u64,
    total: u64,
}

#[derive(ApiResponse)]
enum GetRecordingsResponse {
    #[oai(status = 200)]
    Ok(Json<RecordingsPage>),
}

#[OpenApi]
impl Api {
    #[oai(path = "/recordings", method = "get", operation_id = "get_recordings")]
    async fn api_get_recordings(
        &self,
        admin: ClusterOrAdminContext,
        offset: Query<Option<u64>>,
        limit: Query<Option<u64>>,
    ) -> poem::Result<GetRecordingsResponse> {
        admin.require(AdminPermission::RecordingsView)?;

        let db = &admin.services().db;
        let offset = (*offset).unwrap_or(0);
        let limit = (*limit).unwrap_or(50).clamp(1, 200);
        let query = Recording::Entity::find()
            .filter(Recording::Column::Kind.eq(RecordingKind::Terminal))
            .order_by_desc(Recording::Column::Started)
            .order_by_desc(Recording::Column::Id);
        let total = query
            .clone()
            .paginate(db, limit)
            .num_items()
            .await
            .map_err(InternalServerError)?;
        let recordings = query
            .offset(offset)
            .limit(limit)
            .all(db)
            .await
            .map_err(InternalServerError)?;

        let session_ids = recordings
            .iter()
            .map(|recording| recording.session_id)
            .collect::<Vec<_>>();
        let sessions = if session_ids.is_empty() {
            Vec::new()
        } else {
            Session::Entity::find()
                .filter(Session::Column::Id.is_in(session_ids))
                .all(db)
                .await
                .map_err(InternalServerError)?
        };
        let usernames = sessions
            .iter()
            .filter_map(|session| session.username.clone())
            .collect::<Vec<_>>();
        let users = if usernames.is_empty() {
            Vec::new()
        } else {
            User::Entity::find()
                .filter(User::Column::Username.is_in(usernames))
                .all(db)
                .await
                .map_err(InternalServerError)?
        };

        let session_by_id = sessions
            .into_iter()
            .map(|session| (session.id, session))
            .collect::<std::collections::HashMap<_, _>>();
        let user_id_by_name = users
            .into_iter()
            .map(|user| (user.username.to_lowercase(), user.id))
            .collect::<std::collections::HashMap<_, _>>();

        let items = recordings
            .into_iter()
            .map(|recording| {
                let session = session_by_id.get(&recording.session_id);
                let username = session.and_then(|session| session.username.clone());
                let target = session
                    .and_then(|session| session.target_snapshot.as_deref())
                    .and_then(|snapshot| serde_json::from_str::<serde_json::Value>(snapshot).ok())
                    .and_then(|snapshot| {
                        snapshot
                            .get("name")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned)
                    });
                let ended = recording.ended;
                let recording_status = if ended.is_some() {
                    "completed"
                } else if session.is_some_and(|session| session.ended.is_some()) {
                    "incomplete"
                } else {
                    "recording"
                };

                RecordingListItem {
                    id: recording.id,
                    name: recording.name,
                    started: recording.started,
                    ended,
                    session_id: recording.session_id,
                    kind: recording.kind,
                    metadata: recording.metadata,
                    generation: recording.generation,
                    username: username.clone(),
                    user_id: username
                        .as_ref()
                        .and_then(|name| user_id_by_name.get(&name.to_lowercase()).copied()),
                    target,
                    protocol: "SSH".to_owned(),
                    recording_status: recording_status.to_owned(),
                    storage_bytes: None,
                }
            })
            .collect();

        Ok(GetRecordingsResponse::Ok(Json(RecordingsPage {
            items,
            offset,
            total,
        })))
    }

    #[oai(
        path = "/recordings/:id",
        method = "get",
        operation_id = "get_recording"
    )]
    async fn api_get_recording(
        &self,
        ctx: AuthenticatedContext,
        id: poem_openapi::param::Path<Uuid>,
    ) -> poem::Result<GetRecordingResponse> {
        let db = &ctx.services().db;

        let recording = Recording::Entity::find_by_id(id.0)
            .one(db)
            .await
            .map_err(InternalServerError)?;

        match recording {
            Some(recording) => {
                require_recording_view_access(&ctx, &recording).await?;
                Ok(GetRecordingResponse::Ok(Json(recording)))
            }
            None => Ok(GetRecordingResponse::NotFound),
        }
    }
}

pub async fn require_recording_view_access(
    ctx: &AuthenticatedRequestContext,
    recording: &Recording::Model,
) -> Result<(), WarpgateError> {
    if matches!(
        ctx.auth,
        warpgate_common_http::RequestAuthorization::ClusterToken
    ) || crate::api::admin_permission_set(ctx).await?.is_admin()
    {
        return Ok(());
    }

    if recording.kind != RecordingKind::Terminal {
        return Err(WarpgateError::NoAdminPermission(
            AdminPermission::RecordingsView,
        ));
    }

    let Some(user) = ctx.auth.as_full_user() else {
        return Err(WarpgateError::NoAdminPermission(
            AdminPermission::RecordingsView,
        ));
    };
    let db = &ctx.services().db;
    let application_role = SecureAccessUserRole::Entity::find_by_id(user.user_id())
        .one(db)
        .await?
        .map(|role| role.application_role)
        .filter(|role| role == "auditor_viewer")
        .unwrap_or_else(|| "developer".to_owned());
    let session = Session::Entity::find_by_id(recording.session_id)
        .one(db)
        .await?
        .ok_or(WarpgateError::NoAdminPermission(
            AdminPermission::RecordingsView,
        ))?;

    let authorized_target_ids = user_authorized_target_ids(db, user.user_id()).await?;
    if !scoped_session_is_visible(
        &application_role,
        user.username(),
        session.username.as_deref(),
        target_id_from_snapshot(session.target_snapshot.as_deref()),
        &authorized_target_ids,
    ) {
        return Err(WarpgateError::NoAdminPermission(
            AdminPermission::RecordingsView,
        ));
    }

    Ok(())
}

pub async fn user_authorized_target_ids(
    db: &DatabaseConnection,
    user_id: Uuid,
) -> Result<HashSet<Uuid>, WarpgateError> {
    let assignments = UserRoleAssignment::Entity::find_active()
        .filter(UserRoleAssignment::Column::UserId.eq(user_id))
        .all(db)
        .await?;
    let role_ids = assignments
        .into_iter()
        .map(|assignment| assignment.role_id)
        .collect::<Vec<_>>();
    if role_ids.is_empty() {
        return Ok(HashSet::new());
    }

    let target_assignments = TargetRoleAssignment::Entity::find()
        .filter(TargetRoleAssignment::Column::RoleId.is_in(role_ids))
        .all(db)
        .await?;
    Ok(target_assignments
        .into_iter()
        .map(|assignment| assignment.target_id)
        .collect())
}

pub fn target_id_from_snapshot(snapshot: Option<&str>) -> Option<Uuid> {
    let target: serde_json::Value = serde_json::from_str(snapshot?).ok()?;
    Uuid::parse_str(target.get("id")?.as_str()?).ok()
}

pub fn scoped_session_is_visible(
    application_role: &str,
    username: &str,
    session_username: Option<&str>,
    session_target_id: Option<Uuid>,
    authorized_target_ids: &HashSet<Uuid>,
) -> bool {
    if application_role == "admin" {
        return true;
    }
    if !["developer", "auditor_viewer"].contains(&application_role)
        || username.trim().is_empty()
    {
        return false;
    }
    let has_known_owner = session_username.is_some_and(|session_username| {
        !session_username.trim().is_empty()
            && !session_username.trim().eq_ignore_ascii_case("unknown")
    });
    if !has_known_owner || session_target_id.is_none() {
        return false;
    }
    if application_role == "auditor_viewer" {
        return true;
    }

    session_target_id.is_some_and(|target_id| authorized_target_ids.contains(&target_id))
        && session_username.is_some_and(|session_username| {
            session_username
                .trim()
                .eq_ignore_ascii_case(username.trim())
        })
}

#[cfg(test)]
mod scoped_access_tests {
    use std::collections::HashSet;

    use uuid::Uuid;

    use super::scoped_session_is_visible;

    fn assigned_target() -> Uuid {
        Uuid::from_u128(1)
    }

    fn assigned_targets() -> HashSet<Uuid> {
        HashSet::from([assigned_target()])
    }

    #[test]
    fn developer_can_read_only_own_recordings_on_assigned_targets() {
        assert!(scoped_session_is_visible(
            "developer",
            "dev-user",
            Some("DEV-USER"),
            Some(assigned_target()),
            &assigned_targets(),
        ));
        assert!(!scoped_session_is_visible(
            "developer",
            "dev-user",
            Some("other-user"),
            Some(assigned_target()),
            &assigned_targets(),
        ));
        assert!(!scoped_session_is_visible(
            "developer",
            "dev-user",
            None,
            Some(assigned_target()),
            &assigned_targets(),
        ));
        assert!(!scoped_session_is_visible(
            "developer",
            "dev-user",
            Some("dev-user"),
            None,
            &assigned_targets(),
        ));
    }

    #[test]
    fn auditor_can_read_recordings_for_any_target() {
        assert!(scoped_session_is_visible(
            "auditor_viewer",
            "auditor",
            Some("developer"),
            Some(assigned_target()),
            &assigned_targets(),
        ));
        assert!(scoped_session_is_visible(
            "auditor_viewer",
            "auditor",
            Some("developer"),
            Some(Uuid::from_u128(2)),
            &HashSet::new(),
        ));
        assert!(!scoped_session_is_visible(
            "auditor_viewer",
            "auditor",
            Some("developer"),
            None,
            &assigned_targets(),
        ));
        assert!(!scoped_session_is_visible(
            "auditor_viewer",
            "auditor",
            None,
            Some(assigned_target()),
            &assigned_targets(),
        ));
        assert!(!scoped_session_is_visible(
            "auditor_viewer",
            " ",
            Some("developer"),
            Some(assigned_target()),
            &assigned_targets(),
        ));
        assert!(!scoped_session_is_visible(
            "auditor_viewer",
            "auditor",
            Some("unknown"),
            Some(assigned_target()),
            &assigned_targets(),
        ));
    }

    #[test]
    fn unknown_roles_cannot_read_recordings() {
        assert!(!scoped_session_is_visible(
            "unknown",
            "user",
            Some("user"),
            Some(assigned_target()),
            &assigned_targets(),
        ));
    }
}

async fn find_recording(
    ctx: &AuthenticatedRequestContext,
    id: Uuid,
    kind: Option<RecordingKind>,
) -> poem::Result<Recording::Model> {
    let mut q = Recording::Entity::find_by_id(id);
    if let Some(kind) = kind {
        q = q.filter(Recording::Column::Kind.eq(kind));
    }
    q.one(&ctx.services().db)
        .await
        .map_err(InternalServerError)?
        .ok_or_else(|| NotFoundError.into())
}

#[handler]
pub async fn api_get_recording_tcpdump(
    ctx: Data<&AuthenticatedRequestContext>,
    id: poem::web::Path<Uuid>,
    static_req: StaticFileRequest,
    req: &poem::Request,
) -> poem::Result<poem::Response> {
    require_cluster_or_admin_permission(&ctx, AdminPermission::RecordingsView).await?;

    let recording = find_recording(&ctx, id.0, Some(RecordingKind::Traffic)).await?;
    let owner = recording_owner(&ctx, &recording).await?;
    proxy_or_serve(&ctx, req, owner, None::<&()>, || {
        serve_recording_file(&ctx, &recording, RecordingFile::TcpDumpData, static_req)
    })
    .await
}

#[handler]
pub async fn api_get_recording_data(
    ctx: Data<&AuthenticatedRequestContext>,
    id: poem::web::Path<Uuid>,
    static_req: StaticFileRequest,
    req: &poem::Request,
) -> poem::Result<poem::Response> {
    let recording = find_recording(&ctx, id.0, None).await?;
    require_recording_view_access(&ctx, &recording).await?;
    let owner = recording_owner(&ctx, &recording).await?;
    proxy_or_serve(&ctx, req, owner, None::<&()>, || {
        serve_recording_file(&ctx, &recording, RecordingFile::NDJsonData, static_req)
    })
    .await
}

#[handler]
pub async fn api_get_recording_index(
    ctx: Data<&AuthenticatedRequestContext>,
    id: poem::web::Path<Uuid>,
    static_req: StaticFileRequest,
    req: &poem::Request,
) -> poem::Result<poem::Response> {
    let recording = find_recording(&ctx, id.0, None).await?;
    require_recording_view_access(&ctx, &recording).await?;
    let owner = recording_owner(&ctx, &recording).await?;
    proxy_or_serve(&ctx, req, owner, None::<&()>, || {
        serve_recording_file(&ctx, &recording, RecordingFile::Index, static_req)
    })
    .await
}

async fn serve_recording_file(
    ctx: &AuthenticatedRequestContext,
    recording: &Recording::Model,
    file: RecordingFile,
    static_req: StaticFileRequest,
) -> poem::Result<poem::Response> {
    let access = ctx
        .services()
        .recordings
        .lock()
        .await
        .access(recording, file)
        .await
        .map_err(InternalServerError)?;

    if let Some(url) = access
        .external_access_url()
        .await
        .map_err(InternalServerError)?
    {
        Ok(Redirect::temporary(url).into_response())
    } else if let Some(path) = access.local_path() {
        Ok(static_req
            .create_response(path, false, false)?
            .with_content_type(file.mime_type())
            .into_response())
    } else {
        Err(InternalServerError(std::io::Error::other(
            "recording file access has neither an external URL nor a local path",
        )))
    }
}

/// Messages pushed to a recording live-view WebSocket, serialised with a `type`
/// discriminator the player switches on.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum LiveStreamMessage {
    /// Sent first: whether the session is currently being recorded on this node.
    Start { live: bool },
    /// One raw recording item plus its end byte offset in `data.ndjson`.
    Data {
        data: serde_json::Value,
        offset: u64,
    },
    /// The recording ended.
    End,
}

/// Send one message, false = client disconnected (not an error)
async fn send_message<S: futures::Sink<Message> + Unpin>(
    sink: &mut S,
    message: &LiveStreamMessage,
) -> anyhow::Result<bool> {
    Ok(sink
        .send(Message::Text(serde_json::to_string(message)?))
        .await
        .is_ok())
}

/// next item retained in the received, ignoring Lagged errors
/// None if the receiver is closed (recording ended)
async fn next_retained(receiver: &mut broadcast::Receiver<LiveChunk>) -> Option<LiveChunk> {
    loop {
        match receiver.recv().await {
            Ok(chunk) => return Some(chunk),
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => return None,
        }
    }
}

const LAG_REPLAY_TIMEOUT: Duration = Duration::from_secs(10);

/// Ceiling on a single lag replay. Beyond this, a viewer is treated as unable to
/// keep up and is fast-forwarded to live with a gap rather than served an
/// ever-growing backlog of stale history.
const MAX_LAG_REPLAY_SPAN: u64 = 16 * 1024 * 1024;

/// Replay a part of the scratch recording between two points
/// If the last portion has not been written yet, try to wait for a while
/// for it to get written
async fn replay_scratch_span_awaiting<S: futures::Sink<Message> + Unpin>(
    sink: &mut S,
    path: &Path,
    sent: &mut u64,
    target: u64,
    timeout: Duration,
) -> anyhow::Result<bool> {
    let mut deadline = Instant::now() + timeout;

    while *sent < target {
        let read_from = *sent;
        let mut file = tokio::fs::File::open(path).await?;
        file.seek(SeekFrom::Start(*sent)).await?;
        // Line-at-a-time buffered read: the missed span can be arbitrarily
        // large, so memory use must be bounded by one item, not the span
        let mut reader = BufReader::new(file.take(target - *sent));
        let mut line = Vec::new();
        loop {
            line.clear();
            reader.read_until(b'\n', &mut line).await?;
            // the last line will have no newline at the end if it's incomplete
            let Some(item) = line.strip_suffix(b"\n") else {
                // at this point we need to wait and try again
                break;
            };
            let end = *sent + line.len() as u64;
            if !item.is_empty()
                && !send_message(
                    sink,
                    &LiveStreamMessage::Data {
                        data: serde_json::from_slice(item)?,
                        offset: end,
                    },
                )
                .await?
            {
                return Ok(false);
            }
            *sent = end;
        }

        if *sent < target {
            // The timeout only limits waiting on the file to grow, not the
            // (client-paced) sending above
            if *sent > read_from {
                deadline = Instant::now() + timeout;
            } else if Instant::now() > deadline {
                tracing::warn!("Recording file lags its live stream; leaving a gap for the viewer");
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    Ok(true)
}

/// Relay a recording live broadcast into a socket
async fn serve_live_stream(
    mut sink: SplitSink<WebSocketStream, Message>,
    mut source: SplitStream<WebSocketStream>,
    mut receiver: broadcast::Receiver<LiveChunk>,
    path: &Path,
) -> anyhow::Result<()> {
    // Everything already in the scratch has been fetched by the
    // client separately - start at the end of the scratch
    let mut sent = tokio::fs::metadata(&path).await?.len();
    loop {
        let chunk = tokio::select! {
            item = receiver.recv() => match item {
                Ok(chunk) => Some(chunk),
                // Client is lagging - replay everything it has missed
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    let chunk = next_retained(&mut receiver).await;
                    let end = match &chunk {
                        Some(chunk) => chunk.offset - chunk.data.len() as u64,
                        // Recording ended - just replay to the end
                        None => tokio::fs::metadata(&path).await?.len(),
                    };
                    // A viewer too slow to keep up would grow this span without
                    // bound and only ever watch stale history. Past a cap, drop the
                    // completeness guarantee: skip to the retained item's line
                    // boundary and resume live, leaving one gap.
                    if end.saturating_sub(sent) > MAX_LAG_REPLAY_SPAN {
                        tracing::warn!(
                            "Live viewer too far behind; skipping {} bytes to resume live",
                            end - sent
                        );
                        sent = end;
                    } else if !replay_scratch_span_awaiting(&mut sink, &path, &mut sent, end, LAG_REPLAY_TIMEOUT).await? {
                        return Ok(());
                    }
                    chunk
                }
                Err(broadcast::error::RecvError::Closed) => None,
            },
            // Pump the recv stream to detect disconnection
            frame = source.next() => match frame {
                None | Some(Err(_)) => return Ok::<(), anyhow::Error>(()),
                Some(Ok(_)) => continue,
            },
        };
        let message = match chunk {
            Some(LiveChunk { offset, data }) => {
                // Already replayed from the file after a lag
                if offset <= sent {
                    continue;
                }
                sent = offset;
                LiveStreamMessage::Data {
                    data: serde_json::from_slice(&data)?,
                    offset,
                }
            }
            None => LiveStreamMessage::End,
        };
        if !send_message(&mut sink, &message).await? || matches!(message, LiveStreamMessage::End) {
            return Ok(());
        }
    }
}

fn live_stream_response(
    ws: WebSocket,
    live: Option<(broadcast::Receiver<LiveChunk>, std::path::PathBuf)>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| async move {
        let (mut sink, source) = socket.split();

        sink.send(Message::Text(serde_json::to_string(
            &LiveStreamMessage::Start {
                live: live.is_some(),
            },
        )?))
        .await?;

        if let Some((receiver, path)) = live {
            tokio::spawn(async move {
                if let Err(error) = serve_live_stream(sink, source, receiver, &path).await {
                    error!(%error, "Livestream error:");
                }
            });
        }

        Ok::<(), anyhow::Error>(())
    })
}

#[handler]
pub async fn api_get_recording_stream(
    ws: WebSocket,
    ctx: Data<&AuthenticatedRequestContext>,
    id: poem::web::Path<Uuid>,
    req: &poem::Request,
) -> poem::Result<poem::Response> {
    let recording = find_recording(&ctx, id.0, None).await?;
    require_recording_view_access(&ctx, &recording).await?;
    serve_recording_stream(&ctx, req, ws, id.0, recording).await
}

#[handler]
pub async fn api_get_recording_watch_stream(
    ws: WebSocket,
    ctx: Data<&AuthenticatedRequestContext>,
    id: poem::web::Path<Uuid>,
    req: &poem::Request,
) -> poem::Result<poem::Response> {
    if !matches!(ctx.auth, RequestAuthorization::ClusterToken) {
        require_admin_permission(&ctx, None).await?;
    }
    require_cluster_or_admin_permission(&ctx, AdminPermission::RecordingsView).await?;

    let recording = find_recording(&ctx, id.0, Some(RecordingKind::Terminal)).await?;
    let session = Session::Entity::find_by_id(recording.session_id)
        .one(&ctx.services().db)
        .await
        .map_err(InternalServerError)?
        .ok_or_else(|| poem::Error::from(NotFoundError))?;
    if recording.ended.is_some() || session.ended.is_some() {
        return Err(poem::Error::from_status(poem::http::StatusCode::CONFLICT));
    }

    serve_recording_stream(&ctx, req, ws, id.0, recording).await
}

async fn serve_recording_stream(
    ctx: &AuthenticatedRequestContext,
    req: &poem::Request,
    ws: WebSocket,
    id: Uuid,
    recording: Recording::Model,
) -> poem::Result<poem::Response> {
    let owner = recording_owner(&ctx, &recording).await?;

    proxy_or_serve_websocket(ctx, req, ws, owner, async move |ws| {
        let recordings = ctx.services().recordings.lock().await;
        let live = match recordings.subscribe_live(&id).await {
            Some(receiver) => {
                // An in-progress recording is always a local file on the owner
                // node (S3 uploads stream from a local scratch), and only the
                // owner has a live subscription.
                let access = recordings
                    .access(&recording, RecordingFile::NDJsonData)
                    .await
                    .map_err(InternalServerError)?;
                let path = access.local_path().ok_or_else(|| {
                    InternalServerError(std::io::Error::other(
                        "in-progress recording has no local file",
                    ))
                })?;
                Some((receiver, path.to_owned()))
            }
            None => None,
        };

        Ok(live_stream_response(ws, live).into_response())
    })
    .await
}

pub async fn recording_owner(
    ctx: &AuthenticatedRequestContext,
    recording: &Recording::Model,
) -> Result<Owner, WarpgateError> {
    // Completed recordings live in S3 / on disk and are served by any node.
    if recording.ended.is_some() {
        return Ok(Owner::Local);
    }
    let Some(session) = Session::Entity::find_by_id(recording.session_id)
        .one(&ctx.services().db)
        .await?
    else {
        return Ok(Owner::Local);
    };
    session_owner(ctx, &session).await
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;

    use super::*;

    /// `replay_scratch_span_awaiting` replays exactly the complete lines in `sent..target`,
    /// with each offset being the line's end position in the file.
    #[tokio::test]
    async fn file_span_replay() {
        let path = std::env::temp_dir().join(format!("warpgate-test-{}", Uuid::new_v4()));
        //                offsets:  8 ---------- 16 ---------- 24 --- partial tail
        tokio::fs::write(&path, b"{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n{\"d\"")
            .await
            .unwrap();

        let (mut sink, stream) = futures::channel::mpsc::unbounded::<Message>();
        let mut sent = 8;
        assert!(
            replay_scratch_span_awaiting(&mut sink, &path, &mut sent, 24, LAG_REPLAY_TIMEOUT)
                .await
                .unwrap()
        );
        drop(sink);
        tokio::fs::remove_file(&path).await.unwrap();

        assert_eq!(sent, 24);
        let messages: Vec<String> = stream
            .map(|m| match m {
                Message::Text(text) => text,
                other => panic!("unexpected message {other:?}"),
            })
            .collect()
            .await;
        assert_eq!(
            messages,
            vec![
                r#"{"type":"data","data":{"b":2},"offset":16}"#,
                r#"{"type":"data","data":{"c":3},"offset":24}"#,
            ]
        );
    }
}
