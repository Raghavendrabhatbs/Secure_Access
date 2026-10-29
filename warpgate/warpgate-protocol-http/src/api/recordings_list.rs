use std::collections::{HashMap, HashSet};

use poem_openapi::param::Query;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;
use warpgate_admin::api::admin_permission_set;
use warpgate_admin::api::recordings_detail::{
    scoped_session_is_visible, target_id_from_snapshot, user_authorized_target_ids,
};
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_db_entities::Recording::{self, RecordingKind};
use warpgate_db_entities::{SecureAccessUserRole, Session, User};

use crate::api::auth_scheme::AuthedSession;

pub struct Api;

#[derive(Clone, Debug, Serialize, Object)]
#[oai(rename = "ScopedRecordingListItem", rename_all = "camelCase")]
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
#[oai(rename = "ScopedRecordingsPage", rename_all = "camelCase")]
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
    #[oai(
        path = "/recordings",
        method = "get",
        operation_id = "get_scoped_recordings"
    )]
    async fn api_get_recordings(
        &self,
        ctx: AuthedSession,
        offset: Query<Option<u64>>,
        limit: Query<Option<u64>>,
    ) -> Result<GetRecordingsResponse, WarpgateError> {
        let db = &ctx.services().db;
        let offset = (*offset).unwrap_or(0);
        let limit = (*limit).unwrap_or(50).clamp(1, 200);
        let permissions = admin_permission_set(&ctx).await?;

        let (is_admin, application_role, username) = if permissions.is_admin()
            || matches!(
                ctx.auth,
                warpgate_common_http::RequestAuthorization::ClusterToken
            ) {
            (true, "admin".to_owned(), None)
        } else {
            let Some(user) = ctx.auth.as_full_user() else {
                return Err(WarpgateError::NoAdminPermission(
                    AdminPermission::RecordingsView,
                ));
            };
            let role = SecureAccessUserRole::Entity::find_by_id(user.user_id())
                .one(db)
                .await?
                .map(|role| role.application_role)
                .filter(|role| role == "auditor_viewer")
                .unwrap_or_else(|| "developer".to_owned());
            (false, role, Some(user.username().to_owned()))
        };

        let authorized_target_ids = if is_admin || application_role == "auditor_viewer" {
            HashSet::new()
        } else {
            let Some(user) = ctx.auth.as_full_user() else {
                return Err(WarpgateError::NoAdminPermission(
                    AdminPermission::RecordingsView,
                ));
            };
            user_authorized_target_ids(db, user.user_id()).await?
        };
        let session_rows = Session::Entity::find().all(db).await?;
        let scoped_sessions = session_rows
            .into_iter()
            .filter_map(|session| {
                let target_id = target_id_from_snapshot(session.target_snapshot.as_deref());
                let target_name = session
                    .target_snapshot
                    .as_deref()
                    .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok())
                    .and_then(|snapshot| {
                        snapshot
                            .get("name")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned)
                    });
                let visible = is_admin
                    || username.as_deref().is_some_and(|username| {
                        scoped_session_is_visible(
                            &application_role,
                            username,
                            session.username.as_deref(),
                            target_id,
                            &authorized_target_ids,
                        )
                    });
                visible.then_some((session.id, (session, target_name)))
            })
            .collect::<HashMap<_, _>>();

        let session_ids = scoped_sessions.keys().copied().collect::<Vec<_>>();
        if session_ids.is_empty() {
            return Ok(GetRecordingsResponse::Ok(Json(RecordingsPage {
                items: Vec::new(),
                offset,
                total: 0,
            })));
        }

        let query = Recording::Entity::find()
            .filter(Recording::Column::Kind.eq(RecordingKind::Terminal))
            .filter(Recording::Column::SessionId.is_in(session_ids))
            .order_by_desc(Recording::Column::Started)
            .order_by_desc(Recording::Column::Id);
        let total = query.clone().paginate(db, limit).num_items().await?;
        let recordings = query.offset(offset).limit(limit).all(db).await?;

        let usernames = recordings
            .iter()
            .filter_map(|recording| {
                scoped_sessions
                    .get(&recording.session_id)
                    .and_then(|(session, _)| session.username.clone())
            })
            .collect::<Vec<_>>();
        let users = if usernames.is_empty() {
            Vec::new()
        } else {
            User::Entity::find()
                .filter(User::Column::Username.is_in(usernames))
                .all(db)
                .await?
        };
        let user_id_by_name = users
            .into_iter()
            .map(|user| (user.username.to_lowercase(), user.id))
            .collect::<HashMap<_, _>>();

        let items = recordings
            .into_iter()
            .map(|recording| {
                let session = scoped_sessions.get(&recording.session_id);
                let username = session.and_then(|(session, _)| session.username.clone());
                let target = session.and_then(|(_, target)| target.clone());
                let recording_status = if recording.ended.is_some() {
                    "completed"
                } else if session.is_some_and(|(session, _)| session.ended.is_some()) {
                    "incomplete"
                } else {
                    "recording"
                };

                RecordingListItem {
                    id: recording.id,
                    name: recording.name,
                    started: recording.started,
                    ended: recording.ended,
                    session_id: recording.session_id,
                    kind: recording.kind,
                    metadata: recording.metadata,
                    generation: recording.generation,
                    user_id: username
                        .as_ref()
                        .and_then(|name| user_id_by_name.get(&name.to_lowercase()).copied()),
                    username,
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
}
