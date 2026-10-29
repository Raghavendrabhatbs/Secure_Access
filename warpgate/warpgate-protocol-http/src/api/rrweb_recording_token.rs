use poem::session::Session;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use serde::{Deserialize, Serialize};
use warpgate_common::{TargetOptions, WarpgateError};
use warpgate_common_http::{RequestAuthorization, SessionAuthorization};
use warpgate_core::{AuthorizedIdentity, ConfigProvider, authorize_for_target};

use crate::api::auth_scheme::AuthedSession;
use crate::common::{SessionExt, rrweb_recording_session_id, rrweb_recording_session_owner};
use crate::proxy::{create_rrweb_recording_token, rrweb_recording_session_id_for_context};

pub struct Api;

#[derive(Deserialize, Object)]
struct RecordingTokenRequest {
    target_name: String,
    recording_context_id: Option<String>,
}

#[derive(Serialize, Object)]
struct RecordingToken {
    token: String,
    expires_at: u64,
    recording_session_id: String,
}

#[derive(ApiResponse)]
enum RecordingTokenResponse {
    #[oai(status = 200)]
    Ok(Json<RecordingToken>),
    #[oai(status = 403)]
    Forbidden,
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 400)]
    BadRequest,
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/rrweb-recording-token",
        method = "post",
        operation_id = "refresh_rrweb_recording_token"
    )]
    async fn refresh_recording_token(
        &self,
        ctx: AuthedSession,
        session: &Session,
        request: Json<RecordingTokenRequest>,
    ) -> Result<RecordingTokenResponse, WarpgateError> {
        let services = ctx.services();
        let Some(target) = services
            .config_provider
            .get_target_by_name(&request.0.target_name)
            .await?
        else {
            return Ok(RecordingTokenResponse::NotFound);
        };
        if !matches!(&target.options, TargetOptions::Http(_)) {
            return Ok(RecordingTokenResponse::Forbidden);
        }

        let authorized_target = match &ctx.auth {
            RequestAuthorization::Session(SessionAuthorization::Ticket { target_id, .. }) => {
                (*target_id == target.id).then_some(target)
            }
            RequestAuthorization::Session(SessionAuthorization::User { user_id, username }) => {
                let identity = AuthorizedIdentity::for_authenticated_session(
                    warpgate_common::auth::AuthStateUserInfo {
                        id: *user_id,
                        username: username.clone(),
                    },
                    crate::common::PROTOCOL_NAME,
                );
                authorize_for_target(services.config_provider.as_ref(), &identity, target)
                    .await?
                    .map(|authorization| authorization.into_parts().1)
            }
            _ => None,
        };
        let Some(target) = authorized_target else {
            return Ok(RecordingTokenResponse::Forbidden);
        };

        let RequestAuthorization::Session(auth) = &ctx.auth else {
            return Ok(RecordingTokenResponse::Forbidden);
        };
        let authentication_type = match auth {
            SessionAuthorization::Ticket { .. } => "ticket",
            SessionAuthorization::User { .. } => "user",
        };
        let username = auth.username().to_owned();
        let warpgate_user_id = auth.user_id().to_string();
        let owner = rrweb_recording_session_owner(auth);
        let recording_session_id =
            if let Some(context_id) = request.0.recording_context_id.as_deref() {
                if uuid::Uuid::parse_str(context_id).is_err() {
                    return Ok(RecordingTokenResponse::BadRequest);
                }
                rrweb_recording_session_id_for_context(&owner, &target.name, context_id)?
            } else {
                rrweb_recording_session_id(session, &owner)
            };
        let warpgate_session_id = session.get_session_id().map(|id| id.to_string());
        let (token, expires_at) = create_rrweb_recording_token(
            &username,
            authentication_type,
            &target.name,
            &recording_session_id,
            Some(&warpgate_user_id),
            warpgate_session_id.as_deref(),
        )?;

        Ok(RecordingTokenResponse::Ok(Json(RecordingToken {
            token,
            expires_at: expires_at.min(u64::MAX as u128) as u64,
            recording_session_id,
        })))
    }
}
