use poem_openapi::param::Path;
use poem_openapi::payload::Json;
use poem_openapi::{ApiResponse, Object, OpenApi};
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, EntityTrait, ModelTrait};
use uuid::Uuid;
use warpgate_common::{AdminPermission, WarpgateError};
use warpgate_core::logging::AuditEvent;
use warpgate_core::ticket_requests::delete_ticket;
use warpgate_db_entities::{Target, Ticket, User};

use super::AdminContext;
use super::common::require_secure_access_admin;

pub struct Api;

#[derive(Object)]
struct UpdateTicketMetadataRequest {
    expiry: Option<time::OffsetDateTime>,
    number_of_uses: Option<i16>,
    description: Option<String>,
}

#[derive(ApiResponse)]
enum DeleteTicketResponse {
    #[oai(status = 204)]
    Deleted,

    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum UpdateTicketResponse {
    #[oai(status = 204)]
    Updated,

    #[oai(status = 400)]
    BadRequest(Json<String>),

    #[oai(status = 404)]
    NotFound,
}

#[OpenApi]
impl Api {
    #[oai(
        path = "/tickets/:id",
        method = "put",
        operation_id = "update_ticket_metadata"
    )]
    async fn api_update_ticket_metadata(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
        body: Json<UpdateTicketMetadataRequest>,
    ) -> Result<UpdateTicketResponse, WarpgateError> {
        admin.require(AdminPermission::TicketsCreate)?;
        require_secure_access_admin(&admin).await?;

        if body.number_of_uses.is_some_and(|uses| uses < 0) {
            return Ok(UpdateTicketResponse::BadRequest(Json(
                "number_of_uses must be zero or greater, or null".into(),
            )));
        }

        if body.expiry.is_some_and(|expiry| {
            warpgate_core::is_ticket_expired(Some(expiry), time::OffsetDateTime::now_utc())
        }) {
            return Ok(UpdateTicketResponse::BadRequest(Json(
                "expiry must be in the future".into(),
            )));
        }

        let db = &admin.services().db;
        let Some(ticket) = Ticket::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(UpdateTicketResponse::NotFound);
        };
        let previous_expiry = ticket.expiry;
        let (Some(user), Some(target)) = (
            ticket.find_related(User::Entity).one(db).await?,
            ticket.find_related(Target::Entity).one(db).await?,
        ) else {
            return Err(WarpgateError::InconsistentState(
                "ticket user or target not found".into(),
            ));
        };

        let mut model: Ticket::ActiveModel = ticket.into();
        model.expiry = Set(body.expiry);
        model.uses_left = Set(body.number_of_uses);
        model.description = Set(body.description.clone().unwrap_or_default());
        let ticket = model.update(db).await?;

        AuditEvent::TicketUpdated {
            ticket_id: ticket.id,
            user_id: user.id,
            username: user.username,
            target: target.name,
            previous_expiry,
            new_expiry: ticket.expiry,
            actor_user_id: admin.auth.user_id(),
        }
        .emit();

        Ok(UpdateTicketResponse::Updated)
    }

    #[oai(
        path = "/tickets/:id",
        method = "delete",
        operation_id = "delete_ticket"
    )]
    async fn api_delete_ticket(
        &self,
        admin: AdminContext,
        id: Path<Uuid>,
    ) -> Result<DeleteTicketResponse, WarpgateError> {
        use warpgate_db_entities::Ticket;

        admin.require(AdminPermission::TicketsDelete)?;
        require_secure_access_admin(&admin).await?;

        let db = &admin.services().db;

        let Some(ticket) = Ticket::Entity::find_by_id(id.0).one(db).await? else {
            return Ok(DeleteTicketResponse::NotFound);
        };

        let user = User::Entity::find_by_id(ticket.user_id).one(db).await?;

        let target = Target::Entity::find_by_id(ticket.target_id).one(db).await?;

        let audit_context = user
            .zip(target)
            .map(|(user, target)| (user.id, user.username, target.name));
        delete_ticket(db, ticket.id).await?;
        if let Some((user_id, username, target)) = audit_context {
            AuditEvent::TicketDeleted {
                ticket_id: ticket.id,
                user_id,
                username,
                target,
                actor_user_id: admin.auth.user_id(),
            }
            .emit();
        }
        Ok(DeleteTicketResponse::Deleted)
    }
}
