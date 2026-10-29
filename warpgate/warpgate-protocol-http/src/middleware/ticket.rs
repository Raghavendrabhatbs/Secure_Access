use std::net::IpAddr;

use poem::session::Session;
use poem::web::{Data, FromRequest};
use poem::{Endpoint, Middleware, Request};
use serde::Deserialize;
use warpgate_common::Secret;
use warpgate_common_http::SessionAuthorization;
use warpgate_common_http::auth::UnauthenticatedRequestContext;
use warpgate_common_http::logging::get_client_ip;
use warpgate_core::{authorize_ticket, consume_ticket, is_ticket_session_valid};

use crate::common::SessionExt;

pub struct TicketMiddleware {}

impl TicketMiddleware {
    pub const fn new() -> Self {
        Self {}
    }
}

pub struct TicketMiddlewareEndpoint<E: Endpoint> {
    inner: E,
}

impl<E: Endpoint> Middleware<E> for TicketMiddleware {
    type Output = TicketMiddlewareEndpoint<E>;

    fn transform(&self, inner: E) -> Self::Output {
        TicketMiddlewareEndpoint { inner }
    }
}

#[derive(Deserialize)]
struct QueryParams {
    #[serde(rename = "warpgate-ticket")]
    ticket: Option<String>,
}

impl<E: Endpoint> Endpoint for TicketMiddlewareEndpoint<E> {
    type Output = E::Output;

    async fn call(&self, req: Request) -> poem::Result<Self::Output> {
        let mut session_is_temporary = false;
        let session = <&Session>::from_request_without_body(&req).await?;
        let session = session.clone();

        let ctx = Data::<&UnauthenticatedRequestContext>::from_request_without_body(&req).await?;

        if let Some(SessionAuthorization::Ticket { ticket_id, .. }) = session.get_auth() {
            let is_valid = if let Some(ticket_id) = ticket_id {
                is_ticket_session_valid(&ctx.services().db, &ticket_id).await?
            } else {
                false
            };
            if !is_valid {
                session.clear();
            }
        }

        {
            let params: QueryParams = req.params()?;

            let mut ticket_value = params.ticket;

            for h in req.headers().get_all(http::header::AUTHORIZATION) {
                let header_value = h.to_str().unwrap_or("").to_string();
                if let Some((token_type, token_value)) = header_value.split_once(' ')
                    && &token_type.to_lowercase() == "warpgate"
                {
                    ticket_value = Some(token_value.to_string());
                    session_is_temporary = true;
                }
            }

            if let Some(ticket) = ticket_value
                && let Some(authorization) = {
                    let ticket_secret = Secret::new(ticket);
                    let client_ip: Option<IpAddr> = get_client_ip(&req, ctx.services())
                        .await
                        .and_then(|s| s.parse().ok());
                    if let Some((ticket, authorization)) = authorize_ticket(
                        &ctx.services().db,
                        &ctx.services().login_protection,
                        &ticket_secret,
                        client_ip,
                        crate::common::PROTOCOL_NAME,
                    )
                    .await?
                    {
                        if consume_ticket(&ctx.services().db, &ticket.id).await? {
                            Some((ticket.id, authorization))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
            {
                let (ticket_id, authorization) = authorization;
                let (user_info, target) = authorization.into_parts();
                session.set_auth(SessionAuthorization::Ticket {
                    user_id: user_info.id,
                    username: user_info.username,
                    ticket_id: Some(ticket_id),
                    target_id: target.id,
                });
            }
        }

        let resp = self.inner.call(req).await;

        if session_is_temporary {
            session.clear();
        }

        resp
    }
}
