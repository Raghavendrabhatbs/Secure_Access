use url::Url;
use warpgate_common::{Target, TargetHTTPOptions, TargetOptions};
use warpgate_common_http::{
    AuthenticatedRequestContext, RequestAuthorization, SessionAuthorization,
};
use warpgate_core::ConfigProvider;
use warpgate_tls::TlsMode;

pub fn http_target_origin(options: &TargetHTTPOptions) -> Option<String> {
    let mut url = Url::parse(&options.url).ok()?;
    let scheme = match options.tls.mode {
        TlsMode::Disabled => "http".to_owned(),
        TlsMode::Preferred => url.scheme().to_owned(),
        TlsMode::Required => "https".to_owned(),
    };
    url.set_scheme(&scheme).ok()?;
    url.set_username("").ok()?;
    url.set_password(None).ok()?;
    Some(url.origin().ascii_serialization())
}

pub fn http_target_navigation_origin(options: &TargetHTTPOptions) -> Option<String> {
    let origin = Url::parse(&http_target_origin(options)?).ok()?;
    let host = origin.host_str()?;
    let navigation_host = host.strip_prefix("www.").unwrap_or(host).to_owned();
    let mut navigation_origin = origin;
    navigation_origin.set_host(Some(&navigation_host)).ok()?;
    Some(navigation_origin.origin().ascii_serialization())
}

pub fn http_target_allows_origin(options: &TargetHTTPOptions, candidate_origin: &str) -> bool {
    let Some(configured) = http_target_origin(options).and_then(|value| Url::parse(&value).ok())
    else {
        return false;
    };
    let Ok(candidate) = Url::parse(candidate_origin) else {
        return false;
    };
    if candidate.origin() == configured.origin() {
        return true;
    }

    let Some(configured_host) = configured.host_str() else {
        return false;
    };
    let Some(candidate_host) = candidate.host_str() else {
        return false;
    };
    let Some(navigation_host) = configured_host.strip_prefix("www.") else {
        return false;
    };
    candidate.scheme() == configured.scheme()
        && candidate.port_or_known_default() == configured.port_or_known_default()
        && candidate_host == navigation_host
}

pub fn target_http_origin(target: &Target) -> Option<String> {
    match &target.options {
        TargetOptions::Http(options) => http_target_origin(options),
        _ => None,
    }
}

pub async fn authorized_http_target_for_origin(
    ctx: &AuthenticatedRequestContext,
    origin: &str,
) -> poem::Result<Option<String>> {
    let config_provider = ctx.services().config_provider.as_ref();
    let target = match &ctx.auth {
        RequestAuthorization::Session(SessionAuthorization::Ticket { target_id, .. }) => {
            config_provider.get_target_by_id(*target_id).await?
        }
        RequestAuthorization::Session(SessionAuthorization::User { user_id, .. }) => {
            let authorized_ids = config_provider.authorized_target_ids(*user_id).await?;
            config_provider
                .list_targets()
                .await?
                .into_iter()
                .find(|target| {
                    authorized_ids.contains(&target.id)
                        && target_http_origin(target).as_deref() == Some(origin)
                })
        }
        _ => None,
    };

    Ok(target
        .filter(|target| target_http_origin(target).as_deref() == Some(origin))
        .map(|target| target.name))
}

#[cfg(test)]
mod tests {
    use warpgate_common::Tls;

    use super::*;

    fn options(url: &str, mode: TlsMode) -> TargetHTTPOptions {
        TargetHTTPOptions {
            url: url.to_owned(),
            tls: Tls { mode, verify: true },
            headers: None,
            external_host: None,
        }
    }

    #[test]
    fn target_origin_applies_tls_mode_and_omits_credentials_and_path() {
        assert_eq!(
            http_target_origin(&options(
                "http://user:secret@example.test:8080/app",
                TlsMode::Required,
            )),
            Some("https://example.test:8080".to_owned())
        );
        assert_eq!(
            http_target_origin(&options("https://example.test/app", TlsMode::Disabled)),
            Some("http://example.test".to_owned())
        );
        assert_eq!(
            http_target_origin(&options("https://example.test/app", TlsMode::Preferred)),
            Some("https://example.test".to_owned())
        );
    }

    #[test]
    fn www_target_allows_only_its_bare_domain_alias_on_same_scheme_and_port() {
        let options = options("https://www.wikipedia.org", TlsMode::Required);

        assert!(http_target_allows_origin(
            &options,
            "https://www.wikipedia.org"
        ));
        assert!(http_target_allows_origin(&options, "https://wikipedia.org"));
        assert!(!http_target_allows_origin(
            &options,
            "https://en.wikipedia.org"
        ));
        assert!(!http_target_allows_origin(
            &options,
            "https://admin.wikipedia.org"
        ));
        assert!(!http_target_allows_origin(
            &options,
            "https://www.wikipedia.org.attacker.example"
        ));
        assert!(!http_target_allows_origin(&options, "http://wikipedia.org"));
        assert!(!http_target_allows_origin(
            &options,
            "https://wikipedia.org:444"
        ));
    }
}
