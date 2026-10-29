use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use url::Url;

#[derive(Serialize)]
struct AnalyzeRequest<'a> {
    command: &'a str,
    session_id: &'a str,
    username: &'a str,
}

#[derive(Deserialize)]
struct AnalyzeResponse {
    verdict: String,
    risk_score: f32,
    reason: String,
}

pub enum CommandDecision {
    Disabled,
    Allowed,
    Blocked(String),
}

fn configured_base_url() -> Option<String> {
    std::env::var("SECUREACCESS_AI_AGENT_URL")
        .or_else(|_| std::env::var("AI_AGENT_URL"))
        .ok()
        .filter(|url| !url.trim().is_empty())
        .map(|url| url.trim_end_matches('/').to_string())
}

fn alert_secret() -> anyhow::Result<String> {
    let secret = std::env::var("ALERT_SECRET")
        .map_err(|_| anyhow::anyhow!("ALERT_SECRET is not set for the Warpgate process"))?;
    if secret.trim().is_empty() {
        anyhow::bail!("ALERT_SECRET is empty for the Warpgate process");
    }
    Ok(secret)
}

fn user_block_check_url(base_url: &str, username: &str) -> anyhow::Result<Url> {
    let mut check_url = Url::parse(&format!(
        "{}/security/check",
        base_url.trim_end_matches('/')
    ))?;
    check_url
        .path_segments_mut()
        .map_err(|_| anyhow::anyhow!("Invalid Secure Access API URL"))?
        .push(username);
    Ok(check_url)
}

pub async fn analyze_command(command: &str, session_id: &str, username: &str) -> CommandDecision {
    let Some(base_url) = configured_base_url() else {
        warn!(
            "SSH command inspection is disabled: set SECUREACCESS_AI_AGENT_URL for the Warpgate process"
        );
        return CommandDecision::Disabled;
    };

    let result = async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        let body = serde_json::to_vec(&AnalyzeRequest {
            command,
            session_id,
            username,
        })?;
        let response = client
            .post(format!("{}/ssh/analyze", base_url.trim_end_matches('/')))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await?
            .error_for_status()?;
        let response = serde_json::from_str::<AnalyzeResponse>(&response.text().await?)?;
        Ok::<_, anyhow::Error>(response)
    }
    .await;

    match result {
        Ok(response) if response.verdict == "allow" => CommandDecision::Allowed,
        Ok(response) if response.verdict == "block" => {
            if response.risk_score >= 0.7
                && let Err(error) = persist_user_block(
                    &base_url,
                    command,
                    session_id,
                    username,
                    response.risk_score,
                    &response.reason,
                )
                .await
            {
                error!(
                    ?error,
                    session_id, username, "Failed to persist SSH user security block"
                );
            }
            CommandDecision::Blocked(response.reason)
        }
        Ok(_) => {
            let reason = "SSH analysis service returned an invalid verdict.".to_string();
            alert_on_analysis_failure(command, &reason, session_id, username).await;
            CommandDecision::Blocked(reason)
        }
        Err(error) => {
            error!(
                ?error,
                session_id, "SSH analysis service failed; closing the session"
            );
            let reason = "SSH analysis service is unavailable; command blocked.".to_string();
            alert_on_analysis_failure(command, &reason, session_id, username).await;
            CommandDecision::Blocked(reason)
        }
    }
}

pub async fn is_user_blocked(username: &str) -> anyhow::Result<bool> {
    let Some(base_url) = configured_base_url() else {
        return Ok(false);
    };
    let secret = alert_secret()?;
    let check_url = user_block_check_url(&base_url, username)?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let response = client
        .get(check_url)
        .header("X-Alert-Secret", secret)
        .send()
        .await?
        .error_for_status()?;
    let status = serde_json::from_str::<serde_json::Value>(&response.text().await?)?;
    status
        .get("blocked")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| anyhow::anyhow!("Secure Access returned an invalid block-list response"))
}

async fn persist_user_block(
    base_url: &str,
    command: &str,
    session_id: &str,
    username: &str,
    risk_score: f32,
    reason: &str,
) -> anyhow::Result<()> {
    if username.trim().is_empty() || username == "unknown" {
        anyhow::bail!("Cannot persist a security block without an authenticated username");
    }
    let severity = if risk_score >= 0.9 {
        "CRITICAL"
    } else {
        "HIGH"
    };
    let payload = serde_json::json!({
        "username": username,
        "reason": reason.chars().take(1000).collect::<String>(),
        "command": command.chars().take(4096).collect::<String>(),
        "severity": severity,
        "session_id": session_id,
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    client
        .post(format!("{base_url}/security/block"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("X-Alert-Secret", alert_secret()?)
        .body(serde_json::to_vec(&payload)?)
        .send()
        .await?
        .error_for_status()?;
    info!(
        session_id,
        username, severity, "Persisted SSH security block for future logins"
    );
    Ok(())
}

async fn alert_on_analysis_failure(command: &str, reason: &str, session_id: &str, username: &str) {
    let Ok(secret) = alert_secret() else {
        error!("Could not send SSH inspection failure alert: ALERT_SECRET is not configured");
        return;
    };
    let Some(base_url) = configured_base_url() else {
        return;
    };

    let payload = serde_json::json!({
        "command": command.chars().take(512).collect::<String>(),
        "reason": reason.chars().take(500).collect::<String>(),
        "username": username,
        "session_id": session_id,
        "category": "SSH Inspection Failure",
        "severity": "CRITICAL"
    });

    let result = async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;
        let response = client
            .post(format!("{}/ssh/alert", base_url.trim_end_matches('/')))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("X-Alert-Secret", secret)
            .body(serde_json::to_vec(&payload)?)
            .send()
            .await?
            .error_for_status()?;
        Ok::<_, anyhow::Error>(response.status())
    }
    .await;

    if let Err(error) = result {
        error!(
            ?error,
            session_id, "Failed to submit SSH inspection failure alert"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_analysis_response() {
        let response: AnalyzeResponse = serde_json::from_str(
            r#"{"verdict":"block","risk_score":1.0,"reason":"risky command"}"#,
        )
        .unwrap();
        assert_eq!(response.verdict, "block");
        assert_eq!(response.reason, "risky command");
    }

    #[test]
    fn builds_block_check_url_without_an_empty_path_segment() {
        let check_url = user_block_check_url("http://127.0.0.1:8765/", "admin").unwrap();
        assert_eq!(
            check_url.as_str(),
            "http://127.0.0.1:8765/security/check/admin"
        );
    }
}
