use crate::config::Config;
use crate::model::{Finding, Severity};
use std::sync::Arc;

pub struct Alerter {
    config: Arc<Config>,
    client: Option<reqwest::Client>,
}

impl Alerter {
    pub fn new(config: Arc<Config>) -> Alerter {
        let client = if config.alert.webhook_url.is_some() {
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .ok()
        } else {
            None
        };
        Alerter { config, client }
    }

    pub async fn dispatch(&self, findings: &[Finding]) {
        for finding in findings {
            self.log(finding);
            if finding.severity < self.config.alert.min_severity {
                continue;
            }
            if self.config.alert.desktop {
                self.desktop(finding);
            }
            if let (Some(url), Some(client)) = (&self.config.alert.webhook_url, &self.client)
                && let Err(err) = self.webhook(client, url, finding).await {
                    tracing::warn!("webhook delivery failed: {err:#}");
                }
        }
    }

    fn log(&self, finding: &Finding) {
        match finding.severity {
            Severity::Critical | Severity::High => tracing::warn!(
                rule = finding.rule_id.as_str(),
                agent = finding.agent_id.as_deref().unwrap_or("-"),
                "{}",
                finding.title
            ),
            _ => tracing::info!(
                rule = finding.rule_id.as_str(),
                agent = finding.agent_id.as_deref().unwrap_or("-"),
                "{}",
                finding.title
            ),
        }
    }

    fn desktop(&self, finding: &Finding) {
        let title = format!("agentmon [{}] {}", finding.severity, finding.rule_id);
        let body = finding.title.clone();

        #[cfg(target_os = "macos")]
        {
            let script = format!(
                "display notification {} with title {}",
                applescript_string(&body),
                applescript_string(&title)
            );
            if std::process::Command::new("/usr/bin/osascript")
                .args(["-e", &script])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                return;
            }
        }

        #[cfg(target_os = "linux")]
        {
            if std::process::Command::new("notify-send")
                .args([&title, &body])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                return;
            }
        }

        if let Err(err) = notify_rust::Notification::new()
            .summary(&title)
            .body(&body)
            .show()
        {
            tracing::debug!("desktop notification unavailable: {err:#}");
        }
    }

    async fn webhook(
        &self,
        client: &reqwest::Client,
        url: &str,
        finding: &Finding,
    ) -> anyhow::Result<()> {
        client
            .post(url)
            .json(finding)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn applescript_string(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn escapes_applescript_strings() {
        assert_eq!(applescript_string("a\"b"), "\"a\\\"b\"");
    }
}
