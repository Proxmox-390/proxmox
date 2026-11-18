use std::collections::HashMap;
use std::time::Duration;

use serde_json::json;

use proxmox_http::client::sync::Client;
use proxmox_http::{HttpClient, HttpOptions};

use crate::api_types::{GotifyConfig, GotifyPrivateConfig};
use crate::endpoints::common::mail;
use crate::renderer::TemplateType;
use crate::{Content, Context, Error, Notification, Severity, renderer};

use super::Endpoint;

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

fn severity_to_priority(level: Severity) -> u32 {
    match level {
        Severity::Info => 1,
        Severity::Notice => 3,
        Severity::Warning => 5,
        Severity::Error => 9,
        Severity::Unknown => 3,
    }
}

/// A Gotify notification endpoint.
pub(crate) struct GotifyEndpoint {
    pub config: GotifyConfig,
    pub private_config: GotifyPrivateConfig,
}

impl Endpoint for GotifyEndpoint {
    fn send(&self, context: &Context, notification: &Notification) -> Result<(), Error> {
        let (title, message) = match &notification.content {
            Content::Template {
                template_name,
                data,
            } => {
                let rendered_title =
                    renderer::render_template(context, TemplateType::Subject, template_name, data)?;
                let rendered_message = renderer::render_template(
                    context,
                    TemplateType::PlaintextBody,
                    template_name,
                    data,
                )?;

                (rendered_title, rendered_message)
            }

            Content::ForwardedMail { raw, .. } => mail::parse_subject_and_plaintext_body(raw)?,
        };

        // We don't have a TemplateRenderer::Markdown yet, so simply put everything
        // in code tags. Otherwise tables etc. are not formatted properly
        let message = format!("```\n{message}\n```");

        let body = json!({
            "title": &title,
            "message": &message,
            "priority": severity_to_priority(notification.metadata.severity),
            "extras": {
                "client::display": {
                    "contentType": "text/markdown"
                }
            }
        });

        let body = serde_json::to_vec(&body)
            .map_err(|err| Error::other_with_source("could not serialize JSON body", err))?;

        let extra_headers = HashMap::from([
            (
                http::header::AUTHORIZATION.to_string(),
                format!("Bearer {}", self.private_config.token),
            ),
            ("X-Gotify-Key".into(), self.private_config.token.clone()),
            (
                http::header::CONTENT_LENGTH.to_string(),
                body.len().to_string(),
            ),
        ]);

        let proxy_config = context
            .proxy_config()
            .map_err(|err| Error::invalid_config_with_source("invalid proxy configuration", err))?;

        let options = HttpOptions {
            proxy_config,
            ..Default::default()
        };

        let client = Client::new_with_timeout(options, HTTP_TIMEOUT);
        let uri = format!("{}/message", self.config.server);

        client
            .post(
                &uri,
                Some(body.as_slice()),
                Some("application/json"),
                Some(&extra_headers),
            )
            .map_err(Error::http_request_failed)?;

        Ok(())
    }

    fn name(&self) -> &str {
        &self.config.name
    }

    /// Check if the endpoint is disabled
    fn disabled(&self) -> bool {
        self.config.disable.unwrap_or_default()
    }
}
