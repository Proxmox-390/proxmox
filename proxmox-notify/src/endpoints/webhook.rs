//! This endpoint implements a generic webhook target, allowing users to send notifications through
//! a highly customizable HTTP request.
//!
//! The configuration options include specifying the HTTP method, URL, headers, and body.
//! URLs, headers, and the body support template expansion using the [`handlebars`] templating engine.
//! For secure handling of passwords or tokens, these values can be stored as secrets.
//! Secrets are kept in a private configuration file, accessible only by root, and are not retrievable via the API.
//! Within templates, secrets can be referenced using `{{ secrets.<name> }}`.
//! Additionally, we take measures to prevent secrets from appearing in logs or error messages.
use std::time::Duration;

use handlebars::{
    Context as HandlebarsContext, Handlebars, Helper, HelperResult, Output, RenderContext,
    RenderErrorReason,
};
use http::Request;
use percent_encoding::AsciiSet;
use serde_json::{Map, Value, json};

use proxmox_http::client::sync::Client;
use proxmox_http::{HttpClient, HttpOptions};

use crate::api_types::{HttpMethod, WebhookConfig, WebhookPrivateConfig};
use crate::endpoints::common::mail;
use crate::renderer::TemplateType;
use crate::{Content, Context, Error, Notification, renderer};

use super::Endpoint;

const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

/// A Webhook notification endpoint.
pub(crate) struct WebhookEndpoint {
    pub config: WebhookConfig,
    pub private_config: WebhookPrivateConfig,
}

impl Endpoint for WebhookEndpoint {
    /// Send a notification to a webhook endpoint.
    fn send(&self, context: &Context, notification: &Notification) -> Result<(), Error> {
        let request = self.build_request(context, notification)?;

        self.create_client(context)?
            .request(request)
            .map_err(|err| self.mask_secret_in_error(err))
            .map_err(Error::http_request_failed)?;

        Ok(())
    }

    /// Return the name of the endpoint.
    fn name(&self) -> &str {
        &self.config.name
    }

    /// Check if the endpoint is disabled
    fn disabled(&self) -> bool {
        self.config.disable.unwrap_or_default()
    }
}

impl WebhookEndpoint {
    fn create_client(&self, context: &Context) -> Result<Client, Error> {
        let proxy_config = context
            .proxy_config()
            .map_err(|err| Error::invalid_config_with_source("invalid proxy configuration", err))?;

        let options = HttpOptions {
            proxy_config,
            ..Default::default()
        };

        Ok(Client::new_with_timeout(options, HTTP_TIMEOUT))
    }

    fn build_request(
        &self,
        context: &Context,
        notification: &Notification,
    ) -> Result<Request<String>, Error> {
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

        let mut fields = Map::new();

        for (field_name, field_value) in &notification.metadata.additional_fields {
            fields.insert(field_name.clone(), Value::String(field_value.to_string()));
        }

        let mut secrets = Map::new();

        for secret in &self.private_config.secret {
            let value = secret.decode_value()?;
            secrets.insert(secret.name.clone(), Value::String(value));
        }

        let data = json!({
            "title": &title,
            "message": &message,
            "severity": notification.metadata.severity,
            "timestamp": notification.metadata.timestamp,
            "fields": fields,
            "secrets": secrets,
        });

        let handlebars = setup_handlebars();
        let body_template = self.base64_decode(self.config.body.as_deref().unwrap_or_default())?;

        let body = handlebars
            .render_template(&body_template, &data)
            .map_err(|err| self.mask_secret_in_error(err))
            .map_err(|err| {
                Error::invalid_config(format!("failed to render webhook body: {err}"))
            })?;

        let url = handlebars
            .render_template(&self.config.url, &data)
            .map_err(|err| self.mask_secret_in_error(err))
            .map_err(|err| Error::invalid_config(format!("failed to render webhook url: {err}")))?;

        let method: &str = self.config.method.into();
        let mut builder = http::Request::builder().uri(url).method(method);

        for header in &self.config.header {
            let value = header.decode_value()?;

            let value = handlebars
                .render_template(&value, &data)
                .map_err(|err| self.mask_secret_in_error(err))
                .map_err(|err| {
                    Error::invalid_config(format!(
                        "failed to render header value template: {value}: {err}"
                    ))
                })?;

            builder = builder.header(header.name.clone(), value);
        }

        // From https://datatracker.ietf.org/doc/html/rfc9110#name-content-length :
        //
        // A user agent SHOULD send Content-Length in a request when the method
        // defines a meaning for enclosed content and it is not sending
        // Transfer-Encoding. For example, a user agent normally sends
        // Content-Length in a POST request even when the value is 0 (indicating
        // empty content). A user agent SHOULD NOT send a Content-Length header
        // field when the request message does not contain content and the
        // method semantics do not anticipate such data.
        //
        // -> send the header always, unless we do a get with no body (which is the expected case
        // for GET)
        let content_length = body.len();
        if !(self.config.method == HttpMethod::Get && content_length == 0) {
            builder = builder.header(http::header::CONTENT_LENGTH, content_length);
        }

        let request = builder
            .body(body)
            .map_err(|err| self.mask_secret_in_error(err))
            .map_err(|err| Error::invalid_config(format!("failed to build http request: {err}")))?;

        Ok(request)
    }

    fn base64_decode(&self, s: &str) -> Result<String, Error> {
        let s = proxmox_base64::decode(s).map_err(|err| {
            Error::invalid_config_with_source("could not decode base64 value", err)
        })?;

        String::from_utf8(s).map_err(|err| {
            Error::invalid_config_with_source(
                "base64 encoded value did not contain valid utf8",
                err,
            )
        })
    }

    /// Mask secrets in errors to avoid them showing up in error messages and log files
    ///
    /// Use this for any error from third-party code where you are not 100%
    /// sure whether it could leak the content of secrets in the error.
    /// For instance, the http client will contain the URL, including
    /// any URL parameters that could contain tokens.
    ///
    /// This function will only mask exact matches, but this should suffice
    /// for the majority of cases.
    fn mask_secret_in_error(&self, error: impl std::fmt::Display) -> String {
        let mut s = error.to_string();

        for secret_value in &self.private_config.secret {
            match secret_value.decode_value() {
                Ok(value) => s = s.replace(&value, "<masked>"),
                Err(e) => return format!("could not decode secret while masking error: {e}"),
            }
        }

        s
    }
}

fn setup_handlebars() -> Handlebars<'static> {
    let mut handlebars = Handlebars::new();

    handlebars.register_helper("url-encode", Box::new(handlebars_percent_encode));
    handlebars.register_helper("json", Box::new(handlebars_json));
    handlebars.register_helper("escape", Box::new(handlebars_escape));

    // There is no escape.
    handlebars.register_escape_fn(handlebars::no_escape);

    handlebars
}

fn handlebars_percent_encode(
    h: &Helper,
    _: &Handlebars,
    _: &HandlebarsContext,
    _rc: &mut RenderContext,
    out: &mut dyn Output,
) -> HelperResult {
    let param0 = h
        .param(0)
        .and_then(|v| v.value().as_str())
        .ok_or_else(|| RenderErrorReason::ParamNotFoundForIndex("url-encode", 0))?;

    // See https://developer.mozilla.org/en-US/docs/Glossary/Percent-encoding
    const FRAGMENT: &AsciiSet = &percent_encoding::CONTROLS
        .add(b':')
        .add(b'/')
        .add(b'?')
        .add(b'#')
        .add(b'[')
        .add(b']')
        .add(b'@')
        .add(b'!')
        .add(b'$')
        .add(b'&')
        .add(b'\'')
        .add(b'(')
        .add(b')')
        .add(b'*')
        .add(b'+')
        .add(b',')
        .add(b';')
        .add(b'=')
        .add(b'%')
        .add(b' ');
    let a = percent_encoding::utf8_percent_encode(param0, FRAGMENT);

    out.write(&a.to_string())?;

    Ok(())
}

fn handlebars_json(
    h: &Helper,
    _: &Handlebars,
    _: &HandlebarsContext,
    _rc: &mut RenderContext,
    out: &mut dyn Output,
) -> HelperResult {
    let param0 = h
        .param(0)
        .map(|v| v.value())
        .ok_or_else(|| RenderErrorReason::ParamNotFoundForIndex("json", 0))?;

    let json =
        serde_json::to_string(param0).map_err(|err| RenderErrorReason::NestedError(err.into()))?;
    out.write(&json)?;

    Ok(())
}

fn handlebars_escape(
    h: &Helper,
    _: &Handlebars,
    _: &HandlebarsContext,
    _rc: &mut RenderContext,
    out: &mut dyn Output,
) -> HelperResult {
    let text = h
        .param(0)
        .and_then(|v| v.value().as_str())
        .ok_or_else(|| RenderErrorReason::ParamNotFoundForIndex("escape", 0))?;

    let val = Value::String(text.to_string());
    let json =
        serde_json::to_string(&val).map_err(|err| RenderErrorReason::NestedError(err.into()))?;
    out.write(&json[1..json.len() - 1])?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::{Severity, api_types::KeyAndBase64Val, context::test};

    #[test]
    fn test_build_request() {
        let data = HashMap::from_iter([
            ("hello".into(), "hello world".into()),
            ("test".into(), "escaped\nstring".into()),
        ]);

        let body_template = r#"
{{ fields.test }}
{{ escape fields.test }}

{{ json fields }}
{{ json fields.hello }}

{{ url-encode fields.hello }}

{{ json severity }}

"#;

        let expected_body = r#"
escaped
string
escaped\nstring

{"hello":"hello world","test":"escaped\nstring"}
"hello world"

hello%20world

"info"

"#;

        let endpoint = WebhookEndpoint {
            config: WebhookConfig {
                name: "test".into(),
                method: HttpMethod::Post,
                url: "http://localhost/{{ url-encode fields.hello }}".into(),
                header: vec![
                    KeyAndBase64Val::new_with_plain_value("X-Severity", "{{ severity }}").into(),
                ],
                body: Some(proxmox_base64::encode(body_template)),
                ..Default::default()
            },
            private_config: WebhookPrivateConfig {
                name: "test".into(),
                ..Default::default()
            },
        };

        let notification = Notification::from_template(Severity::Info, "foo", json!({}), data);

        let context = test::test_context();

        let request = endpoint.build_request(&context, &notification).unwrap();

        assert_eq!(request.uri(), "http://localhost/hello%20world");
        assert_eq!(request.body(), expected_body);
        assert_eq!(request.method(), "POST");

        assert_eq!(request.headers().get("X-Severity").unwrap(), "info");
    }
}
