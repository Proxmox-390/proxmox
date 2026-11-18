use proxmox_schema::{
    ApiStringFormat, ApiType, PropertyString, Schema, StringSchema, Updater, api,
    api_types::{COMMENT_SCHEMA, HTTP_URL_SCHEMA},
};
use serde::{Deserialize, Serialize};

use crate::Error;
use crate::api_types::Origin;

use crate::schema::ENTITY_NAME_SCHEMA;

/// This will be used as a section type in the public/private configuration file.
pub const WEBHOOK_TYPENAME: &str = "webhook";

pub const KEY_AND_BASE64_VALUE_SCHEMA: Schema =
    StringSchema::new("String schema for pairs of keys and base64 encoded values")
        .format(&ApiStringFormat::PropertyString(
            &KeyAndBase64Val::API_SCHEMA,
        ))
        .schema();

#[api]
#[derive(Serialize, Deserialize, Clone, Copy, Default, PartialEq)]
#[serde(rename_all = "kebab-case")]
/// HTTP Method to use.
pub enum HttpMethod {
    /// HTTP POST
    #[default]
    Post,
    /// HTTP PUT
    Put,
    /// HTTP GET
    Get,
}

// We only ever need a &str, so we rather implement this
// instead of Display.
impl From<HttpMethod> for &str {
    fn from(value: HttpMethod) -> Self {
        match value {
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Get => "GET",
        }
    }
}

#[api(
    properties: {
        name: {
            schema: ENTITY_NAME_SCHEMA,
        },
        url: {
            schema: HTTP_URL_SCHEMA,
        },
        comment: {
            optional: true,
            schema: COMMENT_SCHEMA,
        },
        header: {
            type: Array,
            items: {
                schema: KEY_AND_BASE64_VALUE_SCHEMA,
            },
            optional: true,
        },
        secret: {
            type: Array,
            items: {
                schema: KEY_AND_BASE64_VALUE_SCHEMA,
            },
            optional: true,
        },
    }
)]
#[derive(Serialize, Deserialize, Updater, Default, Clone)]
#[serde(rename_all = "kebab-case")]
/// Config for Webhook notification endpoints
pub struct WebhookConfig {
    /// Name of the endpoint.
    #[updater(skip)]
    pub name: String,

    pub method: HttpMethod,

    /// Webhook URL. Supports templating.
    pub url: String,
    /// Array of HTTP headers. Each entry is a property string with a name and a value.
    /// The value property contains the header in base64 encoding. Supports templating.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[updater(serde(skip_serializing_if = "Option::is_none"))]
    pub header: Vec<PropertyString<KeyAndBase64Val>>,
    /// The HTTP body to send. Supports templating.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,

    /// Comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Disable this target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable: Option<bool>,
    /// Origin of this config entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[updater(skip)]
    pub origin: Option<Origin>,
    /// Array of secrets. Each entry is a property string with a name and an optional value.
    /// The value property contains the secret in base64 encoding.
    /// For any API endpoints returning the endpoint config,
    /// only the secret name but not the value will be returned.
    /// When updating the config, also send all secrets that you want
    /// to keep, setting only the name but not the value. Can be accessed from templates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[updater(serde(skip_serializing_if = "Option::is_none"))]
    pub secret: Vec<PropertyString<KeyAndBase64Val>>,
}

#[api(
    properties: {
        name: {
            schema: ENTITY_NAME_SCHEMA,
        },
        secret: {
            type: Array,
            items: {
                schema: KEY_AND_BASE64_VALUE_SCHEMA,
            },
            optional: true,
        },
    }
)]
#[derive(Serialize, Deserialize, Clone, Updater, Default)]
#[serde(rename_all = "kebab-case")]
/// Private configuration for Webhook notification endpoints.
/// This config will be saved to a separate configuration file with stricter
/// permissions (root:root 0600).
pub struct WebhookPrivateConfig {
    /// Name of the endpoint
    #[updater(skip)]
    pub name: String,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[updater(serde(skip_serializing_if = "Option::is_none"))]
    /// Array of secrets. Each entry is a property string with a name,
    /// and a value property. The value property contains the secret
    /// in base64 encoding. Can be accessed from templates.
    pub secret: Vec<PropertyString<KeyAndBase64Val>>,
}

#[api]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
/// Webhook configuration properties that can be deleted.
pub enum DeleteableWebhookProperty {
    /// Delete `comment`.
    Comment,
    /// Delete `disable`.
    Disable,
    /// Delete `header`.
    Header,
    /// Delete `body`.
    Body,
    /// Delete `secret`.
    Secret,
}

#[api]
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
/// Datatype used to represent key-value pairs, the value
/// being encoded in base64.
pub struct KeyAndBase64Val {
    /// Name
    pub name: String,
    /// Base64 encoded value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

impl KeyAndBase64Val {
    #[cfg(test)]
    pub fn new_with_plain_value(name: &str, value: &str) -> Self {
        let value = proxmox_base64::encode(value);

        Self {
            name: name.into(),
            value: Some(value),
        }
    }

    /// Decode the contained value, returning the plaintext value
    ///
    /// Returns an error if the contained value is not valid base64-encoded
    /// text.
    pub fn decode_value(&self) -> Result<String, Error> {
        let value = self.value.as_deref().unwrap_or_default();
        let bytes = proxmox_base64::decode(value).map_err(|_| {
            Error::invalid_config(format!(
                "could not decode base64 value with key '{}'",
                self.name
            ))
        })?;
        let value = String::from_utf8(bytes).map_err(|_| {
            Error::invalid_config(format!(
                "could not decode UTF8 string from base64, key '{}'",
                self.name
            ))
        })?;

        Ok(value)
    }
}
