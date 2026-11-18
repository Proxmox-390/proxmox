#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![deny(unsafe_code)]

use std::collections::HashMap;
use std::fmt::Display;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::error;

use proxmox_config_digest::ConfigDigest;
use proxmox_schema::api;
use proxmox_section_config::SectionConfigData;
use proxmox_uuid::Uuid;

#[cfg(feature = "api-impl")]
pub mod api;

pub mod config;
pub mod context;
pub mod endpoints;
pub mod renderer;
pub mod schema;

#[cfg(feature = "send-impl")]
pub mod send;

#[cfg(feature = "api-types")]
pub mod api_types;

mod error;
pub use error::Error;

pub use context::Context;
pub use context::ContextImpl;

#[api()]
#[derive(Clone, Debug, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
/// Severity of a notification
pub enum Severity {
    /// General information
    Info,
    /// A noteworthy event
    Notice,
    /// Warning
    Warning,
    /// Error
    Error,
    /// Unknown severity (e.g. forwarded system mails)
    Unknown,
}

impl Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        match self {
            Severity::Info => f.write_str("info"),
            Severity::Notice => f.write_str("notice"),
            Severity::Warning => f.write_str("warning"),
            Severity::Error => f.write_str("error"),
            Severity::Unknown => f.write_str("unknown"),
        }
    }
}

impl FromStr for Severity {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "info" => Ok(Self::Info),
            "notice" => Ok(Self::Notice),
            "warning" => Ok(Self::Warning),
            "error" => Ok(Self::Error),
            "unknown" => Ok(Self::Unknown),
            _ => Err(Error::invalid_config(format!("invalid severity {s}"))),
        }
    }
}

#[api()]
#[derive(Clone, Debug, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
/// The origin of a notification configuration entry.
pub enum Origin {
    /// User-created config entry
    UserCreated,
    /// Config entry provided by the system
    Builtin,
    /// Config entry provided by the system, but modified by the user.
    ModifiedBuiltin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Content {
    /// Title and body will be rendered as a template
    #[serde(rename_all = "kebab-case")]
    Template {
        /// Name of the used template
        template_name: String,
        /// Data that can be used for template rendering.
        data: Value,
    },
    #[cfg(feature = "mail-forwarder")]
    #[serde(rename_all = "kebab-case")]
    ForwardedMail {
        /// Raw mail contents
        raw: Vec<u8>,
        /// Fallback title
        title: String,
        /// Fallback body
        body: String,
        /// UID to use when calling sendmail
        #[allow(dead_code)] // Unused in some feature flag permutations
        uid: Option<u32>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Metadata {
    /// Notification severity
    severity: Severity,
    /// Timestamp of the notification as a UNIX epoch
    timestamp: i64,
    /// Additional fields for additional key-value metadata
    additional_fields: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
/// Notification which can be sent
pub struct Notification {
    /// Notification content
    content: Content,
    /// Metadata
    metadata: Metadata,
    /// Unique ID
    id: Uuid,
}

impl Notification {
    pub fn from_template<S: AsRef<str>>(
        severity: Severity,
        template_name: S,
        template_data: Value,
        fields: HashMap<String, String>,
    ) -> Self {
        Self {
            metadata: Metadata {
                severity,
                additional_fields: fields,
                timestamp: proxmox_time::epoch_i64(),
            },
            content: Content::Template {
                template_name: template_name.as_ref().to_string(),
                data: template_data,
            },
            id: Uuid::generate(),
        }
    }
    #[cfg(feature = "mail-forwarder")]
    pub fn new_forwarded_mail(raw_mail: &[u8], uid: Option<u32>) -> Result<Self, Error> {
        let message = mail_parser::MessageParser::default()
            .parse(raw_mail)
            .ok_or_else(|| Error::invalid_forwarded_message("could not parse forwarded email"))?;

        let title = message.subject().unwrap_or_default().into();
        let body = message.body_text(0).unwrap_or_default().into();

        let mut additional_fields = HashMap::new();
        additional_fields.insert("hostname".into(), proxmox_sys::nodename().into());
        additional_fields.insert("type".into(), "system-mail".into());

        Ok(Self {
            // Unfortunately we cannot reasonably infer the severity from the
            // mail contents, so just set it to the highest for now so that
            // it is not filtered out.
            content: Content::ForwardedMail {
                raw: raw_mail.into(),
                title,
                body,
                uid,
            },
            metadata: Metadata {
                severity: Severity::Unknown,
                additional_fields,
                timestamp: proxmox_time::epoch_i64(),
            },
            id: Uuid::generate(),
        })
    }

    /// Return the unique ID of this notification.
    pub fn id(&self) -> &Uuid {
        &self.id
    }

    /// Return the notification's timestamp
    pub fn timestamp(&self) -> i64 {
        self.metadata.timestamp
    }
}

/// Notification configuration
#[derive(Debug, Clone)]
pub struct Config {
    config: SectionConfigData,
    private_config: SectionConfigData,
    digest: ConfigDigest,
}

impl Config {
    /// Parse raw config
    pub fn new(
        context: &Context,
        raw_config: &str,
        raw_private_config: &str,
    ) -> Result<Self, Error> {
        let (mut config, digest) = config::config(raw_config)?;
        let (private_config, _) = config::private_config(raw_private_config)?;

        let default_config = context.default_config();

        let builtin_config = config::config_parser()
            .parse("<builtin>", default_config)
            .map_err(|err| Error::ConfigDeserialization(err.into()))?;

        for (key, (builtin_typename, builtin_value)) in &builtin_config.sections {
            if let Some((typename, value)) = config.sections.get_mut(key) {
                if builtin_typename == typename && value == builtin_value {
                    // Entry is built-in and the config entry section in notifications.cfg
                    // is exactly the same.
                    if let Some(obj) = value.as_object_mut() {
                        obj.insert("origin".to_string(), Value::String("builtin".into()));
                    } else {
                        error!("section config entry is not an object. This should not happen");
                    }
                } else {
                    // Entry is built-in, but it has been modified by the user.
                    if let Some(obj) = value.as_object_mut() {
                        obj.insert(
                            "origin".to_string(),
                            Value::String("modified-builtin".into()),
                        );
                    } else {
                        error!("section config entry is not an object. This should not happen");
                    }
                }
            } else {
                let mut val = builtin_value.clone();

                if let Some(obj) = val.as_object_mut() {
                    obj.insert("origin".to_string(), Value::String("builtin".into()));
                } else {
                    error!("section config entry is not an object. This should not happen");
                }
                config
                    .set_data(key, builtin_typename, val)
                    .map_err(|err| Error::ConfigDeserialization(err.into()))?;
            }
        }

        for (_, (_, value)) in config.sections.iter_mut() {
            if let Some(obj) = value.as_object_mut() {
                if obj.get("origin").is_none() {
                    obj.insert("origin".to_string(), Value::String("user-created".into()));
                }
            }
        }

        Ok(Self {
            config,
            digest,
            private_config,
        })
    }

    /// Serialize config
    pub fn write(&self) -> Result<(String, String), Error> {
        let mut c = self.config.clone();
        for (_, (_, value)) in c.sections.iter_mut() {
            // Remove 'origin' parameter, we do not want it in our
            // config fields
            // TODO: Check if there is a better way for this, maybe a
            // separate type for API responses?
            if let Some(obj) = value.as_object_mut() {
                obj.remove("origin");
            } else {
                error!("section config entry is not an object. This should not happen");
            }
        }

        Ok((
            config::write(&c)?,
            config::write_private(&self.private_config)?,
        ))
    }

    /// Returns the SHA256 digest of the configuration.
    /// The digest is only computed once when the configuration deserialized.
    pub fn digest(&self) -> &ConfigDigest {
        &self.digest
    }
}
