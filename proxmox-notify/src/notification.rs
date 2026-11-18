use std::{collections::HashMap, fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use proxmox_schema::api;
use proxmox_uuid::Uuid;

use crate::Error;

#[api]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    #[serde(rename_all = "kebab-case")]
    ForwardedMail {
        /// Raw mail contents
        raw: Vec<u8>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Metadata {
    /// Notification severity
    pub(crate) severity: Severity,
    /// Timestamp of the notification as a UNIX epoch
    pub(crate) timestamp: i64,
    /// Additional fields for additional key-value metadata
    pub(crate) additional_fields: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
/// Notification which can be sent
pub struct Notification {
    /// Notification content
    pub(crate) content: Content,
    /// Metadata
    pub(crate) metadata: Metadata,
    /// Unique ID
    pub(crate) id: Uuid,
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

    pub fn new_forwarded_mail(
        severity: Severity,
        raw_mail: Vec<u8>,
        fields: HashMap<String, String>,
    ) -> Result<Self, Error> {
        Ok(Self {
            content: Content::ForwardedMail { raw: raw_mail },
            metadata: Metadata {
                severity,
                additional_fields: fields,
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
