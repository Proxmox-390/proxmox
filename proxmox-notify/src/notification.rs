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
        #[serde(
            serialize_with = "proxmox_base64::serialize_as_base64",
            deserialize_with = "proxmox_base64::deserialize_from_base64"
        )]
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

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
/// Determine how the notification shall be sent.
pub enum Recipient {
    /// Use matchers to determine which targets shall be notified.
    ///
    /// This is the default mode of operation, use this unless you have a good
    /// reason not to.
    #[default]
    Matcher,
    /// Deliver notification directly to a target, identified by its ID.
    ///
    /// This is useful for test notifications.
    Target(String),
    /// Deliver notification to an ephemeral sendmail target with given list of recipients.
    ///
    /// This is mainly for handling the legacy-sendmail mode in PVE and PBS.
    Email(EmailRecipient),
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
/// Parameters for [`Recipient::Email`]-based recipients.
pub struct EmailRecipient {
    /// List of email addresses to send mails to.
    pub mailto: Vec<String>,
    /// Email author
    pub author: Option<String>,
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
    #[serde(default)]
    /// The recipient of the notification.
    pub(crate) recipient: Recipient,
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
            recipient: Recipient::Matcher,
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
            recipient: Recipient::Matcher,
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

    /// Return the notification's severity.
    pub fn severity(&self) -> Severity {
        self.metadata.severity
    }

    /// Get access to the notification's metadata fields.
    pub fn fields(&self) -> &HashMap<String, String> {
        &self.metadata.additional_fields
    }

    /// Get mutable access to the notification's metadata fields.
    pub fn fields_mut(&mut self) -> &mut HashMap<String, String> {
        &mut self.metadata.additional_fields
    }

    /// Return the recipient of the notification.
    pub fn recipient(&self) -> &Recipient {
        &self.recipient
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const TEST_MAIL: &[u8] = include_bytes!("../testdata/test1.msg");

    const ALL_SEVERITIES: [Severity; 5] = [
        Severity::Info,
        Severity::Notice,
        Severity::Warning,
        Severity::Error,
        Severity::Unknown,
    ];

    #[test]
    fn severity_string_roundtrip() {
        for severity in ALL_SEVERITIES {
            let parsed: Severity = severity.to_string().parse().unwrap();
            assert_eq!(parsed, severity);
        }
    }

    #[test]
    fn severity_display_matches_serde() {
        for severity in ALL_SEVERITIES {
            let serialized = serde_json::to_value(severity).unwrap();
            assert_eq!(serialized, Value::String(severity.to_string()));
        }
    }

    #[test]
    fn severity_from_invalid_str() {
        assert!("".parse::<Severity>().is_err());
        assert!("Info".parse::<Severity>().is_err());
        assert!("critical".parse::<Severity>().is_err());
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Notice);
        assert!(Severity::Notice < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
    }

    #[test]
    fn from_template() {
        let fields = HashMap::from([("hostname".to_string(), "pve".to_string())]);
        let data = json!({"key": "value"});

        let notification =
            Notification::from_template(Severity::Warning, "test", data.clone(), fields.clone());

        assert_eq!(notification.severity(), Severity::Warning);
        assert_eq!(notification.fields(), &fields);
        assert_eq!(
            notification.content,
            Content::Template {
                template_name: "test".into(),
                data,
            }
        );
    }

    #[test]
    fn new_forwarded_mail() {
        let raw = TEST_MAIL.to_vec();

        let notification =
            Notification::new_forwarded_mail(Severity::Unknown, raw.clone(), HashMap::new())
                .unwrap();

        assert_eq!(notification.severity(), Severity::Unknown);
        assert!(notification.fields().is_empty());
        assert_eq!(notification.content, Content::ForwardedMail { raw });
    }

    #[test]
    fn fields_mut() {
        let mut notification =
            Notification::from_template(Severity::Info, "test", Value::Null, HashMap::new());

        notification
            .fields_mut()
            .insert("type".into(), "vzdump".into());

        assert_eq!(
            notification.fields().get("type").map(String::as_str),
            Some("vzdump")
        );
    }

    #[test]
    fn forwarded_mail_base64_roundtrip() {
        // Not valid UTF-8 and not a multiple of three bytes, so the encoding needs padding.
        let content = Content::ForwardedMail {
            raw: b"\xff\x00mai".to_vec(),
        };

        let serialized = serde_json::to_value(&content).unwrap();
        assert_eq!(serialized, json!({"forwarded-mail": {"raw": "/wBtYWk="}}));

        let deserialized: Content = serde_json::from_value(serialized).unwrap();
        assert_eq!(deserialized, content);

        let content = Content::ForwardedMail {
            raw: TEST_MAIL.to_vec(),
        };

        let serialized = serde_json::to_value(&content).unwrap();
        assert_eq!(
            serialized["forwarded-mail"]["raw"],
            proxmox_base64::encode(TEST_MAIL)
        );

        let deserialized: Content = serde_json::from_value(serialized).unwrap();
        assert_eq!(deserialized, content);
    }

    #[test]
    fn forwarded_mail_base64_invalid() {
        let result = serde_json::from_value::<Content>(json!({"forwarded-mail": {"raw": "$$$"}}));
        assert!(result.is_err());
    }

    #[test]
    fn serde_roundtrip() {
        let fields = HashMap::from([("hostname".to_string(), "pve".to_string())]);
        let notifications = [
            Notification::from_template(Severity::Error, "test", json!({"a": [1, 2]}), fields),
            Notification::new_forwarded_mail(Severity::Info, TEST_MAIL.to_vec(), HashMap::new())
                .unwrap(),
        ];

        for notification in notifications {
            let serialized = serde_json::to_string(&notification).unwrap();
            let deserialized: Notification = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized, notification);
        }
    }
}
