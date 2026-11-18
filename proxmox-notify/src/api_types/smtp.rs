use serde::{Deserialize, Serialize};

use proxmox_schema::{Updater, api, api_types::COMMENT_SCHEMA};

use crate::Origin;
use crate::schema::{EMAIL_SCHEMA, ENTITY_NAME_SCHEMA, USER_SCHEMA};

pub const SMTP_TYPENAME: &str = "smtp";

#[api]
#[derive(Debug, Serialize, Deserialize, Default, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
/// Connection security
pub enum SmtpMode {
    /// No encryption (insecure), plain SMTP
    Insecure,
    /// Upgrade to TLS after connecting
    #[serde(rename = "starttls")]
    StartTls,
    /// Use TLS-secured connection
    #[default]
    Tls,
}

#[api(
    properties: {
        name: {
            schema: ENTITY_NAME_SCHEMA,
        },
        mailto: {
            type: Array,
            items: {
                schema: EMAIL_SCHEMA,
            },
            optional: true,
        },
        "mailto-user": {
            type: Array,
            items: {
                schema: USER_SCHEMA,
            },
            optional: true,
        },
        comment: {
            optional: true,
            schema: COMMENT_SCHEMA,
        },
    },
)]
#[derive(Debug, Serialize, Deserialize, Updater, Default)]
#[serde(rename_all = "kebab-case")]
/// Config for SMTP notification endpoints
pub struct SmtpConfig {
    /// Name of the endpoint.
    #[updater(skip)]
    pub name: String,
    /// Host name or IP of the SMTP relay.
    pub server: String,
    /// The port to connect to.
    /// If not set, the used port defaults to 25 (insecure), 465 (tls)
    /// or 587 (starttls), depending on the value of mode
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<SmtpMode>,
    /// Username to use during authentication.
    /// If no username is set, no authentication will be performed.
    /// The PLAIN and LOGIN authentication methods are supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Mail address to send a mail to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[updater(serde(skip_serializing_if = "Option::is_none"))]
    pub mailto: Vec<String>,
    /// Users to send a mail to. The email address of the user
    /// will be looked up in users.cfg.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[updater(serde(skip_serializing_if = "Option::is_none"))]
    pub mailto_user: Vec<String>,
    /// `From` address for the mail.
    /// SMTP relays might require that this address is owned by the user
    /// in order to avoid spoofing. The `From` header in the email will be
    /// set to `$author <$from-address>`.
    pub from_address: String,
    /// Author of the mail. Defaults to 'Proxmox Backup Server ($hostname)'
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
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
}

#[api]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
/// The set of properties that can be deleted from a smtp endpoint configuration.
pub enum DeleteableSmtpProperty {
    /// Delete `author`
    Author,
    /// Delete `comment`
    Comment,
    /// Delete `disable`
    Disable,
    /// Delete `mailto`
    Mailto,
    /// Delete `mailto-user`
    MailtoUser,
    /// Delete `password`
    Password,
    /// Delete `port`
    Port,
    /// Delete `username`
    Username,
}

#[api]
#[derive(Serialize, Deserialize, Clone, Updater, Debug)]
#[serde(rename_all = "kebab-case")]
/// Private configuration for SMTP notification endpoints.
/// This config will be saved to a separate configuration file with stricter
/// permissions (root:root 0600)
pub struct SmtpPrivateConfig {
    /// Name of the endpoint
    #[updater(skip)]
    pub name: String,
    /// The password to use during authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}
