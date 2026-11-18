//! API types for the notification system.
//!
//! Contains the schema-annotated types used for
//!   - endpoint and matcher configuration
//!   - the generic target listing
//!   - send receipts.

use serde::{Deserialize, Serialize};

use proxmox_schema::api;

mod gotify;
pub use gotify::*;

mod sendmail;
pub use sendmail::*;

mod webhook;
pub use webhook::*;

mod smtp;
pub use smtp::*;

mod matcher;
pub use matcher::*;

mod schema;
pub use schema::*;

mod receipt;
pub use receipt::*;

#[api]
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

#[api]
#[derive(Clone, Debug, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
/// Type of the endpoint.
pub enum EndpointType {
    /// Sendmail endpoint
    Sendmail,
    /// SMTP endpoint
    Smtp,
    /// Gotify endpoint
    Gotify,
    /// Webhook endpoint
    Webhook,
}

#[api]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd)]
#[serde(rename_all = "kebab-case")]
/// Target information
pub struct Target {
    /// Name of the endpoint
    pub name: String,
    /// Origin of the endpoint
    pub origin: Origin,
    /// Type of the endpoint
    #[serde(rename = "type")]
    pub endpoint_type: EndpointType,
    /// Target is disabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable: Option<bool>,
    /// Comment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}
