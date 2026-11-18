use serde::{Deserialize, Serialize};

use proxmox_schema::{Updater, api, api_types::COMMENT_SCHEMA};

use crate::{Origin, schema::ENTITY_NAME_SCHEMA};

pub const GOTIFY_TYPENAME: &str = "gotify";

#[api(
    properties: {
        name: {
            schema: ENTITY_NAME_SCHEMA,
        },
        comment: {
            optional: true,
            schema: COMMENT_SCHEMA,
        },
    }
)]
#[derive(Serialize, Deserialize, Updater, Default)]
#[serde(rename_all = "kebab-case")]
/// Config for Gotify notification endpoints
pub struct GotifyConfig {
    /// Name of the endpoint.
    #[updater(skip)]
    pub name: String,
    /// Gotify Server URL.
    pub server: String,
    /// Comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Deprecated.
    #[serde(skip_serializing)]
    #[updater(skip)]
    pub filter: Option<String>,
    /// Disable this target.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable: Option<bool>,
    /// Origin of this config entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[updater(skip)]
    pub origin: Option<Origin>,
}

#[api]
#[derive(Serialize, Deserialize, Clone, Updater)]
#[serde(rename_all = "kebab-case")]
/// Private configuration for Gotify notification endpoints.
/// This config will be saved to a separate configuration file with stricter
/// permissions (root:root 0600)
pub struct GotifyPrivateConfig {
    /// Name of the endpoint
    #[updater(skip)]
    pub name: String,
    /// Authentication token
    pub token: String,
}

#[api]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
/// The set of properties that can be deleted from a gotify endpoint configuration.
pub enum DeleteableGotifyProperty {
    /// Delete `comment`
    Comment,
    /// Delete `disable`
    Disable,
}
