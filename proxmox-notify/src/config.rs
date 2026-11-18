use std::sync::OnceLock;

use proxmox_config_digest::ConfigDigest;
use proxmox_schema::{ApiType, ObjectSchema};
use proxmox_section_config::{SectionConfig, SectionConfigData, SectionConfigPlugin};
use serde_json::Value;
use tracing::error;

use crate::api_types::{
    GOTIFY_TYPENAME, GotifyConfig, GotifyPrivateConfig, MATCHER_TYPENAME, MatcherConfig,
    SENDMAIL_TYPENAME, SMTP_TYPENAME, SendmailConfig, SmtpConfig, SmtpPrivateConfig,
    WEBHOOK_TYPENAME, WebhookConfig, WebhookPrivateConfig,
};
use crate::schema::BACKEND_NAME_SCHEMA;
use crate::{Context, Error};

/// Section config schema for the public config file.
pub fn config_parser() -> &'static SectionConfig {
    static CONFIG: OnceLock<SectionConfig> = OnceLock::new();
    CONFIG.get_or_init(config_init)
}

/// Section config schema for the private config file.
pub fn private_config_parser() -> &'static SectionConfig {
    static CONFIG: OnceLock<SectionConfig> = OnceLock::new();
    CONFIG.get_or_init(private_config_init)
}

fn config_init() -> SectionConfig {
    let mut config = SectionConfig::new(&BACKEND_NAME_SCHEMA);

    {
        const SENDMAIL_SCHEMA: &ObjectSchema = SendmailConfig::API_SCHEMA.unwrap_object_schema();
        config.register_plugin(SectionConfigPlugin::new(
            SENDMAIL_TYPENAME.to_string(),
            Some(String::from("name")),
            SENDMAIL_SCHEMA,
        ));
    }
    {
        const SMTP_SCHEMA: &ObjectSchema = SmtpConfig::API_SCHEMA.unwrap_object_schema();
        config.register_plugin(SectionConfigPlugin::new(
            SMTP_TYPENAME.to_string(),
            Some(String::from("name")),
            SMTP_SCHEMA,
        ));
    }
    {
        const GOTIFY_SCHEMA: &ObjectSchema = GotifyConfig::API_SCHEMA.unwrap_object_schema();
        config.register_plugin(SectionConfigPlugin::new(
            GOTIFY_TYPENAME.to_string(),
            Some(String::from("name")),
            GOTIFY_SCHEMA,
        ));
    }
    {
        const WEBHOOK_SCHEMA: &ObjectSchema = WebhookConfig::API_SCHEMA.unwrap_object_schema();
        config.register_plugin(SectionConfigPlugin::new(
            WEBHOOK_TYPENAME.to_string(),
            Some(String::from("name")),
            WEBHOOK_SCHEMA,
        ));
    }

    const MATCHER_SCHEMA: &ObjectSchema = MatcherConfig::API_SCHEMA.unwrap_object_schema();
    config.register_plugin(SectionConfigPlugin::new(
        MATCHER_TYPENAME.to_string(),
        Some(String::from("name")),
        MATCHER_SCHEMA,
    ));

    config
}

fn private_config_init() -> SectionConfig {
    let mut config = SectionConfig::new(&BACKEND_NAME_SCHEMA);

    const GOTIFY_SCHEMA: &ObjectSchema = GotifyPrivateConfig::API_SCHEMA.unwrap_object_schema();
    config.register_plugin(SectionConfigPlugin::new(
        GOTIFY_TYPENAME.to_string(),
        Some(String::from("name")),
        GOTIFY_SCHEMA,
    ));

    const SMTP_SCHEMA: &ObjectSchema = SmtpPrivateConfig::API_SCHEMA.unwrap_object_schema();
    config.register_plugin(SectionConfigPlugin::new(
        SMTP_TYPENAME.to_string(),
        Some(String::from("name")),
        SMTP_SCHEMA,
    ));

    const WEBHOOK_SCHEMA: &ObjectSchema = WebhookPrivateConfig::API_SCHEMA.unwrap_object_schema();
    config.register_plugin(SectionConfigPlugin::new(
        WEBHOOK_TYPENAME.to_string(),
        Some(String::from("name")),
        WEBHOOK_SCHEMA,
    ));

    config
}

pub fn config(raw_config: &str) -> Result<(SectionConfigData, ConfigDigest), Error> {
    let digest = ConfigDigest::from_slice(raw_config.as_bytes());
    let data = config_parser()
        .parse("notifications.cfg", raw_config)
        .map_err(Error::config_deserialization)?;

    Ok((data, digest))
}

pub fn private_config(raw_config: &str) -> Result<(SectionConfigData, ConfigDigest), Error> {
    let digest = ConfigDigest::from_slice(raw_config.as_bytes());
    let data = private_config_parser()
        .parse("priv/notifications.cfg", raw_config)
        .map_err(Error::config_deserialization)?;

    Ok((data, digest))
}

pub fn write(config: &SectionConfigData) -> Result<String, Error> {
    config_parser()
        .write("notifications.cfg", config)
        .map_err(Error::config_serialization)
}

pub fn write_private(config: &SectionConfigData) -> Result<String, Error> {
    private_config_parser()
        .write("priv/notifications.cfg", config)
        .map_err(Error::config_serialization)
}

/// Notification configuration
#[derive(Debug, Clone)]
pub struct Config {
    pub(crate) config: SectionConfigData,
    pub(crate) private_config: SectionConfigData,
    digest: ConfigDigest,
}

impl Config {
    /// Parse raw config
    pub fn new(
        context: &Context,
        raw_config: &str,
        raw_private_config: &str,
    ) -> Result<Self, Error> {
        let (mut config, digest) = config(raw_config)?;
        let (private_config, _) = private_config(raw_private_config)?;

        let default_config = context.default_config();

        let builtin_config = config_parser()
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

        Ok((write(&c)?, write_private(&self.private_config)?))
    }

    /// Returns the SHA256 digest of the configuration.
    /// The digest is only computed once when the configuration deserialized.
    pub fn digest(&self) -> &ConfigDigest {
        &self.digest
    }
}
