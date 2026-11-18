use std::sync::OnceLock;

use proxmox_config_digest::ConfigDigest;
use proxmox_schema::{ApiType, ObjectSchema};
use proxmox_section_config::{SectionConfig, SectionConfigData, SectionConfigPlugin};

use crate::Error;
use crate::api_types::{
    GOTIFY_TYPENAME, GotifyConfig, GotifyPrivateConfig, MATCHER_TYPENAME, MatcherConfig,
    SENDMAIL_TYPENAME, SMTP_TYPENAME, SendmailConfig, SmtpConfig, SmtpPrivateConfig,
    WEBHOOK_TYPENAME, WebhookConfig, WebhookPrivateConfig,
};
use crate::schema::BACKEND_NAME_SCHEMA;

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
