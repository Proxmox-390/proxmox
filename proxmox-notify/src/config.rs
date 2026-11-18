use proxmox_config_digest::ConfigDigest;
use proxmox_schema::api;
use proxmox_schema::api_types::SAFE_ID_FORMAT;
use proxmox_section_config::typed::{ApiSectionDataEntry, SectionConfigData};
use serde::{Deserialize, Serialize};

use crate::Error;
use crate::api_types::{
    GotifyConfig, GotifyPrivateConfig, MatcherConfig, Origin, SendmailConfig, SmtpConfig,
    SmtpPrivateConfig, WebhookConfig, WebhookPrivateConfig,
};

fn parse_config(
    raw_config: &str,
) -> Result<(SectionConfigData<ConfigEntity>, ConfigDigest), Error> {
    let digest = ConfigDigest::from_slice(raw_config.as_bytes());
    let data = ConfigEntity::parse_section_config("notifications.cfg", raw_config)
        .map_err(Error::config_deserialization)?;

    Ok((data, digest))
}

fn parse_private_config(
    raw_config: &str,
) -> Result<(SectionConfigData<PrivateConfigEntity>, ConfigDigest), Error> {
    let digest = ConfigDigest::from_slice(raw_config.as_bytes());
    let data = PrivateConfigEntity::parse_section_config("priv/notifications.cfg", raw_config)
        .map_err(Error::config_deserialization)?;

    Ok((data, digest))
}

/// Notification configuration
#[derive(Clone)]
pub struct Config {
    pub(crate) config: SectionConfigData<ConfigEntity>,
    pub(crate) private_config: SectionConfigData<PrivateConfigEntity>,
    digest: ConfigDigest,
}

impl Config {
    /// Parse notification configuration from section config format.
    pub fn parse_section_config(
        raw_config: &str,
        raw_private_config: &str,
        builtin_config: Option<&SectionConfigData<ConfigEntity>>,
    ) -> Result<Self, Error> {
        let (mut config, digest) = parse_config(raw_config)?;
        let (private_config, _) = parse_private_config(raw_private_config)?;

        if let Some(builtin_config) = builtin_config {
            for (key, builtin_value) in builtin_config {
                if let Some(value) = config.get_mut(key) {
                    if value == builtin_value {
                        // Entry is built-in and the config entry section in notifications.cfg
                        // is exactly the same.
                        value.set_origin(Some(Origin::Builtin));
                    } else {
                        // Entry is built-in, but it has been modified by the user.
                        value.set_origin(Some(Origin::ModifiedBuiltin));
                    }
                } else {
                    // If it doesn't exist, we insert the builtin
                    let mut value = builtin_value.clone();
                    value.set_origin(Some(Origin::Builtin));
                    config.insert(key.to_string(), value);
                }
            }
        }

        let keys: Vec<String> = config.keys().cloned().collect();

        for key in keys {
            if let Some(value) = config.get_mut(&key)
                && value.origin().is_none()
            {
                value.set_origin(Some(Origin::UserCreated));
            }
        }

        Ok(Self {
            config,
            digest,
            private_config,
        })
    }

    /// Serialize config
    pub fn to_section_config(&self) -> Result<(String, String), Error> {
        let mut configs_without_origin = SectionConfigData::default();

        for (name, section) in &self.config {
            match section {
                ConfigEntity::Sendmail(config) => {
                    let mut config = config.clone();
                    config.origin = None;
                    configs_without_origin.insert(name, ConfigEntity::Sendmail(config));
                }
                ConfigEntity::Smtp(config) => {
                    let mut config = config.clone();
                    config.origin = None;
                    configs_without_origin.insert(name, ConfigEntity::Smtp(config));
                }
                ConfigEntity::Gotify(config) => {
                    let mut config = config.clone();
                    config.origin = None;
                    configs_without_origin.insert(name, ConfigEntity::Gotify(config));
                }
                ConfigEntity::Webhook(config) => {
                    let mut config = config.clone();
                    config.origin = None;
                    configs_without_origin.insert(name, ConfigEntity::Webhook(config));
                }
                ConfigEntity::Matcher(config) => {
                    let mut config = config.clone();
                    config.origin = None;
                    configs_without_origin.insert(name, ConfigEntity::Matcher(config));
                }
            }
        }

        let config_str =
            ConfigEntity::write_section_config("notifications.cfg", &configs_without_origin)
                .map_err(Error::config_serialization)?;
        let private_config_str = PrivateConfigEntity::write_section_config(
            "priv/notifications.cfg",
            &self.private_config,
        )
        .map_err(Error::config_serialization)?;

        Ok((config_str, private_config_str))
    }

    /// Returns the SHA256 digest of the configuration.
    /// The digest is only computed once when the configuration deserialized.
    pub fn digest(&self) -> &ConfigDigest {
        &self.digest
    }
}

#[api(
    "id-property": "name",
    "id-schema": {
        type: String,
        description: "Notification config entity name.",
        min_length: 3,
        max_length: 32,
        format: &SAFE_ID_FORMAT,
    },
)]
/// Config entity in the notification config file.
#[derive(Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "kebab-case", tag = "type")]
pub enum ConfigEntity {
    /// Sendmail endpoint.
    Sendmail(SendmailConfig),
    /// Gotify endpoint.
    Gotify(GotifyConfig),
    /// SMTP endpoint.
    Smtp(SmtpConfig),
    /// Webhook endpoint.
    Webhook(WebhookConfig),
    /// Matcher configuration.
    Matcher(MatcherConfig),
}

impl ConfigEntity {
    pub(crate) fn set_origin(&mut self, origin: Option<Origin>) {
        match self {
            ConfigEntity::Sendmail(config) => config.origin = origin,
            ConfigEntity::Gotify(config) => config.origin = origin,
            ConfigEntity::Smtp(config) => config.origin = origin,
            ConfigEntity::Webhook(config) => config.origin = origin,
            ConfigEntity::Matcher(config) => config.origin = origin,
        }
    }

    pub(crate) fn origin(&self) -> Option<Origin> {
        match self {
            ConfigEntity::Sendmail(config) => config.origin,
            ConfigEntity::Gotify(config) => config.origin,
            ConfigEntity::Smtp(config) => config.origin,
            ConfigEntity::Webhook(config) => config.origin,
            ConfigEntity::Matcher(config) => config.origin,
        }
    }
}

#[api(
    "id-property": "name",
    "id-schema": {
        type: String,
        description: "Notification config entity name.",
        min_length: 3,
        max_length: 32,
        format: &SAFE_ID_FORMAT,
    },
)]
/// Config entity in the private notification config file.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", tag = "type")]
pub enum PrivateConfigEntity {
    /// Private config for a gotify endpoint.
    Gotify(GotifyPrivateConfig),
    /// Private config for an SMTP endpoint.
    Smtp(SmtpPrivateConfig),
    /// Private config for a webhook endpoint.
    Webhook(WebhookPrivateConfig),
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG_REF: &str = include_str!("../testdata/notifications.cfg.ref");
    const PRIV_CONFIG_REF: &str = include_str!("../testdata/notifications-priv.cfg.ref");

    use pretty_assertions::assert_eq;

    #[test]
    fn section_config_roundtrip() {
        let config = Config::parse_section_config(CONFIG_REF, PRIV_CONFIG_REF, None).unwrap();

        assert_eq!(
            config.digest().to_string(),
            "53554a97ca1747b69582f7cde5d4493f68b77c0d5946ce593a59547c9638d504"
        );

        let (public_config, private_config) = config.to_section_config().unwrap();

        assert_eq!(public_config, CONFIG_REF);
        assert_eq!(private_config, PRIV_CONFIG_REF);
    }

    const BUILTIN_CONFIG: &str = "\
sendmail: mail-to-root
	mailto-user root@pam

matcher: default-matcher
	target mail-to-root
";

    fn origins(config: &Config) -> Vec<(String, Option<Origin>)> {
        let mut origins: Vec<_> = config
            .config
            .iter()
            .map(|(name, entity)| (name.to_string(), entity.origin()))
            .collect();
        origins.sort_by(|a, b| a.0.cmp(&b.0));
        origins
    }

    #[test]
    fn builtin_origin() {
        let builtin = ConfigEntity::parse_section_config("builtin", BUILTIN_CONFIG).unwrap();

        let modified_and_user_created = "\
sendmail: mail-to-root
	mailto-user root@pam

matcher: default-matcher
	comment changed by the user
	target mail-to-root

sendmail: user-target
	mailto user@example.com
";

        let config =
            Config::parse_section_config(modified_and_user_created, "", Some(&builtin)).unwrap();
        assert_eq!(
            origins(&config),
            [
                ("default-matcher".into(), Some(Origin::ModifiedBuiltin)),
                ("mail-to-root".into(), Some(Origin::Builtin)),
                ("user-target".into(), Some(Origin::UserCreated)),
            ]
        );

        // Built-in entries are added if missing, and stay built-in when written back unchanged.
        let config = Config::parse_section_config("", "", Some(&builtin)).unwrap();
        let expected = [
            ("default-matcher".into(), Some(Origin::Builtin)),
            ("mail-to-root".into(), Some(Origin::Builtin)),
        ];
        assert_eq!(origins(&config), expected);

        let (written, _) = config.to_section_config().unwrap();
        assert!(!written.contains("origin"));

        let config = Config::parse_section_config(&written, "", Some(&builtin)).unwrap();
        assert_eq!(origins(&config), expected);
    }
}
