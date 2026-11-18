use std::sync::OnceLock;

use proxmox_http::ProxyConfig;
use proxmox_section_config::typed::SectionConfigData;

use crate::Config;
use crate::Context;
use crate::config::ConfigEntity;
use crate::context::ContextImpl;
use crate::error::BoxedError;

use super::TemplateSource;

#[derive(Debug, Default)]
pub(crate) struct TestContext {
    /// Make [`ContextImpl::read_config`] fail, to test how callers handle an unreadable config.
    pub(crate) fail_read_config: bool,
}

impl ContextImpl for TestContext {
    fn lookup_email_for_user(&self, user: &str) -> Option<String> {
        user.split_once('@').and_then(|(user, realm)| {
            if realm == "pve" {
                Some(format!("{user}@example.com"))
            } else {
                None
            }
        })
    }

    fn default_sendmail_author(&self) -> String {
        "Proxmox VE".into()
    }

    fn default_sendmail_from(&self) -> String {
        "root".into()
    }

    fn proxy_config(&self) -> Result<Option<ProxyConfig>, BoxedError> {
        Ok(None)
    }

    fn default_config(&self) -> &'static SectionConfigData<ConfigEntity> {
        static CONFIG: OnceLock<SectionConfigData<ConfigEntity>> = OnceLock::new();
        CONFIG.get_or_init(SectionConfigData::default)
    }

    fn lookup_template(
        &self,
        _filename: &str,
        _namespace: Option<&str>,
        _source: TemplateSource,
    ) -> Result<Option<String>, BoxedError> {
        Ok(Some(String::new()))
    }

    fn read_config(&self) -> Result<Config, BoxedError> {
        if self.fail_read_config {
            return Err(Box::new(crate::Error::other(
                "injected config read failure",
            )));
        }

        // An empty config has no targets and no matchers.
        Ok(Config::parse_section_config("", "", None)?)
    }
}

pub(crate) fn test_context() -> Context {
    Context::new(TestContext::default())
}
