use std::sync::OnceLock;

use proxmox_section_config::typed::SectionConfigData;

use crate::Context;
use crate::config::ConfigEntity;
use crate::context::ContextImpl;
use crate::error::BoxedError;

use super::TemplateSource;

#[derive(Debug)]
pub(crate) struct TestContext;

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

    fn http_proxy_config(&self) -> Option<String> {
        None
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
}

pub(crate) fn test_context() -> Context {
    Context::new(TestContext)
}
