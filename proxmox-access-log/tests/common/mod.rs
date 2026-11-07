use std::sync::Mutex;

use anyhow::Error;
use serde_json::{Value, json};

use proxmox_router::{ApiHandler, ApiMethod, HttpError, RpcEnvironment, RpcEnvironmentType};

struct Env {
    auth_id: Option<String>,
    result: Value,
}

impl RpcEnvironment for Env {
    fn result_attrib_mut(&mut self) -> &mut Value {
        &mut self.result
    }

    fn result_attrib(&self) -> &Value {
        &self.result
    }

    fn env_type(&self) -> RpcEnvironmentType {
        RpcEnvironmentType::PUBLIC
    }

    fn set_auth_id(&mut self, auth_id: Option<String>) {
        self.auth_id = auth_id;
    }

    fn get_auth_id(&self) -> Option<String> {
        self.auth_id.clone()
    }
}

/// The methods refuse more than a few scans at once, while tests run in parallel.
static CALLS: Mutex<()> = Mutex::new(());

/// Calls an API method as the REST server would after verifying the parameters.
pub fn call(method: &'static ApiMethod, mut params: Value, auth_id: &str) -> Result<Value, Error> {
    let _serialized = CALLS.lock().unwrap_or_else(|err| err.into_inner());
    params["node"] = "localhost".into();
    let ApiHandler::Async(handler) = method.handler else {
        panic!("not an async API method");
    };
    let mut env = Env {
        auth_id: Some(auth_id.to_string()),
        result: json!({}),
    };
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(handler(params, method, &mut env))
}

pub fn status(result: Result<Value, Error>) -> u16 {
    result
        .unwrap_err()
        .downcast_ref::<HttpError>()
        .unwrap()
        .code
        .as_u16()
}

pub fn entries(page: &Value) -> usize {
    page["entries"].as_array().unwrap().len()
}
