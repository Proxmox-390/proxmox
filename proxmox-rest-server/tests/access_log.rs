use std::fs::File;
use std::io::BufReader;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::Error;
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use nix::unistd::Gid;
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};

use proxmox_access_log::{AccessLogEntry, AccessLogReader, LogFormat};
use proxmox_daemon::command_socket::CommandSocket;
use proxmox_http::Body;
use proxmox_rest_server::{ApiConfig, AuthError, RestServer};
use proxmox_router::{
    ApiHandler, ApiMethod, Permission, Router, RpcEnvironment, RpcEnvironmentType, SubdirMap,
    UserInformation,
};
use proxmox_schema::ObjectSchema;

struct TestUser;

impl UserInformation for TestUser {
    fn is_superuser(&self, _userid: &str) -> bool {
        false
    }
    fn is_group_member(&self, _userid: &str, _group: &str) -> bool {
        false
    }
    fn lookup_privs(&self, _userid: &str, _path: &[&str]) -> u64 {
        0
    }
}

fn ping(
    _param: Value,
    _info: &ApiMethod,
    _rpcenv: &mut dyn RpcEnvironment,
) -> Result<Value, Error> {
    Ok(json!("pong"))
}

const PARAMETERS: ObjectSchema =
    ObjectSchema::new("No parameters.", &[]).additional_properties(true);
const AUTHENTICATED_PING: ApiMethod =
    ApiMethod::new(&ApiHandler::Sync(&ping), &PARAMETERS).access(None, &Permission::Anybody);
const PUBLIC_PING: ApiMethod =
    ApiMethod::new(&ApiHandler::Sync(&ping), &PARAMETERS).access(None, &Permission::World);

static AUTHENTICATED_ROUTER: Router = Router::new().get(&AUTHENTICATED_PING);
static PUBLIC_ROUTER: Router = Router::new().get(&PUBLIC_PING);
const SUBDIRS: SubdirMap = &[("ping", &AUTHENTICATED_ROUTER), ("public", &PUBLIC_ROUTER)];
static ROUTER: Router = Router::new().subdirs(SUBDIRS);

/// Starts a server logging requests to `log`, authenticating them by their `test` authorization.
async fn start_server(log: &Path) -> Result<SocketAddr, Error> {
    let mut command_socket = CommandSocket::new(Gid::current());
    let config = ApiConfig::new(".", RpcEnvironmentType::PUBLIC)
        .default_api2_handler(&ROUTER)
        .auth_handler_func(|headers, _method| {
            let auth_id = headers
                .get(http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("test "))
                .map(str::to_string);
            Box::pin(async move {
                let user: Box<dyn UserInformation + Send + Sync> = Box::new(TestUser);
                Ok((auth_id.ok_or(AuthError::NoData)?, user))
            })
        })
        .enable_access_log(log, None, None, &mut command_socket)?;
    let server = RestServer::new(config);

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let service = server.api_service(&stream).unwrap();
            tokio::spawn(service.serve(stream, None));
        }
    });
    Ok(address)
}

/// Sends a request, returning the status and size of the response.
async fn send(
    address: SocketAddr,
    method: &str,
    uri: &str,
    auth_id: Option<&str>,
    user_agent: Option<&str>,
) -> Result<(u16, u64), Error> {
    let stream = TcpStream::connect(address).await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(connection);

    let mut request = http::Request::builder()
        .method(method)
        .uri(uri)
        .header(http::header::HOST, "localhost");
    if let Some(auth_id) = auth_id {
        request = request.header(http::header::AUTHORIZATION, format!("test {auth_id}"));
    }
    if let Some(user_agent) = user_agent {
        request = request.header(http::header::USER_AGENT, user_agent);
    }

    let response = sender.send_request(request.body(Body::empty())?).await?;
    let status = response.status().as_u16();
    let size = response.into_body().collect().await?.to_bytes().len();
    Ok((status, size as u64))
}

#[tokio::test]
async fn logged_requests_parse_back() -> Result<(), Error> {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("access-log");
    let _ = std::fs::remove_dir_all(&dir);
    let log = dir.join("access.log");
    let address = start_server(&log).await?;

    let long_user_agent = "x".repeat(200);
    let long_uri = format!("/api2/json/{}", "a".repeat(4000));
    let requests = [
        (
            "GET",
            "/api2/json/ping?x=1&y=%22",
            Some("root@pam!monitoring"),
            Some("client/1.0 (test)"),
        ),
        ("GET", "/api2/json/public", None, None),
        (
            "GET",
            "/api2/json/ping\"quoted\"",
            Some("root@pam"),
            Some(long_user_agent.as_str()),
        ),
        ("GET", long_uri.as_str(), Some("root@pam"), Some("-")),
        // a request target without path, logged as empty URI
        ("CONNECT", "example.com:443", None, Some("curl/8.14.1")),
    ];

    let start = proxmox_time::epoch_i64();
    let mut responses = Vec::new();
    for (method, uri, auth_id, user_agent) in requests {
        responses.push(send(address, method, uri, auth_id, user_agent).await?);
    }
    let end = proxmox_time::epoch_i64();

    let entries = AccessLogReader::new(BufReader::new(File::open(&log)?), LogFormat::RestServer)
        .collect::<Result<Vec<AccessLogEntry>, _>>()?;
    assert_eq!(entries.len(), requests.len());

    for (entry, ((method, uri, auth_id, user_agent), (status, size))) in
        entries.iter().zip(requests.iter().zip(responses))
    {
        assert!((start..=end).contains(&entry.time), "{entry:?}");
        assert_eq!(entry.client, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        // the server authenticates only requests it routes to an API method
        if status == 200 {
            assert_eq!(entry.auth_id.as_deref(), *auth_id);
        }
        assert_eq!(entry.method.as_deref(), Some(*method));
        assert_eq!(entry.status, Some(status), "{entry:?}");
        assert_eq!(entry.size, Some(size), "{entry:?}");

        let expected_uri = match *method {
            "CONNECT" => "",
            _ => &uri[..uri.len().min(3072)],
        };
        assert_eq!(entry.uri.as_deref(), Some(expected_uri));
        let expected_user_agent = user_agent
            .filter(|user_agent| *user_agent != "-")
            .map(|user_agent| &user_agent[..user_agent.len().min(128)]);
        assert_eq!(entry.user_agent.as_deref(), expected_user_agent);
    }

    let statuses: Vec<u16> = entries.iter().map(|entry| entry.status.unwrap()).collect();
    assert_eq!(statuses, [200, 200, 404, 414, 400]);

    Ok(())
}
