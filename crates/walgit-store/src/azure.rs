//! Azure Blob Storage backend (Azurite for local dev / CI).
//!
//! Talks to the Blob REST API with `reqwest`. `bucket` is the container. Two credentials:
//! the account's shared key (`auth = "shared_key"`, connection string from
//! `store.azure.connection_string_env`) signs each request; Workload Identity
//! (`auth = "workload_identity"`) exchanges the pod's federated token for a Microsoft
//! Entra access token, sent as `Authorization: Bearer`.
//!
//! ## Version tokens
//!
//! Blob `ETag`s, quotes stripped, are the opaque `Version`. Conditional headers send
//! them quoted again.
//!
//! ## Conditional writes
//!
//! `PutMode::Create`    → `If-None-Match: *`  (409 `BlobAlreadyExists` or 412 when present).
//! `PutMode::Update(v)` → `If-Match: "<etag>"` (412 `ConditionNotMet` on mismatch).
//! Objects above `multipart_threshold` go up as blocks (`Put Block`), committed by one
//! `Put Block List` that carries the same condition: unlike S3, a large conditional
//! create is atomic. Uncommitted blocks expire on their own.
//!
//! ## Conditional delete
//!
//! Native: `DELETE` with `If-Match` (412 on mismatch). No HEAD + DELETE race.
//!
//! ## Listing
//!
//! `List Blobs` pages by an opaque marker and has no `start-after`: keys up to
//! `start_after` are skipped client side (listings are off the hot path, principle VII).
//!
//! ## Timeouts
//!
//! Every request has a connect timeout and a read timeout, so a store that stops
//! answering fails requests (retryable) instead of holding them.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use futures::StreamExt;
use hmac::{Hmac, Mac};
use reqwest::{Method, StatusCode};
use sha2::Sha256;

use walgit_config::{AzureAuth, AzureConfig};

use crate::{
    BoxStream, GetOptions, GetResult, ObjectMeta, ObjectStore, PutBody, PutMode, PutOptions,
    Result, StoreError, Version, util,
};

const API_VERSION: &str = "2021-08-06";
const LIST_PAGE: u32 = 5000;
const ATTEMPTS: u32 = 4;
const TOKEN_SCOPE: &str = "https://storage.azure.com/.default";
/// A cached access token is replaced this long before it expires.
const TOKEN_REFRESH_MARGIN: Duration = Duration::from_mins(5);

/// Account name, credential and blob endpoint.
#[derive(Clone)]
struct Account {
    name: String,
    credential: Credential,
    /// Base URL of the blob service, without a trailing slash: the account's own host
    /// on Azure, `http://127.0.0.1:10000/devstoreaccount1` on Azurite.
    endpoint: String,
    /// The path the endpoint adds before `/<container>` (Azurite: `/devstoreaccount1`),
    /// which shared key signing includes in the canonical resource.
    endpoint_path: String,
}

#[derive(Clone)]
enum Credential {
    /// The decoded account key.
    SharedKey(Vec<u8>),
    Entra(Arc<WorkloadIdentity>),
}

/// Azurite's well known development account; the key is the public one Microsoft
/// documents for the emulator.
const DEV_ACCOUNT: &str = "devstoreaccount1";
const DEV_KEY: &str =
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";

impl Account {
    fn parse(connection_string: &str) -> anyhow::Result<Self> {
        let mut fields = std::collections::HashMap::new();
        for part in connection_string
            .split(';')
            .filter(|p| !p.trim().is_empty())
        {
            let (k, v) = part
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("azure: malformed connection string field"))?;
            fields.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
        let dev = fields
            .get("usedevelopmentstorage")
            .is_some_and(|v| v.eq_ignore_ascii_case("true"));
        let name = match fields.get("accountname") {
            Some(n) => n.clone(),
            None if dev => DEV_ACCOUNT.to_owned(),
            None => anyhow::bail!("azure: connection string has no AccountName"),
        };
        let key_b64 = match fields.get("accountkey") {
            Some(k) => k.clone(),
            None if dev => DEV_KEY.to_owned(),
            None => anyhow::bail!("azure: connection string has no AccountKey"),
        };
        let key = BASE64
            .decode(key_b64.as_bytes())
            .map_err(|e| anyhow::anyhow!("azure: AccountKey is not base64: {e}"))?;
        let endpoint = if let Some(e) = fields.get("blobendpoint") {
            e.trim_end_matches('/').to_owned()
        } else if dev {
            format!("http://127.0.0.1:10000/{DEV_ACCOUNT}")
        } else {
            let protocol = fields
                .get("defaultendpointsprotocol")
                .map_or("https", String::as_str);
            let suffix = fields
                .get("endpointsuffix")
                .map_or("core.windows.net", String::as_str);
            format!("{protocol}://{name}.blob.{suffix}")
        };
        let endpoint_path = endpoint_path(&endpoint)?;
        Ok(Account {
            name,
            credential: Credential::SharedKey(key),
            endpoint,
            endpoint_path,
        })
    }

    /// The account named in the config, reached with Workload Identity tokens.
    fn entra(cfg: &AzureConfig, identity: WorkloadIdentity) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !cfg.account.is_empty(),
            "azure: store.azure.account must be set with auth = workload_identity"
        );
        let endpoint = if cfg.endpoint.is_empty() {
            format!("https://{}.blob.core.windows.net", cfg.account)
        } else {
            cfg.endpoint.trim_end_matches('/').to_owned()
        };
        let endpoint_path = endpoint_path(&endpoint)?;
        Ok(Account {
            name: cfg.account.clone(),
            credential: Credential::Entra(Arc::new(identity)),
            endpoint,
            endpoint_path,
        })
    }
}

fn endpoint_path(endpoint: &str) -> anyhow::Result<String> {
    let url = reqwest::Url::parse(endpoint)
        .map_err(|e| anyhow::anyhow!("azure: bad blob endpoint {endpoint}: {e}"))?;
    Ok(url.path().trim_end_matches('/').to_owned())
}

/// Microsoft Entra access tokens for a federated identity (AKS Workload Identity): the
/// projected service account token is exchanged for a storage token, cached until
/// shortly before it expires.
struct WorkloadIdentity {
    token_url: String,
    client_id: String,
    /// Re-read on every exchange: the kubelet rotates it.
    token_file: PathBuf,
    cached: tokio::sync::Mutex<Option<CachedToken>>,
}

struct CachedToken {
    value: String,
    refresh_at: Instant,
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

impl WorkloadIdentity {
    /// From the variables the AKS Workload Identity webhook injects into the pod.
    fn from_env() -> anyhow::Result<Self> {
        let var = |name: &str| {
            std::env::var(name)
                .map_err(|_| anyhow::anyhow!("azure workload identity: env var {name} not set"))
        };
        let authority = std::env::var("AZURE_AUTHORITY_HOST")
            .unwrap_or_else(|_| "https://login.microsoftonline.com/".to_owned());
        Ok(Self::new(
            &authority,
            &var("AZURE_TENANT_ID")?,
            var("AZURE_CLIENT_ID")?,
            PathBuf::from(var("AZURE_FEDERATED_TOKEN_FILE")?),
        ))
    }

    fn new(authority: &str, tenant: &str, client_id: String, token_file: PathBuf) -> Self {
        WorkloadIdentity {
            token_url: format!(
                "{}/{tenant}/oauth2/v2.0/token",
                authority.trim_end_matches('/')
            ),
            client_id,
            token_file,
            cached: tokio::sync::Mutex::new(None),
        }
    }

    /// A valid access token. One caller at a time refreshes; the others wait for it.
    async fn token(&self, http: &reqwest::Client) -> Result<String> {
        let mut cached = self.cached.lock().await;
        if let Some(t) = cached.as_ref()
            && Instant::now() < t.refresh_at
        {
            return Ok(t.value.clone());
        }
        let assertion = tokio::fs::read_to_string(&self.token_file)
            .await
            .map_err(|e| {
                StoreError::other(anyhow::anyhow!(
                    "azure: read federated token {}: {e}",
                    self.token_file.display()
                ))
            })?;
        let resp = http
            .post(&self.token_url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.client_id.as_str()),
                ("scope", TOKEN_SCOPE),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", assertion.trim()),
            ])
            .send()
            .await
            .map_err(|e| StoreError::retryable(anyhow::anyhow!("azure token http: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            let detail: String = body.chars().take(300).collect();
            let err = anyhow::anyhow!("azure token: status {status} {detail}");
            return Err(if is_transient_status(status) {
                StoreError::Retryable(err)
            } else {
                StoreError::Other(err)
            });
        }
        let token: TokenResponse = resp
            .json()
            .await
            .map_err(|e| StoreError::retryable(anyhow::anyhow!("azure token body: {e}")))?;
        let lifetime = Duration::from_secs(token.expires_in);
        *cached = Some(CachedToken {
            value: token.access_token.clone(),
            refresh_at: Instant::now() + lifetime.saturating_sub(TOKEN_REFRESH_MARGIN),
        });
        Ok(token.access_token)
    }
}

/// A request about to be signed and sent.
struct Request<'a> {
    method: Method,
    /// Object key, or `None` for a container level request.
    key: Option<&'a str>,
    /// Query parameters, unencoded.
    query: Vec<(&'static str, String)>,
    /// Headers that take part in signing by position.
    if_match: Option<String>,
    if_none_match: Option<String>,
    content_type: Option<&'static str>,
    content_length: u64,
    /// `x-ms-*` headers besides date and version.
    ms_headers: Vec<(&'static str, String)>,
}

impl<'a> Request<'a> {
    fn new(method: Method, key: Option<&'a str>) -> Self {
        Request {
            method,
            key,
            query: Vec::new(),
            if_match: None,
            if_none_match: None,
            content_type: None,
            content_length: 0,
            ms_headers: Vec::new(),
        }
    }
}

/// Azure Blob Storage object store.
pub struct AzureStore {
    http: reqwest::Client,
    account: Account,
    container: String,
    multipart_threshold: u64,
    multipart_part_size: u64,
}

impl AzureStore {
    /// Build a store from `walgit-config::StoreConfig`: the connection string comes from
    /// the env var named in `cfg.azure.connection_string_env`, Workload Identity from the
    /// pod's environment.
    pub fn new(cfg: &walgit_config::StoreConfig) -> anyhow::Result<Self> {
        let account = match cfg.azure.auth {
            AzureAuth::SharedKey => {
                let env = &cfg.azure.connection_string_env;
                let connection_string = std::env::var(env).map_err(|_| {
                    anyhow::anyhow!("azure: env var {env} not set (connection string)")
                })?;
                Account::parse(&connection_string)?
            }
            AzureAuth::WorkloadIdentity => {
                Account::entra(&cfg.azure, WorkloadIdentity::from_env()?)?
            }
        };
        Self::with_account(cfg, account)
    }

    fn with_account(cfg: &walgit_config::StoreConfig, account: Account) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(30))
            .build()?;
        Ok(AzureStore {
            http,
            account,
            container: cfg.bucket.clone(),
            multipart_threshold: cfg.multipart_threshold.as_u64(),
            multipart_part_size: cfg.multipart_part_size.as_u64().max(1024 * 1024),
        })
    }

    fn path(&self, key: Option<&str>) -> String {
        match key {
            Some(k) => format!("/{}/{}", self.container, util::encode_path(k)),
            None => format!("/{}", self.container),
        }
    }

    /// The `Authorization: SharedKey` value for a request (Blob service, version 2015+).
    fn sign(&self, req: &Request<'_>, date: &str, key: &[u8]) -> Result<String> {
        let length = if req.content_length == 0 {
            String::new()
        } else {
            req.content_length.to_string()
        };
        let mut ms: Vec<(String, String)> = req
            .ms_headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .chain([
                ("x-ms-date".to_owned(), date.to_owned()),
                ("x-ms-version".to_owned(), API_VERSION.to_owned()),
            ])
            .collect();
        ms.sort();
        let mut headers = String::new();
        for (k, v) in &ms {
            let _ = writeln!(headers, "{k}:{v}");
        }
        let mut resource = format!(
            "/{}{}{}",
            self.account.name,
            self.account.endpoint_path,
            self.path(req.key)
        );
        let mut query: Vec<&(&str, String)> = req.query.iter().collect();
        query.sort_by_key(|(k, _)| *k);
        for (k, v) in query {
            let _ = write!(resource, "\n{k}:{v}");
        }
        let string_to_sign = format!(
            "{}\n\n\n{}\n\n{}\n\n\n{}\n{}\n\n\n{}{}",
            req.method,
            length,
            req.content_type.unwrap_or(""),
            req.if_match.as_deref().unwrap_or(""),
            req.if_none_match.as_deref().unwrap_or(""),
            headers,
            resource
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .map_err(|e| StoreError::other(anyhow::anyhow!("azure hmac key: {e}")))?;
        mac.update(string_to_sign.as_bytes());
        let signature = BASE64.encode(mac.finalize().into_bytes());
        Ok(format!("SharedKey {}:{signature}", self.account.name))
    }

    /// Sign and send one request; `body` is consumed by this attempt.
    async fn send(
        &self,
        req: &Request<'_>,
        body: Option<reqwest::Body>,
    ) -> Result<reqwest::Response> {
        let date = chrono::Utc::now()
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        let authorization = match &self.account.credential {
            Credential::SharedKey(key) => self.sign(req, &date, key)?,
            Credential::Entra(identity) => format!("Bearer {}", identity.token(&self.http).await?),
        };
        let mut url =
            reqwest::Url::parse(&format!("{}{}", self.account.endpoint, self.path(req.key)))
                .map_err(|e| StoreError::other(anyhow::anyhow!("azure url: {e}")))?;
        if !req.query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (k, v) in &req.query {
                pairs.append_pair(k, v);
            }
        }
        let mut builder = self
            .http
            .request(req.method.clone(), url)
            .header("x-ms-date", &date)
            .header("x-ms-version", API_VERSION)
            .header("authorization", authorization);
        for (k, v) in &req.ms_headers {
            builder = builder.header(*k, v);
        }
        if let Some(v) = &req.if_match {
            builder = builder.header("if-match", v);
        }
        if let Some(v) = &req.if_none_match {
            builder = builder.header("if-none-match", v);
        }
        if let Some(ct) = req.content_type {
            builder = builder.header("content-type", ct);
        }
        if let Some(b) = body {
            builder = builder.body(b);
        }
        builder
            .send()
            .await
            .map_err(|e| StoreError::retryable(anyhow::anyhow!("azure {} http: {e}", req.method)))
    }

    /// Send a request whose body can be rebuilt, retrying throttling, server faults and
    /// connection failures with backoff.
    async fn send_retrying(
        &self,
        req: &Request<'_>,
        body: impl Fn() -> Option<reqwest::Body>,
    ) -> Result<reqwest::Response> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let result = self.send(req, body()).await;
            let retry = match &result {
                Err(e) => e.is_retryable(),
                Ok(resp) => is_transient_status(resp.status()),
            };
            if !retry || attempt >= ATTEMPTS {
                return result;
            }
            tokio::time::sleep(Duration::from_millis(100 * 2u64.pow(attempt))).await;
        }
    }

    /// One conditional `Put Blob` from memory.
    async fn put_blob(&self, key: &str, data: Bytes, opts: &PutOptions) -> Result<ObjectMeta> {
        let len = data.len() as u64;
        let mut req = Request::new(Method::PUT, Some(key));
        req.content_length = len;
        req.content_type = opts.content_type;
        req.ms_headers
            .push(("x-ms-blob-type", "BlockBlob".to_owned()));
        if opts.immutable {
            req.ms_headers.push((
                "x-ms-blob-cache-control",
                "public, max-age=31536000, immutable".to_owned(),
            ));
        }
        apply_mode(&mut req, &opts.mode);
        let resp = self
            .send_retrying(&req, || Some(reqwest::Body::from(data.clone())))
            .await?;
        self.written(key, len, resp).await
    }

    /// A large object as blocks, committed by one conditional `Put Block List`.
    async fn put_blocks(&self, key: &str, body: PutBody, opts: &PutOptions) -> Result<ObjectMeta> {
        use tokio::io::AsyncReadExt;
        let (mut reader, len): (Box<dyn tokio::io::AsyncRead + Unpin + Send>, u64) = match body {
            PutBody::Bytes(b) => {
                let len = b.len() as u64;
                (Box::new(std::io::Cursor::new(b)), len)
            }
            PutBody::Stream { len, stream } => (
                Box::new(tokio_util::io::StreamReader::new(
                    stream.map(|r| r.map_err(std::io::Error::other)),
                )),
                len,
            ),
            PutBody::File(path) => {
                let file = tokio::fs::File::open(&path).await.map_err(|e| {
                    StoreError::other(anyhow::anyhow!("open {}: {e}", path.display()))
                })?;
                let len = file
                    .metadata()
                    .await
                    .map_err(|e| {
                        StoreError::other(anyhow::anyhow!("stat {}: {e}", path.display()))
                    })?
                    .len();
                (Box::new(file), len)
            }
        };
        let part = usize::try_from(self.multipart_part_size).map_err(StoreError::other)?;
        let prefix = uuid::Uuid::new_v4().simple().to_string();
        let mut ids = Vec::new();
        let mut sent = 0u64;
        loop {
            let mut buf = Vec::with_capacity(part);
            (&mut reader)
                .take(part as u64)
                .read_to_end(&mut buf)
                .await
                .map_err(|e| StoreError::other(anyhow::anyhow!("azure block read: {e}")))?;
            if buf.is_empty() {
                break;
            }
            sent += buf.len() as u64;
            // Block ids: base64, all the same length within one blob.
            let id = BASE64.encode(format!("{prefix}-{:08}", ids.len()));
            let data = Bytes::from(buf);
            let mut req = Request::new(Method::PUT, Some(key));
            req.query = vec![("comp", "block".to_owned()), ("blockid", id.clone())];
            req.content_length = data.len() as u64;
            let resp = self
                .send_retrying(&req, || Some(reqwest::Body::from(data.clone())))
                .await?;
            if !resp.status().is_success() {
                return Err(error_from(key, resp).await);
            }
            ids.push(id);
        }
        if sent != len {
            return Err(StoreError::other(anyhow::anyhow!(
                "azure put {key}: body was {sent} bytes, declared {len}"
            )));
        }
        let mut list = String::new();
        for id in &ids {
            let _ = write!(list, "<Latest>{id}</Latest>");
        }
        let xml = Bytes::from(format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList>{list}</BlockList>"
        ));
        let mut req = Request::new(Method::PUT, Some(key));
        req.query = vec![("comp", "blocklist".to_owned())];
        req.content_length = xml.len() as u64;
        req.content_type = Some("application/xml");
        if let Some(ct) = opts.content_type {
            req.ms_headers
                .push(("x-ms-blob-content-type", ct.to_owned()));
        }
        if opts.immutable {
            req.ms_headers.push((
                "x-ms-blob-cache-control",
                "public, max-age=31536000, immutable".to_owned(),
            ));
        }
        apply_mode(&mut req, &opts.mode);
        let resp = self
            .send_retrying(&req, || Some(reqwest::Body::from(xml.clone())))
            .await?;
        self.written(key, len, resp).await
    }

    /// The meta of a successful write, or the write's error.
    async fn written(&self, key: &str, len: u64, resp: reqwest::Response) -> Result<ObjectMeta> {
        if resp.status().is_success() {
            return Ok(ObjectMeta {
                key: key.into(),
                size: len,
                version: Version::new(etag(&resp).unwrap_or_default()),
            });
        }
        let mut err = error_from(key, resp).await;
        if let StoreError::PreconditionFailed { current, .. } = &mut err
            && current.is_none()
        {
            *current = self.head(key).await.ok().flatten().map(|m| m.version);
        }
        Err(err)
    }

    /// One page of `List Blobs`.
    async fn list_page(
        &self,
        prefix: &str,
        marker: Option<&str>,
        delimiter: bool,
    ) -> Result<ListPage> {
        let mut req = Request::new(Method::GET, None);
        req.query = vec![
            ("restype", "container".to_owned()),
            ("comp", "list".to_owned()),
            ("maxresults", LIST_PAGE.to_string()),
        ];
        if !prefix.is_empty() {
            req.query.push(("prefix", prefix.to_owned()));
        }
        if let Some(m) = marker {
            req.query.push(("marker", m.to_owned()));
        }
        if delimiter {
            req.query.push(("delimiter", "/".to_owned()));
        }
        let resp = self.send_retrying(&req, || None).await?;
        if !resp.status().is_success() {
            return Err(error_from(prefix, resp).await);
        }
        let text = resp
            .text()
            .await
            .map_err(|e| StoreError::retryable(anyhow::anyhow!("azure list body: {e}")))?;
        parse_list(&text)
    }
}

fn apply_mode(req: &mut Request<'_>, mode: &PutMode) {
    match mode {
        PutMode::Overwrite => {}
        PutMode::Create => req.if_none_match = Some("*".to_owned()),
        PutMode::Update(v) => req.if_match = Some(format!("\"{}\"", v.as_str())),
    }
}

fn etag(resp: &reqwest::Response) -> Option<String> {
    resp.headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_matches('"').to_owned())
}

fn header_u64(resp: &reqwest::Response, name: &str) -> Option<u64> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse().ok())
}

fn is_transient_status(status: StatusCode) -> bool {
    matches!(status.as_u16(), 429 | 500 | 502 | 503 | 504)
}

/// The store error for a failed response: not found, a failed condition, a transient
/// failure worth retrying, or a permanent one.
async fn error_from(key: &str, resp: reqwest::Response) -> StoreError {
    let status = resp.status();
    let code = resp
        .headers()
        .get("x-ms-error-code")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let current = etag(&resp).map(Version::new);
    match (status.as_u16(), code.as_str()) {
        (404, _) => StoreError::NotFound { key: key.into() },
        (412, _) | (409, "BlobAlreadyExists") => StoreError::PreconditionFailed {
            key: key.into(),
            current,
        },
        _ if is_transient_status(status) => {
            StoreError::Retryable(anyhow::anyhow!("azure {key}: status {status} {code}"))
        }
        _ => {
            let body = resp.text().await.unwrap_or_default();
            let detail: String = body.chars().take(300).collect();
            StoreError::Other(anyhow::anyhow!(
                "azure {key}: status {status} {code} {detail}"
            ))
        }
    }
}

#[async_trait::async_trait]
impl ObjectStore for AzureStore {
    fn backend(&self) -> &'static str {
        "azure"
    }

    async fn get(&self, key: &str, opts: GetOptions) -> Result<GetResult> {
        let mut req = Request::new(Method::GET, Some(key));
        req.if_none_match = opts
            .if_none_match
            .as_ref()
            .map(|v| format!("\"{}\"", v.as_str()));
        req.if_match = opts
            .if_match
            .as_ref()
            .map(|v| format!("\"{}\"", v.as_str()));
        if let Some(r) = &opts.range {
            if r.end <= r.start {
                return Err(StoreError::InvalidArgument(format!(
                    "empty range {}..{} on {key}",
                    r.start, r.end
                )));
            }
            req.ms_headers
                .push(("x-ms-range", format!("bytes={}-{}", r.start, r.end - 1)));
        }
        let resp = self.send_retrying(&req, || None).await?;
        match resp.status().as_u16() {
            200 | 206 => {
                // `ObjectMeta::size` is the whole object, also for a range read.
                let total = resp
                    .headers()
                    .get("content-range")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.rsplit_once('/'))
                    .and_then(|(_, t)| t.trim().parse::<u64>().ok());
                let meta = ObjectMeta {
                    key: key.into(),
                    size: total
                        .or_else(|| header_u64(&resp, "content-length"))
                        .unwrap_or(0),
                    version: Version::new(etag(&resp).unwrap_or_default()),
                };
                let body = resp
                    .bytes_stream()
                    .map(|r| {
                        r.map_err(|e| StoreError::retryable(anyhow::anyhow!("azure body: {e}")))
                    })
                    .boxed();
                Ok(GetResult::Object { meta, body })
            }
            304 => Ok(GetResult::NotModified {
                version: Version::new(etag(&resp).unwrap_or_default()),
            }),
            _ => Err(error_from(key, resp).await),
        }
    }

    async fn head(&self, key: &str) -> Result<Option<ObjectMeta>> {
        let req = Request::new(Method::HEAD, Some(key));
        let resp = self.send_retrying(&req, || None).await?;
        match resp.status().as_u16() {
            200 => Ok(Some(ObjectMeta {
                key: key.into(),
                size: header_u64(&resp, "content-length").unwrap_or(0),
                version: Version::new(etag(&resp).unwrap_or_default()),
            })),
            404 => Ok(None),
            _ => Err(error_from(key, resp).await),
        }
    }

    async fn put(&self, key: &str, body: PutBody, opts: PutOptions) -> Result<ObjectMeta> {
        let len = match &body {
            PutBody::Bytes(b) => b.len() as u64,
            PutBody::Stream { len, .. } => *len,
            PutBody::File(path) => tokio::fs::metadata(path)
                .await
                .map_err(|e| StoreError::other(anyhow::anyhow!("stat {}: {e}", path.display())))?
                .len(),
        };
        if len > self.multipart_threshold {
            return self.put_blocks(key, body, &opts).await;
        }
        let data =
            match body {
                PutBody::Bytes(b) => b,
                PutBody::Stream { len, stream } => {
                    util::collect(stream, usize::try_from(len).map_err(StoreError::other)?).await?
                }
                PutBody::File(path) => Bytes::from(tokio::fs::read(&path).await.map_err(|e| {
                    StoreError::other(anyhow::anyhow!("read {}: {e}", path.display()))
                })?),
            };
        self.put_blob(key, data, &opts).await
    }

    async fn delete(&self, key: &str, if_version: Option<Version>) -> Result<()> {
        let mut req = Request::new(Method::DELETE, Some(key));
        req.if_match = if_version.as_ref().map(|v| format!("\"{}\"", v.as_str()));
        let resp = self.send_retrying(&req, || None).await?;
        let status = resp.status().as_u16();
        if resp.status().is_success() || (status == 404 && if_version.is_none()) {
            return Ok(());
        }
        // A conditional delete of an absent blob fails its `If-Match` (412) before it
        // finds nothing: report it as absent, as the other backends do.
        match error_from(key, resp).await {
            StoreError::PreconditionFailed { .. } if self.head(key).await?.is_none() => {
                Err(StoreError::NotFound { key: key.into() })
            }
            e => Err(e),
        }
    }

    fn list(
        &self,
        prefix: &str,
        start_after: Option<&str>,
    ) -> BoxStream<'static, Result<ObjectMeta>> {
        let store = AzureStore {
            http: self.http.clone(),
            account: self.account.clone(),
            container: self.container.clone(),
            multipart_threshold: self.multipart_threshold,
            multipart_part_size: self.multipart_part_size,
        };
        let state = ListState {
            store,
            prefix: prefix.to_owned(),
            start_after: start_after.map(str::to_owned),
            marker: None,
            started: false,
            buffer: Vec::new().into_iter(),
        };
        Box::pin(futures::stream::unfold(state, |mut state| async move {
            loop {
                if let Some(item) = state.buffer.next() {
                    return Some((Ok(item), state));
                }
                if state.started && state.marker.is_none() {
                    return None;
                }
                state.started = true;
                match state
                    .store
                    .list_page(&state.prefix, state.marker.as_deref(), false)
                    .await
                {
                    Ok(page) => {
                        state.marker = page.next_marker;
                        let after = state.start_after.clone();
                        state.buffer = page
                            .blobs
                            .into_iter()
                            .filter(|m| after.as_deref().is_none_or(|a| m.key.as_str() > a))
                            .collect::<Vec<_>>()
                            .into_iter();
                    }
                    Err(e) => {
                        state.marker = None;
                        return Some((Err(e), state));
                    }
                }
            }
        }))
    }

    async fn list_prefixes(&self, prefix: &str) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let page = self.list_page(prefix, marker.as_deref(), true).await?;
            out.extend(page.prefixes);
            marker = page.next_marker;
            if marker.is_none() {
                break;
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }
}

/// State of the lazy list stream.
struct ListState {
    store: AzureStore,
    prefix: String,
    start_after: Option<String>,
    marker: Option<String>,
    started: bool,
    buffer: std::vec::IntoIter<ObjectMeta>,
}

/// What one `List Blobs` page holds.
#[derive(Debug, Default)]
struct ListPage {
    blobs: Vec<ObjectMeta>,
    prefixes: Vec<String>,
    next_marker: Option<String>,
}

/// Parse a `List Blobs` answer: `<Blob>` names, sizes and etags, `<BlobPrefix>` names, and
/// the next marker. The schema is fixed and flat, so a scan for the few elements needed
/// replaces an XML library.
fn parse_list(xml: &str) -> Result<ListPage> {
    let mut page = ListPage::default();
    for blob in elements(xml, "Blob") {
        let name = element(blob, "Name")
            .ok_or_else(|| StoreError::other(anyhow::anyhow!("azure list: blob without name")))?;
        let size = element(blob, "Content-Length")
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let tag = element(blob, "Etag").unwrap_or_default();
        page.blobs.push(ObjectMeta {
            key: unescape(name),
            size,
            version: Version::new(unescape(tag).trim_matches('"').to_owned()),
        });
    }
    for prefix in elements(xml, "BlobPrefix") {
        if let Some(name) = element(prefix, "Name") {
            page.prefixes.push(unescape(name));
        }
    }
    page.next_marker = element(xml, "NextMarker")
        .map(unescape)
        .filter(|m| !m.is_empty());
    Ok(page)
}

/// The inner text of every `<tag>…</tag>` in `xml`, in order.
fn elements<'x>(xml: &'x str, tag: &str) -> Vec<&'x str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let Some(after) = rest.get(start + open.len()..) else {
            break;
        };
        let Some(end) = after.find(&close) else {
            break;
        };
        if let Some(inner) = after.get(..end) {
            out.push(inner);
        }
        rest = after.get(end + close.len()..).unwrap_or("");
    }
    out
}

/// The inner text of the first `<tag>…</tag>` in `xml`.
fn element<'x>(xml: &'x str, tag: &str) -> Option<&'x str> {
    elements(xml, tag).into_iter().next()
}

/// Decode the XML entities a blob name or marker may carry.
fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(rest.get(..amp).unwrap_or(""));
        let tail = rest.get(amp..).unwrap_or("");
        let Some(semi) = tail.find(';') else {
            out.push_str(tail);
            return out;
        };
        let entity = tail.get(1..semi).unwrap_or("");
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            e if e.starts_with("#x") => e
                .get(2..)
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .and_then(char::from_u32),
            e if e.starts_with('#') => e
                .get(1..)
                .and_then(|d| d.parse::<u32>().ok())
                .and_then(char::from_u32),
            _ => None,
        };
        match decoded {
            Some(c) => out.push(c),
            None => out.push_str(tail.get(..=semi).unwrap_or("")),
        }
        rest = tail.get(semi + 1..).unwrap_or("");
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn azurite_connection_string_keeps_the_account_path() {
        let a = Account::parse(
            "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;",
        )
        .unwrap();
        assert_eq!(a.name, "devstoreaccount1");
        assert_eq!(a.endpoint, "http://127.0.0.1:10000/devstoreaccount1");
        assert_eq!(a.endpoint_path, "/devstoreaccount1");
    }

    #[test]
    fn azure_connection_string_builds_the_account_host() {
        let a = Account::parse(
            "DefaultEndpointsProtocol=https;AccountName=acme;AccountKey=a2V5;EndpointSuffix=core.windows.net",
        )
        .unwrap();
        assert_eq!(a.endpoint, "https://acme.blob.core.windows.net");
        assert_eq!(a.endpoint_path, "");
    }

    #[test]
    fn list_pages_parse_blobs_prefixes_and_markers() {
        let xml = "<EnumerationResults><Blobs><Blob><Name>a/b&amp;c</Name><Properties><Content-Length>12</Content-Length><Etag>\"0x8D1\"</Etag></Properties></Blob><BlobPrefix><Name>a/d/</Name></BlobPrefix></Blobs><NextMarker>m1</NextMarker></EnumerationResults>";
        let page = parse_list(xml).unwrap();
        assert_eq!(page.blobs.len(), 1);
        assert_eq!(page.blobs[0].key, "a/b&c");
        assert_eq!(page.blobs[0].size, 12);
        assert_eq!(page.blobs[0].version.as_str(), "0x8D1");
        assert_eq!(page.prefixes, vec!["a/d/".to_owned()]);
        assert_eq!(page.next_marker.as_deref(), Some("m1"));
        let last =
            parse_list("<EnumerationResults><Blobs/><NextMarker /></EnumerationResults>").unwrap();
        assert!(last.next_marker.is_none());
    }

    /// A token endpoint that checks the federated token exchange and hands out
    /// `tok-<n>`, and a blob endpoint that answers only the latest token.
    async fn fake_entra_and_blob(expires_in: u64) -> (String, Arc<std::sync::atomic::AtomicU64>) {
        use std::sync::atomic::{AtomicU64, Ordering};
        let issued = Arc::new(AtomicU64::new(0));
        let tokens = issued.clone();
        let blobs = issued.clone();
        let app = axum::Router::new()
            .route(
                "/tenant-1/oauth2/v2.0/token",
                axum::routing::post(move |body: String| {
                    let tokens = tokens.clone();
                    async move {
                        assert!(body.contains("grant_type=client_credentials"), "{body}");
                        assert!(body.contains("client_id=client-1"), "{body}");
                        assert!(body.contains("client_assertion=federated-jwt"), "{body}");
                        assert!(
                            body.contains("scope=https%3A%2F%2Fstorage.azure.com%2F.default"),
                            "{body}"
                        );
                        let n = tokens.fetch_add(1, Ordering::SeqCst) + 1;
                        format!(r#"{{"token_type":"Bearer","expires_in":{expires_in},"access_token":"tok-{n}"}}"#)
                    }
                }),
            )
            .route(
                "/container/{key}",
                axum::routing::get(move |headers: axum::http::HeaderMap| {
                    let blobs = blobs.clone();
                    async move {
                        let want = format!("Bearer tok-{}", blobs.load(Ordering::SeqCst));
                        let got = headers.get("authorization").and_then(|v| v.to_str().ok());
                        if got != Some(want.as_str()) {
                            return axum::http::Response::builder()
                                .status(403)
                                .body(axum::body::Body::empty())
                                .unwrap();
                        }
                        axum::http::Response::builder()
                            .header("etag", "\"0x1\"")
                            .body(axum::body::Body::from("hello"))
                            .unwrap()
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), issued)
    }

    fn workload_identity_store(base: &str, token_file: &std::path::Path) -> AzureStore {
        let cfg = walgit_config::StoreConfig {
            backend: walgit_config::StoreBackend::Azure,
            bucket: "container".into(),
            azure: AzureConfig {
                auth: AzureAuth::WorkloadIdentity,
                account: "acct".into(),
                endpoint: base.to_owned(),
                ..AzureConfig::default()
            },
            ..Default::default()
        };
        let identity = WorkloadIdentity::new(
            &format!("{base}/"),
            "tenant-1",
            "client-1".into(),
            token_file.to_owned(),
        );
        AzureStore::with_account(&cfg, Account::entra(&cfg.azure, identity).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn workload_identity_sends_a_cached_bearer_token() {
        use std::sync::atomic::Ordering;
        let (base, issued) = fake_entra_and_blob(3600).await;
        let dir = tempfile::tempdir().unwrap();
        let token_file = dir.path().join("token");
        std::fs::write(&token_file, "federated-jwt\n").unwrap();
        let store = workload_identity_store(&base, &token_file);
        for _ in 0..3 {
            let meta = store.head("blob").await.unwrap().unwrap();
            assert_eq!(meta.version.as_str(), "0x1");
        }
        assert_eq!(issued.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn workload_identity_refreshes_a_token_close_to_expiry() {
        use std::sync::atomic::Ordering;
        let (base, issued) = fake_entra_and_blob(60).await;
        let dir = tempfile::tempdir().unwrap();
        let token_file = dir.path().join("token");
        std::fs::write(&token_file, "federated-jwt").unwrap();
        let store = workload_identity_store(&base, &token_file);
        store.head("blob").await.unwrap().unwrap();
        store.head("blob").await.unwrap().unwrap();
        assert_eq!(issued.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn workload_identity_endpoint_defaults_to_the_account_host() {
        let cfg = AzureConfig {
            auth: AzureAuth::WorkloadIdentity,
            account: "acme".into(),
            ..AzureConfig::default()
        };
        let identity = WorkloadIdentity::new(
            "https://login.microsoftonline.com/",
            "t",
            "c".into(),
            PathBuf::from("/nonexistent"),
        );
        assert_eq!(
            identity.token_url,
            "https://login.microsoftonline.com/t/oauth2/v2.0/token"
        );
        let a = Account::entra(&cfg, identity).unwrap();
        assert_eq!(a.endpoint, "https://acme.blob.core.windows.net");
        assert_eq!(a.endpoint_path, "");
    }
}
