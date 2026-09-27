//! Documented Google REST methods over maintained TLS. No generic caller URL.
//! OAuth minting is delegated to an operator-installed, hash-pinned Google CLI.
use super::{
    Error, Result,
    package::{Artifact, Package, ResourceKind, ResourcePlan},
    read_regular,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, StatusCode,
    body::{Body, Frame, SizeHint},
    client::conn::http1,
};
use hyper_util::rt::TokioIo;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Read,
    num::NonZeroUsize,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    pin::Pin,
    process::Stdio,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, ReadBuf},
    net::TcpStream,
    time::Instant,
};
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

pub fn file_sha256(path: &Path) -> Result<String> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| Error("artifact open failed"))?;
    if !f
        .metadata()
        .map_err(|_| Error("artifact stat failed"))?
        .is_file()
    {
        return Err(Error("artifact must be a regular file"));
    }
    let mut hash = Sha256::new();
    let mut bytes = [0; 65536];
    loop {
        let n = f
            .read(&mut bytes)
            .map_err(|_| Error("artifact read failed"))?;
        if n == 0 {
            break;
        }
        hash.update(&bytes[..n]);
    }
    Ok(hex::encode(hash.finalize()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Runtime {
    pub gcloud: Artifact,
    /// Reviewed CLI distribution identity, including its Python/modules.
    pub gcloud_distribution_receipt: Artifact,
    pub gcloud_config_directory: PathBuf,
    pub trust_roots_der: Vec<Artifact>,
    /// Explicit operator-selected bounds, shared by the entire invocation.
    pub invocation_budget_ms: u64,
    pub response_limit_bytes: usize,
}
impl Runtime {
    pub fn validate(&self) -> Result<()> {
        self.gcloud.verify()?;
        self.gcloud_distribution_receipt.verify()?;
        let m = std::fs::symlink_metadata(&self.gcloud_config_directory)
            .map_err(|_| Error("Google CLI credential directory unavailable"))?;
        if !self.gcloud_config_directory.is_absolute()
            || !m.is_dir()
            || m.file_type().is_symlink()
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o077 != 0
        {
            return Err(Error(
                "Google CLI configuration requires private current-UID directory",
            ));
        }
        if self.invocation_budget_ms == 0
            || self.response_limit_bytes == 0
            || self.trust_roots_der.is_empty()
        {
            return Err(Error(
                "positive runtime bounds and explicit TLS roots required",
            ));
        }
        for a in &self.trust_roots_der {
            a.verify()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Operation {
    pub name: String,
    pub status: String,
    pub target_link: String,
    pub target_id: Option<String>,
    pub client_operation_id: Option<String>,
    pub error: Option<Value>,
}
#[derive(Debug, Clone)]
pub enum Mutation {
    Operation(Operation),
    Object(Value),
    Absent,
}

#[allow(async_fn_in_trait)]
pub trait Provider {
    async fn preflight(&mut self, package: &Package) -> Result<()>;
    async fn get(&mut self, resource: &ResourcePlan) -> Result<Option<Value>>;
    /// A missing live staging object can still have a billable noncurrent or
    /// soft-deleted generation. Check the exact generation recorded at create.
    async fn staging_generation_residual(
        &mut self,
        resource: &ResourcePlan,
        identity: &str,
    ) -> Result<bool>;
    async fn create(
        &mut self,
        package: &Package,
        resource: &ResourcePlan,
        request_id: &str,
    ) -> Result<Mutation>;
    async fn delete(
        &mut self,
        resource: &ResourcePlan,
        identity: &str,
        request_id: &str,
    ) -> Result<Mutation>;
    async fn operation(&mut self, resource: &ResourcePlan, name: &str) -> Result<Operation>;
    async fn recover_operation(
        &mut self,
        resource: &ResourcePlan,
        request_id: &str,
    ) -> Result<Option<Operation>>;
}

pub struct GoogleClient {
    authorization: hyper::header::HeaderValue,
    tls: Arc<ClientConfig>,
    deadline: Instant,
    limit: NonZeroUsize,
}
type RequestBody = UnsyncBoxBody<Bytes, std::io::Error>;
fn full(bytes: Vec<u8>) -> RequestBody {
    Full::new(Bytes::from(bytes))
        .map_err(|never| match never {})
        .boxed_unsync()
}
struct Abort(tokio::task::JoinHandle<()>);
impl Drop for Abort {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl GoogleClient {
    /// Only call after operator admission. This may mint a token via Google CLI.
    pub async fn authenticate(runtime: &Runtime, project: &str) -> Result<Self> {
        runtime.validate()?;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(runtime.invocation_budget_ms))
            .ok_or(Error("invalid invocation deadline"))?;
        let mut command = tokio::process::Command::new(&runtime.gcloud.path);
        command
            .args([
                "--quiet",
                "--verbosity=none",
                "--project",
                project,
                "auth",
                "print-access-token",
            ])
            .env("CLOUDSDK_CONFIG", &runtime.gcloud_config_directory)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .stdout(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|_| Error("Google CLI could not start"))?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or(Error("Google CLI output missing"))?;
        let token = tokio::time::timeout_at(deadline, async {
            let mut bytes = Zeroizing::new(Vec::new());
            (&mut stdout)
                .take(runtime.response_limit_bytes as u64 + 1)
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| Error("Google CLI token read failed"))?;
            if bytes.len() > runtime.response_limit_bytes {
                return Err(Error("Google CLI response exceeds operator bound"));
            }
            if !child
                .wait()
                .await
                .map_err(|_| Error("Google CLI failed"))?
                .success()
            {
                return Err(Error("Google CLI authentication failed"));
            }
            Ok(bytes)
        })
        .await
        .map_err(|_| Error("Google CLI authentication deadline exceeded"))??;
        let token = std::str::from_utf8(&token)
            .map_err(|_| Error("invalid OAuth token"))?
            .trim();
        if token.is_empty()
            || token
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return Err(Error("invalid OAuth token"));
        }
        let header_text = Zeroizing::new(format!("Bearer {token}"));
        let mut authorization = hyper::header::HeaderValue::from_str(&header_text)
            .map_err(|_| Error("invalid OAuth token"))?;
        authorization.set_sensitive(true);
        let mut roots = RootCertStore::empty();
        for a in &runtime.trust_roots_der {
            roots
                .add(CertificateDer::from(read_regular(&a.path)?))
                .map_err(|_| Error("invalid TLS root"))?;
        }
        let mut tls =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|_| Error("TLS configuration failed"))?
                .with_root_certificates(roots)
                .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        tls.resumption = rustls::client::Resumption::disabled();
        tls.enable_early_data = false;
        tls.key_log = Arc::new(rustls::NoKeyLog);
        Ok(Self {
            authorization,
            tls: Arc::new(tls),
            deadline,
            limit: NonZeroUsize::new(runtime.response_limit_bytes)
                .ok_or(Error("invalid response bound"))?,
        })
    }
    async fn exchange(
        &self,
        host: &'static str,
        path: String,
        method: Method,
        body: RequestBody,
        content_type: String,
    ) -> Result<(StatusCode, Vec<u8>)> {
        tokio::time::timeout_at(self.deadline, async {
            let socket = TcpStream::connect((host, 443))
                .await
                .map_err(|_| Error("Google API connection failed"))?;
            let stream = TlsConnector::from(self.tls.clone())
                .connect(
                    ServerName::try_from(host).map_err(|_| Error("invalid API hostname"))?,
                    socket,
                )
                .await
                .map_err(|_| Error("Google API TLS authentication failed"))?;
            let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
                .await
                .map_err(|_| Error("Google API HTTP setup failed"))?;
            let _guard = Abort(tokio::spawn(async move {
                let _ = connection.await;
            }));
            let mut builder = Request::builder()
                .method(method)
                .uri(path)
                .header("Host", host)
                .header("Authorization", self.authorization.clone())
                .header("Content-Type", content_type);
            if let Some(length) = body.size_hint().exact() {
                builder = builder.header("Content-Length", length);
            }
            let request = builder
                .body(body)
                .map_err(|_| Error("Google request encoding failed"))?;
            let response = sender
                .send_request(request)
                .await
                .map_err(|_| Error("Google API request failed; outcome may be uncertain"))?;
            let status = response.status();
            let mut body = response.into_body();
            let mut bytes = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame =
                    frame.map_err(|_| Error("Google response failed; outcome may be uncertain"))?;
                if let Ok(data) = frame.into_data() {
                    if data.len() > self.limit.get().saturating_sub(bytes.len()) {
                        return Err(Error("Google response exceeds operator bound"));
                    }
                    bytes.extend_from_slice(&data);
                }
            }
            if status.is_redirection() {
                return Err(Error("Google API redirect rejected"));
            }
            Ok((status, bytes))
        })
        .await
        .map_err(|_| Error("Google API invocation deadline exceeded; outcome may be uncertain"))?
    }
    async fn json(
        &self,
        host: &'static str,
        path: String,
        method: Method,
        body: Option<&Value>,
    ) -> Result<Option<Value>> {
        let bytes = body
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|_| Error("request JSON failed"))?
            .unwrap_or_default();
        let (status, bytes) = self
            .exchange(host, path, method, full(bytes), "application/json".into())
            .await?;
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(Error(
                "Google API rejected request; preserve journal and inspect account",
            ));
        }
        if bytes.is_empty() {
            return Ok(Some(Value::Null));
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| Error("invalid Google JSON response"))
    }
}
fn path(resource: &ResourcePlan) -> (&'static str, String) {
    if resource.kind == ResourceKind::StagingObject {
        (
            "storage.googleapis.com",
            format!("/storage/v1/{}", resource.path),
        )
    } else {
        (
            "compute.googleapis.com",
            format!("/compute/v1/{}", resource.path),
        )
    }
}
pub(crate) fn staging_generation_paths(
    resource: &ResourcePlan,
    identity: &str,
) -> Result<[String; 2]> {
    if resource.kind != ResourceKind::StagingObject
        || identity.is_empty()
        || !identity.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Error("invalid staging generation query"));
    }
    let (host, path) = path(resource);
    if host != "storage.googleapis.com" {
        return Err(Error("invalid staging resource path"));
    }
    Ok([
        format!("{path}?generation={identity}"),
        format!("{path}?generation={identity}&softDeleted=true"),
    ])
}
pub fn operation_path(resource: &ResourcePlan, name: &str) -> Result<String> {
    if !super::package::name(name) {
        return Err(Error("invalid Google operation name"));
    }
    let collection = resource
        .path
        .rsplit_once('/')
        .ok_or(Error("invalid resource path"))?
        .0;
    let scope = collection
        .rsplit_once('/')
        .ok_or(Error("invalid resource scope"))?
        .0;
    Ok(format!("/compute/v1/{scope}/operations/{name}"))
}
fn parse_operation(v: Value) -> Result<Operation> {
    serde_json::from_value(v).map_err(|_| Error("invalid Google operation response"))
}

fn validate_staging_bucket(bucket: &Value) -> Result<()> {
    // A missing policy is not evidence that soft delete is disabled. Require
    // the explicit zero returned by the Storage JSON API for a disabled policy.
    if bucket.get("retentionPolicy").is_some()
        || bucket.get("defaultEventBasedHold").and_then(Value::as_bool) == Some(true)
        || bucket
            .pointer("/versioning/enabled")
            .and_then(Value::as_bool)
            == Some(true)
        || bucket
            .pointer("/softDeletePolicy/retentionDurationSeconds")
            .and_then(Value::as_str)
            != Some("0")
    {
        return Err(Error(
            "staging bucket retention, versioning, or soft delete prevents bounded cleanup",
        ));
    }
    if bucket
        .pointer("/iamConfiguration/publicAccessPrevention")
        .and_then(Value::as_str)
        != Some("enforced")
    {
        return Err(Error(
            "staging bucket must enforce public access prevention",
        ));
    }
    Ok(())
}

impl Provider for GoogleClient {
    async fn preflight(&mut self, package: &Package) -> Result<()> {
        super::ensure_live_creation_ready()?;
        // Detect storage retention/soft-delete billing before image upload.
        let bucket = self
            .json(
                "storage.googleapis.com",
                format!("/storage/v1/b/{}", package.spec.staging_bucket),
                Method::GET,
                None,
            )
            .await?
            .ok_or(Error("staging bucket missing"))?;
        validate_staging_bucket(&bucket)
    }
    async fn get(&mut self, resource: &ResourcePlan) -> Result<Option<Value>> {
        let (h, p) = path(resource);
        self.json(h, p, Method::GET, None).await
    }
    async fn staging_generation_residual(
        &mut self,
        resource: &ResourcePlan,
        identity: &str,
    ) -> Result<bool> {
        let [noncurrent, soft_deleted] = staging_generation_paths(resource, identity)?;
        let bucket_name = resource
            .path
            .strip_prefix("b/")
            .and_then(|tail| tail.split_once("/o/"))
            .map(|(bucket, _)| bucket)
            .ok_or(Error("invalid staging resource path"))?;
        let bucket = self
            .json(
                "storage.googleapis.com",
                format!("/storage/v1/b/{bucket_name}"),
                Method::GET,
                None,
            )
            .await?
            .ok_or(Error(
                "staging bucket unavailable; cleanup remains uncertain",
            ))?;
        if bucket.get("name").and_then(Value::as_str) != Some(bucket_name) {
            return Err(Error("staging bucket identity mismatch"));
        }
        // Ordinary GET omits both noncurrent and soft-deleted objects. A 404
        // here is not cleanup evidence until both exact-generation reads miss.
        if self
            .json("storage.googleapis.com", noncurrent, Method::GET, None)
            .await?
            .is_some()
        {
            return Ok(true);
        }
        Ok(self
            .json("storage.googleapis.com", soft_deleted, Method::GET, None)
            .await?
            .is_some())
    }
    async fn create(
        &mut self,
        package: &Package,
        resource: &ResourcePlan,
        request_id: &str,
    ) -> Result<Mutation> {
        super::ensure_live_creation_ready()?;
        if resource.kind == ResourceKind::StagingObject {
            package.spec.raw_image_tar_gz.verify()?;
            let boundary = super::uuid()?;
            let metadata = json!({"name":package.spec.object_name(),"metadata":resource.create_body,"contentType":"application/gzip"});
            let prefix=format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{}\r\n--{boundary}\r\nContent-Type: application/gzip\r\n\r\n",serde_json::to_string(&metadata).map_err(|_|Error("upload metadata encoding failed"))?).into_bytes();
            let suffix = format!("\r\n--{boundary}--\r\n").into_bytes();
            let stdfile = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&package.spec.raw_image_tar_gz.path)
                .map_err(|_| Error("raw image open failed"))?;
            let length = stdfile
                .metadata()
                .map_err(|_| Error("raw image stat failed"))?
                .len();
            let body = FileBody {
                file: tokio::fs::File::from_std(stdfile),
                prefix: Some(prefix),
                suffix: Some(suffix),
                remaining: length,
            };
            let (status, bytes) = self
                .exchange(
                    "storage.googleapis.com",
                    format!(
                        "/upload/storage/v1/b/{}/o?uploadType=multipart&ifGenerationMatch=0",
                        package.spec.staging_bucket
                    ),
                    Method::POST,
                    body.boxed_unsync(),
                    format!("multipart/related; boundary={boundary}"),
                )
                .await?;
            if !status.is_success() {
                return Err(Error(
                    "image upload rejected or uncertain; reconcile staging object before retry",
                ));
            }
            return Ok(Mutation::Object(
                serde_json::from_slice(&bytes).map_err(|_| Error("invalid upload response"))?,
            ));
        }
        let collection = resource
            .path
            .rsplit_once('/')
            .ok_or(Error("invalid resource path"))?
            .0;
        let value = self
            .json(
                "compute.googleapis.com",
                format!("/compute/v1/{collection}?requestId={request_id}"),
                Method::POST,
                Some(&resource.create_body),
            )
            .await?
            .ok_or(Error("Google creation endpoint missing"))?;
        Ok(Mutation::Operation(parse_operation(value)?))
    }
    async fn delete(
        &mut self,
        resource: &ResourcePlan,
        identity: &str,
        request_id: &str,
    ) -> Result<Mutation> {
        if resource.kind != ResourceKind::StagingObject {
            return Err(Error(
                "Compute deletion blocked: name-based delete lacks an incarnation precondition",
            ));
        }
        let (h, mut p) = path(resource);
        if resource.kind == ResourceKind::StagingObject {
            if identity.is_empty() || !identity.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error("invalid object generation"));
            }
            p.push_str(&format!(
                "?generation={identity}&ifGenerationMatch={identity}"
            ));
        } else {
            p.push_str(&format!("?requestId={request_id}"));
        }
        match self.json(h, p, Method::DELETE, None).await? {
            None => Ok(Mutation::Absent),
            Some(v) if resource.kind == ResourceKind::StagingObject => Ok(Mutation::Object(v)),
            Some(v) => Ok(Mutation::Operation(parse_operation(v)?)),
        }
    }
    async fn operation(&mut self, resource: &ResourcePlan, name: &str) -> Result<Operation> {
        parse_operation(
            self.json(
                "compute.googleapis.com",
                operation_path(resource, name)?,
                Method::GET,
                None,
            )
            .await?
            .ok_or(Error(
                "Google operation expired or unavailable; outcome remains uncertain",
            ))?,
        )
    }
    async fn recover_operation(
        &mut self,
        resource: &ResourcePlan,
        request_id: &str,
    ) -> Result<Option<Operation>> {
        if !super::valid_uuid(request_id) {
            return Err(Error("invalid request id for operation recovery"));
        }
        let path = operation_path(resource, "placeholder")?;
        let collection = path
            .rsplit_once('/')
            .ok_or(Error("invalid operation collection"))?
            .0;
        let filter = percent_encoding::utf8_percent_encode(
            &format!("clientOperationId = \"{request_id}\""),
            percent_encoding::NON_ALPHANUMERIC,
        )
        .to_string();
        let response = self
            .json(
                "compute.googleapis.com",
                format!("{collection}?filter={filter}"),
                Method::GET,
                None,
            )
            .await?
            .ok_or(Error("Google operation collection unavailable"))?;
        if response
            .get("nextPageToken")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
        {
            return Err(Error("operation recovery is ambiguous; preserve journal"));
        }
        let items = response
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if items.len() > 1 {
            return Err(Error("operation recovery returned multiple matches"));
        }
        items.into_iter().next().map(parse_operation).transpose()
    }
}

struct FileBody {
    file: tokio::fs::File,
    prefix: Option<Vec<u8>>,
    suffix: Option<Vec<u8>>,
    remaining: u64,
}
impl Body for FileBody {
    type Data = Bytes;
    type Error = std::io::Error;
    fn size_hint(&self) -> SizeHint {
        let mut h = SizeHint::new();
        h.set_exact(
            self.remaining
                + self.prefix.as_ref().map_or(0, |v| v.len() as u64)
                + self.suffix.as_ref().map_or(0, |v| v.len() as u64),
        );
        h
    }
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, Self::Error>>> {
        if let Some(prefix) = self.prefix.take() {
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from(prefix)))));
        }
        if self.remaining > 0 {
            let mut buffer = [0u8; 65536];
            let take = (self.remaining as usize).min(buffer.len());
            let mut read = ReadBuf::new(&mut buffer[..take]);
            match Pin::new(&mut self.file).poll_read(cx, &mut read) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(Ok(())) => {
                    let bytes = read.filled();
                    if bytes.is_empty() {
                        return Poll::Ready(Some(Err(std::io::Error::from(
                            std::io::ErrorKind::UnexpectedEof,
                        ))));
                    }
                    self.remaining -= bytes.len() as u64;
                    return Poll::Ready(Some(Ok(Frame::data(Bytes::copy_from_slice(bytes)))));
                }
            }
        }
        Poll::Ready(self.suffix.take().map(|b| Ok(Frame::data(Bytes::from(b)))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_bucket_requires_explicitly_disabled_soft_delete() {
        let mut bucket = json!({
            "iamConfiguration": {"publicAccessPrevention": "enforced"}
        });
        assert!(validate_staging_bucket(&bucket).is_err());

        bucket["softDeletePolicy"] = json!({"retentionDurationSeconds": "604800"});
        assert!(validate_staging_bucket(&bucket).is_err());

        bucket["softDeletePolicy"] = json!({"retentionDurationSeconds": "0"});
        assert!(validate_staging_bucket(&bucket).is_ok());
    }
}
