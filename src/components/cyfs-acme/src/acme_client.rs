//! acme_client.rs
//! ACME 客户端实现
use crate::account_key::AcmeAccountKey;
use anyhow::Result;
use base64::Engine;
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
use reqwest;
use rustls::crypto::ring::sign::any_ecdsa_type;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Display;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::{sync::RwLock, time::Duration};
use tokio::fs;

/// ACME 目录结构
#[derive(Debug, Deserialize, Clone)]
struct Directory {
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newOrder")]
    new_order: String,
    #[serde(rename = "revokeCert")]
    revoke_cert: String,
}

/// Nonce 管理器
#[derive(Debug)]
struct NonceManager {
    current_nonce: Mutex<Option<String>>,
}

impl NonceManager {
    fn new() -> Self {
        Self {
            current_nonce: Mutex::new(None),
        }
    }

    /// 获取 nonce,获取后当前 nonce 失效
    fn take_nonce(&self) -> Option<String> {
        let mut nonce = self.current_nonce.lock().unwrap();
        nonce.take()
    }

    /// 更新 nonce
    fn update_nonce(&self, new_nonce: String) {
        let mut nonce = self.current_nonce.lock().unwrap();
        *nonce = Some(new_nonce);
    }
}

struct AccountInner {
    email: String,
    key: AcmeAccountKey,
    kid: RwLock<Option<String>>,
}

/// ACME 账户信息
#[derive(Serialize, Deserialize)]
#[serde(into = "AccountConfig")]
#[serde(from = "AccountConfig")]
pub struct AcmeAccount {
    inner: Arc<AccountInner>,
}

impl Clone for AcmeAccount {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Into<AccountConfig> for AcmeAccount {
    fn into(self) -> AccountConfig {
        let key_str = self
            .inner
            .key
            .to_pkcs8_pem()
            .expect("Failed to encode private key to PEM");

        AccountConfig {
            email: self.inner.email.clone(),
            key: key_str,
            kid: self.inner.kid.read().unwrap().clone(),
        }
    }
}

impl From<AccountConfig> for AcmeAccount {
    fn from(inner: AccountConfig) -> Self {
        let key = AcmeAccountKey::from_pkcs8_pem(&inner.key)
            .expect("Failed to parse private key from PEM");

        Self {
            inner: Arc::new(AccountInner {
                email: inner.email,
                key,
                kid: RwLock::new(inner.kid),
            }),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct AccountConfig {
    email: String,
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
}

impl std::fmt::Display for AcmeAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AcmeAccount(email: {})", self.inner.email)
    }
}

impl AcmeAccount {
    pub fn new(email: String) -> Self {
        info!("generate acme account key for {}", email);
        let key = AcmeAccountKey::generate_rsa2048().unwrap();

        Self {
            inner: Arc::new(AccountInner {
                email,
                key,
                kid: RwLock::new(None),
            }),
        }
    }

    pub async fn from_file(path: &Path) -> Result<Self> {
        info!("load acme account key from {}", path.display());
        let content = fs::read_to_string(path).await.map_err(|e| {
            error!(
                "read acme account key file {} failed, {}",
                path.display(),
                e
            );
            anyhow::anyhow!(
                "read acme account key file {} failed, {}",
                path.display(),
                e
            )
        })?;

        let account = serde_json::from_str(&content).map_err(|e| {
            error!(
                "parse acme account key file {} failed, {}",
                path.display(),
                e
            );
            anyhow::anyhow!(
                "parse acme account key file {} failed, {}",
                path.display(),
                e
            )
        })?;

        info!(
            "load acme account key from {} success, account: {}",
            path.display(),
            account
        );
        Ok(account)
    }

    pub async fn save_to_file(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json).await.map_err(|e| {
            error!("save acme account key to {} failed, {}", path.display(), e);
            anyhow::anyhow!("save acme account key to {} failed, {}", path.display(), e)
        })?;

        info!(
            "save acme account key to {} success, account: {}",
            path.display(),
            self
        );
        Ok(())
    }

    pub fn email(&self) -> &str {
        &self.inner.email
    }

    pub(crate) fn key(&self) -> &AcmeAccountKey {
        &self.inner.key
    }

    pub fn kid(&self) -> Option<String> {
        self.inner.kid.read().unwrap().clone()
    }

    pub fn set_kid(&self, kid: String) {
        let mut kid_lock = self.inner.kid.write().unwrap();
        *kid_lock = Some(kid);
    }
}

#[derive(Debug, Deserialize)]
struct AcmeError {
    type_: String,
    detail: String,
    status: u16,
}

#[derive(Debug, Deserialize)]
struct AcmeResponse<T> {
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<T>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    errors: Vec<AcmeError>,
}

/// ACME 客户端结构
#[derive(Clone)]
pub struct AcmeClient {
    inner: Arc<AcmeClientInner>,
}

struct AcmeClientInner {
    directory: tokio::sync::Mutex<Option<Directory>>,
    http_client: reqwest::Client,
    nonce_manager: NonceManager,
    account: AcmeAccount,
    acme_server: String,
}

/// 挑战响应接口
#[async_trait::async_trait]
pub trait AcmeChallengeResponder: Send + Sync {
    async fn respond_challenge<'a>(&self, challenges: &'a [Challenge]) -> Result<&'a Challenge>;
    fn revert_challenge(&self, challenge: &Challenge);
}

pub type AcmeChallengeResponderRef = Arc<dyn AcmeChallengeResponder>;

/// 证书订单会话
pub struct AcmeOrderSession {
    domain: String,
    valid_days: u32,
    key_type: KeyType,
    status: OrderStatus,
    client: AcmeClient,
    responder: AcmeChallengeResponderRef,
    respond_logs: Vec<Challenge>,
    order_info: Option<OrderInfo>,
}

impl std::fmt::Display for AcmeOrderSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AcmeOrderSession(domains: {})", self.domain)
    }
}

impl AcmeOrderSession {
    pub fn new(domain: String, client: AcmeClient, responder: AcmeChallengeResponderRef) -> Self {
        Self {
            domain,
            valid_days: 90,
            key_type: KeyType::Rsa2048,
            status: OrderStatus::New,
            client,
            responder,
            respond_logs: vec![],
            order_info: None,
        }
    }

    /// 开始证书申请流程
    pub async fn start(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        let directory = self.client.get_directory().await?;
        // 1. 创建订单
        let (authorizations, finalize_url) = self
            .client
            .create_order(&[self.domain.clone()], directory.clone())
            .await?;

        // 更新订单信息和状态
        self.order_info = Some(OrderInfo {
            authorizations,
            finalize_url,
        });
        self.update_status(OrderStatus::Pending);

        // 2. 处理每个授权
        if let Some(order_info) = &self.order_info {
            for auth_url in &order_info.authorizations {
                // 获取挑战信息
                let mut challenges = self
                    .client
                    .get_challenge(auth_url, directory.clone())
                    .await?;
                for challenge in challenges.iter_mut() {
                    challenge.domain = self.domain.clone();
                }
                info!(
                    "got acme challenge, client: {}, challenge: {:?}",
                    self, challenges
                );
                // 准备挑战响应
                let resp_challenge = self.responder.respond_challenge(&challenges).await?;

                // 通知服务器验证挑战
                self.client
                    .verify_challenge(&resp_challenge.url, directory.clone())
                    .await?;

                // 等待验证完成
                self.client
                    .poll_authorization(auth_url, directory.clone())
                    .await?;

                self.respond_logs.push(resp_challenge.clone());
            }
        }

        // 3. 完成订单
        if let Some(order_info) = &self.order_info {
            // 生成CSR
            let (csr, private_key) = self.client.generate_csr(&[self.domain.clone()])?;

            // Finalize订单
            let cert_url = self
                .client
                .finalize_order(&order_info.finalize_url, directory.clone(), &csr)
                .await?;

            // 下载证书
            let cert = self
                .client
                .download_certificate(&cert_url, directory.clone())
                .await?;

            Ok((cert, private_key))
        } else {
            Err(anyhow::anyhow!("No order information available"))
        }
    }
}

impl Drop for AcmeOrderSession {
    fn drop(&mut self) {
        for log in self.respond_logs.iter() {
            self.responder.revert_challenge(log);
        }
    }
}

#[derive(Debug)]
struct OrderInfo {
    authorizations: Vec<String>,
    finalize_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OrderRequest {
    identifiers: Vec<Identifier>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Identifier {
    #[serde(rename = "type")]
    type_: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct OrderResponse {
    status: String,
    expires: String,
    identifiers: Vec<Identifier>,
    authorizations: Vec<String>,
    finalize: String,
}

impl AcmeOrderSession {
    // 更新状态的方法
    fn update_status(&mut self, new_status: OrderStatus) {
        self.status = new_status;
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Copy, Serialize, Deserialize)]
pub enum ChallengeType {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
    #[serde(other)]
    Unknown,
}

impl Display for ChallengeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            ChallengeType::Http01 => "http-01".to_string(),
            ChallengeType::Dns01 => "dns-01".to_string(),
            ChallengeType::TlsAlpn01 => "tls-alpn-01".to_string(),
            ChallengeType::Unknown => "unknown".to_string(),
        };
        write!(f, "{}", str)
    }
}

impl From<String> for ChallengeType {
    fn from(value: String) -> Self {
        match value.as_str() {
            "http-01" => ChallengeType::Http01,
            "dns-01" => ChallengeType::Dns01,
            "tls-alpn-01" => ChallengeType::TlsAlpn01,
            _ => ChallengeType::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Challenge {
    pub domain: String,
    pub url: String,
    pub data: ChallengeData,
}

#[derive(Debug, Clone)]
pub enum ChallengeData {
    TlsAlpn01 { cert: Arc<CertifiedKey> },
    Http01 { token: String, key_auth: String },
    Dns01 { token: String, key_hash: String },
}

impl std::fmt::Display for AcmeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AcmeClient(account: {})", self.inner.account)
    }
}

impl AcmeClient {
    // 已有方法改为使用 inner
    pub async fn new(account: AcmeAccount, acme_directory: String) -> Result<Self> {
        info!("create acme client, account: {}", account);
        let http_client = reqwest::Client::new();

        let inner = AcmeClientInner {
            directory: tokio::sync::Mutex::new(None),
            http_client,
            nonce_manager: NonceManager::new(),
            account,
            acme_server: acme_directory,
        };

        let client = Self {
            inner: Arc::new(inner),
        };

        Ok(client)
    }

    pub fn account(&self) -> &AcmeAccount {
        &self.inner.account
    }

    async fn get_directory(&self) -> Result<Directory> {
        let mut directory = self.inner.directory.lock().await;
        if directory.is_some() {
            Ok(directory.clone().unwrap())
        } else {
            info!("get acme directory");
            // 从 ACME 服务器获取目录
            let dir: Directory = self
                .inner
                .http_client
                // .get("https://acme-v02.api.letsencrypt.org/directory")
                .get(self.inner.acme_server.as_str())
                .send()
                .await
                .map_err(|e| {
                    error!("get acme directory failed, {}", e);
                    anyhow::anyhow!("get acme directory failed, {}", e)
                })?
                .json()
                .await
                .map_err(|e| {
                    error!("parse acme directory failed, {}", e);
                    anyhow::anyhow!("parse acme directory failed, {}", e)
                })?;

            info!("get acme directory success, directory: {:?}", dir);
            *directory = Some(dir.clone());

            if self.account().kid().is_none() {
                self.register_account(dir.clone()).await?;
            }
            Ok(dir)
        }
    }
    async fn register_account(&self, directory: Directory) -> Result<()> {
        info!("register acme account, client: {}", self);
        let payload = serde_json::json!({
            "termsOfServiceAgreed": true,
            "contact": [
                format!("mailto:{}", self.account().email())
            ]
        });

        let nonce = self.get_nonce(directory.clone()).await?;
        let jws = self.sign_request_new_account(&directory.new_account, &nonce, &payload)?;

        let response = self
            .inner
            .http_client
            .post(&directory.new_account)
            .header("Content-Type", "application/jose+json")
            .json(&jws)
            .send()
            .await
            .map_err(|e| {
                error!("register acme account failed, client: {}, {}", self, e);
                anyhow::anyhow!("register acme account failed, client: {}, {}", self, e)
            })?;

        if response.status().is_success() {
            // 获取账户 URL (kid)
            let kid = response
                .headers()
                .get("Location")
                .ok_or_else(|| anyhow::anyhow!("No Location header in new account response"))?
                .to_str()?
                .to_string();

            self.inner.account.set_kid(kid.clone());
            info!("got account kid: {}", kid);
        }

        let _: AccountResponse = self.handle_response(response).await?;
        Ok(())
    }

    /// 专门用于账户注册的签名请求
    fn sign_request_new_account<T: Serialize>(
        &self,
        url: &str,
        nonce: &str,
        payload: &T,
    ) -> Result<serde_json::Value> {
        let payload_str = serde_json::to_string(payload)?;
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_str);
        let protected = self.build_protected_header(url, nonce, true)?;
        self.sign_jws(protected, payload_b64)
    }

    // 新增方法
    async fn get_challenge(&self, auth_url: &str, directory: Directory) -> Result<Vec<Challenge>> {
        info!(
            "get acme challenge, client: {}, auth_url: {}",
            self, auth_url
        );

        let authz: AuthzResponse =
            self.signed_post_as_get(auth_url, directory)
                .await
                .map_err(|e| {
                    error!(
                        "get acme challenge failed, client: {}, auth_url: {}, {}",
                        self, auth_url, e
                    );
                    anyhow::anyhow!(
                        "get acme challenge failed, client: {}, auth_url: {}, {}",
                        self,
                        auth_url,
                        e
                    )
                })?;

        let mut challengs = vec![];
        for challenge in authz.challenges.iter() {
            match challenge.type_ {
                ChallengeType::Http01 => {
                    challengs.push(Challenge {
                        domain: authz.identifier.value.clone(),
                        url: challenge.url.clone(),
                        data: ChallengeData::Http01 {
                            token: challenge.token.clone(),
                            key_auth: self.compute_key_authorization(&challenge.token)?,
                        },
                    });
                }
                ChallengeType::Dns01 => {
                    challengs.push(Challenge {
                        domain: authz.identifier.value.clone(),
                        url: challenge.url.clone(),
                        data: ChallengeData::Dns01 {
                            token: challenge.token.clone(),
                            key_hash: self.compute_key_authorization_hash(&challenge.token)?,
                        },
                    });
                }
                ChallengeType::TlsAlpn01 => {
                    challengs.push(Challenge {
                        domain: authz.identifier.value.clone(),
                        url: challenge.url.clone(),
                        data: ChallengeData::TlsAlpn01 {
                            cert: Arc::new(self.compute_tls_alpn_01_key(
                                authz.identifier.value.as_str(),
                                &challenge.token,
                            )?),
                        },
                    });
                }
                _ => {}
            }
        }

        Ok(challengs)
    }

    fn compute_key_authorization(&self, token: &str) -> Result<String> {
        // 计算 key authorization: token + "." + base64url(JWK thumbprint)
        let thumbprint = self.account().key().thumbprint()?;

        Ok(format!(
            "{}.{}",
            token,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(thumbprint)
        ))
    }

    fn build_protected_header(
        &self,
        url: &str,
        nonce: &str,
        force_jwk: bool,
    ) -> Result<serde_json::Value> {
        if !force_jwk {
            if let Some(kid) = self.inner.account.kid() {
                return Ok(serde_json::json!({
                    "alg": self.account().key().alg(),
                    "kid": kid,
                    "nonce": nonce,
                    "url": url
                }));
            }
        }

        Ok(serde_json::json!({
            "alg": self.account().key().alg(),
            "nonce": nonce,
            "url": url,
            "jwk": self.account().key().jwk()
        }))
    }

    fn sign_jws(
        &self,
        protected: serde_json::Value,
        payload_b64: String,
    ) -> Result<serde_json::Value> {
        let protected_str = serde_json::to_string(&protected)?;
        let protected_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(protected_str);

        let signing_input = format!("{}.{}", protected_b64, payload_b64);
        let signature = self.account().key().sign(signing_input.as_bytes())?;
        let signature_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature);

        Ok(serde_json::json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": signature_b64,
        }))
    }

    fn compute_key_authorization_hash(&self, token: &str) -> Result<String> {
        let mut hasher = Sha256::new();
        hasher.update(self.compute_key_authorization(token)?.as_bytes());
        let key_bytes = hasher.finalize();
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_bytes))
    }

    fn compute_tls_alpn_01_key(&self, domain: &str, token: &str) -> Result<CertifiedKey> {
        let mut params = rcgen::CertificateParams::new(vec![domain.to_string()]).map_err(|e| {
            error!("generate tls alpn01 key failed, domain: {}, {}", domain, e);
            anyhow::anyhow!("generate tls alpn01 key failed, domain: {}, {}", domain, e)
        })?;
        let key_auth = self.compute_key_authorization_hash(token)?;
        params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(key_auth.as_str())
                .unwrap()
                .as_slice(),
        )];
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|e| {
            error!("generate tls alpn01 key failed, domain: {}, {}", domain, e);
            anyhow::anyhow!("generate tls alpn01 key failed, domain: {}, {}", domain, e)
        })?;
        let cert = params.self_signed(&key_pair).map_err(|e| {
            error!("generate tls alpn01 key failed, domain: {}, {}", domain, e);
            anyhow::anyhow!("generate tls alpn01 key failed, domain: {}, {}", domain, e)
        })?;

        let sk = any_ecdsa_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            key_pair.serialize_der(),
        )))
        .map_err(|e| {
            error!("generate tls alpn01 key failed, domain: {}, {}", domain, e);
            anyhow::anyhow!("generate tls alpn01 key failed, domain: {}, {}", domain, e)
        })?;
        let certi_key = CertifiedKey::new(vec![cert.der().clone()], sk);
        Ok(certi_key)
    }

    /// 处理ACME响应，不关心返回值
    async fn handle_response_no_body(&self, response: reqwest::Response) -> Result<()> {
        // 更新nonce
        if let Some(new_nonce) = response.headers().get("Replay-Nonce") {
            if let Ok(nonce) = new_nonce.to_str() {
                self.inner.nonce_manager.update_nonce(nonce.to_string());
            }
        }

        // 检查状态码
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await?;
            error!("acme response error, status: {}, body: {}", status, body);
            return Err(anyhow::anyhow!("HTTP error: {} - {}", status, body));
        }

        Ok(())
    }

    async fn verify_challenge(&self, challenge_url: &str, directory: Directory) -> Result<()> {
        info!(
            "verify acme challenge, client: {}, challenge_url: {}",
            self, challenge_url
        );
        self.signed_post_no_body(challenge_url, directory, &serde_json::json!({}))
            .await
            .map_err(|e| {
                error!(
                    "verify acme challenge failed, client: {}, challenge_url: {}, {}",
                    self, challenge_url, e
                );
                anyhow::anyhow!(
                    "verify acme challenge failed, client: {}, challenge_url: {}, {}",
                    self,
                    challenge_url,
                    e
                )
            })
    }

    /// 轮询授权状态
    async fn poll_authorization(&self, auth_url: &str, directory: Directory) -> Result<()> {
        info!(
            "poll acme authorization, client: {}, auth_url: {}",
            self, auth_url
        );
        let max_attempts = 10;
        let wait_seconds = 3;

        for _ in 0..max_attempts {
            let authz: AuthzResponse = self
                .signed_post_as_get(auth_url, directory.clone())
                .await
                .map_err(|e| {
                error!(
                    "poll acme authorization failed, client: {}, auth_url: {}, {}",
                    self, auth_url, e
                );
                anyhow::anyhow!(
                    "poll acme authorization failed, client: {}, auth_url: {}, {}",
                    self,
                    auth_url,
                    e
                )
            })?;

            match authz.status.as_str() {
                "valid" => {
                    info!(
                        "poll acme authorization success, client: {}, auth_url: {}",
                        self, auth_url
                    );
                    return Ok(());
                }
                "pending" => {
                    info!(
                        "poll acme authorization pending, client: {}, auth_url: {}, wait {} seconds",
                        self, auth_url, wait_seconds
                    );
                    tokio::time::sleep(Duration::from_secs(wait_seconds)).await;
                    continue;
                }
                "invalid" => {
                    error!(
                        "poll acme authorization failed, client: {}, auth_url: {}, status: {}",
                        self, auth_url, authz.status
                    );
                    return Err(anyhow::anyhow!("Authorization failed"));
                }
                _ => {
                    error!(
                        "poll acme authorization failed, client: {}, auth_url: {}, status: {}",
                        self, auth_url, authz.status
                    );
                    return Err(anyhow::anyhow!(
                        "Unexpected authorization status: {}",
                        authz.status
                    ));
                }
            }
        }

        info!(
            "poll acme authorization timeout, client: {}, auth_url: {}",
            self, auth_url
        );
        Err(anyhow::anyhow!("Authorization polling timeout"))
    }

    /// 完成订单
    async fn finalize_order(&self, url: &str, directory: Directory, csr: &[u8]) -> Result<String> {
        info!(
            "finalize acme order, client: {}, url: {}, csr: {}",
            self,
            url,
            csr.len()
        );
        let payload = serde_json::json!({
            "csr": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(csr)
        });

        let response: FinalizeResponse =
            self.signed_post(url, directory, &payload)
                .await
                .map_err(|e| {
                    error!(
                        "finalize acme order failed, client: {}, url: {}, csr: {}, {}",
                        self,
                        url,
                        csr.len(),
                        e
                    );
                    anyhow::anyhow!(
                        "finalize acme order failed, client: {}, url: {}, csr: {}, {}",
                        self,
                        url,
                        csr.len(),
                        e
                    )
                })?;

        info!(
            "finalize acme order success, client: {}, url: {}, csr: {}, response: {:?}",
            self,
            url,
            csr.len(),
            response
        );
        match response.status.as_str() {
            "valid" => Ok(response
                .certificate
                .ok_or_else(|| anyhow::anyhow!("No certificate URL in response"))?),
            _ => Err(anyhow::anyhow!(
                "Order finalization failed: {}",
                response.status
            )),
        }
    }

    /// 下载证书
    async fn download_certificate(&self, url: &str, directory: Directory) -> Result<Vec<u8>> {
        info!("download acme certificate, client: {}, url: {}", self, url);

        let cert_data = self
            .signed_post_as_get_bytes(url, directory, Some("application/pem-certificate-chain"))
            .await
            .map_err(|e| {
                error!(
                    "download acme certificate failed, client: {}, url: {}, {}",
                    self, url, e
                );
                anyhow::anyhow!("download acme certificate failed: {}", e)
            })?;

        info!(
            "download acme certificate success, client: {}, url: {}",
            self, url
        );
        Ok(cert_data)
    }

    /// 创建新的订单
    async fn create_order(
        &self,
        domains: &[String],
        directory: Directory,
    ) -> Result<(Vec<String>, String)> {
        info!(
            "create acme order, client: {}, domains: {}",
            self,
            domains.join(",")
        );
        // 构造订单请求
        let request = OrderRequest {
            identifiers: domains
                .iter()
                .map(|domain| Identifier {
                    type_: "dns".to_string(),
                    value: domain.clone(),
                })
                .collect(),
        };

        // 发送订单请求
        let response: OrderResponse = self
            .signed_post(directory.new_order.clone().as_str(), directory, &request)
            .await
            .map_err(|e| {
                error!(
                    "create acme order failed, client: {}, domains: {}, {}",
                    self,
                    domains.join(","),
                    e
                );
                anyhow::anyhow!(
                    "create acme order failed, client: {}, domains: {}, {}",
                    self,
                    domains.join(","),
                    e
                )
            })?;

        info!(
            "create acme order success, client: {}, domains: {}, response: {:?}",
            self,
            domains.join(","),
            response
        );

        // 返回授权URL列表和finalize URL
        Ok((response.authorizations, response.finalize))
    }

    fn generate_csr(&self, domains: &[String]) -> Result<(Vec<u8>, Vec<u8>)> {
        if domains.is_empty() {
            return Err(anyhow::anyhow!("generate csr failed: empty domain list"));
        }

        let mut params = rcgen::CertificateParams::new(domains.to_vec())?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, domains[0].clone());

        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let csr = params.serialize_request(&key_pair)?;

        Ok((
            csr.der().as_ref().to_vec(),
            key_pair.serialize_pem().into_bytes(),
        ))
    }

    /// 发送签名的POST请求并处理响应
    async fn signed_post<T, R>(&self, url: &str, directory: Directory, payload: &T) -> Result<R>
    where
        T: Serialize,
        R: DeserializeOwned,
    {
        let nonce = self.get_nonce(directory).await?;
        let jws = self.sign_request(url, &nonce, payload)?;

        let response = self
            .inner
            .http_client
            .post(url)
            .header("Content-Type", "application/jose+json")
            .json(&jws)
            .send()
            .await?;

        self.handle_response(response).await
    }

    async fn signed_post_as_get<R>(&self, url: &str, directory: Directory) -> Result<R>
    where
        R: DeserializeOwned,
    {
        let nonce = self.get_nonce(directory).await?;
        let jws = self.sign_request_post_as_get(url, &nonce)?;

        let response = self
            .inner
            .http_client
            .post(url)
            .header("Content-Type", "application/jose+json")
            .json(&jws)
            .send()
            .await?;

        self.handle_response(response).await
    }

    async fn signed_post_as_get_bytes(
        &self,
        url: &str,
        directory: Directory,
        accept: Option<&str>,
    ) -> Result<Vec<u8>> {
        let nonce = self.get_nonce(directory).await?;
        let jws = self.sign_request_post_as_get(url, &nonce)?;

        let mut request = self
            .inner
            .http_client
            .post(url)
            .header("Content-Type", "application/jose+json");
        if let Some(accept) = accept {
            request = request.header("Accept", accept);
        }

        let response = request.json(&jws).send().await?;

        if let Some(new_nonce) = response.headers().get("Replay-Nonce") {
            if let Ok(nonce) = new_nonce.to_str() {
                self.inner.nonce_manager.update_nonce(nonce.to_string());
            }
        }

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await?;
            error!("acme response error, status: {}, body: {}", status, body);
            return Err(anyhow::anyhow!("HTTP error: {} - {}", status, body));
        }

        Ok(response.bytes().await?.to_vec())
    }

    /// 获取 nonce
    async fn get_nonce(&self, directory: Directory) -> Result<String> {
        if let Some(nonce) = self.inner.nonce_manager.take_nonce() {
            Ok(nonce)
        } else {
            self.fetch_new_nonce(directory).await
        }
    }

    /// 从服务器获取新的 nonce
    async fn fetch_new_nonce(&self, directory: Directory) -> Result<String> {
        info!("fetch acme nonce, client: {}", self);
        let response = self
            .inner
            .http_client
            .head(&directory.new_nonce)
            .send()
            .await
            .map_err(|e| {
                error!("fetch acme nonce failed, client: {}, {}", self, e);
                anyhow::anyhow!("fetch acme nonce failed, client: {}, {}", self, e)
            })?;

        let nonce = response
            .headers()
            .get("Replay-Nonce")
            .ok_or_else(|| anyhow::anyhow!("No nonce found"))?
            .to_str()?
            .to_string();

        info!(
            "fetch acme nonce success, client: {}, nonce: {}",
            self, nonce
        );

        Ok(nonce)
    }

    /// 处理ACME响应
    async fn handle_response<R>(&self, response: reqwest::Response) -> Result<R>
    where
        R: DeserializeOwned,
    {
        // 更新nonce
        if let Some(new_nonce) = response.headers().get("Replay-Nonce") {
            if let Ok(nonce) = new_nonce.to_str() {
                self.inner.nonce_manager.update_nonce(nonce.to_string());
            }
        }

        // 检查状态码
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await?;
            error!("acme response error, status: {}, body: {}", status, body);
            return Err(anyhow::anyhow!("HTTP error: {}", status));
        }

        // 解析响应体
        let body = response.text().await?;
        let result = serde_json::from_str(&body).map_err(|e| {
            error!(
                "decode acme response failed, status: {}, error: {}, body: {}",
                status, e, body
            );
            anyhow::anyhow!("decode acme response failed: {}", e)
        })?;
        Ok(result)
    }

    /// 签名请求数据
    fn sign_request<T: Serialize>(
        &self,
        url: &str,
        nonce: &str,
        payload: &T,
    ) -> Result<serde_json::Value> {
        let payload_str = serde_json::to_string(payload)?;
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_str);
        let protected = self.build_protected_header(url, nonce, false)?;
        self.sign_jws(protected, payload_b64)
    }

    fn sign_request_post_as_get(&self, url: &str, nonce: &str) -> Result<serde_json::Value> {
        let payload_b64 = String::new();
        let protected = self.build_protected_header(url, nonce, false)?;
        self.sign_jws(protected, payload_b64)
    }

    /// 发送签名的POST请求，不需要响应体
    async fn signed_post_no_body<T: Serialize>(
        &self,
        url: &str,
        directory: Directory,
        payload: &T,
    ) -> Result<()> {
        let nonce = self.get_nonce(directory).await?;
        let jws = self.sign_request(url, &nonce, payload)?;

        let response = self
            .inner
            .http_client
            .post(url)
            .header("Content-Type", "application/jose+json")
            .json(&jws)
            .send()
            .await?;

        self.handle_response_no_body(response).await
    }
}

#[derive(Debug)]
enum KeyType {
    Rsa2048,
    Rsa4096,
    // 可以后续添加 ECC 等其他类型
}

#[derive(Debug, PartialEq)]
enum OrderStatus {
    New,
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

#[derive(Debug, Deserialize)]
struct AuthzResponse {
    identifier: Identifier,
    status: String,
    expires: String,
    challenges: Vec<ChallengeResponse>,
}

#[derive(Debug, Deserialize)]
struct ChallengeResponse {
    #[serde(rename = "type")]
    type_: ChallengeType,
    url: String,
    status: String,
    token: String,
}

#[derive(Debug, Deserialize)]
struct FinalizeResponse {
    status: String,
    certificate: Option<String>,
    #[serde(default)]
    error: Option<AcmeError>,
}

#[derive(Debug, Deserialize)]
struct AccountResponse {
    status: String,
    #[serde(default)]
    contact: Vec<String>,
    orders: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_as_get_uses_empty_payload() {
        let client = AcmeClient {
            inner: Arc::new(AcmeClientInner {
                directory: tokio::sync::Mutex::new(None),
                http_client: reqwest::Client::new(),
                nonce_manager: NonceManager::new(),
                account: AcmeAccount::new("test@example.com".to_string()),
                acme_server: "https://example.com/directory".to_string(),
            }),
        };

        let jws = client
            .sign_request_post_as_get("https://example.com/acme/authz/1", "nonce")
            .unwrap();

        assert_eq!(jws["payload"].as_str(), Some(""));
    }
}
