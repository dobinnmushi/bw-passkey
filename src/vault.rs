//! Bitwarden の保管庫からパスキー（login.fido2Credentials）を集める。
//!
//! rbw はパスキーの欄を読まないので、rbw が持つアクセストークンで保管庫の生のデータ（/sync）を取り、
//! 暗号文のまま覚えておく。サイトの判定に使う rpId だけは取得時に平文にし、秘密鍵などは使う直前に
//! rbw-agent で復号する（agent.rs）。
//!
//! 形式は Bitwarden 公式クライアント（libs/common/src/platform/services/fido2/）に合わせる:
//! - keyValue: P-256 の秘密鍵（PKCS#8 DER）の base64url
//! - credentialId: UUID なら 16 バイト、"b64." で始まればその後ろの base64url
//! - userHandle: base64url
//! - Bitwarden が作るパスキーのカウンタは常に 0（使っても書き戻さない）

use crate::agent;
use base64::Engine as _;
use base64::engine::general_purpose::{URL_SAFE_NO_PAD, STANDARD};
use p256::pkcs8::DecodePrivateKey;
use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

/// /sync の結果をこの時間だけ使い回す（新しく登録したパスキーは、見つからなければすぐ取り直す）
const CACHE_TTL: Duration = Duration::from_secs(600);
/// rbw と同じ値（rbw の src/api.rs）。これより古いと返さない欄があるため
const CLIENT_VERSION: &str = "2024.12.0";

/// 保管庫の中の1つのパスキー（rpId 以外は暗号文のまま）
#[derive(Clone)]
pub struct EncPasskey {
    pub item_name: String,
    pub rp_id: String,
    entry_key: Option<String>,
    org_id: Option<String>,
    fields: Value,
}

/// 使う直前に復号したパスキー
pub struct Passkey {
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_handle: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub private_key: [u8; 32],
    pub discoverable: bool,
    pub counter: u32,
}

impl Drop for Passkey {
    fn drop(&mut self) {
        self.private_key.fill(0);
    }
}

pub struct Vault {
    cache: Vec<EncPasskey>,
    fetched: Option<Instant>,
}

// ---- rbw の設定・DB ----
fn profile() -> String {
    match std::env::var("RBW_PROFILE") {
        Ok(p) if !p.is_empty() => format!("rbw-{p}"),
        _ => "rbw".to_string(),
    }
}

fn xdg(var: &str, fallback: &str) -> PathBuf {
    std::env::var(var)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(fallback))
}

fn rbw_config() -> Result<Value, String> {
    let path = xdg("XDG_CONFIG_HOME", ".config").join(profile()).join("config.json");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

/// rbw の設定 base_url から API の URL を作る（rbw の src/config.rs と同じ規則）
fn api_url(config: &Value) -> String {
    match config["base_url"].as_str() {
        None => "https://api.bitwarden.com".into(),
        Some(url) => {
            let url = url.trim_end_matches('/');
            if url == "https://api.bitwarden.eu" { url.into() } else { format!("{url}/api") }
        }
    }
}

/// rbw の DB（~/.cache/rbw/<サーバー>:<メールアドレス>.json）からアクセストークンを読む
fn access_token(config: &Value) -> Result<String, String> {
    let email = config["email"].as_str().ok_or("rbw にメールアドレスが設定されていません")?;
    let dir = xdg("XDG_CACHE_HOME", ".cache").join(profile());
    let suffix = format!(":{email}.json");
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.ends_with(&suffix)) {
            let db: Value = serde_json::from_str(&std::fs::read_to_string(&path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            return db["access_token"].as_str().map(str::to_owned).ok_or_else(|| "rbw にログインしていません".into());
        }
    }
    Err("rbw の DB が見つかりません（rbw login を済ませてください）".into())
}

fn rbw(args: &[&str]) -> bool {
    Command::new("rbw").args(args).status().is_ok_and(|s| s.success())
}

/// 保管庫が開いていなければ開く（pinentry でマスターパスワードを聞く）
pub fn ensure_unlocked() -> Result<(), String> {
    if rbw(&["unlocked"]) || rbw(&["unlock"]) {
        Ok(())
    } else {
        Err("保管庫を開けませんでした".into())
    }
}

/// JSON の欄を、先頭が小文字・大文字のどちらでも取る（Bitwarden の API は両方の書き方がありうる）
fn field<'a>(v: &'a Value, name: &str) -> &'a Value {
    let mut cap = name.to_owned();
    cap[..1].make_ascii_uppercase();
    match v.get(name) {
        Some(x) if !x.is_null() => x,
        _ => v.get(&cap).unwrap_or(&Value::Null),
    }
}

fn fetch_sync(config: &Value) -> Result<Value, String> {
    let url = format!("{}/sync", api_url(config));
    let get = |token: &str| {
        ureq::get(&url)
            .set("Authorization", &format!("Bearer {token}"))
            .set("Bitwarden-Client-Version", CLIENT_VERSION)
            .call()
    };
    match get(&access_token(config)?) {
        Ok(res) => res.into_json().map_err(|e| e.to_string()),
        // トークンが古い: rbw sync がトークンを更新して DB に書くので、読み直してもう一度
        Err(ureq::Error::Status(401, _)) => {
            if !rbw(&["sync"]) {
                return Err("rbw sync に失敗しました".into());
            }
            get(&access_token(config)?).map_err(|e| e.to_string())?.into_json().map_err(|e| e.to_string())
        }
        Err(e) => Err(e.to_string()),
    }
}

fn decode_b64url(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| STANDARD.decode(s))
        .map_err(|e| format!("base64: {e}"))
}

/// Bitwarden の credentialId をバイト列にする（parseCredentialId と同じ）
fn parse_credential_id(s: &str) -> Result<Vec<u8>, String> {
    if let Some(rest) = s.strip_prefix("b64.") {
        return decode_b64url(rest);
    }
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err("credentialId の形式が不正です".into());
    }
    (0..16)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

impl Vault {
    pub fn new() -> Self {
        Vault { cache: Vec::new(), fetched: None }
    }

    fn refresh(&mut self) -> Result<(), String> {
        ensure_unlocked()?;
        let config = rbw_config()?;
        let sync = fetch_sync(&config)?;
        let mut found = Vec::new();
        for cipher in field(&sync, "ciphers").as_array().into_iter().flatten() {
            if field(cipher, "type").as_i64() != Some(1) || !field(cipher, "deletedDate").is_null() {
                continue;
            }
            let creds = field(field(cipher, "login"), "fido2Credentials");
            let Some(creds) = creds.as_array() else { continue };
            let entry_key = field(cipher, "key").as_str().map(str::to_owned);
            let org_id = field(cipher, "organizationId").as_str().map(str::to_owned);
            let enc_name = field(cipher, "name").as_str().unwrap_or("");
            let item_name = agent::decrypt(enc_name, entry_key.as_deref(), org_id.as_deref()).unwrap_or_default();
            for c in creds {
                let enc_rp = field(c, "rpId").as_str().unwrap_or("");
                match agent::decrypt(enc_rp, entry_key.as_deref(), org_id.as_deref()) {
                    Ok(rp_id) => found.push(EncPasskey {
                        item_name: item_name.clone(),
                        rp_id,
                        entry_key: entry_key.clone(),
                        org_id: org_id.clone(),
                        fields: c.clone(),
                    }),
                    Err(e) => log::warn!("パスキーの rpId を復号できません（{item_name}）: {e}"),
                }
            }
        }
        log::info!("保管庫のパスキー: {} 件", found.len());
        self.cache = found;
        self.fetched = Some(Instant::now());
        Ok(())
    }

    fn stale(&self) -> bool {
        self.fetched.is_none_or(|t| t.elapsed() > CACHE_TTL)
    }

    /// rp_id のパスキー（暗号文のまま）。古ければ取り直し、見つからなければもう一度だけ取り直す
    pub fn find(&mut self, rp_id: &str) -> Result<Vec<EncPasskey>, String> {
        if self.stale() {
            self.refresh()?;
        }
        let hits = |v: &Vault| v.cache.iter().filter(|p| p.rp_id == rp_id).cloned().collect::<Vec<_>>();
        let mut found = hits(self);
        if found.is_empty() && self.fetched.is_some_and(|t| t.elapsed() > Duration::from_secs(10)) {
            self.refresh()?;
            found = hits(self);
        }
        Ok(found)
    }

    /// 全サイトのパスキー（暗号文のまま。資格情報の一覧を求められたとき用）
    pub fn all(&mut self) -> Result<Vec<EncPasskey>, String> {
        if self.stale() {
            self.refresh()?;
        }
        Ok(self.cache.clone())
    }
}

impl EncPasskey {
    fn dec(&self, name: &str) -> Result<Option<String>, String> {
        match field(&self.fields, name).as_str() {
            None => Ok(None),
            Some(enc) => agent::decrypt(enc, self.entry_key.as_deref(), self.org_id.as_deref()).map(Some),
        }
    }

    /// 秘密鍵まで含めて復号する
    pub fn decrypt(&self) -> Result<Passkey, String> {
        let algo = self.dec("keyAlgorithm")?.unwrap_or_default();
        let curve = self.dec("keyCurve")?.unwrap_or_default();
        if algo != "ECDSA" || curve != "P-256" {
            return Err(format!("未対応の鍵です（{algo} {curve}）"));
        }
        let der = decode_b64url(&self.dec("keyValue")?.ok_or("keyValue がありません")?)?;
        let secret = p256::SecretKey::from_pkcs8_der(&der).map_err(|e| format!("秘密鍵を読めません: {e}"))?;
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&secret.to_bytes());
        Ok(Passkey {
            credential_id: parse_credential_id(&self.dec("credentialId")?.ok_or("credentialId がありません")?)?,
            rp_id: self.rp_id.clone(),
            rp_name: self.dec("rpName")?,
            user_handle: decode_b64url(&self.dec("userHandle")?.unwrap_or_default())?,
            user_name: self.dec("userName")?,
            user_display_name: self.dec("userDisplayName")?,
            private_key,
            discoverable: self.dec("discoverable")?.as_deref() != Some("false"),
            counter: self.dec("counter")?.and_then(|c| c.parse().ok()).unwrap_or(0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_id_guid() {
        let id = parse_credential_id("6f158274-aab6-443d-9bcf-8a3f69297c88").unwrap();
        assert_eq!(id, vec![0x6f, 0x15, 0x82, 0x74, 0xaa, 0xb6, 0x44, 0x3d, 0x9b, 0xcf, 0x8a, 0x3f, 0x69, 0x29, 0x7c, 0x88]);
    }

    #[test]
    fn credential_id_b64() {
        assert_eq!(parse_credential_id("b64.AQID").unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn field_either_case() {
        let v: Value = serde_json::json!({"RpId": "a", "userName": "b"});
        assert_eq!(field(&v, "rpId"), "a");
        assert_eq!(field(&v, "userName"), "b");
    }
}
