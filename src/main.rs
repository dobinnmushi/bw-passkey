//! bw-passkey: Bitwarden の保管庫にあるパスキーで答える、仮想の FIDO2 セキュリティキー。
//!
//! ブラウザやアプリからは USB のセキュリティキーに見える（uhid）。ログイン（getAssertion）の要求が来たら、
//! 指紋で本人確認をし、保管庫（rbw）からそのサイトのパスキーを取り出して署名する。
//! 新しいパスキーの作成（makeCredential）にはまだ対応しない（作成はブラウザ拡張に任せる）。
//!
//! 構成:
//!   hid.rs     USB HID（CTAPHID）のやり取り
//!   vault.rs   保管庫からパスキーを集める（rbw のトークンで /sync、復号は rbw-agent）
//!   agent.rs   rbw-agent に復号を頼む
//!   verify.rs  本人確認（指紋 → だめならマスターパスワード）

mod agent;
mod hid;
mod verify;
mod vault;

use soft_fido2::{
    Authenticator, AuthenticatorCallbacks, AuthenticatorConfig, AuthenticatorOptions, Credential,
    CredentialBackupState, CredentialRef, CtapCommand, Extensions, RelyingParty, Result, UpResult,
    User, UvResult,
};
use soft_fido2_ctap::{CredentialKey, SecBytes};
use std::sync::Mutex;

/// この仮想キーの AAGUID（認証器の種類を表す番号。bw-passkey 用に作った乱数）
const AAGUID: [u8; 16] = [
    0x17, 0x1a, 0xee, 0x5e, 0x63, 0xac, 0x42, 0x91, 0x9b, 0x6c, 0x57, 0x22, 0xa7, 0x83, 0x9a, 0xcc,
];
/// ES256（P-256 の ECDSA）。Bitwarden のパスキーはこれだけ
const ALG_ES256: i32 = -7;

struct Callbacks {
    vault: Mutex<vault::Vault>,
    verifier: verify::Verifier,
}

fn to_credential(p: &vault::Passkey) -> Credential {
    let mut user = User::new(p.user_handle.clone());
    user.name = p.user_name.clone();
    user.display_name = p.user_display_name.clone();
    let mut rp = RelyingParty::new(p.rp_id.clone());
    rp.name = p.rp_name.clone();
    Credential {
        id: p.credential_id.clone(),
        rp,
        user,
        sign_count: p.counter,
        alg: ALG_ES256,
        key: CredentialKey::software(SecBytes::from_slice(&p.private_key)),
        created: 0,
        discoverable: p.discoverable,
        // Bitwarden は「同期されるパスキー」の印（BE・BS）を常に立てているので合わせる
        backup_state: CredentialBackupState::BackedUp,
        extensions: Extensions::default(),
    }
}

impl AuthenticatorCallbacks for Callbacks {
    fn request_up(&self, _info: &str, _user: Option<&str>, rp_id: &str) -> Result<UpResult> {
        Ok(if self.verifier.presence(rp_id) { UpResult::Accepted } else { UpResult::Denied })
    }

    fn request_uv(&self, _info: &str, _user: Option<&str>, rp_id: &str) -> Result<UvResult> {
        Ok(if self.verifier.verify(rp_id) { UvResult::Accepted } else { UvResult::Denied })
    }

    fn write_credential(&self, _cred: &CredentialRef) -> Result<()> {
        // 作成の命令は受け付けていないのでここには来ないはず。来ても保管庫には書かない
        self.verifier.notify("このキーでは、新しいパスキーはまだ作れません（ブラウザ拡張で作ってください）");
        Err(soft_fido2::Error::Other)
    }

    fn read_credential(&self, cred_id: &[u8]) -> Result<Option<Credential>> {
        let mut vault = self.vault.lock().unwrap();
        let all = vault.all().map_err(|e| {
            log::warn!("{e}");
            soft_fido2::Error::Other
        })?;
        for enc in all {
            match enc.decrypt() {
                Ok(p) if p.credential_id == cred_id => return Ok(Some(to_credential(&p))),
                Ok(_) => {}
                Err(e) => log::warn!("パスキーを復号できません（{}）: {e}", enc.item_name),
            }
        }
        Ok(None)
    }

    fn delete_credential(&self, _cred_id: &[u8]) -> Result<()> {
        Err(soft_fido2::Error::Other)
    }

    fn list_credentials(&self, rp_id: &str, user_id: Option<&[u8]>) -> Result<Vec<Credential>> {
        let mut vault = self.vault.lock().unwrap();
        let found = vault.find(rp_id).map_err(|e| {
            log::warn!("{e}");
            self.verifier.notify(&format!("保管庫からパスキーを読めませんでした: {e}"));
            soft_fido2::Error::Other
        })?;
        let mut out = Vec::new();
        for enc in found {
            match enc.decrypt() {
                Ok(p) if user_id.is_none_or(|u| u == p.user_handle.as_slice()) => out.push(to_credential(&p)),
                Ok(_) => {}
                Err(e) => log::warn!("パスキーを復号できません（{}）: {e}", enc.item_name),
            }
        }
        log::info!("{rp_id}: パスキー {} 件", out.len());
        if out.is_empty() {
            self.verifier.notify(&format!("保管庫に {rp_id} のパスキーがありません"));
        }
        Ok(out)
    }

    fn enumerate_rps(&self) -> Result<Vec<(String, Option<String>, usize)>> {
        // 資格情報の管理（credentialManagement）は受け付けていないので使われない
        Ok(Vec::new())
    }

    fn credential_count(&self) -> Result<usize> {
        // ブラウザの問い合わせ（getInfo）のたびに保管庫を開かないよう、数えない
        Ok(0)
    }

    fn get_timestamp_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

/// --list: 保管庫のパスキーを、秘密を出さずに一覧する（読めるかの確認用）
fn list() -> i32 {
    let mut vault = vault::Vault::new();
    let all = match vault.all() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let mut bad = 0;
    for enc in &all {
        match enc.decrypt() {
            Ok(p) => println!("{}\t{}\t{}\t鍵OK{}", enc.item_name, p.rp_id, p.user_name.as_deref().unwrap_or(""),
                              if p.counter > 0 { format!("（カウンタ {}）", p.counter) } else { String::new() }),
            Err(e) => {
                bad += 1;
                println!("{}\t{}\t-\t読めない: {e}", enc.item_name, enc.rp_id);
            }
        }
    }
    println!("合計 {} 件（読めないもの {bad} 件）", all.len());
    i32::from(bad > 0)
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .init();
    if std::env::args().nth(1).as_deref() == Some("--list") {
        std::process::exit(list());
    }

    let callbacks = Callbacks { vault: Mutex::new(vault::Vault::new()), verifier: verify::Verifier::new() };
    let options = AuthenticatorOptions::new()
        .with_resident_keys(true)
        .with_user_presence(true)
        .with_user_verification(Some(true)) // 指紋による本人確認を内蔵している、と名乗る
        .with_pin_uv_auth_token(Some(true))
        .with_client_pin(None); // PIN は持たない
    let config = AuthenticatorConfig::builder()
        .aaguid(AAGUID)
        .commands(vec![
            CtapCommand::GetInfo,
            CtapCommand::GetAssertion,
            CtapCommand::GetNextAssertion,
            CtapCommand::ClientPin,
            CtapCommand::Selection,
        ])
        .options(options)
        .max_credentials(1000)
        // 署名の回数は常に 0（Bitwarden のパスキーも 0 のまま。保管庫に書き戻さない）
        .constant_sign_count(true)
        .build();

    let mut auth = match Authenticator::with_config(callbacks, config) {
        Ok(a) => a,
        Err(e) => {
            log::error!("認証器を作れません: {e:?}");
            std::process::exit(1);
        }
    };
    if let Err(e) = hid::run(&mut auth) {
        log::error!("仮想セキュリティキーを動かせません: {e:?}（/dev/uhid の権限を確かめてください）");
        std::process::exit(1);
    }
}
