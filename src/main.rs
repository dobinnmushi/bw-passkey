//! bw-passkey: Bitwarden の保管庫にあるパスキーで答える、仮想の FIDO2 セキュリティキー。
//!
//! ブラウザやアプリからは USB のセキュリティキーに見える（uhid）。指紋で本人確認をしたうえで、
//! - ログイン（getAssertion）: 保管庫（rbw）からそのサイトのパスキーを取り出して署名する。
//! - 作成（makeCredential）: 作ったパスキーを、保管庫の新しいログイン項目として保存する。
//!
//! 構成:
//!   hid.rs     USB HID（CTAPHID）のやり取り
//!   vault.rs   保管庫からパスキーを集める（rbw のトークンで /sync、復号は rbw-agent）
//!   agent.rs   rbw-agent に復号を頼む
//!   verify.rs  本人確認（指紋 → だめならマスターパスワード）

#[macro_use]
mod i18n;
mod agent;
mod hid;
mod verify;
mod vault;

use soft_fido2::{
    Authenticator, AuthenticatorCallbacks, AuthenticatorConfig, AuthenticatorOptions, Credential,
    CredentialBackupState, CredentialKeyError, CredentialKeyProvider, CredentialKeyProviderId,
    CredentialRef, CtapCommand, Extensions, GeneratedCredentialKey, RelyingParty, Result,
    SoftwareCredentialKeyProvider, UpResult, User, UvResult,
};
use soft_fido2_ctap::{CredentialKey, SecBytes};
use std::sync::Mutex;

/// この仮想キーの AAGUID（認証器の種類を表す番号。bw-passkey 用に作った乱数）
const AAGUID: [u8; 16] = [
    0x17, 0x1a, 0xee, 0x5e, 0x63, 0xac, 0x42, 0x91, 0x9b, 0x6c, 0x57, 0x22, 0xa7, 0x83, 0x9a, 0xcc,
];
/// ES256（P-256 の ECDSA）。Bitwarden のパスキーはこれだけ
const ALG_ES256: i32 = -7;

/// 鍵を作る部品。soft-fido2 の標準（ソフトウェアの鍵）に任せるが、ES256 にしか対応しないと答える。
/// 設定の algorithms で絞っても、サイトが Ed25519 を先に挙げると soft-fido2 はそれを選ぶため
/// （make_credential.rs の validate_and_choose_algorithm）、ここで断る
struct Es256Only(SoftwareCredentialKeyProvider);

impl CredentialKeyProvider for Es256Only {
    fn provider_id(&self) -> CredentialKeyProviderId {
        self.0.provider_id()
    }

    fn supports_algorithm(&self, algorithm: i32) -> bool {
        algorithm == ALG_ES256
    }

    fn generate(&self, algorithm: i32) -> std::result::Result<GeneratedCredentialKey, CredentialKeyError> {
        if algorithm != ALG_ES256 {
            return Err(CredentialKeyError::UnsupportedAlgorithm);
        }
        self.0.generate(algorithm)
    }

    fn sign(&self, key: &CredentialKey, algorithm: i32, message: &[u8]) -> std::result::Result<Vec<u8>, CredentialKeyError> {
        self.0.sign(key, algorithm, message)
    }
}

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

    fn write_credential(&self, cred: &CredentialRef) -> Result<()> {
        log::debug!("create: {} alg={} key {} bytes", cred.rp_id, cred.alg, cred.key.material.as_slice().len());
        // 新しいパスキーの作成（force_resident_keys なので必ずここを通る）。保存に失敗したらサイトにもエラーを返す
        let key = cred.key.material.as_slice();
        if *cred.alg != ALG_ES256 || key.len() != 32 {
            self.verifier.notify(&tr!("このキーでは、P-256 の ECDSA 以外のパスキーは作れません", "This key can only create P-256 ECDSA passkeys"));
            return Err(soft_fido2::Error::Other);
        }
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(key);
        let new = vault::NewPasskey {
            credential_id: cred.id.to_vec(),
            rp_id: cred.rp_id.to_owned(),
            rp_name: cred.rp_name.map(str::to_owned),
            user_handle: cred.user_id.to_vec(),
            user_name: cred.user_name.map(str::to_owned),
            user_display_name: cred.user_display_name.map(str::to_owned),
            private_key,
        };
        match self.vault.lock().unwrap().save_new(&new) {
            Ok(name) => {
                log::info!("{}: created a passkey and saved it to the vault", cred.rp_id);
                self.verifier.notify(&tr!("パスキーを作って保管庫に保存しました: {name}", "Created a passkey and saved it to the vault: {name}"));
                Ok(())
            }
            Err(e) => {
                log::warn!("{}: could not save the passkey: {e}", cred.rp_id);
                self.verifier.notify(&tr!("パスキーを保管庫に保存できませんでした: {e}", "Could not save the passkey to the vault: {e}"));
                Err(soft_fido2::Error::Other)
            }
        }
    }

    fn read_credential(&self, cred_id: &[u8]) -> Result<Option<Credential>> {
        log::debug!("find by id ({} bytes)", cred_id.len());
        let mut vault = self.vault.lock().unwrap();
        let all = vault.all().map_err(|e| {
            log::warn!("{e}");
            soft_fido2::Error::Other
        })?;
        // ID だけを復号して探し、見つかったものだけ秘密鍵まで復号する
        for enc in all {
            if enc.credential_id().is_ok_and(|id| id == cred_id) {
                return match enc.decrypt() {
                    Ok(p) => Ok(Some(to_credential(&p))),
                    Err(e) => {
                        log::warn!("could not decrypt a passkey ({}): {e}", enc.item_name);
                        Ok(None)
                    }
                };
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
            self.verifier.notify(&tr!("保管庫からパスキーを読めませんでした: {e}", "Could not read passkeys from the vault: {e}"));
            soft_fido2::Error::Other
        })?;
        let mut out = Vec::new();
        for enc in found {
            match enc.decrypt() {
                Ok(p) if user_id.is_none_or(|u| u == p.user_handle.as_slice()) => out.push(to_credential(&p)),
                Ok(_) => {}
                Err(e) => log::warn!("could not decrypt a passkey ({}): {e}", enc.item_name),
            }
        }
        log::info!("{rp_id}: {} passkey(s)", out.len());
        if out.is_empty() {
            self.verifier.notify(&tr!("保管庫に {rp_id} のパスキーがありません", "No passkey for {rp_id} in the vault"));
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
            Ok(p) => println!("{}\t{}\t{}\t{}{}", enc.item_name, p.rp_id, p.user_name.as_deref().unwrap_or(""), tr!("鍵OK", "key OK"),
                              if p.counter > 0 { tr!("（カウンタ {}）", " (counter {})", p.counter) } else { String::new() }),
            Err(e) => {
                bad += 1;
                println!("{}\t{}\t-\t{}", enc.item_name, enc.rp_id, tr!("読めない: {e}", "unreadable: {e}"));
            }
        }
    }
    println!("{}", tr!("合計 {} 件（読めないもの {bad} 件）", "{} in total ({bad} unreadable)", all.len()));
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
            CtapCommand::MakeCredential,
            CtapCommand::GetInfo,
            CtapCommand::GetAssertion,
            CtapCommand::GetNextAssertion,
            CtapCommand::ClientPin,
            CtapCommand::Selection,
        ])
        .options(options)
        // Bitwarden のパスキーは ES256（P-256 の ECDSA）だけ（鍵を作る部品の Es256Only でも断る）
        .algorithms(vec![ALG_ES256])
        .max_credentials(1000)
        // 署名の回数は常に 0（Bitwarden のパスキーも 0 のまま。保管庫に書き戻さない）
        .constant_sign_count(true)
        // 作るパスキーは必ず保管庫に保存する（ID に鍵を包んで返す方式は使わない）
        .force_resident_keys(true)
        // Bitwarden と同じく「同期されるパスキー」の印（BE・BS）を作成時から立てる
        .default_credential_backup_state(CredentialBackupState::BackedUp)
        .build();

    let mut auth = match Authenticator::with_config_and_key_provider(callbacks, config, Es256Only(SoftwareCredentialKeyProvider)) {
        Ok(a) => a,
        Err(e) => {
            log::error!("could not create the authenticator: {e:?}");
            std::process::exit(1);
        }
    };
    if let Err(e) = hid::run(&mut auth) {
        log::error!("could not run the virtual security key: {e:?} (check write access to /dev/uhid)");
        std::process::exit(1);
    }
}
