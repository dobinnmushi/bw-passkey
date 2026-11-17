//! 本人確認（指紋）。bw-vault の門があるときは、門が秘密鍵を渡す前（と、パスキーを保存する前）に polkit で本人確認をするので、
//! ここでは確認しない（鍵がなければ署名できず、鍵は確認なしには得られないので、ブラウザの UV・UP の要求はそのまま通してよい）。
//! 門がないときは、bw-autotype と同じ方針:
//! - 保管庫がロック中なら、マスターパスワードで開くこと自体を本人確認とする。
//! - 指紋（fprintd-verify）が一致すれば通す。
//! - 指紋が使えない・一致しないときは、保管庫をロックし直してマスターパスワードを聞く（それより弱い経路にしない）。
//! - 同じサイトについて直前（数秒以内）に確認が済んでいれば、続く「本人の操作の確認（UP）」はもう一度求めない。

use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const FINGER_TRIES: u32 = 3;
const FINGER_TIMEOUT_SECS: u64 = 15;
/// この時間内の確認は、続く UP の要求に使い回す（1回のログインで指紋を2度求めないため）
const REUSE: Duration = Duration::from_secs(10);

pub struct Verifier {
    last: Mutex<Option<(Instant, String)>>,
}

fn notify(body: &str, replace: Option<&str>) -> Option<String> {
    let mut cmd = Command::new("notify-send");
    cmd.args(["-p", "-a", "bw-passkey", "-i", "dialog-password", "-t", "20000"]);
    if let Some(id) = replace {
        cmd.args(["-r", id]);
    }
    let title = tr!("Bitwarden パスキー", "Bitwarden passkey");
    let out = cmd.args([title.as_str(), body]).stderr(Stdio::null()).output().ok()?;
    let id = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    (!id.is_empty()).then_some(id)
}

fn close_notification(id: Option<String>) {
    if let Some(id) = id {
        let _ = Command::new("gdbus")
            .args(["call", "--session", "--dest", "org.freedesktop.Notifications",
                   "--object-path", "/org/freedesktop/Notifications",
                   "--method", "org.freedesktop.Notifications.CloseNotification", &id])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn fingerprint(rp_id: &str) -> bool {
    // ログインか作成かは、ブラウザの問い合わせ方（UV の許可を先にもらう）からは区別できないので中立の文言にする
    let mut nid = notify(&tr!("{rp_id} でパスキーを使います。指紋センサーに触れてください", "Using a passkey for {rp_id}. Touch the fingerprint sensor"), None);
    let mut ok = false;
    for left in (0..FINGER_TRIES).rev() {
        let out = Command::new("timeout")
            .args([&FINGER_TIMEOUT_SECS.to_string(), "fprintd-verify"])
            .stdin(Stdio::null())
            .output();
        let Ok(out) = out else { break };
        let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
        if text.contains("verify-match") {
            ok = true;
            break;
        }
        if text.contains("verify-no-match") && left > 0 {
            nid = notify(&tr!("指紋が一致しません。もう一度触れてください（残り {left} 回）", "No match. Touch the sensor again ({left} left)"), nid.as_deref())
                .or(nid);
            continue;
        }
        break;
    }
    close_notification(nid);
    ok
}

fn master_password() -> bool {
    let nid = notify(&tr!("指紋を確認できなかったため、マスターパスワードで確認します", "Fingerprint not verified. Asking for the master password instead"), None);
    let _ = Command::new("rbw").arg("lock").status();
    let ok = Command::new("rbw").arg("unlock").status().is_ok_and(|s| s.success());
    close_notification(nid);
    ok
}

impl Verifier {
    pub fn new() -> Self {
        Verifier { last: Mutex::new(None) }
    }

    /// 本人確認（UV）。通れば true
    pub fn verify(&self, rp_id: &str) -> bool {
        if crate::gate::available() {
            return true;
        }
        let ok = if !Command::new("rbw").arg("unlocked").status().is_ok_and(|s| s.success()) {
            // 保管庫がロック中: マスターパスワードで開くこと自体を本人確認とする（指紋と二重に求めない）
            log::info!("verification: vault locked, unlocking with the master password ({rp_id})");
            let nid = notify(&tr!("{rp_id} でパスキーを使います。保管庫を開いてください",
                                  "Using a passkey for {rp_id}. Unlock the vault"), None);
            let ok = Command::new("rbw").arg("unlock").status().is_ok_and(|s| s.success());
            close_notification(nid);
            ok
        } else if fingerprint(rp_id) {
            log::info!("verification: fingerprint ok ({rp_id})");
            true
        } else {
            log::info!("verification: fingerprint failed, asking for the master password ({rp_id})");
            master_password()
        };
        if ok {
            *self.last.lock().unwrap() = Some((Instant::now(), rp_id.to_owned()));
        } else {
            log::info!("verification: denied ({rp_id})");
        }
        ok
    }

    /// 本人の操作の確認（UP）。同じサイトで直前に本人確認が済んでいればそれを使い、なければ本人確認と同じことをする
    pub fn presence(&self, rp_id: &str) -> bool {
        if crate::gate::available() {
            return true;
        }
        let recent = self.last.lock().unwrap().as_ref().is_some_and(|(t, rp)| t.elapsed() < REUSE && rp == rp_id);
        recent || self.verify(rp_id)
    }

    pub fn notify(&self, body: &str) {
        notify(body, None);
    }
}
