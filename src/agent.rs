//! rbw-agent に暗号文の復号・平文の暗号化を頼む。
//!
//! rbw-agent は UNIX ソケット（$XDG_RUNTIME_DIR/rbw/socket）で、1行の JSON の要求を受けて
//! 1行の JSON で答える（rbw の src/protocol.rs）。保管庫の鍵は rbw-agent の中にあり、
//! こちらは暗号文を渡して平文を受け取るだけ。

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

/// pinentry（マスターパスワードの再確認がある項目）が画面を出せるように渡す環境変数（rbw と同じ一覧の一部）
const ENV_VARS: &[&str] = &[
    "DISPLAY",
    "XAUTHORITY",
    "WAYLAND_DISPLAY",
    "XDG_SESSION_TYPE",
    "DBUS_SESSION_BUS_ADDRESS",
    "GTK_IM_MODULE",
];

fn profile() -> String {
    match std::env::var("RBW_PROFILE") {
        Ok(p) if !p.is_empty() => format!("rbw-{p}"),
        _ => "rbw".to_string(),
    }
}

fn socket_path() -> PathBuf {
    let runtime = std::env::var("XDG_RUNTIME_DIR")
        .unwrap_or_else(|_| format!("/run/user/{}", unsafe { libc::getuid() }));
    PathBuf::from(runtime).join(profile()).join("socket")
}

fn request(action: Value) -> Result<Value, String> {
    let env_vars: Vec<[String; 2]> = ENV_VARS
        .iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| [STANDARD.encode(k), STANDARD.encode(v)]))
        .collect();
    let msg = json!({"tty": null, "environment": {"tty": null, "env_vars": env_vars}, "action": action});
    let mut sock = UnixStream::connect(socket_path()).map_err(|e| tr!("rbw-agent に接続できません: {e}", "cannot connect to rbw-agent: {e}"))?;
    sock.write_all(format!("{msg}\n").as_bytes()).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(&sock).read_line(&mut line).map_err(|e| e.to_string())?;
    serde_json::from_str(&line).map_err(|e| format!("cannot read the answer of rbw-agent: {e}"))
}

/// 暗号文を平文にする。entry_key は項目ごとの鍵（暗号文のまま）、org_id は組織の項目のとき。
pub fn decrypt(cipherstring: &str, entry_key: Option<&str>, org_id: Option<&str>) -> Result<String, String> {
    let res = request(json!({
        "type": "Decrypt",
        "cipherstring": cipherstring,
        "entry_key": entry_key,
        "org_id": org_id,
    }))?;
    match res.get("type").and_then(Value::as_str) {
        Some("Decrypt") => res["plaintext"].as_str().map(str::to_owned).ok_or_else(|| "no plaintext in the answer".into()),
        Some("Error") => Err(res["error"].as_str().unwrap_or("unknown error").to_owned()),
        _ => Err(format!("unexpected answer: {res}")),
    }
}

/// 平文を暗号文にする（個人の保管庫の鍵、org_id があればその組織の鍵で）
pub fn encrypt(plaintext: &str, org_id: Option<&str>) -> Result<String, String> {
    let res = request(json!({"type": "Encrypt", "plaintext": plaintext, "org_id": org_id}))?;
    match res.get("type").and_then(Value::as_str) {
        Some("Encrypt") => res["cipherstring"].as_str().map(str::to_owned).ok_or_else(|| "no cipherstring in the answer".into()),
        Some("Error") => Err(res["error"].as_str().unwrap_or("unknown error").to_owned()),
        _ => Err(format!("unexpected answer: {res}")),
    }
}
