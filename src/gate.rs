//! bw-vault の門（保管庫の鍵を別ユーザーに置き、秘密を出す前に polkit で本人確認をする）との会話。
//!
//! 門のソケット（既定 /run/bwvault-gate/gate.sock）があれば、保管庫の読み書きはすべて門に頼む:
//! - PasskeyList: パスキーの一覧（サイト名・ユーザー名・credentialId など。秘密鍵は含まない。確認なし）
//! - PasskeyGet: 1つのパスキーの秘密鍵（門が、そのサイトとユーザー名を出して本人確認をしてから返す）
//! - AddEntry(kind=passkey): 新しいパスキーを保管庫に保存する（門が暗号化・送信・本人確認をする）
//! 門がなければ、従来どおり rbw のトークンと rbw-agent を直接使う（vault.rs・agent.rs・verify.rs）。

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

pub fn socket_path() -> PathBuf {
    std::env::var("BWVAULT_GATE_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/bwvault-gate/gate.sock"))
}

/// 門が使えるか（使えるなら、すべて門に頼む）
pub fn available() -> bool {
    socket_path().exists()
}

/// 門に1つ頼む。Error の答えは Err にする。本人確認の画面で待つ時間を含めて、長めに待つ
pub fn request(action: Value) -> Result<Value, String> {
    let msg = json!({"tty": null, "environment": null, "action": action});
    let mut sock = UnixStream::connect(socket_path()).map_err(|e| tr!("門に接続できません: {e}", "cannot connect to the gate: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_secs(150))).map_err(|e| e.to_string())?;
    sock.write_all(format!("{msg}\n").as_bytes()).map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(&sock).read_line(&mut line).map_err(|e| e.to_string())?;
    let res: Value = serde_json::from_str(&line).map_err(|e| format!("cannot read the answer of the gate: {e}"))?;
    match res.get("type").and_then(Value::as_str) {
        Some("Error") => Err(res["error"].as_str().unwrap_or("unknown error").to_owned()),
        _ => Ok(res),
    }
}
