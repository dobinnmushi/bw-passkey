//! USB HID（CTAPHID）のやり取り。uhid の仮想デバイスとしてパケットを受け、まとまった要求を
//! soft-fido2 の Authenticator に渡す。
//!
//! soft-fido2 の examples/authenticator.rs（AGPL-3.0）の受信ループを元にし、次を足した:
//! - 時間のかかる要求（指紋を待つ間など）は、100ms ごとに KEEPALIVE を送る（ブラウザが諦めないように）
//! - チャネル番号の割り当てを 0 と 0xffffffff を避けて回す

use soft_fido2::{Authenticator, AuthenticatorCallbacks, CredentialKeyProvider, Uhid};
use soft_fido2_transport::{Cmd, Message, Packet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const KEEPALIVE_INTERVAL: Duration = Duration::from_millis(100);
/// KEEPALIVE の状態: 本人の操作を待っている
const STATUS_UPNEEDED: u8 = 2;
/// CTAPHID のエラー: 知らない命令
const ERR_INVALID_CMD: u8 = 0x01;

pub fn run<C: AuthenticatorCallbacks, K: CredentialKeyProvider + Send + 'static>(auth: &mut Authenticator<C, K>) -> soft_fido2::Result<()> {
    let uhid = Uhid::open()?;
    log::info!("仮想セキュリティキーを用意しました（uhid）");

    let mut current_channel: u32 = 0xffff_ffff;
    let mut next_channel_id: u32 = 1;
    let mut pending: Vec<Packet> = Vec::new();
    let mut buffer = [0u8; 64];

    loop {
        match uhid.read_packet(&mut buffer) {
            Ok(len) if len > 0 => {
                let packet = Packet::from_bytes(buffer);
                if packet.is_init() {
                    current_channel = packet.cid();
                    pending.clear();
                    pending.push(packet);
                } else if packet.cid() == current_channel && !pending.is_empty() {
                    pending.push(packet);
                } else {
                    continue;
                }
                let total = pending[0].payload_len().unwrap_or(0) as usize;
                let received: usize = pending.iter().map(|p| p.payload().len()).sum();
                if received >= total {
                    if let Err(e) = process(auth, &uhid, &pending, &mut next_channel_id) {
                        log::warn!("要求を処理できませんでした: {e:?}");
                    }
                    pending.clear();
                }
            }
            Ok(_) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => {
                log::warn!("uhid の読み込みに失敗: {e:?}");
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn process<C: AuthenticatorCallbacks, K: CredentialKeyProvider + Send + 'static>(
    auth: &mut Authenticator<C, K>,
    uhid: &Uhid,
    packets: &[Packet],
    next_channel_id: &mut u32,
) -> soft_fido2::Result<()> {
    let message = Message::from_packets(packets, None).map_err(|_| soft_fido2::Error::Other)?;
    let cid = message.cid;
    match message.cmd {
        Cmd::Cbor => {
            let mut response = Vec::new();
            let done = AtomicBool::new(false);
            let result = std::thread::scope(|s| {
                // 処理が長引く間は KEEPALIVE を送り続ける
                s.spawn(|| {
                    while !done.load(Ordering::Relaxed) {
                        std::thread::sleep(KEEPALIVE_INTERVAL);
                        if done.load(Ordering::Relaxed) {
                            break;
                        }
                        let _ = send(uhid, &Message::new(cid, Cmd::Keepalive, vec![STATUS_UPNEEDED], None));
                    }
                });
                let r = auth.handle(&message.data, &mut response);
                done.store(true, Ordering::Relaxed);
                r
            });
            log::debug!("CTAP {:02x?} → 結果 {:02x?}", message.data.first(), response.first());
            let body = match result {
                Ok(_) => response,
                Err(e) => {
                    log::warn!("CTAP の命令 {:02x?} が失敗: {e:?}", message.data.first());
                    vec![0x01]
                }
            };
            send(uhid, &Message::new(cid, Cmd::Cbor, body, None))
        }
        Cmd::Init if message.data.len() >= 8 => {
            let new_cid = *next_channel_id;
            *next_channel_id = match next_channel_id.wrapping_add(1) {
                0 | 0xffff_ffff => 1,
                n => n,
            };
            let mut data = message.data[..8].to_vec(); // ブラウザが送った乱数をそのまま返す
            data.extend_from_slice(&new_cid.to_be_bytes());
            data.extend_from_slice(&[2, 0, 1, 0]); // CTAPHID の版、デバイスの版（0.1.0）
            data.push(0x04 | 0x08); // CBOR に対応、U2F（MSG）は非対応
            send(uhid, &Message::new(0xffff_ffff, Cmd::Init, data, None))
        }
        Cmd::Ping => send(uhid, &Message::new(cid, Cmd::Ping, message.data, None)),
        Cmd::Cancel => Ok(()),
        _ => send(uhid, &Message::new(cid, Cmd::Error, vec![ERR_INVALID_CMD], None)),
    }
}

fn send(uhid: &Uhid, message: &Message) -> soft_fido2::Result<()> {
    for packet in message.to_packets().map_err(|_| soft_fido2::Error::Other)?.iter() {
        uhid.write_packet(packet.as_bytes())?;
    }
    Ok(())
}
