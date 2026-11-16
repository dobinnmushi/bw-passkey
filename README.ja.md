# bw-passkey

[English](README.md)

**Bitwarden の保管庫にあるパスキー**で答え、新しいパスキーもそこへ保存する、Linux 用の仮想 FIDO2 セキュリティキー。
ブラウザやアプリからは普通の USB のセキュリティキーに見えるので、Bitwarden のブラウザ拡張なしでパスキーが使える。
拡張が届かない場面（ブラウザが「セキュリティキーを使ってください」と言う場面など）でも使える。

```
ブラウザ・アプリ ──USB HID 上の CTAP2──▶ bw-passkey（uhid の仮想キー。soft-fido2 を使う）
                                          ├ 本人確認: 指紋（fprintd）→ だめならマスターパスワード
                                          └ 鍵: rbw 経由の保管庫（rbw のトークンで同期し、rbw-agent で復号）
```

- **ログイン**: 保管庫にあるパスキーで入れる（Bitwarden のアプリで作ったものも）。
- **作成**: 新しいパスキーは、保管庫の新しいログイン項目として保存する（名前・ユーザー名・URI はサイトから入れる）。
  既存のログイン項目にパスキーを足すことはできない（rbw-agent が項目ごとの鍵での暗号化に対応しないため）。
- [soft-fido2](https://github.com/pando85/soft-fido2)（CTAP 2.x と uhid）と [rbw](https://github.com/doy/rbw) を使う。
  [bw-autotype](https://github.com/dobinnmushi/bw-autotype)（GNOME/Wayland でパスワードを入力する道具）の姉妹品だが、単独で動く。
- 通知は LANG に合わせて日本語か英語。

Ubuntu 26.04（GNOME 50 / Wayland）の Firefox（Snap 版）と Google Chrome で、実際のサイトでのログインと作成を試している。
Chrome では、Google パスワード マネージャーが出てきたら「別のデバイス・セキュリティ キー」を選ぶか、その提案を切る。

## 仕組み
1. サイトがパスキーを求めると、ブラウザがキーに本人確認を頼む。bw-passkey は通知を出して指紋を待つ。
   だめなら保管庫をロックし直してマスターパスワードを聞く（それより弱い経路にはしない）。同じサイトの続く要求には、その確認を使い回す。
2. rbw のアクセストークンで保管庫（`/sync`）を取り（古ければ `rbw sync` で更新）、暗号文のパスキーを10分間メモリに置き、
   そのサイトの分だけ rbw-agent に復号させる。
3. 復号した鍵で署名する。署名の回数は Bitwarden のパスキーと同じく常に 0 なので、ログインでは保管庫に何も書き戻さない。
4. サイトがパスキーを作るとき（Bitwarden と同じく ES256 だけ）は、各欄を rbw-agent が個人の保管庫の鍵で暗号化し、
   サイトに答える前に `POST /ciphers` で新しいログイン項目として保存する。保存に失敗したら登録も失敗する。
   そのあと `rbw sync` を走らせ、rbw からも新しい項目が見えるようにする。

## 必要なもの
- [rbw](https://github.com/doy/rbw)（ログイン済み。必要なら `rbw unlock` を呼ぶ）、fprintd（任意）、notify-send
- `/dev/uhid` への書き込み権限（最初に1回、sudo で）:
  ```
  echo 'KERNEL=="uhid", SUBSYSTEM=="misc", TAG+="uaccess", OPTIONS+="static_node=uhid"' | sudo tee /etc/udev/rules.d/70-uhid-uaccess.rules
  echo uhid | sudo tee /etc/modules-load.d/uhid.conf
  sudo modprobe uhid && sudo udevadm control --reload && sudo udevadm trigger --name-match=uhid
  ```
  仮想キーは systemd の `fido_id` が FIDO のデバイスと判定するので、ログイン中の人が使え、
  snapd も Snap のブラウザ（Firefox）に `u2f-devices` インタフェースで通す。
- ビルド用の Rust。sudo なしなら例えば
  `RUSTUP_HOME=~/.local/share/rustup CARGO_HOME=~/.local/share/cargo sh rustup-init.sh --no-modify-path --profile minimal`
  （`install.sh` はそこの cargo も見つける）。

## 導入
`./install.sh` がビルドして `~/.local/bin/bw-passkey` に入れ、ログイン中は常に動く systemd のユーザーサービスを入れる。
記録は `journalctl --user -u bw-passkey`。外すときは `./uninstall.sh`。

`bw-passkey --list` で、読めるパスキー（項目・サイト・ユーザー。秘密は出さない）を確かめられる。

## 注意
- Bitwarden のブラウザ拡張がパスキーを扱う設定だと、拡張が先に答える。拡張の「設定 → 通知」の
  「パスキーの保存と使用を確認する」をオフにすると、ブラウザがこのキーを使う。
- ソフトウェアのキーなので、守りの強さは「保管庫が開いている間」と同じ。自分の権限で動くプログラムは、どのみち rbw-agent と話せる。席を立つときは画面ロック。
- 他の道具から取り込んだ、カウンタが 0 でないパスキーにも 0 で答える。サイトによっては拒まれる。
- 作るパスキーは常にサイトに保存される型（discoverable / resident）にし、すべて保管庫に入れる。
- Snap や Flatpak のアプリは、箱の設定がセキュリティキーを許すとき（Snap なら `u2f-devices` インタフェース）だけ使える。
  Firefox の Snap は許しているが、たとえば Discord や Slack の Snap は許していないので、それらはブラウザでログインする。
  それ以外の Electron 製のアプリは、Chrome と同じ WebAuthn の仕組みを使う。

## ライセンス
AGPL-3.0-or-later（soft-fido2 が AGPL-3.0 のため）。
