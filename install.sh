#!/bin/sh
# bw-passkey をビルドして入れ、ログイン中は常に動くようにする（systemd のユーザーサービス）。何度実行してもよい。
# 事前に必要なもの（sudo が要るものを含む）は README の「導入」（Installation）を参照。
set -eu
R=$(cd "$(dirname "$0")" && pwd)
msg() { # msg <日本語> <English>（LANG が ja なら日本語）
    case "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}" in ja*) echo "$1";; *) echo "$2";; esac
}

# cargo（rustup を ~/.local/share に入れた場合も見つける）
if ! command -v cargo >/dev/null 2>&1 && [ -x "$HOME/.local/share/cargo/bin/cargo" ]; then
    export RUSTUP_HOME=${RUSTUP_HOME:-$HOME/.local/share/rustup} CARGO_HOME=${CARGO_HOME:-$HOME/.local/share/cargo}
    PATH=$CARGO_HOME/bin:$PATH
fi
command -v cargo >/dev/null 2>&1 || { msg "cargo がありません（README の「導入」を参照）" "cargo not found (see Installation in the README)"; exit 1; }
(cd "$R" && cargo build --release --locked)

mkdir -p "$HOME/.local/bin" "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
install -m755 "$R/target/release/bw-passkey" "$HOME/.local/bin/bw-passkey"
msg "入れました: ~/.local/bin/bw-passkey" "Installed: ~/.local/bin/bw-passkey"
unit=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/bw-passkey.service
cp "$R/contrib/bw-passkey.service" "$unit"
systemctl --user daemon-reload
systemctl --user enable bw-passkey.service >/dev/null 2>&1
systemctl --user restart bw-passkey.service
msg "サービス: $unit（ログイン中は常に動く。記録は journalctl --user -u bw-passkey）" \
    "Service: $unit (runs while you are logged in; logs: journalctl --user -u bw-passkey)"

missing=""
for c in rbw rbw-agent fprintd-verify notify-send; do command -v "$c" >/dev/null 2>&1 || missing="$missing $c"; done
[ -w /dev/uhid ] || missing="$missing /dev/uhid(write-permission)"
if [ -n "$missing" ]; then
    msg "足りないもの:$missing（README の「導入」を参照）" "Missing:$missing (see Installation in the README)"
else
    msg "必要なものはそろっています" "All requirements are present"
fi
