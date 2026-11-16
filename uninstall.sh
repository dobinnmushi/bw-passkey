#!/bin/sh
# install.sh で入れたもの（プログラムとサービス）を外す。udev の規則と Rust の開発環境は自動では戻さない。
set -eu
msg() { case "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}" in ja*) echo "$1";; *) echo "$2";; esac; }
systemctl --user disable --now bw-passkey.service 2>/dev/null || true
rm -fv "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/bw-passkey.service" "$HOME/.local/bin/bw-passkey"
systemctl --user daemon-reload
msg "自動では戻していないもの（必要なら手で）:" "Not reverted automatically (undo by hand if you want):"
cat <<'EOF2'
  udev rule   sudo rm /etc/udev/rules.d/70-uhid-uaccess.rules /etc/modules-load.d/uhid.conf && sudo udevadm control --reload
EOF2
