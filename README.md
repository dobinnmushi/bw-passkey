# bw-passkey

A virtual FIDO2 security key for Linux that signs with the **passkeys stored in your Bitwarden vault**.
Browsers and apps see an ordinary USB security key, so passkey sign-in works without the Bitwarden
browser extension: in Firefox (also the Snap), Chrome and Electron apps.

```
browser / app ──CTAP2 over USB HID──▶ bw-passkey (uhid virtual key, built on soft-fido2)
                                        ├ user verification: fingerprint (fprintd), else master password
                                        └ keys: your vault via rbw (sync with rbw's token, decrypt with rbw-agent)
```

- **Sign-in only (for now).** It answers getAssertion with passkeys that are already in the vault.
  Create passkeys with the Bitwarden extension or app as before.
- Built on [soft-fido2](https://github.com/pando85/soft-fido2) (CTAP 2.x, uhid transport).
- Companion of [bw-autotype](https://github.com/dobinnmushi/bw-autotype), but independent of it.

## How it works
1. When a site asks for a passkey, the browser sends getInfo, then asks the key for user verification:
   bw-passkey shows a notification and waits for your fingerprint (falls back to locking the vault and asking
   for the master password, never to something weaker).
2. It fetches the vault with rbw's access token (`/sync`; refreshed with `rbw sync` when expired), keeps the
   encrypted passkeys in memory for 10 minutes, and asks rbw-agent to decrypt the ones for that site.
3. It signs with the decrypted key. The signature counter is always 0, like Bitwarden's own passkeys, so
   nothing is written back to the vault.

## Requirements
- rbw (logged in and unlocked; `rbw unlock` is run when needed), fprintd (optional), notify-send
- Write access to `/dev/uhid` (once, with sudo):
  ```
  echo 'KERNEL=="uhid", SUBSYSTEM=="misc", TAG+="uaccess", OPTIONS+="static_node=uhid"' | sudo tee /etc/udev/rules.d/70-uhid-uaccess.rules
  echo uhid | sudo tee /etc/modules-load.d/uhid.conf
  sudo modprobe uhid && sudo udevadm control --reload && sudo udevadm trigger --name-match=uhid
  ```
  The virtual key is detected as a FIDO device by systemd's `fido_id`, so browsers (including Snap Firefox)
  may open it without further rules.
- Rust (for building), e.g. rustup without sudo:
  `RUSTUP_HOME=~/.local/share/rustup CARGO_HOME=~/.local/share/cargo sh rustup-init.sh --no-modify-path --profile minimal`

## Install
`./install.sh` builds, installs `~/.local/bin/bw-passkey` and a systemd user service that runs while you are
logged in. Logs: `journalctl --user -u bw-passkey`. `./uninstall.sh` removes both.

`bw-passkey --list` shows which passkeys it can read (item, site, user; no secrets).

## Notes
- If the Bitwarden browser extension is set to handle passkeys, it answers first. Turn off "Ask to save and use
  passkeys" in the extension to let the browser use this key.
- A software key is only as safe as your unlocked vault: anything running as you can talk to rbw-agent anyway.
  Lock your screen when you leave.
- Passkeys imported with a non-zero counter are answered with counter 0; a site may reject that.

## License
AGPL-3.0-or-later (soft-fido2 is AGPL-3.0).
