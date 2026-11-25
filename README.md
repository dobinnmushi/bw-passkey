# bw-passkey

[日本語](README.ja.md)

A virtual FIDO2 security key for Linux that uses and creates the **passkeys in your Bitwarden vault**.
Browsers and apps see an ordinary USB security key, so passkeys work without the Bitwarden browser extension,
including where the extension can't reach (for example, when the browser asks to "use a security key").

```
browser / app ──CTAP2 over USB HID──▶ bw-passkey (uhid virtual key, built on soft-fido2)
                                        ├ user verification: fingerprint (fprintd), else master password
                                        └ keys: your vault via rbw (sync with rbw's token, decrypt with rbw-agent)
```

- **Sign in** with passkeys that are already in the vault (also those created by the Bitwarden apps).
- **Create** passkeys: a new passkey is saved to the vault as a new login item (name, username and URI set
  from the site). It can't add a passkey to an existing login item (rbw-agent can't encrypt with per-item keys).
- Built on [soft-fido2](https://github.com/pando85/soft-fido2) (CTAP 2.x, uhid transport) and
  [rbw](https://github.com/doy/rbw). Companion of [bw-autotype](https://github.com/dobinnmushi/bw-autotype)
  (typing passwords on GNOME/Wayland), but independent of it.
- **Choose** among several accounts for the same site in its own window (item, user, display name; the last
  choice comes first), instead of the browser's name-only list.
- Notifications and the window follow `LANG` (Japanese or English).

Tested on Ubuntu 26.04 (GNOME 50 / Wayland) with Firefox (Snap) and Google Chrome, signing in and creating
passkeys on real sites. In Chrome, choose "use a different device / security key" when Google Password Manager
offers itself, or turn off its passkey offers.

## How it compares
| Option | Passkeys from the Bitwarden vault outside the extension | Notes |
|---|---|---|
| Bitwarden browser extension | – | Works in the browser where the extension intercepts WebAuthn. It can't answer the browser's own "use a security key" prompt or apps, and on Linux its fingerprint unlock goes through the desktop app and is often unreliable. |
| Bitwarden desktop app | – | Native passkey support is [in progress](https://community.bitwarden.com/t/desktop-app-auto-type-windows-macos-linux/158), with the roadmap mentioning Windows and macOS. |
| Hardware security key (YubiKey etc.) | – | Works everywhere, but the keys live on the device, not in your vault, so they don't sync. |
| Other software FIDO2 keys ([passless](https://github.com/pando85/passless) etc.) | – | Same virtual-key idea (bw-passkey is built on passless's library, soft-fido2), but they store keys in pass, a TPM or files, not in Bitwarden. |
| [Credentials for Linux](https://github.com/linux-credentials) (credentialsd) | – | A system passkey service for Linux, still in development; browser integration is experimental. |

bw-passkey uses the passkeys you already have in Bitwarden (including those created by the official apps) and
saves new ones there, so they keep syncing to your other devices, and it works wherever a USB security key works.

## How it works
1. When a site asks for a passkey, the browser asks the key for user verification: bw-passkey shows a
   notification and waits for your fingerprint. If that fails, it locks the vault and asks for the master
   password (never something weaker); if the vault is locked, unlocking it is the verification. One verification
   covers the following request for the same site.
   If the site does not name an account and the vault has several passkeys for it, bw-passkey opens its own
   window to choose one (`bw-passkey --choose`) and gives the browser only that one.
2. It fetches the vault with rbw's access token (`/sync`; refreshed with `rbw sync` when expired), keeps the
   encrypted passkeys in memory for 10 minutes, and asks rbw-agent to decrypt the ones for that site.
3. It signs with the decrypted key. The signature counter is always 0, like Bitwarden's own passkeys, so
   nothing is written back to the vault when you sign in.
4. When a site creates a passkey (ES256 only, like Bitwarden), the fields are encrypted by rbw-agent with your
   personal vault key and saved as a new login item with `POST /ciphers` before the site gets its answer, so a
   failed save also fails the registration. `rbw sync` runs afterwards so rbw sees the new item.

## Standalone, or with bw-vault
bw-passkey has two backends and picks one by itself.

| | Standalone (default) | With [bw-vault](https://github.com/dobinnmushi/bw-vault) (companion) |
|---|---|---|
| Chosen when | bw-vault's socket does not exist | `/run/bwvault-gate/gate.sock` exists (override the path with `BWVAULT_GATE_SOCKET`) |
| Vault key and token | in your user: rbw-agent's memory and rbw's database | under a separate user (`bwvault`); nothing here can read them |
| Identity check | bw-passkey asks for your fingerprint (see "How it works") | bw-vault's gate asks polkit — fingerprint, then your password, like `sudo` — and bw-passkey asks for nothing itself |
| Reading passkeys | decrypts every passkey of the site up front | lists the site's passkeys (names only) with one confirmation, lets you choose, then fetches **only the chosen private key**; its confirmation names the site and user |
| Creating a passkey | encrypts with rbw-agent and `POST`s it itself | hands the fields to the gate, which asks for a confirmation, encrypts and saves them before the site gets its answer |
| `bw-passkey --list` | shows keys as readable | does not fetch keys (it would ask for each one) |

With bw-vault, the browser's "user verification" and "user presence" requests are answered without a second prompt: a
signature needs the private key, and the private key is not released without a confirmation, so the check has already happened.
Creating a passkey is the same: if the gate's confirmation fails, nothing is saved and the registration fails.

To use the standalone backend even though bw-vault is installed, point `BWVAULT_GATE_SOCKET` at a path that does not exist
(`systemctl --user edit bw-passkey`, then `Environment=BWVAULT_GATE_SOCKET=/nonexistent`).

## Requirements
- [rbw](https://github.com/doy/rbw) (logged in; `rbw unlock` is run when needed), fprintd (optional),
  notify-send. With [bw-vault](#standalone-or-with-bw-vault), rbw and fprintd are used by bw-vault instead
- Write access to `/dev/uhid` (once, with sudo):
  ```
  echo 'KERNEL=="uhid", SUBSYSTEM=="misc", TAG+="uaccess", OPTIONS+="static_node=uhid"' | sudo tee /etc/udev/rules.d/70-uhid-uaccess.rules
  echo uhid | sudo tee /etc/modules-load.d/uhid.conf
  sudo modprobe uhid && sudo udevadm control --reload && sudo udevadm trigger --name-match=uhid
  ```
  systemd's `fido_id` recognizes the virtual key as a FIDO device, which gives your session access to it and
  lets snapd pass it to Snap browsers (Firefox) through their `u2f-devices` interface.
- To build: GTK 4 and libadwaita development files (`sudo apt install libgtk-4-dev libadwaita-1-dev`) and Rust,
  e.g. rustup without sudo:
  `RUSTUP_HOME=~/.local/share/rustup CARGO_HOME=~/.local/share/cargo sh rustup-init.sh --no-modify-path --profile minimal`
  (`install.sh` finds cargo there).

## Install
`./install.sh` builds, installs `~/.local/bin/bw-passkey` and a systemd user service that runs while you are
logged in. Logs: `journalctl --user -u bw-passkey`. `./uninstall.sh` removes both.

`bw-passkey --list` shows which passkeys it can read (item, site, user; no secrets).

## Notes
- If the Bitwarden browser extension is set to handle passkeys, it answers first. Turn off "Ask to save and use
  passkeys" in the extension (Settings → Notifications) to let the browser use this key.
- A software key is only as safe as your unlocked vault: anything running as you can talk to rbw-agent anyway.
  Lock your screen when you leave, or use [bw-vault](#standalone-or-with-bw-vault), which keeps the key out of your user.
- Passkeys imported with a non-zero counter are answered with counter 0; a site may reject that.
- Passkeys are always created as discoverable (resident) credentials, so they are all stored in the vault.
- Snap or Flatpak apps can only use security keys if their confinement allows it (for snaps, the
  `u2f-devices` interface). Firefox's snap has it; for example the Discord and Slack snaps do not, so sign in
  to those services in a browser instead. Electron apps otherwise use the same WebAuthn code as Chrome.

## License
AGPL-3.0-or-later (soft-fido2 is AGPL-3.0).
