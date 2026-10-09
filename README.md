<img src="docs/icon.png" width="96" height="96" alt="WGMenu app icon" align="right">

# WGMenu

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Platform: macOS 13+ (Apple Silicon)](https://img.shields.io/badge/platform-macOS%2013%2B%20%C2%B7%20Apple%20Silicon-lightgrey.svg)

A macOS menu-bar app that runs **multiple WireGuard tunnels at once**. The official WireGuard app allows only one active tunnel.

![WGMenu menu-bar label in light and dark menu bars](docs/menubar.png)

*The menu-bar label in its gray (off), orange (connecting / no data) and green (receiving) states.*

## Features

- **Multiple simultaneous tunnels**: one switch per config in `/etc/wireguard`, plus Disconnect All.
- **State-colored logo**: the WireGuard logo, tinted gray when nothing is up, orange while connecting or when an up tunnel has received no data for 180 s, green when every up tunnel is receiving.
- **Up count** in a small disc over the logo's lower loop.
- **Live ↑/↓ speed** (total) next to the logo, refreshed every 5 s.
- **Per-tunnel details**: status dot, speed, last handshake and transferred bytes.
- **Import / Edit / Delete configs** from the menu. Each asks for your admin password.
- **Office auto-off**: mark a network as office for a tunnel (tunnel menu); on arriving there, WGMenu turns that tunnel off once. Turn it back on and it stays on. The office is recognized by the default gateway's MAC address, so no location permission is needed.
- **Tunnel priority routing**: order tunnels with **Move Up** / **Move Down** in a tunnel's menu (top = highest priority). WGMenu installs the routes itself: each tunnel gets its `AllowedIPs` minus what a higher-priority connected tunnel already claims, so the same or nested networks in two tunnels no longer fail or silently go to the more specific one. Routes are recomputed on every connect, disconnect, reorder and network change, so a lower tunnel gets its networks back when a higher one disconnects. A full tunnel (`0.0.0.0/0`) is routed as `0.0.0.0/1` + `128.0.0.0/1` and keeps its server endpoint on your real gateway. Only the highest-priority tunnel that sets `DNS` gets it.
- **Launch at login**.

## Requirements

- Apple Silicon Mac, macOS 13 (Ventura) or later
- [Homebrew](https://brew.sh)
- Xcode Command Line Tools: `xcode-select --install`
- An administrator account (for `sudo wgmenu-setup`)
- `/usr/local` owned by root (setup refuses if a legacy Intel Homebrew left it user-owned; fix: `sudo chown root:wheel /usr/local; sudo chmod go-w /usr/local`)

## Install

```sh
brew install kapong/tap/wgmenu
sudo wgmenu-setup
open /Applications/WGMenu.app
```

Then choose **Import Config…** in the menu and pick your `.conf` files (for example, tunnels exported from the official WireGuard app). The tunnel name is the file name without `.conf` (1–15 characters: letters, digits, `_ = + . -`).

## Upgrade

```sh
brew upgrade wgmenu
sudo wgmenu-setup
```

Also re-run `sudo wgmenu-setup` after upgrading `wireguard-tools`, `wireguard-go` or `bash`: it refreshes the root-owned copies of those tools. Upgrading WGMenu itself also needs it, to install the updated helper (if the helper is older than the app, WGMenu says it can't check for conflicts before connecting). Quit and reopen WGMenu after an upgrade; if **Launch at login** stops working, turn it off and on again.

## Uninstall

```sh
sudo wgmenu-setup --uninstall
brew uninstall wgmenu
```

Your configs stay in `/etc/wireguard`.

## Build from source

```sh
brew install wireguard-tools bash
git clone https://github.com/kapong/WGMenu.git
cd WGMenu
./build.sh            # as your normal user -> build/WGMenu.app
sudo ./wgmenu-setup   # copies the app to /Applications
```

`sudo ./wgmenu-setup --uninstall` removes it. The build uses `swiftc` from the Command Line Tools; no Xcode project.

## How it works / Security

WireGuard needs root to bring tunnels up. WGMenu keeps that surface small:

- **Narrow root helper.** `wgmenu-setup` installs `/usr/local/sbin/wgctl` (root-owned) and a sudoers rule that lets your user run only that helper without a password. The helper does six things: `list`, `status`, `routes NAME`, `up NAME`, `down NAME`, `apply-routes`. Names are validated and must match a config in `/etc/wireguard`. `routes` prints only a tunnel's `AllowedIPs` and `DNS` values (never keys), so WGMenu can check for conflicts before connecting. `up` starts the tunnel from a root-only copy in `/var/run/wgmenu` with `Table = off` added, so `wg-quick` adds no routes; `apply-routes` then installs WGMenu's route plan. It accepts only strictly validated `NAME CIDR` lines, only for tunnels WGMenu itself brought up, records every route it adds in `/var/run/wgmenu/routes`, and `down` removes them again.
- **No tools from user-writable paths.** `/opt/homebrew` is writable by your user, so the passwordless helper never runs anything from it. Setup copies `wg-quick`, `wg`, `wireguard-go` and `bash` (with its libraries) into root-owned `/usr/local/libexec/wgmenu`. Before every call, the helper checks that those files and their parent directories are root-owned and not writable by others, and runs them with a clean environment.
- **Configs always need your password.** Configs hold private keys, and `wg-quick` runs their `PreUp`/`PostUp`/`PreDown`/`PostDown` lines as root. A passwordless write would be passwordless root, so reading, writing and deleting configs is never part of the helper. Import, Edit and Delete each ask for your admin password.
- **Hook warning.** If a config contains `PreUp`/`PostUp`/`PreDown`/`PostDown`, WGMenu warns that those commands run as root and asks you to confirm before saving it.
- **Locked config directory.** `/etc/wireguard` is `root:wheel 700` and configs are `600`.
- **What you still trust.** `wgmenu-setup` copies the tools from Homebrew at the moment you run it, so it trusts what Homebrew installed then, like any `sudo` of a brew-installed tool; re-run it after upgrades. The passwordless rule applies to your account, so any process running as you can bring tunnels up and down, including the hooks of configs you already imported. Only import configs you trust. Each 5-second status poll goes through `sudo` and is logged.

## Tips and limitations

- Priority routing needs the current helper: re-run `sudo wgmenu-setup` after upgrading (WGMenu says the helper is out of date otherwise).
- Priority routing applies only to tunnels WGMenu connects. A tunnel started outside WGMenu (e.g. `wg-quick up` in Terminal) keeps `wg-quick`'s own routes and WGMenu leaves them alone; disconnect it and connect it from WGMenu.
- DNS does not move to a lower-priority tunnel when a higher one disconnects. Reconnect the lower tunnel to give it DNS.
- Overlapping `AllowedIPs`, two full tunnels or two `DNS` settings still deserve a look: Import and Save warn about a full tunnel (`0.0.0.0/0` or `::/0`) and suggest the VPN subnet instead, and every connect warns when the tunnel overlaps a connected one, both are full tunnels, or both set `DNS`.
- Don't run the same tunnel in the official WireGuard app at the same time.
- An idle tunnel without keepalives receives nothing and turns orange after 3 minutes. Add `PersistentKeepalive = 25` to its `[Peer]` section to keep it green.
- macOS may ask you to approve WGMenu under System Settings > General > Login Items.
- Office auto-off matches the gateway's MAC address. If the office router is replaced (or a mesh hands you a different access point as gateway), mark the network again. Anyone on the LAN who spoofs a marked gateway MAC can make WGMenu turn that tunnel off; it never turns tunnels on.

## License

[MIT](LICENSE)

"WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld. This project is not affiliated with or endorsed by WireGuard. https://www.wireguard.com/
