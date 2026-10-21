<p align="center">
  <img src="logo.png" alt="evil-winrm-rs" width="360">
</p>

# evil-winrm-rs

A native Rust WinRM shell for Linux and Windows. Persistent PowerShell sessions, file transfers, script and assembly helpers, tab completion and multiline input—without a Ruby or Python runtime.

Also includes resumable/compressed transfers, proxy support, JSON output and remote exit codes, a session broker shared by CLI and MCP clients, and SOCKS5 forwarding through Windows.

**[Documentation](https://github.com/botnetbuddies/evil-winrm-rs/wiki)** · [Build and install](https://github.com/botnetbuddies/evil-winrm-rs/wiki/Build-and-install) · [Authentication](https://github.com/botnetbuddies/evil-winrm-rs/wiki/Connections-and-authentication)

## Quick start

```sh
# The password prompt is hidden.
evil-winrm-rs -i windows.example.test -u 'DOMAIN\user'

# HTTPS
evil-winrm-rs -i windows.example.test -u 'DOMAIN\user' --ssl

evil-winrm-rs --help
```

Inside the shell, run `menu` for helpers. Tab completes commands and paths; Ctrl+C stops the current command or transfer.

## Build

```sh
cargo build --release --locked
```

Requires Rust 1.98+ and native build dependencies for the default features. See the [build guide](https://github.com/botnetbuddies/evil-winrm-rs/wiki/Build-and-install) for Linux, Windows, feature selection and Docker.

## Credits and license

Based on [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) and [evil-winrm-py](https://github.com/adityatelange/evil-winrm-py).

[LGPL-3.0-or-later](LICENSE). See [third-party notices](THIRD_PARTY_NOTICES.md) for dependencies and helper attributions.
